// Package report renders a Collector snapshot into the machine-readable
// JSON artifact instructions.md's "Reporting" section calls for. The
// Markdown summary and the multi-step ramp table are M4 concerns; this
// package currently covers the single fixed-rate run M2 needs — its
// types are shaped so the ramp package can grow Steps into multiple
// entries without a rewrite.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"teleport-auth-stress/internal/collect"
)

// HarnessVersion is this build's version. There's no release process yet
// (M2), so it's a fixed development marker rather than an ldflags-injected
// value — revisit once this toolkit is actually versioned/released.
const HarnessVersion = "0.1.0-dev"

// GitSHA returns the VCS revision Go embedded at build time (available
// when built with `go build` from within a git working tree with at
// least one commit), or "" if unavailable.
func GitSHA() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return ""
}

// Meta is the run-identifying metadata block.
type Meta struct {
	HarnessVersion  string    `json:"harnessVersion"`
	GitSHA          string    `json:"gitSHA,omitempty"`
	StartTime       time.Time `json:"startTime"`
	Scenario        string    `json:"scenario"`
	LoadModel       string    `json:"loadModel"`
	Arrival         string    `json:"arrival"`
	TeleportVersion string    `json:"teleportVersion,omitempty"`
	ClusterName     string    `json:"clusterName,omitempty"`
}

// Step is one offered-rate step's results. For M2 a run has exactly one
// step; the ramp package (M4) will append more as it steps the rate up.
type Step struct {
	OfferedRPS   float64          `json:"offeredRPS"`
	AchievedRPS  float64          `json:"achievedRPS"`
	Total        int64            `json:"total"`
	ErrorRatePct float64          `json:"errorRatePct"`
	Outcomes     map[string]int64 `json:"outcomes"`
	P50Ms        float64          `json:"p50Ms"`
	P90Ms        float64          `json:"p90Ms"`
	P99Ms        float64          `json:"p99Ms"`
	P999Ms       float64          `json:"p999Ms"`
	BytesTotal   int64            `json:"bytesTotal"`
}

// StepFromSnapshot converts a collect.Snapshot into a report Step.
func StepFromSnapshot(snap collect.Snapshot) Step {
	outcomes := make(map[string]int64, len(snap.Outcomes))
	for outcome, count := range snap.Outcomes {
		outcomes[outcome.String()] = count
	}
	return Step{
		OfferedRPS:   snap.OfferedRPS,
		AchievedRPS:  snap.AchievedRPS,
		Total:        snap.Total,
		ErrorRatePct: snap.ErrorRatePct(),
		Outcomes:     outcomes,
		P50Ms:        snap.P50.Seconds() * 1000,
		P90Ms:        snap.P90.Seconds() * 1000,
		P99Ms:        snap.P99.Seconds() * 1000,
		P999Ms:       snap.P999.Seconds() * 1000,
		BytesTotal:   snap.Bytes,
	}
}

// Report is the full JSON artifact for one run.
type Report struct {
	Meta         Meta   `json:"meta"`
	Steps        []Step `json:"steps"`
	ReproCommand string `json:"reproCommand"`
}

// WriteJSON marshals r as indented JSON to path, creating parent
// directories as needed.
func WriteJSON(path string, r *Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
