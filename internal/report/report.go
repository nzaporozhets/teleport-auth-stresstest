// Package report renders a ramp Result into the machine-readable JSON
// artifact and human Markdown summary instructions.md's "Reporting"
// section calls for.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"teleport-auth-stress/internal/attrib"
	"teleport-auth-stress/internal/collect"
	"teleport-auth-stress/internal/ramp"
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

// GeneratorHealth is one step's worst observed generator resource
// usage, for the "generator health" column instructions.md's step table
// calls for.
type GeneratorHealth struct {
	CPUPercent     float64 `json:"cpuPercent"`
	Goroutines     int     `json:"goroutines"`
	OpenFDs        int     `json:"openFDs"`
	EphemeralConns int     `json:"ephemeralConns"`
}

// Step is one offered-rate step's results.
type Step struct {
	OfferedRPS        float64          `json:"offeredRPS"`
	AchievedRPS       float64          `json:"achievedRPS"`
	Total             int64            `json:"total"`
	ErrorRatePct      float64          `json:"errorRatePct"`
	AbortErrorRatePct float64          `json:"abortErrorRatePct"`
	Outcomes          map[string]int64 `json:"outcomes"`
	P50Ms             float64          `json:"p50Ms"`
	P90Ms             float64          `json:"p90Ms"`
	P99Ms             float64          `json:"p99Ms"`
	P999Ms            float64          `json:"p999Ms"`
	BytesTotal        int64            `json:"bytesTotal"`
	GeneratorHealth   GeneratorHealth  `json:"generatorHealth"`
	GeneratorLimited  bool             `json:"generatorLimited"`
	Pass              bool             `json:"pass"`
	FailReasons       []string         `json:"failReasons,omitempty"`
	// RankedCauses is populated only for failing, non-generator-limited
	// steps (instructions.md's "Attribution" section: "for the failing
	// steps, correlate ... and emit a ranked list of candidate limiting
	// resources"). Highest-scored first; empty if attribution wasn't
	// run (M2-M5 callers) or found no evidence either way.
	RankedCauses []attrib.Candidate `json:"rankedCauses,omitempty"`
}

// StepFromSnapshot converts a collect.Snapshot into a report Step, with
// no generator-health or pass/fail information (used directly by M2/M3
// callers that don't run a full ramp.Run).
func StepFromSnapshot(snap collect.Snapshot) Step {
	return stepFromSnapshot(snap)
}

func stepFromSnapshot(snap collect.Snapshot) Step {
	outcomes := make(map[string]int64, len(snap.Outcomes))
	for outcome, count := range snap.Outcomes {
		outcomes[outcome.String()] = count
	}
	return Step{
		OfferedRPS:        snap.OfferedRPS,
		AchievedRPS:       snap.AchievedRPS,
		Total:             snap.Total,
		ErrorRatePct:      snap.ErrorRatePct(),
		AbortErrorRatePct: snap.AbortErrorRatePct(),
		Outcomes:          outcomes,
		P50Ms:             snap.P50.Seconds() * 1000,
		P90Ms:             snap.P90.Seconds() * 1000,
		P99Ms:             snap.P99.Seconds() * 1000,
		P999Ms:            snap.P999.Seconds() * 1000,
		BytesTotal:        snap.Bytes,
	}
}

// StepFromRampReport converts a ramp.StepReport (which additionally
// carries generator health and the pass/fail verdict) into a report
// Step.
func StepFromRampReport(sr ramp.StepReport) Step {
	step := stepFromSnapshot(sr.Snapshot)
	step.GeneratorHealth = GeneratorHealth{
		CPUPercent:     sr.Health.CPUPercent,
		Goroutines:     sr.Health.Goroutines,
		OpenFDs:        sr.Health.OpenFDs,
		EphemeralConns: sr.Health.EphemeralConns,
	}
	step.GeneratorLimited = sr.GeneratorLimited
	step.Pass = sr.Pass
	step.FailReasons = sr.FailReasons
	return step
}

// Report is the full JSON artifact for one run.
type Report struct {
	Meta  Meta   `json:"meta"`
	Steps []Step `json:"steps"`
	// Outcome is "converged", "generator-limited", or "inconclusive"
	// (ramp.Outcome.String()). BreakingPointRPS is only meaningful when
	// Outcome is "converged" — see instructions.md's "declared breaking
	// point, or generator-limited / inconclusive with the reason."
	Outcome          string   `json:"outcome"`
	BreakingPointRPS *float64 `json:"breakingPointRPS,omitempty"`
	OutcomeReason    string   `json:"outcomeReason,omitempty"`
	ReproCommand     string   `json:"reproCommand"`
}

// FromRampResult builds the full report from a ramp.Result.
func FromRampResult(result *ramp.Result, meta Meta, reproCommand string) *Report {
	steps := make([]Step, len(result.Steps))
	for i, sr := range result.Steps {
		steps[i] = StepFromRampReport(sr)
	}

	r := &Report{
		Meta:          meta,
		Steps:         steps,
		Outcome:       result.Outcome.String(),
		OutcomeReason: result.Reason,
		ReproCommand:  reproCommand,
	}
	if result.Outcome == ramp.Converged {
		bp := result.BreakingPointRPS
		r.BreakingPointRPS = &bp
	}
	return r
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

// WriteMarkdown renders r as a human-readable Markdown summary and
// writes it to path, creating parent directories as needed.
func WriteMarkdown(path string, r *Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(renderMarkdown(r)), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func renderMarkdown(r *Report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# teleport-auth-stress report\n\n")

	fmt.Fprintf(&b, "## Run metadata\n\n")
	fmt.Fprintf(&b, "- Scenario: `%s`\n", r.Meta.Scenario)
	fmt.Fprintf(&b, "- Load model: `%s` (%s arrival)\n", r.Meta.LoadModel, r.Meta.Arrival)
	fmt.Fprintf(&b, "- Start time: %s\n", r.Meta.StartTime.Format(time.RFC3339))
	if r.Meta.ClusterName != "" {
		fmt.Fprintf(&b, "- Cluster: `%s`\n", r.Meta.ClusterName)
	}
	if r.Meta.TeleportVersion != "" {
		fmt.Fprintf(&b, "- Teleport version: `%s`\n", r.Meta.TeleportVersion)
	}
	fmt.Fprintf(&b, "- Harness version: `%s`", r.Meta.HarnessVersion)
	if r.Meta.GitSHA != "" {
		fmt.Fprintf(&b, " (`%s`)", r.Meta.GitSHA)
	}
	fmt.Fprintf(&b, "\n\n")

	fmt.Fprintf(&b, "## Result: %s\n\n", strings.ToUpper(r.Outcome))
	switch {
	case r.BreakingPointRPS != nil:
		fmt.Fprintf(&b, "Breaking point: **%.1f RPS**\n\n", *r.BreakingPointRPS)
	case r.OutcomeReason != "":
		fmt.Fprintf(&b, "%s\n\n", r.OutcomeReason)
	}

	fmt.Fprintf(&b, "## Step table\n\n")
	fmt.Fprintf(&b, "| Offered RPS | Achieved RPS | p50 | p90 | p99 | p99.9 | Error %% (abort) | Generator CPU %% | Pass |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|---|---|---|---|\n")
	for _, s := range r.Steps {
		pass := "yes"
		if !s.Pass {
			pass = "no"
		}
		if s.GeneratorLimited {
			pass = "generator-limited"
		}
		fmt.Fprintf(&b, "| %.1f | %.1f | %.1fms | %.1fms | %.1fms | %.1fms | %.2f%% | %.1f%% | %s |\n",
			s.OfferedRPS, s.AchievedRPS, s.P50Ms, s.P90Ms, s.P99Ms, s.P999Ms, s.AbortErrorRatePct, s.GeneratorHealth.CPUPercent, pass)
	}
	b.WriteString("\n")

	for _, s := range r.Steps {
		if len(s.FailReasons) == 0 {
			continue
		}
		fmt.Fprintf(&b, "**Step at %.1f RPS failed:**\n", s.OfferedRPS)
		for _, reason := range s.FailReasons {
			fmt.Fprintf(&b, "- %s\n", reason)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Ranked limiting resources\n\n")
	anyRanked := false
	for _, s := range r.Steps {
		if len(s.RankedCauses) == 0 {
			continue
		}
		anyRanked = true
		fmt.Fprintf(&b, "**Step at %.1f RPS:**\n\n", s.OfferedRPS)
		for i, c := range s.RankedCauses {
			fmt.Fprintf(&b, "%d. `%s` (score %.1f)\n", i+1, c.Name, c.Score)
			for _, e := range c.Evidence {
				fmt.Fprintf(&b, "   - %s\n", e)
			}
		}
		b.WriteString("\n")
	}
	if !anyRanked {
		fmt.Fprintf(&b, "No failing step had attribution data (either every step passed, attribution wasn't run, or no detector had enough evidence to score).\n\n")
	}

	fmt.Fprintf(&b, "## Reproduction\n\n```\n%s\n```\n", r.ReproCommand)

	return b.String()
}
