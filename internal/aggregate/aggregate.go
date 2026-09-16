// Package aggregate merges per-pod raw step data into one fleet-wide
// ramp.Result, per instructions.md's "Distributed execution": each
// generator pod writes its own HDR histograms and counters, and
// aggregation is a separate step so a run can be re-analyzed without
// re-running load. HDR histograms merge losslessly, so the merged
// percentiles are exact, not an average of each pod's percentiles.
package aggregate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"teleport-auth-stress/internal/collect"
	"teleport-auth-stress/internal/ramp"
)

// RawStep is what one pod writes for one step, once that step
// completes. Every pod running the same shared step plan produces one
// of these per step per pod; the aggregate command reads every pod's
// files for a run and merges them.
type RawStep struct {
	StepIndex  int                  `json:"stepIndex"`
	ShardIndex int                  `json:"shardIndex"`
	Data       collect.RawData      `json:"data"`
	Health     ramp.GeneratorHealth `json:"health"`
}

// fileName is deterministic and collision-free across shards for the
// same step, so concurrent pods writing to the same shared directory
// never clobber each other.
func fileName(r RawStep) string {
	return fmt.Sprintf("step-%04d-shard-%04d.json", r.StepIndex, r.ShardIndex)
}

// WriteRawStep persists one pod's one-step result to dir, creating it
// if needed.
func WriteRawStep(dir string, r RawStep) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling raw step: %w", err)
	}
	path := filepath.Join(dir, fileName(r))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// ReadRawSteps reads every raw step file previously written to dir by
// any pod, in no particular order — Merge sorts and groups them.
func ReadRawSteps(dir string) ([]RawStep, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	var raws []RawStep
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		var r RawStep
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		raws = append(raws, r)
	}
	if len(raws) == 0 {
		return nil, fmt.Errorf("no raw step files found in %s", dir)
	}
	return raws, nil
}

// Merge combines every pod's raw step data into one fleet-wide
// ramp.Result, re-evaluating abort criteria and generator thresholds
// against the merged (not per-pod) statistics for each step — a
// fleet-wide aggregate can cross a threshold no individual shard did on
// its own, or vice versa, so this must not just AND/OR each shard's own
// verdict. stepDuration is the plan's configured step duration (shared
// across every pod by construction), used as the nominal elapsed time
// for achieved-rate calculations rather than any single pod's own
// measured wall-clock time.
func Merge(raws []RawStep, stepDuration time.Duration, abort ramp.AbortCriteria, thresholds ramp.GeneratorThresholds) (*ramp.Result, error) {
	if len(raws) == 0 {
		return nil, fmt.Errorf("no raw step data to merge")
	}

	byStep := make(map[int][]RawStep)
	for _, r := range raws {
		byStep[r.StepIndex] = append(byStep[r.StepIndex], r)
	}

	stepIndices := make([]int, 0, len(byStep))
	for idx := range byStep {
		stepIndices = append(stepIndices, idx)
	}
	sort.Ints(stepIndices)

	steps := make([]ramp.StepReport, 0, len(stepIndices))
	for _, idx := range stepIndices {
		shardsAtStep := byStep[idx]

		rawData := make([]collect.RawData, len(shardsAtStep))
		var health ramp.GeneratorHealth
		for i, s := range shardsAtStep {
			rawData[i] = s.Data
			health = ramp.WorstHealth(health, s.Health)
		}

		snap, err := collect.MergeRaw(rawData, stepDuration)
		if err != nil {
			return nil, fmt.Errorf("step %d: %w", idx, err)
		}

		limited, healthReasons := health.Exceeds(thresholds)
		pass, abortReasons := ramp.EvaluateStep(snap, abort)

		steps = append(steps, ramp.StepReport{
			OfferedRPS:       snap.OfferedRPS,
			Snapshot:         snap,
			Health:           health,
			GeneratorLimited: limited,
			Pass:             pass && !limited,
			FailReasons:      append(abortReasons, healthReasons...),
		})
	}

	return ramp.DetermineOutcome(steps), nil
}
