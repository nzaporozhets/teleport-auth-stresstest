package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"teleport-auth-stress/internal/collect"
	"teleport-auth-stress/internal/scenario"
)

func TestStepFromSnapshot(t *testing.T) {
	c := collect.New()
	c.Add(10*time.Millisecond, scenario.Success, 100)
	c.Add(20*time.Millisecond, scenario.RateLimited, 0)
	snap := c.Snapshot(20, time.Second)

	step := StepFromSnapshot(snap)
	if step.Total != 2 {
		t.Errorf("Total = %d, want 2", step.Total)
	}
	if step.Outcomes["success"] != 1 || step.Outcomes["rate-limited"] != 1 {
		t.Errorf("Outcomes = %+v, want success:1 rate-limited:1", step.Outcomes)
	}
	if step.BytesTotal != 100 {
		t.Errorf("BytesTotal = %d, want 100", step.BytesTotal)
	}
	if step.P50Ms <= 0 {
		t.Errorf("P50Ms = %v, want > 0", step.P50Ms)
	}
}

func TestWriteJSON_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "report.json")

	c := collect.New()
	c.Add(5*time.Millisecond, scenario.Success, 10)
	snap := c.Snapshot(10, time.Second)

	r := &Report{
		Meta: Meta{
			HarnessVersion: HarnessVersion,
			StartTime:      time.Now().UTC(),
			Scenario:       "cert-renewal",
			LoadModel:      "open",
			Arrival:        "poisson",
		},
		Steps:        []Step{StepFromSnapshot(snap)},
		ReproCommand: "authload run -c scenarios/example.yaml",
	}

	if err := WriteJSON(path, r); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written report: %v", err)
	}
	var loaded Report
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshalling written report: %v", err)
	}
	if loaded.Meta.Scenario != "cert-renewal" {
		t.Errorf("Scenario = %q, want cert-renewal", loaded.Meta.Scenario)
	}
	if len(loaded.Steps) != 1 || loaded.Steps[0].Total != 1 {
		t.Errorf("Steps = %+v, want one step with Total=1", loaded.Steps)
	}
}

func TestGitSHA_DoesNotPanic(t *testing.T) {
	_ = GitSHA() // may be "" in a test binary; just must not panic
}
