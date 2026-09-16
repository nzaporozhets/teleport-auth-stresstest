package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"teleport-auth-stress/internal/collect"
	"teleport-auth-stress/internal/ramp"
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

func TestFromRampResult_Converged(t *testing.T) {
	c := collect.New()
	c.Add(10*time.Millisecond, scenario.Success, 0)
	snap := c.Snapshot(100, time.Second)

	result := &ramp.Result{
		Steps:            []ramp.StepReport{{OfferedRPS: 100, Snapshot: snap, Pass: true}},
		Outcome:          ramp.Converged,
		BreakingPointRPS: 100,
	}
	r := FromRampResult(result, Meta{Scenario: "cert-renewal"}, "repro")

	if r.Outcome != "converged" {
		t.Errorf("Outcome = %q, want converged", r.Outcome)
	}
	if r.BreakingPointRPS == nil || *r.BreakingPointRPS != 100 {
		t.Errorf("BreakingPointRPS = %v, want pointer to 100", r.BreakingPointRPS)
	}
	if len(r.Steps) != 1 || !r.Steps[0].Pass {
		t.Errorf("Steps = %+v, want one passing step", r.Steps)
	}
}

func TestFromRampResult_GeneratorLimited_NoBreakingPoint(t *testing.T) {
	c := collect.New()
	c.Add(10*time.Millisecond, scenario.Success, 0)
	snap := c.Snapshot(100, time.Second)

	result := &ramp.Result{
		Steps:   []ramp.StepReport{{OfferedRPS: 100, Snapshot: snap, GeneratorLimited: true}},
		Outcome: ramp.GeneratorLimited,
		Reason:  "generator saturated",
	}
	r := FromRampResult(result, Meta{}, "repro")

	if r.Outcome != "generator-limited" {
		t.Errorf("Outcome = %q, want generator-limited", r.Outcome)
	}
	if r.BreakingPointRPS != nil {
		t.Errorf("BreakingPointRPS = %v, want nil when generator-limited", *r.BreakingPointRPS)
	}
	if r.OutcomeReason != "generator saturated" {
		t.Errorf("OutcomeReason = %q, want %q", r.OutcomeReason, "generator saturated")
	}
	if !r.Steps[0].GeneratorLimited {
		t.Error("expected step to carry GeneratorLimited=true")
	}
}

func TestWriteMarkdown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.md")

	bp := 400.0
	r := &Report{
		Meta: Meta{
			Scenario:  "cert-renewal",
			LoadModel: "open",
			Arrival:   "poisson",
			StartTime: time.Now().UTC(),
		},
		Steps: []Step{
			{OfferedRPS: 200, AchievedRPS: 200, Pass: true},
			{OfferedRPS: 400, AchievedRPS: 380, Pass: true},
			{OfferedRPS: 600, AchievedRPS: 300, Pass: false, FailReasons: []string{"p99 latency 5000.0ms exceeds threshold 2000.0ms"}},
		},
		Outcome:          "converged",
		BreakingPointRPS: &bp,
		ReproCommand:     "authload run -c scenarios/example.yaml -y",
	}

	if err := WriteMarkdown(path, r); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written markdown: %v", err)
	}
	out := string(data)

	for _, want := range []string{
		"# teleport-auth-stress report",
		"cert-renewal",
		"CONVERGED",
		"Breaking point: **400.0 RPS**",
		"p99 latency 5000.0ms exceeds threshold 2000.0ms",
		"authload run -c scenarios/example.yaml -y",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered markdown missing %q; got:\n%s", want, out)
		}
	}
}
