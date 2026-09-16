// Command authload is the load generator for teleport-auth-stress. One
// process runs per pod; see deploy/helm for multi-pod sharding.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"teleport-auth-stress/internal/aggregate"
	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/driver"
	"teleport-auth-stress/internal/identity"
	"teleport-auth-stress/internal/ramp"
	"teleport-auth-stress/internal/report"
	"teleport-auth-stress/internal/scenario"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "validate":
		os.Exit(runValidate(os.Args[2:]))
	case "run":
		os.Exit(runRun(os.Args[2:]))
	case "aggregate":
		os.Exit(runAggregate(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "authload: unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `authload — teleport-auth-stress load generator

Usage:
  authload validate -c <config.yaml>      Validate a config file and exit.
  authload run -c <config.yaml> -y        Run the load generator.
  authload aggregate -c <config.yaml> --results-dir <dir>
                                           Merge multiple pods' raw per-step
                                           data (from -y run --results-dir)
                                           into one fleet-wide report.

Omit -y to see the pre-flight summary without generating any load.

Multi-pod sharding flags for run (see deploy/helm and docs/runbook.md):
  --shard-index N     This pod's index (default: $JOB_COMPLETION_INDEX, else 0)
  --shard-count N     Total number of pods (default: 1)
  --start-at RFC3339  Wait until this shared wall-clock time before the step
                       plan begins; every pod must be given the same value
  --results-dir DIR   Write this pod's raw per-step data here for later
                       aggregation, instead of (or in addition to) its own
                       single-pod report
`)
}

func runValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	path := fs.String("c", "", "path to config YAML")
	fs.Parse(args)

	if *path == "" {
		fmt.Fprintln(os.Stderr, "authload validate: -c <config.yaml> is required")
		return 2
	}

	cfg, err := config.LoadAndValidate(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	fmt.Printf("OK: %s is valid (scenario=%s, target=%s, cluster=%s)\n", *path, cfg.Load.Scenario, cfg.Target.ProxyAddr, cfg.Target.Cluster)
	return 0
}

// newScenario is the one place authload branches on scenario name. The
// driver, collector, and reporter above it are scenario-agnostic (M7's
// acceptance criterion) — this factory is CLI wiring, not part of that
// pipeline.
func newScenario(name config.ScenarioName) (scenario.Scenario, error) {
	switch name {
	case config.ScenarioCertRenewal:
		return &scenario.CertRenewal{}, nil
	case config.ScenarioLocalLoginWebAuthn:
		return &scenario.LocalLoginWebAuthn{}, nil
	case config.ScenarioLocalLoginTOTP:
		return &scenario.LocalLoginTOTP{}, nil
	case config.ScenarioBotJoinRenew:
		return &scenario.BotJoinRenew{}, nil
	case config.ScenarioRouteCertIssuance:
		return &scenario.RouteCertIssuance{}, nil
	case config.ScenarioMixed:
		return &scenario.Mixed{}, nil
	default:
		return nil, fmt.Errorf("scenario %q is not a known scenario", name)
	}
}

func printPreflight(cfg *config.Config, shardIndex, shardCount int) {
	duration := cfg.Load.Ramp.Warmup + cfg.Load.Ramp.StepDuration
	estimatedEvents := int64(cfg.Load.Ramp.StartRPS * duration.Seconds())
	fmt.Printf(`Pre-flight summary (run)
  target proxy:      %s
  required cluster:  %s
  scenario:          %s
  load model:        %s (%s arrival)
  offered rate:      %.1f RPS fleet-wide (this pod: shard %d/%d)
  warmup + duration: %v + %v
  est. audit events: ~%d
  fixture state:     %s
  report output:     %s
`, cfg.Target.ProxyAddr, cfg.Target.Guardrail.RequireClusterName, cfg.Load.Scenario, cfg.Load.Model, cfg.Load.Arrival, cfg.Load.Ramp.StartRPS, shardIndex, shardCount, cfg.Load.Ramp.Warmup, cfg.Load.Ramp.StepDuration, estimatedEvents, cfg.Fixtures.StatePath, cfg.Report.OutputDir)
}

// defaultShardIndex reads $JOB_COMPLETION_INDEX (set automatically by a
// Kubernetes Indexed Job — see deploy/helm) so the chart doesn't need to
// compute and inject a per-pod index itself.
func defaultShardIndex() int {
	if v := os.Getenv("JOB_COMPLETION_INDEX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

func runRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	path := fs.String("c", "", "path to config YAML")
	confirm := fs.Bool("y", false, "actually run (without this flag, only the pre-flight summary is printed)")
	shardIndex := fs.Int("shard-index", defaultShardIndex(), "this pod's index (0-based) among shard-count pods")
	shardCount := fs.Int("shard-count", 1, "total number of pods sharing the load")
	startAt := fs.String("start-at", "", "RFC3339 timestamp: wait until this shared wall-clock time before starting the step plan")
	resultsDir := fs.String("results-dir", "", "directory to write this pod's raw per-step data for later `authload aggregate`")
	fs.Parse(args)

	if *path == "" {
		fmt.Fprintln(os.Stderr, "authload run: -c <config.yaml> is required")
		return 2
	}
	if *shardCount < 1 {
		fmt.Fprintln(os.Stderr, "authload run: --shard-count must be >= 1")
		return 2
	}
	if *shardIndex < 0 || *shardIndex >= *shardCount {
		fmt.Fprintf(os.Stderr, "authload run: --shard-index must be within [0, %d)\n", *shardCount)
		return 2
	}
	var startAtTime *time.Time
	if *startAt != "" {
		t, err := time.Parse(time.RFC3339, *startAt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "authload run: --start-at: %v\n", err)
			return 2
		}
		startAtTime = &t
	}

	cfg, err := config.LoadAndValidate(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	if cfg.Load.Model == config.LoadModelClosed {
		fmt.Fprintln(os.Stderr, "authload run: load.model \"closed\" is implemented in internal/driver but not yet wired into this command")
		return 1
	}

	printPreflight(cfg, *shardIndex, *shardCount)
	if !*confirm {
		fmt.Println("\nDry run: pass -y to run.")
		return 3
	}

	if err := runLoad(*path, cfg, *shardIndex, *shardCount, startAtTime, *resultsDir); err != nil {
		fmt.Fprintf(os.Stderr, "run failed: %v\n", err)
		return 1
	}
	return 0
}

func runLoad(configPath string, cfg *config.Config, shardIndex, shardCount int, startAt *time.Time, resultsDir string) error {
	ctx := context.Background()

	sc, err := newScenario(cfg.Load.Scenario)
	if err != nil {
		return err
	}

	fixtures, err := identity.LoadFixtureState(cfg.Fixtures.StatePath)
	if err != nil {
		return fmt.Errorf("loading fixture state (did you run authseed apply?): %w", err)
	}
	fixtures = fixtures.Shard(shardIndex, shardCount)
	slog.Info("sharded fixtures", "shardIndex", shardIndex, "shardCount", shardCount, "users", len(fixtures.Users))

	admin, err := identity.NewAdminClient(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connecting to cluster: %w", err)
	}
	clusterName, serverVersion, err := admin.CheckLiveClusterName(ctx, cfg)
	if err != nil {
		admin.Close()
		return err
	}

	slog.Info("running scenario setup", "scenario", sc.Name())
	if err := sc.Setup(ctx, &scenario.Env{Config: cfg, Admin: admin, Fixtures: fixtures}); err != nil {
		admin.Close()
		return fmt.Errorf("scenario setup: %w", err)
	}
	// The admin identity is used for one-time bootstrap only: close it
	// now so nothing below this point could reference it even by
	// accident, then let the scenario's own Execute run entirely on
	// credentials it already holds.
	admin.Close()
	defer func() {
		if err := sc.Teardown(ctx); err != nil {
			slog.Warn("scenario teardown returned an error", "error", err)
		}
	}()

	// Attribution setup (M6) happens once per pod, independent of the
	// shared start-at clock — every pod scraping simultaneously right at
	// go-time would be wasteful, and this doesn't need to be
	// synchronized across pods the way the measured step plan does.
	metricsClient := newMetricsClient(cfg.Target.InsecureSkipVerify)
	attributor := newStepAttributor(metricsClient, cfg, setupAttribution(ctx, metricsClient, cfg))

	// The shared wall-clock rendezvous applies to the measured step
	// plan, not to Setup: every pod's (possibly slow, cert-issuing)
	// bootstrap runs independently and as soon as it's ready, then all
	// pods wait here so the step plan itself starts in lockstep — no
	// leader election, no runtime RPC between pods, just the same
	// timestamp given to every pod (instructions.md "Distributed
	// execution").
	if startAt != nil {
		if d := time.Until(*startAt); d > 0 {
			slog.Info("waiting for shared start time", "startAt", startAt, "wait", d)
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return ctx.Err()
			}
		} else {
			slog.Warn("start-at is already in the past; starting immediately", "startAt", startAt, "late_by", -d)
		}
	}

	task := driver.Task(func(ctx context.Context) (scenario.Result, error) {
		return sc.Execute(ctx)
	})

	plan := ramp.Plan{
		StartRPS:     cfg.Load.Ramp.StartRPS / float64(shardCount),
		StepRPS:      cfg.Load.Ramp.StepRPS / float64(shardCount),
		StepDuration: cfg.Load.Ramp.StepDuration,
		Warmup:       cfg.Load.Ramp.Warmup,
		Settle:       cfg.Load.Ramp.Settle,
		MaxRPS:       cfg.Load.Ramp.MaxRPS / float64(shardCount),
	}
	abort := ramp.AbortCriteria{
		P99LatencyMs:         cfg.Load.Abort.P99LatencyMs,
		ErrorRatePct:         cfg.Load.Abort.ErrorRatePct,
		ThroughputDeficitPct: cfg.Load.Abort.ThroughputDeficitPct,
		ConsecutiveBadSteps:  cfg.Load.Abort.ConsecutiveBadSteps,
	}
	if shardCount > 1 {
		// When sharded, only the fleet-wide aggregate's verdict matters
		// (authload aggregate re-evaluates abort criteria against the
		// merged data). A single pod stopping early on its own noisy
		// shard would leave other pods' later steps with no matching
		// step index to merge against — so every pod runs the full
		// range up to maxRPS unconditionally. This doesn't change the
		// eventual breaking point: DetermineOutcome/aggregate.Merge
		// already just take the highest *passing* rate, so extra
		// trailing failing steps past the real knee don't affect it.
		abort.ConsecutiveBadSteps = int(plan.MaxRPS/plan.StepRPS) + 2
	}
	thresholds := ramp.GeneratorThresholds{
		MaxCPUPercent:     cfg.Load.GeneratorLimits.MaxCPUPercent,
		MaxGoroutines:     cfg.Load.GeneratorLimits.MaxGoroutines,
		MaxOpenFDs:        cfg.Load.GeneratorLimits.MaxOpenFDs,
		MaxEphemeralConns: cfg.Load.GeneratorLimits.MaxEphemeralConns,
	}

	startTime := time.Now().UTC()
	stepIndex := 0
	result, err := ramp.RunWithHooks(ctx, plan, abort, thresholds, driver.Arrival(cfg.Load.Arrival), task, ramp.NewOSHealthSampler(),
		attributor.onStepStart,
		func(s ramp.StepReport) {
			slog.Info("step complete", "shardIndex", shardIndex, "offeredRPS", s.OfferedRPS, "achievedRPS", s.Snapshot.AchievedRPS, "pass", s.Pass, "generatorLimited", s.GeneratorLimited, "failReasons", s.FailReasons)
			if resultsDir != "" {
				if err := aggregate.WriteRawStep(resultsDir, aggregate.RawStep{
					StepIndex:  stepIndex,
					ShardIndex: shardIndex,
					Data:       s.RawData,
					Health:     s.Health,
				}); err != nil {
					slog.Warn("writing raw step data failed", "error", err)
				}
			}
			// Attribution ranking currently only feeds the single-pod
			// report below, not the multi-pod aggregate command — a
			// sharded run's attribution still runs (harmless) but its
			// ranked causes aren't persisted to resultsDir yet.
			attributor.onStep(ctx, s)
			stepIndex++
		})
	if err != nil {
		return fmt.Errorf("ramp: %w", err)
	}
	slog.Info("run complete", "shardIndex", shardIndex, "outcome", result.Outcome, "breakingPointRPS", result.BreakingPointRPS, "reason", result.Reason)

	if resultsDir != "" {
		fmt.Printf("\nShard %d/%d complete. Raw step data written to %s — run `authload aggregate` once every pod finishes.\n", shardIndex, shardCount, resultsDir)
		return nil
	}

	// Single-pod (or sharded-without---results-dir) mode: this pod's own
	// result is the final report.
	return writeReport(cfg, configPath, result, startTime, clusterName, serverVersion, shardIndex, shardCount, attributor)
}

// writeReport builds and writes the final report. attributor is nil for
// authload aggregate, which has no live scrape data to rank with (it
// re-evaluates abort/generator criteria against merged data, but
// ranked-cause attribution doesn't yet span multi-pod aggregation — see
// docs/methodology.md's M6 notes).
func writeReport(cfg *config.Config, reproTarget string, result *ramp.Result, startTime time.Time, clusterName, serverVersion string, shardIndex, shardCount int, attributor *stepAttributor) error {
	r := report.FromRampResult(result, report.Meta{
		HarnessVersion:  report.HarnessVersion,
		GitSHA:          report.GitSHA(),
		StartTime:       startTime,
		Scenario:        string(cfg.Load.Scenario),
		LoadModel:       string(cfg.Load.Model),
		Arrival:         string(cfg.Load.Arrival),
		TeleportVersion: serverVersion,
		ClusterName:     clusterName,
	}, reproTarget)

	if attributor != nil {
		for i := range r.Steps {
			r.Steps[i].RankedCauses = attributor.rankedFor(i)
		}
	}

	stamp := startTime.Format("20060102T150405Z")
	suffix := ""
	if shardCount > 1 {
		suffix = fmt.Sprintf("-shard-%d", shardIndex)
	}
	fmt.Printf("\nOutcome: %s", result.Outcome)
	if result.Outcome == ramp.Converged {
		fmt.Printf(" (breaking point: %.1f RPS)", result.BreakingPointRPS)
	} else if result.Reason != "" {
		fmt.Printf(" (%s)", result.Reason)
	}
	fmt.Println()

	for _, format := range cfg.Report.Formats {
		switch format {
		case config.ReportFormatJSON:
			outPath := filepath.Join(cfg.Report.OutputDir, fmt.Sprintf("report-%s%s.json", stamp, suffix))
			if err := report.WriteJSON(outPath, r); err != nil {
				return fmt.Errorf("writing JSON report: %w", err)
			}
			fmt.Printf("JSON report written to %s\n", outPath)
		case config.ReportFormatMarkdown:
			outPath := filepath.Join(cfg.Report.OutputDir, fmt.Sprintf("report-%s%s.md", stamp, suffix))
			if err := report.WriteMarkdown(outPath, r); err != nil {
				return fmt.Errorf("writing Markdown report: %w", err)
			}
			fmt.Printf("Markdown report written to %s\n", outPath)
		}
	}
	return nil
}

func runAggregate(args []string) int {
	fs := flag.NewFlagSet("aggregate", flag.ExitOnError)
	path := fs.String("c", "", "path to config YAML (used for load.abort/load.generatorLimits/load.ramp.stepDuration/report settings)")
	resultsDir := fs.String("results-dir", "", "directory containing raw per-step data written by every pod's `run --results-dir`")
	fs.Parse(args)

	if *path == "" || *resultsDir == "" {
		fmt.Fprintln(os.Stderr, "authload aggregate: -c <config.yaml> and --results-dir <dir> are required")
		return 2
	}

	cfg, err := config.LoadAndValidate(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	raws, err := aggregate.ReadRawSteps(*resultsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aggregate failed: %v\n", err)
		return 1
	}

	abort := ramp.AbortCriteria{
		P99LatencyMs:         cfg.Load.Abort.P99LatencyMs,
		ErrorRatePct:         cfg.Load.Abort.ErrorRatePct,
		ThroughputDeficitPct: cfg.Load.Abort.ThroughputDeficitPct,
		ConsecutiveBadSteps:  cfg.Load.Abort.ConsecutiveBadSteps,
	}
	thresholds := ramp.GeneratorThresholds{
		MaxCPUPercent:     cfg.Load.GeneratorLimits.MaxCPUPercent,
		MaxGoroutines:     cfg.Load.GeneratorLimits.MaxGoroutines,
		MaxOpenFDs:        cfg.Load.GeneratorLimits.MaxOpenFDs,
		MaxEphemeralConns: cfg.Load.GeneratorLimits.MaxEphemeralConns,
	}

	result, err := aggregate.Merge(raws, cfg.Load.Ramp.StepDuration, abort, thresholds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aggregate failed: %v\n", err)
		return 1
	}

	if err := writeReport(cfg, fmt.Sprintf("authload aggregate -c %s --results-dir %s", *path, *resultsDir), result, time.Now().UTC(), "", "", 0, 1, nil); err != nil {
		fmt.Fprintf(os.Stderr, "aggregate failed: %v\n", err)
		return 1
	}
	return 0
}
