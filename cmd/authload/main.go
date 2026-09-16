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
	"time"

	"teleport-auth-stress/internal/collect"
	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/driver"
	"teleport-auth-stress/internal/identity"
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

Omit -y to see the pre-flight summary without generating any load.
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
	default:
		return nil, fmt.Errorf("scenario %q is not yet implemented (see instructions.md milestone M7)", name)
	}
}

func printPreflight(cfg *config.Config) {
	duration := cfg.Load.Ramp.Warmup + cfg.Load.Ramp.StepDuration
	estimatedEvents := int64(cfg.Load.Ramp.StartRPS * duration.Seconds())
	fmt.Printf(`Pre-flight summary (run)
  target proxy:      %s
  required cluster:  %s
  scenario:          %s
  load model:        %s (%s arrival)
  offered rate:      %.1f RPS
  warmup + duration: %v + %v
  est. audit events: ~%d
  fixture state:     %s
  report output:     %s
`, cfg.Target.ProxyAddr, cfg.Target.Guardrail.RequireClusterName, cfg.Load.Scenario, cfg.Load.Model, cfg.Load.Arrival, cfg.Load.Ramp.StartRPS, cfg.Load.Ramp.Warmup, cfg.Load.Ramp.StepDuration, estimatedEvents, cfg.Fixtures.StatePath, cfg.Report.OutputDir)
}

func runRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	path := fs.String("c", "", "path to config YAML")
	confirm := fs.Bool("y", false, "actually run (without this flag, only the pre-flight summary is printed)")
	fs.Parse(args)

	if *path == "" {
		fmt.Fprintln(os.Stderr, "authload run: -c <config.yaml> is required")
		return 2
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

	printPreflight(cfg)
	if !*confirm {
		fmt.Println("\nDry run: pass -y to run.")
		return 3
	}

	if err := runLoad(*path, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "run failed: %v\n", err)
		return 1
	}
	return 0
}

func runLoad(configPath string, cfg *config.Config) error {
	ctx := context.Background()

	sc, err := newScenario(cfg.Load.Scenario)
	if err != nil {
		return err
	}

	fixtures, err := identity.LoadFixtureState(cfg.Fixtures.StatePath)
	if err != nil {
		return fmt.Errorf("loading fixture state (did you run authseed apply?): %w", err)
	}

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

	task := driver.Task(func(ctx context.Context) (scenario.Result, error) {
		return sc.Execute(ctx)
	})

	arrival := driver.Arrival(cfg.Load.Arrival)
	rate := cfg.Load.Ramp.StartRPS

	if warmup := cfg.Load.Ramp.Warmup; warmup > 0 {
		slog.Info("warming up", "duration", warmup, "rate", rate)
		if err := driver.RunOpenLoop(ctx, rate, arrival, warmup, task, func(driver.Sample) {}); err != nil {
			return fmt.Errorf("warmup: %w", err)
		}
	}

	collector := collect.New()
	slog.Info("running measured step", "duration", cfg.Load.Ramp.StepDuration, "rate", rate)
	measuredStart := time.Now()
	if err := driver.RunOpenLoop(ctx, rate, arrival, cfg.Load.Ramp.StepDuration, task, func(s driver.Sample) {
		collector.Add(s.OpenLoopLatency(), s.Result.Outcome, s.Result.Bytes)
	}); err != nil {
		return fmt.Errorf("measured step: %w", err)
	}
	elapsed := time.Since(measuredStart)

	snap := collector.Snapshot(rate, elapsed)
	slog.Info("run complete", "summary", snap.String())

	r := &report.Report{
		Meta: report.Meta{
			HarnessVersion:  report.HarnessVersion,
			GitSHA:          report.GitSHA(),
			StartTime:       measuredStart.UTC(),
			Scenario:        string(cfg.Load.Scenario),
			LoadModel:       string(cfg.Load.Model),
			Arrival:         string(cfg.Load.Arrival),
			TeleportVersion: serverVersion,
			ClusterName:     clusterName,
		},
		Steps:        []report.Step{report.StepFromSnapshot(snap)},
		ReproCommand: fmt.Sprintf("authload run -c %s -y", configPath),
	}

	outPath := filepath.Join(cfg.Report.OutputDir, fmt.Sprintf("report-%s.json", measuredStart.UTC().Format("20060102T150405Z")))
	if err := report.WriteJSON(outPath, r); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	fmt.Printf("\n%s\nReport written to %s\n", snap.String(), outPath)
	return nil
}
