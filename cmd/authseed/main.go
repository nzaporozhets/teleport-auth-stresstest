// Command authseed provisions and tears down the fixtures (users, roles,
// second-factor devices, keypair pool) that authload drives load against.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/identity"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "apply":
		os.Exit(runApply(os.Args[2:]))
	case "teardown":
		os.Exit(runTeardown(os.Args[2:]))
	case "validate":
		os.Exit(runValidate(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "authseed: unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `authseed — teleport-auth-stress fixture provisioning

Usage:
  authseed validate -c <config.yaml>            Validate a config file and exit.
  authseed apply -c <config.yaml> -y            Create users, roles, MFA devices, and the keypair pool.
  authseed teardown -c <config.yaml> -y         Delete every fixture matching fixtures.userPrefix.

Omit -y to see the pre-flight summary without making any change.
`)
}

func runValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	path := fs.String("c", "", "path to config YAML")
	fs.Parse(args)

	if *path == "" {
		fmt.Fprintln(os.Stderr, "authseed validate: -c <config.yaml> is required")
		return 2
	}

	cfg, err := config.LoadAndValidate(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	fmt.Printf("OK: %s is valid (userCount=%d, userPrefix=%s, secondFactor=%s)\n", *path, cfg.Fixtures.UserCount, cfg.Fixtures.UserPrefix, cfg.Fixtures.SecondFactor)
	return 0
}

// printPreflight satisfies the guardrail requirement to print a
// pre-flight summary (target, cluster name, user count, ...) before any
// mutating action, whether or not it's about to actually run.
func printPreflight(action string, cfg *config.Config) {
	// Rough estimate: user create + password/device change each emit at
	// least one audit event; see domain constraint #5.
	estimatedEvents := cfg.Fixtures.UserCount * 3
	fmt.Printf(`Pre-flight summary (%s)
  target proxy:      %s
  required cluster:  %s
  user count:        %d
  user prefix:        %s
  second factor:     %s
  key pool:          %d x %s
  state path:        %s
  est. audit events: ~%d
`, action, cfg.Target.ProxyAddr, cfg.Target.Guardrail.RequireClusterName, cfg.Fixtures.UserCount, cfg.Fixtures.UserPrefix, cfg.Fixtures.SecondFactor, cfg.Fixtures.KeyPool.Size, cfg.Fixtures.KeyPool.Algorithm, cfg.Fixtures.StatePath, estimatedEvents)
}

func runApply(args []string) int {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	path := fs.String("c", "", "path to config YAML")
	confirm := fs.Bool("y", false, "actually apply (without this flag, only the pre-flight summary is printed)")
	fs.Parse(args)

	if *path == "" {
		fmt.Fprintln(os.Stderr, "authseed apply: -c <config.yaml> is required")
		return 2
	}

	cfg, err := config.LoadAndValidate(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	printPreflight("apply", cfg)
	if !*confirm {
		fmt.Println("\nDry run: pass -y to apply.")
		return 3
	}

	ctx := context.Background()
	admin, err := identity.NewAdminClient(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connecting to cluster: %v\n", err)
		return 1
	}
	defer admin.Close()

	result, err := identity.ApplyFixtures(ctx, cfg, admin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply failed: %v\n", err)
		return 1
	}

	fmt.Printf("\nApplied: %d users, %d-entry key pool, state written to %s\n", result.UsersCreated, result.KeyPoolSize, result.StatePath)
	return 0
}

func runTeardown(args []string) int {
	fs := flag.NewFlagSet("teardown", flag.ExitOnError)
	path := fs.String("c", "", "path to config YAML")
	confirm := fs.Bool("y", false, "actually delete (without this flag, only the pre-flight summary is printed)")
	fs.Parse(args)

	if *path == "" {
		fmt.Fprintln(os.Stderr, "authseed teardown: -c <config.yaml> is required")
		return 2
	}

	cfg, err := config.LoadAndValidate(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	printPreflight("teardown", cfg)
	if !*confirm {
		fmt.Println("\nDry run: pass -y to delete every user matching the prefix above.")
		return 3
	}

	ctx := context.Background()
	admin, err := identity.NewAdminClient(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connecting to cluster: %v\n", err)
		return 1
	}
	defer admin.Close()

	deleted, err := identity.TeardownFixtures(ctx, cfg, admin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "teardown failed after deleting %d user(s): %v\n", deleted, err)
		return 1
	}

	fmt.Printf("\nDeleted %d user(s) matching prefix %q\n", deleted, cfg.Fixtures.UserPrefix)
	return 0
}
