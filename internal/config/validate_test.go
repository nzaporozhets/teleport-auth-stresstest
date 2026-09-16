package config

import (
	"strings"
	"testing"
)

func TestLoadAndValidate_Good(t *testing.T) {
	cfg, err := LoadAndValidate("testdata/good.yaml")
	if err != nil {
		t.Fatalf("expected good.yaml to validate, got: %v", err)
	}
	if cfg.Target.Cluster != "loadtest" {
		t.Errorf("unexpected cluster: %q", cfg.Target.Cluster)
	}
}

func TestLoadAndValidate_Broken(t *testing.T) {
	cases := []struct {
		file      string
		wantInErr string
	}{
		{"testdata/bad-cluster-name.yaml", "requireClusterName"},
		{"testdata/bad-confirm-phrase.yaml", "confirmPhrase"},
		{"testdata/bad-second-factor.yaml", "secondFactor"},
		{"testdata/bad-ramp.yaml", "maxRPS"},
		{"testdata/bad-scenario.yaml", "scenario"},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			_, err := LoadAndValidate(tc.file)
			if err == nil {
				t.Fatalf("expected validation error for %s, got nil", tc.file)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("error for %s = %q, want it to mention %q", tc.file, err.Error(), tc.wantInErr)
			}
		})
	}
}

// goodConfig loads testdata/good.yaml unvalidated, as a baseline for
// tests that mutate one field and check Validate()'s reaction, without
// re-declaring the whole schema inline or diluting M0's "5 deliberately
// broken configs" acceptance criterion with unrelated cases.
func goodConfig(t *testing.T) *Config {
	t.Helper()
	cfg, err := Load("testdata/good.yaml")
	if err != nil {
		t.Fatalf("Load(good.yaml): %v", err)
	}
	return cfg
}

func TestValidate_BotCountNegativeRejected(t *testing.T) {
	cfg := goodConfig(t)
	cfg.Fixtures.BotCount = -1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "botCount") {
		t.Errorf("expected a botCount error, got %v", err)
	}
}

func TestValidate_BotCountZeroIsValid(t *testing.T) {
	cfg := goodConfig(t)
	cfg.Fixtures.BotCount = 0
	if err := cfg.Validate(); err != nil {
		t.Errorf("botCount=0 (\"use the default\") should be valid, got %v", err)
	}
}

func TestValidate_RouteCertIssuance(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*Config)
		wantInErr string
	}{
		{
			name: "bad route type",
			mutate: func(c *Config) {
				c.Load.RouteCertIssuance = RouteCertIssuance{RouteType: "ssh", Target: "x"}
			},
			wantInErr: "routeType",
		},
		{
			name: "missing target",
			mutate: func(c *Config) {
				c.Load.RouteCertIssuance = RouteCertIssuance{RouteType: RouteTypeApp}
			},
			wantInErr: "target",
		},
		{
			name: "database without protocol",
			mutate: func(c *Config) {
				c.Load.RouteCertIssuance = RouteCertIssuance{RouteType: RouteTypeDatabase, Target: "pg"}
			},
			wantInErr: "databaseProtocol",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := goodConfig(t)
			cfg.Load.Scenario = ScenarioRouteCertIssuance
			tc.mutate(cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("expected an error mentioning %q, got %v", tc.wantInErr, err)
			}
		})
	}
}

func TestValidate_RouteCertIssuance_ValidDatabaseRoute(t *testing.T) {
	cfg := goodConfig(t)
	cfg.Load.Scenario = ScenarioRouteCertIssuance
	cfg.Load.RouteCertIssuance = RouteCertIssuance{RouteType: RouteTypeDatabase, Target: "pg", DatabaseProtocol: "postgres"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected a valid database route to pass, got %v", err)
	}
}

func TestValidate_Mixed(t *testing.T) {
	cases := []struct {
		name      string
		weights   map[ScenarioName]float64
		wantInErr string
	}{
		{"too few", map[ScenarioName]float64{ScenarioCertRenewal: 1}, "at least two"},
		{"unknown scenario", map[ScenarioName]float64{ScenarioCertRenewal: 1, "not-a-scenario": 1}, "not a scenario mixed can blend"},
		{"nested mixed", map[ScenarioName]float64{ScenarioCertRenewal: 1, ScenarioMixed: 1}, "not a scenario mixed can blend"},
		{"zero weight", map[ScenarioName]float64{ScenarioCertRenewal: 1, ScenarioLocalLoginWebAuthn: 0}, "must be > 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := goodConfig(t)
			cfg.Load.Scenario = ScenarioMixed
			cfg.Load.Mixed = Mixed{Weights: tc.weights}
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("expected an error mentioning %q, got %v", tc.wantInErr, err)
			}
		})
	}
}

func TestValidate_Mixed_ValidWeights(t *testing.T) {
	cfg := goodConfig(t)
	cfg.Load.Scenario = ScenarioMixed
	cfg.Load.Mixed = Mixed{Weights: map[ScenarioName]float64{
		ScenarioCertRenewal:        1,
		ScenarioLocalLoginWebAuthn: 3,
	}}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid mixed weights to pass, got %v", err)
	}
}

func TestValidate_AggregatesAllErrors(t *testing.T) {
	cfg := &Config{} // everything empty
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty config")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if len(ve.Errors) < 5 {
		t.Errorf("expected many aggregated errors for an empty config, got %d: %v", len(ve.Errors), ve.Errors)
	}
}
