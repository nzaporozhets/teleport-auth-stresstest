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
