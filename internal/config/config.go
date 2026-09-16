// Package config defines the YAML schema for teleport-auth-stress and
// validates it before any network connection is made.
package config

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// RequiredConfirmPhrase is the literal phrase an operator must type into
// target.guardrail.confirmPhrase. It exists so that running against a real
// cluster requires an explicit, hard-to-fat-finger acknowledgement rather
// than a boolean flag that could be left on by default.
const RequiredConfirmPhrase = "I am not in production"

// SecondFactor mirrors the second-factor kinds the harness can drive.
type SecondFactor string

const (
	SecondFactorNone     SecondFactor = "none"
	SecondFactorTOTP     SecondFactor = "totp"
	SecondFactorWebAuthn SecondFactor = "webauthn"
)

// LoadModel selects the arrival control strategy. Open is the default and
// the only one that avoids coordinated omission; closed exists for
// comparison only (see driver package).
type LoadModel string

const (
	LoadModelOpen   LoadModel = "open"
	LoadModelClosed LoadModel = "closed"
)

// ArrivalProcess selects how offered request timestamps are generated
// within the open-loop driver.
type ArrivalProcess string

const (
	ArrivalPoisson ArrivalProcess = "poisson"
	ArrivalUniform ArrivalProcess = "uniform"
)

// KeyAlgorithm is a keypair-pool algorithm accepted by the target cluster's
// certificate signer. Keep this list in sync with what GenerateUserCerts
// actually accepts for the pinned Teleport version.
type KeyAlgorithm string

const (
	KeyAlgorithmECDSA   KeyAlgorithm = "ecdsa"
	KeyAlgorithmEd25519 KeyAlgorithm = "ed25519"
	KeyAlgorithmRSA2048 KeyAlgorithm = "rsa2048"
)

// ScenarioName is a registered Scenario implementation name.
type ScenarioName string

const (
	ScenarioCertRenewal        ScenarioName = "cert-renewal"
	ScenarioLocalLoginWebAuthn ScenarioName = "local-login-webauthn"
	ScenarioLocalLoginTOTP     ScenarioName = "local-login-totp"
	ScenarioBotJoinRenew       ScenarioName = "bot-join-renew"
	ScenarioRouteCertIssuance  ScenarioName = "route-cert-issuance"
	ScenarioMixed              ScenarioName = "mixed"
)

var validScenarios = map[ScenarioName]bool{
	ScenarioCertRenewal:        true,
	ScenarioLocalLoginWebAuthn: true,
	ScenarioLocalLoginTOTP:     true,
	ScenarioBotJoinRenew:       true,
	ScenarioRouteCertIssuance:  true,
	ScenarioMixed:              true,
}

// ReportFormat is an output format the report package can emit.
type ReportFormat string

const (
	ReportFormatJSON     ReportFormat = "json"
	ReportFormatMarkdown ReportFormat = "markdown"
)

// Config is the root of the YAML schema described in instructions.md.
type Config struct {
	Target        Target        `yaml:"target"`
	Identity      Identity      `yaml:"identity"`
	Fixtures      Fixtures      `yaml:"fixtures"`
	Load          LoadSpec      `yaml:"load"`
	Observability Observability `yaml:"observability"`
	Report        Report        `yaml:"report"`
}

type Target struct {
	ProxyAddr string    `yaml:"proxyAddr"`
	AuthAddr  string    `yaml:"authAddr"`
	Cluster   string    `yaml:"cluster"`
	Guardrail Guardrail `yaml:"guardrail"`
	// InsecureSkipVerify disables TLS certificate verification for the
	// proxy web API calls local-login-webauthn/-totp make (M3+). Not in
	// instructions.md's original sketch — added because a disposable
	// kind/dev cluster typically has a self-signed proxy certificate,
	// and the gRPC admin/scenario clients already have their own,
	// separate way of trusting the cluster (identity file / issued CA),
	// which doesn't cover this HTTP path. Defaults to false: a config
	// that omits it is secure by default.
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
}

type Guardrail struct {
	RequireClusterName string `yaml:"requireClusterName"`
	ConfirmPhrase      string `yaml:"confirmPhrase"`
}

type Identity struct {
	AdminIdentityFile string `yaml:"adminIdentityFile"`
}

type Fixtures struct {
	UserCount    int          `yaml:"userCount"`
	UserPrefix   string       `yaml:"userPrefix"`
	Roles        []string     `yaml:"roles"`
	SecondFactor SecondFactor `yaml:"secondFactor"`
	KeyPool      KeyPool      `yaml:"keyPool"`
	// StatePath is where `authseed apply` persists per-user credentials
	// (password, WebAuthn/TOTP secret material) and the keypair pool, so
	// authload can read them later without ever touching the admin
	// identity. Not part of the original config sketch in
	// instructions.md; added because M1 fixture seeding has no other way
	// to hand seeded credentials to the load generator.
	StatePath string `yaml:"statePath"`
}

type KeyPool struct {
	Size      int          `yaml:"size"`
	Algorithm KeyAlgorithm `yaml:"algorithm"`
}

type LoadSpec struct {
	Scenario ScenarioName   `yaml:"scenario"`
	Model    LoadModel      `yaml:"model"`
	Arrival  ArrivalProcess `yaml:"arrival"`
	Ramp     Ramp           `yaml:"ramp"`
	Abort    Abort          `yaml:"abort"`
}

type Ramp struct {
	StartRPS     float64       `yaml:"startRPS"`
	StepRPS      float64       `yaml:"stepRPS"`
	StepDuration time.Duration `yaml:"stepDuration"`
	Warmup       time.Duration `yaml:"warmup"`
	Settle       time.Duration `yaml:"settle"`
	MaxRPS       float64       `yaml:"maxRPS"`
}

type Abort struct {
	P99LatencyMs         float64 `yaml:"p99LatencyMs"`
	ErrorRatePct         float64 `yaml:"errorRatePct"`
	ThroughputDeficitPct float64 `yaml:"throughputDeficitPct"`
	ConsecutiveBadSteps  int     `yaml:"consecutiveBadSteps"`
}

type Observability struct {
	Listen string         `yaml:"listen"`
	Scrape []ScrapeTarget `yaml:"scrape"`
	Pprof  Pprof          `yaml:"pprof"`
}

type ScrapeTarget struct {
	Name     string        `yaml:"name"`
	URL      string        `yaml:"url"`
	Interval time.Duration `yaml:"interval"`
}

type Pprof struct {
	Enabled           bool     `yaml:"enabled"`
	Targets           []string `yaml:"targets"`
	CaptureAtEachStep bool     `yaml:"captureAtEachStep"`
}

type Report struct {
	OutputDir string         `yaml:"outputDir"`
	Formats   []ReportFormat `yaml:"formats"`
}

// Load reads and parses a YAML config file. It does not validate; call
// Validate separately so callers can choose whether a validation failure
// is fatal.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return &cfg, nil
}

// LoadAndValidate reads, parses, and validates a config file in one call.
// It's the entry point CLI subcommands should use.
func LoadAndValidate(path string) (*Config, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}
