package attrib

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PProfURL derives the pprof CPU-profile endpoint from a /metrics
// scrape URL, on the assumption that both are served by the same
// diagnostic listener — Teleport's auth/proxy `diag_addr` serves
// `/metrics` and `/debug/pprof/*` side by side (standard `net/http/pprof`
// registration on the same mux). If a target ever splits these across
// different listeners, this needs a separate config field instead.
func PProfURL(metricsURL string) string {
	base := strings.TrimSuffix(metricsURL, "/metrics")
	return base + "/debug/pprof/profile"
}

// CaptureCPUProfile fetches a CPU profile of the given duration from a
// pprof profile endpoint (as returned by PProfURL) and writes the raw
// pprof-format bytes to outPath. The server blocks for the full
// duration before responding, so client must have no Timeout (or one
// comfortably longer than duration) — this is checked explicitly rather
// than surfacing as a confusing mid-capture timeout error.
func CaptureCPUProfile(ctx context.Context, client *http.Client, url string, duration time.Duration, outPath string) error {
	if client.Timeout > 0 && client.Timeout <= duration {
		return fmt.Errorf("http client timeout (%v) must be greater than the requested profile duration (%v)", client.Timeout, duration)
	}

	reqURL := fmt.Sprintf("%s?seconds=%d", url, int(duration.Seconds()))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", reqURL, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("capturing profile from %s: %w", reqURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("capturing profile from %s: unexpected status %d", reqURL, resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(outPath), err)
	}
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", outPath, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("writing profile to %s: %w", outPath, err)
	}
	return nil
}
