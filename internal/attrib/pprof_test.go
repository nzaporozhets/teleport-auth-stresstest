package attrib

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPProfURL(t *testing.T) {
	cases := map[string]string{
		"https://teleport-auth.teleport.svc.cluster.local:3000/metrics": "https://teleport-auth.teleport.svc.cluster.local:3000/debug/pprof/profile",
		"http://localhost:3000/metrics":                                 "http://localhost:3000/debug/pprof/profile",
	}
	for in, want := range cases {
		if got := PProfURL(in); got != want {
			t.Errorf("PProfURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCaptureCPUProfile_WritesResponseBody(t *testing.T) {
	const fakeProfile = "not a real pprof profile, just bytes to round-trip"
	var gotSecondsParam string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSecondsParam = r.URL.Query().Get("seconds")
		w.Write([]byte(fakeProfile)) //nolint:errcheck
	}))
	defer srv.Close()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "nested", "cpu.pprof")

	err := CaptureCPUProfile(context.Background(), srv.Client(), srv.URL+"/debug/pprof/profile", 5*time.Second, outPath)
	if err != nil {
		t.Fatalf("CaptureCPUProfile: %v", err)
	}
	if gotSecondsParam != "5" {
		t.Errorf("seconds query param = %q, want %q", gotSecondsParam, "5")
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading captured profile: %v", err)
	}
	if string(data) != fakeProfile {
		t.Errorf("captured profile content = %q, want %q", string(data), fakeProfile)
	}
}

func TestCaptureCPUProfile_RejectsTooShortClientTimeout(t *testing.T) {
	client := &http.Client{Timeout: 2 * time.Second}
	err := CaptureCPUProfile(context.Background(), client, "http://example.invalid/debug/pprof/profile", 30*time.Second, "/dev/null")
	if err == nil {
		t.Fatal("expected an error when client.Timeout is shorter than the requested profile duration")
	}
}

func TestCaptureCPUProfile_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	dir := t.TempDir()
	err := CaptureCPUProfile(context.Background(), srv.Client(), srv.URL+"/debug/pprof/profile", time.Second, filepath.Join(dir, "cpu.pprof"))
	if err == nil {
		t.Fatal("expected an error for a non-200 response")
	}
}
