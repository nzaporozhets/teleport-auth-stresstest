package ramp

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// GeneratorHealth is one point-in-time reading of the load generator's
// own resource usage. Domain constraint #7: a breaking point is only
// real if the generator wasn't the thing that broke.
type GeneratorHealth struct {
	CPUPercent     float64 // process CPU utilization, 0-100+ (>100 possible with multiple cores)
	Goroutines     int
	OpenFDs        int
	EphemeralConns int // approximate: TCP sockets in this process's network namespace
}

// GeneratorThresholds are the limits that, if crossed, mark a run
// generator-limited.
type GeneratorThresholds struct {
	MaxCPUPercent     float64
	MaxGoroutines     int
	MaxOpenFDs        int
	MaxEphemeralConns int
}

// Exceeds reports whether h crosses any threshold in t, and why.
func (h GeneratorHealth) Exceeds(t GeneratorThresholds) (bool, []string) {
	var reasons []string
	if t.MaxCPUPercent > 0 && h.CPUPercent > t.MaxCPUPercent {
		reasons = append(reasons, fmt.Sprintf("generator CPU %.1f%% exceeds threshold %.1f%%", h.CPUPercent, t.MaxCPUPercent))
	}
	if t.MaxGoroutines > 0 && h.Goroutines > t.MaxGoroutines {
		reasons = append(reasons, fmt.Sprintf("goroutine count %d exceeds threshold %d", h.Goroutines, t.MaxGoroutines))
	}
	if t.MaxOpenFDs > 0 && h.OpenFDs > t.MaxOpenFDs {
		reasons = append(reasons, fmt.Sprintf("open file descriptors %d exceeds threshold %d", h.OpenFDs, t.MaxOpenFDs))
	}
	if t.MaxEphemeralConns > 0 && h.EphemeralConns > t.MaxEphemeralConns {
		reasons = append(reasons, fmt.Sprintf("ephemeral connections %d exceeds threshold %d", h.EphemeralConns, t.MaxEphemeralConns))
	}
	return len(reasons) > 0, reasons
}

// worst combines two readings by taking the max of each field —
// used to summarize a step's worst moment rather than its average,
// since a brief saturation spike is exactly what this exists to catch.
func worst(a, b GeneratorHealth) GeneratorHealth {
	return GeneratorHealth{
		CPUPercent:     maxFloat(a.CPUPercent, b.CPUPercent),
		Goroutines:     maxInt(a.Goroutines, b.Goroutines),
		OpenFDs:        maxInt(a.OpenFDs, b.OpenFDs),
		EphemeralConns: maxInt(a.EphemeralConns, b.EphemeralConns),
	}
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// HealthSampler produces one GeneratorHealth reading. Implementations
// must not panic and should degrade gracefully (returning a zero-ish
// reading) rather than fail the run if a metric is unavailable on the
// current platform.
type HealthSampler interface {
	Sample() GeneratorHealth
}

// procSampler samples generator health from /proc, as this toolkit is
// deployed to Linux (Kubernetes) pods (see instructions.md
// "Distributed execution"). It degrades gracefully on any other
// platform or on any read error: CPUPercent/OpenFDs/EphemeralConns come
// back zero rather than failing the run, so a threshold with a nonzero
// max would simply never trigger, and the caller should treat a zero
// GeneratorThresholds field as "don't check this metric" accordingly
// (Exceeds already only checks fields with max > 0).
type procSampler struct {
	lastCPUTime time.Duration
	lastWall    time.Time
}

// NewOSHealthSampler returns the real, process-local HealthSampler used
// by cmd/authload. Tests use a fake HealthSampler instead.
func NewOSHealthSampler() HealthSampler {
	return &procSampler{lastWall: time.Now()}
}

func (s *procSampler) Sample() GeneratorHealth {
	now := time.Now()
	cpuTime, cpuErr := readProcessCPUTime()

	var cpuPercent float64
	if cpuErr == nil {
		wallDelta := now.Sub(s.lastWall)
		cpuDelta := cpuTime - s.lastCPUTime
		if wallDelta > 0 {
			cpuPercent = 100 * float64(cpuDelta) / float64(wallDelta)
		}
	}
	s.lastWall = now
	s.lastCPUTime = cpuTime

	openFDs, _ := countOpenFDs()
	conns, _ := countEphemeralConns()

	return GeneratorHealth{
		CPUPercent:     cpuPercent,
		Goroutines:     runtime.NumGoroutine(),
		OpenFDs:        openFDs,
		EphemeralConns: conns,
	}
}

// clockTicksPerSecond is USER_HZ, needed to convert /proc/self/stat's
// utime/stime (in clock ticks) to a duration. This is 100 on every
// mainstream Linux distribution on every architecture this toolkit
// targets; getting the exact value would require cgo (sysconf), which
// isn't worth it for an approximate health signal — see Exceeds, which
// only gates on this when a nonzero MaxCPUPercent is configured.
const clockTicksPerSecond = 100

func readProcessCPUTime() (time.Duration, error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	line := string(data)

	// Field 2 (comm) is parenthesized and may itself contain spaces or
	// parens, so skip past the LAST ')' rather than naively splitting on
	// spaces from the start of the line.
	idx := strings.LastIndexByte(line, ')')
	if idx < 0 || idx+2 > len(line) {
		return 0, fmt.Errorf("unexpected /proc/self/stat format")
	}
	fields := strings.Fields(line[idx+1:])
	// After the comm field, utime is the 12th field (index 11) and
	// stime is the 13th (index 12): state, ppid, pgrp, session, tty_nr,
	// tpgid, flags, minflt, cminflt, majflt, cmajflt, utime, stime, ...
	const utimeIdx, stimeIdx = 11, 12
	if len(fields) <= stimeIdx {
		return 0, fmt.Errorf("unexpected /proc/self/stat field count: %d", len(fields))
	}
	utime, err := strconv.ParseInt(fields[utimeIdx], 10, 64)
	if err != nil {
		return 0, err
	}
	stime, err := strconv.ParseInt(fields[stimeIdx], 10, 64)
	if err != nil {
		return 0, err
	}
	ticks := utime + stime
	return time.Duration(ticks) * time.Second / clockTicksPerSecond, nil
}

func countOpenFDs() (int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

// countEphemeralConns counts TCP sockets visible in this process's
// network namespace via /proc/net/{tcp,tcp6}. This is namespace-wide,
// not strictly per-PID (Linux has no cheap per-PID socket list without
// resolving every /proc/self/fd symlink against socket inodes) — an
// acceptable approximation given the deployment model this toolkit
// assumes: one generator process per pod, so its network namespace is
// its own.
func countEphemeralConns() (int, error) {
	total := 0
	found := false
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		n, err := countLinesAfterHeader(path)
		if err != nil {
			continue
		}
		found = true
		total += n
	}
	if !found {
		return 0, fmt.Errorf("neither /proc/net/tcp nor /proc/net/tcp6 was readable")
	}
	return total, nil
}

func countLinesAfterHeader(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := -1 // first line is the header
	for scanner.Scan() {
		count++
	}
	if count < 0 {
		count = 0
	}
	return count, scanner.Err()
}
