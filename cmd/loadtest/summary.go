package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// A machine-readable version of what report() prints.
//
// It exists because the stdout report is the wrong shape for two consumers at
// once: a person reading a run, and cmd/loadreport merging the run with CPU
// samples collected outside the process. Rather than parse formatted text, the
// harness writes the same numbers as JSON. Everything here is derived from the
// existing accessors — windowed, allLatencies, latencies, percentile, mean and
// classify — so the summary and the printed report can never disagree.

// latencyStats is one distribution, in milliseconds. Milliseconds rather than
// time.Duration because the consumer formats them for a report and a raw
// nanosecond integer in JSON is unreadable when eyeballing the file.
type latencyStats struct {
	N    int     `json:"n"`
	Min  float64 `json:"min_ms"`
	P50  float64 `json:"p50_ms"`
	P95  float64 `json:"p95_ms"`
	P99  float64 `json:"p99_ms"`
	P999 float64 `json:"p999_ms"`
	Max  float64 `json:"max_ms"`
	Mean float64 `json:"mean_ms"`
}

// phaseSummary is one phase's numbers. A login run produces two of these
// (limiter, compute); a health run produces one.
type phaseSummary struct {
	Name string `json:"name"`

	// The measured window in wall-clock UTC. cmd/loadreport intersects the CPU
	// samples with this, so saturation covers the same seconds the latency and
	// throughput figures do.
	WindowStartUTC time.Time `json:"window_start_utc"`
	WindowEndUTC   time.Time `json:"window_end_utc"`

	MeasuredSeconds float64 `json:"measured_seconds"`
	WallSeconds     float64 `json:"wall_seconds"`

	// A request counts as failed if it errored in transport OR did not answer
	// OkStatus. The two are kept apart because a 502 and a timeout are both
	// failures with completely different causes.
	TotalRequests   int `json:"total_requests"`
	Accepted        int `json:"accepted"`
	TransportErrors int `json:"transport_errors"`
	NonOK           int `json:"non_ok"`
	Failed          int `json:"failed"`

	RPS         float64 `json:"rps"`
	AcceptedRPS float64 `json:"accepted_rps"`
	OkStatus    int     `json:"ok_status"`
	OfferedRPS  float64 `json:"offered_rps,omitempty"`

	// All includes failed and timed-out requests at their measured latency, and
	// is the honest headline; Acc covers successes only. See allLatencies for
	// why excluding failures flatters the tail.
	All latencyStats `json:"all_requests"`
	Acc latencyStats `json:"accepted_requests"`

	Errors   map[string]int `json:"errors"`
	Statuses map[string]int `json:"status_codes"`

	// Censored means the slowest request was pressed up against -timeout, so the
	// tail was cut off rather than measured and p99.9/max are floors.
	Censored bool `json:"censored"`
}

// runSummary is one invocation of the harness.
type runSummary struct {
	SchemaVersion int       `json:"schema_version"`
	StartedUTC    time.Time `json:"started_utc"`

	Concurrency int    `json:"concurrency"`
	Target      string `json:"target"`
	Path        string `json:"path"`
	URL         string `json:"url"`

	Duration string `json:"duration"`
	Warmup   string `json:"warmup"`
	Think    string `json:"think"`
	Timeout  string `json:"timeout"`
	Ramp     string `json:"ramp"`

	ClosedLoop  bool    `json:"closed_loop"`
	OfferedRate float64 `json:"offered_rate,omitempty"`

	Phases []phaseSummary `json:"phases"`
}

// toMS renders a duration the way the report reads it.
func toMS(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// statsFor packages an already-sorted latency slice.
func statsFor(sorted []time.Duration) latencyStats {
	if len(sorted) == 0 {
		return latencyStats{}
	}
	return latencyStats{
		N:    len(sorted),
		Min:  toMS(sorted[0]),
		P50:  toMS(percentile(sorted, 50)),
		P95:  toMS(percentile(sorted, 95)),
		P99:  toMS(percentile(sorted, 99)),
		P999: toMS(percentile(sorted, 99.9)),
		Max:  toMS(sorted[len(sorted)-1]),
		Mean: toMS(mean(sorted)),
	}
}

// summarize collapses a phase into the numbers a report needs. It mirrors the
// counting loop at the top of report() deliberately: same source, same window,
// same definitions.
func (r *result) summarize() phaseSummary {
	windowed := r.windowed()

	statuses := map[string]int{}
	errs := map[string]int{}
	transport := 0
	for _, s := range windowed {
		if s.err != nil {
			errs[string(classify(s.err))]++
			transport++
			continue
		}
		statuses[strconv.Itoa(s.status)]++
	}

	total := len(windowed)
	accepted := statuses[strconv.Itoa(r.okStatus)]
	nonOK := total - transport - accepted

	secs := r.measured.Seconds()
	if secs <= 0 {
		secs = r.wall.Seconds()
	}
	if secs <= 0 {
		secs = 1 // a zero-length window would make every rate +Inf
	}

	all := r.allLatencies()
	censored := false
	if len(all) > 0 && r.timeout > 0 {
		censored = all[len(all)-1] >= time.Duration(float64(r.timeout)*0.98)
	}

	return phaseSummary{
		Name:            r.name,
		WindowStartUTC:  r.windowStart.UTC(),
		WindowEndUTC:    r.windowEnd.UTC(),
		MeasuredSeconds: r.measured.Seconds(),
		WallSeconds:     r.wall.Seconds(),
		TotalRequests:   total,
		Accepted:        accepted,
		TransportErrors: transport,
		NonOK:           nonOK,
		Failed:          transport + nonOK,
		RPS:             float64(total) / secs,
		AcceptedRPS:     float64(accepted) / secs,
		OkStatus:        r.okStatus,
		OfferedRPS:      r.offered,
		All:             statsFor(all),
		Acc:             statsFor(r.latencies(r.okStatus)),
		Errors:          errs,
		Statuses:        statuses,
		Censored:        censored,
	}
}

// writeSummary serialises the whole run. The directory is created if missing —
// the report path is built by the runner script and may name a fresh results
// directory.
func writeSummary(path string, cfg config, results []*result) error {
	sum := runSummary{
		SchemaVersion: 1,
		StartedUTC:    time.Now().UTC(),
		Concurrency:   cfg.users,
		Target:        cfg.target,
		Path:          cfg.path,
		URL:           cfg.baseURL,
		Duration:      cfg.duration.String(),
		Warmup:        cfg.warmup.String(),
		Think:         cfg.think.String(),
		Timeout:       cfg.timeout.String(),
		Ramp:          cfg.ramp.String(),
		ClosedLoop:    !cfg.openLoop(),
		OfferedRate:   cfg.rate,
	}
	if sum.Path == "" && cfg.target == "health" {
		sum.Path = "/api/v1/health"
	}
	if sum.Path == "" && cfg.target == "login" {
		sum.Path = "/api/v1/auth/login"
	}
	// StartedUTC is stamped at write time, which is the end of the run. Back it
	// up to the first window so the filename timestamp and the header agree.
	if len(results) > 0 && !results[0].windowStart.IsZero() {
		sum.StartedUTC = results[0].windowStart.UTC()
	}

	for _, r := range results {
		if r == nil {
			continue
		}
		sum.Phases = append(sum.Phases, r.summarize())
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
