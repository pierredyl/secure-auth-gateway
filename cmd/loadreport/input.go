package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Mirrors cmd/loadtest/summary.go. Only the fields the report reads are
// declared; unknown fields are ignored, so the harness can add to the summary
// without breaking this.

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

type phase struct {
	Name            string         `json:"name"`
	WindowStartUTC  time.Time      `json:"window_start_utc"`
	WindowEndUTC    time.Time      `json:"window_end_utc"`
	MeasuredSeconds float64        `json:"measured_seconds"`
	WallSeconds     float64        `json:"wall_seconds"`
	TotalRequests   int            `json:"total_requests"`
	Accepted        int            `json:"accepted"`
	TransportErrors int            `json:"transport_errors"`
	NonOK           int            `json:"non_ok"`
	Failed          int            `json:"failed"`
	RPS             float64        `json:"rps"`
	AcceptedRPS     float64        `json:"accepted_rps"`
	OkStatus        int            `json:"ok_status"`
	OfferedRPS      float64        `json:"offered_rps"`
	All             latencyStats   `json:"all_requests"`
	Acc             latencyStats   `json:"accepted_requests"`
	Errors          map[string]int `json:"errors"`
	Statuses        map[string]int `json:"status_codes"`
	Censored        bool           `json:"censored"`
}

type summary struct {
	SchemaVersion int       `json:"schema_version"`
	StartedUTC    time.Time `json:"started_utc"`
	Concurrency   int       `json:"concurrency"`
	Target        string    `json:"target"`
	Path          string    `json:"path"`
	URL           string    `json:"url"`
	Duration      string    `json:"duration"`
	Warmup        string    `json:"warmup"`
	Think         string    `json:"think"`
	Timeout       string    `json:"timeout"`
	Ramp          string    `json:"ramp"`
	ClosedLoop    bool      `json:"closed_loop"`
	OfferedRate   float64   `json:"offered_rate"`
	Phases        []phase   `json:"phases"`
}

func readSummary(path string) (summary, error) {
	var s summary
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	return s, nil
}

// cpuSample is one container's CPU at one poll.
type cpuSample struct {
	at        time.Time
	container string
	cpu       float64 // docker's CPU%, where 100 is one fully busy core
}

// readCPU parses the collector's CSV: timestamp,container,cpu_percent.
//
// Malformed rows are skipped rather than fatal. docker stats can emit "--" for a
// container that restarted mid-run, and losing one poll is not a reason to lose
// the report.
func readCPU(path string) ([]cpuSample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1

	var out []cpuSample
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		if len(rec) < 3 || strings.EqualFold(strings.TrimSpace(rec[0]), "timestamp") {
			continue
		}
		at, err := time.Parse(time.RFC3339, strings.TrimSpace(rec[0]))
		if err != nil {
			continue
		}
		pct, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(rec[2]), "%"), 64)
		if err != nil {
			continue
		}
		out = append(out, cpuSample{at: at.UTC(), container: strings.TrimSpace(rec[1]), cpu: pct})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable rows in %s", path)
	}
	return out, nil
}

// containerAgg is one container's CPU over the samples that were counted.
type containerAgg struct {
	name string
	avg  float64
	peak float64
	n    int
}

// cpuAgg is the whole saturation picture for one window.
type cpuAgg struct {
	perContainer []containerAgg
	combinedAvg  float64 // mean of the per-timestamp sums
	combinedPeak float64 // max of the per-timestamp sums
	polls        int     // distinct timestamps counted
	interval     time.Duration
	windowed     bool // false when the fallback to whole-run samples was used
	first, last  time.Time
}

// aggregate reduces raw samples to the numbers the saturation section prints.
//
// The combined figure sums per timestamp and then averages, rather than summing
// the per-container averages. Those are the same for the average but not for the
// peak: container peaks do not coincide, so summing individual peaks would invent
// a moment of load that never happened.
func aggregate(samples []cpuSample, start, end time.Time) cpuAgg {
	in := make([]cpuSample, 0, len(samples))
	for _, s := range samples {
		if !s.at.Before(start) && !s.at.After(end) {
			in = append(in, s)
		}
	}

	// Host and VM clocks can drift far enough that the window and the samples do
	// not overlap. Reporting the whole run is worse than reporting the window,
	// but it is much better than reporting nothing — as long as it is labelled.
	windowed := true
	if len(in) < 3 {
		in = samples
		windowed = false
	}

	byContainer := map[string][]float64{}
	byTime := map[time.Time]float64{}
	for _, s := range in {
		byContainer[s.container] = append(byContainer[s.container], s.cpu)
		byTime[s.at] += s.cpu
	}

	agg := cpuAgg{windowed: windowed, polls: len(byTime)}

	for name, vals := range byContainer {
		var sum, peak float64
		for _, v := range vals {
			sum += v
			if v > peak {
				peak = v
			}
		}
		agg.perContainer = append(agg.perContainer, containerAgg{
			name: name, avg: sum / float64(len(vals)), peak: peak, n: len(vals),
		})
	}
	sort.Slice(agg.perContainer, func(i, j int) bool {
		return agg.perContainer[i].avg > agg.perContainer[j].avg
	})

	times := make([]time.Time, 0, len(byTime))
	for t := range byTime {
		times = append(times, t)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })

	var sum float64
	for _, t := range times {
		v := byTime[t]
		sum += v
		if v > agg.combinedPeak {
			agg.combinedPeak = v
		}
	}
	if len(times) > 0 {
		agg.combinedAvg = sum / float64(len(times))
		agg.first, agg.last = times[0], times[len(times)-1]
	}
	if len(times) > 1 {
		agg.interval = agg.last.Sub(agg.first) / time.Duration(len(times)-1)
	}
	return agg
}
