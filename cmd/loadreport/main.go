// Command loadreport turns one load-test run into one markdown report.
//
// It exists because the two halves of a run are measured in different places.
// The harness knows throughput, latency and errors but cannot see the CPU of the
// containers it is hammering; `docker stats` on the host knows the CPU but
// nothing about the measurement window. This merges them: it reads the harness's
// -json summary and the CPU samples collected alongside it, intersects the two on
// wall-clock time, and writes the report.
//
// It is driven by scripts/loadtest.sh and normally not run by hand.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type opts struct {
	jsonPath     string
	cpuPath      string
	outPath      string
	cores        float64
	ceiling      float64
	ceilingLabel string
	ceilingWhy   string
	concurrency  int
	coreRange    string
}

func main() {
	var o opts
	flag.StringVar(&o.jsonPath, "json", "", "path to the harness -json run summary (required)")
	flag.StringVar(&o.cpuPath, "cpu", "", "path to the docker stats CSV: timestamp,container,cpu_percent")
	flag.StringVar(&o.outPath, "out", "", "path to write the markdown report (required)")
	flag.Float64Var(&o.cores, "cores", 8, "cores allocated to the services under test; the saturation denominator")
	flag.StringVar(&o.coreRange, "core-range", "0-7", "label for the pinned cores, for the report text")
	flag.Float64Var(&o.ceiling, "ceiling", 14000, "throughput ceiling to measure headroom against, in req/s")
	flag.StringVar(&o.ceilingLabel, "ceiling-label", "general throughput ceiling", "name of the ceiling, printed in the headroom section")
	flag.StringVar(&o.ceilingWhy, "ceiling-why", "", "one sentence explaining why this ceiling applies to this run")
	flag.IntVar(&o.concurrency, "concurrency", 0, "concurrency level for the header (0 = take it from the summary)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "loadreport merges a loadtest -json summary with docker stats CPU samples\n"+
			"into a single markdown report.\n\nUsage:\n  loadreport -json=<run.json> -cpu=<run_cpu.csv> -out=<run.md> [flags]\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if err := run(o); err != nil {
		fmt.Fprintf(os.Stderr, "loadreport: %v\n", err)
		os.Exit(1)
	}
}

func run(o opts) error {
	if o.jsonPath == "" || o.outPath == "" {
		flag.Usage()
		return fmt.Errorf("-json and -out are required")
	}
	if o.cores <= 0 {
		return fmt.Errorf("-cores must be positive")
	}

	sum, err := readSummary(o.jsonPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", o.jsonPath, err)
	}
	if len(sum.Phases) == 0 {
		return fmt.Errorf("%s contains no phases — the run produced no data", o.jsonPath)
	}

	// CPU is best-effort. A run whose collector failed is still worth a report
	// with three of its four sections intact, as long as it says so plainly
	// rather than printing zeroes.
	var cpu []cpuSample
	var cpuErr error
	if o.cpuPath != "" {
		cpu, cpuErr = readCPU(o.cpuPath)
	} else {
		cpuErr = fmt.Errorf("no -cpu file given")
	}

	if o.concurrency == 0 {
		o.concurrency = sum.Concurrency
	}

	var b strings.Builder
	writeReport(&b, o, sum, cpu, cpuErr)

	if dir := filepath.Dir(o.outPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(o.outPath, []byte(b.String()), 0o644)
}

// headline picks the phase the summary and headroom sections describe. A login
// run produces a limiter phase as well, but the limiter phase is deliberately
// throttled — capacity questions are only meaningful against the compute one.
func (s summary) headline() phase {
	for _, p := range s.Phases {
		if p.Name == "compute" || p.Name == "health" {
			return p
		}
	}
	return s.Phases[len(s.Phases)-1]
}
