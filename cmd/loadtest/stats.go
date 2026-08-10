package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// sample is one request/response round trip. Recorded per virtual user in an
// unshared slice, then merged once the phase is over.
type sample struct {
	at      time.Time     // when the request was sent, relative timing for 429 onset
	ip      string        // spoofed X-Forwarded-For value we sent
	latency time.Duration // Do() plus draining the body
	status  int           // 0 when err != nil
	err     error
	// Which throttle produced a 429. The server has two that answer with the
	// same status, and conflating them makes a run look broken when it isn't.
	throttle throttleKind
}

type throttleKind string

const (
	throttleNone    throttleKind = ""
	throttleIP      throttleKind = "ip limiter"
	throttleAccount throttleKind = "account lockout"
)

// errKind buckets transport failures so "server is slow" reads differently from
// "server fell over".
type errKind string

const (
	errNone      errKind = ""
	errTimeout   errKind = "timeout"
	errRefused   errKind = "connection refused"
	errResetEOF  errKind = "reset / EOF"
	errOtherKind errKind = "other"
)

func classify(err error) errKind {
	if err == nil {
		return errNone
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return errTimeout
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return errRefused
	case strings.Contains(msg, "EOF"),
		strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "broken pipe"):
		return errResetEOF
	default:
		return errOtherKind
	}
}

// result is everything one phase produced.
type result struct {
	name     string
	samples  []sample
	wall     time.Duration
	okStatus int // success code for this endpoint: login answers 201, health 200
	ipCount  int // size of the IP bucket, 0 when every request used a fresh IP
	rateHdrs string
}

// latencies pulls the latency of every sample matching status, sorted ascending.
func (r *result) latencies(status int) []time.Duration {
	out := make([]time.Duration, 0, len(r.samples))
	for _, s := range r.samples {
		if s.err == nil && s.status == status {
			out = append(out, s.latency)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// percentile expects sorted input. p is 0..100.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	// Nearest-rank: the smallest value at or above the p-th position.
	idx := int(p / 100 * float64(len(sorted)))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func mean(vals []time.Duration) time.Duration {
	if len(vals) == 0 {
		return 0
	}
	var total time.Duration
	for _, v := range vals {
		total += v
	}
	return total / time.Duration(len(vals))
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
}

// latencyLine renders the min/max/percentile row for one status class.
func latencyLine(label string, sorted []time.Duration) string {
	if len(sorted) == 0 {
		return fmt.Sprintf("  %-18s (none)", label)
	}
	return fmt.Sprintf("  %-18s n=%-7d min=%-9s max=%-9s mean=%-9s p50=%-9s p95=%-9s p99=%s",
		label, len(sorted),
		ms(sorted[0]), ms(sorted[len(sorted)-1]), ms(mean(sorted)),
		ms(percentile(sorted, 50)), ms(percentile(sorted, 95)), ms(percentile(sorted, 99)))
}

func (r *result) report(w io.Writer) {
	fmt.Fprintf(w, "\n=== %s phase ===\n", r.name)

	statuses := map[int]int{}
	errs := map[errKind]int{}
	throttles := map[throttleKind]int{}
	for _, s := range r.samples {
		if s.err != nil {
			errs[classify(s.err)]++
			continue
		}
		statuses[s.status]++
		if s.throttle != throttleNone {
			throttles[s.throttle]++
		}
	}

	total := len(r.samples)
	accepted := statuses[r.okStatus]
	secs := r.wall.Seconds()
	fmt.Fprintf(w, "duration=%s  requests=%d  rps=%.1f  accepted-rps=%.1f\n",
		r.wall.Round(time.Millisecond), total, float64(total)/secs, float64(accepted)/secs)

	// A 429 is rejected in middleware before Argon2id runs, so folding it into a
	// single average would hide the only number that matters here.
	fmt.Fprintln(w, "latency:")
	fmt.Fprintln(w, latencyLine(fmt.Sprintf("%d accepted", r.okStatus), r.latencies(r.okStatus)))
	fmt.Fprintln(w, latencyLine("429 rejected", r.latencies(429)))

	fmt.Fprint(w, "status codes: ")
	codes := make([]int, 0, len(statuses))
	for c := range statuses {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	if len(codes) == 0 {
		fmt.Fprint(w, "(none)")
	}
	for i, c := range codes {
		if i > 0 {
			fmt.Fprint(w, "  ")
		}
		fmt.Fprintf(w, "%d=%d", c, statuses[c])
	}
	fmt.Fprintln(w)

	if len(throttles) > 0 {
		fmt.Fprint(w, "429 breakdown: ")
		for _, k := range []throttleKind{throttleIP, throttleAccount} {
			if throttles[k] > 0 {
				fmt.Fprintf(w, "%s=%d  ", k, throttles[k])
			}
		}
		fmt.Fprintln(w)
	}

	if len(errs) > 0 {
		fmt.Fprint(w, "transport errors: ")
		for _, k := range []errKind{errTimeout, errRefused, errResetEOF, errOtherKind} {
			if errs[k] > 0 {
				fmt.Fprintf(w, "%s=%d  ", k, errs[k])
			}
		}
		fmt.Fprintln(w)
	}

	if r.ipCount > 0 {
		r.reportLimiter(w)
		return
	}

	// Every request in this phase used a fresh IP, so the IP limiter should be
	// silent. If it isn't, the spoofing has stopped reaching it.
	if throttles[throttleIP] > 0 {
		fmt.Fprintf(w, "\n!! WARNING: %d responses hit the IP limiter in a phase that uses a unique IP\n"+
			"!! per request. The spoofed X-Forwarded-For is not reaching it, so the latency\n"+
			"!! numbers above do NOT reflect real endpoint cost.\n", throttles[throttleIP])
	}
	// Account lockouts are a different story: one poisoned account taints every
	// request that happens to pick it, which skews throughput without being a
	// harness bug.
	if throttles[throttleAccount] > 0 {
		fmt.Fprintf(w, "\n!! NOTE: %d responses were account lockouts. One or more test accounts is locked\n"+
			"!! from earlier failed logins, so that share of the run never reached the password\n"+
			"!! check and throughput above is understated. Lockouts are cleared automatically\n"+
			"!! unless -keep-lockouts is set, or the -redis address is unreachable.\n",
			throttles[throttleAccount])
	}
}

// reportLimiter covers the questions only the bucketed phase can answer: did each
// IP get its own window, and did it admit the number of requests it should have.
func (r *result) reportLimiter(w io.Writer) {
	admitted := map[string]int{}
	firstReq := map[string]time.Time{}
	first429 := map[string]time.Time{}

	for _, s := range r.samples {
		if s.err != nil {
			continue
		}
		if t, ok := firstReq[s.ip]; !ok || s.at.Before(t) {
			firstReq[s.ip] = s.at
		}
		switch s.status {
		case r.okStatus:
			admitted[s.ip]++
		case 429:
			if t, ok := first429[s.ip]; !ok || s.at.Before(t) {
				first429[s.ip] = s.at
			}
		}
	}

	counts := make([]int, 0, r.ipCount)
	for _, ip := range bucketAddrs(r.ipCount) {
		counts = append(counts, admitted[ip]) // absent IPs count as 0, which is itself a finding
	}
	sort.Ints(counts)

	fmt.Fprintf(w, "limiter: bucket=%d IPs   limit=%d req / %s\n", r.ipCount, rateLimitReqs, rateLimitWindow)
	if len(counts) > 0 {
		expected := rateLimitReqs * (r.wall.Minutes() + 1) // +1 for the window open at t=0
		fmt.Fprintf(w, "  admitted per IP:  min=%d  median=%d  max=%d  (expected up to ~%.0f)\n",
			counts[0], counts[len(counts)/2], counts[len(counts)-1], expected)
	}

	var onsets []time.Duration
	for ip, t := range first429 {
		onsets = append(onsets, t.Sub(firstReq[ip]))
	}
	sort.Slice(onsets, func(i, j int) bool { return onsets[i] < onsets[j] })
	if len(onsets) > 0 {
		fmt.Fprintf(w, "  time to first 429: median=%s  (%d of %d IPs hit the limit)\n",
			ms(percentile(onsets, 50)), len(onsets), r.ipCount)
	} else {
		fmt.Fprintf(w, "  no IP ever hit the limit — raise -users or lower -ips to apply pressure\n")
	}

	if r.rateHdrs != "" {
		fmt.Fprintf(w, "  429 headers: %s\n", r.rateHdrs)
	}
}

// writeCSV dumps raw samples so a run can be re-analysed outside the harness.
func writeCSV(path string, results []*result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	cw := csv.NewWriter(f)
	defer cw.Flush()

	if err := cw.Write([]string{"phase", "sent_at", "ip", "latency_ms", "status", "error"}); err != nil {
		return err
	}
	for _, r := range results {
		for _, s := range r.samples {
			errStr := ""
			if s.err != nil {
				errStr = s.err.Error()
			}
			rec := []string{
				r.name,
				s.at.Format(time.RFC3339Nano),
				s.ip,
				strconv.FormatFloat(float64(s.latency.Microseconds())/1000, 'f', 3, 64),
				strconv.Itoa(s.status),
				errStr,
			}
			if err := cw.Write(rec); err != nil {
				return err
			}
		}
	}
	return cw.Error()
}
