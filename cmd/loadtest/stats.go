package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
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
	at      time.Time     // when the request was actually sent
	ip      string        // spoofed X-Forwarded-For value we sent
	latency time.Duration // Do() plus draining the body
	status  int           // 0 when err != nil
	err     error
	// Which throttle produced a 429. The server has two that answer with the
	// same status, and conflating them makes a run look broken when it isn't.
	throttle throttleKind

	// scheduledAt is when open-loop mode intended to send this request. Zero in
	// closed-loop mode, where there is no schedule to fall behind. The gap
	// between it and at is how late the generator was, which is the difference
	// between "the server is slow" and "we never asked it in time".
	scheduledAt time.Time

	// inWindow marks samples inside the measurement window: after ramp and
	// warmup, before the window closes. Everything is kept for the CSV; only
	// these feed the statistics.
	inWindow bool

	// connReused reports whether this request went out on an already-open
	// connection. A slow request that had to open a new one was delayed by
	// plumbing rather than by the service, and that is worth being able to tell
	// apart when explaining a tail.
	connReused bool
}

// schedLag is how late this request went out against its intended slot. Always
// zero in closed-loop mode.
func (s sample) schedLag() time.Duration {
	if s.scheduledAt.IsZero() {
		return 0
	}
	if d := s.at.Sub(s.scheduledAt); d > 0 {
		return d
	}
	return 0
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
	errCapacity  errKind = "not sent (over capacity)"
	errOtherKind errKind = "other"
)

func classify(err error) errKind {
	if err == nil {
		return errNone
	}
	// Never left the harness, so it is not a network failure and lumping it in
	// with "other" makes an over-capacity run look like a mystery.
	if errors.Is(err, errInFlightCap) {
		return errCapacity
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
	wall     time.Duration // ramp + warmup + measured window + drain
	measured time.Duration // the window statistics are computed over
	okStatus int           // success code for this endpoint: login answers 201, health 200
	ipCount  int           // size of the IP bucket, 0 when every request used a fresh IP
	rateHdrs string
	timeout  time.Duration // per-request timeout, for detecting a censored tail
	offered  float64       // open-loop target rate; 0 in closed-loop mode

	// windowStart and windowEnd bracket the measured window in wall-clock time.
	// markWindow already computes that boundary and then throws it away; keeping
	// it is what lets an outside sampler — the CPU collector in scripts/loadtest.sh
	// — be lined up against the same window the latency numbers came from,
	// instead of averaging warmup and drain into the saturation figure.
	windowStart time.Time
	windowEnd   time.Time
}

// windowed returns the samples statistics are computed over.
func (r *result) windowed() []sample {
	out := make([]sample, 0, len(r.samples))
	for _, s := range r.samples {
		if s.inWindow {
			out = append(out, s)
		}
	}
	return out
}

// latencies pulls the latency of every in-window sample matching status, sorted
// ascending. Successes only — see allLatencies for the honest version.
func (r *result) latencies(status int) []time.Duration {
	out := make([]time.Duration, 0, len(r.samples))
	for _, s := range r.samples {
		if s.inWindow && s.err == nil && s.status == status {
			out = append(out, s.latency)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// allLatencies includes failed and timed-out requests at their measured latency.
//
// This is the headline number, and it exists because excluding them is a lie in
// the dangerous direction: a request that timed out took the full -timeout to
// fail, and that is a real delay a real user sat through. Dropping those samples
// caps the reported p99 at -timeout no matter how bad things get, and lets the
// percentiles *improve* under load as the slowest requests are deleted rather
// than counted.
func (r *result) allLatencies() []time.Duration {
	out := make([]time.Duration, 0, len(r.samples))
	for _, s := range r.samples {
		if s.inWindow && s.timed() {
			out = append(out, s.latency)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// timed reports whether this sample has a latency worth including in a
// distribution. A request rejected by the in-flight cap never went out, so its
// latency is zero — and folding a pile of zeroes into the percentiles drags the
// median toward nothing while the service is at its worst. It counts as an
// error, not as a fast request.
func (s sample) timed() bool { return !errors.Is(s.err, errInFlightCap) }

// correctedLatencies measures from the slot a request was *meant* to go out in,
// not from when it actually did. Open-loop only.
//
// This is what a user in line experiences: if the generator could not dispatch
// on time because the service was not finishing fast enough, that wait was real
// and belongs in the number. Reporting only from the send time is how a load
// test reports a two-second stall as a handful of slow requests.
func (r *result) correctedLatencies() []time.Duration {
	out := make([]time.Duration, 0, len(r.samples))
	for _, s := range r.samples {
		if s.inWindow && s.timed() {
			out = append(out, s.latency+s.schedLag())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// schedLags returns how late each in-window request was dispatched, sorted.
// Open-loop only; empty in closed-loop mode.
func (r *result) schedLags() []time.Duration {
	out := make([]time.Duration, 0, len(r.samples))
	for _, s := range r.samples {
		if s.inWindow && !s.scheduledAt.IsZero() {
			out = append(out, s.schedLag())
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
	// Nearest-rank proper: the smallest value whose rank is at or above p% of
	// the set. The ceil matters — a floor index returns one rank too high
	// whenever p*n/100 lands on a whole number, which is exactly what happens
	// on the round sample counts a load test tends to produce.
	idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
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
	return fmt.Sprintf("  %-18s n=%-8d min=%-9s p50=%-9s p95=%-9s p99=%-9s p99.9=%-9s max=%-9s mean=%s",
		label, len(sorted),
		ms(sorted[0]),
		ms(percentile(sorted, 50)), ms(percentile(sorted, 95)),
		ms(percentile(sorted, 99)), ms(percentile(sorted, 99.9)),
		ms(sorted[len(sorted)-1]), ms(mean(sorted)))
}

// pct renders n as a percentage of total, for the error and non-2xx lines.
func pct(n, total int) string {
	if total == 0 {
		return "0.0000%"
	}
	return fmt.Sprintf("%.4f%%", float64(n)/float64(total)*100)
}

func (r *result) report(w io.Writer) {
	fmt.Fprintf(w, "\n=== %s phase ===\n", r.name)

	statuses := map[int]int{}
	errs := map[errKind]int{}
	throttles := map[throttleKind]int{}
	errTotal := 0
	for _, s := range r.windowed() {
		if s.err != nil {
			errs[classify(s.err)]++
			errTotal++
			continue
		}
		statuses[s.status]++
		if s.throttle != throttleNone {
			throttles[s.throttle]++
		}
	}

	total := len(r.windowed())
	accepted := statuses[r.okStatus]
	secs := r.measured.Seconds()
	if secs <= 0 {
		secs = r.wall.Seconds()
	}
	fmt.Fprintf(w, "window=%s (wall %s)  requests=%d  rps=%.1f  accepted-rps=%.1f\n",
		r.measured.Round(time.Millisecond), r.wall.Round(time.Millisecond), total,
		float64(total)/secs, float64(accepted)/secs)

	// Open loop asks a different question than closed loop, so it gets a
	// different headline: did we actually deliver the rate we promised, and were
	// we on time doing it. A generator that fell behind produces numbers about
	// the generator.
	if r.offered > 0 {
		achieved := float64(total) / secs
		fmt.Fprintf(w, "offered=%.1f rps  achieved=%.1f rps  (%.1f%% of target)\n",
			r.offered, achieved, achieved/r.offered*100)

		lags := r.schedLags()
		if len(lags) > 0 {
			// Some lag is structural: requests are dispatched in batches, so
			// about one tick is the floor, and container timer jitter adds a few
			// ms at the tail. That is fine as long as it stays small next to the
			// latency being measured — and the corrected line already includes
			// it either way.
			//
			// The run is only untrustworthy when the generator's own delay is
			// comparable to the service's, because then the numbers describe the
			// generator, or when it could not deliver the rate it promised.
			lagP99 := percentile(lags, 99)
			svcP99 := percentile(r.allLatencies(), 99)
			achieved := float64(len(r.windowed())) / r.measured.Seconds()

			verdict := "[OK]"
			switch {
			case achieved < 0.99*r.offered:
				// The rate was never actually offered, so nothing here describes
				// what the service would do at the requested load.
				verdict = "[!! COULD NOT DELIVER THE RATE — RESULT INVALID]"
			case svcP99 > 0 && lagP99 > svcP99:
				// Not invalid: the service line is still a clean measurement.
				// It just means the endpoint is faster than the generator's own
				// dispatch granularity, so the corrected line is mostly us.
				verdict = "[dispatch dominates — read 'all requests', not 'corrected']"
			}
			fmt.Fprintf(w, "scheduler lag: p50=%s p99=%s max=%s   %s (floor ~%s, service p99 %s)\n",
				ms(percentile(lags, 50)), ms(lagP99), ms(lags[len(lags)-1]),
				verdict, ms(dispatchTick), ms(svcP99))
		}
	}

	// Three lines, not one. "all requests" is the honest headline; the split
	// exists because a 429 is rejected in middleware before Argon2id runs, so
	// folding it into a single average hides the only number that matters.
	all := r.allLatencies()
	fmt.Fprintln(w, "latency:")
	if r.offered > 0 {
		// Corrected first: it is the honest headline for an open-loop run,
		// because it includes time a request spent waiting for its turn.
		fmt.Fprintln(w, latencyLine("corrected (queued)", r.correctedLatencies()))
	}
	fmt.Fprintln(w, latencyLine("all requests", all))
	fmt.Fprintln(w, latencyLine(fmt.Sprintf("%d accepted", r.okStatus), r.latencies(r.okStatus)))
	fmt.Fprintln(w, latencyLine("429 rejected", r.latencies(429)))

	// If the slowest request is pressed up against -timeout, the distribution was
	// cut off rather than measured: everything slower failed and got recorded as
	// the timeout value. p99.9 and max are then floors, not measurements.
	if len(all) > 0 && r.timeout > 0 {
		if all[len(all)-1] >= time.Duration(float64(r.timeout)*0.98) {
			fmt.Fprintf(w, "!! latency is CENSORED at -timeout=%s — p99.9 and max are floors, not values.\n",
				r.timeout)
			fmt.Fprintf(w, "!! Re-run with a larger -timeout to see how bad the tail actually gets.\n")
		}
	}

	// Always printed, even at zero. "0 errors" is a result; a missing line is
	// indistinguishable from a harness that forgot to look. And a bare count is
	// meaningless without knowing whether it is out of 500 or 500,000.
	fmt.Fprintf(w, "errors:  %d / %d (%s)  [timeout=%d refused=%d reset/EOF=%d over-capacity=%d other=%d]\n",
		errTotal, total, pct(errTotal, total),
		errs[errTimeout], errs[errRefused], errs[errResetEOF], errs[errCapacity], errs[errOtherKind])

	nonOK := 0
	for code, n := range statuses {
		if code != r.okStatus {
			nonOK += n
		}
	}
	// Kept separate from transport errors: a 502 and a timeout both count as
	// failure but have completely different causes.
	fmt.Fprintf(w, "non-2xx: %d / %d (%s)\n", nonOK, total, pct(nonOK, total))

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

	// Every sample is written, in-window or not, errored or not. The CSV is the
	// real artifact — per-second rates, latency-over-time and tail histograms are
	// all reconstructable from it, and re-running an hour of load because a
	// column was missing is a bad trade against writing one extra field.
	header := []string{
		"phase", "scheduled_at", "sent_at", "sched_lag_ms", "latency_ms",
		"status", "throttle", "conn_reused", "in_window", "ip", "error",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	msField := func(d time.Duration) string {
		return strconv.FormatFloat(float64(d.Microseconds())/1000, 'f', 3, 64)
	}
	for _, r := range results {
		for _, s := range r.samples {
			errStr := ""
			if s.err != nil {
				errStr = s.err.Error()
			}
			schedAt := ""
			if !s.scheduledAt.IsZero() {
				schedAt = s.scheduledAt.Format(time.RFC3339Nano)
			}
			rec := []string{
				r.name,
				schedAt,
				s.at.Format(time.RFC3339Nano),
				msField(s.schedLag()),
				msField(s.latency),
				strconv.Itoa(s.status),
				string(s.throttle),
				strconv.FormatBool(s.connReused),
				strconv.FormatBool(s.inWindow),
				s.ip,
				errStr,
			}
			if err := cw.Write(rec); err != nil {
				return err
			}
		}
	}
	return cw.Error()
}
