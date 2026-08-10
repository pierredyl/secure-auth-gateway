// Command loadtest simulates real users logging in against the auth gateway.
//
// It runs in two phases. The limiter phase drives every request through a small
// shared bucket of spoofed client IPs so the 10 req/min rate limiter is actually
// exercised. The compute phase gives every request a fresh IP so the limiter
// stays out of the way and the numbers reflect the real cost of a login —
// Argon2id hashing plus the Postgres round trip.
//
// See README.md in this directory for why the X-Forwarded-For spoofing is
// mandatory rather than a convenience.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Mirrors httprate.Limit(10, 1*time.Minute) in internal/handlers/routes.go.
// Used only to label the report; the harness never enforces anything itself.
const (
	rateLimitReqs   = 10
	rateLimitWindow = time.Minute
)

type config struct {
	baseURL  string
	target   string
	users    int
	duration time.Duration
	think    time.Duration
	ips      int
	phase    string
	cooldown time.Duration
	timeout  time.Duration
	ramp     time.Duration
	seedOnly bool
	skipSeed bool
	redisURL string
	keepLock bool
	csvPath  string
}

// okStatus is the success code for the endpoint under test. Login answers 201,
// not 200.
func (c config) okStatus() int {
	if c.target == "health" {
		return http.StatusOK
	}
	return http.StatusCreated
}

func main() {
	var cfg config
	flag.StringVar(&cfg.baseURL, "url", "http://localhost:80", "base URL of the gateway (nginx; app replicas publish no ports)")
	flag.StringVar(&cfg.target, "target", "login", "endpoint under test: login (two-phase) or health (raw capacity)")
	flag.IntVar(&cfg.users, "users", 100, "number of concurrent virtual users")
	flag.DurationVar(&cfg.duration, "duration", 30*time.Second, "how long each phase runs")
	flag.DurationVar(&cfg.think, "think", time.Second, "pause between a user's requests (jittered +/-20%)")
	flag.IntVar(&cfg.ips, "ips", 25, "size of the shared IP bucket in the limiter phase")
	flag.StringVar(&cfg.phase, "phase", "both", "which phases to run: limiter, compute, or both")
	flag.DurationVar(&cfg.cooldown, "cooldown", 65*time.Second, "pause between phases so limiter windows expire")
	flag.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "per-request timeout")
	flag.DurationVar(&cfg.ramp, "ramp", 0, "stagger user start over this window (0 = all at once)")
	flag.BoolVar(&cfg.seedOnly, "seed-only", false, "create the 5 accounts and exit")
	flag.BoolVar(&cfg.skipSeed, "skip-seed", false, "assume the accounts already exist")
	flag.StringVar(&cfg.redisURL, "redis", "localhost:6379", "redis address used to clear the test accounts' login lockouts")
	flag.BoolVar(&cfg.keepLock, "keep-lockouts", false, "don't clear the test accounts' login lockouts before running")
	flag.StringVar(&cfg.csvPath, "csv", "", "optional path to dump raw per-request samples")
	flag.Parse()

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "\nloadtest: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	if cfg.users < 1 {
		return fmt.Errorf("-users must be at least 1")
	}
	if cfg.ips < 1 {
		return fmt.Errorf("-ips must be at least 1")
	}
	runLimiter := cfg.phase == "both" || cfg.phase == "limiter"
	runCompute := cfg.phase == "both" || cfg.phase == "compute"
	if !runLimiter && !runCompute {
		return fmt.Errorf("-phase must be limiter, compute, or both (got %q)", cfg.phase)
	}
	if cfg.target != "login" && cfg.target != "health" {
		return fmt.Errorf("-target must be login or health (got %q)", cfg.target)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := newClient(cfg)

	// The health endpoint needs no accounts, and having no rate limit it has no
	// limiter phase to run — there is only one question to ask it.
	if cfg.target == "health" {
		return runHealthTarget(ctx, cfg, client)
	}

	accts := accounts()

	// Before seeding, not after: seeding ends with a verification login per
	// account, and a locked account would fail that check.
	if !cfg.keepLock {
		if err := clearLockouts(ctx, cfg.redisURL, accts); err != nil {
			// Not fatal — the harness may be pointed at an environment whose
			// Redis isn't reachable from here. Say so loudly, since a stale
			// lockout silently distorts the results.
			fmt.Fprintf(os.Stderr, "warning: could not clear login lockouts: %v\n", err)
			fmt.Fprintf(os.Stderr, "         any locked test account will show up as 429s in the report\n")
		}
	}

	if !cfg.skipSeed {
		var err error
		if accts, err = seed(ctx, client, cfg.baseURL); err != nil {
			return err
		}
	}
	if cfg.seedOnly {
		fmt.Println("\nseed complete.")
		return nil
	}

	fmt.Printf("\ntarget %s/api/v1/auth/login   users=%d   duration=%s   think=%s\n",
		cfg.baseURL, cfg.users, cfg.duration, cfg.think)

	login := loginRequestFn(cfg.baseURL, accts)
	var results []*result

	if runLimiter {
		// Offered load per IP versus the server's 10/min ceiling. Printing it up
		// front makes it obvious when a run is too gentle to prove anything.
		perIP := float64(cfg.users) / cfg.think.Seconds() * 60 / float64(cfg.ips)
		if cfg.think <= 0 {
			perIP = 0
		}
		fmt.Printf("\nlimiter phase: %d IPs, ~%.0f req/min offered per IP against a %d req/min limit\n",
			cfg.ips, perIP, rateLimitReqs)

		r := runPhase(ctx, cfg, client, "limiter", &bucketIPs{n: cfg.ips}, login)
		r.ipCount = cfg.ips
		results = append(results, r)
		r.report(os.Stdout)
	}

	if runLimiter && runCompute && cfg.cooldown > 0 && ctx.Err() == nil {
		fmt.Printf("\ncooling down %s so the limiter windows expire...\n", cfg.cooldown)
		select {
		case <-time.After(cfg.cooldown):
		case <-ctx.Done():
		}
	}

	if runCompute && ctx.Err() == nil {
		fmt.Printf("\ncompute phase: unique IP per request, limiter bypassed\n")
		r := runPhase(ctx, cfg, client, "compute", &uniqueIPs{}, login)
		results = append(results, r)
		r.report(os.Stdout)
	}

	if len(results) == 2 {
		lim, comp := results[0], results[1]
		limAcc, compAcc := lim.latencies(lim.okStatus), comp.latencies(comp.okStatus)
		fmt.Printf("\n=== comparison ===\n")
		fmt.Printf("accepted requests:  limiter=%d (%.1f/s)   compute=%d (%.1f/s)\n",
			len(limAcc), float64(len(limAcc))/lim.wall.Seconds(),
			len(compAcc), float64(len(compAcc))/comp.wall.Seconds())
		fmt.Printf("accepted p95:       limiter=%s   compute=%s\n",
			ms(percentile(limAcc, 95)), ms(percentile(compAcc, 95)))
		// These two samples are not like-for-like. Nearly every request the
		// limiter admits arrives in the opening seconds, before any window has
		// filled, so its accepted latencies are a cold thundering-herd burst.
		// The compute phase spreads the same offered load across the whole run.
		fmt.Println("note: the limiter phase admits most of its traffic in the opening burst before")
		fmt.Println("      the windows fill, so its accepted latencies skew high. Use the compute")
		fmt.Println("      phase for capacity, and the limiter phase for throttling behaviour.")
	}

	if cfg.csvPath != "" {
		if err := writeCSV(cfg.csvPath, results); err != nil {
			return fmt.Errorf("writing csv: %w", err)
		}
		fmt.Printf("\nraw samples written to %s\n", cfg.csvPath)
	}

	if ctx.Err() != nil {
		fmt.Println("\ninterrupted — results above cover the work completed before the signal")
	}
	return nil
}

// runHealthTarget measures the stack's baseline: nginx, the three replicas and
// Go's HTTP stack, with no hashing and no database in the path.
func runHealthTarget(ctx context.Context, cfg config, client *http.Client) error {
	fmt.Printf("\ntarget %s/api/v1/health   users=%d   duration=%s   think=%s\n",
		cfg.baseURL, cfg.users, cfg.duration, cfg.think)
	fmt.Println("no accounts, no rate limit, no hashing — pure request-handling capacity")

	r := runPhase(ctx, cfg, client, "health", &uniqueIPs{}, healthRequestFn(cfg.baseURL))
	r.report(os.Stdout)

	if cfg.csvPath != "" {
		if err := writeCSV(cfg.csvPath, []*result{r}); err != nil {
			return fmt.Errorf("writing csv: %w", err)
		}
		fmt.Printf("\nraw samples written to %s\n", cfg.csvPath)
	}
	if ctx.Err() != nil {
		fmt.Println("\ninterrupted — results above cover the work completed before the signal")
	}
	return nil
}

// requestFn issues one request and reports how it went. Swapping it is how the
// harness points at a different endpoint without duplicating the worker,
// think-time and reporting scaffolding.
type requestFn func(ctx context.Context, client *http.Client, rng *rand.Rand, ip string) (sample, string)

// loginRequestFn POSTs a login for a randomly chosen account. Bodies are built
// once here rather than marshalled per request on the hot path.
func loginRequestFn(baseURL string, accts []account) requestFn {
	bodies := make([][]byte, len(accts))
	for i, a := range accts {
		bodies[i], _ = json.Marshal(map[string]string{"email": a.email, "password": a.password})
	}
	url := baseURL + "/api/v1/auth/login"

	return func(ctx context.Context, client *http.Client, rng *rand.Rand, ip string) (sample, string) {
		body := bodies[rng.Intn(len(bodies))]
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return sample{at: time.Now(), ip: ip, err: err}, ""
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", ip)
		return do(client, req, ip)
	}
}

func healthRequestFn(baseURL string) requestFn {
	url := baseURL + "/api/v1/health"

	return func(ctx context.Context, client *http.Client, _ *rand.Rand, ip string) (sample, string) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return sample{at: time.Now(), ip: ip, err: err}, ""
		}
		req.Header.Set("X-Forwarded-For", ip)
		return do(client, req, ip)
	}
}

// newClient builds the one shared client. The default transport keeps only 2
// idle connections per host, which under 100 users would mean constant dial
// churn and latency numbers that measure our own TCP handshakes.
func newClient(cfg config) *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        cfg.users * 2,
		MaxIdleConnsPerHost: cfg.users * 2,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: cfg.timeout}
}

// ipSource hands out the value we put in X-Forwarded-For. Swapping the
// implementation is the only difference between the two phases.
type ipSource interface {
	next() string
}

// bucketIPs cycles round-robin through a fixed set of addresses so several
// virtual users share each limiter bucket. Round-robin rather than random keeps
// the per-IP arithmetic in the report predictable.
type bucketIPs struct {
	n int
	c atomic.Uint64
}

func (b *bucketIPs) next() string {
	i := b.c.Add(1) - 1
	return ipFor(int(i % uint64(b.n)))
}

// uniqueIPs never repeats, so every request lands in a fresh limiter window.
type uniqueIPs struct{ c atomic.Uint64 }

func (u *uniqueIPs) next() string {
	return ipFor(int(u.c.Add(1) - 1))
}

// ipFor maps an index into 198.18.0.0/15, the RFC 2544 benchmarking range. It
// sits outside the 172.16.0.0/12 prefix that ClientIPFromXFF treats as trusted,
// so these addresses survive the right-to-left walk and become the limiter key.
// 131,072 addresses are available, far past any concurrency we would run.
func ipFor(n int) string {
	n %= 1 << 17
	return fmt.Sprintf("198.%d.%d.%d", 18+(n>>16), (n>>8)&0xff, n&0xff)
}

func bucketAddrs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = ipFor(i)
	}
	return out
}

// runPhase drives cfg.users goroutines against whatever endpoint issue targets,
// until the phase deadline passes or the process is interrupted.
func runPhase(parent context.Context, cfg config, client *http.Client, name string, ips ipSource, issue requestFn) *result {
	// phaseCtx governs when users stop issuing new requests and wakes them out of
	// their think-time sleep. Requests themselves are issued against parent so
	// that the last one in flight when the deadline passes is allowed to finish
	// instead of being cancelled and miscounted as a timeout.
	phaseCtx, cancel := context.WithTimeout(parent, cfg.duration)
	defer cancel()

	perUser := make([][]sample, cfg.users)
	var sent atomic.Int64
	var hdrsOnce sync.Once
	var hdrs string

	var wg sync.WaitGroup
	start := time.Now()

	for u := 0; u < cfg.users; u++ {
		wg.Add(1)
		go func(u int) {
			defer wg.Done()

			// Each user gets its own rand source; the global one takes a lock and
			// would serialise 100 goroutines on every iteration.
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(u)))

			if cfg.ramp > 0 {
				delay := time.Duration(int64(cfg.ramp) * int64(u) / int64(cfg.users))
				if !sleepCtx(phaseCtx, delay) {
					return
				}
			}

			// Rough capacity guess so the common case never reallocates.
			est := 16
			if cfg.think > 0 {
				est = int(cfg.duration/cfg.think) + 8
			}
			samples := make([]sample, 0, est)

			for phaseCtx.Err() == nil {
				s, rateHdr := issue(parent, client, rng, ips.next())
				samples = append(samples, s)
				sent.Add(1)

				if rateHdr != "" {
					hdrsOnce.Do(func() { hdrs = rateHdr })
				}

				if cfg.think > 0 {
					// +/-20% jitter so users don't march in lockstep.
					jitter := time.Duration(float64(cfg.think) * (0.8 + 0.4*rng.Float64()))
					if !sleepCtx(phaseCtx, jitter) {
						break
					}
				}
			}
			perUser[u] = samples
		}(u)
	}

	done := make(chan struct{})
	go progress(done, &sent, start)

	wg.Wait()
	close(done)
	wall := time.Since(start)

	total := 0
	for _, s := range perUser {
		total += len(s)
	}
	merged := make([]sample, 0, total)
	for _, s := range perUser {
		merged = append(merged, s...)
	}

	return &result{name: name, samples: merged, wall: wall, okStatus: cfg.okStatus(), rateHdrs: hdrs}
}

// do performs one request and times it. The timer covers draining the body as
// well as Do(), because a response isn't received until it's fully read — and
// leaving the body unread also breaks connection reuse.
func do(client *http.Client, req *http.Request, ip string) (sample, string) {
	sentAt := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return sample{at: sentAt, ip: ip, latency: time.Since(sentAt), err: err}, ""
	}
	_, copyErr := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	latency := time.Since(sentAt)

	if copyErr != nil {
		return sample{at: sentAt, ip: ip, latency: latency, err: copyErr}, ""
	}

	// Capture the throttling headers once so the report can confirm the server
	// tells clients how long to back off.
	var rateHdr string
	throttle := throttleNone
	if resp.StatusCode == http.StatusTooManyRequests {
		rateHdr = fmt.Sprintf("Retry-After=%q X-RateLimit-Limit=%q X-RateLimit-Remaining=%q X-RateLimit-Reset=%q",
			resp.Header.Get("Retry-After"),
			resp.Header.Get("X-RateLimit-Limit"),
			resp.Header.Get("X-RateLimit-Remaining"),
			resp.Header.Get("X-RateLimit-Reset"))
		// Not distinguishable by X-RateLimit-*: httprate sets those on every
		// response passing through the middleware, so the handler's own 429
		// carries them too. The content type does separate them — httprate
		// rejects with http.Error (text/plain), the lockout answers JSON.
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			throttle = throttleAccount
		} else {
			throttle = throttleIP
		}
	}
	return sample{at: sentAt, ip: ip, latency: latency, status: resp.StatusCode, throttle: throttle}, rateHdr
}

// progress prints a heartbeat so a 30s run doesn't look like a hang. It keeps
// ticking past the phase deadline until the workers have actually drained.
func progress(done <-chan struct{}, sent *atomic.Int64, start time.Time) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			elapsed := time.Since(start)
			n := sent.Load()
			fmt.Printf("  ...%3.0fs elapsed, %d requests (%.0f rps)\n",
				elapsed.Seconds(), n, float64(n)/elapsed.Seconds())
		case <-done:
			return
		}
	}
}

// sleepCtx reports false when the context ended before the sleep finished.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
