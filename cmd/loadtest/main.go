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
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/signal"
	"strconv"
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
	path     string
	users    int
	rate     float64
	maxInFl  int
	workers  int
	duration time.Duration
	warmup   time.Duration
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
	jsonPath string

	timingSamples   int
	timingTolerance time.Duration

	insecureSkipVerify bool
}

// openLoop reports whether this run dispatches on a fixed schedule rather than
// letting each virtual user pace itself.
func (c config) openLoop() bool { return c.rate > 0 }

// okStatus is the success code for the endpoint under test. Login answers 201,
// not 200.
func (c config) okStatus() int {
	switch c.target {
	case "health":
		return http.StatusOK
	case "timing":
		return http.StatusUnauthorized
	}
	return http.StatusCreated
}

func main() {
	var cfg config
	flag.StringVar(&cfg.baseURL, "url", "https://localhost:443", "base URL of the gateway (nginx; app replicas publish no ports)")
	flag.StringVar(&cfg.target, "target", "login", "endpoint under test: login (two-phase), health (raw capacity), or timing (login failure padding check)")
	flag.StringVar(&cfg.path, "path", "", "override the request path (e.g. /nginx-noop); default is the target's own path")
	flag.IntVar(&cfg.users, "users", envInt("CONCURRENCY", 100), "number of concurrent virtual users (closed loop; ignored when -rate is set). Env CONCURRENCY sets the default; an explicit -users still wins")
	flag.Float64Var(&cfg.rate, "rate", 0, "open loop: requests per second to offer regardless of server speed (0 = closed loop)")
	flag.IntVar(&cfg.maxInFl, "max-inflight", 20000, "open loop: abort if this many requests are outstanding")
	flag.IntVar(&cfg.workers, "workers", 0, "open loop: pre-spawned senders (0 = auto from -rate)")
	flag.DurationVar(&cfg.duration, "duration", 30*time.Second, "length of the MEASURED window, excluding ramp and warmup")
	flag.DurationVar(&cfg.warmup, "warmup", 10*time.Second, "discard this much traffic before measuring, so cold pools and a cold runtime stay out of the numbers")
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
	flag.StringVar(&cfg.jsonPath, "json", "", "optional path to write a structured run summary for the report generator (see cmd/loadreport)")
	flag.IntVar(&cfg.timingSamples, "timing-samples", 300, "timing target: samples per group")
	flag.DurationVar(&cfg.timingTolerance, "timing-tolerance", 3*time.Millisecond, "timing target: largest median difference between the two failure paths that still passes")
	flag.BoolVar(&cfg.insecureSkipVerify, "insecure-skip-verify", true, "skip TLS certificate verification — on by default because nginx presents a self-signed dev cert (scripts/gen-dev-cert.sh); set false when pointed at a real certificate")
	flag.Parse()

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "\nloadtest: %v\n", err)
		os.Exit(1)
	}
}

// envInt reads an integer from the environment, falling back to def when the
// variable is unset or unparseable.
//
// It supplies the flag's *default* rather than overriding the flag, so
// `CONCURRENCY=200 loadtest -users=50` runs 50 users. One value, one winner, and
// the command line is always the winner.
func envInt(name string, def int) int {
	v, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s=%q is not a number, using %d\n", name, v, def)
		return def
	}
	return n
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
	if cfg.target != "login" && cfg.target != "health" && cfg.target != "timing" {
		return fmt.Errorf("-target must be login, health, or timing (got %q)", cfg.target)
	}
	if cfg.rate < 0 {
		return fmt.Errorf("-rate cannot be negative")
	}
	if cfg.openLoop() && cfg.maxInFl < 1 {
		return fmt.Errorf("-max-inflight must be at least 1")
	}
	// The limiter phase is built around a fixed set of IPs each racing a 10/min
	// window; driving it on a schedule instead of by user measures something
	// else entirely, and the per-IP arithmetic in the report would not apply.
	if cfg.openLoop() && (cfg.phase == "limiter" || cfg.phase == "both") && cfg.target == "login" {
		return fmt.Errorf("-rate applies to the compute phase only; use -phase=compute with -rate")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := newClient(cfg)

	// The health endpoint needs no accounts, and having no rate limit it has no
	// limiter phase to run — there is only one question to ask it.
	if cfg.target == "health" {
		return runHealthTarget(ctx, cfg, client)
	}

	// The timing target is serial and measures one request at a time, so none of
	// the phase, concurrency or rate machinery below applies to it.
	if cfg.target == "timing" {
		return runTimingTarget(ctx, cfg, client)
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
		r := drive(ctx, cfg, client, "compute", &uniqueIPs{}, login)
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
	if cfg.jsonPath != "" {
		if err := writeSummary(cfg.jsonPath, cfg, results); err != nil {
			return fmt.Errorf("writing json summary: %w", err)
		}
		fmt.Printf("\nrun summary written to %s\n", cfg.jsonPath)
	}

	if ctx.Err() != nil {
		fmt.Println("\ninterrupted — results above cover the work completed before the signal")
	}
	return nil
}

// runHealthTarget measures the stack's baseline: nginx, the three replicas and
// Go's HTTP stack, with no hashing and no database in the path.
func runHealthTarget(ctx context.Context, cfg config, client *http.Client) error {
	path := cfg.path
	if path == "" {
		path = "/api/v1/health"
	}
	if cfg.openLoop() {
		fmt.Printf("\ntarget %s%s   rate=%.0f/s (open loop)   duration=%s   warmup=%s\n",
			cfg.baseURL, path, cfg.rate, cfg.duration, cfg.warmup)
	} else {
		fmt.Printf("\ntarget %s%s   users=%d   duration=%s   warmup=%s   think=%s\n",
			cfg.baseURL, path, cfg.users, cfg.duration, cfg.warmup, cfg.think)
	}
	fmt.Println("no accounts, no rate limit, no hashing — pure request-handling capacity")

	r := drive(ctx, cfg, client, "health", &uniqueIPs{}, healthRequestFn(cfg.baseURL, cfg.path))
	r.report(os.Stdout)

	if cfg.csvPath != "" {
		if err := writeCSV(cfg.csvPath, []*result{r}); err != nil {
			return fmt.Errorf("writing csv: %w", err)
		}
		fmt.Printf("\nraw samples written to %s\n", cfg.csvPath)
	}
	if cfg.jsonPath != "" {
		if err := writeSummary(cfg.jsonPath, cfg, []*result{r}); err != nil {
			return fmt.Errorf("writing json summary: %w", err)
		}
		fmt.Printf("\nrun summary written to %s\n", cfg.jsonPath)
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

// healthRequestFn issues the GET under test. path lets a run point at something
// other than /api/v1/health — notably /nginx-noop, which nginx answers itself so
// the result is the ceiling of everything that is not the Go app.
func healthRequestFn(baseURL, path string) requestFn {
	if path == "" {
		path = "/api/v1/health"
	}
	url := baseURL + path

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
	// Size the pool to the number of connections that can actually be in use at
	// once. In closed loop that is the user count; in open loop -users is
	// meaningless, so size it from the concurrency the offered rate implies and
	// leave generous headroom. Undersizing here closes idle connections that are
	// about to be needed again, and the resulting dial churn gets misread as the
	// server being slow.
	idle := cfg.users * 2
	if cfg.openLoop() {
		idle = cfg.workers
		if idle <= 0 {
			idle = int(cfg.rate * 0.25)
		}
		if idle < 512 {
			idle = 512
		}
	}
	tr := &http.Transport{
		MaxIdleConns:        idle,
		MaxIdleConnsPerHost: idle,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,
	}
	if cfg.insecureSkipVerify {
		// nginx presents a self-signed dev cert (scripts/gen-dev-cert.sh) — there's
		// no public CA to have issued it, so the client has to be told explicitly
		// to trust it rather than verify against a chain that doesn't exist.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
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

// errInFlightCap marks a request that was never sent because too many were
// already outstanding. It is a real failure — the generator could not keep the
// promised arrival rate — and counting it as anything else would hide the fact
// that the offered load was not actually offered.
var errInFlightCap = errors.New("in-flight cap exceeded (server not keeping up)")

const (
	// dispatchTick is the open-loop batching granularity. One timer per request
	// is not viable — at several thousand rps the inter-arrival gap is a few
	// hundred microseconds, which the runtime cannot schedule reliably — so
	// requests due within the same tick go out together. scheduledAt still
	// records the exact slot each one was meant to occupy, so the resulting lag
	// is measured rather than hidden.
	dispatchTick = time.Millisecond
)

// drive picks the load model. Closed loop is the default; -rate switches to open
// loop, which is the only one that can answer "can it handle N per second".
func drive(parent context.Context, cfg config, client *http.Client, name string, ips ipSource, issue requestFn) *result {
	if cfg.openLoop() {
		return runOpenLoop(parent, cfg, client, name, ips, issue)
	}
	return runPhase(parent, cfg, client, name, ips, issue)
}

// runOpenLoop issues requests on a fixed schedule rather than letting each user
// pace itself against the server's replies.
//
// This is the difference between "N users hammering as fast as they can" and
// "N requests arrive every second whether or not you are keeping up". Only the
// second one describes real traffic, and only the second one can be turned into
// a throughput claim: in closed loop a slow server automatically receives less
// load, so the test quietly stops pushing exactly when the answer gets
// interesting.
//
// It also fixes the tail. When the service stalls for two seconds, a closed loop
// records one slow sample per user; a real arrival process would have piled up
// rate x 2s requests, all of them slow. Reporting against scheduledAt rather
// than the send time puts that queueing time back into the numbers.
func runOpenLoop(parent context.Context, cfg config, client *http.Client, name string, ips ipSource, issue requestFn) *result {
	phaseCtx, cancel := context.WithTimeout(parent, cfg.warmup+cfg.duration)
	defer cancel()

	period := time.Duration(float64(time.Second) / cfg.rate)

	// Workers are pre-spawned and pull from a queue rather than being created per
	// request. Spawning on the hot path makes the dispatcher unstable under load:
	// once it slips a tick it has to fire a larger batch, which costs more
	// scheduling, which makes it slip further. That feedback loop shows up as a
	// throughput cliff that belongs to the generator, not to the service.
	workers := cfg.workers
	if workers <= 0 {
		workers = int(cfg.rate * 0.25) // enough for a 250ms stall at the target rate
		if workers < 256 {
			workers = 256
		}
	}
	if workers > cfg.maxInFl {
		workers = cfg.maxInFl
	}

	var (
		inFlight atomic.Int64
		sent     atomic.Int64
		wg       sync.WaitGroup
	)

	type job struct {
		due time.Time
		ip  string
	}
	queue := make(chan job, cfg.maxInFl)

	// Per-worker slices, merged after the run — the same approach runPhase uses,
	// and it keeps a shared mutex off the measurement path.
	perWorker := make([][]sample, workers)
	est := int(cfg.rate*(cfg.warmup+cfg.duration).Seconds())/workers + 64

	start := time.Now()

	for wkr := 0; wkr < workers; wkr++ {
		wg.Add(1)
		go func(wkr int) {
			defer wg.Done()
			// Each worker gets its own generator; math/rand.Rand is not safe for
			// concurrent use.
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(wkr)))
			out := make([]sample, 0, est)
			for j := range queue {
				s, _ := issue(parent, client, rng, j.ip)
				s.scheduledAt = j.due
				out = append(out, s)
				sent.Add(1)
				inFlight.Add(-1)
			}
			perWorker[wkr] = out
		}(wkr)
	}

	var (
		mu      sync.Mutex
		dropped []sample // requests the queue had no room for
	)
	done := make(chan struct{})
	go progress(done, &sent, start)

	// If the queue stays pegged near the cap, the offered rate is above what the
	// service can complete and the backlog will grow until something dies.
	// Stopping and saying so is more useful than a report full of timeouts.
	abort := make(chan string, 1)
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		over := 0
		for {
			select {
			case <-t.C:
				if float64(inFlight.Load()) > 0.9*float64(cfg.maxInFl) {
					if over++; over >= 5 {
						select {
						case abort <- fmt.Sprintf(
							"offered %.0f rps, only %.0f rps completing — queue unbounded, this rate is above capacity",
							cfg.rate, float64(sent.Load())/time.Since(start).Seconds()):
						default:
						}
						return
					}
				} else {
					over = 0
				}
			case <-phaseCtx.Done():
				return
			}
		}
	}()

	tick := time.NewTicker(dispatchTick)
	defer tick.Stop()

	var issued int64
	var aborted string

dispatch:
	for {
		select {
		case <-phaseCtx.Done():
			break dispatch
		case msg := <-abort:
			aborted = msg
			break dispatch
		case <-tick.C:
		}

		now := time.Now()
		for {
			due := start.Add(time.Duration(issued) * period)
			if due.After(now) {
				break
			}
			issued++
			ip := ips.next()

			select {
			case queue <- job{due: due, ip: ip}:
				inFlight.Add(1)
			default:
				// Queue full: the service is not draining work as fast as it is
				// arriving. Record it as never-sent rather than pretending it
				// was a fast request.
				mu.Lock()
				dropped = append(dropped, sample{scheduledAt: due, at: now, ip: ip, err: errInFlightCap})
				mu.Unlock()
				sent.Add(1)
			}
		}
	}

	close(queue)
	wg.Wait()
	close(done)
	wall := time.Since(start)

	total := len(dropped)
	for _, s := range perWorker {
		total += len(s)
	}
	samples := make([]sample, 0, total)
	for _, s := range perWorker {
		samples = append(samples, s...)
	}
	samples = append(samples, dropped...)

	if aborted != "" {
		fmt.Printf("\n!! ABORTED at %s: %s\n", wall.Round(time.Second), aborted)
	}

	// An aborted run stopped early, so the window is however much of it actually
	// elapsed. Dividing by the full -duration would quietly understate the rate
	// the service was managing right up to the point it gave up.
	measured := cfg.duration
	if elapsed := wall - cfg.warmup; elapsed < measured {
		measured = elapsed
	}
	if measured < 0 {
		measured = 0
	}
	windowStart := start.Add(cfg.warmup)
	markWindow(samples, windowStart, measured)

	return &result{
		name:        name,
		samples:     samples,
		wall:        wall,
		measured:    measured,
		okStatus:    cfg.okStatus(),
		timeout:     cfg.timeout,
		offered:     cfg.rate,
		windowStart: windowStart,
		windowEnd:   windowStart.Add(measured),
	}
}

// runPhase drives cfg.users goroutines against whatever endpoint issue targets,
// until the phase deadline passes or the process is interrupted.
func runPhase(parent context.Context, cfg config, client *http.Client, name string, ips ipSource, issue requestFn) *result {
	// phaseCtx governs when users stop issuing new requests and wakes them out of
	// their think-time sleep. Requests themselves are issued against parent so
	// that the last one in flight when the deadline passes is allowed to finish
	// instead of being cancelled and miscounted as a timeout.
	//
	// -duration is the measured window, so the phase has to run for ramp and
	// warmup on top of it. That way asking for 60s of data gets 60s of data
	// instead of 60s minus however long the ramp took.
	phaseCtx, cancel := context.WithTimeout(parent, cfg.ramp+cfg.warmup+cfg.duration)
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

			// Rough capacity guess so the common case never reallocates. With
			// -think=0 — the mode used to find a ceiling — a user can record
			// thousands of samples, so guessing 16 there means growing the slice
			// on the measurement path.
			est := 16
			if cfg.think > 0 {
				est = int((cfg.ramp+cfg.warmup+cfg.duration)/cfg.think) + 8
			} else {
				est = 2048
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
	windowStart := start.Add(cfg.ramp + cfg.warmup)
	markWindow(merged, windowStart, cfg.duration)

	return &result{
		name:        name,
		samples:     merged,
		wall:        wall,
		measured:    cfg.duration,
		okStatus:    cfg.okStatus(),
		rateHdrs:    hdrs,
		timeout:     cfg.timeout,
		windowStart: windowStart,
		windowEnd:   windowStart.Add(cfg.duration),
	}
}

// markWindow flags the samples that count toward the statistics: those sent
// between t0 and t0+d.
//
// Everything outside it is still written to the CSV — the point is not to throw
// data away, it is to keep first-request costs (opening connections, a cold Go
// runtime, an empty DB pool) from being averaged into a steady-state number.
func markWindow(samples []sample, t0 time.Time, d time.Duration) {
	tEnd := t0.Add(d)
	for i := range samples {
		at := samples[i].at
		samples[i].inWindow = !at.Before(t0) && at.Before(tEnd)
	}
}

// do performs one request and times it. The timer covers draining the body as
// well as Do(), because a response isn't received until it's fully read — and
// leaving the body unread also breaks connection reuse.
func do(client *http.Client, req *http.Request, ip string) (sample, string) {
	// One bit of connection instrumentation, no more. Over plaintext HTTP on a
	// warm keepalive pool, DNS and TLS timings are always zero; whether the
	// connection was reused is the only part that varies, and it is what
	// separates "the service was slow" from "we had to open a socket first".
	var reused bool
	trace := &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	sentAt := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return sample{at: sentAt, ip: ip, latency: time.Since(sentAt), err: err, connReused: reused}, ""
	}
	_, copyErr := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	latency := time.Since(sentAt)

	if copyErr != nil {
		return sample{at: sentAt, ip: ip, latency: latency, err: copyErr, connReused: reused}, ""
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
	return sample{
		at: sentAt, ip: ip, latency: latency,
		status: resp.StatusCode, throttle: throttle, connReused: reused,
	}, rateHdr
}

// progress prints a heartbeat so a 30s run doesn't look like a hang. It keeps
// ticking past the phase deadline until the workers have actually drained.
func progress(done <-chan struct{}, sent *atomic.Int64, start time.Time) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	lastN, lastT := int64(0), start
	for {
		select {
		case <-t.C:
			elapsed := time.Since(start)
			n := sent.Load()
			// Instantaneous, not cumulative. An average since the start keeps
			// looking healthy for a long time after the server has stopped
			// keeping up, which is exactly when you want to see it fall over.
			inst := float64(n-lastN) / time.Since(lastT).Seconds()
			lastN, lastT = n, time.Now()
			fmt.Printf("  ...%3.0fs elapsed, %d requests (inst=%.0f rps, avg=%.0f rps)\n",
				elapsed.Seconds(), n, inst, float64(n)/elapsed.Seconds())
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
