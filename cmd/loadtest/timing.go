package main

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"secure-auth-gateway/internal/redis_db"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	timingWarmup      = 20
	timingFloor       = 20 * time.Millisecond
	bootstrapRounds   = 2000
	bootstrapAlpha    = 0.05
	timingWrongPasswd = "TimingCheck-WrongPassw0rd-2026!"
)

type timingGroup struct {
	name    string
	samples []time.Duration
}

func (g *timingGroup) sorted() []time.Duration {
	out := append([]time.Duration(nil), g.samples...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func runTimingTarget(ctx context.Context, cfg config, client *http.Client) error {
	if cfg.timingSamples < 30 {
		return fmt.Errorf("-timing-samples must be at least 30 (got %d)", cfg.timingSamples)
	}

	accts := accounts()
	if !cfg.skipSeed {
		var err error
		accts, err = seed(ctx, client, cfg.baseURL)
		if err != nil {
			return err
		}
	}

	rdb := redis.NewClient(&redis.Options{Addr: cfg.redisURL})
	defer rdb.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		return fmt.Errorf("connecting to redis at %s: %w", cfg.redisURL, err)
	}

	total := cfg.timingSamples + timingWarmup
	fmt.Printf("\ntarget %s/api/v1/auth/login\n", cfg.baseURL)
	fmt.Printf("timing check: %d samples per group (+%d discarded warmup), serial, unique IP per request\n",
		cfg.timingSamples, timingWarmup)
	fmt.Println("comparing: unknown email  vs  known email + wrong password")
	fmt.Println("both should be padded to the same calibrated window by padFailure")

	absent := &timingGroup{name: "unknown email"}
	wrong := &timingGroup{name: "wrong password"}
	ips := &uniqueIPs{}
	runID := time.Now().UnixNano()

	// A balanced sequence of the two request kinds, shuffled.
	//
	// Strict alternation looked like the safe choice and is not. nginx balances
	// across three replicas that each calibrated their own target at boot, and
	// with keepalive an upstream can stay pinned to a connection — so a fixed
	// A/B/A/B pattern can line one group up with one replica and turn a
	// difference between replicas into an apparent difference between groups.
	// Shuffling leaves no period for the balancer to correlate with.
	order := make([]int, 0, 2*total)
	for i := 0; i < total; i++ {
		order = append(order, 0, 1)
	}
	rng := rand.New(rand.NewSource(runID))
	rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })

	seen := map[int]int{}
	for idx, kind := range order {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Warmup is counted per group, so each discards the same number of early
		// samples no matter where the shuffle happened to put them.
		seen[kind]++
		keep := seen[kind] > timingWarmup

		if kind == 0 {
			absentEmail := absentEmailFor(runID, idx)
			d, err := timeLogin(ctx, client, cfg.baseURL, ips.next(), absentEmail, timingWrongPasswd)
			if err != nil {
				return fmt.Errorf("unknown-email sample %d: %w", idx, err)
			}
			if keep {
				absent.samples = append(absent.samples, d)
			}
		} else {
			a := accts[idx%len(accts)]
			// The seeded accounts really do lock out after 5 failures, so the
			// counter is cleared before every attempt. Without this the run turns
			// into 429s that never reach the password check at all.
			if err := rdb.Del(ctx, redis_db.LockoutKey(a.email)).Err(); err != nil {
				return fmt.Errorf("clearing lockout for %s: %w", a.email, err)
			}
			d, err := timeLogin(ctx, client, cfg.baseURL, ips.next(), a.email, timingWrongPasswd)
			if err != nil {
				return fmt.Errorf("wrong-password sample %d: %w", idx, err)
			}
			if keep {
				wrong.samples = append(wrong.samples, d)
			}
		}

		if idx > 0 && idx%200 == 0 {
			fmt.Printf("  %d/%d requests\n", idx, len(order))
		}
	}

	for _, a := range accts {
		if err := rdb.Del(ctx, redis_db.LockoutKey(a.email)).Err(); err != nil {
			return fmt.Errorf("clearing lockout for %s: %w", a.email, err)
		}
	}

	return reportTiming(cfg, absent, wrong)
}

// absentEmailFor builds an address that does not exist, the same length as the
// seeded accounts in seed.go.
//
// The length matters. padFailure starts its clock just before the user lookup,
// so the JSON decode, the validator regex and the IsLocked call all run
// unpadded, and every one of them scales with how long the address is. Probing
// with longer addresses than the real accounts measures that difference and
// reports it as a difference between the two code paths.
//
// "absent-" plus 8 digits is 15 characters, matching "loadtest-user-N".
func absentEmailFor(runID int64, idx int) string {
	n := (runID/1e6 + int64(idx)) % 1e8
	if n < 0 {
		n = -n
	}
	return fmt.Sprintf("absent-%08d@loadtest.local", n)
}

// timeLogin sends one login that is expected to fail and returns how long it
// took. A 429 is an error rather than a slow sample: the request never reached
// the password check, so its latency describes the limiter, not the padding.
func timeLogin(ctx context.Context, client *http.Client, baseURL, ip, email, password string) (time.Duration, error) {
	start := time.Now()
	status, body, err := postJSON(ctx, client, baseURL+"/api/v1/auth/login", ip, map[string]string{
		"email":    email,
		"password": password,
	})
	elapsed := time.Since(start)
	if err != nil {
		return 0, err
	}
	if status == http.StatusTooManyRequests {
		return 0, fmt.Errorf("got 429 for %s: a throttle fired, so this sample measures the limiter and not the login path", email)
	}
	if status != http.StatusUnauthorized {
		return 0, fmt.Errorf("expected 401 for %s, got %d: %s", email, status, strings.TrimSpace(body))
	}
	return elapsed, nil
}

func reportTiming(cfg config, absent, wrong *timingGroup) error {
	a, w := absent.sorted(), wrong.sorted()

	fmt.Printf("\n=== login failure timing ===\n")
	fmt.Println("latency:")
	fmt.Println(latencyLine(absent.name, a))
	fmt.Println(latencyLine(wrong.name, w))

	delta := percentile(w, 50) - percentile(a, 50)
	lo, hi := bootstrapMedianDiffCI(a, w)
	u, z, p := mannWhitney(a, w)

	fmt.Printf("\nmedian difference (wrong password - unknown email): %s\n", ms(delta))
	fmt.Printf("  bootstrap 95%% CI: [%s, %s]  (%d resamples)\n", ms(lo), ms(hi), bootstrapRounds)
	fmt.Printf("  Mann-Whitney U=%.0f  z=%.3f  p=%.4f (two-sided)\n", u, z, p)

	tol := cfg.timingTolerance
	withinTol := lo >= -tol && hi <= tol
	livenessOK := percentile(a, 50) >= timingFloor && percentile(w, 50) >= timingFloor

	fmt.Println()
	fmt.Println("gates:")
	fmt.Printf("  %-12s CI within +/-%s ....... %s\n", "equivalence", ms(tol), passFail(withinTol))
	fmt.Printf("  %-12s both p50 >= %s ........ %s\n", "liveness", ms(timingFloor), passFail(livenessOK))

	// The p-value is deliberately not a gate. Failing to detect a difference is
	// not the same as showing there is none, and at a few hundred samples a high
	// p-value is weak evidence either way. The CI is the claim being made.
	if !livenessOK {
		fmt.Println("\n!! LIVENESS FAILED: responses came back faster than the padding floor, so padFailure")
		fmt.Println("!! is not delaying anything. The two groups matching here means nothing: an")
		fmt.Println("!! unpadded server also returns two identical distributions.")
	}
	if !withinTol {
		fmt.Println("\n!! EQUIVALENCE FAILED: the two paths are distinguishable by response time, which is")
		fmt.Println("!! exactly the email enumeration oracle the padding exists to close.")
	}

	fmt.Println("\nnote: nginx round-robins across app1/app2/app3 and each replica calibrates its own")
	fmt.Println("target at boot, so the pooled distribution is a mixture of three and may look")
	fmt.Println("multi-modal. Both groups sample that mixture in the same proportion, which is why")
	fmt.Println("the analysis above is rank-based and median-centred rather than assuming one mode.")

	if !withinTol || !livenessOK {
		return fmt.Errorf("timing check FAILED")
	}
	fmt.Println("\ntiming check PASSED")
	return nil
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

// bootstrapMedianDiffCI resamples both groups with replacement and returns the
// 2.5th and 97.5th percentiles of the median difference.
func bootstrapMedianDiffCI(a, w []time.Duration) (time.Duration, time.Duration) {
	if len(a) == 0 || len(w) == 0 {
		return 0, 0
	}
	rng := rand.New(rand.NewSource(1))
	diffs := make([]time.Duration, bootstrapRounds)
	ra := make([]time.Duration, len(a))
	rw := make([]time.Duration, len(w))

	for i := 0; i < bootstrapRounds; i++ {
		for j := range ra {
			ra[j] = a[rng.Intn(len(a))]
		}
		for j := range rw {
			rw[j] = w[rng.Intn(len(w))]
		}
		sort.Slice(ra, func(x, y int) bool { return ra[x] < ra[y] })
		sort.Slice(rw, func(x, y int) bool { return rw[x] < rw[y] })
		diffs[i] = percentile(rw, 50) - percentile(ra, 50)
	}

	sort.Slice(diffs, func(i, j int) bool { return diffs[i] < diffs[j] })
	return percentile(diffs, bootstrapAlpha/2*100), percentile(diffs, (1-bootstrapAlpha/2)*100)
}

// mannWhitney is the rank-sum test with a normal approximation and a tie
// correction. Rank-based on purpose: the pooled latencies are a mixture across
// replicas, so a test assuming one normal distribution would be answering a
// question the data cannot support.
func mannWhitney(a, w []time.Duration) (u, z, p float64) {
	na, nw := len(a), len(w)
	if na == 0 || nw == 0 {
		return 0, 0, 1
	}

	type obs struct {
		v time.Duration
		g int
	}
	all := make([]obs, 0, na+nw)
	for _, v := range a {
		all = append(all, obs{v, 0})
	}
	for _, v := range w {
		all = append(all, obs{v, 1})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v < all[j].v })

	ranks := make([]float64, len(all))
	var tieCorrection float64
	for i := 0; i < len(all); {
		j := i
		for j < len(all) && all[j].v == all[i].v {
			j++
		}
		avg := float64(i+j+1) / 2
		for k := i; k < j; k++ {
			ranks[k] = avg
		}
		if t := float64(j - i); t > 1 {
			tieCorrection += t*t*t - t
		}
		i = j
	}

	var rankSumA float64
	for i, o := range all {
		if o.g == 0 {
			rankSumA += ranks[i]
		}
	}

	fna, fnw := float64(na), float64(nw)
	uA := rankSumA - fna*(fna+1)/2
	u = math.Min(uA, fna*fnw-uA)

	meanU := fna * fnw / 2
	n := fna + fnw
	varU := fna * fnw / 12 * ((n + 1) - tieCorrection/(n*(n-1)))
	if varU <= 0 {
		return u, 0, 1
	}
	z = (uA - meanU) / math.Sqrt(varU)
	p = 2 * (1 - normalCDF(math.Abs(z)))
	if p > 1 {
		p = 1
	}
	return u, z, p
}

func normalCDF(x float64) float64 {
	return 0.5 * math.Erfc(-x/math.Sqrt2)
}
