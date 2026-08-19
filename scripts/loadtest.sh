#!/usr/bin/env bash
#
# One load test run at one fixed concurrency level, start to finish:
# bring the stack up, sample CPU while the generator works, write one markdown
# report, exit.
#
# Normally invoked through the Makefile (`make loadtest CONCURRENCY=200`), which
# is only a thin wrapper around this. Run it directly if you prefer.
#
# The CPU sampling is the reason this is a script rather than a compose command.
# `docker stats` has to run on the host, outside the containers being measured,
# for the whole time the generator is working — and it has to be stopped and
# cleaned up afterwards even if the run fails or is interrupted.

set -euo pipefail

# Repairs the Windows environment (ProgramFiles, path-conversion switches) that a
# make recipe does not pass through. Without this, `docker compose` inside a
# Makefile target fails with "unknown command: docker compose".
source "$(dirname "$0")/win-env.sh"

# --- Configuration ---------------------------------------------------------
#
# Environment variables supply the defaults; command-line flags override them.
# The Makefile passes flags, because the environment is the one channel that does
# not survive a make recipe here — see scripts/win-env.sh.
CONCURRENCY="${CONCURRENCY:-100}"
DURATION="${DURATION:-30s}"
WARMUP="${WARMUP:-10s}"
THINK="${THINK:-0}"
TIMEOUT="${TIMEOUT:-10s}"
CORES="${CORES:-8}"
CORE_RANGE="${CORE_RANGE:-0-7}"
CEILING="${CEILING:-14000}"
RESULTS_DIR="${RESULTS_DIR:-results}"

# Everything under test. An explicit list, not a wildcard: the generator runs on
# cores 8-11 and including it would inflate the saturation number for the cores
# it is measuring. This is the single place that guarantees it cannot leak in.
SERVICES=(postgres redis app1 app2 app3 nginx)

usage() {
    cat << 'HELPEOF'
loadtest.sh — run one load test at one concurrency level and write one report.

RUNNING IT
    bash scripts/loadtest.sh --concurrency 200
    CONCURRENCY=200 bash scripts/loadtest.sh
    make loadtest CONCURRENCY=200            # same thing

WHAT IT DOES
    1. Brings up the stack (postgres, redis, app1-3, nginx) if it is not running.
    2. Rebuilds the loadgen image so harness edits are picked up.
    3. Waits for nginx to actually answer, not just to have started.
    4. Streams `docker stats` for the six services under test, on the host, in
       the background, for the length of the run.
    5. Runs the generator inside the compose network at the given concurrency.
    6. Stops the collector and merges its samples with the run summary into
       results/loadtest_<concurrency>_<timestamp>.md

OPTIONS                                                            (default)
    --concurrency N    concurrent virtual users, the controlled variable  (100)
    --duration D       measured window, excluding warmup                  (30s)
    --warmup D         traffic discarded before measuring                 (10s)
    --think D          pause between a user's requests; 0 = flat out      (0)
    --timeout D        per-request timeout                                (10s)
    --cores N          cores allocated to the stack, saturation denominator (8)
    --core-range S     label for those cores, for the report text         (0-7)
    --ceiling N        throughput ceiling for the headroom section, req/s (14000)
    --results-dir D    where reports are written                          (results)
    -h, --help         print this and exit without touching Docker

Every option can also be given as an environment variable in caps
(CONCURRENCY, DURATION, ...). Flags win over the environment.

The endpoint is fixed at GET /api/v1/health. See docs/LOADTEST.md.
HELPEOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --concurrency)
            CONCURRENCY="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --warmup)
            WARMUP="$2"
            shift 2
            ;;
        --think)
            THINK="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --cores)
            CORES="$2"
            shift 2
            ;;
        --core-range)
            CORE_RANGE="$2"
            shift 2
            ;;
        --ceiling)
            CEILING="$2"
            shift 2
            ;;
        --results-dir)
            RESULTS_DIR="$2"
            shift 2
            ;;
        -h | --help | help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option '$1'" >&2
            echo "run 'bash scripts/loadtest.sh --help' for usage" >&2
            exit 2
            ;;
    esac
done

cd "$(dirname "$0")/.."

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN="loadtest_${CONCURRENCY}_${STAMP}"
mkdir -p "$RESULTS_DIR"

CPU_CSV="${RESULTS_DIR}/${RUN}_cpu.csv"
SUMMARY_JSON="${RESULTS_DIR}/${RUN}.json"
REPORT_MD="${RESULTS_DIR}/${RUN}.md"

COLLECTOR_PID=""

# The collector outlives any single command in this script, so it needs to be
# reaped on every exit path — a failed run or a Ctrl-C included. Without this a
# stray `docker stats` stream keeps running after the script is gone.
cleanup() {
    if [[ -n "$COLLECTOR_PID" ]] && kill -0 "$COLLECTOR_PID" 2> /dev/null; then
        # The collector is a pipeline (docker stats | sed | grep | while), so the
        # PID captured below names only the subshell wrapping it. Killing that
        # alone would leave `docker stats` streaming after the script exits, which
        # is why the job is started under `set -m`: it gets its own process group,
        # and the negative PID below kills every member of it. pkill would be the
        # obvious tool but Git Bash does not ship one.
        kill -- -"$COLLECTOR_PID" 2> /dev/null || kill "$COLLECTOR_PID" 2> /dev/null || true
        wait "$COLLECTOR_PID" 2> /dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "==> run ${RUN}"
echo "    concurrency=${CONCURRENCY} duration=${DURATION} warmup=${WARMUP} think=${THINK}"

echo "==> bringing up the stack"
docker compose up -d "${SERVICES[@]}"

echo "==> building the load generator image"
docker compose build loadgen

# nginx lists app1-3 in depends_on without a condition, so it can be up and
# accepting connections before any replica can answer. Polling the endpoint the
# run actually targets is the only check that means anything.
echo "==> waiting for the gateway to answer"
ready=false
for _ in $(seq 1 60); do
    # Redirect rather than -o /dev/null: MSYS2_ARG_CONV_EXCL above stops Git Bash
    # translating "/dev/null" into "NUL", so mingw curl takes it as a literal path,
    # fails to create the file and exits 23 — even though the request returned 200.
    #
    # https + -k, not http: port 80 now only issues a 301 to 443 (nginx.conf), and
    # curl -f treats a 3xx as success without -L, so probing plaintext would report
    # ready as soon as nginx starts even if the app behind TLS never comes up. -k
    # skips verification of the self-signed dev cert from scripts/gen-dev-cert.sh.
    if curl -skf --max-time 2 https://localhost/api/v1/health > /dev/null; then
        ready=true
        break
    fi
    sleep 1
done
if [[ "$ready" != true ]]; then
    echo "error: gateway did not answer on https://localhost/api/v1/health within 60s" >&2
    echo "       check 'docker compose ps' and 'docker compose logs nginx app1'" >&2
    echo "       and confirm certs/dev.crt exists (bash scripts/gen-dev-cert.sh)" >&2
    exit 1
fi

# Resolve service names to container ids once, up front. Passing ids to
# `docker stats` rather than a name filter is what keeps the generator's own
# run container out of the sample even though it shares the compose project.
mapfile -t CONTAINER_IDS < <(docker compose ps -q "${SERVICES[@]}")
if [[ "${#CONTAINER_IDS[@]}" -eq 0 ]]; then
    echo "error: no running containers found for: ${SERVICES[*]}" >&2
    exit 1
fi
echo "==> sampling CPU for ${#CONTAINER_IDS[@]} containers (generator excluded)"

echo "timestamp,container,cpu_percent" > "$CPU_CSV"

# Streaming, not repeated `--no-stream` calls. `--no-stream` has to take two
# readings to compute a CPU delta, so one poll costs 3-4 seconds on Docker
# Desktop — a 30s window would land about seven samples and miss any peak
# narrower than four seconds. Streaming gives roughly three blocks a second.
#
# The cost is that `docker stats` draws a table: cursor-home, erase-line and
# erase-screen escapes are interleaved with the rows even when stdout is a pipe.
# The sed strips them, and the grep keeps only lines that still look like
# "name,12.34%" — a defensive filter, so a redraw artefact is dropped rather
# than parsed as a container with a nonsense CPU figure.
#
# Timestamps are millisecond-precision on purpose. cmd/loadreport groups samples
# by timestamp and sums each group to get combined CPU, so two blocks sharing a
# timestamp would be added together and report double the real load. At second
# precision that happens constantly, because the redraw rate is faster than 1Hz.
# One timestamp per block of ${#CONTAINER_IDS[@]} rows keeps each group equal to
# exactly one reading.
collect() {
    local n=${#CONTAINER_IDS[@]}
    docker stats --format '{{.Name}},{{.CPUPerc}}' "${CONTAINER_IDS[@]}" 2> /dev/null \
        | sed -u 's/\x1b\[[0-9;]*[A-Za-z]//g; s/[[:space:]]*$//' \
        | grep --line-buffered -E '^[A-Za-z0-9_.-]+,[0-9.]+%$' \
        | {
            local i=0 ts=""
            while IFS= read -r line; do
                if ((i % n == 0)); then
                    ts="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
                fi
                printf '%s,%s\n' "$ts" "$line"
                i=$((i + 1))
            done
        } >> "$CPU_CSV"
}
# Monitor mode just long enough to launch the collector: it puts the background
# job in its own process group, which is what makes the group kill in cleanup()
# able to reach every process in the pipeline.
set -m
collect &
COLLECTOR_PID=$!
set +m

echo "==> running the load test"
set +e
docker compose run --rm loadgen \
    -url=https://nginx:443 \
    -redis=redis:6379 \
    -target=health \
    -users="$CONCURRENCY" \
    -think="$THINK" \
    -duration="$DURATION" \
    -warmup="$WARMUP" \
    -timeout="$TIMEOUT" \
    -json="/report/${RUN}.json"
LOAD_RC=$?
set -e

cleanup
COLLECTOR_PID=""

if [[ "$LOAD_RC" -ne 0 ]]; then
    echo "error: the load generator exited $LOAD_RC — no report written" >&2
    exit "$LOAD_RC"
fi

echo "==> writing the report"
docker compose run --rm --no-deps --entrypoint /loadreport loadgen \
    -json="/report/${RUN}.json" \
    -cpu="/report/${RUN}_cpu.csv" \
    -out="/report/${RUN}.md" \
    -cores="$CORES" \
    -core-range="$CORE_RANGE" \
    -ceiling="$CEILING" \
    -ceiling-label="general throughput ceiling" \
    -ceiling-why="This run drives GET /api/v1/health — the cheap request-handling path through nginx and the three Go replicas, with no Argon2id hashing and no Postgres round trip. The login-specific ~105 req/s ceiling does not apply, because no login was issued: that ceiling is set by Argon2id saturating all cores, and nothing in this run hashes a password." \
    -concurrency="$CONCURRENCY"

echo
echo "==> done"
echo "    report:  ${REPORT_MD}"
echo "    summary: ${SUMMARY_JSON}"
echo "    cpu:     ${CPU_CSV}"
