# Load testing entry points. Everything here is testing infrastructure; nothing
# in this file builds or runs the gateway itself outside of docker compose.
#
#   make loadtest CONCURRENCY=200
#
# See docs/LOADTEST.md for what the numbers mean.

# Tunables. Override on the command line: make loadtest CONCURRENCY=500 DURATION=60s
CONCURRENCY ?= 100
DURATION    ?= 30s
WARMUP      ?= 10s
THINK       ?= 0
TIMEOUT     ?= 10s
CORES       ?= 8
CORE_RANGE  ?= 0-7
CEILING     ?= 14000
RESULTS_DIR ?= results

# Every service under test. The load generator is deliberately absent: it runs on
# cores 8-11 and is not part of what is being measured.
SERVICES = postgres redis app1 app2 app3 nginx

# Passed as flags, not as environment. GNU Make on MSYS does not propagate
# environment variables to a recipe's child processes at all here — neither a
# `VAR=x cmd` prefix nor make's own `export` directive arrives — so anything sent
# that way silently falls back to the script's defaults. Arguments always arrive.
LOADTEST_ARGS = --concurrency $(CONCURRENCY) --duration $(DURATION) --warmup $(WARMUP) \
                --think $(THINK) --timeout $(TIMEOUT) --cores $(CORES) \
                --core-range $(CORE_RANGE) --ceiling $(CEILING) --results-dir $(RESULTS_DIR)

.DEFAULT_GOAL := help
.PHONY: help loadtest up down ps logs build test clean-results

help: ## Show this help
	@echo "Load testing targets:"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Tunables (shown at their current value; override on the command line,"
	@echo "e.g. make loadtest CONCURRENCY=500 DURATION=60s):"
	@printf "  \033[36m%-22s\033[0m %s\n" \
		"CONCURRENCY=$(CONCURRENCY)"   "concurrent virtual users; the controlled variable" \
		"DURATION=$(DURATION)"         "measured window, excluding warmup" \
		"WARMUP=$(WARMUP)"             "traffic discarded before measuring" \
		"THINK=$(THINK)"               "pause between a user's requests; 0 = flat out" \
		"TIMEOUT=$(TIMEOUT)"           "per-request timeout" \
		"CORES=$(CORES)"               "cores allocated to the stack; saturation denominator" \
		"CORE_RANGE=$(CORE_RANGE)"     "label for those cores, for the report text" \
		"CEILING=$(CEILING)"           "throughput ceiling for the headroom section, req/s" \
		"RESULTS_DIR=$(RESULTS_DIR)"   "where reports are written"
	@echo
	@echo "One run = one concurrency level. Sweep by invoking it several times:"
	@echo "  make loadtest CONCURRENCY=50 && make loadtest CONCURRENCY=100 && make loadtest CONCURRENCY=200"
	@echo
	@echo "Full documentation: docs/LOADTEST.md"

loadtest: ## Run one load test at CONCURRENCY and write results/loadtest_<n>_<ts>.md
	@bash scripts/loadtest.sh $(LOADTEST_ARGS)

# Every Docker call goes through scripts/compose.sh, which repairs the Windows
# environment first. A make recipe here does not inherit the variables the Docker
# CLI needs to locate its compose plugin, so a bare `docker compose` in a recipe
# fails with "unknown command: docker compose" while the same line typed at a
# prompt works. See scripts/win-env.sh.
up: ## Start the stack (services under test only, not the generator)
	@bash scripts/compose.sh up -d $(SERVICES)

down: ## Stop the stack, keeping the postgres volume
	@bash scripts/compose.sh down

ps: ## Show the state of every compose service
	@bash scripts/compose.sh ps

logs: ## Tail the gateway and nginx logs
	@bash scripts/compose.sh logs -f nginx app1 app2 app3

build: ## Rebuild the app and load generator images
	@bash scripts/compose.sh build $(SERVICES) loadgen

test: ## Run the Go unit tests
	@bash -c 'source scripts/win-env.sh; go test ./...'

clean-results: ## Delete the raw CPU CSVs, keeping the markdown reports and summaries
	@rm -f $(RESULTS_DIR)/*_cpu.csv
	@echo "removed raw CPU samples from $(RESULTS_DIR)/ (reports and summaries kept)"
