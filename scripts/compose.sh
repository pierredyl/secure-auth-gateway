#!/usr/bin/env bash
#
# `docker compose` with the Windows environment repaired first.
#
#     bash scripts/compose.sh ps
#     bash scripts/compose.sh up -d nginx
#
# Every Makefile target that touches Docker goes through this rather than
# calling `docker compose` directly, because a make recipe does not inherit the
# environment the Docker CLI needs to find its compose plugin. See
# scripts/win-env.sh for the full explanation.
set -euo pipefail

cd "$(dirname "$0")/.."
source scripts/win-env.sh

exec docker compose "$@"
