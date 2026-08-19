#!/usr/bin/env bash
#
# Environment repair for running this repo's tooling from a Makefile on Windows.
# Source it — do not execute it — before invoking docker, docker compose, or go:
#
#     source "$(dirname "$0")/win-env.sh"
#
# It is sourced by scripts/loadtest.sh and scripts/compose.sh, and by the `test`
# target directly. Every Makefile target that shells out goes through it.
#
# --- Why this is needed ----------------------------------------------------
#
# GNU Make on MSYS hands its recipes an environment stripped of the Windows-side
# variables: USERPROFILE, ProgramFiles, LOCALAPPDATA and friends are all gone,
# and on this toolchain it does not propagate new ones either — neither a
# `VAR=x cmd` prefix nor make's own `export` directive reaches a child process.
#
# Two things break as a result. The Docker CLI locates its cli-plugins directory
# through %ProgramFiles%, so `docker compose` fails with "unknown command: docker
# compose"; and the Go toolchain derives GOPATH from %USERPROFILE%, so `go test`
# fails with "neither GOMODCACHE nor GOPATH is set". Both work when the identical
# command is typed at a prompt, which makes for a confusing bug report.
# Establishing the values here rather than inheriting them is what makes
# `make <target>` and a direct run behave the same.
#
# The `:-` defaults only fill in values that are missing, so a normal shell that
# already has them is left untouched.

export ProgramFiles="${ProgramFiles:-C:\\Program Files}"
export USERPROFILE="${USERPROFILE:-$(cygpath -w "$HOME" 2> /dev/null || echo "C:\\Users\\${USER:-${LOGNAME:-}}")}"

# Derived from USERPROFILE rather than hardcoded, so they stay correct on a
# machine whose profile does not live under C:\Users. Go needs LOCALAPPDATA for
# its build cache ("build cache is required, but could not be located") on top
# of USERPROFILE for GOPATH.
export LOCALAPPDATA="${LOCALAPPDATA:-${USERPROFILE}\\AppData\\Local}"
export APPDATA="${APPDATA:-${USERPROFILE}\\AppData\\Roaming}"

# Git Bash rewrites arguments that look like Unix paths into Windows paths before
# handing them to a native binary, which turns `-json=/report/run.json` into
# `-json=C:/Program Files/Git/report/run.json` inside a container. These two
# switch that off, so container-side paths survive intact.
#
# Note the knock-on effect: with conversion off, "/dev/null" is no longer
# translated to "NUL" either, so a native tool given `-o /dev/null` will take it
# as a literal path and fail. Use a shell redirect instead.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
