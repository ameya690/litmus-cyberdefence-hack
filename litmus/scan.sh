#!/usr/bin/env bash
# Litmus — Detect stage. Runs Semgrep (default/auto rules) against the target app.
# Verified in Block 1: fires `python...path-traversal-open` on the planted sink
# (litmus/target_app/app.py:/download). Pass --json for machine-readable output.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec docker run --rm -v "$HERE/target_app:/src" -w /src semgrep/semgrep \
  semgrep scan --config=auto --no-git-ignore "$@"
