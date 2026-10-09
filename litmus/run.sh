#!/usr/bin/env bash
# Litmus end-to-end (two-container): build, start, prove, show the funnel.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
docker compose up -d --build
python3 harness/prove.py --mode compose
