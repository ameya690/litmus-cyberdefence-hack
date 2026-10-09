#!/usr/bin/env bash
# Litmus end-to-end LIVE: build, start, and run the agent-with-fallback prove loop.
# Needs a Claude credential (ANTHROPIC_API_KEY or an SDK/ant profile) for the live
# agent; without one it degrades to the scripted fallback automatically.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
docker compose up -d --build
python3 harness/prove_live.py "$@"
