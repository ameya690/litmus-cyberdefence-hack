#!/usr/bin/env bash
# Litmus Report stage: serve the live dashboard (reads litmus/events.jsonl).
# Needs Flask on the host: pip install -r dashboard/requirements.txt
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
exec python3 dashboard/server.py
