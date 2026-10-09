"""Append-only JSONL event log -- the local backing store for the Report stage.

Every pipeline event lands here (candidate found, negative control, proof
attempted, proof result, with per-stage latency). ClickHouse swaps in behind
this same emit() interface later (BUILD_PLAN section 3 / Block 4).
"""
import json
import os
import sys
import time

# Make the ClickHouse client importable (litmus/report), without a hard dependency.
_REPORT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "report")
if _REPORT not in sys.path:
    sys.path.insert(0, _REPORT)


class EventLog:
    def __init__(self, path):
        self.path = path
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)

    def emit(self, event, **fields):
        rec = {"ts": round(time.time(), 3), "event": event, **fields}
        with open(self.path, "a") as f:
            f.write(json.dumps(rec) + "\n")
        # Mirror to ClickHouse when enabled; never let the store break the pipeline.
        try:
            import clickhouse
            if clickhouse.enabled():
                clickhouse.insert_event(rec)
        except Exception:  # noqa: BLE001
            pass
        return rec
