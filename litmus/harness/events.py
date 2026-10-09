"""Append-only JSONL event log -- the local backing store for the Report stage.

Every pipeline event lands here (candidate found, negative control, proof
attempted, proof result, with per-stage latency). ClickHouse swaps in behind
this same emit() interface later (BUILD_PLAN section 3 / Block 4).
"""
import json
import os
import time


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
        return rec
