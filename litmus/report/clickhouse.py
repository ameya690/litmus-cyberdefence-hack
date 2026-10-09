"""ClickHouse backing store for Litmus events (the Report stage's scale store).

Same event records as the JSONL log, inserted over ClickHouse's HTTP interface
(stdlib only -- no driver dependency). read_events() returns the same
list-of-dicts that aggregate_state() already folds, so ClickHouse is a drop-in
behind the dashboard's read path (BUILD_PLAN: "swap in behind the same read
interface"). funnel() runs the aggregation in ClickHouse and reports its own
query latency -- the ClickHouse prize is judged on scale, query latency, and
insight, so the funnel is computed there, not in Python.

Enabled when LITMUS_CLICKHOUSE is set; URL from CLICKHOUSE_URL
(default http://127.0.0.1:8123). No auth (the dev image's default user).
"""
import json
import os
import time
import urllib.parse
import urllib.request

DB = os.environ.get("CLICKHOUSE_DB", "litmus")
TABLE = f"{DB}.events"
_schema_ready = False


def enabled():
    return bool(os.environ.get("LITMUS_CLICKHOUSE"))


def _url():
    return os.environ.get("CLICKHOUSE_URL", "http://127.0.0.1:8123")


def _exec(sql, body=None, timeout=10):
    url = _url() + "/?" + urllib.parse.urlencode({"query": sql})
    data = body.encode() if isinstance(body, str) else (body or b"")
    req = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def ensure_schema():
    global _schema_ready
    if _schema_ready:
        return
    _exec(f"CREATE DATABASE IF NOT EXISTS {DB}")
    _exec(
        f"CREATE TABLE IF NOT EXISTS {TABLE} ("
        "ts Float64, event LowCardinality(String), cand_id String, "
        "status LowCardinality(String), driver LowCardinality(String), "
        "verdict LowCardinality(String), cwe LowCardinality(String), "
        "endpoint String, ms Int32, raw String"
        ") ENGINE = MergeTree ORDER BY ts"
    )
    _schema_ready = True


def insert_event(rec):
    ensure_schema()
    row = {
        "ts": rec.get("ts", time.time()),
        "event": rec.get("event", ""),
        "cand_id": str(rec.get("id", "")),
        "status": str(rec.get("status", "")),
        "driver": str(rec.get("driver") or ""),
        "verdict": str(rec.get("verdict", "")),
        "cwe": str(rec.get("cwe", "")),
        "endpoint": str(rec.get("endpoint", "")),
        "ms": int(rec.get("ms") or 0),
        "raw": json.dumps(rec),
    }
    _exec(f"INSERT INTO {TABLE} FORMAT JSONEachRow", json.dumps(row) + "\n")


def read_events():
    """Return all events as dicts, oldest first (aggregate_state scopes to the latest run)."""
    ensure_schema()
    out = _exec(f"SELECT raw FROM {TABLE} ORDER BY ts FORMAT JSONEachRow")
    evs = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evs.append(json.loads(json.loads(line)["raw"]))
        except Exception:  # noqa: BLE001
            pass
    return evs


def funnel():
    """Cumulative funnel across ALL runs, computed in ClickHouse, with query latency."""
    ensure_schema()
    sql = (
        "SELECT "
        "countIf(event='run_started') AS runs, "
        "countIf(event='candidate_found') AS candidates, "
        "countIf(event='triaged' AND verdict='likely') AS likely, "
        "countIf(event='proof_result' AND status='PROVEN') AS proven, "
        "countIf(event='proof_result' AND status='UNPROVEN') AS unproven, "
        "countIf(event='proof_result' AND driver='agent') AS by_agent, "
        "round(avgIf(ms, event='proof_result' AND ms > 0)) AS avg_proof_ms, "
        "count() AS rows "
        f"FROM {TABLE} FORMAT JSON"
    )
    t0 = time.time()
    out = _exec(sql)
    query_ms = round((time.time() - t0) * 1000, 1)
    row = (json.loads(out).get("data") or [{}])[0]
    row["query_ms"] = query_ms
    return row
