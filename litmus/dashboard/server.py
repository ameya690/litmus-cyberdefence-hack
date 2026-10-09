"""Litmus Report stage -- the live dashboard.

Reads the append-only event log (litmus/events.jsonl) that the Prove stage
writes, aggregates the latest run into a funnel + per-finding results, and serves
them to a self-refreshing page. This is the demo surface (BUILD_PLAN Block 3/4):
run the prove loop in one terminal and watch findings flip PROVEN/UNPROVEN here.

ClickHouse swaps in behind the same read shape later: aggregate_state() is the
one place that reads events, so only its source changes.

Run:  python dashboard/server.py   (then open http://127.0.0.1:8900)
"""
import json
import os
import sys

from flask import Flask, Response, jsonify

HERE = os.path.dirname(os.path.abspath(__file__))
LITMUS = os.path.dirname(HERE)
EVENTS = os.environ.get("LITMUS_EVENTS", os.path.join(LITMUS, "events.jsonl"))
sys.path.insert(0, os.path.join(LITMUS, "report"))

app = Flask(__name__)


def _read_events():
    # ClickHouse is a drop-in behind this read: same records, same folding below.
    try:
        import clickhouse
        if clickhouse.enabled():
            return clickhouse.read_events()
    except Exception:  # noqa: BLE001 - fall back to the local log if CH is unreachable
        pass
    try:
        with open(EVENTS) as f:
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []


def aggregate_state():
    """Fold the event log into the latest run's funnel + per-finding results."""
    events = _read_events()
    # Scope to the latest run (from the last run_started onward).
    starts = [i for i, e in enumerate(events) if e["event"] == "run_started"]
    run = events[starts[-1]:] if starts else []

    meta = next((e for e in run if e["event"] == "run_started"), {})
    order, cands = [], {}
    for e in run:
        cid = e.get("id")
        if e["event"] == "candidate_found":
            if cid not in cands:
                order.append(cid)
            cands[cid] = {"id": cid, "cwe": e.get("cwe"), "finding": e.get("finding"),
                          "endpoint": e.get("endpoint"), "flag": None, "control": None,
                          "triage": None, "status": "pending", "artifact": None,
                          "driver": None, "ms": None}
        elif cid in cands:
            c = cands[cid]
            if e["event"] == "secret_planted":
                c["flag"] = e.get("flag")
            elif e["event"] == "triaged":
                c["triage"] = e.get("verdict")
            elif e["event"] == "negative_control":
                c["control"] = bool(e.get("passed"))
            elif e["event"] == "proof_result":
                c["status"] = e.get("status", "pending").lower()
                c["artifact"] = e.get("artifact")
                c["driver"] = e.get("driver")
                c["ms"] = e.get("ms")

    results = [cands[c] for c in order]
    proven = sum(1 for c in results if c["status"] == "proven")
    unproven = sum(1 for c in results if c["status"] == "unproven")
    rejected = sum(1 for c in results if c["status"] == "rejected")
    likely = sum(1 for c in results if c["triage"] == "likely")
    finished = next((e for e in run if e["event"] == "run_finished"), None)
    return {
        "mode": meta.get("mode"),
        "agent": meta.get("agent"),
        "triage": meta.get("triage"),
        "target": meta.get("target") or meta.get("proxy"),
        "total": len(results),
        "likely": likely,
        "proven": proven,
        "unproven": unproven,
        "rejected": rejected,
        "running": finished is None and len(results) > 0,
        "results": results,
        # The most recently planted secret drives the "visible randomness" callout.
        "latest_secret": next((c["flag"] for c in reversed(results) if c["flag"]), None),
    }


@app.route("/api/state")
def api_state():
    return jsonify(aggregate_state())


@app.route("/api/ch")
def api_ch():
    """Cumulative funnel across all runs, computed in ClickHouse (scale + latency)."""
    try:
        import clickhouse
        if not clickhouse.enabled():
            return jsonify({"enabled": False})
        f = clickhouse.funnel()
        f["enabled"] = True
        return jsonify(f)
    except Exception as e:  # noqa: BLE001
        return jsonify({"enabled": False, "error": str(e)})


@app.route("/")
def index():
    with open(os.path.join(HERE, "index.html")) as f:
        return Response(f.read(), mimetype="text/html")


if __name__ == "__main__":
    print(f"Litmus dashboard -> http://127.0.0.1:8900  (events: {EVENTS})")
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8900")), debug=False)
