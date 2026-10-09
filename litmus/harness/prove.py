"""Litmus Prove stage -- scripted baseline (BUILD_PLAN Block 2 floor).

For each Semgrep candidate: plant a fresh random secret, run the NEGATIVE
CONTROL (a benign request that must NOT yield the flag), run the file-read
exploit, and let the oracle stamp PROVEN / UNPROVEN by reading the target's
response bytes. Every step is emitted to the event log for the Report stage.

Only the real path-traversal candidate yields the flag; the decoy findings are
attempted honestly and come back UNPROVEN -- that is the funnel.

Modes:
  local    target reachable on localhost; exploit runs in-process (fast dev).
  compose  two-container topology; the exploit runs INSIDE the attacker
           container, which can reach the target ONLY over the Docker network
           (BUILD_PLAN Q2/Q3). This is the real deliverable.

NOTE ON INTEGRITY: in this scripted baseline the exploit relays the target's
response and the oracle checks it. When the untrusted LLM agent is added
(Block 3), a capturing proxy sits between attacker and target so the oracle
observes the target's bytes independently of anything the agent claims.
"""
import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LITMUS = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LITMUS, "oracle"))
sys.path.insert(0, os.path.join(LITMUS, "attacker"))
from oracle import FileReadOracle  # noqa: E402
import exploit as exploit_mod  # noqa: E402
from events import EventLog  # noqa: E402

SECRET_PATH = os.path.join(LITMUS, "challenge", "secret")
COMPOSE_FILE = os.path.join(LITMUS, "docker-compose.yml")

# Candidates as they would arrive from the Detect stage (Semgrep findings mapped
# to the endpoint each one lives in). Litmus attempts the file-read capability
# against every one; only the traversal proves out.
CANDIDATES = [
    {"id": "traversal", "cwe": "CWE-22", "endpoint": "/download", "param": "file",
     "benign": "welcome.txt", "exploit": "../../challenge/secret",
     "finding": "path-traversal-open @ app.py:68"},
    {"id": "sqli-search", "cwe": "CWE-89", "endpoint": "/search", "param": "q",
     "benign": "alice", "exploit": "../../challenge/secret",
     "finding": "tainted-sql-string @ app.py:99"},
    {"id": "md5-login", "cwe": "CWE-327", "endpoint": "/login", "param": "password",
     "benign": "password", "exploit": "../../challenge/secret",
     "finding": "md5-used-as-password @ app.py:88"},
]


def run_exploit(mode, target_url, endpoint, param, payload):
    """Produce the target's raw response bytes for one request."""
    if mode == "local":
        return exploit_mod.exploit(target_url, endpoint, param, payload)
    out = subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "exec", "-T", "attacker",
         "python", "/app/exploit.py", target_url, endpoint, param, payload],
        capture_output=True,
    )
    return out.stdout


def wait_for_target(mode, target_url, tries=20):
    for _ in range(tries):
        body = run_exploit(mode, target_url, "/", "x", "x")
        if body and b"Document Portal" in body:
            return True
        time.sleep(1)
    return False


def prove_candidate(c, oracle, target_url, mode, log):
    log.emit("candidate_found", id=c["id"], cwe=c["cwe"], finding=c["finding"])
    flag = oracle.plant()  # fresh random secret per candidate
    print(f"\n[{c['id']}] {c['finding']}")
    print(f"  planted {flag}  (the attacker is never told this value)")

    # 1) Negative control: a benign request must NOT yield the flag.
    neg = run_exploit(mode, target_url, c["endpoint"], c["param"], c["benign"])
    control_ok = not oracle.verify(neg)
    log.emit("negative_control", id=c["id"], passed=control_ok)
    print(f"  negative control: GET {c['endpoint']}?{c['param']}={c['benign']}"
          f" -> {'no flag (control holds)' if control_ok else 'FLAG LEAKED (reject)'}")
    if not control_ok:
        log.emit("proof_result", id=c["id"], status="REJECTED",
                 reason="baseline leaked flag")
        print("  => REJECTED (baseline leaked the flag; not attributable to the bug)")
        return {"id": c["id"], "status": "REJECTED"}

    # 2) Exploit attempt: does the target emit the flag on the wire?
    t0 = time.time()
    resp = run_exploit(mode, target_url, c["endpoint"], c["param"], c["exploit"])
    ms = int((time.time() - t0) * 1000)
    proven = oracle.verify(resp)
    log.emit("proof_attempted", id=c["id"], ms=ms, driver="scripted")
    status = "PROVEN" if proven else "UNPROVEN"
    artifact = (f"GET {c['endpoint']}?{c['param']}={c['exploit']}") if proven else None
    log.emit("proof_result", id=c["id"], status=status, artifact=artifact, ms=ms)
    print(f"  exploit:          GET {c['endpoint']}?{c['param']}={c['exploit']}"
          f" -> {'FLAG RETURNED' if proven else 'no flag'}  ({ms} ms)")
    print(f"  => {status}" + (f"  (proof: {artifact})" if artifact else ""))
    return {"id": c["id"], "status": status, "artifact": artifact}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["local", "compose"], default="compose")
    ap.add_argument("--target-url", default=None)
    ap.add_argument("--events", default=os.path.join(LITMUS, "events.jsonl"))
    args = ap.parse_args()

    target_url = args.target_url or (
        "http://127.0.0.1:8000" if args.mode == "local" else "http://target:5000")

    log = EventLog(args.events)
    oracle = FileReadOracle(SECRET_PATH)
    log.emit("run_started", mode=args.mode, target=target_url, candidates=len(CANDIDATES))

    print(f"== Litmus Prove ==  mode={args.mode}  target={target_url}")
    if not wait_for_target(args.mode, target_url):
        print("ERROR: target not reachable", file=sys.stderr)
        sys.exit(2)

    results = [prove_candidate(c, oracle, target_url, args.mode, log) for c in CANDIDATES]
    proven = sum(1 for r in results if r["status"] == "PROVEN")
    print(f"\nSummary: {proven} PROVEN, {len(results) - proven} not proven "
          f"(of {len(results)} candidates)")
    log.emit("run_finished", proven=proven, total=len(results))


if __name__ == "__main__":
    main()
