"""Litmus Prove stage -- LIVE (BUILD_PLAN Block 3).

Per candidate: plant a fresh secret, run the negative control, let the LLM agent
attempt the exploit live through the capturing proxy, and fall back to the
scripted exploit if the agent stalls, fails, or is unavailable. The oracle's
verdict comes from the proxy's WIRE CAPTURE (the target's actual response bytes),
never from anything the agent claims -- so agent and fallback are indistinguishable
and a hallucination cannot pass.

The handoff is invisible: the verdict is PROVEN/UNPROVEN, not "which driver."
The driver is recorded in the event log for our own analysis only.

Everything is driven from the host through the proxy at http://127.0.0.1:8080;
the target itself publishes no host port.
"""
import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LITMUS = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LITMUS, "oracle"))
sys.path.insert(0, os.path.join(LITMUS, "attacker"))
from oracle import FileReadOracle  # noqa: E402
import exploit as exploit_mod  # noqa: E402
import agent as agent_mod  # noqa: E402
from events import EventLog  # noqa: E402

SECRET_PATH = os.path.join(LITMUS, "challenge", "secret")
CAPTURE_PATH = os.path.join(LITMUS, "capture", "wire.log")

# Same candidates as the scripted baseline (prove.py): the Detect-stage findings.
from prove import CANDIDATES  # noqa: E402


def reset_capture():
    os.makedirs(os.path.dirname(CAPTURE_PATH), exist_ok=True)
    open(CAPTURE_PATH, "wb").close()


def read_capture():
    try:
        with open(CAPTURE_PATH, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return b""


def wait_for_target(proxy_url, tries=20):
    for _ in range(tries):
        if b"Document Portal" in (exploit_mod.exploit(proxy_url, "/", "x", "x") or b""):
            return True
        time.sleep(1)
    return False


def prove_candidate(c, oracle, proxy_url, log, use_agent, agent_timeout):
    log.emit("candidate_found", id=c["id"], cwe=c["cwe"], finding=c["finding"])
    flag = oracle.plant()
    print(f"\n[{c['id']}] {c['finding']}")
    print(f"  planted {flag}  (the attacker is never told this value)")

    # 1) Negative control through the proxy -- benign request must NOT yield the flag.
    reset_capture()
    exploit_mod.exploit(proxy_url, c["endpoint"], c["param"], c["benign"])
    control_ok = not oracle.verify(read_capture())
    log.emit("negative_control", id=c["id"], passed=control_ok)
    print(f"  negative control: {c['endpoint']}?{c['param']}={c['benign']}"
          f" -> {'no flag (holds)' if control_ok else 'FLAG LEAKED'}")
    if not control_ok:
        log.emit("proof_result", id=c["id"], status="REJECTED", reason="baseline leaked")
        print("  => REJECTED (baseline leaked the flag)")
        return {"id": c["id"], "status": "REJECTED", "driver": None}

    # 2) Live agent attempt (through the proxy), if enabled.
    driver, note = None, None
    reset_capture()
    t0 = time.time()
    if use_agent:
        try:
            agent_mod.run_agent(proxy_url, c, timeout=agent_timeout)
            print(f"  agent: attempted live ({int(time.time()-t0)}s)")
        except (agent_mod.AgentUnavailable, agent_mod.AgentTimeout) as e:
            note = f"{type(e).__name__}: {e}"
            print(f"  agent: {note} -> falling back")
    if oracle.verify(read_capture()):
        driver = "agent"

    # 3) Fallback: scripted exploit through the proxy (invisible handoff).
    if driver is None:
        reset_capture()
        exploit_mod.exploit(proxy_url, c["endpoint"], c["param"], c["exploit"])
        if oracle.verify(read_capture()):
            driver = "fallback"

    ms = int((time.time() - t0) * 1000)
    proven = driver is not None
    status = "PROVEN" if proven else "UNPROVEN"
    artifact = f"GET {c['endpoint']}?{c['param']}={c['exploit']}" if proven else None
    log.emit("proof_attempted", id=c["id"], ms=ms, driver=driver, agent_note=note)
    log.emit("proof_result", id=c["id"], status=status, artifact=artifact, ms=ms, driver=driver)
    print(f"  => {status}" + (f"  (proof: {artifact})" if artifact else ""))
    return {"id": c["id"], "status": status, "driver": driver}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy-url", default="http://127.0.0.1:8080")
    ap.add_argument("--events", default=os.path.join(LITMUS, "events.jsonl"))
    ap.add_argument("--no-agent", action="store_true",
                    help="skip the LLM agent; use the scripted exploit only")
    ap.add_argument("--agent-timeout", type=int, default=75)
    args = ap.parse_args()

    log = EventLog(args.events)
    oracle = FileReadOracle(SECRET_PATH)
    use_agent = not args.no_agent
    log.emit("run_started", mode="live", proxy=args.proxy_url,
             agent=use_agent, candidates=len(CANDIDATES))

    print(f"== Litmus Prove (LIVE) ==  proxy={args.proxy_url}  agent={'on' if use_agent else 'off'}")
    if not wait_for_target(args.proxy_url):
        print("ERROR: target not reachable through proxy", file=sys.stderr)
        sys.exit(2)

    results = [prove_candidate(c, oracle, args.proxy_url, log, use_agent, args.agent_timeout)
               for c in CANDIDATES]
    proven = sum(1 for r in results if r["status"] == "PROVEN")
    by = {}
    for r in results:
        if r["driver"]:
            by[r["driver"]] = by.get(r["driver"], 0) + 1
    print(f"\nSummary: {proven} PROVEN, {len(results) - proven} not proven "
          f"(of {len(results)}).  drivers={by or '{}'}")
    log.emit("run_finished", proven=proven, total=len(results), drivers=by)


if __name__ == "__main__":
    main()
