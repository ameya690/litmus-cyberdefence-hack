"""Litmus Triage stage (PRD stage 2).

Classifies each Semgrep candidate as plausibly exploitable via ARBITRARY FILE
READ or not, so the expensive LLM attacker only runs on the promising ones and
obvious non-file-read findings (SQLi, weak crypto, config) skip the slow agent
pass. This is purely a WHERE-to-spend-effort gate: the scripted file-read check
still runs on every candidate regardless of the verdict, so a wrong "unlikely"
label can never turn a real file read into a false negative -- it only costs a
slow agent attempt. The oracle remains the sole arbiter of PROVEN.

Backends (like the attacker): OpenRouter or native Anthropic for the LLM label;
a CWE/finding heuristic if no credential is configured or the call fails.
"""
import json
import os
import urllib.error
import urllib.request

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = os.environ.get("TRIAGE_MODEL", "anthropic/claude-haiku-4.5")
ANTHROPIC_MODEL = os.environ.get("TRIAGE_ANTHROPIC_MODEL", "claude-haiku-4-5")

SYSTEM = (
    "You triage static-analysis findings for one question only: is this finding "
    "plausibly exploitable as ARBITRARY FILE READ -- i.e. could an attacker make the "
    "web app return the contents of a file of their choosing on the server's disk? "
    "Path traversal, directory traversal, LFI, or user input flowing into open()/"
    "send_file() are LIKELY. SQL injection, weak hashing, hardcoded secrets, insecure "
    "config, SSRF, and command injection are UNLIKELY (they are real bugs, but not file "
    "reads). Answer with exactly one word on the first line, LIKELY or UNLIKELY, then "
    "one short sentence of reasoning."
)

_MARKERS = ("traversal", "path-traversal", "cwe-22", "cwe-23", "cwe-36", "cwe-73",
            "lfi", "arbitrary file", "open(", "send_file")


def _prompt(c):
    return (f"Finding: {c.get('finding')}\nCWE: {c.get('cwe')}\n"
            f"Endpoint: {c.get('endpoint')}  Parameter: {c.get('param')}\n"
            f"Is this exploitable as arbitrary file read?")


def _parse(text):
    t = (text or "").strip()
    head = t.upper().lstrip("*# -")
    verdict = "unlikely" if head.startswith("UNLIKELY") else ("likely" if head.startswith("LIKELY") else None)
    reason = " ".join(t.splitlines()[1:]).strip() or t.splitlines()[0] if t else ""
    return verdict, reason[:200]


def _heuristic(c):
    blob = (str(c.get("finding", "")) + " " + str(c.get("cwe", ""))).lower()
    verdict = "likely" if any(m in blob for m in _MARKERS) else "unlikely"
    return {"verdict": verdict, "reason": "CWE/finding heuristic", "by": "heuristic"}


def _openrouter(c):
    payload = json.dumps({
        "model": OPENROUTER_MODEL, "max_tokens": 120,
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": _prompt(c)}],
    }).encode()
    req = urllib.request.Request(OPENROUTER_URL, data=payload, headers={
        "Authorization": f"Bearer {os.environ['OPENROUTER_API_KEY']}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/ameya690/litmus-cyberdefence-hack",
        "X-Title": "Litmus",
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    text = data["choices"][0]["message"].get("content", "")
    verdict, reason = _parse(text)
    if verdict is None:
        raise ValueError(f"unparseable triage reply: {text[:80]!r}")
    return {"verdict": verdict, "reason": reason, "by": "llm:openrouter"}


def _anthropic(c):
    import anthropic
    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=ANTHROPIC_MODEL, max_tokens=120, system=SYSTEM,
        messages=[{"role": "user", "content": _prompt(c)}],
    )
    text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    verdict, reason = _parse(text)
    if verdict is None:
        raise ValueError(f"unparseable triage reply: {text[:80]!r}")
    return {"verdict": verdict, "reason": reason, "by": "llm:anthropic"}


def triage(candidate):
    """Return {verdict: 'likely'|'unlikely', reason, by}. Never raises."""
    try:
        if os.environ.get("ANTHROPIC_API_KEY"):
            return _anthropic(candidate)
        if os.environ.get("OPENROUTER_API_KEY"):
            return _openrouter(candidate)
    except Exception:  # noqa: BLE001 - any LLM failure degrades to the heuristic
        pass
    return _heuristic(candidate)
