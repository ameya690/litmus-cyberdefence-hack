"""Litmus LLM attacker agent (Claude).

Drives the file-read exploit live. Given the target reachable through the
capturing proxy and a candidate (endpoint/param hint), it uses an `http_request`
tool to retrieve the challenge secret. It is NEVER told the flag value -- it must
actually read /challenge/secret through the vulnerability, so success is real.

It shares the attacker interface with the scripted exploit (BUILD_PLAN Q3/Q4):
both only cause HTTP requests to the target. The oracle judges success by reading
the proxy's wire capture, so the agent and the script are indistinguishable to it.

Model: Claude Sonnet (BUILD_PLAN Q13 -- Sonnet-class for agentic speed). Two
backends, chosen by whichever credential is present:
  * ANTHROPIC_API_KEY  -> native Anthropic SDK  (model claude-sonnet-5)
  * OPENROUTER_API_KEY -> OpenRouter, OpenAI-compatible HTTP (anthropic/claude-sonnet-5)
If neither is set (or the call fails/stalls/refuses), run_agent raises
AgentUnavailable/AgentTimeout and the harness falls back to the scripted exploit.
"""
import json
import os
import time
import urllib.error
import urllib.request

ANTHROPIC_MODEL = "claude-sonnet-5"
OPENROUTER_MODEL = "anthropic/claude-sonnet-5"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
# The exploit needs only a couple of short turns; keep the per-request output cap
# small so it fits within limited OpenRouter credit balances.
OPENROUTER_MAX_TOKENS = int(os.environ.get("OPENROUTER_MAX_TOKENS", "1200"))


class AgentUnavailable(Exception):
    """No credential / SDK, a refusal, or an API error -- use the fallback."""


class AgentTimeout(Exception):
    """Agent ran out of time or turns without proving -- use the fallback."""


_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Path and query string to request, "
                           "e.g. /download?file=../../challenge/secret",
        }
    },
    "required": ["path"],
    "additionalProperties": False,
}
_TOOL_DESC = (
    "Send an HTTP GET to the target web app and return its raw response body. Use it "
    "to probe endpoints and read files. 'path' is the full path plus query string, "
    "e.g. '/download?file=welcome.txt'."
)

SYSTEM = (
    "You are an authorized penetration tester working in an isolated sandbox on a "
    "web application you have explicit permission to attack. The app has a suspected "
    "file-read vulnerability. A secret file exists on the server at '/challenge/secret' "
    "(outside the web document root). Your goal: retrieve the EXACT contents of that "
    "secret file by sending HTTP requests with the http_request tool and exploiting the "
    "vulnerability (for a path-traversal bug, climb out of the document root with ../ "
    "segments). You are NOT given the secret; you must read it off the server. When you "
    "have obtained it, state the exact string you retrieved. Keep requests minimal."
)


def _hint(candidate):
    ep = candidate.get("endpoint")
    return (
        f"Semgrep finding: {candidate.get('finding')}. The vulnerable endpoint under test "
        f"is {ep} with parameter '{candidate.get('param')}'. You may send requests ONLY to "
        f"{ep} (any request to a different path is blocked); vary the '{candidate.get('param')}' "
        f"value to exploit THIS endpoint. If {ep} cannot yield the secret, say so. Begin."
    )


def _http_get(proxy_url, path):
    if not path.startswith("/"):
        path = "/" + path
    try:
        with urllib.request.urlopen(proxy_url + path, timeout=10) as r:
            body = r.read()
    except urllib.error.HTTPError as e:
        body = e.read() or b""
    except Exception as e:  # noqa: BLE001
        return f"[request error] {e}"
    return body.decode("utf-8", "replace")[:4000]


def _scoped_get(proxy_url, path, endpoint):
    """Only allow requests to the candidate's own endpoint.

    The agent attacks ONE finding at a time, so it may vary the parameter but not
    roam to other endpoints (which would let it prove the real traversal while
    nominally attacking a decoy). This is the agent's only network access, so the
    restriction is enforced here, not merely requested in the prompt.
    """
    p = path if path.startswith("/") else "/" + path
    base = (p.split("?", 1)[0].rstrip("/") or "/")
    want = (endpoint.rstrip("/") or "/")
    if base != want:
        return (f"[blocked] For this test you may only send requests to {endpoint}. "
                f"'{base}' is out of scope.")
    return _http_get(proxy_url, p)


def run_agent(proxy_url, candidate, timeout=25, max_turns=4):
    """Run the live agent against the target (through the proxy).

    Returns the backend name on normal finish; the harness then reads the wire
    capture to decide PROVEN/UNPROVEN. Raises AgentUnavailable / AgentTimeout to
    signal the harness to fall back to the scripted exploit.
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return _run_anthropic(proxy_url, candidate, timeout, max_turns)
    if os.environ.get("OPENROUTER_API_KEY"):
        return _run_openrouter(proxy_url, candidate, timeout, max_turns)
    raise AgentUnavailable("no credential (set ANTHROPIC_API_KEY or OPENROUTER_API_KEY)")


# --- Backend: native Anthropic SDK -----------------------------------------
def _run_anthropic(proxy_url, candidate, timeout, max_turns):
    try:
        import anthropic
    except ImportError as e:
        raise AgentUnavailable("anthropic SDK not installed") from e
    try:
        client = anthropic.Anthropic()
    except Exception as e:  # noqa: BLE001
        raise AgentUnavailable(f"client init failed: {e}") from e

    tool = {"name": "http_request", "description": _TOOL_DESC, "input_schema": _TOOL_SCHEMA}
    messages = [{"role": "user", "content": _hint(candidate)}]
    deadline = time.time() + timeout
    for _ in range(max_turns):
        if time.time() > deadline:
            raise AgentTimeout(f"exceeded {timeout}s")
        try:
            resp = client.messages.create(
                model=ANTHROPIC_MODEL, max_tokens=8000, system=SYSTEM,
                thinking={"type": "adaptive"}, output_config={"effort": "low"},
                tools=[tool], messages=messages,
            )
        except Exception as e:  # noqa: BLE001
            raise AgentUnavailable(f"API error: {e}") from e
        if resp.stop_reason == "refusal":
            raise AgentUnavailable("model declined the task")
        if resp.stop_reason == "end_turn":
            return "anthropic"
        tool_uses = [b for b in resp.content if b.type == "tool_use"]
        messages.append({"role": "assistant", "content": resp.content})
        if not tool_uses:
            return "anthropic"
        results = [{
            "type": "tool_result", "tool_use_id": tu.id,
            "content": _scoped_get(proxy_url, tu.input.get("path", "/")
                                   if isinstance(tu.input, dict) else "/", candidate["endpoint"]),
        } for tu in tool_uses]
        messages.append({"role": "user", "content": results})
    raise AgentTimeout(f"exceeded {max_turns} turns")


# --- Backend: OpenRouter (OpenAI-compatible HTTP) --------------------------
def _run_openrouter(proxy_url, candidate, timeout, max_turns):
    key = os.environ["OPENROUTER_API_KEY"]
    tool = {"type": "function", "function": {
        "name": "http_request", "description": _TOOL_DESC, "parameters": _TOOL_SCHEMA}}
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": _hint(candidate)},
    ]
    deadline = time.time() + timeout
    for _ in range(max_turns):
        if time.time() > deadline:
            raise AgentTimeout(f"exceeded {timeout}s")
        payload = json.dumps({
            "model": OPENROUTER_MODEL, "messages": messages, "tools": [tool],
            # Read at call time so .env / env can tune it for a given credit budget.
            "max_tokens": int(os.environ.get("OPENROUTER_MAX_TOKENS", str(OPENROUTER_MAX_TOKENS))),
        }).encode()
        req = urllib.request.Request(OPENROUTER_URL, data=payload, headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/ameya690/litmus-cyberdefence-hack",
            "X-Title": "Litmus",
        })
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.load(r)
        except urllib.error.HTTPError as e:
            raise AgentUnavailable(f"OpenRouter HTTP {e.code}: "
                                   f"{(e.read() or b'')[:200].decode('utf-8','replace')}") from e
        except Exception as e:  # noqa: BLE001
            raise AgentUnavailable(f"OpenRouter error: {e}") from e

        choice = data["choices"][0]
        msg = choice.get("message", {})
        tool_calls = msg.get("tool_calls") or []
        assistant = {"role": "assistant", "content": msg.get("content")}
        if tool_calls:
            assistant["tool_calls"] = tool_calls
        messages.append(assistant)
        if not tool_calls:
            return "openrouter"
        for tc in tool_calls:
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            messages.append({
                "role": "tool", "tool_call_id": tc["id"],
                "content": _scoped_get(proxy_url, args.get("path", "/"), candidate["endpoint"]),
            })
    raise AgentTimeout(f"exceeded {max_turns} turns")
