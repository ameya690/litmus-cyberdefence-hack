"""Litmus LLM attacker agent (Claude).

Drives the file-read exploit live. Given the target reachable through the
capturing proxy and a candidate (endpoint/param hint), it uses an `http_request`
tool to retrieve the challenge secret. It is NEVER told the flag value -- it must
actually read /challenge/secret through the vulnerability, so success is real.

It shares the attacker interface with the scripted exploit (BUILD_PLAN Q3/Q4):
both only cause HTTP requests to the target. The oracle judges success by reading
the proxy's wire capture, so the agent and the script are indistinguishable to it.

Model: claude-sonnet-5 (BUILD_PLAN Q13 -- Sonnet-class for agentic speed), run at
low effort with a tight turn/time cap. If no credential is configured or the SDK
is missing, run_agent() raises AgentUnavailable and the harness falls back to the
scripted exploit (the Q13 contingency) -- the proof still lands.
"""
import time
import urllib.error
import urllib.request

MODEL = "claude-sonnet-5"


class AgentUnavailable(Exception):
    """No credential / SDK, a refusal, or an API error -- use the fallback."""


class AgentTimeout(Exception):
    """Agent ran out of time or turns without proving -- use the fallback."""


HTTP_TOOL = {
    "name": "http_request",
    "description": (
        "Send an HTTP GET to the target web app and return its raw response body. "
        "Use it to probe endpoints and read files. 'path' is the full path plus "
        "query string, e.g. '/download?file=welcome.txt'."
    ),
    "input_schema": {
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
    },
}

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


def run_agent(proxy_url, candidate, timeout=75, max_turns=8):
    """Run the live agent against the target (through the proxy).

    Returns normally when the agent finishes; the harness then reads the wire
    capture to decide PROVEN/UNPROVEN. Raises AgentUnavailable / AgentTimeout to
    signal the harness to fall back to the scripted exploit.
    """
    try:
        import anthropic
    except ImportError as e:
        raise AgentUnavailable("anthropic SDK not installed") from e
    try:
        client = anthropic.Anthropic()
    except Exception as e:  # noqa: BLE001 - missing/invalid credentials
        raise AgentUnavailable(f"client init failed: {e}") from e

    hint = (
        f"Semgrep finding: {candidate.get('finding')}. A likely vulnerable endpoint is "
        f"{candidate.get('endpoint')} with parameter '{candidate.get('param')}'. Begin."
    )
    messages = [{"role": "user", "content": hint}]
    deadline = time.time() + timeout

    for _ in range(max_turns):
        if time.time() > deadline:
            raise AgentTimeout(f"exceeded {timeout}s")
        try:
            resp = client.messages.create(
                model=MODEL,
                max_tokens=8000,
                system=SYSTEM,
                thinking={"type": "adaptive"},
                output_config={"effort": "low"},
                tools=[HTTP_TOOL],
                messages=messages,
            )
        except Exception as e:  # noqa: BLE001 - rate limit, network, auth, etc.
            raise AgentUnavailable(f"API error: {e}") from e

        if resp.stop_reason == "refusal":
            raise AgentUnavailable("model declined the task")
        if resp.stop_reason == "end_turn":
            return  # done; oracle reads the wire to judge

        tool_uses = [b for b in resp.content if b.type == "tool_use"]
        messages.append({"role": "assistant", "content": resp.content})
        if not tool_uses:
            return
        results = []
        for tu in tool_uses:
            path = tu.input.get("path", "/") if isinstance(tu.input, dict) else "/"
            results.append({
                "type": "tool_result",
                "tool_use_id": tu.id,
                "content": _http_get(proxy_url, path),
            })
        messages.append({"role": "user", "content": results})

    raise AgentTimeout(f"exceeded {max_turns} turns")
