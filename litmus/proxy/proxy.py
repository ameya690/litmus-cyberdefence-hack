"""Litmus capturing proxy -- how the oracle reads the wire.

Sits between the attacker (LLM agent OR scripted fallback) and the target. It
forwards every request to the target and tees the TARGET's response bytes to a
capture file. The oracle checks that capture -- never the attacker's claim -- so
a hallucinating or lying agent cannot fake a proof, and the agent and the script
are indistinguishable to the oracle (BUILD_PLAN Q12).

The target is reachable ONLY from inside the Docker network; the proxy is the
one channel exposed to the host, and everything through it is recorded.
"""
import os
import urllib.error
import urllib.request

from flask import Flask, Response, request

app = Flask(__name__)
TARGET = os.environ.get("TARGET_URL", "http://target:5000")
CAPTURE = os.environ.get("CAPTURE_FILE", "/capture/wire.log")

_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]


@app.route("/", defaults={"path": ""}, methods=_METHODS)
@app.route("/<path:path>", methods=_METHODS)
def forward(path):
    qs = request.query_string.decode()
    url = f"{TARGET}/{path}" + (f"?{qs}" if qs else "")
    body = request.get_data() or None
    headers = {k: v for k, v in request.headers
               if k.lower() not in ("host", "content-length")}
    req = urllib.request.Request(url, data=body, method=request.method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            resp_body, status = r.read(), r.status
            ctype = r.headers.get("Content-Type", "application/octet-stream")
    except urllib.error.HTTPError as e:
        resp_body, status = (e.read() or b""), e.code
        ctype = e.headers.get("Content-Type", "text/plain")
    except Exception as e:  # noqa: BLE001
        resp_body, status, ctype = f"[proxy error] {e}".encode(), 502, "text/plain"

    # Tee the TARGET's response (the wire) for the oracle to inspect.
    try:
        os.makedirs(os.path.dirname(CAPTURE), exist_ok=True)
        with open(CAPTURE, "ab") as f:
            f.write(f"\n### {request.method} /{path}?{qs} -> {status}\n".encode())
            f.write(resp_body)
    except Exception:  # noqa: BLE001 - capture must never break forwarding
        pass

    return Response(resp_body, status=status, content_type=ctype)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
