"""
Acme Internal Document Portal
=============================

A small internal tool for browsing and downloading team documents.

This app is an AI-generated target for Litmus. It contains ONE planted,
genuinely-exploitable vulnerability (an arbitrary file read via path
traversal) plus several decoy weaknesses. The decoys are real findings a
scanner will flag, but none of them can reach the oracle's challenge secret,
so Litmus should stamp them UNPROVEN while proving only the traversal.

Run:  python app.py   (listens on 0.0.0.0:5000)
"""
import hashlib
import os
import sqlite3
import subprocess

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

# --- DECOY #1 (config) -------------------------------------------------------
# Hardcoded secret key. A scanner flags this as a hardcoded secret, but it
# grants no file access, so it is UNPROVEN under the file-read oracle.
app.secret_key = "super-secret-dev-key-123"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Documents live here. The oracle's secret lives OUTSIDE this directory, so the
# only way to read it is to escape DOCS_DIR via path traversal.
DOCS_DIR = os.environ.get("DOCS_DIR", os.path.join(BASE_DIR, "docs"))


def _init_db():
    """In-memory user directory backing the /search and /login demo endpoints.
    Deliberately holds NO secret, so even a successful SQL injection here cannot
    reach the challenge flag."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, role TEXT)")
    conn.executemany(
        "INSERT INTO users VALUES (?, ?, ?)",
        [(1, "alice", "admin"), (2, "bob", "editor"), (3, "carol", "viewer")],
    )
    conn.commit()
    return conn


DB = _init_db()


@app.route("/")
def index():
    return jsonify(
        service="Acme Internal Document Portal",
        endpoints=["/download?file=", "/login (POST)", "/search?q=", "/status"],
    )


# --- THE PLANTED BUG (provable, arbitrary file read) -------------------------
# `file` is user-controlled and flows straight into open() with no
# normalization or containment check. A request like
#   /download?file=../../challenge/secret
# escapes DOCS_DIR and reads any file the process can reach -- including the
# oracle's planted FLAG. This is the single finding Litmus should PROVE.
@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # Vulnerable join: user input is concatenated onto the base path with no
    # containment check, so "../" escapes DOCS_DIR. (os.path.join(DOCS_DIR,
    # filename) is just as exploitable, but Semgrep's path-traversal-open rule
    # does not track taint through os.path.join, so we concatenate to keep the
    # flow in a shape the scanner follows end-to-end.)
    path = DOCS_DIR + "/" + filename
    try:
        with open(path, "rb") as f:  # <-- traversal sink (tainted open)
            data = f.read()
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return Response("not found", status=404)
    return Response(data, mimetype="application/octet-stream")


# --- DECOY #2 (crypto) -------------------------------------------------------
# Weak MD5 password hash. A real finding, but it reads no files; UNPROVEN.
@app.route("/login", methods=["POST"])
def login():
    password = request.form.get("password", "")
    digest = hashlib.md5(password.encode()).hexdigest()  # <-- insecure hash
    authenticated = digest == "5f4dcc3b5aa765d61d8327deb882cf99"  # "password"
    return jsonify(authenticated=authenticated)


# --- DECOY #3 (SQL injection) ------------------------------------------------
# User input is f-stringed directly into the query. Genuinely injectable, but
# the table holds no secret, so it cannot reach the flag; UNPROVEN.
@app.route("/search")
def search():
    q = request.args.get("q", "")
    query = f"SELECT username, role FROM users WHERE username = '{q}'"  # <-- SQLi
    rows = DB.execute(query).fetchall()
    return jsonify(results=[{"username": u, "role": r} for u, r in rows])


# --- DECOY #4 (command execution) --------------------------------------------
# subprocess with shell=True. Flagged by scanners, but the command is a fixed
# string with no user input, so it is not exploitable; UNPROVEN.
@app.route("/status")
def status():
    out = subprocess.check_output("uptime", shell=True)  # <-- shell=True
    return Response(out, mimetype="text/plain")


if __name__ == "__main__":
    # Bind to all interfaces so the attacker container can reach the target over
    # the Docker network. Debug is intentionally OFF: the Werkzeug debugger would
    # be an unintended code-execution path to the secret and would break oracle
    # integrity (the flag must be reachable ONLY through the traversal).
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
