#!/usr/bin/env python3
"""Local vulnerable-app benchmark for the GEPA optimizer — deterministic, offline, 127.0.0.1 only.

Each app hosts ONE provable bug (plus benign/negative routes to penalize false positives) on its own
port, so a task = one app = one expected finding class. An OOB/metadata mock gives blind SSRF/RCE a
deterministic callback. Everything is stdlib; nothing leaves localhost.

Run standalone:   python serve.py            # starts all apps, prints the task->url map, serves
Import:           from serve import start_all, stop_all, APPS, OOB_PORT
"""
import http.server
import json
import socketserver
import sqlite3
import subprocess
import threading
import urllib.parse
import urllib.request

socketserver.ThreadingTCPServer.allow_reuse_address = True
HOST = "127.0.0.1"
OOB_PORT = 8899
OOB_HOST = f"{HOST}:{OOB_PORT}"

# ---- OOB / metadata mock --------------------------------------------------- #
_HITS = {}            # token -> list of hit dicts
_HITS_LOCK = threading.Lock()
META_SECRET = "BENCH_IAM_AKIA_LIVE_4f9c2"   # what a cloud-metadata SSRF read should leak


def _oob(method, path, qs, body, headers):
    if path.startswith("/h/"):                       # blind callback: /h/<token>
        tok = path[3:].split("/")[0]
        with _HITS_LOCK:
            _HITS.setdefault(tok, []).append({"path": path, "ua": headers.get("User-Agent", "")})
        return 200, "text/plain", b"ok"
    if path.startswith("/poll/"):                     # poll for callbacks: /poll/<token>
        tok = path[6:]
        with _HITS_LOCK:
            return 200, "application/json", json.dumps(_HITS.get(tok, [])).encode()
    if "meta-data" in path or path == "/metadata":    # fake cloud metadata
        return 200, "text/plain", f"iam-role-creds: {META_SECRET}".encode()
    return 200, "text/plain", b"oob-mock"


# ---- vulnerable apps (each returns (status, ctype, body_bytes)) ------------- #
def _html(s):
    return 200, "text/html", s.encode()


def app_xss_reflected(method, path, qs, body, headers):
    """Reflected XSS: /search?q= reflects q unescaped. Safe: /about."""
    if path == "/search":
        q = qs.get("q", [""])[0]
        return _html(f"<html><body><h1>Results for: {q}</h1></body></html>")  # unescaped -> XSS
    if path == "/about":
        return _html("<html><body>About us. No user input here.</body></html>")
    return _html('<html><body><a href="/search?q=test">search</a> <a href="/about">about</a></body></html>')


def app_xss_dom(method, path, qs, body, headers):
    """DOM XSS: the page writes location.hash into innerHTML (sink). Confirm with xss-confirm.js."""
    page = ("<html><body><div id=out></div>"
            "<script>document.getElementById('out').innerHTML=decodeURIComponent(location.hash.slice(1))</script>"
            "</body></html>")
    return _html(page)


def app_sqli(method, path, qs, body, headers):
    """Error/boolean SQLi: /item?id= concatenated into SQL. Safe: /items (parameterized list)."""
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE items(id INTEGER, name TEXT, secret TEXT)")
    db.executemany("INSERT INTO items VALUES (?,?,?)",
                   [(1, "Widget", "s1"), (2, "Gadget", "s2"), (3, "Gizmo", "FLAG_SQLI_3")])
    if path == "/item":
        idv = qs.get("id", ["1"])[0]
        try:
            rows = db.execute(f"SELECT id,name FROM items WHERE id='{idv}'").fetchall()  # injectable
            return 200, "application/json", json.dumps(rows).encode()
        except Exception as e:
            return 500, "text/plain", f"SQL error: {e}".encode()  # error-based leak
    if path == "/items":
        rows = db.execute("SELECT id,name FROM items").fetchall()
        return 200, "application/json", json.dumps(rows).encode()
    return _html('<html><body><a href="/item?id=1">item</a></body></html>')


def app_ssrf(method, path, qs, body, headers):
    """SSRF: /fetch?url= fetches server-side (reaches the OOB mock / metadata). Safe: /img (fixed)."""
    if path == "/fetch":
        url = qs.get("url", [""])[0]
        if not url:
            return 400, "text/plain", b"url required"
        try:
            with urllib.request.urlopen(url, timeout=4) as r:   # no allowlist -> SSRF
                return 200, "text/plain", r.read()[:2000]
        except Exception as e:
            return 502, "text/plain", f"fetch error: {e}".encode()
    return _html('<html><body>image proxy: <a href="/fetch?url=http://example.com">fetch</a></body></html>')


def app_ssti(method, path, qs, body, headers):
    """SSTI: /greet?name= renders {{expr}} via eval. Safe: /hello (no templating)."""
    if path == "/greet":
        name = qs.get("name", ["guest"])[0]
        out = name
        if "{{" in name and "}}" in name:
            expr = name[name.find("{{") + 2:name.find("}}")].strip()
            try:
                out = name.replace("{{" + expr + "}}", str(eval(expr, {"__builtins__": {}}, {})))  # SSTI
            except Exception:
                pass
        return _html(f"<html><body>Hello, {out}!</body></html>")
    if path == "/hello":
        return _html("<html><body>Hello, world!</body></html>")
    return _html('<html><body><a href="/greet?name=guest">greet</a></body></html>')


def app_cmdi(method, path, qs, body, headers):
    """Command injection: /resolve?host= passed to a shell. Safe: /status."""
    if path == "/resolve":
        host = qs.get("host", [""])[0]
        try:
            out = subprocess.run("echo resolving " + host, shell=True, capture_output=True,
                                 text=True, timeout=4).stdout            # shell=True -> cmdi
            return 200, "text/plain", out.encode()
        except Exception as e:
            return 500, "text/plain", str(e).encode()
    if path == "/status":
        return 200, "text/plain", b"ok"
    return _html('<html><body><a href="/resolve?host=localhost">resolve</a></body></html>')


def app_secret(method, path, qs, body, headers):
    """Secret-in-JS: /static/app.js leaks a live API key; /api/profile validates it."""
    key = "sk-bench-LIVE-7h3k9q"
    if path == "/static/app.js":
        return 200, "application/javascript", f'const API_KEY="{key}";fetch("/api/profile");'.encode()
    if path == "/api/profile":
        auth = headers.get("Authorization", "")
        if auth == f"Bearer {key}":
            return 200, "application/json", b'{"email":"admin@bench.local","plan":"enterprise"}'
        return 401, "application/json", b'{"error":"unauthorized"}'
    return _html('<html><body><script src="/static/app.js"></script>dashboard</body></html>')


def app_safe(method, path, qs, body, headers):
    """NEGATIVE control: properly-escaped, parameterized, no SSRF. Expected findings: NONE."""
    if path == "/search":
        q = qs.get("q", [""])[0]
        esc = q.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        return _html(f"<html><body>Results for: {esc}</body></html>")
    return _html('<html><body>A safe app. <a href="/search?q=hi">search</a></body></html>')


# task_id -> (port, app_fn, vuln_class, endpoint_contains|None)
APPS = {
    "xss_reflected": (8801, app_xss_reflected, "xss", "/search"),
    "xss_dom":       (8802, app_xss_dom,       "xss", "/"),
    "sqli":          (8803, app_sqli,          "sqli", "/item"),
    "ssrf":          (8804, app_ssrf,          "ssrf", "/fetch"),
    "ssti":          (8805, app_ssti,          "ssti", "/greet"),
    "cmdi":          (8806, app_cmdi,          "cmdi", "/resolve"),
    "secret":        (8807, app_secret,        "secret", "/static/app.js"),
    "safe":          (8808, app_safe,          None, None),   # negative control
}


def _make_handler(fn):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a):  # quiet
            pass
        def _do(self, method):
            u = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(u.query)
            ln = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(ln) if ln else b""
            try:
                status, ctype, out = fn(method, u.path, qs, body, self.headers)
            except Exception as e:
                status, ctype, out = 500, "text/plain", f"err: {e}".encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
        def do_GET(self): self._do("GET")
        def do_POST(self): self._do("POST")
    return H


def start_all():
    """Start the OOB mock + every app. Returns (servers, taskmap{id: base_url})."""
    servers, taskmap = [], {}
    specs = [("oob", OOB_PORT, _oob)] + [(tid, port, fn) for tid, (port, fn, _, _) in APPS.items()]
    for tid, port, fn in specs:
        srv = socketserver.ThreadingTCPServer((HOST, port), _make_handler(fn))
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        if tid != "oob":
            taskmap[tid] = f"http://{HOST}:{port}"
    return servers, taskmap


def stop_all(servers):
    for s in servers:
        try:
            s.shutdown(); s.server_close()
        except Exception:
            pass


if __name__ == "__main__":
    import time
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    servers, taskmap = start_all()
    print(f"OOB/metadata mock: http://{OOB_HOST}  (AUTOHUNT_OOB={OOB_HOST})")
    for tid, url in taskmap.items():
        print(f"  {tid:14} {url}")
    print("serving… Ctrl-C to stop")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop_all(servers)
