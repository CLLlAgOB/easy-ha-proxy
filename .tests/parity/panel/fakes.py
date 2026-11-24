"""Fake host daemons for the panel harness.

Every socket the panel talks to answers from canned replies in
/srv/fake_replies.json (keyed by daemon and request) and logs each request to
/srv/fakes.log, so both panels can be checked for the same daemon traffic.
"""
import base64
import json
import os
import socketserver
import threading
from http.server import BaseHTTPRequestHandler

LOG = "/srv/fakes.log"
REPLIES = "/srv/fake_replies.json"
lock = threading.Lock()


def replies():
    try:
        with open(REPLIES) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}


def log(daemon, request):
    with lock:
        with open(LOG, "a") as fh:
            fh.write(json.dumps({"daemon": daemon, "request": request}, sort_keys=True) + "\n")


def pick(daemon, key, default):
    table = replies().get(daemon, {})
    for k, v in table.items():
        if key.startswith(k):
            return v
    return table.get("*", default)


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(path, handler):
    if os.path.exists(path):
        os.unlink(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    srv = UnixServer(path, handler)
    os.chmod(path, 0o666)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def line_handler(daemon):
    """One text line in, a canned text answer out (controld, HAProxy runtime)."""

    class H(socketserver.StreamRequestHandler):
        def handle(self):
            raw = self.rfile.readline().decode("utf-8", "replace").rstrip("\n")
            log(daemon, raw)
            answer = pick(daemon, raw, "OK" if daemon == "controld" else "")
            if isinstance(answer, dict) and "b64json" in answer:
                answer = "OK " + base64.b64encode(json.dumps(answer["b64json"]).encode()).decode()
            self.wfile.write(answer.encode("utf-8"))
    return H


def json_line_handler(daemon):
    """One JSON line in, one JSON line out (backupd, updated, authelia-*)."""

    class H(socketserver.StreamRequestHandler):
        def handle(self):
            raw = self.rfile.readline()
            try:
                req = json.loads(raw)
            except ValueError:
                req = raw.decode("utf-8", "replace")
            log(daemon, req)
            key = req.get("action") or req.get("op") or req.get("command") or "" if isinstance(req, dict) else ""
            answer = pick(daemon, str(key), {"ok": True})
            self.wfile.write((json.dumps(answer) + "\n").encode())
    return H


def http_handler(daemon):
    class H(BaseHTTPRequestHandler):
        def address_string(self):
            return "unix"

        def log_message(self, *a):
            pass

        def _answer(self, body):
            log(daemon, {"method": self.command, "path": self.path, "body": body,
                         "token": self.headers.get("X-Guardd-Token") or self.headers.get("X-Alertd-Token")
                         or self.headers.get("X-Healthd-Token")})
            answer = pick(daemon, self.command + " " + self.path, {"ok": True})
            status = 200
            if isinstance(answer, dict) and "__status" in answer:
                status = answer.pop("__status")
            if isinstance(answer, dict) and "__raw" in answer:
                data = answer["__raw"].encode()
            else:
                data = json.dumps(answer).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._answer(None)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n)
            try:
                body = json.loads(raw)
            except ValueError:
                body = raw.decode("utf-8", "replace")
            self._answer(body)

    class S(socketserver.StreamRequestHandler):
        def handle(self):
            h = H.__new__(H)
            H.__init__(h, self.request, ("unix", 0), None)
    return S


R = "/run/easy-ha-proxy/"
serve("/run/haproxy/admin.sock", line_handler("haproxy"))
serve(R + "haproxy-controld.sock", line_handler("controld"))
for name in ("easy-ha-proxy-backupd", "easy-ha-proxy-updated", "authelia-usersd", "authelia-configd", "authelia-bans",
             ):
    serve(R + name + ".sock", json_line_handler(name))
for name in ("haproxy-healthd", "easy-ha-proxy-metricsd", "easy-ha-proxy-alertd", "easy-ha-proxy-guardd", "haproxy-certd"):
    serve(R + name + ".sock", http_handler(name))
class Health(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200 if self.path == "/api/health" else 404)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")


from http.server import ThreadingHTTPServer  # noqa: E402
_health = ThreadingHTTPServer(("127.0.0.1", 9091), Health)
threading.Thread(target=_health.serve_forever, daemon=True).start()
print("fakes ready", flush=True)
threading.Event().wait()
