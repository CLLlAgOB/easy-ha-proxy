"""Flask panel vs Go panel on the same requests.

Usage: run.py <cases module> [filter]
Each side starts from the same filesystem state, gets the same requests and
the same daemon replies; responses, daemon traffic and touched files are
normalized and compared. It rewrites /opt, /etc and /var/lib, so it runs only
in the throwaway container .tests/parity/run.sh starts (REPO is the checkout,
PANEL_BIN the Go panel built from it). Exits 1 when the two sides differ.
"""
import hashlib
import http.client
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse

SECRET = "harness-proxy-secret"
ENV = {
    "HAPROXY_ADMIN_PROXY_SECRET": SECRET,
    "HAPROXY_ADMIN_SECRET_KEY": "k" * 64,
    "EHP_SERVER_TIMEZONE": "Europe/Moscow",
    "LOG_LEVEL": "WARNING",
    "EHP_BUILD_REVISION": "0123456789abcdef0123456789abcdef01234567",
    "EHP_BUILD_DATE": "2026-11-20T10:00:00+00:00",
    "EHP_SOURCE_TREE": "a" * 64,
    "HAPROXY_ADMIN_TRASH_DIR": "/var/lib/haproxy-admin/trash",
}
REPO = os.environ.get("REPO", "/repo")
PANEL_BIN = os.environ.get("PANEL_BIN", "/work/panel")
WATCH = ["/opt/haproxy-admin", "/etc/haproxy", "/var/lib/haproxy-admin", "/var/lib/easy-ha-proxy"]

spec = importlib.util.spec_from_file_location("cases", sys.argv[1])
cases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cases)
FILTER = sys.argv[2] if len(sys.argv) > 2 else ""


def reset_state():
    for d in WATCH:
        shutil.rmtree(d, ignore_errors=True)
    shutil.copytree("/srv/state", "/", dirs_exist_ok=True)
    shutil.copytree(REPO + "/docker/app/haproxy_admin", "/opt/haproxy-admin/haproxy_admin", copy_function=shutil.copy2,
                    ignore=shutil.ignore_patterns("__pycache__"))
    open("/srv/fakes.log", "w").close()
    with open("/srv/fake_replies.json", "w") as fh:
        json.dump(getattr(cases, "REPLIES", {}), fh)
    if hasattr(cases, "setup"):
        cases.setup()


def start(side):
    env = dict(os.environ, **ENV, **getattr(cases, "ENV", {}))
    if side == "py":
        code = ("import sys; sys.path.insert(0, '/opt/haproxy-admin'); from haproxy_admin import create_app; "
                "create_app().run(host='127.0.0.1', port=5001, threaded=True)")
        proc = subprocess.Popen(["python3", "-c", code], cwd="/opt/haproxy-admin", env=env,
                                stdout=open("/srv/py.log", "w"), stderr=subprocess.STDOUT)
        port = 5001
    else:
        env.update({
            "HAPROXY_ADMIN_LISTEN_ADDR": "127.0.0.1:5002",
            "HAPROXY_ADMIN_STATIC_DIR": "/opt/haproxy-admin/haproxy_admin/static",
            "HAPROXY_ADMIN_TRANSLATIONS_DIR": "/opt/haproxy-admin/haproxy_admin/translations",
            "HAPROXY_ADMIN_TEMPLATES_DIR": "/opt/haproxy-admin/haproxy_admin/templates",
        })
        proc = subprocess.Popen([PANEL_BIN, "serve"], cwd="/opt/haproxy-admin", env=env,
                                stdout=open("/srv/go.log", "w"), stderr=subprocess.STDOUT)
        port = 5002
    for _ in range(100):
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            c.request("GET", "/api/control-plane-health", headers={
                "X-Easy-HA-Proxy-Secret": SECRET, "Remote-User": "easy-ha-proxy-healthcheck",
                "Remote-Groups": "healthcheck"})
            c.getresponse().read()
            return proc, port
        except OSError:
            time.sleep(0.1)
    raise SystemExit("%s did not start: %s" % (side, open("/srv/%s.log" % side).read()[-3000:]))


class Client:
    def __init__(self, port):
        self.port = port
        self.cookies = {}
        self.csrf = ""
        self.snap = ""
        self.captured = {}

    def request(self, method, path, user="admin", groups="admins,superadmin", form=None, json_body=None,
                headers=None, raw=None):
        path, form, json_body, headers = self.fill(path), self.fill(form), self.fill(json_body), self.fill(headers)
        h = {"X-Easy-HA-Proxy-Secret": SECRET, "Host": "panel.test"}
        if user is not None:
            h["Remote-User"] = user
            h["Remote-Groups"] = groups
        if self.cookies:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in sorted(self.cookies.items()))
        body = None
        if form is not None:
            form = dict(form)
            if form.get("csrf_token") == "CSRF":
                form["csrf_token"] = self.csrf
            if form.get("acl_snapshot") == "SNAP":
                form["acl_snapshot"] = self.snap
            body = urllib.parse.urlencode(form, doseq=True)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        elif json_body is not None:
            body = json.dumps(json_body)
            h["Content-Type"] = "application/json"
            h["X-CSRFToken"] = self.csrf
        elif raw is not None:
            body = raw
        if headers:
            for k, v in headers.items():
                h[k] = self.csrf if v == "CSRF" else v
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, _, rest = v.partition("=")
                value = rest.split(";", 1)[0]
                if "Max-Age=0" in v or "expires=Thu, 01 Jan 1970" in v.lower() or value == "":
                    self.cookies.pop(name, None)
                else:
                    self.cookies[name] = value
        text = data.decode("utf-8", "replace")
        m = re.search(r'<meta name="csrf-token" content="([^"]+)"', text)
        if m:
            self.csrf = m.group(1)
        m = re.search(r'name="acl_snapshot" value="([^"]+)"', text)
        if m:
            self.snap = m.group(1)
        for name, rx in getattr(cases, "CAPTURE", {}).items():
            found = re.findall(rx, text)
            if found:
                self.captured[name] = found
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), text

    def fill(self, value):
        """Replace NAME#i placeholders with this side's own captured values."""
        if isinstance(value, str):
            def sub(m):
                got = self.captured.get(m.group(1), [])
                i = int(m.group(2))
                return got[i] if i < len(got) else "MISSING"
            return re.sub(r"\b([A-Z]+)#([0-9]+)", sub, value)
        if isinstance(value, list):
            return [self.fill(v) for v in value]
        if isinstance(value, dict):
            return {k: self.fill(v) for k, v in value.items()}
        return value


KEEP_HEADERS = ("content-type", "location", "cache-control", "content-disposition", "allow", "x-frame-options",
                "content-security-policy", "pragma", "x-content-type-options", "referrer-policy",
                "content-language", "retry-after")


def normalize(text, csrf):
    if csrf:
        text = text.replace(csrf, "CSRF")
    text = re.sub(r"nonce-[A-Za-z0-9_\-]+", "nonce-N", text)
    text = re.sub(r'nonce="[A-Za-z0-9_\-]+"', 'nonce="N"', text)
    text = re.sub(r'"now": [0-9.e+]+', '"now": 0', text)
    return text


def norm_headers(h, csrf):
    out = {}
    for k in KEEP_HEADERS + tuple(getattr(cases, "EXTRA_HEADERS", ())):
        if k in h:
            out[k] = normalize(h[k], csrf)
    if "content-disposition" in out:
        out["content-disposition"] = re.sub(r"_[0-9]{8}_[0-9]{6}\.zip", "_TS.zip", out["content-disposition"])
        out["content-disposition"] = re.sub(r"-[0-9]{8}-[0-9]{6}\.zip", "-TS.zip", out["content-disposition"])
    if "set-cookie" in h:
        out["set-cookie"] = "present"
    return out


def audit_rows(path):
    import sqlite3
    try:
        conn = sqlite3.connect(path)
        rows = conn.execute("SELECT actor_type, actor, source_ip, action, object_type, object_id, result, summary, "
                            "before_json, after_json, detail FROM audit_events ORDER BY id").fetchall()
        conn.close()
        return [list(r) for r in rows]
    except Exception as exc:  # noqa: BLE001
        return "error: %s" % exc


def snapshot():
    out = {}
    for d in WATCH:
        for dp, _dirs, fns in os.walk(d):
            for n in fns:
                p = os.path.join(dp, n)
                if "/opt/haproxy-admin/haproxy_admin" in p or "__pycache__" in p:
                    continue
                if any(s in p for s in getattr(cases, "IGNORE_FILES", ())):
                    continue
                if p.endswith("-wal") or p.endswith("-shm") or ".bak." in p:
                    continue
                if p.endswith("audit.db"):
                    out[p] = audit_rows(p)
                    continue
                key = re.sub(r"\.bak\.[0-9]{14}$", ".bak.TS", p)
                key = re.sub(r"before-restore-[0-9]{14}", "before-restore-TS", key)
                tm = re.search(r"/[0-9]{9,12}-[0-9a-f]{12}\.(json|pending|restoring)$", key)
                if tm:
                    try:
                        tname = json.loads(open(p).read()).get("name", "?")
                    except Exception:  # noqa: BLE001
                        tname = "?"
                    key = key[:tm.start()] + "/ID-" + str(tname) + "." + tm.group(1)
                try:
                    data = open(p, "rb").read()
                except OSError:
                    continue
                st = os.stat(p)
                if len(data) < 20000:
                    try:
                        body = data.decode()
                    except UnicodeDecodeError:
                        body = hashlib.sha256(data).hexdigest()
                else:
                    body = hashlib.sha256(data).hexdigest()
                if "/trash/" in p and body.startswith("{"):
                    body = re.sub(r'"(id|deleted_at)": ("?)[0-9a-f-]+("?)', r'"": X', body)
                if hasattr(cases, "normalize_key"):
                    key = cases.normalize_key(key)
                if hasattr(cases, "normalize_file"):
                    body = cases.normalize_file(p, body)
                entry = [oct(st.st_mode & 0o777), body]
                if key in out:  # names that normalize alike: keep all, in a stable order
                    prev = out[key] if isinstance(out[key][0], list) else [out[key]]
                    entry = sorted(prev + [entry])
                out[key] = entry
    return out


def fakes_log():
    out = []
    for line in open("/srv/fakes.log"):
        line = re.sub(r"--[0-9a-f]{24,}", "--BOUNDARY", line)
        if hasattr(cases, "normalize_log_line"):
            line = cases.normalize_log_line(line)
        out.append(json.loads(line))
    open("/srv/fakes.log", "w").close()
    return out


results = {}
for side in ("py", "go"):
    reset_state()
    proc, port = start(side)
    client = Client(port)
    steps = []
    try:
        for step in cases.STEPS:
            label = step[0]
            if FILTER and FILTER not in label:
                continue
            kw = dict(step[3]) if len(step) > 3 else {}
            if "replies" in kw:
                with open("/srv/fake_replies.json", "w") as fh:
                    json.dump(kw.pop("replies"), fh)
            status, headers, body = client.request(step[1], step[2], **kw)
            body = normalize(body, client.csrf)
            if client.snap:
                body = body.replace(client.snap, "SNAP")
            if hasattr(cases, "normalize_body"):
                body = cases.normalize_body(label, body)
            steps.append({"label": label, "status": status, "headers": norm_headers(headers, client.csrf),
                          "body": body, "daemons": fakes_log(),
                          "files": snapshot() if getattr(cases, "SNAPSHOT_EACH", False) else None})
        steps.append({"label": "final files", "files": snapshot()})
    finally:
        proc.terminate()
        proc.wait()
    results[side] = steps

diffs = 0
for a, b in zip(results["py"], results["go"], strict=False):
    if a == b:
        continue
    diffs += 1
    print("=== %s" % a["label"])
    for key in ("status", "headers", "daemons", "files", "body"):
        if a.get(key) == b.get(key):
            continue
        if key == "body":
            al, bl = (a["body"] or "").splitlines(), (b["body"] or "").splitlines()
            for i in range(max(len(al), len(bl))):
                x = al[i] if i < len(al) else "<EOF>"
                y = bl[i] if i < len(bl) else "<EOF>"
                if x != y:
                    k = next((n for n in range(min(len(x), len(y))) if x[n] != y[n]), min(len(x), len(y)))
                    lo = max(0, k - 200)
                    print("  body line %d char %d\n    py: %s\n    go: %s" % (i + 1, k, x[lo:k + 300], y[lo:k + 300]))
                    break
        elif key == "files":
            fa, fb = a.get("files") or {}, b.get("files") or {}
            for p in sorted(set(fa) | set(fb)):
                if fa.get(p) != fb.get(p):
                    x, y = json.dumps(fa.get(p)), json.dumps(fb.get(p))
                    k = next((n for n in range(min(len(x), len(y))) if x[n] != y[n]), min(len(x), len(y)))
                    lo = max(0, k - 150)
                    print("  file %s char %d\n    py: %s\n    go: %s" % (p, k, x[lo:k + 250], y[lo:k + 250]))
        else:
            print("  %s\n    py: %s\n    go: %s" % (key, json.dumps(a.get(key), ensure_ascii=False)[:1500],
                                                  json.dumps(b.get(key), ensure_ascii=False)[:1500]))
if os.environ.get("SHOW_STATUS"):
    for a in results["go"]:
        if "status" in a:
            b = a["body"] or ""
            m = re.findall(r'class="alert[^"]*"[^>]*>\s*([^<]{0,160})', b)
            print(a["status"], a["label"], a["headers"].get("location", ""), m[:3] if m else b[:220].replace(chr(10), " "))
if len(results["py"]) != len(results["go"]):
    diffs += 1
    print("step counts differ: py %d, go %d" % (len(results["py"]), len(results["go"])))
print("steps", len(results["py"]), "diffs", diffs)
if os.environ.get("SHOW_LOGS"):
    print("--- go log\n" + open("/srv/go.log").read()[-3000:])
    print("--- py log\n" + open("/srv/py.log").read()[-3000:])
sys.exit(1 if diffs else 0)
