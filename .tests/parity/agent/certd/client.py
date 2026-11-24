import datetime as dt, http.client, json, re, socket, sys, uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=120)
        self.p = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(self.p)


def req(sock, method, path, body=None, raw=None, ctype=None):
    c = UnixHTTP(sock)
    headers = {}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if raw is not None:
        data = raw
        headers["Content-Type"] = ctype
    c.request(method, path, body=data, headers=headers)
    r = c.getresponse()
    out = r.read()
    try:
        return r.status, json.loads(out)
    except ValueError:
        return r.status, {"raw": out.decode(errors="replace")}


def multipart(fields, files):
    boundary = uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    for k, (fn, content) in files.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; filename="{fn}"\r\n'
                     f'Content-Type: application/octet-stream\r\n\r\n'.encode() + content + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def material():
    now = dt.datetime.now(dt.timezone.utc)
    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name("Test Corp Root")).issuer_name(name("Test Corp Root"))
          .public_key(ca_key.public_key()).serial_number(1).not_valid_before(now - dt.timedelta(days=1))
          .not_valid_after(now + dt.timedelta(days=900))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
    def leaf(names, key, days=60, issuer=ca, ikey=ca_key):
        return (x509.CertificateBuilder().subject_name(name(names[0])).issuer_name(issuer.subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=days))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(ikey, hashes.SHA256()))
    k1 = ec.generate_private_key(ec.SECP256R1())
    c1 = leaf(["web.example.org", "www.example.org"], k1, 20)
    k2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    c2 = leaf(["*.example.org"], k2, 300)
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM)
    kp = lambda k: k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    p12 = pkcs12.serialize_key_and_certificates(b"pfx", k2, c2, [ca], serialization.BestAvailableEncryption(b"secret"))
    enc_key = k1.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.BestAvailableEncryption(b"kpass"))
    return {"ca": pem(ca), "c1": pem(c1) + kp(k1), "c2": pem(c2) + kp(k2), "c1_enc": pem(c1) + enc_key,
            "p12": p12, "leaf_only": pem(c1), "ca_fp": ca.fingerprint(hashes.SHA256()).hex()}


def run(sock, m):
    out = []

    def rec(name, r):
        out.append((name, r))
        return r

    P = lambda path, body=None: req(sock, "POST", path, body if body is not None else {})
    rec("list0", req(sock, "GET", "/api/v1/certs/list"))
    rec("unknown_get", req(sock, "GET", "/api/v1/certs/nope"))
    rec("unknown_post", P("/api/v1/certs/nope"))
    rec("status_bad", P("/api/v1/certs/status", {"domains": ["bad name!"]}))
    rec("ensure", P("/api/v1/certs/ca/internal/ensure"))
    rec("ensure2", P("/api/v1/certs/ca/internal/ensure"))
    rec("int_issue", P("/api/v1/certs/ca/internal/issue", {"domain": "app.example.net", "alt_names": ["API.example.net", "app.example.net"]}))
    rec("int_issue_bad", P("/api/v1/certs/ca/internal/issue", {"domain": "x"}))
    rec("status", P("/api/v1/certs/status", {"domains": ["app.example.net", "api.example.net", "none.example.net"]}))
    body, ct = multipart({"name": ""}, {"ca_file": ("ca.pem", m["ca"])})
    rec("ca_upload", req(sock, "POST", "/api/v1/certs/ca/upload", raw=body, ctype=ct))
    rec("ca_upload_dup", req(sock, "POST", "/api/v1/certs/ca/upload", raw=body, ctype=ct))
    body, ct = multipart({}, {"ca_file": ("k.pem", m["c1"])})
    rec("ca_upload_key", req(sock, "POST", "/api/v1/certs/ca/upload", raw=body, ctype=ct))
    rec("ca_upload_nomp", req(sock, "POST", "/api/v1/certs/ca/upload", raw=b"x", ctype="text/plain"))
    for label, fields, files in (
        ("inspect_pem", {}, {"file": ("c1.pem", m["c1"])}),
        ("inspect_enc_nopw", {}, {"file": ("c1.pem", m["c1_enc"])}),
        ("inspect_enc_pw", {"password": "kpass"}, {"file": ("c1.pem", m["c1_enc"])}),
        ("inspect_p12_nopw", {}, {"file": ("c.p12", m["p12"])}),
        ("inspect_p12_badpw", {"password": "nope"}, {"file": ("c.p12", m["p12"])}),
        ("inspect_p12", {"password": "secret", "name": "Corp CA"}, {"file": ("c.p12", m["p12"])}),
        ("inspect_leafonly", {}, {"file": ("l.pem", m["leaf_only"])}),
        ("inspect_garbage", {}, {"file": ("g.bin", b"\x01\x02garbage")}),
        ("inspect_nofile", {}, {}),
    ):
        body, ct = multipart(fields, files)
        rec(label, req(sock, "POST", "/api/v1/certs/inspect", raw=body, ctype=ct))
    body, ct = multipart({"password": "secret", "name": "test-corp-root"}, {"file": ("c.p12", m["p12"])})
    rec("import_p12_conflict", req(sock, "POST", "/api/v1/certs/import", raw=body, ctype=ct))
    body, ct = multipart({"password": "secret", "name": "corp2", "domain": "shop.example.org"}, {"file": ("c.p12", m["p12"])})
    rec("import_p12", req(sock, "POST", "/api/v1/certs/import", raw=body, ctype=ct))
    body, ct = multipart({"domain": "web.example.org"}, {"cert_file": ("c1.pem", m["c1"])})
    rec("upload_shadow", req(sock, "POST", "/api/v1/certs/upload", raw=body, ctype=ct))
    body, ct = multipart({"domain": "other.example.com"}, {"cert_file": ("c1.pem", m["c1"])})
    rec("upload_wrongdomain", req(sock, "POST", "/api/v1/certs/upload", raw=body, ctype=ct))
    rec("list1", req(sock, "GET", "/api/v1/certs/list"))
    rec("standby0", P("/api/v1/certs/standby"))
    rec("sb_store_reserved", P("/api/v1/certs/standby/store", {"domain": "shop.example.org", "slot": "letsencrypt", "pem": m["c2"].decode()}))
    rec("sb_store", P("/api/v1/certs/standby/store", {"domain": "shop.example.org", "slot": "Backup CA", "pem": m["c2"].decode() + m["c2"].decode()}))
    rec("sb_store_all", P("/api/v1/certs/standby/store-all", {"slot": "wild", "pem": m["c2"].decode()}))
    rec("sb_store_mismatch", P("/api/v1/certs/standby/store", {"domain": "app.example.net", "slot": "x", "pem": m["c2"].decode()}))
    sb1 = rec("standby1", P("/api/v1/certs/standby"))
    import subprocess
    print("DBG", sock, [ (d["domain"], d["active"].get("days_left"), d["active"].get("not_after")) for d in sb1[1]["domains"]], dt.datetime.now(dt.timezone.utc))
    print(subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in", sock.replace("run/certd.sock", "certs/app.example.net.pem")], capture_output=True, text=True).stdout)
    rec("sb_activate", P("/api/v1/certs/standby/activate", {"domain": "shop.example.org", "slot": "Backup-CA"}))
    rec("sb_delete_inuse", P("/api/v1/certs/standby/delete", {"domain": "shop.example.org", "slot": "Backup-CA"}))
    rec("sb_release", P("/api/v1/certs/standby/release", {"domain": "shop.example.org"}))
    rec("sb_release_again", P("/api/v1/certs/standby/release", {"domain": "shop.example.org"}))
    rec("sb_adopt_only", P("/api/v1/certs/standby/adopt", {"domain": "app.example.net", "slot": "kept"}))
    rec("sb_delete", P("/api/v1/certs/standby/delete", {"domain": "shop.example.org", "slot": "wild", "actor": "admin"}))
    rec("client_auth", P("/api/v1/certs/ca/client-auth", {"ids": ["Test-Corp-Root", "internal", "internal"]}))
    rec("client_auth_bad", P("/api/v1/certs/ca/client-auth", {"ids": ["missing"]}))
    rec("revoked", P("/api/v1/certs/ca/revoked", {"fingerprints": [m["ca_fp"].upper(), "AA:" * 31 + "AA", "", m["ca_fp"]]}))
    rec("revoked_bad", P("/api/v1/certs/ca/revoked", {"fingerprints": ["xyz"]}))
    rec("export_int", P("/api/v1/certs/ca/export", {"ca_id": "internal"}))
    rec("export_ext", P("/api/v1/certs/ca/export", {"ca_id": "Test Corp Root"}))
    rec("export_missing", P("/api/v1/certs/ca/export", {"ca_id": "nope"}))
    rec("rotate_noconf", P("/api/v1/certs/ca/internal/rotate", {}))
    rec("rotate_trusted", P("/api/v1/certs/ca/internal/rotate", {"confirmation": "ROTATE"}))
    rec("client_auth_ext", P("/api/v1/certs/ca/client-auth", {"ids": ["test-corp-root"]}))
    rec("rotate", P("/api/v1/certs/ca/internal/rotate", {"confirmation": "ROTATE"}))
    rec("int_delete_blocked", P("/api/v1/certs/ca/internal/delete", {"confirmation": "DELETE"}))
    rec("dns0", P("/api/v1/certs/dns-providers"))
    rec("dns_bad", P("/api/v1/certs/dns-providers/save", {"name": "cf", "provider": "nope", "credentials": {}}))
    rec("dns_extra", P("/api/v1/certs/dns-providers/save", {"name": "cf", "provider": "cloudflare", "credentials": {"x": "1"}}))
    rec("dns_cf", P("/api/v1/certs/dns-providers/save", {"name": "cf", "provider": "cloudflare", "credentials": {"dns_cloudflare_api_token": "tok"}}))
    rec("dns_r53_half", P("/api/v1/certs/dns-providers/save", {"name": "aws", "provider": "route53", "credentials": {"aws_access_key_id": "A"}}))
    rec("dns_rfc", P("/api/v1/certs/dns-providers/save", {"name": "ns1", "provider": "rfc2136", "credentials": {"dns_rfc2136_server": "1.2.3.4", "dns_rfc2136_secret": "s"}}))
    rec("dns_rfc_keep", P("/api/v1/certs/dns-providers/save", {"name": "ns1", "provider": "rfc2136", "credentials": {"dns_rfc2136_server": "5.6.7.8", "dns_rfc2136_secret": ""}}))
    rec("dns1", P("/api/v1/certs/dns-providers"))
    rec("dns_del", P("/api/v1/certs/dns-providers/delete", {"name": "cf", "actor": "admin"}))
    rec("issue_wild_nodns", P("/api/v1/certs/issue", {"domain": "*.example.org"}))
    rec("issue_reserved", P("/api/v1/certs/issue", {"domain": "x.example.test"}))
    rec("issue_dns_noplugin", P("/api/v1/certs/issue", {"domain": "*.example.org", "dns_profile": "ns1"}))
    rec("issue", P("/api/v1/certs/issue", {"domain": "le.example.com", "alt_names": ["www.le.example.com"], "key_types": ["ecdsa", "rsa", "dsa"]}))
    rec("pauses", P("/api/v1/certs/renewal-pauses", {"domains": ["le.example.com", "nolineage.example.com"]}))
    rec("pauses_off", P("/api/v1/certs/renewal-pauses", {"domains": []}))
    rec("del_bad", P("/api/v1/certs/deliveries/save", {"name": "Bad Name"}))
    rec("del_save", P("/api/v1/certs/deliveries/save", {"name": "rdg", "domains": ["le.example.com"], "host": "10.0.0.9", "user": "svc",
                                                        "remote_path": "C:/certs/x.pfx", "port": "2222", "private_key": "KEY", "pfx_password": "pw",
                                                        "post_command": "a && b > c"}))
    rec("del_list", P("/api/v1/certs/deliveries"))
    rec("del_test", P("/api/v1/certs/deliveries/test", {"name": "rdg"}))
    rec("del_delete", P("/api/v1/certs/deliveries/delete", {"name": "rdg", "actor": "admin"}))
    st, lst = req(sock, "GET", "/api/v1/certs/list")
    rec("list2", (st, lst))
    target = next(i["path"] for i in lst["haproxy"] if "shop" in i["path"])
    rec("delete_outside", P("/api/v1/certs/delete-haproxy", {"path": "/etc/passwd"}))
    rec("delete_hap", P("/api/v1/certs/delete-haproxy", {"path": target, "actor": "admin"}))
    rec("delete_le", P("/api/v1/certs/delete-le", {"lineage": "le.example.com-rsa", "actor": "admin"}))
    st, trash = P("/api/v1/certs/trash")
    rec("trash", (st, trash))
    rec("trash_settings", P("/api/v1/certs/trash/settings", {"keep_days": "7"}))
    rec("trash_settings_bad", P("/api/v1/certs/trash/settings", {"keep_days": "x"}))
    for item in sorted(trash.get("items", []), key=lambda i: i["kind"]):
        if item["kind"] in ("haproxy_cert", "letsencrypt"):
            rec("restore_" + item["kind"], P("/api/v1/certs/trash/restore", {"id": item["id"]}))
    rec("restore_bad", P("/api/v1/certs/trash/restore", {"id": "1-abc"}))
    rec("purge_none", P("/api/v1/certs/trash/purge", {}))
    rec("purge_all", P("/api/v1/certs/trash/purge", {"all": True}))
    st, backup = P("/api/v1/certs/backup")
    rec("backup", (st, {k: v for k, v in backup.items() if k != "archive_b64"}))
    rec("restore_zip", P("/api/v1/certs/restore", {"archive_b64": backup.get("archive_b64", "")}))
    rec("restore_badb64", P("/api/v1/certs/restore", {"archive_b64": "!!!"}))
    rec("list3", req(sock, "GET", "/api/v1/certs/list"))
    return out


H64 = re.compile(r"\b[0-9a-f]{64}\b")
TRASH = re.compile(r"\b\d{9,12}-[0-9a-f]{12}\b")
TMPN = re.compile(r"\.(cert|pause|restore|replaced|tmp)-[A-Za-z0-9_]+")


def norm(obj, root):
    text = json.dumps(obj, sort_keys=True, ensure_ascii=False)
    text = text.replace(root, "<ROOT>")
    text = H64.sub("<H>", text)
    text = TRASH.sub("<TRASHID>", text)
    o = json.loads(text)

    def strip(x, key=""):
        if isinstance(x, dict):
            res = {}
            for k, v in x.items():
                if k in ("archive_b64", "certificate_b64", "deleted_at", "expires_at", "updated_ts", "at", "stdout", "stderr",
                         "cmd", "output", "detail", "pem_stdout", "reload_stdout", "message") and k != "message" or (k == "message" and "Archive size" in str(v)):
                    res[k] = "<var>"
                elif k in ("not_before", "days_left"):
                    res[k] = "<date>"
                else:
                    res[k] = strip(v, k)
            return res
        if isinstance(x, list):
            items = [strip(v, key) for v in x]
            if all(isinstance(v, str) for v in items):
                return sorted(items)
            if key == "items" and all(isinstance(v, dict) and "kind" in v for v in items):
                return sorted(items, key=lambda i: json.dumps(i, sort_keys=True))
            return items
        return x

    return strip(o)


if __name__ == "__main__":
    m = material()
    a = run(sys.argv[1], m)
    b = run(sys.argv[2], m)
    diffs = 0
    for (na, ra), (_nb, rb) in zip(a, b, strict=False):
        xa, xb = norm(ra, sys.argv[3]), norm(rb, sys.argv[4])
        if xa != xb:
            diffs += 1
            sa = json.dumps(xa, sort_keys=True, ensure_ascii=False)
            sb = json.dumps(xb, sort_keys=True, ensure_ascii=False)
            n = next((k for k in range(min(len(sa), len(sb))) if sa[k] != sb[k]), min(len(sa), len(sb)))
            print("=== DIFF", na)
            print("PY:", sa[max(0, n - 250):n + 350])
            print("GO:", sb[max(0, n - 250):n + 350])
    print("steps", len(a), len(b), "diffs", diffs)
    sys.exit(1 if diffs or len(a) != len(b) else 0)
