#!/usr/bin/env python3
import hashlib, os, re, sys, time
prog = os.path.basename(sys.argv[0])
argv = sys.argv[1:]
log = open(os.environ.get("FAKE_LOG", "/tmp/fake.log"), "a")


def norm(s):
    return re.sub(r"/tmp/cert-deliver-[^/\"\s]+", "/tmp/WD", s)


def stat(path):
    try:
        st = os.stat(path)
    except OSError:
        return f"{norm(path)} missing"
    mode = oct(st.st_mode & 0o777)
    if path.endswith(".pfx"):
        return f"{norm(path)} {mode} pfx"
    return f"{norm(path)} {mode} {hashlib.sha256(open(path, 'rb').read()).hexdigest()[:12]}"


log.write(f"{prog} {norm(' '.join(argv))}\n")
joined = " ".join(argv)
if prog == "sftp":
    batch = sys.stdin.read()
    log.write("  batch: " + norm(batch).replace("\n", "|") + "\n")
    for line in batch.splitlines():
        m = re.match(r'put "((?:[^"\\]|\\.)*)"', line)
        if m:
            log.write("  " + stat(m.group(1).replace('\\"', '"').replace("\\\\", "\\")) + "\n")
elif prog == "scp":
    rest = argv[argv.index("--") + 1:]
    for p in rest[:-1]:
        log.write("  " + stat(p) + "\n")
log.close()
if "slow.example" in joined:
    time.sleep(3)
if "fail.example" in joined and prog != "ssh":
    sys.stderr.write("ssh: connect to host fail.example port 22: Connection refused\n")
    sys.exit(1)
if "silent.example" in joined and prog != "ssh":
    sys.exit(255)
if prog == "ssh" and argv[-1] == "fail":
    sys.stderr.write("boom\n")
    sys.exit(3)
if prog == "ssh" and argv[-1] == "quiet-fail":
    sys.exit(4)
sys.exit(0)
