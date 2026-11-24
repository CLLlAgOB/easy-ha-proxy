"""server-state: the agent against installer/haproxy_server_state.py on configs x dumps.

Runs in the parity container (REPO, AGENT_BIN as for the other stands); exits 1 on any diff.
"""
import itertools
import os
import subprocess
import sys

REPO = os.environ.get("REPO", "/repo")

AGENT = os.environ.get("AGENT_BIN", "/work/agent")
HEAD = ("# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight "
        "srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state "
        "srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord")
OPT = " srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port"


def row(be, srv, addr="10.0.0.9", op=0, adm=0, fqdn="-", port=8080, srvrec="-", extra=""):
    return f"3 {be} 1 {srv} {addr} {op} {adm} 1 1 100 6 3 4 6 0 0 0 {fqdn} {port} {srvrec}{extra}"


configs = {
    "basic": """global
  stats socket /run/haproxy/admin.sock
defaults
  mode http
  default-server check inter 2s
backend web
  server w1 10.0.0.1:80
  server w2 app.Example.COM.:8443 no-check
  server w3 _http._tcp.svc.local resolvers dns
  server w4 [2001:db8::1]:443 check
  server w5 ipv4@10.0.0.5
  server w6 unix@/run/app.sock
  server w7 /var/run/x.sock
  server w8 "quoted.example":81 agent-check # trailing comment
  server w9 2001:db8::9
listen stats
  default-server no-check
  server s1 10.0.0.10:9000
frontend fe
  server ignored 10.9.9.9:1
""",
    "nodefaults": """backend b
  server a host.example:80 check
  server b 10.0.0.2:${PORT}
  server c 10.0.0.3:070
defaults second
  default-server agent-check
backend c
  server x 10.0.0.4:1
  #server commented 10.0.0.5:1
  server y [::ffff:10.0.0.6]:1
""",
    "badport": "backend b\n  server a 10.0.0.1:70000\n",
    "badbracket": "backend b\n  server a [::1:80\n",
    "tabs": "backend\tt\n\tserver\tt1\t10.1.1.1:5\tcheck\r\n\tserver t2 h#x.example:5\n",
}

states = {
    "plain": "1\n" + HEAD + "\n" + "\n".join([
        row("web", "w1", adm=0x41, op=1), row("web", "w2", addr="1.2.3.4", fqdn="app.example.com", op=0),
        row("web", "w2b"), row("web", "w3", srvrec="_http._tcp.svc.local", fqdn="x"),
        row("web", "w4", addr="2001:db8:0::1"), row("web", "w5"), row("web", "w6"), row("web", "w7"),
        row("web", "w8", fqdn="QUOTED.example.", addr="5.5.5.5"), row("web", "w9"),
        row("stats", "s1", op=0), row("fe", "ignored"), row("b", "a"), row("b", "b"), row("b", "c"),
        row("c", "x"), row("c", "y"), row("t", "t1"), row("t", "t2", fqdn="h"),
    ]) + "\n",
    "optional": "1\n" + HEAD + OPT + "\n" + row("web", "w1", extra=" 1 0 - - 0") + "\n\n# comment\n",
    "srvmismatch": "1\n" + HEAD + "\n" + row("web", "w3", srvrec="_other._tcp", port=0) + "\n",
    "badversion": "2\n" + HEAD + "\n",
    "empty": "",
    "badheader": "1\n# be_id be_name x\n",
    "badoptional": "1\n" + HEAD + " srv_check_port\n",
    "short": "1\n" + HEAD + "\n3 web 1 w1\n",
    "noheader": "1\n" + row("web", "w1") + "\n",
    "nonnum": "1\n" + HEAD + "\n" + row("web", "w1", port="x") + "\n",
    "crlf": "1\r\n" + HEAD + "\r\n" + row("web", "w1") + "\r\n",
}

os.makedirs("/tmp/ss", exist_ok=True)
diffs = total = 0
for (cn, ctext), (sn, stext) in itertools.product(list(configs.items()) + [("missing", None)], states.items()):
    cfg = f"/tmp/ss/{cn}.cfg"
    if ctext is not None:
        open(cfg, "w").write(ctext)
    else:
        cfg = "/tmp/ss/does-not-exist.cfg"
    st = f"/tmp/ss/{sn}.state"
    open(st, "w", newline="").write(stext)
    outs = []
    for argv in (["python3", REPO + "/installer/haproxy_server_state.py"], [AGENT, "server-state"]):
        p = subprocess.run(argv + ["--config", cfg, "--state", st], capture_output=True, text=True)
        outs.append((p.returncode, p.stdout, p.stderr))
    total += 1
    if outs[0] != outs[1]:
        diffs += 1
        print(f"=== {cn} x {sn}")
        print("py:", outs[0])
        print("go:", outs[1])
print(f"cases: {total}  diffs: {diffs}")
sys.exit(1 if diffs else 0)
