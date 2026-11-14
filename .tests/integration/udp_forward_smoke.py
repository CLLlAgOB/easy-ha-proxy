"""Run ONLY inside a disposable privileged container with iproute2/iptables/ipset.

Creates a client and backend netns; the container is the gateway. Never run
against a production network namespace. Verifies actual UDP replies, bans,
authorization, Docker rule reordering, and removal with mixed packet filters.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)


def main():
    if not Path('/.dockerenv').exists() or os.geteuid() != 0:
        raise SystemExit('Use a disposable privileged Docker container, never a host')
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('udp', root / 'ansible/roles/haproxy-admin/files/haproxy-udp-forward.py')
    udp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(udp)
    for name, address, interface, peer in (
        ('client', '192.0.2', 'uc0', 'uc1'), ('backend', '198.51.100', 'ub0', 'ub1'),
    ):
        run('ip', 'netns', 'add', name)
        run('ip', 'link', 'add', interface, 'type', 'veth', 'peer', 'name', peer)
        run('ip', 'link', 'set', peer, 'netns', name)
        run('ip', 'addr', 'add', address + '.1/24', 'dev', interface)
        run('ip', 'link', 'set', interface, 'up')
        run('ip', '-n', name, 'addr', 'add', address + '.2/24', 'dev', peer)
        run('ip', '-n', name, 'link', 'set', peer, 'up')
        run('ip', '-n', name, 'link', 'set', 'lo', 'up')
        run('ip', '-n', name, 'route', 'add', 'default', 'via', address + '.1')
    for name in (udp.BAN_SET, udp.AUTH_SET):
        run('ipset', 'create', name, 'hash:ip')
    run('iptables-nft', '-N', 'DOCKER-USER')
    run('iptables-nft', '-N', 'DOCKER-FORWARD')
    run('iptables-nft', '-A', 'DOCKER-FORWARD', '-j', 'DROP')
    run('iptables-nft', '-A', 'FORWARD', '-j', 'DOCKER-USER')
    run('iptables-nft', '-A', 'FORWARD', '-j', 'DOCKER-FORWARD')
    run('iptables-nft', '-P', 'FORWARD', 'DROP')
    server = subprocess.Popen(['ip', 'netns', 'exec', 'backend', sys.executable, '-u', '-c',
        "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('198.51.100.2',30000))\n"
        "while True:\n data,peer=s.recvfrom(1024);s.sendto(data,peer)\n"])
    def exchange(expected, host='192.0.2.1', port=20000):
        result = run('ip', 'netns', 'exec', 'client', sys.executable, '-c',
            "import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.5);"
            f"s.sendto(b'udp-proof',('{host}',{port}));"
            "\ntry: ok=s.recv(1024)==b'udp-proof'\nexcept TimeoutError: ok=False\n"
            f"sys.exit(0 if ok=={expected!r} else 1)")
        return result
    try:
        time.sleep(.2)
        with tempfile.TemporaryDirectory() as directory:
            udp.STATE_PATH = Path(directory) / 'state.json'
            forward = udp.normalize_forward({'listen_port':20000, 'backend_host':'198.51.100.2', 'backend_port':30000})
            sync = udp._sync_other_forward_filters
            udp._sync_other_forward_filters = lambda _commands: None
            udp.apply_forwards([forward]); exchange(False)
            udp._sync_other_forward_filters = sync
            udp.apply_forwards([forward]); exchange(True)
            # Docker can put its own jumps back ahead of the UDP FORWARD hook.
            for chain in ('DOCKER-USER', 'DOCKER-FORWARD'):
                run('iptables-nft', '-D', 'FORWARD', '-j', chain)
            for chain in ('DOCKER-FORWARD', 'DOCKER-USER'):
                run('iptables-nft', '-I', 'FORWARD', '1', '-j', chain)
            exchange(True)
            exchange(False, '198.51.100.2', 30000)  # direct traffic is not opened
            run('ipset', 'add', udp.BAN_SET, '192.0.2.2'); exchange(False)
            run('ipset', 'del', udp.BAN_SET, '192.0.2.2')
            forward['zero_trust'] = True
            udp.apply_forwards([forward]); exchange(False)
            run('ipset', 'add', udp.AUTH_SET, '192.0.2.2'); exchange(True)
            udp.apply_forwards([forward]); exchange(True)  # repeated apply
            udp.apply_forwards([]); exchange(False)
            policy = run('iptables-nft', '-S', 'FORWARD').stdout.splitlines()[0]
            assert policy == '-P FORWARD DROP', policy
            print('PASS: mixed Docker filters, UDP replies, ordering, bans, zero trust, isolation, removal')
    finally:
        server.terminate(); server.wait(timeout=5)
        for name in ('client', 'backend'):
            run('ip', 'netns', 'del', name)


if __name__ == '__main__':
    main()
