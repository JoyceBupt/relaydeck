"""Real WireGuard encapsulation regression in disposable network namespaces."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def run(*args, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=10)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or 'kernel command failed')
    return result.stdout


assert os.geteuid() == 0, 'isolated root Linux is required'
old, fixed = json.load(sys.stdin)
client, peer = [f'rd-wg-{os.getpid()}-{side}' for side in ('client', 'peer')]
created = []
server = None
try:
    with tempfile.TemporaryDirectory(prefix='rd-wg-') as directory:
        root = Path(directory)
        for ns in (client, peer):
            run('ip', 'netns', 'add', ns)
            created.append(ns)
            run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
        run('ip', 'link', 'add', 'rd-wg-a', 'type', 'veth', 'peer', 'name', 'rd-wg-b')
        for ns, dev, address in ((client, 'rd-wg-a', '8.8.45.1/24'), (peer, 'rd-wg-b', '8.8.45.2/24')):
            run('ip', 'link', 'set', dev, 'netns', ns)
            run('ip', '-n', ns, 'address', 'add', address, 'dev', dev)
            run('ip', '-n', ns, 'link', 'set', dev, 'up')
            run('ip', '-n', ns, 'link', 'add', 'wg-test', 'type', 'wireguard')
        keys = [run('wg', 'genkey').strip() for _ in range(2)]
        publics = [run('wg', 'pubkey', data=key).strip() for key in keys]
        for i, ns in enumerate((client, peer)):
            private = root / f'key-{i}'
            private.write_text(keys[i])
            private.chmod(0o600)
            run('ip', 'netns', 'exec', ns, 'wg', 'set', 'wg-test', 'private-key', str(private),
                'listen-port', str(51920 + i), 'fwmark', '51820', 'peer', publics[1-i],
                'endpoint', f'8.8.45.{2-i}:{51921-i}', 'allowed-ips', '2001:4860:44::/64')
            run('ip', '-n', ns, '-6', 'address', 'add', f'2001:4860:44::{i+1}/64', 'dev', 'wg-test', 'nodad')
            run('ip', '-n', ns, 'link', 'set', 'wg-test', 'up')
        echo = '''import socket,threading
def udp(host,port,family):
 s=socket.socket(family,socket.SOCK_DGRAM);s.bind((host,port))
 while True:
  b,a=s.recvfrom(4096);s.sendto(b,a)
threading.Thread(target=udp,args=('2001:4860:44::2',443,socket.AF_INET6),daemon=True).start()
threading.Thread(target=udp,args=('8.8.45.2',52921,socket.AF_INET),daemon=True).start()
s=socket.socket(socket.AF_INET6);s.bind(('2001:4860:44::2',443));s.listen()
while True:
 c,_=s.accept()
 with c:
  b=c.recv(4096)
  if b:c.sendall(b)
'''
        server = subprocess.Popen(['ip', 'netns', 'exec', peer, 'python3', '-c', echo])
        time.sleep(.2)
        probe = '''import socket,sys
expected=sys.argv[1]=='yes'
for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
 s=socket.socket(socket.AF_INET6,kind);s.settimeout(1)
 try:
  s.connect(('2001:4860:44::2',443));s.sendall(b'wireguard-test');ok=s.recv(4096)==b'wireguard-test'
 except OSError:ok=False
 finally:s.close()
 assert ok==expected,('forwarding mismatch',kind,ok,expected)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.5)
try:s.setsockopt(socket.SOL_SOCKET,36,51820)
except PermissionError:pass
else:raise AssertionError('tenant forged WireGuard mark')
try:
 s.sendto(b'direct-peer',('8.8.45.2',52921));s.recv(4096)
except (socket.timeout,PermissionError):pass
else:raise AssertionError('unmarked tenant reached non-target peer')
'''
        for rules, allowed in ((old, 'no'), (fixed, 'yes')):
            run('ip', 'netns', 'exec', client, 'nft', '-f', '-', data=rules)
            if binary := os.environ.get('RELAYDECK_PROBE_BINARY'):
                result = json.loads(run('ip','netns','exec',client,'setpriv','--reuid','60000','--regid','60000','--clear-groups','--bounding-set=-all',binary,'probe-tcp','[2001:4860:44::2]:443'))
                # A handshake can succeed before the kernel drops later payload packets.
                if allowed == 'yes':
                    assert result['status'] == 'connected', result
            run('ip', 'netns', 'exec', client, 'setpriv', '--reuid', '60000', '--regid', '60000',
                '--clear-groups', '--bounding-set=-all', 'python3', '-c', probe, allowed)
        print('WireGuard TCP/UDP forwarding and unmarked target isolation passed')
finally:
    if server:
        server.terminate()
        server.wait(timeout=5)
    for ns in reversed(created):
        run('ip', 'netns', 'delete', ns)
