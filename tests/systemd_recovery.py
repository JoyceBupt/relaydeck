"""Opt-in root tests, ONLY in an isolated systemd Docker container.

RELAYDECK_SYSTEMD_TEST=1 python3 tests/systemd_recovery.py
Requires the pinned Realm binary, built RelayDeck, dedicated runner identities,
and an isolated echo peer at 8.8.43.20/21:8443. No production host is accepted.
"""
import json
import os
import pathlib
import signal
import socket
import subprocess
import time
import unittest

ROOT = pathlib.Path('/var/lib/relaydeck-qa')
BIN = '/usr/local/libexec/relaydeck'
SYSTEMCTL = pathlib.Path('/usr/bin/systemctl')
IP = pathlib.Path('/usr/sbin/ip')
TRANSPORT = """import json,socket,struct,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(40);s.connect(sys.argv[1]);b=sys.stdin.buffer.read();s.sendall(struct.pack('!I',len(b))+b)
def read(n):
 b=b''
 while len(b)<n:
  x=s.recv(n-len(b))
  if not x: raise RuntimeError('broker closed connection')
  b+=x
 return b
n=struct.unpack('!I',read(4))[0];assert n<=131072;print(read(n).decode())
"""


def wait_for(predicate, seconds=15):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.2)
    raise AssertionError('Timed out waiting for runtime state')


def request(op, data=None, success=True):
    if op == 'apply':
        request('traffic', [{'owner_id': data['owner_id'], 'budget': {'limit_bytes': None, 'mode': 'both'}}])
    value = {'op': op}
    if data is not None:
        value['data'] = data
    result = subprocess.run(['runuser', '-u', 'relaydeck', '--', 'python3', '-c', TRANSPORT, str(ROOT / 'broker.sock')],
                            input=json.dumps(value), capture_output=True, text=True, check=True, timeout=45)
    reply = json.loads(result.stdout)
    if success:
        assert reply['error'] is None, reply
    return reply


def plan(owner, revision=1, target='8.8.43.20', ports=None):
    ports = ports or ([41000, 41001] if owner == 1 else [41010])
    return {'owner_id': owner, 'revision': revision, 'expires_at': None,
            'port_start': 41000 if owner == 1 else 41010, 'port_end': 41009 if owner == 1 else 41019, 'max_rules': 30,
            'rules': [{'id': owner*100 + index, 'listen_port': port, 'target_ip': target if index == 0 else '8.8.43.20',
                       'target_port': 8443, 'protocol': 'both', 'source_cidrs': [], 'enabled': True}
                      for index, port in enumerate(ports)]}


def connection(port):
    stream = socket.create_connection(('8.8.43.10', port), timeout=3)
    echo(stream)
    return stream


def echo(stream):
    stream.sendall(b'keep-connection')
    assert stream.recv(4096) == b'keep-connection'


def udp_echo(port):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
        stream.settimeout(3)
        stream.sendto(b'udp-forward',('8.8.43.10',port))
        assert stream.recv(4096)==b'udp-forward'


def pid(owner):
    return subprocess.check_output([str(SYSTEMCTL), 'show', '--property=MainPID', '--value', f'relaydeck-owner-{owner}.service'], text=True).strip()


@unittest.skipUnless(os.environ.get('RELAYDECK_SYSTEMD_TEST') == '1', 'isolated systemd runtime gate only')
class Recovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or not pathlib.Path('/.dockerenv').exists():
            raise RuntimeError('Refuse runtime tests outside an isolated Docker container')
        active = subprocess.check_output([str(SYSTEMCTL), 'list-units', '--state=active', '--plain', '--no-legend', 'relaydeck-*.service'],text=True)
        if active.strip():
            raise RuntimeError('Refuse runtime tests when existing RelayDeck services are active')
        ROOT.mkdir(mode=0o755,exist_ok=True)
        (ROOT / 'runtime').mkdir(mode=0o755,exist_ok=True)
        if pathlib.Path('/proc/sys/net/ipv4/ip_local_reserved_ports').read_text().strip() != '41000-41019':
            raise RuntimeError('Launch the isolated container with --sysctl net.ipv4.ip_local_reserved_ports=41000-41019')
        policy = json.loads(pathlib.Path('/fixture/deploy/broker.example.json').read_text())
        policy.update(database=str(ROOT / 'data.db'), web_uid=1100, web_gid=1100, runtime_dir=str(ROOT / 'runtime'),
                      socket_path=str(ROOT / 'broker.sock'), allowed_port_start=41000, allowed_port_end=41019,
                      authorization_ttl_secs=30)
        (ROOT / 'policy.json').write_text(json.dumps(policy))
        cls.log = (ROOT / 'broker.log').open('ab')
        cls.start()

    @classmethod
    def start(cls):
        socket_path=ROOT / 'broker.sock'
        if socket_path.exists():
            socket_path.unlink()
        cls.broker = subprocess.Popen([BIN, 'broker', str(ROOT / 'policy.json')], stdout=cls.log, stderr=cls.log)
        wait_for(lambda: (ROOT / 'broker.sock').exists() and cls.broker.poll() is None)
        # The socket is bound before startup validation. Inspect waits for readiness.
        request('inspect')

    @classmethod
    def tearDownClass(cls):
        cls.broker.send_signal(signal.SIGTERM)
        cls.broker.wait(timeout=30)
        cls.log.close()
        for path in (SYSTEMCTL, IP):
            original = path.with_name(path.name + '.qa-original')
            if original.exists():
                path.unlink()
                original.rename(path)

    def test_recovery_isolation_and_incremental_updates(self):
        request('apply', plan(1))
        request('apply', plan(2))
        udp_echo(41000)
        udp_echo(41010)
        stable = connection(41001)
        self.addCleanup(stable.close)
        other = connection(41010)
        self.addCleanup(other.close)
        parent = pid(1)
        request('apply', plan(1, 2, '8.8.43.21'))
        self.assertEqual(parent, pid(1))
        udp_echo(41000)
        udp_echo(41001)
        echo(stable)
        echo(other)
        with connection(41000) as changed:
            echo(changed)
        # Add/remove a listener without replacing the parent or unaffected child.
        request('apply', plan(1, 3, '8.8.43.21', [41000, 41001, 41002]))
        with connection(41002) as added:
            echo(added)
        echo(stable)
        request('apply', plan(1, 4, '8.8.43.21'))
        echo(stable)
        # Deleting the firewall is repaired in-place without stopping tenants.
        subprocess.run(['nft', 'delete', 'table', 'inet', 'relaydeck'], check=True)
        time.sleep(12)
        self.assertEqual(parent, pid(1))
        echo(stable)
        echo(other)
        # Fault injection affects only the fixed tool inside this test container.
        IP.rename(IP.with_name('ip.qa-original'))
        IP.write_text('#!/bin/sh\nif [ -f /run/qa-ip-fail ]; then sleep 5; exit 1; fi\nexec /usr/sbin/ip.qa-original "$@"\n')
        IP.chmod(0o755)
        pathlib.Path('/run/qa-ip-fail').touch()
        # Two failed global probes; identical lease renewals need no IP command.
        time.sleep(11)
        request('apply', plan(1, 4, '8.8.43.21'))
        request('apply', plan(2))
        pathlib.Path('/run/qa-ip-fail').unlink()
        time.sleep(7)
        self.assertEqual(parent, pid(1))
        echo(stable)
        echo(other)
        IP.unlink()
        IP.with_name('ip.qa-original').rename(IP)
        SYSTEMCTL.rename(SYSTEMCTL.with_name('systemctl.qa-original'))
        SYSTEMCTL.write_text('#!/bin/sh\nif [ "$1" = stop ] && [ "$2" = relaydeck-owner-1.service ]; then exit 1; fi\nexec /usr/bin/systemctl.qa-original "$@"\n')
        SYSTEMCTL.chmod(0o755)
        reply = request('stop', 1, success=False)
        self.assertTrue(reply['retryable'])
        self.assertIsNone(self.broker.poll())
        echo(other)
        # Restart still serves owner 2 even when owner 1 cleanup fails.
        self.broker.send_signal(signal.SIGTERM)
        self.broker.wait(timeout=35)
        self.start()
        request('apply', plan(2, 2))
        with connection(41010) as resumed:
            echo(resumed)
        SYSTEMCTL.unlink()
        SYSTEMCTL.with_name('systemctl.qa-original').rename(SYSTEMCTL)
        request('apply', plan(1, 5, '8.8.43.21'))
        with connection(41000) as resumed:
            echo(resumed)
        # Independent authorization expiration can recover the same revision.
        time.sleep(32)
        request('apply', plan(1, 5, '8.8.43.21'))
        with connection(41001) as resumed:
            echo(resumed)
        subprocess.run([str(SYSTEMCTL),'kill','--signal=SIGKILL','relaydeck-owner-1.service'],check=True)
        time.sleep(.3)
        crashed=request('apply',plan(1,5,'8.8.43.21'),success=False)
        self.assertTrue(crashed['retryable'])
        events=request('inspect')['events']
        self.assertTrue(any(event['owner']==1 and event['retryable'] for event in events))
        request('apply',plan(1,6,'8.8.43.21'))
        with connection(41000) as recovered:
            echo(recovered)
            # Tightening a source ACL must also revoke accepted connections.
            acl=plan(1,7,'8.8.43.21')
            acl['rules'][0]['source_cidrs']=['8.8.43.11/32']
            with connection(41001) as unaffected:
                request('apply',acl)
                recovered.settimeout(3)
                self.assertEqual(recovered.recv(4096),b'')
                echo(unaffected)
            request('apply',plan(1,8,'8.8.43.21'))
            with connection(41000) as restored:
                echo(restored)


if __name__ == '__main__':
    unittest.main()
