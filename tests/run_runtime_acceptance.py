"""Build and test a disposable systemd host; never operates on an SSH host."""
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import urllib.request

SOURCE=pathlib.Path(__file__).resolve().parents[1]

def run(*args,**kwargs):
    return subprocess.run(args,check=True,**kwargs)


def main():
    binary=pathlib.Path(os.environ.get('RELAYDECK_TEST_BINARY',SOURCE / 'target/debug/relaydeck')).resolve()
    architecture=subprocess.check_output(['docker','version','--format','{{.Server.Arch}}'],text=True).strip()
    arch,checksum={'arm64':('aarch64','f4c0318dd86854da483dcb7645b4f39cae2cc3f91c688fef969d53220b949488'),
                   'amd64':('x86_64','b1cc335547bea8bb2a88178bef12ec7f2363e36200e7ea1d4e1e67627929bf65')}[architecture]
    prefix='relaydeck-acceptance-'+str(os.getpid())
    image=prefix+':test'; network=prefix+'-net'; host=prefix+'-host'; peer=prefix+'-peer'
    with tempfile.TemporaryDirectory(prefix=prefix) as directory:
        work=pathlib.Path(directory)
        archive=work / 'realm.tar.gz'
        with urllib.request.urlopen(f'https://github.com/zhboner/realm/releases/download/v2.9.6/realm-{arch}-unknown-linux-musl.tar.gz',timeout=60) as response:
            archive.write_bytes(response.read())
        if hashlib.sha256(archive.read_bytes()).hexdigest()!=checksum: raise RuntimeError('Pinned Realm checksum mismatch')
        import tarfile
        with tarfile.open(archive) as tar:
            member=next(item for item in tar.getmembers() if pathlib.PurePosixPath(item.name).name=='realm' and item.isfile())
            (work / 'realm').write_bytes(tar.extractfile(member).read())
        shutil.copy2(binary,work / 'relaydeck')
        base=os.environ.get('RELAYDECK_RUNTIME_IMAGE','debian:bookworm-slim')
        if base not in ('debian:bookworm-slim','ubuntu:24.04'): raise ValueError('Unsupported runtime test image')
        (work / 'Dockerfile').write_text('FROM '+base+'''
ENV container=docker
RUN apt-get update -qq && apt-get install -y --no-install-recommends systemd systemd-sysv nftables iproute2 python3 ca-certificates procps && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 1100 relaydeck && useradd -u 1100 -g 1100 -M -d /nonexistent -s /usr/sbin/nologin relaydeck && for i in $(seq 1 11); do n=$((62000+i-1)); groupadd -g $n relaydeck-runner-$i; useradd -u $n -g $n -M -d /nonexistent -s /usr/sbin/nologin relaydeck-runner-$i; done
COPY relaydeck realm /usr/local/libexec/
RUN chmod 0755 /usr/local/libexec/relaydeck /usr/local/libexec/realm
CMD ["/sbin/init"]
''')
        try:
            run('docker','build','-q','-t',image,str(work))
            run('docker','network','create','--internal','--subnet','8.8.43.0/24',network)
            run('docker','run','-d','--name',host,'--privileged','--cgroupns=private','--tty','--env','SYSTEMD_LOG_TARGET=console','--tmpfs','/run','--tmpfs','/run/lock','--network',network,'--ip','8.8.43.10','--sysctl','net.ipv4.ip_local_reserved_ports=41000-41019','--volume',str(SOURCE)+':/fixture:ro',image)
            run('docker','run','-d','--name',peer,'--cap-add','NET_ADMIN','--network',network,'--ip','8.8.43.20',image,'sleep','infinity')
            run('docker','exec',peer,'ip','addr','add','8.8.43.21/24','dev','eth0')
            echo="""import socket,threading

def tcp(c):
 try:
  while b:=c.recv(65536): c.sendall(b)
 finally: c.close()
def udp():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',8443))
 while True:
  b,a=s.recvfrom(65536);s.sendto(b,a)
threading.Thread(target=udp,daemon=True).start()
s=socket.socket();s.bind(('0.0.0.0',8443));s.listen()
while True:
 c,_=s.accept();threading.Thread(target=tcp,args=(c,),daemon=True).start()
"""
            run('docker','exec','-d',peer,'python3','-c',echo)
            subprocess.run(['docker','exec',host,'systemctl','is-system-running','--wait'],timeout=45)
            result=subprocess.run(['docker','exec','-e','RELAYDECK_SYSTEMD_TEST=1','-e','PYTHONDONTWRITEBYTECODE=1',host,'python3','/fixture/tests/systemd_recovery.py','-v'])
            if result.returncode == 0:
                result=subprocess.run(['docker','exec','-e','PYTHONDONTWRITEBYTECODE=1',host,'unshare','--net','python3','/fixture/tests/recovery_acceptance.py','-v'])
            if result.returncode:
                subprocess.run(['docker','info','--format','{{.CgroupVersion}} {{.CgroupDriver}}'])
                subprocess.run(['docker','inspect','--format','{{json .State}}',host])
                subprocess.run(['docker','logs',host])
                subprocess.run(['docker','exec',host,'cat','/var/lib/relaydeck-qa/broker.log'])
                subprocess.run(['docker','exec',host,'journalctl','--no-pager','-n','80'])
                raise RuntimeError('Systemd runtime acceptance failed')
        finally:
            for name in (host,peer): subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


if __name__=='__main__': main()
