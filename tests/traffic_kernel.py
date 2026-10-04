"""Run the root quota regression in disposable network namespaces only."""
import os
from pathlib import Path
import subprocess
import sys
import time

prefix=f'rd-traffic-{os.getpid()}'
server_ns,client_ns=prefix+'-s',prefix+'-c'
created=[]
children=[]
def run(*args):
    subprocess.run(args,check=True,timeout=10,capture_output=True,text=True)
try:
    for ns in (server_ns,client_ns):
        run('ip','netns','add',ns);created.append(ns)
        run('ip','-n',ns,'link','set','lo','up')
    a,b=f'rdt{os.getpid()}a',f'rdt{os.getpid()}b'
    run('ip','link','add',a,'type','veth','peer','name',b)
    for ns,dev,address in ((server_ns,a,'8.8.45.1/24'),(client_ns,b,'8.8.45.2/24')):
        run('ip','link','set',dev,'netns',ns)
        run('ip','-n',ns,'address','add',address,'dev',dev)
        run('ip','-n',ns,'link','set',dev,'up')
    echo='''import socket,sys,threading
def tcp():
 s=socket.socket();s.bind(('8.8.45.1',int(sys.argv[1])));s.listen()
 while True:
  c,_=s.accept()
  with c:
   b=c.recv(4096)
   if b:c.sendall(b)
threading.Thread(target=tcp,daemon=True).start()
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('8.8.45.1',int(sys.argv[1])))
while True:
 b,a=s.recvfrom(4096);s.sendto(b,a)
'''
    for owner in (1,2,3):
        children.append(subprocess.Popen(['ip','netns','exec',server_ns,'setpriv','--reuid',str(59999+owner),'--regid',str(59999+owner),'--clear-groups','--bounding-set=-all','python3','-c',echo,str(40990+owner*10)]))
    time.sleep(.2)
    env=dict(os.environ,RELAYDECK_TRAFFIC_NAMESPACE='1',RELAYDECK_TRAFFIC_CLIENT=client_ns)
    subprocess.run(['ip','netns','exec',server_ns,sys.argv[1],'traffic_kernel_enforcement_and_recovery','--ignored','--exact','--test-threads=1','--nocapture'],env=env,check=True,timeout=90)
finally:
    for child in children:
        child.terminate();child.wait(timeout=5)
    for ns in reversed(created):
        run('ip','netns','delete',ns)
