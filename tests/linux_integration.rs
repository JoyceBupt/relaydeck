//! Opt-in data-plane check in task-owned, isolated Docker networks. It does not
//! validate systemd, cgroup hardening, the production host, or the root worker.
use std::{
    collections::HashSet,
    fs,
    io::Write,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use relaydeck::{
    executor::{DesiredPlan, DesiredRule, ExecutorPolicy, Protocol},
    linux::{BrokerPolicy, render_nft, validate_runtime_listeners},
};
use sha2::{Digest, Sha256};

fn output(program: &str, arguments: &[&str]) -> String {
    let result = Command::new(program)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("{program}: {error}"));
    assert!(
        result.status.success(),
        "{program} {arguments:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).expect("UTF-8 command output")
}

fn docker(arguments: &[&str]) -> String {
    output("docker", arguments)
}

fn python(container: &str, program: &str, uid: Option<u32>) {
    let mut command = Command::new("docker");
    command.args(["exec", "-i", container]);
    if let Some(uid) = uid {
        command.args([
            "setpriv",
            "--reuid",
            &uid.to_string(),
            "--regid",
            &uid.to_string(),
            "--clear-groups",
            "--no-new-privs",
        ]);
    }
    let mut child = command
        .args(["python3", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch bounded container Python check");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .expect("send check");
    let result = child.wait_with_output().expect("wait for check");
    assert!(
        result.status.success(),
        "container check failed: {} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

struct Cleanup {
    containers: Vec<String>,
    networks: Vec<String>,
    image: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for name in &self.containers {
            let _ = Command::new("docker").args(["rm", "-f", name]).output();
        }
        for name in &self.networks {
            let _ = Command::new("docker")
                .args(["network", "rm", name])
                .output();
        }
        let _ = Command::new("docker")
            .args(["image", "rm", &self.image])
            .output();
    }
}

const SERVER: &str = r#"
import socket, threading
def tcp(family):
    server=socket.socket(family,socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    if family==socket.AF_INET6: server.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
    server.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',8443)); server.listen()
    while True:
        client,_=server.accept()
        def echo(client):
            with client:
                client.settimeout(5)
                while True:
                    data=client.recv(4096)
                    if not data: break
                    client.sendall(data)
        threading.Thread(target=echo,args=(client,),daemon=True).start()
def udp(family):
    server=socket.socket(family,socket.SOCK_DGRAM)
    if family==socket.AF_INET6: server.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
    server.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',8443))
    while True:
        data,peer=server.recvfrom(4096); server.sendto(data,peer)
for family in (socket.AF_INET,socket.AF_INET6):
    for target in (tcp,udp): threading.Thread(target=target,args=(family,),daemon=True).start()
threading.Event().wait()
"#;

fn echo_check(port: u16, allowed: bool, ipv6: bool) -> String {
    format!(
        r#"
import socket
for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
    client=socket.socket(socket.AF_INET6 if {ipv6} else socket.AF_INET,kind)
    client.settimeout(1)
    destination=('2001:4860:42::10' if {ipv6} else '8.8.42.10',{port})
    success=False
    try:
        client.connect(destination)
        for payload in (b'forward-one',b'forward-two-longer'):
            client.sendall(payload)
            assert client.recv(4096)==payload, 'wrong echo'
        success=True
    except (OSError,AssertionError):
        pass
    finally:
        client.close()
    assert success=={allowed}, ('source ACL or bidirectional forwarding mismatch',destination,kind,success)
"#,
        ipv6 = if ipv6 { "True" } else { "False" },
        allowed = if allowed { "True" } else { "False" },
    )
}

fn absolute_expiry_check(realm: &str, client: &str, peer: &str) {
    python(
        realm,
        r#"
import pathlib,os,signal
for path in pathlib.Path('/proc').glob('[0-9]*/status'):
    try:
        text=path.read_text()
        uid=int(next(line for line in text.splitlines() if line.startswith('Uid:')).split()[1])
        if text.splitlines()[0].split()[1]=='realm' and uid==60000:
            os.kill(int(path.parent.name),signal.SIGKILL)
    except (OSError,StopIteration): pass
"#,
        None,
    );
    docker(&["exec", realm, "mkdir", "-p", "/run/relaydeck-check"]);
    docker(&[
        "exec",
        realm,
        "cp",
        "/fixture/owner-1.json",
        "/run/relaydeck-check/realm.json",
    ]);
    docker(&[
        "exec",
        realm,
        "chmod",
        "0444",
        "/run/relaydeck-check/realm.json",
    ]);
    python(
        realm,
        r#"
import subprocess,pathlib,time
pathlib.Path('/run/relaydeck-check/authorization').write_text(str(int(time.time())+300))
pathlib.Path('/run/relaydeck-check/bind-ready').write_text('1')
result=subprocess.run(['setpriv','--reuid','60000','--regid','60000','--clear-groups','--no-new-privs','relaydeck','tenant','/usr/local/bin/realm','/run/relaydeck-check/realm.json','1','60000'],capture_output=True,timeout=3)
assert result.returncode!=0 and b'account has expired' in result.stderr, ('expired startup verification',result.stdout,result.stderr)
"#,
        None,
    );
    let expiry = docker(&[
        "exec",
        realm,
        "python3",
        "-c",
        "import time; print(int(time.time())+2)",
    ]);
    docker(&[
        "exec",
        "-d",
        realm,
        "setpriv",
        "--reuid",
        "60000",
        "--regid",
        "60000",
        "--clear-groups",
        "--no-new-privs",
        "relaydeck",
        "tenant",
        "/usr/local/bin/realm",
        "/run/relaydeck-check/realm.json",
        expiry.trim(),
        "60000",
    ]);
    python(
        realm,
        r#"
import subprocess,time
for _ in range(20):
    text=subprocess.check_output(['ss','-Hlnte'],text=True)
    if 'uid:60000' in text and ':41000' in text: break
    time.sleep(.03)
else: raise AssertionError('future tenant did not listen')
"#,
        None,
    );
    python(client, &echo_check(41000, true, false), None);
    python(
        client,
        r#"
import socket
client=socket.create_connection(('8.8.42.10',41000),timeout=1)
client.settimeout(4)
client.sendall(b'keep-open-until-expiry')
assert client.recv(4096)==b'keep-open-until-expiry'
try:
    assert client.recv(4096)==b'', 'unexpected data after expiry'
except (ConnectionResetError,BrokenPipeError):
    pass
finally:
    client.close()
"#,
        None,
    );
    python(
        realm,
        r#"
import pathlib,time
for _ in range(60):
    active=False
    for path in pathlib.Path('/proc').glob('[0-9]*/status'):
        try:
            text=path.read_text()
            uid=int(next(line for line in text.splitlines() if line.startswith('Uid:')).split()[1])
            # Docker's detached exec may leave reaped/zombie bookkeeping; only
            # a non-zombie tenant/realm can still own or serve sockets.
            state=next(line for line in text.splitlines() if line.startswith('State:')).split()[1]
            active=active or (uid==60000 and state!='Z')
        except (OSError,StopIteration): pass
    if not active: break
    time.sleep(.05)
else: raise AssertionError('absolute expiry left tenant/realm processes running')
"#,
        None,
    );
    let udp = docker(&["exec", realm, "ss", "-Hlnue"]);
    let tcp = docker(&["exec", realm, "ss", "-Hlnte"]);
    assert!(
        !udp.contains("uid:60000") && !tcp.contains("uid:60000"),
        "expired tenant still owns sockets"
    );
    python(peer, &echo_check(41010, true, false), None);
    println!(
        "Verified expired startup refusal and independent absolute two-second tenant expiry; the other account's forwarding remains alive."
    );
}

#[test]
#[ignore = "requires Docker, Debian package downloads, NET_ADMIN and isolated internal networks"]
fn realm_data_plane_enforces_dual_stack_acl_targets_and_account_uids() {
    let architecture = docker(&["version", "--format", "{{.Server.Arch}}"]);
    let (asset, checksum) = match architecture.trim() {
        "arm64" => (
            "realm-aarch64-unknown-linux-musl.tar.gz",
            "f4c0318dd86854da483dcb7645b4f39cae2cc3f91c688fef969d53220b949488",
        ),
        "amd64" => (
            "realm-x86_64-unknown-linux-musl.tar.gz",
            "b1cc335547bea8bb2a88178bef12ec7f2363e36200e7ea1d4e1e67627929bf65",
        ),
        other => panic!("unsupported Docker architecture: {other}"),
    };
    let directory = tempfile::tempdir().unwrap();
    let runtime_focus = std::env::var("RELAYDECK_LINUX_FOCUS").as_deref() == Ok("runtime");
    let runner = std::env::var_os("RELAYDECK_LINUX_RUNNER");
    if let Some(path) = &runner {
        assert!(
            std::path::Path::new(path).is_file(),
            "Linux runner artifact is missing"
        );
        fs::copy(path, directory.path().join("relaydeck-runner")).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // These fixtures contain no credentials and must be readable by the
        // deliberately unprivileged realm UIDs inside the read-only mount.
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let archive = directory.path().join("realm.tar.gz");
    let url = format!("https://github.com/zhboner/realm/releases/download/v2.9.6/{asset}");
    output(
        "curl",
        &[
            "--fail",
            "--location",
            "--max-time",
            "90",
            "--output",
            archive.to_str().unwrap(),
            &url,
        ],
    );
    assert_eq!(
        hex::encode(Sha256::digest(fs::read(&archive).unwrap())),
        checksum
    );
    output(
        "tar",
        &[
            "-xzf",
            archive.to_str().unwrap(),
            "-C",
            directory.path().to_str().unwrap(),
        ],
    );
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let image = format!("relaydeck-linux-check-{suffix}");
    let public = format!("relaydeck-public-{suffix}");
    let private = format!("relaydeck-private-{suffix}");
    let names: Vec<String> = ["backend", "realm", "alice", "bob"]
        .map(|name| format!("relaydeck-{name}-{suffix}"))
        .into();
    let _cleanup = Cleanup {
        containers: names.clone(),
        networks: vec![public.clone(), private.clone()],
        image: image.clone(),
    };
    let mut dockerfile = String::from(
        "FROM debian:bookworm-slim\nRUN apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 update && apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 install -y --no-install-recommends nftables python3 iproute2 util-linux ca-certificates && rm -rf /var/lib/apt/lists/*\nCOPY realm /usr/local/bin/realm\nRUN chmod 0755 /usr/local/bin/realm\n",
    );
    if runner.is_some() {
        dockerfile.push_str("COPY relaydeck-runner /usr/local/bin/relaydeck\nRUN chmod 0755 /usr/local/bin/relaydeck\n");
    }
    dockerfile.push_str("CMD [\"sleep\",\"infinity\"]\n");
    fs::write(directory.path().join("Dockerfile"), dockerfile).unwrap();
    docker(&["build", "--tag", &image, directory.path().to_str().unwrap()]);
    docker(&[
        "network",
        "create",
        "--internal",
        "--ipv6",
        "--subnet",
        "8.8.42.0/24",
        "--subnet",
        "2001:4860:42::/64",
        &public,
    ]);
    docker(&[
        "network",
        "create",
        "--internal",
        "--subnet",
        "172.30.55.0/24",
        &private,
    ]);
    let policy = BrokerPolicy {
        port_policy_version: 2,
        database: "/var/lib/relaydeck/relaydeck.db".into(),
        web_uid: 1000,
        web_gid: None,
        runtime_dir: "/run/relaydeck".into(),
        realm_binary: "/usr/local/bin/realm".into(),
        runner_binary: "/usr/local/bin/relaydeck".into(),
        allowed_port_start: 41000,
        allowed_port_end: 41019,
        reserved_ports: vec![41019],
        local_ips: vec![
            "8.8.42.10".parse().unwrap(),
            "2001:4860:42::10".parse().unwrap(),
            "172.30.55.10".parse().unwrap(),
        ],
        uid_start: 60000,
        max_owners: 2,
        socket_path: "/run/relaydeck/broker.sock".into(),
        authorization_ttl_secs: 120,
        limits: serde_json::Value::Null,
    };
    let boundary = ExecutorPolicy {
        reserved_ports: policy.reserved_ports.clone(),
        local_ips: policy.local_ips.clone(),
    };
    let plans: Vec<_> = [(1, 41000, "8.8.42.2", 3), (2, 41010, "2001:4860:42::2", 4)]
        .map(|(owner, port, target, client)| {
            DesiredPlan {
                traffic: None,
                owner_id: owner,
                revision: 1,
                enabled: true,
                expires_at: None,
                port_start: port,
                port_end: port + 9,
                max_rules: 1,
                rules: vec![DesiredRule {
                    id: owner,
                    listen_port: port,
                    target_ip: target.parse().unwrap(),
                    target_port: 8443,
                    protocol: Protocol::Both,
                    source_cidrs: vec![
                        format!("8.8.42.{client}/32"),
                        format!("2001:4860:42::{client}/128"),
                    ],
                    enabled: true,
                }],
            }
            .validate(&boundary, 100)
            .unwrap()
        })
        .into();
    for plan in &plans {
        fs::write(
            directory
                .path()
                .join(format!("owner-{}.json", plan.owner_id())),
            plan.realm_json().unwrap(),
        )
        .unwrap();
    }
    fs::write(
        directory.path().join("rules.nft"),
        render_nft(&policy, &plans, &[], 100).unwrap(),
    )
    .unwrap();
    fs::write(directory.path().join("server.py"), SERVER).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["owner-1.json", "owner-2.json", "server.py", "rules.nft"] {
            fs::set_permissions(
                directory.path().join(name),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
    }
    let mount = format!(
        "type=bind,src={},dst=/fixture,readonly",
        directory.path().display()
    );
    for (index, address) in [2, 10, 3, 4].into_iter().enumerate() {
        let ip = format!("8.8.42.{address}");
        let ip6 = format!("2001:4860:42::{address}");
        let mut arguments = vec![
            "run",
            "-d",
            "--name",
            &names[index],
            "--network",
            &public,
            "--ip",
            &ip,
            "--ip6",
            &ip6,
            "--mount",
            &mount,
        ];
        if index == 1 {
            arguments.extend(["--cap-add", "NET_ADMIN"]);
        }
        arguments.push(&image);
        docker(&arguments);
    }
    docker(&[
        "network",
        "connect",
        "--ip",
        "172.30.55.2",
        &private,
        &names[0],
    ]);
    docker(&[
        "network",
        "connect",
        "--ip",
        "172.30.55.10",
        &private,
        &names[1],
    ]);
    docker(&["exec", "-d", &names[0], "python3", "/fixture/server.py"]);
    docker(&[
        "exec",
        &names[1],
        "nft",
        "--check",
        "-f",
        "/fixture/rules.nft",
    ]);
    docker(&["exec", &names[1], "nft", "-f", "/fixture/rules.nft"]);
    for (owner, uid) in [(1, 60000), (2, 60001)] {
        let path = format!("/fixture/owner-{owner}.json");
        let uid = uid.to_string();
        docker(&[
            "exec",
            "-d",
            &names[1],
            "setpriv",
            "--reuid",
            &uid,
            "--regid",
            &uid,
            "--clear-groups",
            "--no-new-privs",
            "realm",
            "-c",
            &path,
        ]);
    }
    // Listener readiness is local inspection, without opening any public port.
    python(
        &names[1],
        "import subprocess,time\nfor _ in range(30):\n text=subprocess.check_output(['ss','-lnut'],text=True)\n if all(str(port) in text for port in (41000,41010)): break\n time.sleep(.1)\nelse: raise AssertionError('realm listener readiness failed')\n",
        None,
    );
    for ipv6 in [false, true] {
        python(&names[2], &echo_check(41000, true, ipv6), None);
        python(&names[3], &echo_check(41010, true, ipv6), None);
        if !runtime_focus {
            python(&names[3], &echo_check(41000, false, ipv6), None);
            python(&names[2], &echo_check(41010, false, ipv6), None);
        }
    }
    for plan in &plans {
        let uid = 60000 + plan.owner_id() - 1;
        let mut sockets = HashSet::new();
        for (protocol, flags) in [("tcp", "-Hlnte"), ("udp", "-Hlnue")] {
            let rows = docker(&["exec", &names[1], "ss", flags]);
            for row in rows.lines() {
                let fields: Vec<_> = row.split_whitespace().collect();
                if !fields.iter().any(|field| {
                    field
                        .strip_prefix("uid:")
                        .and_then(|value| value.parse::<i64>().ok())
                        == Some(uid)
                }) {
                    continue;
                }
                let port = fields[3]
                    .rsplit_once(':')
                    .unwrap()
                    .1
                    .parse::<u16>()
                    .unwrap();
                sockets.insert((protocol, port));
            }
        }
        validate_runtime_listeners(Some(plan), &sockets)
            .expect("readiness accepts actual upstream UDP sockets");
        assert!(
            sockets
                .iter()
                .filter(|(protocol, _)| *protocol == "udp")
                .count()
                > 1,
            "fixture must expose extra upstream UDP sockets"
        );
        println!("Post-traffic UID {uid} actual TCP/UDP socket ports: {sockets:?}");
    }
    // Control probes first prove the private fixture is reachable to root. The
    // same sockets as a forwarding UID must fail, while its numeric target works.
    for uid in if runtime_focus {
        Vec::new()
    } else {
        vec![None, Some(60000)]
    } {
        let allowed = if uid.is_none() { "True" } else { "False" };
        python(
            &names[1],
            &format!(
                "import socket\nfor kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):\n s=socket.socket(socket.AF_INET,kind);s.settimeout(1)\n success=False\n try:\n  s.connect(('172.30.55.2',8443));s.sendall(b'private');success=s.recv(4096)==b'private'\n except OSError: pass\n finally: s.close()\n assert success=={allowed},('private egress mismatch',kind,success)\n"
            ),
            uid,
        );
    }
    // UID 60000 cannot initiate traffic to UID 60001's approved IPv6 target.
    if !runtime_focus {
        python(
            &names[1],
            "import socket\nfor kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):\n s=socket.socket(socket.AF_INET6,kind);s.settimeout(1)\n try:\n  s.connect(('2001:4860:42::2',8443));s.sendall(b'cross-owner');s.recv(4096)\n except OSError: pass\n else: raise AssertionError('cross-owner egress succeeded')\n finally: s.close()\n",
            Some(60000),
        );
    }
    python(
        &names[1],
        "import pathlib\nuids=set()\nfor path in pathlib.Path('/proc').glob('[0-9]*/status'):\n try:\n  text=path.read_text()\n  if 'Name:\\trealm' not in text: continue\n  uids.add(int(next(line for line in text.splitlines() if line.startswith('Uid:')).split()[1]))\n except (OSError,StopIteration): pass\nassert {60000,60001}.issubset(uids),('dedicated UID mismatch',uids)\n",
        None,
    );
    if runner.is_some() {
        absolute_expiry_check(&names[1], &names[2], &names[3]);
    }
    if runtime_focus {
        println!(
            "Verified realm checksum, dual-stack roundtrips and actual UDP upstream-socket readiness. Systemd/cgroup deployment remains unverified."
        );
    } else {
        println!(
            "Verified realm 2.9.6 checksum, IPv4/IPv6 TCP+UDP roundtrips, source ACLs, private target denial and UID target isolation. Systemd/cgroup deployment remains unverified."
        );
    }
}
