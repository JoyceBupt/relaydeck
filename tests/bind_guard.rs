//! Opt-in kernel acceptance in an isolated cgroup namespace.
#![cfg(target_os = "linux")]

#[test]
#[ignore = "requires root, BPF capabilities, Python and an explicitly provided writable cgroup v2 parent"]
fn kernel_bind_guard_enforces_port_protocol_and_address_families() {
    use relaydeck::executor::{DesiredPlan, DesiredRule, ExecutorPolicy, Protocol};
    use std::{net::TcpListener, path::PathBuf, process::Command};

    let parent = PathBuf::from(
        std::env::var_os("RELAYDECK_BIND_TEST_CGROUP")
            .expect("provide a dedicated test cgroup parent"),
    );
    assert!(parent.starts_with("/sys/fs/cgroup"));
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let path = parent.join(format!("relaydeck-bind-test-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            std::fs::remove_dir(&self.0).expect("remove empty test cgroup");
        }
    }
    let cleanup = Cleanup(path.clone());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let plan = DesiredPlan {
        owner_id: 1,
        revision: 1,
        enabled: true,
        expires_at: None,
        port_start: port,
        port_end: port,
        max_rules: 1,
        rules: vec![DesiredRule {
            id: 1,
            listen_port: port,
            target_ip: "8.8.8.8".parse().unwrap(),
            target_port: 443,
            protocol: Protocol::Tcp,
            source_cidrs: vec![],
            enabled: true,
        }],
    }
    .validate(&ExecutorPolicy::default(), 1)
    .unwrap();
    let guard = relaydeck::bindguard::BindGuard::attach(&plan, &path).unwrap();
    let child = Command::new("python3")
        .args([
            "-c",
            r#"import errno,os,pathlib,socket,sys
pathlib.Path(sys.argv[1],'cgroup.procs').write_text(str(os.getpid()))
os.setgroups([]);os.setgid(60000);os.setuid(60000)
port=int(sys.argv[2]);wrong=port-1 if port>1 else port+1
for family,host in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
 for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
  for selected in (port,wrong,0):
   with socket.socket(family,kind) as sock:
    allowed=selected==0 or (selected==port and kind==socket.SOCK_STREAM)
    try:sock.bind((host,selected));assert allowed,(family,kind,selected)
    except OSError as error:assert not allowed and error.errno==errno.EPERM,(family,kind,selected,error)
"#,
        ])
        .arg(&path)
        .arg(port.to_string())
        .status()
        .unwrap();
    assert!(child.success());
    guard.verify(&path).unwrap();
    drop(guard);
    drop(cleanup);
}
