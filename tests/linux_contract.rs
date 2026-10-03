use std::net::IpAddr;

use relaydeck::{
    executor::{DesiredPlan, DesiredRule, ExecutorPolicy, Protocol},
    linux::{BrokerPolicy, render_nft, render_systemd},
};

fn policy() -> BrokerPolicy {
    BrokerPolicy {
        database: "/var/lib/relaydeck/relaydeck.db".into(),
        web_uid: 999,
        web_gid: None,
        runtime_dir: "/var/lib/relaydeck-runtime".into(),
        realm_binary: "/usr/local/libexec/realm".into(),
        runner_binary: "/usr/local/libexec/relaydeck".into(),
        allowed_port_start: 40000,
        allowed_port_end: 42000,
        reserved_ports: vec![40100],
        local_ips: vec!["8.8.4.4".parse().unwrap()],
        uid_start: 60000,
        max_owners: 11,
        socket_path: "/run/relaydeck/broker.sock".into(),
        authorization_ttl_secs: 120,
        limits: relaydeck::linux::ResourceLimits::default(),
    }
}

#[test]
fn unrelated_managed_port_listeners_are_rejected_before_firewall_changes() {
    use relaydeck::linux::validate_listener_inventory;
    assert!(
        validate_listener_inventory(&policy(), "LISTEN 0 128 0.0.0.0:41000 0.0.0.0:* ino:1")
            .is_err()
    );
    assert!(
        validate_listener_inventory(&policy(), "UNCONN 0 0 [::]:41000 [::]:* uid:1000 ino:1")
            .is_err()
    );
    assert!(
        validate_listener_inventory(&policy(), "LISTEN 0 128 [::]:41000 [::]:* uid:60000 ino:1")
            .is_ok()
    );
    assert!(
        validate_listener_inventory(&policy(), "LISTEN 0 128 0.0.0.0:40100 0.0.0.0:* ino:1")
            .is_ok()
    );
    assert!(
        validate_listener_inventory(&policy(), "LISTEN 0 128 127.0.0.1:7410 0.0.0.0:* ino:1")
            .is_ok()
    );
}

fn plan(
    owner: i64,
    port: u16,
    target: IpAddr,
    sources: Vec<String>,
) -> relaydeck::executor::RuntimePlan {
    DesiredPlan {
        owner_id: owner,
        revision: 2,
        enabled: true,
        expires_at: Some(2000),
        port_start: port,
        port_end: port + 9,
        max_rules: 3,
        rules: vec![DesiredRule {
            id: 1,
            listen_port: port,
            target_ip: target,
            target_port: 443,
            protocol: Protocol::Both,
            source_cidrs: sources,
            enabled: true,
        }],
    }
    .validate(&ExecutorPolicy::default(), 1000)
    .unwrap()
}

#[test]
fn systemd_has_fixed_nonroot_identity_expiry_and_limits() {
    let policy = policy();
    let plan = plan(2, 41000, "1.1.1.1".parse().unwrap(), vec![]);
    let unit = render_systemd(&policy, &plan, 1500).unwrap();
    for required in [
        "User=60001\n",
        "Group=60001\n",
        "Restart=no\n",
        "RuntimeMaxSec=500s\n",
        "KillMode=control-group\n",
        "NoNewPrivileges=yes\n",
        "CapabilityBoundingSet=\n",
        "MemoryMax=64M\n",
        "TasksMax=16\n",
        "SocketBindDeny=any\n",
        "SocketBindAllow=tcp:41000\n",
        "SocketBindAllow=udp:41000\n",
        "ExecStart=/usr/local/libexec/relaydeck tenant /usr/local/libexec/realm /var/lib/relaydeck-runtime/owner-2/realm.json 2000 60001 2\n",
        "Slice=relaydeck.slice\n",
    ] {
        assert!(unit.contains(required), "missing {required}");
    }
    assert!(!unit.contains("/bin/sh"));
    assert!(render_systemd(&policy, &plan, 2000).is_err());
}

#[test]
fn configurable_resource_limits_and_counter_updates_preserve_policy_checks() {
    let mut policy = policy();
    policy.limits.nofile = 4096;
    policy.limits.memory_max_mb = 256;
    policy.limits.memory_high_mb = 128;
    policy.limits.cpu_percent = 50;
    let unit = render_systemd(
        &policy,
        &plan(1, 41000, "8.8.8.8".parse().unwrap(), vec![]),
        1000,
    )
    .unwrap();
    for expected in [
        "LimitNOFILE=4096",
        "MemoryMax=256M",
        "MemoryHigh=128M",
        "CPUQuota=50%",
    ] {
        assert!(unit.contains(expected));
    }
    let original = serde_json::json!({"nftables":[{"rule":{"expr":[{"counter":{"packets":1,"bytes":100}},{"accept":null}]}}]});
    let mut counted = original.clone();
    counted["nftables"][0]["rule"]["expr"][0]["counter"]["bytes"] = serde_json::json!(1000);
    assert_eq!(
        relaydeck::linux::firewall_fingerprint(&original).unwrap(),
        relaydeck::linux::firewall_fingerprint(&counted).unwrap()
    );
    counted["nftables"][0]["rule"]["expr"][1] = serde_json::json!({"drop":null});
    assert_ne!(
        relaydeck::linux::firewall_fingerprint(&original).unwrap(),
        relaydeck::linux::firewall_fingerprint(&counted).unwrap()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn fixed_system_tool_aliases_resolve_only_to_immutable_root_executables() {
    if std::path::Path::new("/usr/sbin/ip").exists() {
        let target = relaydeck::linux::system_tool(std::path::Path::new("/usr/sbin/ip")).unwrap();
        assert!(target.is_file());
    }
    assert!(relaydeck::linux::system_tool(std::path::Path::new("/tmp/ip")).is_err());
}

#[test]
fn nft_preserves_scoped_client_replies_and_never_flushes_host_rules() {
    let nft = render_nft(
        &policy(),
        &[plan(
            1,
            41000,
            "1.1.1.1".parse().unwrap(),
            vec!["10.0.0.0/8".into()],
        )],
        &[],
        1000,
    )
    .unwrap();
    assert!(!nft.contains("flush ruleset"));
    assert!(nft.contains("flush table inet relaydeck\n"));
    assert!(nft.contains("type filter hook output priority -10; policy accept"));
    assert!(nft.contains("meta skuid 60000 jump owner_1"));
    assert!(nft.contains("tcp dport 41000 ip saddr 10.0.0.0/8 return"));
    let account = nft
        .split("chain owner_1 {")
        .nth(1)
        .unwrap()
        .split("chain owner_2 {")
        .next()
        .unwrap();
    let reply = account
        .find("ct direction reply tcp sport 41000 ct original proto-dst 41000 return")
        .unwrap();
    let local_block = account.find("fib daddr type local drop").unwrap();
    let tuple = account
        .find("ct direction original ip daddr 1.1.1.1 tcp dport 443 return")
        .unwrap();
    assert!(reply < local_block && local_block < tuple);
    assert!(!nft.contains("ct state established"));
    assert!(nft.contains("elements = { 40000-40099, 40101-42000 }"));
}

#[test]
fn root_ceiling_local_interfaces_and_cross_account_collisions_are_rechecked() {
    let first = plan(1, 41000, "1.1.1.1".parse().unwrap(), vec![]);
    assert!(
        render_nft(
            &policy(),
            std::slice::from_ref(&first),
            &["1.1.1.1".parse().unwrap()],
            1000
        )
        .is_err()
    );
    assert!(
        render_nft(
            &policy(),
            &[first, plan(2, 41000, "8.8.8.8".parse().unwrap(), vec![])],
            &[],
            1000
        )
        .is_err()
    );
    assert!(
        render_nft(
            &policy(),
            &[plan(1, 43000, "1.1.1.1".parse().unwrap(), vec![])],
            &[],
            1000
        )
        .is_err()
    );
    assert!(
        render_nft(
            &policy(),
            &[plan(12, 41000, "1.1.1.1".parse().unwrap(), vec![])],
            &[],
            1000
        )
        .is_err()
    );
}

#[test]
fn expired_snapshots_and_empty_runtime_leave_default_drop_uid_chains() {
    let nft = render_nft(
        &policy(),
        &[plan(1, 41000, "1.1.1.1".parse().unwrap(), vec![])],
        &[],
        2000,
    )
    .unwrap();
    assert!(!nft.contains("daddr 1.1.1.1"));
    assert!(!nft.contains("sport 41000"));
    assert!(
        nft.contains("chain owner_1 {\n  ct state invalid drop\n  fib daddr type local drop\n")
    );
    let empty = render_nft(&policy(), &[], &[], 1000).unwrap();
    assert!(empty.contains("chain owner_1 {\n  ct state invalid drop\n  drop\n }"));
}

#[test]
fn broker_policy_rejects_path_grammar_uid_and_port_escalations() {
    let mut value = policy();
    assert!(value.validate().is_ok());
    value.web_uid = 0;
    assert!(value.validate().is_err());
    value = policy();
    value.runtime_dir = "/var/lib/../../etc".into();
    assert!(value.validate().is_err());
    value = policy();
    value.realm_binary = "/usr/bin/realm --hook=exec".into();
    assert!(value.validate().is_err());
    value = policy();
    value.uid_start = 0;
    assert!(value.validate().is_err());
    value = policy();
    value.max_owners = 1000;
    assert!(value.validate().is_err());
    value = policy();
    value.allowed_port_start = 22;
    assert!(value.validate().is_err());
}

#[tokio::test]
async fn process_stop_is_attempted_when_firewall_blocking_fails() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let stopped = Arc::new(AtomicBool::new(false));
    let marker = stopped.clone();
    let result = relaydeck::linux::fail_closed_cleanup(
        async { Err(anyhow::anyhow!("nft table disappeared")) },
        async move {
            marker.store(true, Ordering::SeqCst);
            Ok(())
        },
    )
    .await;
    assert!(stopped.load(Ordering::SeqCst));
    assert!(result.unwrap_err().to_string().contains("runtime stopped"));
}

#[tokio::test]
async fn cleanup_reports_network_and_process_failures_without_false_success() {
    let result = relaydeck::linux::fail_closed_cleanup(
        async { Err(anyhow::anyhow!("missing ip tool")) },
        async { Err(anyhow::anyhow!("systemd stop failed")) },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(result.contains("missing ip tool") && result.contains("systemd stop failed"));
}

#[test]
fn udp_readiness_accepts_ephemeral_upstream_sockets_but_stop_requires_none() {
    use relaydeck::linux::validate_runtime_listeners;
    use std::collections::HashSet;
    let plan = plan(1, 41000, "1.1.1.1".parse().unwrap(), vec![]);
    let after_traffic = HashSet::from([
        ("tcp", 41000),
        ("udp", 41000),
        ("udp", 52001),
        ("udp", 52002),
    ]);
    assert!(validate_runtime_listeners(Some(&plan), &after_traffic).is_ok());
    assert!(validate_runtime_listeners(None, &after_traffic).is_err());
    let missing_entry = HashSet::from([("tcp", 41000), ("udp", 52001)]);
    assert!(validate_runtime_listeners(Some(&plan), &missing_entry).is_err());
    let extra_tcp = HashSet::from([("tcp", 41000), ("tcp", 52001), ("udp", 41000)]);
    assert!(validate_runtime_listeners(Some(&plan), &extra_tcp).is_err());
    assert!(validate_runtime_listeners(None, &HashSet::new()).is_ok());
}
