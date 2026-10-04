use relaydeck::traffic::{TrafficMode, kernel_values, utc_month};
use serde_json::json;
#[test]
fn monthly_reset_uses_utc_calendar_months_including_leap_years() {
    assert_eq!(utc_month(1709251199).unwrap(), (1706745600, 1709251200));
    assert_eq!(utc_month(1709251200).unwrap(), (1709251200, 1711929600));
    assert_eq!(utc_month(1735689600).unwrap(), (1735689600, 1738368000));
    assert!(utc_month(-1).is_err());
}
#[test]
fn direction_selects_one_client_leg_and_saturates_without_overflow() {
    assert_eq!(TrafficMode::Both.usage(30, 50), 80);
    assert_eq!(TrafficMode::Ingress.usage(30, 50), 30);
    assert_eq!(TrafficMode::Egress.usage(30, 50), 50);
    assert_eq!(TrafficMode::Both.usage(u64::MAX, 1), u64::MAX);
}
#[test]
fn dynamic_counts_do_not_weaken_integrity_checks_for_quota_limits() {
    let before = json!({"nftables":[{"quota":{"table":"relaydeck_usage","name":"q_1","bytes":1000,"used":1,"inv":true}},{"set":{"table":"relaydeck_usage","name":"blocked_1","type":"nf_proto","elem":[]}}]});
    let mut after = before.clone();
    after["nftables"][0]["quota"]["used"] = 1001.into();
    after["nftables"][1]["set"]["elem"] = json!(["ipv4", "ipv6"]);
    assert_eq!(
        relaydeck::linux::firewall_fingerprint(&before).unwrap(),
        relaydeck::linux::firewall_fingerprint(&after).unwrap()
    );
    after["nftables"][0]["quota"]["bytes"] = 2000.into();
    assert_ne!(
        relaydeck::linux::firewall_fingerprint(&before).unwrap(),
        relaydeck::linux::firewall_fingerprint(&after).unwrap()
    );
    assert_eq!(kernel_values(&before).unwrap()["q_1"], 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires isolated root Linux with nftables, quota module, iproute2 and Python"]
async fn traffic_kernel_enforcement_and_recovery() {
    use relaydeck::{
        executor::{DesiredPlan, DesiredRule, ExecutorPolicy, Protocol},
        linux::BrokerPolicy,
        traffic::{TrafficBudget, TrafficGrant, driver::TrafficMeter},
    };
    use std::sync::atomic::{AtomicI64, Ordering};
    if std::env::var("RELAYDECK_TRAFFIC_NAMESPACE").ok().as_deref() != Some("1") {
        assert!(
            std::process::Command::new("python3")
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/traffic_kernel.py"
                ))
                .arg(std::env::current_exe().unwrap())
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    static CLOCK: AtomicI64 = AtomicI64::new(0);
    fn clock() -> i64 {
        CLOCK.load(Ordering::Relaxed)
    }
    CLOCK.store(relaydeck::db::now(), Ordering::Relaxed);
    let root = tempfile::Builder::new()
        .prefix("relaydeck-traffic-")
        .tempdir_in("/run")
        .unwrap();
    let policy = BrokerPolicy {
        port_policy_version: 2,
        database: root.path().join("unused.db"),
        web_uid: 995,
        web_gid: None,
        runtime_dir: root.path().to_owned(),
        realm_binary: "/usr/local/libexec/realm".into(),
        runner_binary: "/usr/local/libexec/relaydeck".into(),
        allowed_port_start: 1024,
        allowed_port_end: 65535,
        reserved_ports: vec![22, 80, 443],
        local_ips: vec![],
        uid_start: 60000,
        max_owners: 11,
        socket_path: "/run/relaydeck/broker.sock".into(),
        authorization_ttl_secs: 120,
        limits: serde_json::Value::Null,
    };
    let make_grant = |owner, limit, mode| TrafficGrant {
        owner_id: owner,
        budget: TrafficBudget {
            limit_bytes: limit,
            mode,
        },
    };
    let mut grants = vec![
        make_grant(1, Some(2000), TrafficMode::Both),
        make_grant(2, None, TrafficMode::Both),
        make_grant(3, Some(1000), TrafficMode::Ingress),
    ];
    let plans = (1..=3)
        .map(|owner| {
            DesiredPlan {
                traffic: Some(grants[(owner - 1) as usize].budget.clone()),
                owner_id: owner,
                revision: 1,
                enabled: true,
                expires_at: None,
                port_start: 1024,
                port_end: 65535,
                max_rules: 10,
                rules: vec![DesiredRule {
                    id: owner,
                    listen_port: (40990 + owner * 10) as u16,
                    target_ip: "8.8.44.2".parse().unwrap(),
                    target_port: 443,
                    protocol: Protocol::Both,
                    source_cidrs: vec![],
                    enabled: true,
                }],
            }
            .validate(&ExecutorPolicy::default(), clock())
            .unwrap()
        })
        .collect::<Vec<_>>();
    let client = std::env::var("RELAYDECK_TRAFFIC_CLIENT").unwrap();
    let probe = |port: u16, size: usize| {
        let program = "import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.4);b=b'x'*int(sys.argv[2]);s.sendto(b,('8.8.45.1',int(sys.argv[1])));\ntry:\n r=s.recv(4096);print('ok' if r==b else 'bad')\nexcept OSError:print('blocked')";
        let output = std::process::Command::new("ip")
            .args([
                "netns",
                "exec",
                &client,
                "python3",
                "-c",
                program,
                &port.to_string(),
                &size.to_string(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    let mut meter = TrafficMeter::open_with_clock(policy.clone(), clock).unwrap();
    assert!(
        meter
            .synchronize(&grants)
            .await
            .unwrap()
            .iter()
            .all(|row| row.ready)
    );
    meter.update_routes(plans.clone(), vec![]).await.unwrap();
    assert_eq!(probe(41000, 600), "ok");
    assert_eq!(probe(41000, 600), "blocked");
    assert_eq!(probe(41010, 600), "ok");
    let rows = meter.synchronize(&grants).await.unwrap();
    let first = rows.iter().find(|row| row.owner_id == 1).unwrap();
    assert!(first.blocked);
    let used = first.used_bytes;
    assert!(used >= 2000);
    // Route replacement and a broker restart preserve the current month.
    meter.update_routes(plans.clone(), vec![]).await.unwrap();
    assert_eq!(
        meter.synchronize(&grants).await.unwrap()[0].used_bytes,
        used
    );
    drop(meter);
    let mut meter = TrafficMeter::open_with_clock(policy.clone(), clock).unwrap();
    meter.synchronize(&grants).await.unwrap();
    meter.update_routes(plans.clone(), vec![]).await.unwrap();
    assert_eq!(probe(41000, 100), "blocked");
    assert!(meter.synchronize(&grants).await.unwrap()[0].used_bytes >= used);
    grants[0].budget.limit_bytes = Some(5000);
    meter.synchronize(&grants).await.unwrap();
    assert_eq!(probe(41000, 200), "ok");
    assert!(meter.synchronize(&grants).await.unwrap()[0].used_bytes > used);
    assert_eq!(probe(41020, 600), "ok");
    assert_eq!(probe(41020, 600), "blocked");
    let rows = meter.synchronize(&grants).await.unwrap();
    assert!(rows[2].blocked);
    assert_eq!(rows[2].used_bytes, rows[2].in_bytes);
    assert!(rows[2].out_bytes > 0);
    // A monthly transition restores traffic without toggling the forwarding rules.
    CLOCK.store(rows[0].reset_at + 1, Ordering::Relaxed);
    let ledger = root.path().join("traffic-ledger.json");
    let backup = root.path().join("traffic-ledger.before-rollover");
    std::fs::rename(&ledger, &backup).unwrap();
    std::fs::create_dir(&ledger).unwrap();
    assert!(meter.check_month().await.is_err());
    assert!(!meter.authorized(1, Some(&grants[0].budget)));
    std::fs::remove_dir(&ledger).unwrap();
    std::fs::rename(&backup, &ledger).unwrap();
    meter.check_month().await.unwrap();
    let rows = meter.synchronize(&grants).await.unwrap();
    assert!(rows.iter().all(|row| !row.blocked && row.used_bytes == 0));
    assert_eq!(probe(41000, 200), "ok");
    assert_eq!(probe(41020, 200), "ok");
    // Changing to egress counts outgoing traffic already measured in this month.
    grants[2].budget.mode = TrafficMode::Egress;
    grants[2].budget.limit_bytes = Some(500);
    meter.synchronize(&grants).await.unwrap();
    assert_eq!(probe(41020, 200), "ok");
    assert_eq!(probe(41020, 200), "blocked");
    let rows = meter.synchronize(&grants).await.unwrap();
    assert!(rows[2].blocked);
    assert_eq!(rows[2].used_bytes, rows[2].out_bytes);
    assert_eq!(probe(41010, 200), "ok");
    println!(
        "Kernel direction quotas, isolation, rule updates, restart, budget changes and monthly reset passed"
    );
}
