use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, process::Command, sync::Mutex};

use crate::{
    db::now,
    executor::{DriverError, DriverFuture, ExecutorDriver, ExecutorPolicy, Protocol, RuntimePlan},
};

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const NFT: &str = "/usr/sbin/nft";
const SS: &str = "/usr/bin/ss";
const IP: &str = "/usr/sbin/ip";
#[cfg(target_os = "linux")]
const WG: &str = "/usr/bin/wg";
const UNIT_DIR: &str = "/run/systemd/system";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(4);

pub fn firewall_fingerprint(value: &serde_json::Value) -> Result<Vec<u8>, serde_json::Error> {
    fn normalize(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::Object(counter)) = map.get_mut("counter") {
                    for name in ["bytes", "packets"] {
                        if counter.contains_key(name) {
                            counter.insert(name.into(), 0.into());
                        }
                    }
                }
                for value in map.values_mut() {
                    normalize(value);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    normalize(value);
                }
            }
            _ => (),
        }
    }
    let mut value = value.clone();
    normalize(&mut value);
    serde_json::to_vec(&value)
}

#[derive(Debug, thiserror::Error)]
#[error("realm process exited")]
struct RuntimeExited;

pub async fn fail_closed_cleanup<B, S>(block: B, stop: S) -> anyhow::Result<()>
where
    B: std::future::Future<Output = anyhow::Result<()>>,
    S: std::future::Future<Output = anyhow::Result<()>>,
{
    // Firewall failures, including a vanished table or missing interface data,
    // must never prevent the independent process stop from being attempted.
    let blocked = tokio::time::timeout(Duration::from_secs(10), block)
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("network blocking timed out")));
    let stopped = stop.await;
    match (blocked, stopped) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error.context("network blocking failed; runtime stopped")),
        (Ok(()), Err(error)) => Err(error.context("network blocked; runtime stop failed")),
        (Err(block), Err(stop)) => Err(anyhow::anyhow!(
            "network blocking failed: {block}; runtime stop failed: {stop}"
        )),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerPolicy {
    #[serde(default = "legacy_port_policy_version")]
    pub port_policy_version: u32,
    pub database: PathBuf,
    pub web_uid: u32,
    #[serde(default)]
    pub web_gid: Option<u32>,
    pub runtime_dir: PathBuf,
    pub realm_binary: PathBuf,
    pub runner_binary: PathBuf,
    pub allowed_port_start: u16,
    pub allowed_port_end: u16,
    pub reserved_ports: Vec<u16>,
    pub local_ips: Vec<IpAddr>,
    pub uid_start: u32,
    pub max_owners: u32,
    #[serde(default = "default_socket")]
    pub socket_path: PathBuf,
    #[serde(default = "default_authorization_ttl")]
    pub authorization_ttl_secs: u64,
    #[serde(default)]
    pub limits: ResourceLimits,
}

fn legacy_port_policy_version() -> u32 {
    1
}

fn default_socket() -> PathBuf {
    "/run/relaydeck/broker.sock".into()
}
fn default_authorization_ttl() -> u64 {
    120
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceLimits {
    pub memory_high_mb: u64,
    pub memory_max_mb: u64,
    pub tasks: u32,
    pub cpu_percent: u32,
    pub nofile: u32,
    pub total_memory_mb: u64,
    pub total_cpu_percent: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_high_mb: 32,
            memory_max_mb: 64,
            tasks: 96,
            cpu_percent: 20,
            nofile: 512,
            total_memory_mb: 384,
            total_cpu_percent: 150,
        }
    }
}

impl BrokerPolicy {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            matches!(self.port_policy_version, 1 | 2),
            "unsupported port policy version"
        );
        ensure!(self.web_uid != 0, "web_uid must not be root");
        ensure!(self.web_gid != Some(0), "web_gid must not be root");
        ensure!(
            (30..=300).contains(&self.authorization_ttl_secs),
            "authorization TTL must be 30..300 seconds"
        );
        validate_absolute_path(&self.socket_path)?;
        ensure!(
            self.socket_path
                .file_name()
                .is_some_and(|name| name == "broker.sock"),
            "broker socket must use its fixed name"
        );
        let limits = &self.limits;
        ensure!(
            limits.memory_high_mb >= 16
                && limits.memory_high_mb <= limits.memory_max_mb
                && limits.memory_max_mb <= 4096,
            "invalid memory limits"
        );
        ensure!(
            (64..=256).contains(&limits.tasks)
                && (128..=65536).contains(&limits.nofile)
                && (1..=800).contains(&limits.cpu_percent),
            "invalid tenant limits: tasks must be 64..256 for the per-rule supervisor"
        );
        ensure!(
            limits.total_memory_mb >= limits.memory_max_mb
                && limits.total_memory_mb <= 65536
                && (1..=1600).contains(&limits.total_cpu_percent),
            "invalid aggregate limits"
        );
        ensure!(
            self.allowed_port_start >= 1024 && self.allowed_port_end >= self.allowed_port_start,
            "invalid global port boundary"
        );
        ensure!(
            (1..=11).contains(&self.max_owners),
            "max_owners must be 1..11"
        );
        ensure!(
            self.uid_start >= 60000 && self.uid_start.checked_add(self.max_owners).is_some(),
            "invalid dedicated UID boundary"
        );
        ensure!(
            self.web_uid < self.uid_start || self.web_uid >= self.uid_start + self.max_owners,
            "Web UID overlaps runtime UID pool"
        );
        for path in [
            &self.database,
            &self.runtime_dir,
            &self.realm_binary,
            &self.runner_binary,
        ] {
            validate_absolute_path(path)?;
            ensure!(path != Path::new("/"), "root is not a runtime path");
        }
        ensure!(
            self.database
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".db")),
            "database must end in .db"
        );
        // These strings enter systemd's ExecStart grammar. Restrict root policy
        // paths as well as rejecting untrusted runtime identifiers.
        for path in [&self.runtime_dir, &self.realm_binary, &self.runner_binary] {
            ensure!(
                path.as_os_str().to_str().is_some_and(|value| value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric()
                        || matches!(byte, b'/' | b'_' | b'-' | b'.'))),
                "runtime paths must contain only plain ASCII path characters"
            );
        }
        Ok(())
    }

    pub(crate) fn uid(&self, owner_id: i64) -> anyhow::Result<u32> {
        ensure!(
            owner_id > 0 && owner_id <= i64::from(self.max_owners),
            "owner exceeds dedicated UID pool"
        );
        Ok(self.uid_start + (owner_id as u32) - 1)
    }

    pub(crate) fn boundary(&self, local_ips: Vec<IpAddr>) -> ExecutorPolicy {
        let mut reserved_ports = self.reserved_ports.clone();
        reserved_ports.extend([22, 80, 443]);
        reserved_ports.sort_unstable();
        reserved_ports.dedup();
        ExecutorPolicy {
            reserved_ports,
            local_ips,
        }
    }
}

/// Old panel updaters keep executing their already-imported Python module.
/// Preparing the new policy in ExecStartPre also covers that first upgrade;
/// the original policy stays usable by the old units during rollback.
pub fn prepare_broker_policy(source: &Path, destination: &Path) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source, destination);
        anyhow::bail!("broker policy preparation requires Linux root");
    }
    #[cfg(target_os = "linux")]
    {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "policy preparation requires root"
        );
        secure_root_path(source, false)?;
        ensure!(
            std::fs::metadata(source)?.len() <= 16 * 1024,
            "broker policy too large"
        );
        let mut policy: BrokerPolicy = serde_json::from_slice(&std::fs::read(source)?)?;
        policy.validate()?;
        ensure!(
            destination == policy.runtime_dir.join("broker-effective.json")
                && source != destination,
            "effective policy must use its dedicated runtime path"
        );
        match std::fs::symlink_metadata(destination) {
            Ok(_) => secure_root_path(destination, false)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        if policy.port_policy_version == 1 {
            policy.allowed_port_start = 1024;
            policy.allowed_port_end = 65535;
            policy.port_policy_version = 2;
        }
        policy.validate()?;
        let bytes = serde_json::to_vec(&policy)?;
        ensure!(
            bytes.len() <= 16 * 1024,
            "effective broker policy too large"
        );
        write_root_file(destination, &bytes, 0o644, 0)
    }
}

fn validate_absolute_path(path: &Path) -> anyhow::Result<()> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "paths must be absolute and contain no parent traversal"
    );
    ensure!(
        !path.as_os_str().as_encoded_bytes().contains(&0),
        "invalid path"
    );
    Ok(())
}

pub fn render_systemd(
    policy: &BrokerPolicy,
    plan: &RuntimePlan,
    timestamp: i64,
) -> anyhow::Result<String> {
    policy.validate()?;
    let uid = policy.uid(plan.owner_id())?;
    ensure!(!plan.stopped(), "cannot render a stopped runtime");
    let lifetime = match plan.expires_at() {
        Some(expiry) => {
            ensure!(expiry > timestamp, "account has expired");
            format!("{}s", expiry - timestamp)
        }
        None => "infinity".to_owned(),
    };
    let config = policy
        .runtime_dir
        .join(format!("owner-{}/plan.json", plan.owner_id()));
    let mut unit = format!(
        "[Unit]\nDescription=RelayDeck account {}\n\n[Service]\nType=exec\nUser={uid}\nGroup={uid}\nExecStart={} tenant-plan {} {} {} {uid} {revision}\nRestart=no\nRuntimeMaxSec={lifetime}\nKillMode=control-group\nTimeoutStartSec=5s\nTimeoutStopSec=3s\nSendSIGKILL=yes\nUMask=0077\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nRestrictSUIDSGID=yes\nRestrictRealtime=yes\nLockPersonality=yes\nRestrictAddressFamilies=AF_INET AF_INET6\nSystemCallArchitectures=native\nMemoryHigh={memory_high}M\nMemoryMax={memory_max}M\nMemorySwapMax=0\nTasksMax={tasks}\nCPUQuota={cpu}%\nLimitNOFILE={nofile}\nLimitCORE=0\nSocketBindDeny=any\n",
        plan.owner_id(),
        policy.runner_binary.display(),
        policy.realm_binary.display(),
        config.display(),
        plan.expires_at().unwrap_or(0),
        memory_high = policy.limits.memory_high_mb,
        memory_max = policy.limits.memory_max_mb,
        tasks = policy.limits.tasks,
        cpu = policy.limits.cpu_percent,
        nofile = policy.limits.nofile,
        revision = plan.revision(),
    );
    // The optional systemd guard covers the shared root boundary. The mandatory
    // independent BPF guard restricts binds to this account's exact active rules.
    for protocol in ["tcp", "udp"] {
        unit.push_str(&format!(
            "SocketBindAllow={protocol}:{}-{}\n",
            policy.allowed_port_start, policy.allowed_port_end
        ));
    }
    unit.push_str(&format!(
        "ReadWritePaths={}\n",
        policy
            .runtime_dir
            .join(format!("owner-{}/applied-revision", plan.owner_id()))
            .display()
    ));
    unit.push_str("Slice=relaydeck.slice\n");
    Ok(unit)
}

pub fn render_nft(
    policy: &BrokerPolicy,
    plans: &[RuntimePlan],
    local_ips: &[IpAddr],
    timestamp: i64,
) -> anyhow::Result<String> {
    render_nft_with_listeners(policy, plans, local_ips, timestamp, &[])
}

// Kernel-owned tenant sockets remain guarded even after a failed stop or broker
// restart. Keep protocols separate: a UDP upstream port must not block an
// unrelated TCP service using the same number.
pub fn render_nft_with_listeners(
    policy: &BrokerPolicy,
    plans: &[RuntimePlan],
    local_ips: &[IpAddr],
    timestamp: i64,
    listeners: &[(Protocol, u16)],
) -> anyhow::Result<String> {
    render_nft_with_tunnels(policy, plans, local_ips, timestamp, listeners, &[])
}

/// The encrypted outer packet can retain the original application's socket UID.
/// Only root-owned kernel WireGuard peers with a nonzero, privileged socket mark
/// may bypass a second application-target check. Inner packets remain checked.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WireguardPeer {
    pub mark: u32,
    pub endpoint: std::net::SocketAddr,
}

pub fn parse_wireguard_peers(marks: &str, endpoints: &str) -> anyhow::Result<Vec<WireguardPeer>> {
    ensure!(
        marks.len() <= 16 * 1024 && endpoints.len() <= 64 * 1024,
        "WireGuard inventory too large"
    );
    let mut interfaces = BTreeMap::new();
    for line in marks.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(fields.len() == 2, "invalid WireGuard mark inventory");
        let mark = if fields[1] == "off" {
            0
        } else {
            u32::from_str_radix(
                fields[1]
                    .strip_prefix("0x")
                    .context("invalid WireGuard mark")?,
                16,
            )?
        };
        ensure!(
            interfaces.insert(fields[0], mark).is_none(),
            "duplicate WireGuard interface"
        );
    }
    let mut peers = std::collections::BTreeSet::new();
    for line in endpoints.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(fields.len() == 3, "invalid WireGuard endpoint inventory");
        let mark = *interfaces
            .get(fields[0])
            .context("WireGuard interface changed during inventory")?;
        if mark == 0 || fields[2] == "(none)" {
            continue;
        }
        let endpoint: std::net::SocketAddr = fields[2].parse()?;
        ensure!(
            endpoint.port() != 0
                && !endpoint.ip().is_unspecified()
                && !endpoint.ip().is_multicast(),
            "invalid WireGuard peer address"
        );
        peers.insert(WireguardPeer { mark, endpoint });
        ensure!(peers.len() <= 64, "too many WireGuard peers");
    }
    Ok(peers.into_iter().collect())
}

#[cfg(target_os = "linux")]
async fn wireguard_peers() -> anyhow::Result<Vec<WireguardPeer>> {
    match std::fs::symlink_metadata(WG) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
        Ok(_) => {
            system_tool(Path::new(WG))?;
        }
    }
    // Never use `dump` or `showconf`, both of which expose private keys.
    let marks = command(WG, &["show", "all", "fwmark"], None).await?;
    let endpoints = command(WG, &["show", "all", "endpoints"], None).await?;
    parse_wireguard_peers(
        std::str::from_utf8(&marks)?,
        std::str::from_utf8(&endpoints)?,
    )
}

#[cfg(not(target_os = "linux"))]
async fn wireguard_peers() -> anyhow::Result<Vec<WireguardPeer>> {
    Ok(Vec::new())
}

pub fn render_nft_with_tunnels(
    policy: &BrokerPolicy,
    plans: &[RuntimePlan],
    local_ips: &[IpAddr],
    timestamp: i64,
    listeners: &[(Protocol, u16)],
    peers: &[WireguardPeer],
) -> anyhow::Result<String> {
    policy.validate()?;
    let mut boundary_ips = policy.local_ips.clone();
    boundary_ips.extend_from_slice(local_ips);
    let boundary = policy.boundary(boundary_ips);
    let mut validated = BTreeMap::new();
    let mut ports = HashSet::new();
    for raw in plans {
        policy.uid(raw.owner_id())?;
        let plan = raw.validate_again(&boundary, timestamp)?;
        ensure!(
            plan.rules()
                .iter()
                .all(|rule| (policy.allowed_port_start..=policy.allowed_port_end)
                    .contains(&rule.listen_port)),
            "account grant exceeds root global port boundary"
        );
        for rule in plan.rules() {
            ensure!(
                ports.insert(rule.listen_port),
                "cross-account listener collision"
            );
        }
        ensure!(
            validated.insert(plan.owner_id(), plan).is_none(),
            "duplicate runtime owner"
        );
    }
    // add+flush only this fixed table, in a single nft transaction. Never flush
    // the host ruleset, and never depend on an accept overriding another table.
    let mut rules = String::from(
        "add table inet relaydeck\nflush table inet relaydeck\ntable inet relaydeck {\n",
    );
    let mut managed = BTreeMap::new();
    for (protocol, tcp) in [("tcp", true), ("udp", false)] {
        let mut claimed = std::collections::BTreeSet::new();
        for plan in validated.values() {
            for rule in plan.rules() {
                if (tcp && rule.protocol.tcp()) || (!tcp && rule.protocol.udp()) {
                    claimed.insert(rule.listen_port);
                }
            }
        }
        for (kind, port) in listeners {
            ensure!(*port > 0, "invalid kernel listener port");
            if (tcp && kind.tcp()) || (!tcp && kind.udp()) {
                claimed.insert(*port);
            }
        }
        if !claimed.is_empty() {
            let values = claimed
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            rules.push_str(&format!(" set managed_{protocol}_ports {{ type inet_service; elements = {{ {values} }}; }}\n"));
        }
        managed.insert(protocol, !claimed.is_empty());
    }
    rules.push_str(" chain ingress {\n");
    for plan in validated.values() {
        for rule in plan.rules() {
            for protocol in ["tcp", "udp"] {
                if (protocol == "tcp" && !rule.protocol.tcp())
                    || (protocol == "udp" && !rule.protocol.udp())
                {
                    continue;
                }
                if rule.source_cidrs.is_empty() {
                    rules.push_str(&format!("  {protocol} dport {} return\n", rule.listen_port));
                } else {
                    for cidr in &rule.source_cidrs {
                        let network: ipnet::IpNet = cidr.parse()?;
                        let family = if matches!(network, ipnet::IpNet::V4(_)) {
                            "ip"
                        } else {
                            "ip6"
                        };
                        rules.push_str(&format!(
                            "  {protocol} dport {} {family} saddr {network} return\n",
                            rule.listen_port
                        ));
                    }
                }
            }
        }
    }
    rules.push_str("  drop\n }\n chain input { type filter hook input priority -10; policy accept;\n  ct direction reply return\n");
    for protocol in ["tcp", "udp"] {
        if managed[protocol] {
            rules.push_str(&format!(
                "  {protocol} dport @managed_{protocol}_ports jump ingress\n"
            ));
        }
    }
    rules.push_str(" }\n");
    for owner_id in 1..=i64::from(policy.max_owners) {
        rules.push_str(&format!(
            " chain owner_{owner_id} {{\n  ct state invalid drop\n"
        ));
        if let Some(plan) = validated.get(&owner_id) {
            for rule in plan.rules() {
                for protocol in ["tcp", "udp"] {
                    if (protocol == "tcp" && !rule.protocol.tcp())
                        || (protocol == "udp" && !rule.protocol.udp())
                    {
                        continue;
                    }
                    rules.push_str(&format!("  ct direction reply {protocol} sport {} ct original proto-dst {} return\n", rule.listen_port, rule.listen_port));
                }
            }
            rules.push_str("  fib daddr type local drop\n");
            for address in &boundary.local_ips {
                let family = if address.is_ipv4() { "ip" } else { "ip6" };
                rules.push_str(&format!(
                    "  ct direction original {family} daddr {address} drop\n"
                ));
            }
            for rule in plan.rules() {
                let family = if rule.target_ip.is_ipv4() {
                    "ip"
                } else {
                    "ip6"
                };
                if rule.protocol.tcp() {
                    rules.push_str(&format!(
                        "  ct direction original {family} daddr {} tcp dport {} return\n",
                        rule.target_ip, rule.target_port
                    ));
                }
                if rule.protocol.udp() {
                    rules.push_str(&format!(
                        "  ct direction original {family} daddr {} udp dport {} return\n",
                        rule.target_ip, rule.target_port
                    ));
                }
            }
        }
        rules.push_str("  drop\n }\n");
    }
    rules.push_str(" chain output { type filter hook output priority -10; policy accept;\n");
    for peer in peers {
        ensure!(
            peer.mark != 0 && peer.endpoint.port() != 0,
            "unmarked WireGuard peers cannot bypass target policy"
        );
        let family = if peer.endpoint.is_ipv4() { "ip" } else { "ip6" };
        rules.push_str(&format!(
            "  meta mark {} {family} daddr {} udp dport {} return\n",
            peer.mark,
            peer.endpoint.ip(),
            peer.endpoint.port()
        ));
    }
    for owner_id in 1..=i64::from(policy.max_owners) {
        rules.push_str(&format!(
            "  meta skuid {} jump owner_{owner_id}\n",
            policy.uid(owner_id)?
        ));
    }
    rules.push_str(" }\n}\n");
    Ok(rules)
}

pub struct LinuxDriver {
    policy: BrokerPolicy,
    plans: Mutex<BTreeMap<i64, RuntimePlan>>,
    firewall_digest: Mutex<Option<Vec<u8>>>,
    tunnel_peers: Mutex<Vec<WireguardPeer>>,
    global_failures: Mutex<u8>,
    #[cfg(target_os = "linux")]
    bindguards: Mutex<BTreeMap<i64, crate::bindguard::BindGuard>>,
}

pub fn validate_runtime_listeners(
    plan: Option<&RuntimePlan>,
    found: &HashSet<(&str, u16)>,
) -> anyhow::Result<()> {
    if let Some(plan) = plan {
        let expected_tcp: HashSet<u16> = plan
            .rules()
            .iter()
            .filter(|rule| rule.protocol.tcp())
            .map(|rule| rule.listen_port)
            .collect();
        let expected_udp: HashSet<u16> = plan
            .rules()
            .iter()
            .filter(|rule| rule.protocol.udp())
            .map(|rule| rule.listen_port)
            .collect();
        let actual_tcp: HashSet<u16> = found
            .iter()
            .filter(|(protocol, _)| *protocol == "tcp")
            .map(|(_, port)| *port)
            .collect();
        let actual_udp: HashSet<u16> = found
            .iter()
            .filter(|(protocol, _)| *protocol == "udp")
            .map(|(_, port)| *port)
            .collect();
        // Realm creates unconnected, ephemeral upstream UDP sockets after
        // traffic arrives. The account OUTPUT chain confines their traffic;
        // readiness requires all entry sockets, without banning those sockets.
        ensure!(
            actual_tcp == expected_tcp && expected_udp.is_subset(&actual_udp),
            "runtime listener protocol/port/UID mismatch"
        );
    } else {
        ensure!(found.is_empty(), "stopped runtime still owns sockets");
    }
    Ok(())
}

pub fn validate_listener_inventory(
    policy: &BrokerPolicy,
    output: &str,
    plan: &RuntimePlan,
) -> anyhow::Result<()> {
    policy.validate()?;
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let local = fields
            .get(3)
            .context("invalid listener inventory address")?;
        let (_, value) = local
            .rsplit_once(':')
            .context("invalid listener inventory port")?;
        let port: u16 = value.parse().context("invalid listener inventory port")?;
        if !plan.rules().iter().any(|rule| rule.listen_port == port) {
            continue;
        }
        // ss omits uid for root sockets. Treat absent uid as root, never as a
        // tenant, so a broad root port grant cannot block existing services.
        let uid = fields
            .iter()
            .find_map(|field| field.strip_prefix("uid:"))
            .map(str::parse::<u32>)
            .transpose()?
            .unwrap_or(0);
        ensure!(
            uid == policy.uid(plan.owner_id())?,
            "port {port} is occupied by another service; choose another port"
        );
    }
    Ok(())
}

fn udp_grants_for_owner(policy: &BrokerPolicy, owner: i64) -> anyhow::Result<HashSet<u16>> {
    let directory = policy.runtime_dir.join(format!("owner-{owner}"));
    let held = directory.join("held-udp-ports.json");
    if held.try_exists()? {
        secure_root_path(&held, false)?;
        ensure!(
            std::fs::metadata(&held)?.len() <= 1024,
            "UDP grant snapshot too large"
        );
        let ports: HashSet<u16> = serde_json::from_slice(&std::fs::read(held)?)?;
        ensure!(
            ports.len() <= crate::executor::MAX_RULES * 2 && ports.iter().all(|port| *port >= 1024),
            "invalid UDP grant snapshot"
        );
        return Ok(ports);
    }
    // Compatibility with a runtime started by an earlier release.
    let snapshot = directory.join("plan.json");
    if !snapshot.try_exists()? {
        return Ok(HashSet::new());
    }
    secure_root_path(&snapshot, false)?;
    ensure!(
        std::fs::metadata(&snapshot)?.len() <= 128 * 1024,
        "runtime snapshot too large"
    );
    let plan: RuntimePlan = serde_json::from_slice(&std::fs::read(snapshot)?)?;
    ensure!(plan.owner_id() == owner, "runtime snapshot owner mismatch");
    Ok(plan
        .rules()
        .iter()
        .filter(|rule| rule.protocol.udp())
        .map(|rule| rule.listen_port)
        .collect())
}

#[cfg(target_os = "linux")]
fn save_udp_grants(
    policy: &BrokerPolicy,
    plan: &RuntimePlan,
    retain_previous: bool,
) -> anyhow::Result<()> {
    let mut ports = if retain_previous {
        udp_grants_for_owner(policy, plan.owner_id())?
    } else {
        HashSet::new()
    };
    ports.extend(
        plan.rules()
            .iter()
            .filter(|rule| rule.protocol.udp())
            .map(|rule| rule.listen_port),
    );
    ensure!(
        ports.len() <= crate::executor::MAX_RULES * 2,
        "too many retained UDP listener ports"
    );
    let mut ports: Vec<_> = ports.into_iter().collect();
    ports.sort_unstable();
    write_root_file(
        &policy
            .runtime_dir
            .join(format!("owner-{}/held-udp-ports.json", plan.owner_id())),
        &serde_json::to_vec(&ports)?,
        0o600,
        0,
    )
}

fn tenant_kernel_listeners(policy: &BrokerPolicy) -> anyhow::Result<Vec<(Protocol, u16)>> {
    use std::io::BufRead;
    let mut udp_grants = BTreeMap::new();
    for owner in 1..=i64::from(policy.max_owners) {
        udp_grants.insert(policy.uid(owner)?, udp_grants_for_owner(policy, owner)?);
    }
    let mut held = Vec::new();
    for (protocol, name) in [
        (Protocol::Tcp, "tcp"),
        (Protocol::Tcp, "tcp6"),
        (Protocol::Udp, "udp"),
        (Protocol::Udp, "udp6"),
    ] {
        let file = std::fs::File::open(Path::new("/proc/net").join(name))?;
        for line in std::io::BufReader::new(file).lines().skip(1) {
            let line = line?;
            let fields: Vec<_> = line.split_whitespace().collect();
            let uid: u32 = fields
                .get(7)
                .context("missing kernel socket UID")?
                .parse()?;
            if !(policy.uid_start..policy.uid_start + policy.max_owners).contains(&uid)
                || (protocol == Protocol::Tcp && fields.get(3) != Some(&"0A"))
            {
                continue;
            }
            let port = fields
                .get(1)
                .and_then(|address| address.rsplit_once(':'))
                .context("invalid kernel socket address")?
                .1;
            let port = u16::from_str_radix(port, 16)?;
            // UDP upstream sockets also bind ephemeral ports. They are not
            // managed listeners and must not capture other host services.
            if protocol == Protocol::Udp
                && !udp_grants
                    .get(&uid)
                    .is_some_and(|ports| ports.contains(&port))
            {
                continue;
            }
            held.push((protocol, port));
        }
    }
    Ok(held)
}

#[cfg(target_os = "linux")]
pub(crate) fn secure_root_path(path: &Path, directory: bool) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    validate_absolute_path(path)?;
    let mut current = PathBuf::from("/");
    for part in path.components().skip(1) {
        current.push(part.as_os_str());
        let metadata = std::fs::symlink_metadata(&current)
            .with_context(|| format!("inspect {}", current.display()))?;
        ensure!(
            !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0,
            "{} must be root owned, not a symlink, and not writable by others",
            current.display()
        );
        if current != path {
            ensure!(metadata.is_dir(), "path ancestor is not a directory");
        } else {
            ensure!(
                if directory {
                    metadata.is_dir()
                } else {
                    metadata.is_file() && metadata.nlink() == 1
                },
                "invalid root runtime object"
            );
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn secure_root_path(_path: &Path, _directory: bool) -> anyhow::Result<()> {
    anyhow::bail!("the production executor requires Linux")
}

#[cfg(target_os = "linux")]
fn validate_uid_pool(policy: &BrokerPolicy) -> anyhow::Result<()> {
    let passwd = std::fs::read_to_string("/etc/passwd")?;
    let mut found = HashSet::new();
    for line in passwd.lines() {
        if let Some(uid) = line
            .split(':')
            .nth(2)
            .and_then(|field| field.parse::<u32>().ok())
            .filter(|uid| (policy.uid_start..policy.uid_start + policy.max_owners).contains(uid))
        {
            let fields: Vec<_> = line.split(':').collect();
            let owner = uid - policy.uid_start + 1;
            ensure!(
                fields.len() == 7
                    && fields[0] == format!("relaydeck-runner-{owner}")
                    && fields[3].parse::<u32>() == Ok(uid)
                    && fields[5] == "/nonexistent"
                    && fields[6] == "/usr/sbin/nologin",
                "runtime UID belongs to an unexpected account"
            );
            found.insert(uid);
        }
    }
    ensure!(
        found.len() == policy.max_owners as usize,
        "provision the dedicated runtime accounts before starting the broker"
    );
    let group = std::fs::read_to_string("/etc/group")?;
    let mut groups = HashSet::new();
    for line in group.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if let Some(gid) = fields
            .get(2)
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|gid| (policy.uid_start..policy.uid_start + policy.max_owners).contains(gid))
        {
            ensure!(
                fields[0] == format!("relaydeck-runner-{}", gid - policy.uid_start + 1)
                    && fields.get(3) == Some(&""),
                "runtime group is shared with another account"
            );
            groups.insert(gid);
        }
    }
    ensure!(groups == found, "dedicated runtime groups are missing");
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let Some(uid) = status.lines().find_map(|line| {
            line.strip_prefix("Uid:")
                .and_then(|value| value.split_whitespace().next()?.parse::<u32>().ok())
        }) else {
            continue;
        };
        if (policy.uid_start..policy.uid_start + policy.max_owners).contains(&uid) {
            let cgroup = std::fs::read_to_string(entry.path().join("cgroup"))?;
            let owner = uid - policy.uid_start + 1;
            ensure!(
                cgroup
                    .lines()
                    .any(|line| line.ends_with(&format!("/relaydeck-owner-{owner}.service"))),
                "dedicated UID used by an unrelated running process"
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn system_tool(path: &Path) -> anyhow::Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    ensure!(
        [SYSTEMCTL, NFT, SS, IP, WG]
            .iter()
            .any(|tool| Path::new(tool) == path),
        "unknown system tool"
    );
    validate_absolute_path(path)?;
    let mut current = PathBuf::from("/");
    for part in path.components().skip(1) {
        current.push(part.as_os_str());
        let meta = std::fs::symlink_metadata(&current)?;
        ensure!(
            meta.uid() == 0 && (meta.file_type().is_symlink() || meta.mode() & 0o022 == 0),
            "system tool alias must be immutable and root owned"
        );
    }
    let target = std::fs::canonicalize(path)?;
    secure_root_path(&target, false)?;
    Ok(target)
}

#[derive(Debug, thiserror::Error)]
#[error("runtime command unavailable: {0}")]
struct CommandUnavailable(String);

async fn command(program: &str, args: &[&str], input: Option<&[u8]>) -> anyhow::Result<Vec<u8>> {
    use std::process::Stdio;
    #[cfg(target_os = "linux")]
    let executable = system_tool(Path::new(program))?;
    #[cfg(not(target_os = "linux"))]
    let executable = PathBuf::from(program);
    let mut builder = Command::new(executable);
    builder
        .args(args)
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = builder
        .spawn()
        .map_err(|error| CommandUnavailable(format!("start {program}: {error}")))?;
    if let Some(input) = input {
        let mut stdin = child.stdin.take().context("missing command stdin")?;
        tokio::time::timeout(COMMAND_TIMEOUT, stdin.write_all(input))
            .await
            .map_err(|_| CommandUnavailable("command input timed out".into()))?
            .map_err(|error| CommandUnavailable(error.to_string()))?;
        drop(stdin);
    }
    let output = tokio::time::timeout(COMMAND_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| CommandUnavailable("command timed out".into()))?
        .map_err(|error| CommandUnavailable(error.to_string()))?;
    if !output.status.success() {
        return Err(CommandUnavailable(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .filter(|c| !c.is_control())
                .take(240)
                .collect::<String>()
        ))
        .into());
    }
    ensure!(
        output.stdout.len() <= 4 * 1024 * 1024,
        "runtime command response too large"
    );
    Ok(output.stdout)
}

async fn interface_ips() -> anyhow::Result<Vec<IpAddr>> {
    let output = command(IP, &["-j", "address", "show"], None).await?;
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&output)?;
    let mut ips = Vec::new();
    for row in rows {
        for address in row
            .get("addr_info")
            .and_then(serde_json::Value::as_array)
            .context("missing interface addresses")?
        {
            let value = address
                .get("local")
                .and_then(serde_json::Value::as_str)
                .context("invalid local interface address")?;
            ips.push(value.parse()?);
        }
    }
    Ok(ips)
}

#[cfg(target_os = "linux")]
fn write_root_file(path: &Path, bytes: &[u8], mode: u32, group: u32) -> anyhow::Result<()> {
    use std::{
        io::Write,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    };
    secure_root_path(path.parent().context("missing runtime file parent")?, true)?;
    if path.try_exists()? {
        secure_root_path(path, false)?;
    }
    let temporary = path.with_extension("relaydeck-tmp");
    if temporary.try_exists()? {
        secure_root_path(&temporary, false)?;
        std::fs::remove_file(&temporary)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    let result = (|| {
        ensure!(
            file.metadata()?.nlink() == 1,
            "runtime file has multiple links"
        );
        file.write_all(bytes)?;
        ensure!(
            unsafe { libc::fchown(file.as_raw_fd(), 0, group) } == 0,
            "cannot assign runtime file group"
        );
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

impl LinuxDriver {
    pub async fn new(policy: BrokerPolicy) -> anyhow::Result<Self> {
        policy.validate()?;
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("the production executor requires Linux");
        }
        #[cfg(target_os = "linux")]
        {
            ensure!(
                unsafe { libc::geteuid() } == 0,
                "the production executor requires root"
            );
            secure_root_path(&policy.runtime_dir, true)?;
            secure_root_path(&policy.realm_binary, false)?;
            secure_root_path(&policy.runner_binary, false)?;
            secure_root_path(Path::new(UNIT_DIR), true)?;
            use std::os::unix::fs::MetadataExt;
            for directory in policy.runtime_dir.ancestors() {
                ensure!(
                    std::fs::metadata(directory)?.mode() & 0o001 != 0,
                    "runtime directory ancestors must allow tenant traversal"
                );
            }
            ensure!(
                std::fs::metadata(&policy.realm_binary)?.mode() & 0o001 != 0,
                "realm binary must be executable by tenants"
            );
            ensure!(
                std::fs::metadata(&policy.runner_binary)?.mode() & 0o001 != 0,
                "tenant runner must be executable by tenants"
            );
            ensure!(
                Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
                "unified cgroups are required"
            );
            for tool in [SYSTEMCTL, NFT, SS, IP] {
                system_tool(Path::new(tool))?;
            }
            validate_uid_pool(&policy)?;
            write_root_file(&Path::new(UNIT_DIR).join("relaydeck.slice"), format!("[Unit]\nDescription=RelayDeck runtime budget\n\n[Slice]\nMemoryMax={}M\nMemorySwapMax=0\nTasksMax={}\nCPUQuota={}%\n",policy.limits.total_memory_mb,policy.limits.tasks * policy.max_owners,policy.limits.total_cpu_percent).as_bytes(), 0o644, 0)?;
            command(SYSTEMCTL, &["daemon-reload"], None).await?;
            let driver = Self {
                policy,
                plans: Mutex::new(BTreeMap::new()),
                firewall_digest: Mutex::new(None),
                tunnel_peers: Mutex::new(Vec::new()),
                global_failures: Mutex::new(0),
                bindguards: Mutex::new(BTreeMap::new()),
            };
            // On broker restart discard every old runtime first; reconstruct
            // desired state from fresh DB snapshots rather than trusting files.
            let plans = driver.plans.lock().await;
            // Install default-drop first. An unkillable tenant remains isolated,
            // but cannot prevent the broker from serving every other tenant.
            driver.firewall(&plans).await?;
            if let Err(error) = driver.stop_all_services().await {
                tracing::error!(%error,"startup tenant cleanup incomplete; quarantined tenants will be retried on apply");
            }
            drop(plans);
            Ok(driver)
        }
    }

    async fn firewall(&self, plans: &BTreeMap<i64, RuntimePlan>) -> anyhow::Result<()> {
        let addresses = interface_ips().await?;
        let held = tenant_kernel_listeners(&self.policy)?;
        let peers = wireguard_peers().await?;
        let nft = render_nft_with_tunnels(
            &self.policy,
            &plans.values().cloned().collect::<Vec<_>>(),
            &addresses,
            now(),
            &held,
            &peers,
        )?;
        command(NFT, &["--check", "-f", "-"], Some(nft.as_bytes())).await?;
        command(NFT, &["-f", "-"], Some(nft.as_bytes())).await?;
        let actual = command(NFT, &["-j", "list", "table", "inet", "relaydeck"], None).await?;
        let value: serde_json::Value = serde_json::from_slice(&actual)?;
        *self.firewall_digest.lock().await = Some(firewall_fingerprint(&value)?);
        *self.tunnel_peers.lock().await = peers;
        Ok(())
    }

    pub async fn unhealthy_owners(&self) -> Vec<(i64, i64, String, bool)> {
        let plans = self.plans.lock().await;
        let global = async {
            let actual =
                match command(NFT, &["-j", "list", "table", "inet", "relaydeck"], None).await {
                    Ok(actual) => actual,
                    Err(error) => {
                        tracing::warn!(%error,"firewall query failed; attempting policy repair");
                        self.firewall(&plans).await?;
                        command(NFT, &["-j", "list", "table", "inet", "relaydeck"], None).await?
                    }
                };
            let value: serde_json::Value = serde_json::from_slice(&actual)?;
            let changed =
                self.firewall_digest.lock().await.as_ref() != Some(&firewall_fingerprint(&value)?);
            let peers_changed = *self.tunnel_peers.lock().await != wireguard_peers().await?;
            if changed || peers_changed {
                tracing::warn!("runtime firewall changed; rebuilding root policy");
                self.firewall(&plans).await?;
            }
            interface_ips().await
        }
        .await;
        let mut failures = self.global_failures.lock().await;
        if let Err(error) = &global {
            *failures = failures.saturating_add(1);
            tracing::warn!(consecutive=*failures,%error,"global runtime check failed");
            if *failures < 3 {
                return Vec::new();
            }
            return plans
                .values()
                .map(|plan| {
                    (
                        plan.owner_id(),
                        plan.revision(),
                        format!("全局检查连续失败：{error}"),
                        true,
                    )
                })
                .collect();
        }
        *failures = 0;
        drop(failures);
        let mut unhealthy = Vec::new();
        for plan in plans.values() {
            let check = async {
                let ips = global
                    .as_ref()
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                let validated = plan.validate_again(
                    &self.policy.boundary(
                        self.policy
                            .local_ips
                            .iter()
                            .copied()
                            .chain(ips.iter().copied())
                            .collect(),
                    ),
                    now(),
                )?;
                ensure!(!validated.stopped(), "runtime expired");
                self.confirm_service(plan).await?;
                self.confirm_listeners(plan.owner_id(), Some(plan)).await
            }
            .await;
            if let Err(error) = check {
                let retryable = error.downcast_ref::<RuntimeExited>().is_some()
                    || error.downcast_ref::<CommandUnavailable>().is_some();
                unhealthy.push((
                    plan.owner_id(),
                    plan.revision(),
                    error.to_string(),
                    retryable,
                ));
            }
        }
        unhealthy
    }

    #[cfg(not(target_os = "linux"))]
    async fn confirm_service(&self, _plan: &RuntimePlan) -> anyhow::Result<()> {
        anyhow::bail!("the production executor requires Linux")
    }

    #[cfg(target_os = "linux")]
    async fn confirm_service(&self, plan: &RuntimePlan) -> anyhow::Result<()> {
        let uid = self.policy.uid(plan.owner_id())?;
        let unit = format!("relaydeck-owner-{}.service", plan.owner_id());
        let output = command(SYSTEMCTL, &["show", "--property=ActiveState,SubState,MainPID,User,Group,NoNewPrivileges,CapabilityBoundingSet,ControlGroup,Restart", &unit], None).await?;
        let values: BTreeMap<&str, &str> = std::str::from_utf8(&output)?
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();
        if matches!(values.get("ActiveState"), Some(&"failed" | &"inactive")) {
            return Err(RuntimeExited.into());
        }
        for (name, expected) in [
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", ""),
            ("Restart", "no"),
        ] {
            ensure!(
                values.get(name) == Some(&expected),
                "systemd runtime property {name} is not enforced"
            );
        }
        let expected_uid = uid.to_string();
        ensure!(
            values.get("User") == Some(&expected_uid.as_str())
                && values.get("Group") == Some(&expected_uid.as_str()),
            "systemd runtime identity mismatch"
        );
        let pid: u32 = values.get("MainPID").context("missing main PID")?.parse()?;
        ensure!(pid > 1, "missing runtime process");
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
        ensure!(
            std::fs::read_link(format!("/proc/{pid}/exe"))? == self.policy.runner_binary,
            "runtime executable differs from fixed tenant runner"
        );
        let identity: BTreeMap<&str, &str> = status
            .lines()
            .filter_map(|line| line.split_once(':').map(|(key, value)| (key, value.trim())))
            .collect();
        let limits = std::fs::read_to_string(format!("/proc/{pid}/limits"))?;
        let open_files = limits
            .lines()
            .find_map(|line| line.strip_prefix("Max open files"))
            .context("missing open-file limits")?;
        let expected_limit = self.policy.limits.nofile.to_string();
        ensure!(
            open_files
                .split_whitespace()
                .take(2)
                .all(|value| value == expected_limit),
            "effective file limit differs"
        );
        for key in ["Uid", "Gid"] {
            let ids = identity
                .get(key)
                .context("missing process identity")?
                .split_whitespace()
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()?;
            ensure!(
                ids.len() == 4 && ids.iter().all(|id| *id == uid),
                "runtime failed to drop all credentials"
            );
        }
        ensure!(
            identity.get("NoNewPrivs") == Some(&"1"),
            "process no_new_privs is not enforced"
        );
        ensure!(
            identity.get("Groups").is_some_and(|value| value
                .split_whitespace()
                .all(|group| group.parse::<u32>() == Ok(uid))),
            "runtime has unexpected supplementary groups"
        );
        for key in ["CapEff", "CapPrm", "CapBnd", "CapAmb"] {
            ensure!(
                identity
                    .get(key)
                    .is_some_and(|value| value.bytes().all(|byte| byte == b'0')),
                "runtime retains capabilities"
            );
        }
        let group = values
            .get("ControlGroup")
            .context("missing control group")?;
        validate_absolute_path(Path::new(group))?;
        ensure!(
            group.ends_with(&format!("/relaydeck-owner-{}.service", plan.owner_id())),
            "runtime control group mismatch"
        );
        let directory = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
        ensure!(
            std::fs::read_to_string("/sys/fs/cgroup/relaydeck.slice/memory.max")?.trim()
                == (self.policy.limits.total_memory_mb * 1024 * 1024).to_string(),
            "aggregate runtime memory limit is not enforced"
        );
        for (file, expected) in [
            (
                "memory.high",
                (self.policy.limits.memory_high_mb * 1024 * 1024).to_string(),
            ),
            (
                "memory.max",
                (self.policy.limits.memory_max_mb * 1024 * 1024).to_string(),
            ),
            ("memory.swap.max", "0".into()),
            ("pids.max", self.policy.limits.tasks.to_string()),
        ] {
            ensure!(
                std::fs::read_to_string(directory.join(file))?.trim() == expected,
                "effective cgroup limit {file} differs"
            );
        }
        let cpu = std::fs::read_to_string(directory.join("cpu.max"))?;
        let quota: Vec<u64> = cpu
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            quota.len() == 2
                && quota[0] > 0
                && quota[0].checked_mul(100)
                    == quota[1].checked_mul(u64::from(self.policy.limits.cpu_percent)),
            "effective CPU quota differs"
        );
        let guards = self.bindguards.lock().await;
        guards
            .get(&plan.owner_id())
            .context("missing bind guard")?
            .verify(&directory)?;
        Ok(())
    }

    async fn stop_service(&self, owner_id: i64) -> anyhow::Result<()> {
        // One bounded command per poll; transient failures do not exhaust a
        // lifetime budget or prevent future cleanup after the host recovers.
        self.stop_service_inner(owner_id).await
    }

    async fn stop_service_inner(&self, owner_id: i64) -> anyhow::Result<()> {
        let unit = format!("relaydeck-owner-{owner_id}.service");
        let exists = Path::new(UNIT_DIR).join(&unit).try_exists()?;
        if exists {
            secure_root_path(&Path::new(UNIT_DIR).join(&unit), false)?;
            ensure!(
                std::fs::read_to_string(Path::new(UNIT_DIR).join(&unit))?.starts_with(&format!(
                    "[Unit]\nDescription=RelayDeck account {owner_id}\n"
                )),
                "fixed unit name belongs to another service"
            );
            command(SYSTEMCTL, &["stop", &unit], None).await?;
            let output = command(
                SYSTEMCTL,
                &["show", "--property=ActiveState", "--value", &unit],
                None,
            )
            .await?;
            let state = std::str::from_utf8(&output)?.trim();
            ensure!(
                matches!(state, "inactive" | "failed"),
                "runtime did not stop"
            );
        }
        self.confirm_listeners(owner_id, None).await?;
        #[cfg(target_os = "linux")]
        {
            let held = self
                .policy
                .runtime_dir
                .join(format!("owner-{owner_id}/held-udp-ports.json"));
            if held.try_exists()? {
                write_root_file(&held, b"[]", 0o600, 0)?;
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn stop_all_services(&self) -> anyhow::Result<()> {
        let mut failures = Vec::new();
        for owner in 1..=i64::from(self.policy.max_owners) {
            if let Err(error) = self.stop_service(owner).await {
                failures.push(format!("owner {owner}: {error}"));
            }
        }
        ensure!(failures.is_empty(), "{}", failures.join("; "));
        Ok(())
    }

    async fn confirm_listeners(
        &self,
        owner_id: i64,
        plan: Option<&RuntimePlan>,
    ) -> anyhow::Result<()> {
        let uid = self.policy.uid(owner_id)?;
        let mut found = HashSet::new();
        for (protocol, flags) in [("tcp", "-Hlnte"), ("udp", "-Hlnue")] {
            let output = command(SS, &[flags], None).await?;
            for line in std::str::from_utf8(&output)?.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if !fields.iter().any(|field| {
                    field
                        .strip_prefix("uid:")
                        .and_then(|value| value.parse::<u32>().ok())
                        == Some(uid)
                }) {
                    continue;
                }
                let local = fields.get(3).context("invalid ss local-address column")?;
                let (_, port) = local
                    .rsplit_once(':')
                    .context("invalid ss listener address")?;
                found.insert((protocol, port.parse::<u16>()?));
            }
        }
        validate_runtime_listeners(plan, &found)?;
        if plan.is_none() {
            #[cfg(target_os = "linux")]
            for entry in std::fs::read_dir("/proc")? {
                let entry = entry?;
                if !entry
                    .file_name()
                    .as_encoded_bytes()
                    .iter()
                    .all(u8::is_ascii_digit)
                {
                    continue;
                }
                let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
                    continue;
                };
                let same_uid = status.lines().find_map(|line| {
                    line.strip_prefix("Uid:")
                        .and_then(|value| value.split_whitespace().next()?.parse::<u32>().ok())
                }) == Some(uid);
                ensure!(!same_uid, "stopped runtime still has a running process");
            }
        }
        Ok(())
    }

    async fn apply_plan(&self, raw: &RuntimePlan) -> anyhow::Result<()> {
        self.policy.uid(raw.owner_id())?;
        {
            let mut plans = self.plans.lock().await;
            if plans.get(&raw.owner_id()).is_some_and(|existing| {
                existing.rules() == raw.rules()
                    && existing.expires_at() == raw.expires_at()
                    && existing.port_start() == raw.port_start()
                    && existing.port_end() == raw.port_end()
            }) {
                if self.runtime_present(raw)? {
                    // Renewals inspect kernel state without spawning tools.
                    let plan = raw.validate_again(
                        &self.policy.boundary(self.policy.local_ips.clone()),
                        now(),
                    )?;
                    ensure!(!plan.stopped(), "runtime authorization expired");
                    self.renew_authorization(&plan)?;
                    plans.insert(plan.owner_id(), plan);
                    return Ok(());
                }
                let authorization = self
                    .policy
                    .runtime_dir
                    .join(format!("owner-{}/authorization", raw.owner_id()));
                let until: i64 = std::fs::read_to_string(authorization)?.parse()?;
                // A crash consumes the bounded worker retry budget. A known
                // expired lease can be restarted with this fresh authorization.
                if until > now() {
                    return Err(RuntimeExited.into());
                }
            }
        }
        let local_ips = interface_ips().await?;
        let plan = raw.validate_again(
            &self.policy.boundary(
                self.policy
                    .local_ips
                    .iter()
                    .copied()
                    .chain(local_ips)
                    .collect(),
            ),
            now(),
        )?;
        ensure!(
            plan.rules()
                .iter()
                .all(
                    |rule| (self.policy.allowed_port_start..=self.policy.allowed_port_end)
                        .contains(&rule.listen_port)
                ),
            "account grant exceeds root global port boundary"
        );
        // Check only requested ports. A shared pool must coexist with unrelated
        // host services, and never install ACLs over another service's listener.
        for flags in ["-Hlnte", "-Hlnue"] {
            let listeners = command(SS, &[flags], None).await?;
            validate_listener_inventory(&self.policy, std::str::from_utf8(&listeners)?, &plan)?;
        }
        let mut plans = self.plans.lock().await;
        #[cfg(target_os = "linux")]
        if let Some(previous) = plans.get(&plan.owner_id())
            && previous.expires_at() == plan.expires_at()
            && previous.port_start() == plan.port_start()
            && previous.port_end() == plan.port_end()
            && !plan.stopped()
            && self.runtime_present(previous)?
        {
            let directory = self
                .policy
                .runtime_dir
                .join(format!("owner-{}", plan.owner_id()));
            self.confirm_service(previous).await?;
            let cgroup = Path::new("/sys/fs/cgroup/relaydeck.slice")
                .join(format!("relaydeck-owner-{}.service", plan.owner_id()));
            // Restrict network access first, then bind permissions, then publish
            // the child plan. Unchanged rules retain their processes and sockets.
            let mut next = plans.clone();
            next.insert(plan.owner_id(), plan.clone());
            self.firewall(&next).await?;
            let mut guards = self.bindguards.lock().await;
            let replacement = guards
                .get(&plan.owner_id())
                .context("missing bind guard")?
                .replace(&plan, &cgroup)?;
            guards.insert(plan.owner_id(), replacement);
            drop(guards);
            self.write_plan(&plan, &directory)?;
            self.renew_authorization(&plan)?;
            self.confirm_applied(&plan, &directory).await?;
            self.confirm_service(&plan).await?;
            save_udp_grants(&self.policy, &plan, false)?;
            *plans = next;
            return Ok(());
        }
        plans.remove(&plan.owner_id());
        fail_closed_cleanup(self.firewall(&plans), self.stop_service(plan.owner_id())).await?;
        if plan.stopped() {
            return Ok(());
        }
        ensure!(
            plans
                .values()
                .flat_map(RuntimePlan::rules)
                .all(|other| !plan
                    .rules()
                    .iter()
                    .any(|rule| rule.listen_port == other.listen_port)),
            "listener owned by another account"
        );
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let uid = self.policy.uid(plan.owner_id())?;
            let directory = self
                .policy
                .runtime_dir
                .join(format!("owner-{}", plan.owner_id()));
            if !directory.try_exists()? {
                std::fs::create_dir(&directory)?;
            }
            secure_root_path(&directory, true)?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))?;
            self.write_plan(&plan, &directory)?;
            initialize_ack(&directory.join("applied-revision"), uid)?;
            self.renew_authorization(&plan)?;
            let unit = format!("relaydeck-owner-{}.service", plan.owner_id());
            write_root_file(
                &Path::new(UNIT_DIR).join(&unit),
                render_systemd(&self.policy, &plan, now())?.as_bytes(),
                0o644,
                0,
            )?;
            command(SYSTEMCTL, &["daemon-reload"], None).await?;
            write_root_file(&directory.join("bind-ready"), b"0", 0o640, uid)?;
            command(SYSTEMCTL, &["start", &unit], None).await?;
            let output = command(
                SYSTEMCTL,
                &["show", "--property=ControlGroup", "--value", &unit],
                None,
            )
            .await?;
            let group = std::str::from_utf8(&output)?.trim();
            validate_absolute_path(Path::new(group))?;
            ensure!(
                group.ends_with(&format!("/relaydeck-owner-{}.service", plan.owner_id())),
                "unexpected bind-guard cgroup"
            );
            let cgroup = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
            let guard = crate::bindguard::BindGuard::attach(&plan, &cgroup)?;
            self.bindguards.lock().await.insert(plan.owner_id(), guard);
            write_root_file(
                &directory.join("bind-ready"),
                plan.revision().to_string().as_bytes(),
                0o640,
                uid,
            )?;
            self.confirm_applied(&plan, &directory).await?;
            self.confirm_service(&plan).await?;
            save_udp_grants(&self.policy, &plan, false)?;
            plans.insert(plan.owner_id(), plan.clone());
            self.firewall(&plans).await?;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("the production executor requires Linux");
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn runtime_present(&self, _plan: &RuntimePlan) -> anyhow::Result<bool> {
        Ok(false)
    }

    #[cfg(target_os = "linux")]
    fn runtime_present(&self, plan: &RuntimePlan) -> anyhow::Result<bool> {
        use std::io::BufRead;
        let directory = Path::new("/sys/fs/cgroup/relaydeck.slice")
            .join(format!("relaydeck-owner-{}.service", plan.owner_id()));
        let pids = match std::fs::read_to_string(directory.join("cgroup.procs")) {
            Ok(pids) => pids,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let uid = self.policy.uid(plan.owner_id())?;
        let mut runners = 0;
        let mut children = 0;
        for pid in pids.split_whitespace() {
            let pid: u32 = pid.parse()?;
            let base = Path::new("/proc").join(pid.to_string());
            let executable = match std::fs::read_link(base.join("exe")) {
                Ok(path) => path,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error.into()),
            };
            let status = match std::fs::read_to_string(base.join("status")) {
                Ok(status) => status,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error.into()),
            };
            ensure!(
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("Uid:"))
                    .is_some_and(|values| values
                        .split_whitespace()
                        .all(|value| value.parse::<u32>() == Ok(uid))),
                "runtime identity changed"
            );
            if executable == self.policy.runner_binary {
                runners += 1;
            } else if executable == self.policy.realm_binary {
                children += 1;
            } else {
                anyhow::bail!("unexpected runtime executable");
            }
        }
        if runners != 1 || children != plan.rules().len() {
            return Ok(false);
        }
        let mut sockets = HashSet::new();
        for (protocol, name) in [
            ("tcp", "tcp"),
            ("tcp", "tcp6"),
            ("udp", "udp"),
            ("udp", "udp6"),
        ] {
            let file = std::fs::File::open(Path::new("/proc/net").join(name))?;
            for line in std::io::BufReader::new(file).lines().skip(1) {
                let line = line?;
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.get(7).and_then(|value| value.parse::<u32>().ok()) != Some(uid)
                    || (protocol == "tcp" && fields.get(3) != Some(&"0A"))
                {
                    continue;
                }
                let port = fields
                    .get(1)
                    .and_then(|address| address.rsplit_once(':'))
                    .context("invalid kernel socket address")?
                    .1;
                sockets.insert((protocol, u16::from_str_radix(port, 16)?));
            }
        }
        Ok(validate_runtime_listeners(Some(plan), &sockets).is_ok())
    }

    #[cfg(target_os = "linux")]
    fn write_plan(&self, plan: &RuntimePlan, directory: &Path) -> anyhow::Result<()> {
        save_udp_grants(&self.policy, plan, true)?;
        let uid = self.policy.uid(plan.owner_id())?;
        for rule in plan.rules() {
            write_root_file(
                &directory.join(format!("rule-{}.json", rule.id)),
                &plan.rule_json(rule.id)?,
                0o640,
                uid,
            )?;
        }
        write_root_file(
            &directory.join("plan.json"),
            &serde_json::to_vec(plan)?,
            0o640,
            uid,
        )
    }

    #[cfg(target_os = "linux")]
    async fn confirm_applied(&self, plan: &RuntimePlan, directory: &Path) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            ensure!(
                plan.expires_at().is_none_or(|expiry| expiry > now()),
                "account expired during apply"
            );
            let acknowledged = read_ack(
                &directory.join("applied-revision"),
                self.policy.uid(plan.owner_id())?,
            )?;
            if acknowledged == Some(plan.revision())
                && self
                    .confirm_listeners(plan.owner_id(), Some(plan))
                    .await
                    .is_ok()
            {
                return Ok(());
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "realm plan was not confirmed"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn stop_owner(&self, owner_id: i64) -> anyhow::Result<()> {
        // A corrupt DB owner outside the fixed pool cannot have a runtime from
        // this driver. No UID/unit/path is derived from that unbounded value.
        if self.policy.uid(owner_id).is_err() {
            return Ok(());
        }
        let mut plans = self.plans.lock().await;
        plans.remove(&owner_id);
        // Revoke the tenant's independent monotonic lease before invoking tools.
        #[cfg(target_os = "linux")]
        {
            let path = self
                .policy
                .runtime_dir
                .join(format!("owner-{owner_id}/authorization"));
            if path.try_exists()? {
                write_root_file(&path, b"0", 0o640, self.policy.uid(owner_id)?)?;
            }
        }
        let result = fail_closed_cleanup(self.firewall(&plans), self.stop_service(owner_id)).await;
        #[cfg(target_os = "linux")]
        if result.is_ok() {
            self.bindguards.lock().await.remove(&owner_id);
        }
        result
    }

    pub(crate) fn renew_authorization(&self, plan: &RuntimePlan) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let until = now() + self.policy.authorization_ttl_secs as i64;
            write_root_file(
                &self
                    .policy
                    .runtime_dir
                    .join(format!("owner-{}/authorization", plan.owner_id())),
                until.to_string().as_bytes(),
                0o640,
                self.policy.uid(plan.owner_id())?,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = plan;
            anyhow::bail!("Linux is required")
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn shutdown(&self) -> anyhow::Result<()> {
        let mut plans = self.plans.lock().await;
        plans.clear();
        fail_closed_cleanup(self.firewall(&plans), self.stop_all_services()).await
    }
}

impl ExecutorDriver for LinuxDriver {
    fn apply<'a>(&'a self, plan: &'a RuntimePlan) -> DriverFuture<'a> {
        Box::pin(async move {
            self.apply_plan(plan).await.map_err(|error| {
                if error.downcast_ref::<RuntimeExited>().is_some() {
                    DriverError::crashed(error.to_string())
                } else if error.downcast_ref::<CommandUnavailable>().is_some() {
                    DriverError::temporary(error.to_string())
                } else {
                    DriverError::new(error.to_string())
                }
            })
        })
    }

    fn stop(&self, owner_id: i64) -> DriverFuture<'_> {
        Box::pin(async move {
            self.stop_owner(owner_id).await.map_err(|error| {
                if error.downcast_ref::<CommandUnavailable>().is_some() {
                    DriverError::temporary(error.to_string())
                } else {
                    DriverError::new(error.to_string())
                }
            })
        })
    }
}

impl ExecutorDriver for Arc<LinuxDriver> {
    fn apply<'a>(&'a self, plan: &'a RuntimePlan) -> DriverFuture<'a> {
        self.as_ref().apply(plan)
    }
    fn stop(&self, owner_id: i64) -> DriverFuture<'_> {
        self.as_ref().stop(owner_id)
    }
}

pub async fn run(policy_path: &Path) -> anyhow::Result<()> {
    crate::broker::run(policy_path).await
}

#[cfg(target_os = "linux")]
fn initialize_ack(path: &Path, uid: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if path.try_exists()? {
        read_ack(path, uid)?;
        std::fs::remove_file(path)?;
    }
    write_root_file(path, b"0", 0o600, uid)?;
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(meta.uid() == 0, "unexpected initial ack owner");
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe { libc::chown(name.as_ptr(), uid, uid) } == 0,
        "cannot assign supervisor acknowledgement"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_ack(path: &Path, uid: u32) -> anyhow::Result<Option<i64>> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    secure_root_path(path.parent().context("missing ack directory")?, true)?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == uid
            && meta.nlink() == 1
            && meta.mode() & 0o077 == 0
            && meta.len() <= 20,
        "invalid supervisor acknowledgement"
    );
    let mut value = String::new();
    file.by_ref().take(21).read_to_string(&mut value)?;
    Ok(value.parse().ok())
}

#[cfg(all(test, target_os = "linux"))]
mod shared_port_kernel_tests {
    use super::*;
    use crate::executor::{DesiredPlan, DesiredRule};
    use std::{
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
    };

    struct Process(Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "requires an isolated root Linux environment with Python and setpriv"]
    fn udp_listener_history_survives_apply_failure_and_excludes_upstream_and_host_sockets() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let dir = tempfile::Builder::new()
            .prefix("relaydeck-port-tests-")
            .tempdir_in("/run")
            .unwrap();
        let mut policy: BrokerPolicy =
            serde_json::from_str(include_str!("../deploy/broker.example.json")).unwrap();
        policy.runtime_dir = dir.path().to_path_buf();
        let owner = dir.path().join("owner-1");
        std::fs::create_dir(&owner).unwrap();
        let host = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let script = r#"import socket,json,sys
a=socket.socket();a.bind(('127.0.0.1',0));a.listen()
sockets=[a];ports=[a.getsockname()[1]]
for _ in range(2):
 for attempt in range(3):
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0))
  port=s.getsockname()[1]
  if port not in ports:
   sockets.append(s);ports.append(port);break
  s.close()
 else: raise RuntimeError('cannot allocate distinct fixture ports')
print(json.dumps(ports),flush=True)
sys.stdin.read(1)
"#;
        let mut child = Process(
            Command::new("setpriv")
                .args([
                    "--reuid",
                    "60000",
                    "--regid",
                    "60000",
                    "--clear-groups",
                    "python3",
                    "-u",
                    "-c",
                    script,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let ports: Vec<u16> = serde_json::from_str(&line).unwrap();
        let rule = |id, port, protocol| DesiredRule {
            id,
            listen_port: port,
            target_ip: "1.1.1.1".parse().unwrap(),
            target_port: 443,
            protocol,
            source_cidrs: vec![],
            enabled: true,
        };
        let mut desired = DesiredPlan {
            owner_id: 1,
            revision: 1,
            enabled: true,
            expires_at: None,
            port_start: 1024,
            port_end: 65535,
            max_rules: 10,
            rules: vec![
                rule(1, ports[0], Protocol::Tcp),
                rule(2, ports[1], Protocol::Udp),
            ],
        };
        let first = desired.validate(&ExecutorPolicy::default(), 0).unwrap();
        write_root_file(
            &owner.join("plan.json"),
            &serde_json::to_vec(&first).unwrap(),
            0o600,
            0,
        )
        .unwrap();
        let held = tenant_kernel_listeners(&policy).unwrap();
        assert!(held.contains(&(Protocol::Tcp, ports[0])));
        assert!(held.contains(&(Protocol::Udp, ports[1])));
        assert!(!held.contains(&(Protocol::Udp, ports[2])));
        assert!(!held.contains(&(Protocol::Udp, host.local_addr().unwrap().port())));
        // A new snapshot cannot erase the old UDP listener's ACL before stop
        // confirmation. The history is root-owned and survives broker restart.
        desired.revision = 2;
        desired.rules[1].listen_port = ports[2];
        let next = desired.validate(&ExecutorPolicy::default(), 0).unwrap();
        save_udp_grants(&policy, &next, true).unwrap();
        write_root_file(
            &owner.join("plan.json"),
            &serde_json::to_vec(&next).unwrap(),
            0o600,
            0,
        )
        .unwrap();
        let held = tenant_kernel_listeners(&policy).unwrap();
        assert!(held.contains(&(Protocol::Udp, ports[1])));
        assert!(held.contains(&(Protocol::Udp, ports[2])));
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        save_udp_grants(&policy, &next, false).unwrap();
        assert!(
            !udp_grants_for_owner(&policy, 1)
                .unwrap()
                .contains(&ports[1])
        );
        assert!(tenant_kernel_listeners(&policy).unwrap().is_empty());
    }
}
