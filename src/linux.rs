use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, ensure};
use serde::Deserialize;
#[cfg(target_os = "linux")]
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use tokio::{io::AsyncWriteExt, process::Command, sync::Mutex};

#[cfg(target_os = "linux")]
use crate::executor::Reconciler;
use crate::{
    db::now,
    executor::{DriverError, DriverFuture, ExecutorDriver, ExecutorPolicy, RuntimePlan},
};

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const NFT: &str = "/usr/sbin/nft";
const SS: &str = "/usr/bin/ss";
const IP: &str = "/usr/sbin/ip";
#[cfg(target_os = "linux")]
const BPFTOOL: &str = "/usr/sbin/bpftool";
const UNIT_DIR: &str = "/run/systemd/system";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(4);

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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerPolicy {
    pub database: PathBuf,
    pub web_uid: u32,
    pub runtime_dir: PathBuf,
    pub realm_binary: PathBuf,
    pub runner_binary: PathBuf,
    pub allowed_port_start: u16,
    pub allowed_port_end: u16,
    pub reserved_ports: Vec<u16>,
    pub local_ips: Vec<IpAddr>,
    pub uid_start: u32,
    pub max_owners: u32,
}

impl BrokerPolicy {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(self.web_uid != 0, "web_uid must not be root");
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

    fn uid(&self, owner_id: i64) -> anyhow::Result<u32> {
        ensure!(
            owner_id > 0 && owner_id <= i64::from(self.max_owners),
            "owner exceeds dedicated UID pool"
        );
        Ok(self.uid_start + (owner_id as u32) - 1)
    }

    fn boundary(&self, local_ips: Vec<IpAddr>) -> ExecutorPolicy {
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
        .join(format!("owner-{}/realm.json", plan.owner_id()));
    let mut unit = format!(
        "[Unit]\nDescription=RelayDeck account {}\n\n[Service]\nType=exec\nUser={uid}\nGroup={uid}\nExecStart={} tenant {} {} {} {uid}\nRestart=no\nRuntimeMaxSec={lifetime}\nKillMode=control-group\nTimeoutStartSec=5s\nTimeoutStopSec=3s\nSendSIGKILL=yes\nUMask=0077\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nRestrictSUIDSGID=yes\nRestrictRealtime=yes\nLockPersonality=yes\nRestrictAddressFamilies=AF_INET AF_INET6\nSystemCallArchitectures=native\nMemoryHigh=32M\nMemoryMax=64M\nMemorySwapMax=0\nTasksMax=16\nCPUQuota=20%\nLimitNOFILE=512\nLimitCORE=0\nSocketBindDeny=any\n",
        plan.owner_id(),
        policy.runner_binary.display(),
        policy.realm_binary.display(),
        config.display(),
        plan.expires_at().unwrap_or(0)
    );
    for rule in plan.rules() {
        if rule.protocol.tcp() {
            unit.push_str(&format!("SocketBindAllow=tcp:{}\n", rule.listen_port));
        }
        if rule.protocol.udp() {
            unit.push_str(&format!("SocketBindAllow=udp:{}\n", rule.listen_port));
        }
    }
    unit.push_str("Slice=relaydeck.slice\n");
    Ok(unit)
}

fn allowed_port_intervals(policy: &BrokerPolicy) -> String {
    let mut excluded: Vec<u16> = policy
        .reserved_ports
        .iter()
        .copied()
        .chain([22, 80, 443])
        .filter(|port| (policy.allowed_port_start..=policy.allowed_port_end).contains(port))
        .collect();
    excluded.sort_unstable();
    excluded.dedup();
    let mut cursor = u32::from(policy.allowed_port_start);
    let mut ranges = Vec::new();
    let end = u32::from(policy.allowed_port_end);
    for port in excluded.into_iter().map(u32::from).chain([end + 1]) {
        if cursor < port {
            ranges.push(if cursor == port - 1 {
                cursor.to_string()
            } else {
                format!("{cursor}-{}", port - 1)
            });
        }
        cursor = port + 1;
    }
    ranges.join(", ")
}

pub fn render_nft(
    policy: &BrokerPolicy,
    plans: &[RuntimePlan],
    local_ips: &[IpAddr],
    timestamp: i64,
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
            plan.stopped()
                || (plan.port_start() >= policy.allowed_port_start
                    && plan.port_end() <= policy.allowed_port_end),
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
    let intervals = allowed_port_intervals(policy);
    // add+flush only this fixed table, in a single nft transaction. Never flush
    // the host ruleset, and never depend on an accept overriding another table.
    let mut rules = String::from(
        "add table inet relaydeck\nflush table inet relaydeck\ntable inet relaydeck {\n",
    );
    if !intervals.is_empty() {
        rules.push_str(&format!(" set managed_ports {{ type inet_service; flags interval; elements = {{ {intervals} }}; }}\n"));
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
    if !intervals.is_empty() {
        rules.push_str(
            "  tcp dport @managed_ports jump ingress\n  udp dport @managed_ports jump ingress\n",
        );
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
    stop_attempts: Mutex<BTreeMap<i64, u8>>,
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

pub fn validate_listener_inventory(policy: &BrokerPolicy, output: &str) -> anyhow::Result<()> {
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
        if !(policy.allowed_port_start..=policy.allowed_port_end).contains(&port)
            || policy.reserved_ports.contains(&port)
            || [22, 80, 443].contains(&port)
        {
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
            (policy.uid_start..policy.uid_start + policy.max_owners).contains(&uid),
            "managed port {port} already belongs to another service"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn secure_root_path(path: &Path, directory: bool) -> anyhow::Result<()> {
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
fn secure_root_path(_path: &Path, _directory: bool) -> anyhow::Result<()> {
    anyhow::bail!("the production executor requires Linux")
}

#[cfg(target_os = "linux")]
fn validate_uid_pool(policy: &BrokerPolicy) -> anyhow::Result<()> {
    let passwd = std::fs::read_to_string("/etc/passwd")?;
    for line in passwd.lines() {
        if let Some(uid) = line
            .split(':')
            .nth(2)
            .and_then(|field| field.parse::<u32>().ok())
        {
            ensure!(
                uid < policy.uid_start || uid >= policy.uid_start + policy.max_owners,
                "dedicated runtime UID already belongs to a system account"
            );
        }
    }
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
fn private_database(policy: &BrokerPolicy) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let parent = policy
        .database
        .parent()
        .context("missing database parent")?;
    secure_root_path(parent, true)?;
    // A root-owned, non-writable parent prevents pathname swaps by the Web UID,
    // including SQLite's automatically opened -wal and -shm names.
    for suffix in ["", "-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", policy.database.display()));
        if !path.try_exists()? && !suffix.is_empty() {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?;
            use std::os::fd::AsRawFd;
            // This new file is exclusively inside the verified root directory.
            ensure!(
                unsafe { libc::fchown(file.as_raw_fd(), policy.web_uid, policy.web_uid) } == 0,
                "cannot assign SQLite sidecar owner"
            );
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.uid() == policy.web_uid
                && metadata.mode() & 0o077 == 0,
            "SQLite files must be private, single-link regular files owned by web_uid"
        );
    }
    Ok(())
}

async fn command(program: &str, args: &[&str], input: Option<&[u8]>) -> anyhow::Result<Vec<u8>> {
    use std::process::Stdio;
    let mut builder = Command::new(program);
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
        .with_context(|| format!("start {program}"))?;
    if let Some(input) = input {
        let mut stdin = child.stdin.take().context("missing command stdin")?;
        tokio::time::timeout(COMMAND_TIMEOUT, stdin.write_all(input))
            .await
            .context("command input timed out")??;
        drop(stdin);
    }
    let output = tokio::time::timeout(COMMAND_TIMEOUT, child.wait_with_output())
        .await
        .context("runtime command timed out")??;
    ensure!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .filter(|value| !value.is_control())
            .take(240)
            .collect::<String>()
    );
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
            for tool in [SYSTEMCTL, NFT, SS, IP, BPFTOOL] {
                secure_root_path(Path::new(tool), false)?;
            }
            validate_uid_pool(&policy)?;
            for flags in ["-Hlnte", "-Hlnue"] {
                let listeners = command(SS, &[flags], None).await?;
                validate_listener_inventory(&policy, std::str::from_utf8(&listeners)?)?;
            }
            write_root_file(&Path::new(UNIT_DIR).join("relaydeck.slice"), b"[Unit]\nDescription=RelayDeck runtime budget\n\n[Slice]\nMemoryHigh=256M\nMemoryMax=384M\nMemorySwapMax=0\nTasksMax=176\nCPUQuota=150%\n", 0o644, 0)?;
            command(SYSTEMCTL, &["daemon-reload"], None).await?;
            let driver = Self {
                policy,
                plans: Mutex::new(BTreeMap::new()),
                firewall_digest: Mutex::new(None),
                stop_attempts: Mutex::new(BTreeMap::new()),
            };
            // On broker restart discard every old runtime first; reconstruct
            // desired state from fresh DB snapshots rather than trusting files.
            let plans = driver.plans.lock().await;
            fail_closed_cleanup(driver.firewall(&plans), driver.stop_all_services()).await?;
            drop(plans);
            Ok(driver)
        }
    }

    async fn firewall(&self, plans: &BTreeMap<i64, RuntimePlan>) -> anyhow::Result<()> {
        let addresses = interface_ips().await?;
        let nft = render_nft(
            &self.policy,
            &plans.values().cloned().collect::<Vec<_>>(),
            &addresses,
            now(),
        )?;
        command(NFT, &["--check", "-f", "-"], Some(nft.as_bytes())).await?;
        command(NFT, &["-f", "-"], Some(nft.as_bytes())).await?;
        let actual = command(NFT, &["-j", "list", "table", "inet", "relaydeck"], None).await?;
        let value: serde_json::Value = serde_json::from_slice(&actual)?;
        *self.firewall_digest.lock().await = Some(serde_json::to_vec(&value)?);
        Ok(())
    }

    pub async fn unhealthy_owners(&self) -> Vec<(i64, i64, String)> {
        let plans = self.plans.lock().await;
        let global = async {
            let actual = command(NFT, &["-j", "list", "table", "inet", "relaydeck"], None).await?;
            let value: serde_json::Value = serde_json::from_slice(&actual)?;
            ensure!(
                self.firewall_digest.lock().await.as_ref() == Some(&serde_json::to_vec(&value)?),
                "runtime firewall changed outside the executor"
            );
            interface_ips().await
        }
        .await;
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
                self.confirm_listeners(plan.owner_id(), Some(plan)).await?;
                self.confirm_service(plan).await
            }
            .await;
            if let Err(error) = check {
                unhealthy.push((plan.owner_id(), plan.revision(), error.to_string()));
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
                == "402653184",
            "aggregate runtime memory limit is not enforced"
        );
        for (file, expected) in [
            ("memory.high", "33554432"),
            ("memory.max", "67108864"),
            ("memory.swap.max", "0"),
            ("pids.max", "16"),
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
            quota.len() == 2 && quota[0] > 0 && quota[0].checked_mul(5) == Some(quota[1]),
            "effective CPU quota differs"
        );
        let output = command(
            BPFTOOL,
            &[
                "-j",
                "cgroup",
                "show",
                directory.to_str().context("invalid cgroup path")?,
            ],
            None,
        )
        .await?;
        let programs: Vec<serde_json::Value> =
            serde_json::from_slice(&output).context("no socket-bind BPF programs attached")?;
        for hook in ["cgroup_inet4_bind", "cgroup_inet6_bind"] {
            let short = if hook == "cgroup_inet4_bind" {
                "bind4"
            } else {
                "bind6"
            };
            ensure!(
                programs.iter().any(|program| program
                    .get("attach_type")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| value == hook || value == short)
                    && program
                        .get("id")
                        .and_then(serde_json::Value::as_u64)
                        .is_some_and(|id| id > 0)),
                "socket-bind BPF hook {hook} is not attached"
            );
        }
        Ok(())
    }

    async fn stop_service(&self, owner_id: i64) -> anyhow::Result<()> {
        let mut attempts = self.stop_attempts.lock().await;
        let count = attempts.entry(owner_id).or_default();
        ensure!(
            *count < 3,
            "runtime stop retry limit reached; operator action required"
        );
        *count += 1;
        drop(attempts);
        let result = self.stop_service_inner(owner_id).await;
        if result.is_ok() {
            self.stop_attempts.lock().await.remove(&owner_id);
        }
        result
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
        self.confirm_listeners(owner_id, None).await
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
            plan.stopped()
                || (plan.port_start() >= self.policy.allowed_port_start
                    && plan.port_end() <= self.policy.allowed_port_end),
            "account grant exceeds root global port boundary"
        );
        let mut plans = self.plans.lock().await;
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
            write_root_file(
                &directory.join("realm.json"),
                &plan.realm_json()?,
                0o640,
                uid,
            )?;
            let unit = format!("relaydeck-owner-{}.service", plan.owner_id());
            write_root_file(
                &Path::new(UNIT_DIR).join(&unit),
                render_systemd(&self.policy, &plan, now())?.as_bytes(),
                0o644,
                0,
            )?;
            command(SYSTEMCTL, &["daemon-reload"], None).await?;
            plans.insert(plan.owner_id(), plan.clone());
            self.firewall(&plans).await?;
            command(SYSTEMCTL, &["start", &unit], None).await?;
            // realm may start successfully before every async listener binds.
            for attempt in 0..3 {
                if plan.expires_at().is_some_and(|expiry| expiry <= now()) {
                    anyhow::bail!("account expired during start");
                }
                match self.confirm_listeners(plan.owner_id(), Some(&plan)).await {
                    Ok(()) => break,
                    Err(error) if attempt == 2 => return Err(error),
                    Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
                }
            }
            self.confirm_service(&plan).await?;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("the production executor requires Linux");
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
        fail_closed_cleanup(self.firewall(&plans), self.stop_service(owner_id)).await
    }

    #[cfg(target_os = "linux")]
    async fn shutdown(&self) -> anyhow::Result<()> {
        let mut plans = self.plans.lock().await;
        plans.clear();
        fail_closed_cleanup(self.firewall(&plans), self.stop_all_services()).await
    }
}

impl ExecutorDriver for LinuxDriver {
    fn apply<'a>(&'a self, plan: &'a RuntimePlan) -> DriverFuture<'a> {
        Box::pin(async move {
            self.apply_plan(plan)
                .await
                .map_err(|error| DriverError::new(error.to_string()))
        })
    }

    fn stop(&self, owner_id: i64) -> DriverFuture<'_> {
        Box::pin(async move {
            self.stop_owner(owner_id)
                .await
                .map_err(|error| DriverError::new(error.to_string()))
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

#[cfg(target_os = "linux")]
async fn heartbeat(pool: &SqlitePool, status: &str) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO executor_status(id,last_seen,status) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,status=excluded.status")
        .bind(now()).bind(status).execute(pool).await?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn stop_previous_units() -> anyhow::Result<()> {
    // A rejected policy cannot authorize any dynamic command arguments. The
    // previous generated units have a fixed namespace and root-owned marker.
    secure_root_path(Path::new(UNIT_DIR), true)?;
    secure_root_path(Path::new(SYSTEMCTL), false)?;
    let mut failures = Vec::new();
    for owner in 1..=11 {
        let unit = format!("relaydeck-owner-{owner}.service");
        let path = Path::new(UNIT_DIR).join(&unit);
        let exists = match path.try_exists() {
            Ok(value) => value,
            Err(error) => {
                failures.push(format!("owner {owner}: {error}"));
                continue;
            }
        };
        if !exists {
            continue;
        }
        let stopped = async {
            secure_root_path(&path, false)?;
            ensure!(
                std::fs::read_to_string(&path)?
                    .starts_with(&format!("[Unit]\nDescription=RelayDeck account {owner}\n")),
                "unit namespace collision"
            );
            command(SYSTEMCTL, &["stop", &unit], None).await?;
            let output = command(
                SYSTEMCTL,
                &["show", "--property=ActiveState", "--value", &unit],
                None,
            )
            .await?;
            ensure!(
                matches!(std::str::from_utf8(&output)?.trim(), "inactive" | "failed"),
                "previous runtime still active"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = stopped {
            failures.push(format!("owner {owner}: {error}"));
        }
    }
    ensure!(failures.is_empty(), "{}", failures.join("; "));
    Ok(())
}

pub async fn run(policy_path: &Path) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy_path;
        anyhow::bail!("the production executor requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "the production executor requires root"
        );
        let setup = async {
        secure_root_path(policy_path, false)?;
        ensure!(
            std::fs::metadata(policy_path)?.len() <= 16 * 1024,
            "broker policy too large"
        );
        let policy: BrokerPolicy = serde_json::from_slice(&std::fs::read(policy_path)?)?;
        policy.validate()?;
        private_database(&policy)?;
        let options = SqliteConnectOptions::new()
            .filename(&policy.database)
            .create_if_missing(false)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(3))
            .pragma("trusted_schema", "OFF")
            .pragma("temp_store", "MEMORY");
        let pool = SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await?;
        // Migrations are performed by the Web application's normal startup;
        // root only opens the explicitly provisioned database, never migrates.
        let expected_tables: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('users','rules','port_leases','apply_jobs','runtime_states','executor_status')").fetch_one(&pool).await?;
        ensure!(
            expected_tables == 6,
            "run the application migrations before the executor"
        );
        heartbeat(&pool, "failed").await?;
        let driver = Arc::new(LinuxDriver::new(policy.clone()).await?);
        let addresses = interface_ips().await?;
        let reconciler = Reconciler::new(
            pool.clone(),
            policy.boundary(policy.local_ips.iter().copied().chain(addresses).collect()),
            driver.clone(),
            Duration::from_secs(30),
        )?;
        Ok::<_,anyhow::Error>((pool, driver, reconciler))
        }.await;
        let (pool, driver, reconciler) = match setup {
            Ok(state) => state,
            Err(error) => {
                let stopped = stop_previous_units().await;
                return match stopped {
                    Ok(()) => {
                        Err(error.context("executor startup rejected; previous runtimes stopped"))
                    }
                    Err(stop) => Err(anyhow::anyhow!(
                        "executor startup rejected: {error}; previous runtime cleanup failed: {stop}"
                    )),
                };
            }
        };
        let result = async {
        for owner in reconciler.startup_owners().await? { reconciler.reconcile_owner(owner).await?; }
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut stop_failures: BTreeMap<i64, u8> = BTreeMap::new();
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let mut failed = !stop_failures.is_empty();
                    for owner in stop_failures.keys().copied().collect::<Vec<_>>() {
                        if let Err(error) = driver.stop(owner).await {
                            let attempts = stop_failures.get_mut(&owner).expect("retry owner exists");
                            *attempts += 1;
                            tracing::error!(owner_id=owner, %error, attempts=*attempts, "runtime stop retry failed");
                            heartbeat(&pool, "failed").await?;
                            ensure!(*attempts < 3, "runtime stop failed three times; operator action required");
                        } else { stop_failures.remove(&owner); }
                    }
                    for owner in reconciler.pending_owners().await? {
                        if stop_failures.contains_key(&owner) { continue; }
                        if let Err(error) = reconciler.reconcile_owner(owner).await {
                            tracing::error!(owner_id=owner, %error, "runtime reconciliation failed");
                            if matches!(error, crate::executor::ReconcileError::Stop(_)) { stop_failures.insert(owner, 1); }
                            failed = true;
                        }
                    }
                    for (owner, revision, message) in driver.unhealthy_owners().await {
                        failed = true;
                        if let Err(error) = driver.stop(owner).await {
                            let attempts = stop_failures.entry(owner).or_default();
                            *attempts += 1;
                            tracing::error!(owner_id=owner, %error, attempts=*attempts, "unhealthy runtime stop failed");
                            heartbeat(&pool, "failed").await?;
                            ensure!(*attempts < 3, "runtime stop failed three times; operator action required");
                        } else {
                            stop_failures.remove(&owner);
                        }
                        sqlx::query("UPDATE runtime_states SET status='failed',last_error=?,updated_at=? WHERE owner_id=? AND revision=?")
                            .bind(message.chars().filter(|value| !value.is_control()).take(240).collect::<String>()).bind(now()).bind(owner).bind(revision).execute(&pool).await?;
                    }
                    heartbeat(&pool, if failed { "failed" } else { "running" }).await?;
                },
                _ = terminate.recv() => break,
                _ = tokio::signal::ctrl_c() => break,
            }
        }
        Ok::<_, anyhow::Error>(())
        }.await;
        // The tenant runner enforces absolute expiry even when the broker dies.
        // RuntimeMaxSec is an additional systemd lifetime bound.
        let pulse = heartbeat(&pool, "failed").await;
        let shutdown = driver.shutdown().await;
        pool.close().await;
        result?;
        pulse?;
        shutdown
    }
}
