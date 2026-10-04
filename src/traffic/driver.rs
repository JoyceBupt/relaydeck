use super::{TrafficBudget, TrafficGrant, TrafficSnapshot, kernel_values, utc_month};
use crate::{
    executor::RuntimePlan,
    linux::{
        BrokerPolicy, WireguardPeer, command, firewall_fingerprint, secure_root_path,
        write_root_file,
    },
};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

const NFT: &str = "/usr/sbin/nft";
const TABLE: &str = "relaydeck_usage";
const GUARD: &str = "relaydeck_usage_guard";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Account {
    budget: TrafficBudget,
    incoming: u64,
    outgoing: u64,
    charged: u64,
    applied: Option<TrafficBudget>,
    prepared: bool,
}
impl Account {
    fn used(&self) -> u64 {
        self.charged
            .max(self.budget.mode.usage(self.incoming, self.outgoing))
    }
    fn blocked(&self) -> bool {
        self.budget
            .limit_bytes
            .is_some_and(|limit| self.used() >= limit as u64)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u8,
    period: i64,
    reset_at: i64,
    accounts: BTreeMap<i64, Account>,
}

pub struct TrafficMeter {
    policy: BrokerPolicy,
    path: PathBuf,
    ledger: Ledger,
    initialized: bool,
    expected: Option<Vec<u8>>,
    plans: Vec<RuntimePlan>,
    peers: Vec<WireguardPeer>,
    clock: fn() -> i64,
}

impl TrafficMeter {
    pub fn open(policy: BrokerPolicy) -> anyhow::Result<Self> {
        Self::open_with_clock(policy, crate::db::now)
    }

    pub fn open_with_clock(policy: BrokerPolicy, clock: fn() -> i64) -> anyhow::Result<Self> {
        policy.validate()?;
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "traffic meter requires root"
        );
        let path = policy.runtime_dir.join("traffic-ledger.json");
        let (period, reset_at) = utc_month(clock())?;
        let ledger = match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                use std::os::unix::fs::MetadataExt;
                secure_root_path(&path, false)?;
                ensure!(
                    meta.mode() & 0o077 == 0,
                    "traffic ledger must remain private to root"
                );
                ensure!(meta.len() <= 64 * 1024, "traffic ledger too large");
                let ledger: Ledger = serde_json::from_slice(&std::fs::read(&path)?)?;
                ensure!(
                    ledger.version == 1 && ledger.accounts.len() <= policy.max_owners as usize,
                    "invalid traffic ledger version or size"
                );
                ensure!(
                    utc_month(ledger.period)? == (ledger.period, ledger.reset_at),
                    "invalid stored traffic period"
                );
                for (owner, account) in &ledger.accounts {
                    policy.uid(*owner)?;
                    account.budget.validate()?;
                    if let Some(applied) = &account.applied {
                        applied.validate()?;
                    }
                    ensure!(
                        !account.prepared || account.applied.as_ref() == Some(&account.budget),
                        "inconsistent prepared traffic grant"
                    );
                }
                ledger
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ledger {
                version: 1,
                period,
                reset_at,
                accounts: BTreeMap::new(),
            },
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            policy,
            path,
            ledger,
            initialized: false,
            expected: None,
            plans: Vec::new(),
            peers: Vec::new(),
            clock,
        })
    }

    fn names(&self, owner: i64, account: &Account) -> (String, String, String) {
        (
            format!("rx_{owner}_{}", self.ledger.period),
            format!("tx_{owner}_{}", self.ledger.period),
            format!(
                "q_{owner}_{}_{}",
                self.ledger.period,
                account.budget.mode.as_str()
            ),
        )
    }

    fn persist(&self) -> anyhow::Result<()> {
        write_root_file(&self.path, &serde_json::to_vec(&self.ledger)?, 0o600, 0)?;
        std::fs::File::open(&self.policy.runtime_dir)?.sync_all()?;
        Ok(())
    }

    async fn apply(text: &str) -> anyhow::Result<()> {
        command(NFT, &["--check", "-f", "-"], Some(text.as_bytes())).await?;
        command(NFT, &["-f", "-"], Some(text.as_bytes())).await?;
        Ok(())
    }

    async fn table() -> anyhow::Result<Option<serde_json::Value>> {
        let tables: serde_json::Value =
            serde_json::from_slice(&command(NFT, &["-j", "list", "tables"], None).await?)?;
        let found = tables["nftables"]
            .as_array()
            .context("missing nft table inventory")?
            .iter()
            .any(|entry| entry["table"]["name"] == TABLE && entry["table"]["family"] == "inet");
        if found {
            Ok(Some(serde_json::from_slice(
                &command(NFT, &["-j", "list", "table", "inet", TABLE], None).await?,
            )?))
        } else {
            Ok(None)
        }
    }

    fn absorb(&mut self, value: &serde_json::Value) -> anyhow::Result<()> {
        let values = kernel_values(value)?;
        let period = self.ledger.period;
        for (owner, account) in &mut self.ledger.accounts {
            account.incoming = account
                .incoming
                .max(*values.get(&format!("rx_{owner}_{period}")).unwrap_or(&0));
            account.outgoing = account
                .outgoing
                .max(*values.get(&format!("tx_{owner}_{period}")).unwrap_or(&0));
            account.charged = account.charged.max(
                *values
                    .get(&format!(
                        "q_{owner}_{period}_{}",
                        account.budget.mode.as_str()
                    ))
                    .unwrap_or(&0),
            );
        }
        Ok(())
    }

    fn roll_clock(&mut self, timestamp: i64) -> anyhow::Result<bool> {
        let (period, reset_at) = utc_month(timestamp)?;
        // A backward clock correction must never create free traffic credits.
        if period <= self.ledger.period {
            return Ok(false);
        }
        self.ledger.period = period;
        self.ledger.reset_at = reset_at;
        for account in self.ledger.accounts.values_mut() {
            account.incoming = 0;
            account.outgoing = 0;
            account.charged = 0;
        }
        Ok(true)
    }

    async fn freeze(&self, owners: &[i64]) -> anyhow::Result<()> {
        let mut uids = owners
            .iter()
            .map(|owner| self.policy.uid(*owner).map(|uid| uid.to_string()))
            .collect::<anyhow::Result<Vec<_>>>()?;
        uids.sort();
        uids.dedup();
        let mut ports = self
            .plans
            .iter()
            .filter(|plan| owners.contains(&plan.owner_id()))
            .flat_map(|plan| plan.rules().iter().map(|rule| rule.listen_port.to_string()))
            .collect::<Vec<_>>();
        ports.sort();
        ports.dedup();
        let mut text = format!(
            "add table inet {GUARD}\nflush table inet {GUARD}\nadd chain inet {GUARD} input {{type filter hook input priority -20;policy accept;}}\nadd chain inet {GUARD} output {{type filter hook output priority -20;policy accept;}}\nadd rule inet {GUARD} input ct direction reply return\n"
        );
        if !ports.is_empty() {
            for protocol in ["tcp", "udp"] {
                text.push_str(&format!(
                    "add rule inet {GUARD} input {protocol} dport {{ {} }} drop\n",
                    ports.join(",")
                ));
            }
        }
        if !uids.is_empty() {
            text.push_str(&format!(
                "add rule inet {GUARD} output meta skuid {{ {} }} drop\n",
                uids.join(",")
            ));
        }
        Self::apply(&text).await
    }

    async fn thaw() -> anyhow::Result<()> {
        command(NFT, &["delete", "table", "inet", GUARD], None).await?;
        Ok(())
    }

    async fn release_guard(&self) -> anyhow::Result<()> {
        let blocked = self
            .ledger
            .accounts
            .iter()
            .filter(|(_, account)| !account.prepared)
            .map(|(owner, _)| *owner)
            .collect::<Vec<_>>();
        if blocked.is_empty() {
            Self::thaw().await
        } else {
            self.freeze(&blocked).await
        }
    }

    fn account_rules(&self, owner: i64, account: &Account) -> String {
        let (rx, tx, quota) = self.names(owner, account);
        let mut text = String::new();
        if let Some(limit) = account.budget.limit_bytes {
            text.push_str(&format!(
                "add quota inet {TABLE} {quota} {{over {limit} bytes used {} bytes;}}\n",
                account.used()
            ));
        }
        if account.blocked() {
            text.push_str(&format!(
                "add element inet {TABLE} blocked_{owner} {{ipv4,ipv6}}\n"
            ));
        }
        for (chain, counter, billed) in [
            (
                "rx",
                rx,
                !matches!(account.budget.mode, super::TrafficMode::Egress),
            ),
            (
                "tx",
                tx,
                !matches!(account.budget.mode, super::TrafficMode::Ingress),
            ),
        ] {
            text.push_str(&format!("add rule inet {TABLE} {chain}_{owner} meta nfproto @blocked_{owner} drop\nadd rule inet {TABLE} {chain}_{owner} counter name {counter}\n"));
            if billed && account.budget.limit_bytes.is_some() {
                text.push_str(&format!("add rule inet {TABLE} {chain}_{owner} quota name {quota} add @blocked_{owner} {{ipv4}} add @blocked_{owner} {{ipv6}} drop\n"));
            }
        }
        text
    }

    fn routes(&self) -> anyhow::Result<String> {
        let mut text = format!(
            "flush chain inet {TABLE} input\nflush chain inet {TABLE} output\nadd rule inet {TABLE} input ct direction reply return\n"
        );
        let mut marks = self.peers.iter().map(|peer| peer.mark).collect::<Vec<_>>();
        marks.sort_unstable();
        marks.dedup();
        if !marks.is_empty() {
            text.push_str(&format!(
                "add rule inet {TABLE} output meta mark {{ {} }} return\n",
                marks
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        for plan in &self.plans {
            ensure!(
                self.ledger.accounts.contains_key(&plan.owner_id()),
                "account traffic grant is not configured"
            );
            let uid = self.policy.uid(plan.owner_id())?;
            for rule in plan.rules() {
                for (protocol, allowed) in
                    [("tcp", rule.protocol.tcp()), ("udp", rule.protocol.udp())]
                {
                    if !allowed {
                        continue;
                    }
                    text.push_str(&format!("add rule inet {TABLE} input ct direction original {protocol} dport {} jump rx_{}\n",rule.listen_port,plan.owner_id()));
                    text.push_str(&format!("add rule inet {TABLE} output meta skuid {uid} ct direction reply {protocol} sport {} ct original proto-dst {} jump tx_{}\n",rule.listen_port,rule.listen_port,plan.owner_id()));
                }
            }
        }
        Ok(text)
    }

    async fn remember(&mut self) -> anyhow::Result<()> {
        let value = Self::table().await?.context("traffic table disappeared")?;
        self.expected = Some(firewall_fingerprint(&value)?);
        Ok(())
    }

    async fn rebuild(&mut self) -> anyhow::Result<()> {
        // Recovery freezes the client legs while taking a final counter snapshot.
        let owners = self.ledger.accounts.keys().copied().collect::<Vec<_>>();
        self.freeze(&owners).await?;
        if let Some(value) = Self::table().await? {
            self.absorb(&value)?;
        }
        self.persist()?;
        let mut text = format!(
            "add table inet {TABLE}\nflush table inet {TABLE}\nadd chain inet {TABLE} input {{type filter hook input priority -9;policy accept;}}\nadd chain inet {TABLE} output {{type filter hook output priority -9;policy accept;}}\n"
        );
        for (owner, account) in &self.ledger.accounts {
            let (rx, tx, _) = self.names(*owner, account);
            text.push_str(&format!("add counter inet {TABLE} {rx} {{packets 0 bytes {};}}\nadd counter inet {TABLE} {tx} {{packets 0 bytes {};}}\nadd set inet {TABLE} blocked_{owner} {{type nf_proto;flags dynamic;size 2;}}\nadd chain inet {TABLE} rx_{owner}\nadd chain inet {TABLE} tx_{owner}\n",account.incoming,account.outgoing));
        }
        text.push_str(&self.routes()?);
        Self::apply(&text).await?;
        for owner in owners {
            let result =
                Self::apply(&self.account_rules(owner, &self.ledger.accounts[&owner])).await;
            let account = self.ledger.accounts.get_mut(&owner).unwrap();
            account.prepared = result.is_ok();
            account.applied = result.is_ok().then(|| account.budget.clone());
            if let Err(error) = result {
                tracing::error!(owner,%error,"account traffic policy is quarantined");
            }
        }
        self.persist()?;
        self.remember().await?;
        self.initialized = true;
        self.release_guard().await?;
        Ok(())
    }

    async fn initialize(&mut self) -> anyhow::Result<()> {
        if self.initialized {
            return Ok(());
        }
        if Self::table().await?.is_some() {
            ensure!(
                self.path.try_exists()?,
                "traffic ledger missing; restore its root-owned backup"
            );
        }
        self.roll_clock((self.clock)())?;
        self.rebuild().await
    }

    pub async fn update_routes(
        &mut self,
        plans: Vec<RuntimePlan>,
        peers: Vec<WireguardPeer>,
    ) -> anyhow::Result<()> {
        self.initialize().await?;
        self.plans = plans;
        self.peers = peers;
        Self::apply(&self.routes()?).await?;
        self.remember().await
    }

    pub async fn synchronize(
        &mut self,
        grants: &[TrafficGrant],
    ) -> anyhow::Result<Vec<TrafficSnapshot>> {
        ensure!(
            grants.len() <= self.policy.max_owners as usize,
            "too many traffic grants"
        );
        let mut desired = BTreeMap::new();
        for grant in grants {
            self.policy.uid(grant.owner_id)?;
            grant.budget.validate()?;
            ensure!(
                desired
                    .insert(grant.owner_id, grant.budget.clone())
                    .is_none(),
                "duplicate traffic grant"
            );
        }
        self.initialize().await?;
        self.check_month().await?;
        if let Some(value) = Self::table().await? {
            self.absorb(&value)?;
            if self.expected.as_ref() != Some(&firewall_fingerprint(&value)?) {
                self.rebuild().await?;
            }
        } else {
            self.rebuild().await?;
        }
        let changed = desired
            .iter()
            .filter(|(owner, budget)| {
                self.ledger
                    .accounts
                    .get(owner)
                    .is_none_or(|account| !account.prepared || account.budget != **budget)
            })
            .map(|(owner, _)| *owner)
            .collect::<Vec<_>>();
        if !changed.is_empty() {
            let mut frozen = changed.clone();
            frozen.extend(
                self.ledger
                    .accounts
                    .iter()
                    .filter(|(_, account)| !account.prepared)
                    .map(|(owner, _)| *owner),
            );
            self.freeze(&frozen).await?;
            if let Some(value) = Self::table().await? {
                self.absorb(&value)?;
            }
            let present =
                kernel_values(&Self::table().await?.context("traffic table disappeared")?)?;
            for owner in changed {
                let mut text = String::new();
                let previous = self.ledger.accounts.get(&owner).cloned();
                let dummy = Account {
                    budget: desired[&owner].clone(),
                    incoming: 0,
                    outgoing: 0,
                    charged: 0,
                    prepared: false,
                    applied: None,
                };
                let (rx, tx, _) = self.names(owner, &dummy);
                if present.contains_key(&rx) && present.contains_key(&tx) {
                    text.push_str(&format!("flush chain inet {TABLE} rx_{owner}\nflush chain inet {TABLE} tx_{owner}\nflush set inet {TABLE} blocked_{owner}\n"));
                    if let Some(applied) = previous
                        .as_ref()
                        .and_then(|account| account.applied.as_ref())
                        && applied.limit_bytes.is_some()
                    {
                        let q =
                            format!("q_{owner}_{}_{}", self.ledger.period, applied.mode.as_str());
                        text.push_str(&format!("delete quota inet {TABLE} {q}\n"));
                    }
                } else {
                    let base = format!(
                        "add counter inet {TABLE} {rx}\nadd counter inet {TABLE} {tx}\nadd set inet {TABLE} blocked_{owner} {{type nf_proto;flags dynamic;size 2;}}\nadd chain inet {TABLE} rx_{owner}\nadd chain inet {TABLE} tx_{owner}\n"
                    );
                    Self::apply(&base).await?;
                }
                let mut account = previous.unwrap_or(dummy);
                if account.budget.mode != desired[&owner].mode {
                    account.charged = 0;
                }
                account.budget = desired[&owner].clone();
                account.prepared = false;
                text.push_str(&self.account_rules(owner, &account));
                self.ledger.accounts.insert(owner, account);
                self.persist()?;
                let result = Self::apply(&text).await;
                let account = self.ledger.accounts.get_mut(&owner).unwrap();
                account.prepared = result.is_ok();
                if account.prepared {
                    account.applied = Some(account.budget.clone());
                }
                if let Err(error) = result {
                    tracing::error!(owner,%error,"account traffic grant is quarantined; retrying independently");
                }
            }
            self.persist()?;
            self.remember().await?;
            self.release_guard().await?;
        }
        self.persist()?;
        let observed_at = (self.clock)();
        Ok(self
            .ledger
            .accounts
            .iter()
            .map(|(owner, account)| TrafficSnapshot {
                owner_id: *owner,
                budget: account.budget.clone(),
                in_bytes: account.incoming,
                out_bytes: account.outgoing,
                used_bytes: account.used(),
                period_start: self.ledger.period,
                reset_at: self.ledger.reset_at,
                blocked: !account.prepared || account.blocked(),
                ready: account.prepared,
                error: (!account.prepared).then(|| "流量策略未就绪".into()),
                observed_at,
            })
            .collect())
    }

    pub async fn check_month(&mut self) -> anyhow::Result<()> {
        if self.roll_clock((self.clock)())? {
            self.rebuild().await?;
        }
        Ok(())
    }

    pub fn authorized(&self, owner: i64, budget: Option<&TrafficBudget>) -> bool {
        self.ledger.accounts.get(&owner).is_some_and(|account| {
            account.prepared
                && !account.blocked()
                && budget.map_or(account.budget.limit_bytes.is_none(), |budget| {
                    budget == &account.budget
                })
        })
    }
}
