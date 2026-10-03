use std::{
    collections::HashSet,
    future::Future,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    pin::Pin,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sqlx::{Sqlite, SqlitePool, Transaction};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{db::now, policy};

pub const MAX_RULES: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Both,
}

impl Protocol {
    pub fn tcp(self) -> bool {
        matches!(self, Self::Tcp | Self::Both)
    }

    pub fn udp(self) -> bool {
        matches!(self, Self::Udp | Self::Both)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredRule {
    pub id: i64,
    pub listen_port: u16,
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub protocol: Protocol,
    pub source_cidrs: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredPlan {
    pub owner_id: i64,
    pub revision: i64,
    pub enabled: bool,
    pub expires_at: Option<i64>,
    pub port_start: u16,
    pub port_end: u16,
    pub max_rules: u8,
    pub rules: Vec<DesiredRule>,
}

#[derive(Debug, Clone, Default)]
pub struct ExecutorPolicy {
    pub reserved_ports: Vec<u16>,
    pub local_ips: Vec<IpAddr>,
}

#[derive(Debug, Error)]
pub enum PlanError {
    #[error("invalid owner identifier or revision")]
    Identity,
    #[error("too many forwarding rules")]
    RuleLimit,
    #[error("duplicate rule identifier or listening port")]
    Duplicate,
    #[error("invalid rule identifier or target port")]
    RuleIdentity,
    #[error(transparent)]
    Policy(#[from] policy::PolicyError),
    #[error("invalid stored forwarding rule")]
    StoredRule,
    #[error("forwarding port reservation is missing or belongs to another rule")]
    Lease,
}

// The fields are private: runtime commands are built only after policy checks.
// A broker receiving JSON must decode DesiredPlan and validate it again using
// its own policy, rather than accepting a caller's already-validated assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePlan {
    owner_id: i64,
    revision: i64,
    expires_at: Option<i64>,
    port_start: u16,
    port_end: u16,
    max_rules: u8,
    rules: Vec<DesiredRule>,
}

impl DesiredPlan {
    pub fn available_at(&self, timestamp: i64) -> bool {
        self.enabled && self.expires_at.is_none_or(|expiry| expiry > timestamp)
    }

    pub fn validate(
        &self,
        boundary: &ExecutorPolicy,
        timestamp: i64,
    ) -> Result<RuntimePlan, PlanError> {
        if self.owner_id <= 0 || self.revision < 0 {
            return Err(PlanError::Identity);
        }
        // Revocation remains executable even when old desired rules are corrupt
        // or their grant has been narrowed beyond the previous rule settings.
        if !self.available_at(timestamp) {
            return Ok(RuntimePlan {
                owner_id: self.owner_id,
                revision: self.revision,
                expires_at: self.expires_at,
                port_start: self.port_start,
                port_end: self.port_end,
                max_rules: self.max_rules,
                rules: Vec::new(),
            });
        }
        policy::validate_port_grant(
            i64::from(self.port_start),
            i64::from(self.port_end),
            i64::from(self.max_rules),
        )?;
        if self.rules.len() > MAX_RULES {
            return Err(PlanError::RuleLimit);
        }
        let mut identifiers = HashSet::new();
        let mut ports = HashSet::new();
        let mut rules = Vec::new();
        for rule in self.rules.iter().filter(|rule| rule.enabled) {
            if rule.id <= 0 || rule.target_port == 0 {
                return Err(PlanError::RuleIdentity);
            }
            policy::validate_target_port(rule.target_port)?;
            if !identifiers.insert(rule.id) || !ports.insert(rule.listen_port) {
                return Err(PlanError::Duplicate);
            }
            policy::validate_listen_port(
                i64::from(rule.listen_port),
                i64::from(self.port_start),
                i64::from(self.port_end),
                &boundary.reserved_ports,
            )?;
            policy::validate_target_ip(rule.target_ip, &boundary.local_ips)?;
            let mut normalized = rule.clone();
            normalized.source_cidrs = policy::validate_source_cidrs(&rule.source_cidrs)?;
            rules.push(normalized);
        }
        if rules.len() > usize::from(self.max_rules) {
            return Err(PlanError::RuleLimit);
        }
        rules.sort_unstable_by_key(|rule| (rule.listen_port, rule.id));
        Ok(RuntimePlan {
            owner_id: self.owner_id,
            revision: self.revision,
            expires_at: self.expires_at,
            port_start: self.port_start,
            port_end: self.port_end,
            max_rules: self.max_rules,
            rules,
        })
    }
}

impl RuntimePlan {
    pub fn owner_id(&self) -> i64 {
        self.owner_id
    }

    pub fn revision(&self) -> i64 {
        self.revision
    }

    pub fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }

    pub fn port_start(&self) -> u16 {
        self.port_start
    }

    pub fn port_end(&self) -> u16 {
        self.port_end
    }

    pub fn max_rules(&self) -> u8 {
        self.max_rules
    }

    pub fn rules(&self) -> &[DesiredRule] {
        &self.rules
    }

    // Deserialization is available for root-owned recovery snapshots. It is
    // deliberately followed by these same checks before any runtime action.
    pub fn validate_again(
        &self,
        boundary: &ExecutorPolicy,
        timestamp: i64,
    ) -> Result<Self, PlanError> {
        DesiredPlan {
            owner_id: self.owner_id,
            revision: self.revision,
            enabled: true,
            expires_at: self.expires_at,
            port_start: self.port_start,
            port_end: self.port_end,
            max_rules: self.max_rules,
            rules: self.rules.clone(),
        }
        .validate(boundary, timestamp)
    }

    pub fn stopped(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rule_json(&self, id: i64) -> Result<Vec<u8>, serde_json::Error> {
        let mut single = self.clone();
        single.rules.retain(|rule| rule.id == id);
        single.realm_json()
    }

    pub fn realm_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        #[derive(Serialize)]
        struct Network {
            no_tcp: bool,
            use_udp: bool,
            ipv6_only: bool,
        }
        #[derive(Serialize)]
        struct Endpoint {
            listen: String,
            remote: String,
            network: Network,
        }
        #[derive(Serialize)]
        struct RealmConfig {
            endpoints: Vec<Endpoint>,
        }
        // Source CIDRs are enforced by the executor firewall, not by realm.
        // Only these typed fields can enter the realm configuration. User input
        // cannot enable transports, hooks, interface bindings or DNS lookups.
        let endpoints = self
            .rules
            .iter()
            .map(|rule| Endpoint {
                listen: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), rule.listen_port)
                    .to_string(),
                remote: SocketAddr::new(rule.target_ip, rule.target_port).to_string(),
                network: Network {
                    no_tcp: !rule.protocol.tcp(),
                    use_udp: rule.protocol.udp(),
                    ipv6_only: false,
                },
            })
            .collect();
        serde_json::to_vec_pretty(&RealmConfig { endpoints })
    }
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct DriverError {
    pub message: String,
    pub retryable: bool,
    pub crashed: bool,
}

impl DriverError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
            crashed: false,
        }
    }

    pub fn crashed(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
            crashed: true,
        }
    }
    pub fn temporary(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
            crashed: false,
        }
    }
}

pub type DriverFuture<'a> = Pin<Box<dyn Future<Output = Result<(), DriverError>> + Send + 'a>>;

pub trait ExecutorDriver: Send + Sync {
    // Success means every expected TCP/UDP listener and its source/target
    // filtering has been confirmed. Merely launching a process is insufficient.
    // Implementations must safely cancel, serialize operations per owner, and
    // use fixed process/service identifiers, never caller-supplied shell code.
    fn apply<'a>(&'a self, plan: &'a RuntimePlan) -> DriverFuture<'a>;

    // Success means the account's complete runtime has stopped, including old
    // accepted connections; a pending stop request is not confirmation.
    fn stop(&self, owner_id: i64) -> DriverFuture<'_>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileOutcome {
    Applied,
    Stopped,
    StaleStopped,
    Failed,
    Missing,
}

#[derive(Debug, Error)]
pub enum ReconcileError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("invalid executor timeout")]
    Timeout,
    #[error("invalid owner identifier")]
    Owner,
    #[error("runtime could not be stopped: {0}")]
    Stop(String),
    #[error("broker temporarily unavailable: {0}")]
    Temporary(String),
}

pub struct Reconciler<D: ExecutorDriver> {
    pool: SqlitePool,
    policy: ExecutorPolicy,
    driver: D,
    timeout: Duration,
    operation_lock: Mutex<()>,
}

#[derive(sqlx::FromRow)]
struct PlanUser {
    id: i64,
    enabled: bool,
    expires_at: Option<i64>,
    port_start: i64,
    port_end: i64,
    max_rules: i64,
    desired_revision: i64,
}

#[derive(sqlx::FromRow)]
struct PlanRule {
    id: i64,
    listen_port: i64,
    target_ip: String,
    target_port: i64,
    protocol: String,
    source_cidrs: String,
    enabled: bool,
}

async fn load_plan(
    tx: &mut Transaction<'_, Sqlite>,
    owner_id: i64,
    timestamp: i64,
) -> Result<Option<Result<DesiredPlan, PlanError>>, sqlx::Error> {
    let Some(user) = sqlx::query_as::<_, PlanUser>(
        "SELECT id,enabled,expires_at,port_start,port_end,max_rules,desired_revision FROM users WHERE id=?",
    )
    .bind(owner_id)
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(None);
    };
    let available = user.enabled && user.expires_at.is_none_or(|expiry| expiry > timestamp);
    let raw_rules = if available {
        sqlx::query_as::<_, PlanRule>(
            "SELECT id,listen_port,target_ip,target_port,protocol,source_cidrs,(enabled=1 AND dns_blocked=0) AS enabled FROM rules WHERE owner_id=? AND deleted_at IS NULL ORDER BY id LIMIT 31",
        )
        .bind(owner_id)
        .fetch_all(&mut **tx)
        .await?
    } else {
        Vec::new()
    };
    let invalid_leases: i64 = if available {
        sqlx::query_scalar("SELECT COUNT(*) FROM rules r LEFT JOIN port_leases p ON p.port=r.listen_port WHERE r.owner_id=? AND r.enabled=1 AND r.deleted_at IS NULL AND (p.port IS NULL OR p.owner_id<>r.owner_id OR p.rule_id<>r.id)")
            .bind(owner_id)
            .fetch_one(&mut **tx)
            .await?
    } else {
        0
    };
    let result = (|| {
        // Disabled rules need not remain inside a narrowed authorization. They
        // are not sent to the runtime; malformed dormant data cannot block stop.
        let count = raw_rules.len();
        if count > MAX_RULES {
            return Err(PlanError::RuleLimit);
        }
        if invalid_leases > 0 {
            return Err(PlanError::Lease);
        }
        let rules = raw_rules
            .into_iter()
            .filter(|rule| rule.enabled)
            .map(|rule| {
                Ok(DesiredRule {
                    id: rule.id,
                    listen_port: rule
                        .listen_port
                        .try_into()
                        .map_err(|_| PlanError::StoredRule)?,
                    target_ip: rule.target_ip.parse().map_err(|_| PlanError::StoredRule)?,
                    target_port: rule
                        .target_port
                        .try_into()
                        .map_err(|_| PlanError::StoredRule)?,
                    protocol: match rule.protocol.as_str() {
                        "tcp" => Protocol::Tcp,
                        "udp" => Protocol::Udp,
                        "both" => Protocol::Both,
                        _ => return Err(PlanError::StoredRule),
                    },
                    source_cidrs: serde_json::from_str(&rule.source_cidrs)
                        .map_err(|_| PlanError::StoredRule)?,
                    enabled: true,
                })
            })
            .collect::<Result<_, PlanError>>()?;
        Ok(DesiredPlan {
            owner_id: user.id,
            revision: user.desired_revision,
            enabled: user.enabled,
            expires_at: user.expires_at,
            port_start: user
                .port_start
                .try_into()
                .map_err(|_| PlanError::StoredRule)?,
            port_end: user
                .port_end
                .try_into()
                .map_err(|_| PlanError::StoredRule)?,
            max_rules: user
                .max_rules
                .try_into()
                .map_err(|_| PlanError::StoredRule)?,
            rules,
        })
    })();
    Ok(Some(result))
}

fn error_message(error: impl std::fmt::Display) -> String {
    error
        .to_string()
        .chars()
        .filter(|character| !character.is_control())
        .take(240)
        .collect()
}

impl<D: ExecutorDriver> Reconciler<D> {
    pub fn new(
        pool: SqlitePool,
        policy: ExecutorPolicy,
        driver: D,
        timeout: Duration,
    ) -> Result<Self, ReconcileError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(ReconcileError::Timeout);
        }
        Ok(Self {
            pool,
            policy,
            driver,
            timeout,
            operation_lock: Mutex::new(()),
        })
    }

    pub async fn pending_owners(&self) -> Result<Vec<i64>, ReconcileError> {
        // Expiry is independent of a queued HTTP change. A stopped runtime is
        // excluded so an expired account does not cause endless repeated stops.
        Ok(sqlx::query_scalar(
            "SELECT DISTINCT u.id FROM users u LEFT JOIN runtime_states s ON s.owner_id=u.id WHERE EXISTS (SELECT 1 FROM apply_jobs j WHERE j.owner_id=u.id AND j.status='pending') OR ((u.enabled=0 OR (u.expires_at IS NOT NULL AND u.expires_at<=?)) AND (s.status IS NULL OR s.status IN ('active','failed'))) ORDER BY CASE WHEN u.enabled=0 OR (u.expires_at IS NOT NULL AND u.expires_at<=?) THEN 0 ELSE 1 END,u.id",
        )
        .bind(now())
        .bind(now())
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn reconcile_owner(&self, owner_id: i64) -> Result<ReconcileOutcome, ReconcileError> {
        if owner_id <= 0 {
            return Err(ReconcileError::Owner);
        }
        let _guard = self.operation_lock.lock().await;
        let mut runtime_changed = false;
        let result = self.reconcile_locked(owner_id, &mut runtime_changed).await;
        let untouched_busy = matches!(&result,Err(ReconcileError::Database(error)) if !runtime_changed && crate::worker::transient_database(error));
        if result.is_err()
            && !untouched_busy
            && !matches!(&result, Err(ReconcileError::Temporary(_)))
        {
            // A failed DB read/finalization may conceal a revocation. Keep the
            // runtime stopped rather than continuing an unconfirmed revision.
            // Stop implementations are idempotent and must be cancellation-safe.
            self.confirm_stop(owner_id).await?;
        }
        result
    }

    async fn reconcile_locked(
        &self,
        owner_id: i64,
        runtime_changed: &mut bool,
    ) -> Result<ReconcileOutcome, ReconcileError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let Some(desired) = load_plan(&mut tx, owner_id, now()).await? else {
            tx.rollback().await?;
            self.confirm_stop(owner_id).await?;
            return Ok(ReconcileOutcome::Missing);
        };
        let revision: i64 = sqlx::query_scalar("SELECT desired_revision FROM users WHERE id=?")
            .bind(owner_id)
            .fetch_one(&mut *tx)
            .await?;
        let plan = desired.and_then(|plan| plan.validate(&self.policy, now()));
        tx.commit().await?;
        let plan = match plan {
            Ok(plan) => plan,
            Err(error) => {
                // Invalid desired data must never leave an old, potentially
                // revoked configuration running. Keep reservations until a
                // later valid revision is fully confirmed.
                let stopped = self.confirm_stop(owner_id).await;
                self.mark_failure(owner_id, revision, error_message(error))
                    .await?;
                stopped?;
                return Ok(ReconcileOutcome::Failed);
            }
        };
        if !self.current(&plan).await? {
            self.confirm_stop(owner_id).await?;
            return Ok(ReconcileOutcome::StaleStopped);
        }
        *runtime_changed = true;
        let result = if plan.stopped() {
            tokio::time::timeout(self.timeout, self.driver.stop(owner_id)).await
        } else {
            tokio::time::timeout(self.timeout, self.driver.apply(&plan)).await
        };
        let result = match result {
            Ok(result) => result,
            Err(_) => {
                self.confirm_stop(owner_id).await?;
                Err(DriverError::temporary("executor operation timed out"))
            }
        };
        if let Err(error) = result {
            if error.retryable {
                // Keep the desired job pending. The root-owned lease stops an
                // unconfirmed runtime even while the broker socket is absent.
                let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
                sqlx::query("UPDATE apply_jobs SET status='pending' WHERE owner_id=? AND revision=? AND revision=(SELECT desired_revision FROM users WHERE id=?)")
                    .bind(owner_id).bind(revision).bind(owner_id).execute(&mut *tx).await?;
                sqlx::query("UPDATE runtime_states SET status='pending',last_error=?,healthy_since=NULL WHERE owner_id=? AND revision=?")
                    .bind(&error.message).bind(owner_id).bind(revision).execute(&mut *tx).await?;
                tx.commit().await?;
                return Err(ReconcileError::Temporary(error_message(error)));
            }
            let stopped = self.confirm_stop(owner_id).await;
            self.mark_failure(owner_id, revision, error_message(error))
                .await?;
            stopped?;
            return Ok(ReconcileOutcome::Failed);
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if !current_in(&mut tx, &plan, now()).await? {
            tx.rollback().await?;
            // A disable/edit racing with slow runtime work wins. Do not release
            // any leases or revive the old configuration through rollback.
            self.confirm_stop(owner_id).await?;
            return Ok(ReconcileOutcome::StaleStopped);
        }
        sqlx::query("UPDATE users SET applied_revision=? WHERE id=?")
            .bind(revision)
            .bind(owner_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE apply_jobs SET status='applied' WHERE owner_id=? AND revision<=?")
            .bind(owner_id)
            .bind(revision)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO runtime_states(owner_id,revision,status,last_error,updated_at,healthy_since) VALUES(?,?,?,NULL,?,?) ON CONFLICT(owner_id) DO UPDATE SET revision=excluded.revision,status=excluded.status,last_error=NULL,updated_at=excluded.updated_at,retry_at=NULL,retry_count=CASE WHEN runtime_states.revision!=excluded.revision OR (runtime_states.status='active' AND runtime_states.healthy_since<=excluded.updated_at-300) THEN 0 ELSE runtime_states.retry_count END,healthy_since=CASE WHEN excluded.status!='active' THEN NULL WHEN runtime_states.status='active' AND runtime_states.revision=excluded.revision THEN COALESCE(runtime_states.healthy_since,excluded.healthy_since) ELSE excluded.healthy_since END")
            .bind(owner_id)
            .bind(revision)
            .bind(if plan.stopped() { "stopped" } else { "active" })
            .bind(now())
            .bind((!plan.stopped()).then(now))
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM port_leases WHERE owner_id=? AND NOT EXISTS (SELECT 1 FROM rules r WHERE r.id=port_leases.rule_id AND r.deleted_at IS NULL AND r.listen_port=port_leases.port)")
            .bind(owner_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(if plan.stopped() {
            ReconcileOutcome::Stopped
        } else {
            ReconcileOutcome::Applied
        })
    }

    async fn current(&self, plan: &RuntimePlan) -> Result<bool, ReconcileError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let current = current_in(&mut tx, plan, now()).await?;
        tx.commit().await?;
        Ok(current)
    }

    async fn confirm_stop(&self, owner_id: i64) -> Result<(), ReconcileError> {
        match tokio::time::timeout(self.timeout, self.driver.stop(owner_id)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if error.retryable => {
                Err(ReconcileError::Temporary(error_message(error)))
            }
            Ok(Err(error)) => Err(ReconcileError::Stop(error_message(error))),
            Err(_) => Err(ReconcileError::Temporary("executor stop timed out".into())),
        }
    }

    async fn mark_failure(
        &self,
        owner_id: i64,
        revision: i64,
        message: String,
    ) -> Result<(), ReconcileError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        // Failure to apply an obsolete task must not overwrite a new revision's
        // status, and must not release reservations for the previous runtime.
        let current: Option<i64> =
            sqlx::query_scalar("SELECT desired_revision FROM users WHERE id=?")
                .bind(owner_id)
                .fetch_optional(&mut *tx)
                .await?;
        if current == Some(revision) {
            sqlx::query("UPDATE apply_jobs SET status='failed' WHERE owner_id=? AND revision<=? AND status='pending'")
                .bind(owner_id)
                .bind(revision)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO runtime_states(owner_id,revision,status,last_error,updated_at) VALUES(?,?,'failed',?,?) ON CONFLICT(owner_id) DO UPDATE SET revision=excluded.revision,status='failed',last_error=excluded.last_error,updated_at=excluded.updated_at,healthy_since=NULL")
                .bind(owner_id)
                .bind(revision)
                .bind(message)
                .bind(now())
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

async fn current_in(
    tx: &mut Transaction<'_, Sqlite>,
    plan: &RuntimePlan,
    timestamp: i64,
) -> Result<bool, sqlx::Error> {
    let user: Option<(i64, bool, Option<i64>)> =
        sqlx::query_as("SELECT desired_revision,enabled,expires_at FROM users WHERE id=?")
            .bind(plan.owner_id)
            .fetch_optional(&mut **tx)
            .await?;
    Ok(user.is_some_and(|(revision, enabled, expiry)| {
        revision == plan.revision
            && (plan.stopped() || (enabled && expiry.is_none_or(|expiry| expiry > timestamp)))
    }))
}
