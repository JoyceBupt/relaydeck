use std::{
    net::IpAddr,
    sync::{Arc, LazyLock},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use sqlx::{Executor, Sqlite};
use tokio::sync::Semaphore;

use crate::{
    api::{AppState, AuthContext, enqueue_apply, record_audit, write_actor},
    db::now,
    error::ApiError,
    models::DbUser,
    policy,
};

static DNS_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));
const MAX_DNS_RESULTS: usize = 32;
const RULE_SELECT: &str = "SELECT r.id,r.owner_id,u.username AS owner_username,r.name,r.listen_port,r.target_host,r.target_ip,r.target_port,r.protocol,r.source_cidrs,r.enabled,r.created_at,r.updated_at,r.dns_error,CASE WHEN r.enabled=0 OR u.enabled=0 OR (u.expires_at IS NOT NULL AND u.expires_at<=unixepoch()) THEN 'stopped' WHEN r.dns_blocked=1 THEN 'blocked' WHEN s.revision=u.desired_revision AND s.status='failed' THEN 'failed' WHEN e.status IS NULL OR e.status!='running' OR e.last_seen<=unixepoch()-10 THEN 'pending' WHEN s.revision!=u.desired_revision OR u.applied_revision!=u.desired_revision THEN 'pending' WHEN s.status='stopped' THEN 'stopped' WHEN s.status='active' AND r.enabled=0 THEN 'stopped' WHEN s.status='active' AND u.enabled=1 AND (u.expires_at IS NULL OR u.expires_at>unixepoch()) THEN 'active' ELSE 'pending' END AS runtime_status,CASE WHEN s.revision=u.desired_revision AND s.status='failed' THEN s.last_error END AS runtime_error,s.updated_at AS runtime_updated_at FROM rules r JOIN users u ON u.id=r.owner_id LEFT JOIN runtime_states s ON s.owner_id=u.id LEFT JOIN executor_status e ON e.id=1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRule {
    owner_id: Option<i64>,
    name: String,
    listen_port: i64,
    target_host: String,
    target_port: i64,
    protocol: String,
    source_cidrs: Vec<String>,
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleInput {
    name: String,
    listen_port: i64,
    target_host: String,
    target_port: i64,
    protocol: String,
    source_cidrs: Vec<String>,
    enabled: bool,
}

impl CreateRule {
    fn into_input(self) -> RuleInput {
        RuleInput {
            name: self.name,
            listen_port: self.listen_port,
            target_host: self.target_host,
            target_port: self.target_port,
            protocol: self.protocol,
            source_cidrs: self.source_cidrs,
            enabled: self.enabled,
        }
    }
}

impl RuleInput {
    fn validate(mut self) -> Result<Self, ApiError> {
        policy::validate_rule_name(&self.name)?;
        self.name = self.name.trim().to_owned();
        self.target_host = policy::validate_target_host(&self.target_host)?;
        if !(1..=65535).contains(&self.target_port) {
            return Err(ApiError::bad_request("目标端口须为1至65535"));
        }
        if !matches!(self.protocol.as_str(), "tcp" | "udp" | "both") {
            return Err(ApiError::bad_request("转发协议无效"));
        }
        // An explicit empty list means no source restriction. No broad CIDR is
        // silently inserted, and the executor must enforce non-empty lists.
        self.source_cidrs = policy::validate_source_cidrs(&self.source_cidrs)?;
        Ok(self)
    }
}

#[derive(sqlx::FromRow)]
struct DbRule {
    id: i64,
    owner_id: i64,
    owner_username: String,
    name: String,
    listen_port: i64,
    target_host: String,
    target_ip: String,
    target_port: i64,
    protocol: String,
    source_cidrs: String,
    enabled: bool,
    created_at: i64,
    updated_at: i64,
    dns_error: Option<String>,
    runtime_status: String,
    runtime_error: Option<String>,
    runtime_updated_at: Option<i64>,
}

#[derive(Serialize)]
struct RuleView {
    id: i64,
    owner_id: i64,
    owner_username: String,
    name: String,
    listen_port: i64,
    target_host: String,
    target_ip: String,
    target_port: i64,
    protocol: String,
    source_cidrs: Vec<String>,
    enabled: bool,
    dns_error: Option<String>,
    runtime_status: String,
    // Executor-reported reason for the current revision's failure; sanitized
    // and bounded by the executor before it is stored.
    runtime_error: Option<String>,
    runtime_updated_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

impl DbRule {
    fn into_view(self) -> Result<RuleView, ApiError> {
        let source_cidrs = serde_json::from_str(&self.source_cidrs).map_err(|error| {
            tracing::error!(rule_id = self.id, %error, "invalid stored source CIDRs");
            stored_data_error()
        })?;
        Ok(RuleView {
            id: self.id,
            owner_id: self.owner_id,
            owner_username: self.owner_username,
            name: self.name,
            listen_port: self.listen_port,
            target_host: self.target_host,
            target_ip: self.target_ip,
            target_port: self.target_port,
            protocol: self.protocol,
            source_cidrs,
            enabled: self.enabled,
            dns_error: self.dns_error,
            runtime_status: self.runtime_status,
            runtime_error: self.runtime_error,
            runtime_updated_at: self.runtime_updated_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

fn stored_data_error() -> ApiError {
    ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "rule_data_error",
        message: "规则数据异常".into(),
    }
}

async fn load_owner<'e, E>(executor: E, id: i64) -> Result<DbUser, ApiError>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query_as("SELECT * FROM users WHERE id=?")
        .bind(id)
        .fetch_optional(executor)
        .await?
        .ok_or_else(ApiError::not_found)
}

fn validate_owner_rule(
    state: &AppState,
    owner: &DbUser,
    input: &RuleInput,
) -> Result<(), ApiError> {
    if !owner.available() {
        return Err(ApiError::bad_request("账户已停用或到期"));
    }
    // Administrators may prepare rules for a newly provisioned account before
    // its initial password change. The actor's ready state is still enforced.
    policy::validate_listen_port(input.listen_port, 1024, 65535, &state.config.reserved_ports)?;
    Ok(())
}

async fn load_rule<'e, E>(executor: E, actor: &DbUser, id: i64) -> Result<DbRule, ApiError>
where
    E: Executor<'e, Database = Sqlite>,
{
    let query = format!(
        "{RULE_SELECT} WHERE r.id=? AND r.deleted_at IS NULL AND (?='admin' OR r.owner_id=?)"
    );
    sqlx::query_as(&query)
        .bind(id)
        .bind(&actor.role)
        .bind(actor.id)
        .fetch_optional(executor)
        .await?
        .ok_or_else(ApiError::not_found)
}

async fn check_create_quota<'e, E>(executor: E, owner: &DbUser) -> Result<(), ApiError>
where
    E: Executor<'e, Database = Sqlite>,
{
    let (owner_count, total_count): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM rules WHERE owner_id=? AND deleted_at IS NULL),(SELECT COUNT(*) FROM rules WHERE deleted_at IS NULL)",
    )
    .bind(owner.id)
    .fetch_one(executor)
    .await?;
    if owner_count >= owner.max_rules {
        return Err(ApiError::conflict("端口额度已满"));
    }
    if total_count >= 30 {
        return Err(ApiError::conflict("总规则数已达30条"));
    }
    Ok(())
}

async fn check_enabled_quota<'e, E>(
    executor: E,
    owner: &DbUser,
    rule_id: i64,
    enabled: bool,
) -> Result<(), ApiError>
where
    E: Executor<'e, Database = Sqlite>,
{
    if !enabled {
        return Ok(());
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM rules WHERE owner_id=? AND id<>? AND deleted_at IS NULL AND enabled=1",
    )
    .bind(owner.id)
    .bind(rule_id)
    .fetch_one(executor)
    .await?;
    if count >= owner.max_rules {
        return Err(ApiError::conflict("启用数量已达上限"));
    }
    Ok(())
}

async fn check_lease<'e, E>(
    executor: E,
    port: i64,
    owner_id: i64,
    rule_id: Option<i64>,
) -> Result<(), ApiError>
where
    E: Executor<'e, Database = Sqlite>,
{
    let lease: Option<(i64, i64)> =
        sqlx::query_as("SELECT owner_id,rule_id FROM port_leases WHERE port=?")
            .bind(port)
            .fetch_optional(executor)
            .await?;
    if let Some((existing_owner, existing_rule)) = lease
        && (existing_owner != owner_id || Some(existing_rule) != rule_id)
    {
        return Err(ApiError {
            status: StatusCode::CONFLICT,
            code: "port_unavailable",
            message: format!("端口 {port} 已占用或待释放，请更换端口"),
        });
    }
    Ok(())
}

// This is a preflight, not a reservation. Database leases serialize panel
// claims; the root broker checks kernel ownership again before touching nft.
fn check_host_port(port: i64) -> Result<(), ApiError> {
    for host in ["0.0.0.0", "::"] {
        let address = format!("{host}:{port}");
        let address = if host == "::" {
            format!("[{host}]:{port}")
        } else {
            address
        };
        let address: std::net::SocketAddr = address.parse().map_err(|_| ApiError::unavailable())?;
        for (kind, protocol) in [
            (socket2::Type::STREAM, socket2::Protocol::TCP),
            (socket2::Type::DGRAM, socket2::Protocol::UDP),
        ] {
            let result = (|| {
                let socket = socket2::Socket::new(
                    socket2::Domain::for_address(address),
                    kind,
                    Some(protocol),
                )?;
                socket.set_reuse_address(false)?;
                if address.is_ipv6() {
                    socket.set_only_v6(true)?;
                }
                socket.bind(&address.into())
            })();
            if let Err(error) = result {
                if host == "::"
                    && matches!(
                        error.raw_os_error(),
                        Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL)
                    )
                {
                    continue;
                }
                if error.kind() == std::io::ErrorKind::AddrInUse {
                    return Err(ApiError {
                        status: StatusCode::CONFLICT,
                        code: "port_unavailable",
                        message: format!("端口 {port} 已占用，请更换端口"),
                    });
                }
                tracing::warn!(%error, port, "cannot check listening port");
                return Err(ApiError::unavailable());
            }
        }
    }
    Ok(())
}

async fn resolve_target(state: &AppState, input: &RuleInput) -> Result<String, ApiError> {
    resolve_host(
        &input.target_host,
        input.target_port as u16,
        &state.config.local_ips,
    )
    .await
}

pub async fn resolve_host(host: &str, port: u16, local_ips: &[IpAddr]) -> Result<String, ApiError> {
    policy::validate_target_port(port)?;
    let host = policy::validate_target_host(host)?;
    let validate = |ip| {
        policy::validate_target_ip(ip, local_ips).map_err(|error| ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "target_denied",
            message: error.to_string(),
        })
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        validate(ip)?;
        return Ok(ip.to_string());
    }
    let permit = DNS_SLOTS
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::unavailable())?;
    // Tokio's blocking resolver cannot be cancelled after a timeout. Keep the
    // owned permit in the lookup task until the resolver actually completes, so
    // timed-out requests cannot dispatch more than four lookups concurrently.
    let lookup = tokio::spawn(async move {
        let _permit = permit;
        let results = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|_| ApiError::bad_request("目标域名无法解析"))?;
        let mut ips = Vec::new();
        for address in results {
            if ips.len() >= MAX_DNS_RESULTS {
                return Err(ApiError::bad_request("目标解析结果过多"));
            }
            ips.push(address.ip());
        }
        Ok::<_, ApiError>(ips)
    });
    let mut ips = tokio::time::timeout(Duration::from_secs(3), lookup)
        .await
        .map_err(|_| ApiError::bad_request("目标解析超时"))?
        .map_err(|error| {
            tracing::error!(%error, "target lookup task failed");
            ApiError::unavailable()
        })??;
    if ips.is_empty() {
        return Err(ApiError::bad_request("目标域名无可用地址"));
    }
    // Reject the complete answer if any address is forbidden. Picking one safe
    // result from a mixed private/public answer would hide a policy violation.
    for ip in &ips {
        validate(*ip)?;
    }
    ips.sort_unstable(); // IpAddr orders IPv4 before IPv6.
    ips.dedup();
    Ok(ips[0].to_string())
}

async fn list_rules(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<RuleView>>, ApiError> {
    auth.ready()?;
    let rows: Vec<DbRule> = if auth.user.role == "admin" {
        let query = format!("{RULE_SELECT} WHERE r.deleted_at IS NULL ORDER BY r.id");
        sqlx::query_as(&query).fetch_all(&state.pool).await?
    } else {
        let query =
            format!("{RULE_SELECT} WHERE r.deleted_at IS NULL AND r.owner_id=? ORDER BY r.id");
        sqlx::query_as(&query)
            .bind(auth.user.id)
            .fetch_all(&state.pool)
            .await?
    };
    Ok(Json(
        rows.into_iter()
            .map(DbRule::into_view)
            .collect::<Result<_, _>>()?,
    ))
}

async fn check_rule(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<i64>,
) -> Result<Json<crate::connectivity::RuleCheck>, ApiError> {
    auth.ready()?;
    let rule = load_rule(&state.pool, &auth.user, id).await?;
    if rule.runtime_status != "active" {
        return Err(ApiError::conflict("转发尚未运行"));
    }
    crate::api::mutation_limit(&state, auth.user.id, "rule_check", 6).await?;
    let revision: i64 = sqlx::query_scalar("SELECT desired_revision FROM users WHERE id=?")
        .bind(rule.owner_id)
        .fetch_one(&state.pool)
        .await?;
    let request = crate::connectivity::CheckRequest {
        owner_id: rule.owner_id,
        revision,
        rule_id: id,
    };
    let result = tokio::time::timeout(Duration::from_secs(12), state.connectivity.check(request))
        .await
        .map_err(|_| ApiError::unavailable())?
        .map_err(|error| {
            tracing::warn!(rule_id=id,%error,"connectivity check unavailable");
            ApiError::unavailable()
        })?;
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let actor = write_actor(&mut tx, &auth).await?;
    let current = load_rule(&mut *tx, &actor, id).await?;
    let current_revision: i64 = sqlx::query_scalar("SELECT desired_revision FROM users WHERE id=?")
        .bind(rule.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    if current.runtime_status != "active"
        || current_revision != revision
        || current.target_ip != result.target_ip.to_string()
        || current.target_port != i64::from(result.target_port)
        || result.rule_id != id
        || result.revision != revision
    {
        return Err(ApiError::conflict("转发已变更，请重新检测"));
    }
    tx.commit().await?;
    Ok(Json(result))
}

async fn create_rule(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(input): Json<CreateRule>,
) -> Result<(StatusCode, Json<RuleView>), ApiError> {
    crate::api::mutation_limit(&state, auth.user.id, "rules", 60).await?;
    auth.ready()?;
    let owner_override = input.owner_id.is_some();
    if owner_override && auth.user.role != "admin" {
        return Err(ApiError::forbidden());
    }
    let owner_id = input.owner_id.unwrap_or(auth.user.id);
    let input = input.into_input().validate()?;
    let owner = load_owner(&state.pool, owner_id).await?;
    validate_owner_rule(&state, &owner, &input)?;
    check_create_quota(&state.pool, &owner).await?;
    check_lease(&state.pool, input.listen_port, owner.id, None).await?;
    check_host_port(input.listen_port)?;
    let target_ip = resolve_target(&state, &input).await?;
    let source_cidrs =
        serde_json::to_string(&input.source_cidrs).map_err(|_| stored_data_error())?;

    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let actor = write_actor(&mut tx, &auth).await?;
    if actor.role != "admin" && (owner_override || owner_id != actor.id) {
        return Err(ApiError::forbidden());
    }
    let owner = load_owner(&mut *tx, owner_id).await?;
    validate_owner_rule(&state, &owner, &input)?;
    check_create_quota(&mut *tx, &owner).await?;
    check_lease(&mut *tx, input.listen_port, owner.id, None).await?;
    check_host_port(input.listen_port)?;
    let timestamp = now();
    let id = sqlx::query("INSERT INTO rules(owner_id,name,listen_port,target_host,target_ip,target_port,protocol,source_cidrs,enabled,created_at,updated_at,dns_checked_at,dns_resolved_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,unixepoch(),unixepoch())")
        .bind(owner.id)
        .bind(&input.name)
        .bind(input.listen_port)
        .bind(&input.target_host)
        .bind(&target_ip)
        .bind(input.target_port)
        .bind(&input.protocol)
        .bind(&source_cidrs)
        .bind(input.enabled)
        .bind(timestamp)
        .bind(timestamp)
        .execute(&mut *tx)
        .await?
        .last_insert_rowid();
    sqlx::query("INSERT INTO port_leases(port,owner_id,rule_id,created_at) VALUES(?,?,?,?)")
        .bind(input.listen_port)
        .bind(owner.id)
        .bind(id)
        .bind(timestamp)
        .execute(&mut *tx)
        .await?;
    record_audit(&mut tx, &actor, "rule_created", Some(id)).await?;
    enqueue_apply(&mut tx, owner.id).await?;
    let view = load_rule(&mut *tx, &actor, id).await?.into_view()?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(view)))
}

async fn update_rule(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<i64>,
    Json(input): Json<RuleInput>,
) -> Result<Json<RuleView>, ApiError> {
    crate::api::mutation_limit(&state, auth.user.id, "rules", 60).await?;
    auth.ready()?;
    let existing = load_rule(&state.pool, &auth.user, id).await?;
    let input = input.validate()?;
    let owner = load_owner(&state.pool, existing.owner_id).await?;
    validate_owner_rule(&state, &owner, &input)?;
    check_enabled_quota(&state.pool, &owner, id, input.enabled).await?;
    check_lease(&state.pool, input.listen_port, owner.id, Some(id)).await?;
    if input.listen_port != existing.listen_port || (!existing.enabled && input.enabled) {
        check_host_port(input.listen_port)?;
    }
    let target_ip = if !input.enabled
        && input.target_host == existing.target_host
        && input.target_port == existing.target_port
    {
        // Stopping a rule must remain possible when its DNS is unavailable.
        // The unchanged numeric target was validated when the rule was saved.
        existing
            .target_ip
            .parse::<IpAddr>()
            .map_err(|_| stored_data_error())?
            .to_string()
    } else {
        resolve_target(&state, &input).await?
    };
    let source_cidrs =
        serde_json::to_string(&input.source_cidrs).map_err(|_| stored_data_error())?;

    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let actor = write_actor(&mut tx, &auth).await?;
    let current = load_rule(&mut *tx, &actor, id).await?;
    let owner = load_owner(&mut *tx, current.owner_id).await?;
    validate_owner_rule(&state, &owner, &input)?;
    check_enabled_quota(&mut *tx, &owner, id, input.enabled).await?;
    check_lease(&mut *tx, input.listen_port, owner.id, Some(id)).await?;
    if input.listen_port != current.listen_port || (!current.enabled && input.enabled) {
        check_host_port(input.listen_port)?;
    }
    sqlx::query("UPDATE rules SET name=?,listen_port=?,target_host=?,target_ip=?,target_port=?,protocol=?,source_cidrs=?,enabled=?,updated_at=?,dns_checked_at=unixepoch(),dns_resolved_at=unixepoch(),dns_error=NULL,dns_blocked=0 WHERE id=? AND deleted_at IS NULL")
        .bind(&input.name)
        .bind(input.listen_port)
        .bind(&input.target_host)
        .bind(&target_ip)
        .bind(input.target_port)
        .bind(&input.protocol)
        .bind(&source_cidrs)
        .bind(input.enabled)
        .bind(now())
        .bind(id)
        .execute(&mut *tx)
        .await?;
    // Old leases remain reserved until a future executor confirms removal.
    // Reusing this rule's own historical lease is allowed; another rule cannot.
    sqlx::query("INSERT INTO port_leases(port,owner_id,rule_id,created_at) VALUES(?,?,?,?) ON CONFLICT(port) DO NOTHING")
        .bind(input.listen_port)
        .bind(owner.id)
        .bind(id)
        .bind(now())
        .execute(&mut *tx)
        .await?;
    record_audit(&mut tx, &actor, "rule_updated", Some(id)).await?;
    enqueue_apply(&mut tx, owner.id).await?;
    let view = load_rule(&mut *tx, &actor, id).await?.into_view()?;
    tx.commit().await?;
    Ok(Json(view))
}

async fn delete_rule(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<i64>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    crate::api::mutation_limit(&state, auth.user.id, "rules", 60).await?;
    auth.ready()?;
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let actor = write_actor(&mut tx, &auth).await?;
    let rule = load_rule(&mut *tx, &actor, id).await?;
    let timestamp = now();
    sqlx::query(
        "UPDATE rules SET enabled=0,deleted_at=?,updated_at=? WHERE id=? AND deleted_at IS NULL",
    )
    .bind(timestamp)
    .bind(timestamp)
    .bind(rule.id)
    .execute(&mut *tx)
    .await?;
    record_audit(&mut tx, &actor, "rule_deleted", Some(rule.id)).await?;
    enqueue_apply(&mut tx, rule.owner_id).await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"status":"pending"})),
    ))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/rules", get(list_rules).post(create_rule))
        .route("/api/rules/{id}", put(update_rule).delete(delete_rule))
        .route("/api/rules/{id}/check", post(check_rule))
}
