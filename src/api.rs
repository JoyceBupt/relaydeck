use crate::{
    config::Config,
    credentials::{Credentials, new_session_token, token_hash},
    db::now,
    error::ApiError,
    models::{DbUser, UserView},
    policy,
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, FromRequestParts, Path, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use sqlx::{Sqlite, SqlitePool, Transaction};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
    pub credentials: Credentials,
    pub mfa: crate::mfa::MfaService,
    dummy_hash: Arc<String>,
    network_limits: Arc<Mutex<crate::limits::Limits>>,
    account_limits: Arc<Mutex<crate::limits::Limits>>,
    mutation_limits: Arc<Mutex<crate::limits::Limits>>,
}

impl AppState {
    pub async fn new(pool: SqlitePool, config: Config) -> anyhow::Result<Self> {
        let credentials = Credentials::new();
        let mfa = crate::mfa::MfaService::from_key_file(&config.mfa_key).map_err(|error| {
            anyhow::anyhow!("cannot load MFA key (initialize once with init-key): {error}")
        })?;
        let dummy_hash = credentials.hash_password(new_session_token()).await?;
        Ok(Self {
            pool,
            config: Arc::new(config),
            credentials,
            mfa,
            dummy_hash: Arc::new(dummy_hash),
            network_limits: Arc::new(Mutex::new(crate::limits::Limits::new(4096))),
            account_limits: Arc::new(Mutex::new(crate::limits::Limits::new(1024))),
            mutation_limits: Arc::new(Mutex::new(crate::limits::Limits::new(1024))),
        })
    }
}

pub struct AuthContext {
    pub user: DbUser,
    pub csrf_token: String,
    pub session_hash: String,
    require_admin_mfa: bool,
}

#[derive(sqlx::FromRow)]
struct AuthRow {
    #[sqlx(flatten)]
    user: DbUser,
    csrf_token: String,
}

impl AuthContext {
    pub fn ready(&self) -> Result<(), ApiError> {
        if self.user.must_change_password {
            return Err(ApiError {
                status: StatusCode::FORBIDDEN,
                code: "password_change_required",
                message: "请先修改密码".into(),
            });
        }
        check_mfa_ready(&self.user, self.require_admin_mfa)?;
        Ok(())
    }
    pub fn admin(&self) -> Result<(), ApiError> {
        self.ready()?;
        if self.user.role != "admin" {
            return Err(ApiError::forbidden());
        }
        Ok(())
    }
}

impl FromRequestParts<AppState> for AuthContext {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let cookie = parts
            .headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(ApiError::unauthorized)?;
        let token = cookie
            .split(';')
            .find_map(|item| item.trim().strip_prefix("relaydeck_session="))
            .ok_or_else(ApiError::unauthorized)?;
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ApiError::unauthorized());
        }
        let session_hash = token_hash(token);
        let row: Option<AuthRow> = sqlx::query_as(
            "SELECT u.*,s.csrf_token FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.auth_version=u.auth_version AND u.enabled=1 AND (u.expires_at IS NULL OR u.expires_at>?)"
        ).bind(&session_hash).bind(now()).bind(now()).fetch_optional(&state.pool).await?;
        let AuthRow { user, csrf_token } = row.ok_or_else(ApiError::unauthorized)?;
        if !parts.method.is_safe() {
            check_origin(&parts.headers, state)?;
            if parts
                .headers
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                != Some(csrf_token.as_str())
            {
                return Err(ApiError::forbidden());
            }
        }
        Ok(Self {
            user,
            csrf_token,
            session_hash,
            require_admin_mfa: state.config.require_admin_mfa,
        })
    }
}

fn check_origin(headers: &HeaderMap, state: &AppState) -> Result<(), ApiError> {
    if headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
        != Some(state.config.public_origin.as_str())
    {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

// Mutations revalidate the session under an IMMEDIATE transaction so revocation
// and grant changes cannot race a request which already passed the extractor.
pub async fn write_actor(
    tx: &mut Transaction<'_, Sqlite>,
    auth: &AuthContext,
) -> Result<DbUser, ApiError> {
    let user = session_actor(tx, auth).await?;
    if user.must_change_password {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            code: "password_change_required",
            message: "请先修改密码".into(),
        });
    }
    check_mfa_ready(&user, auth.require_admin_mfa)?;
    Ok(user)
}

fn check_mfa_ready(user: &DbUser, required: bool) -> Result<(), ApiError> {
    if required && user.role == "admin" && user.mfa_secret.is_none() {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            code: "mfa_enrollment_required",
            message: "请启用双因素".into(),
        });
    }
    Ok(())
}

async fn session_actor(
    tx: &mut Transaction<'_, Sqlite>,
    auth: &AuthContext,
) -> Result<DbUser, ApiError> {
    let user: Option<DbUser> = sqlx::query_as("SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.id=? AND s.token_hash=? AND s.auth_version=u.auth_version AND s.expires_at>?")
        .bind(auth.user.id).bind(&auth.session_hash).bind(now()).fetch_optional(&mut **tx).await?;
    let user = user
        .filter(DbUser::available)
        .ok_or_else(ApiError::unauthorized)?;
    Ok(user)
}

pub async fn record_audit(
    tx: &mut Transaction<'_, Sqlite>,
    actor: &DbUser,
    action: &str,
    resource_id: Option<i64>,
) -> Result<(), ApiError> {
    let kind = resource_id.map(|_| {
        if action.starts_with("rule_") {
            "rule"
        } else {
            "user"
        }
    });
    let (name, port): (Option<String>, Option<i64>) = match (kind, resource_id) {
        (Some("rule"), Some(id)) => sqlx::query_as("SELECT name,listen_port FROM rules WHERE id=?")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?
            .unwrap_or_default(),
        (Some("user"), Some(id)) => (
            sqlx::query_scalar("SELECT username FROM users WHERE id=?")
                .bind(id)
                .fetch_optional(&mut **tx)
                .await?,
            None,
        ),
        _ => (None, None),
    };
    sqlx::query("INSERT INTO audit_events(actor_id,actor_username,action,resource_id,created_at,resource_kind,resource_name,resource_port) VALUES(?,?,?,?,?,?,?,?)")
        .bind(actor.id).bind(&actor.username).bind(action).bind(resource_id).bind(now()).bind(kind).bind(name).bind(port).execute(&mut **tx).await?;
    sqlx::query("DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT -1 OFFSET 10000)").execute(&mut **tx).await?;
    Ok(())
}

pub async fn enqueue_apply(
    tx: &mut Transaction<'_, Sqlite>,
    owner_id: i64,
) -> Result<(), ApiError> {
    let revision: i64 = sqlx::query_scalar("UPDATE users SET desired_revision=desired_revision+1 WHERE id=? RETURNING desired_revision")
        .bind(owner_id).fetch_one(&mut **tx).await?;
    sqlx::query("DELETE FROM apply_jobs WHERE owner_id=? AND status='pending'")
        .bind(owner_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("INSERT INTO apply_jobs(owner_id,revision,created_at) VALUES(?,?,?)")
        .bind(owner_id)
        .bind(revision)
        .bind(now())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn user_view(pool: &SqlitePool, id: i64) -> Result<UserView, ApiError> {
    let user = sqlx::query_as::<_, DbUser>("SELECT * FROM users WHERE id=?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    let count =
        sqlx::query_scalar("SELECT COUNT(*) FROM rules WHERE owner_id=? AND deleted_at IS NULL")
            .bind(id)
            .fetch_one(pool)
            .await?;
    Ok(UserView::from_user(user, count))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    username: String,
    password: String,
    code: Option<String>,
}

#[derive(Serialize)]
struct SessionView {
    user: UserView,
    csrf_token: String,
    mfa_required: bool,
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Result<ConnectInfo<SocketAddr>, axum::extract::rejection::ExtensionRejection>,
    Json(input): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    check_origin(&headers, &state)?;
    if input.username.len() > 32 || input.password.len() > 128 {
        return Err(ApiError::unauthorized());
    }
    let peer_ip = peer
        .ok()
        .map(|peer| peer.0.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let ip = if state.config.trust_proxy {
        if !peer_ip.is_loopback() {
            return Err(ApiError::forbidden());
        }
        // Caddy must overwrite this dedicated header with {remote_host}; a
        // user-supplied X-Forwarded-For chain is never an authentication input.
        if headers.get_all("x-relaydeck-client-ip").iter().count() != 1 {
            return Err(ApiError::unavailable());
        }
        headers
            .get("x-relaydeck-client-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<IpAddr>().ok())
            .ok_or_else(ApiError::unavailable)?
    } else {
        peer_ip
    };
    if !state
        .network_limits
        .lock()
        .await
        .admit(crate::limits::network_key(ip), 32, now())
    {
        return Err(ApiError::rate_limited());
    }
    let user: Option<DbUser> = sqlx::query_as("SELECT * FROM users WHERE username=?")
        .bind(&input.username)
        .fetch_optional(&state.pool)
        .await?;
    if let Some(user) = &user
        && !state
            .account_limits
            .lock()
            .await
            .admit(user.id.to_string(), 8, now())
    {
        return Err(ApiError::rate_limited());
    }
    let hash = user
        .as_ref()
        .map(|u| u.password_hash.clone())
        .unwrap_or_else(|| (*state.dummy_hash).clone());
    let verified = state
        .credentials
        .verify_password(input.password, hash)
        .await?;
    let Some(user) = user else {
        return Err(ApiError::unauthorized());
    };
    if !verified || !user.available() {
        let mut tx = state.pool.begin().await?;
        record_audit(&mut tx, &user, "login_failed", Some(user.id)).await?;
        tx.commit().await?;
        return Err(ApiError::unauthorized());
    }
    let token = new_session_token();
    let csrf_token = new_session_token();
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    // The password check precedes the write transaction. Check the exact auth
    // version again so a simultaneous reset/disable cannot issue a fresh session.
    let current: DbUser = sqlx::query_as("SELECT * FROM users WHERE id=?")
        .bind(user.id)
        .fetch_one(&mut *tx)
        .await?;
    if !current.available() || current.auth_version != user.auth_version {
        return Err(ApiError::unauthorized());
    }
    if current.mfa_secret.is_some() {
        let code = input
            .code
            .as_deref()
            .filter(|code| !code.is_empty())
            .ok_or_else(|| ApiError {
                status: StatusCode::UNAUTHORIZED,
                code: "mfa_required",
                message: "请输入验证码".into(),
            })?;
        check_mfa_budget(&current, code)?;
        if !state.mfa.verify(&mut tx, current.id, code, now()).await? {
            record_mfa_failure(&mut tx, &current, "login_mfa_failed").await?;
            tx.commit().await?;
            return Err(ApiError::bad_request("验证码无效"));
        }
        clear_mfa_failures(&mut tx, current.id).await?;
    }
    sqlx::query("DELETE FROM sessions WHERE expires_at<=?")
        .bind(now())
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC,token_hash DESC LIMIT -1 OFFSET 7)")
        .bind(user.id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO sessions(token_hash,user_id,csrf_token,auth_version,expires_at,created_at) VALUES(?,?,?,?,?,?)")
        .bind(token_hash(&token)).bind(user.id).bind(&csrf_token).bind(user.auth_version).bind(now()+8*3600).bind(now()).execute(&mut *tx).await?;
    record_audit(&mut tx, &user, "login", Some(user.id)).await?;
    tx.commit().await?;
    let value = SessionView {
        user: user_view(&state.pool, user.id).await?,
        csrf_token,
        mfa_required: state.config.require_admin_mfa && user.role == "admin",
    };
    let mut response = Json(value).into_response();
    let secure = if state.config.secure_cookie {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "relaydeck_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800{secure}"
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie.parse().expect("hex cookie is a valid header"),
    );
    Ok(response)
}

async fn session(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<SessionView>, ApiError> {
    Ok(Json(SessionView {
        user: user_view(&state.pool, auth.user.id).await?,
        csrf_token: auth.csrf_token,
        mfa_required: state.config.require_admin_mfa && auth.user.role == "admin",
    }))
}

async fn logout(State(state): State<AppState>, auth: AuthContext) -> Result<Response, ApiError> {
    sqlx::query("DELETE FROM sessions WHERE token_hash=?")
        .bind(auth.session_hash)
        .execute(&state.pool)
        .await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    let secure = if state.config.secure_cookie {
        "; Secure"
    } else {
        ""
    };
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("relaydeck_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}")
            .parse()
            .expect("static cookie"),
    );
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordRequest {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(input): Json<PasswordRequest>,
) -> Result<StatusCode, ApiError> {
    sensitive_limit(&state, auth.user.id).await?;
    policy::validate_password(&input.new_password)?;
    if !state
        .credentials
        .verify_password(input.current_password, auth.user.password_hash.clone())
        .await?
    {
        return Err(ApiError::bad_request("当前密码不正确"));
    }
    let hash = state.credentials.hash_password(input.new_password).await?;
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let current: DbUser = sqlx::query_as("SELECT * FROM users WHERE id=?")
        .bind(auth.user.id)
        .fetch_one(&mut *tx)
        .await?;
    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE token_hash=? AND user_id=? AND auth_version=? AND expires_at>?")
        .bind(&auth.session_hash).bind(current.id).bind(current.auth_version).bind(now()).fetch_one(&mut *tx).await?;
    if !current.available() || current.auth_version != auth.user.auth_version || active != 1 {
        return Err(ApiError::unauthorized());
    }
    sqlx::query("UPDATE users SET password_hash=?,must_change_password=0,auth_version=auth_version+1 WHERE id=?").bind(hash).bind(current.id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM sessions WHERE user_id=?")
        .bind(current.id)
        .execute(&mut *tx)
        .await?;
    record_audit(&mut tx, &current, "password_changed", Some(current.id)).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MfaSetupRequest {
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MfaCodeRequest {
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MfaDisableRequest {
    password: String,
    code: String,
}

async fn sensitive_limit(state: &AppState, user_id: i64) -> Result<(), ApiError> {
    mutation_limit(state, user_id, "security", 8).await
}

fn check_mfa_budget(user: &DbUser, code: &str) -> Result<(), ApiError> {
    // Strong recovery codes remain usable during a TOTP lockout.
    let recovery =
        matches!(code.len(), 32 | 35) && code.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
    if user.mfa_locked_until > now() && !recovery {
        return Err(ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "mfa_locked",
            message: "验证码已锁定，请稍后重试或使用恢复码".into(),
        });
    }
    Ok(())
}

async fn clear_mfa_failures(tx: &mut Transaction<'_, Sqlite>, id: i64) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET mfa_failures=0,mfa_locked_until=0 WHERE id=?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn record_mfa_failure(
    tx: &mut Transaction<'_, Sqlite>,
    user: &DbUser,
    action: &str,
) -> Result<(), ApiError> {
    let failures = user.mfa_failures.saturating_add(1).min(64);
    let delay = if failures < 5 {
        0
    } else {
        (60_i64 * (1_i64 << (failures - 5).min(11))).min(86400)
    };
    sqlx::query("UPDATE users SET mfa_failures=?,mfa_locked_until=? WHERE id=?")
        .bind(failures)
        .bind(now().saturating_add(delay))
        .bind(user.id)
        .execute(&mut **tx)
        .await?;
    record_audit(tx, user, action, Some(user.id)).await
}

async fn reauthenticate(
    state: &AppState,
    auth: &AuthContext,
    password: String,
) -> Result<(), ApiError> {
    sensitive_limit(state, auth.user.id).await?;
    if password.len() > 128
        || !state
            .credentials
            .verify_password(password, auth.user.password_hash.clone())
            .await?
    {
        return Err(ApiError::bad_request("密码不正确"));
    }
    Ok(())
}

async fn mfa_actor(
    tx: &mut Transaction<'_, Sqlite>,
    auth: &AuthContext,
) -> Result<DbUser, ApiError> {
    let user = session_actor(tx, auth).await?;
    if user.must_change_password {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            code: "password_change_required",
            message: "请先修改密码".into(),
        });
    }
    if user.auth_version != auth.user.auth_version {
        return Err(ApiError::unauthorized());
    }
    Ok(user)
}

async fn begin_mfa(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(input): Json<MfaSetupRequest>,
) -> Result<Json<crate::mfa::Enrollment>, ApiError> {
    reauthenticate(&state, &auth, input.password).await?;
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let actor = mfa_actor(&mut tx, &auth).await?;
    let enrollment = state
        .mfa
        .begin_enrollment(&mut tx, actor.id, &actor.username, now())
        .await?;
    record_audit(&mut tx, &actor, "mfa_setup", Some(actor.id)).await?;
    tx.commit().await?;
    Ok(Json(enrollment))
}

async fn revoke_sessions(tx: &mut Transaction<'_, Sqlite>, user_id: i64) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET auth_version=auth_version+1 WHERE id=?")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id=?")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn confirm_mfa(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(input): Json<MfaCodeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    sensitive_limit(&state, auth.user.id).await?;
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let actor = mfa_actor(&mut tx, &auth).await?;
    check_mfa_budget(&actor, &input.code)?;
    let Some(codes) = state
        .mfa
        .confirm_enrollment(&mut tx, actor.id, &input.code, now())
        .await?
    else {
        record_mfa_failure(&mut tx, &actor, "mfa_confirmation_failed").await?;
        tx.commit().await?;
        return Err(ApiError::bad_request("验证码无效或已过期"));
    };
    clear_mfa_failures(&mut tx, actor.id).await?;
    revoke_sessions(&mut tx, actor.id).await?;
    record_audit(&mut tx, &actor, "mfa_enabled", Some(actor.id)).await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({"recovery_codes": codes})))
}

async fn disable_mfa(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(input): Json<MfaDisableRequest>,
) -> Result<StatusCode, ApiError> {
    reauthenticate(&state, &auth, input.password).await?;
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let actor = mfa_actor(&mut tx, &auth).await?;
    if state.config.require_admin_mfa && actor.role == "admin" {
        return Err(ApiError::forbidden());
    }
    check_mfa_budget(&actor, &input.code)?;
    if !state
        .mfa
        .verify(&mut tx, actor.id, &input.code, now())
        .await?
    {
        record_mfa_failure(&mut tx, &actor, "mfa_disable_failed").await?;
        tx.commit().await?;
        return Err(ApiError::bad_request("验证码无效"));
    }
    clear_mfa_failures(&mut tx, actor.id).await?;
    sqlx::query("UPDATE users SET mfa_secret=NULL,mfa_pending_secret=NULL,mfa_pending_at=NULL,mfa_last_step=NULL WHERE id=?").bind(actor.id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id=?")
        .bind(actor.id)
        .execute(&mut *tx)
        .await?;
    revoke_sessions(&mut tx, actor.id).await?;
    record_audit(&mut tx, &actor, "mfa_disabled", Some(actor.id)).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn health(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let runtime: Option<(i64, String)> =
        sqlx::query_as("SELECT last_seen,status FROM executor_status WHERE id=1")
            .fetch_optional(&state.pool)
            .await?;
    let executor = match runtime {
        None => "unconfigured",
        Some((seen, status)) if status == "running" && now().saturating_sub(seen) < 10 => "running",
        Some(_) => "offline",
    };
    Ok(Json(
        serde_json::json!({"status":"ok","name":"RelayDeck","version":env!("CARGO_PKG_VERSION"),"executor":executor}),
    ))
}

async fn retry_apply(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    auth.ready()?;
    mutation_limit(&state, auth.user.id, "retry", 8).await?;
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let actor = write_actor(&mut tx, &auth).await?;
    if actor.role != "admin" && actor.id != id {
        return Err(ApiError::not_found());
    }
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id=?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if exists != 1 {
        return Err(ApiError::not_found());
    }
    let pending: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM apply_jobs WHERE owner_id=? AND status='pending'")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if pending != 0 {
        return Ok(StatusCode::ACCEPTED);
    }
    let failed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM runtime_states s JOIN users u ON u.id=s.owner_id WHERE s.owner_id=? AND s.revision=u.desired_revision AND s.status='failed'").bind(id).fetch_one(&mut *tx).await?;
    if failed != 1 {
        return Err(ApiError::conflict("当前无需重试"));
    }
    enqueue_apply(&mut tx, id).await?;
    record_audit(&mut tx, &actor, "apply_retry", Some(id)).await?;
    tx.commit().await?;
    Ok(StatusCode::ACCEPTED)
}

pub async fn mutation_limit(
    state: &AppState,
    user_id: i64,
    action: &str,
    maximum: u32,
) -> Result<(), ApiError> {
    if state
        .mutation_limits
        .lock()
        .await
        .admit(format!("{action}:{user_id}"), maximum, now())
    {
        Ok(())
    } else {
        Err(ApiError::rate_limited())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateUser {
    username: String,
    password: String,
    port_start: i64,
    port_end: i64,
    max_rules: i64,
    expires_at: Option<i64>,
}

fn validate_expiry(expiry: Option<i64>) -> Result<(), ApiError> {
    if expiry.is_some_and(|expiry| expiry <= now()) {
        return Err(ApiError::bad_request("到期时间须晚于当前时间"));
    }
    Ok(())
}

async fn create_user(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(input): Json<CreateUser>,
) -> Result<(StatusCode, Json<UserView>), ApiError> {
    auth.admin()?;
    policy::validate_username(&input.username)?;
    policy::validate_password(&input.password)?;
    policy::validate_port_grant(input.port_start, input.port_end, input.max_rules)?;
    validate_expiry(input.expires_at)?;
    let hash = state.credentials.hash_password(input.password).await?;
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let actor = write_actor(&mut tx, &auth).await?;
    if actor.role != "admin" {
        return Err(ApiError::forbidden());
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role='user'")
        .fetch_one(&mut *tx)
        .await?;
    if count >= 10 {
        return Err(ApiError::conflict("首版最多10个用户"));
    }
    let overlap: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE port_start<=? AND port_end>=?")
            .bind(input.port_end)
            .bind(input.port_start)
            .fetch_one(&mut *tx)
            .await?;
    if overlap > 0 {
        return Err(ApiError::conflict("端口范围与已有授权重叠"));
    }
    let id=sqlx::query("INSERT INTO users(username,password_hash,role,port_start,port_end,max_rules,expires_at,created_at) VALUES(?,?,'user',?,?,?,?,?)")
        .bind(input.username).bind(hash).bind(input.port_start).bind(input.port_end).bind(input.max_rules).bind(input.expires_at).bind(now()).execute(&mut *tx).await?.last_insert_rowid();
    record_audit(&mut tx, &actor, "user_created", Some(id)).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(user_view(&state.pool, id).await?)))
}

async fn list_users(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<UserView>>, ApiError> {
    auth.admin()?;
    let users: Vec<DbUser> = sqlx::query_as("SELECT * FROM users ORDER BY id")
        .fetch_all(&state.pool)
        .await?;
    let mut result = Vec::with_capacity(users.len());
    for user in users {
        let count = sqlx::query_scalar(
            "SELECT COUNT(*) FROM rules WHERE owner_id=? AND deleted_at IS NULL",
        )
        .bind(user.id)
        .fetch_one(&state.pool)
        .await?;
        result.push(UserView::from_user(user, count));
    }
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateUser {
    enabled: bool,
    port_start: i64,
    port_end: i64,
    max_rules: i64,
    expires_at: Option<i64>,
}

async fn update_user(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<i64>,
    Json(input): Json<UpdateUser>,
) -> Result<Json<UserView>, ApiError> {
    auth.admin()?;
    policy::validate_port_grant(input.port_start, input.port_end, input.max_rules)?;
    if input.enabled {
        validate_expiry(input.expires_at)?;
    }
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let actor = write_actor(&mut tx, &auth).await?;
    if actor.role != "admin" {
        return Err(ApiError::forbidden());
    }
    let target: DbUser = sqlx::query_as("SELECT * FROM users WHERE id=?")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if target.role == "admin" && (!input.enabled || input.expires_at.is_some()) {
        return Err(ApiError::bad_request("管理员不能停用或设置到期时间"));
    }
    let overlap: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE id<>? AND port_start<=? AND port_end>=?",
    )
    .bind(id)
    .bind(input.port_end)
    .bind(input.port_start)
    .fetch_one(&mut *tx)
    .await?;
    if overlap > 0 {
        return Err(ApiError::conflict("端口范围与已有授权重叠"));
    }
    sqlx::query("UPDATE users SET enabled=?,port_start=?,port_end=?,max_rules=?,expires_at=?,auth_version=auth_version+1 WHERE id=?")
        .bind(input.enabled).bind(input.port_start).bind(input.port_end).bind(input.max_rules).bind(input.expires_at).bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM sessions WHERE user_id=?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    // Narrowing grants never leaves an out-of-policy desired rule enabled.
    sqlx::query("UPDATE rules SET enabled=0,updated_at=? WHERE owner_id=? AND deleted_at IS NULL AND (listen_port<? OR listen_port>?)")
        .bind(now()).bind(id).bind(input.port_start).bind(input.port_end).execute(&mut *tx).await?;
    sqlx::query("UPDATE rules SET enabled=0,updated_at=? WHERE id IN (SELECT id FROM rules WHERE owner_id=? AND deleted_at IS NULL AND enabled=1 ORDER BY created_at,id LIMIT -1 OFFSET ?)")
        .bind(now()).bind(id).bind(input.max_rules).execute(&mut *tx).await?;
    enqueue_apply(&mut tx, id).await?;
    record_audit(&mut tx, &actor, "user_updated", Some(id)).await?;
    tx.commit().await?;
    Ok(Json(user_view(&state.pool, id).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetPassword {
    password: String,
}

async fn reset_password(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<i64>,
    Json(input): Json<ResetPassword>,
) -> Result<StatusCode, ApiError> {
    auth.admin()?;
    policy::validate_password(&input.password)?;
    let hash = state.credentials.hash_password(input.password).await?;
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let actor = write_actor(&mut tx, &auth).await?;
    if actor.role != "admin" {
        return Err(ApiError::forbidden());
    }
    let target: DbUser = sqlx::query_as("SELECT * FROM users WHERE id=?")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if target.role == "admin" {
        return Err(ApiError::forbidden());
    }
    sqlx::query("UPDATE users SET password_hash=?,must_change_password=1,auth_version=auth_version+1 WHERE id=?").bind(hash).bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM sessions WHERE user_id=?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    clear_mfa_failures(&mut tx, id).await?;
    record_audit(&mut tx, &actor, "password_reset", Some(id)).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preference {
    view_mode: String,
}

async fn preferences(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(input): Json<Preference>,
) -> Result<Json<serde_json::Value>, ApiError> {
    auth.ready()?;
    if !["table", "cards"].contains(&input.view_mode.as_str()) {
        return Err(ApiError::bad_request("视图无效"));
    }
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let actor = write_actor(&mut tx, &auth).await?;
    sqlx::query("UPDATE users SET view_mode=? WHERE id=?")
        .bind(&input.view_mode)
        .bind(actor.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({"view_mode":input.view_mode})))
}

#[derive(Serialize, sqlx::FromRow)]
struct AuditView {
    id: i64,
    actor_username: String,
    action: String,
    resource_id: Option<i64>,
    // Current name of the referenced rule or account, so the log reads as
    // sentences rather than bare identifiers. Rules keep their name after
    // soft deletion; accounts are never deleted.
    resource_kind: Option<String>,
    resource_name: Option<String>,
    resource_port: Option<i64>,
    created_at: i64,
}

async fn audit(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<AuditView>>, ApiError> {
    auth.admin()?;
    Ok(Json(sqlx::query_as("SELECT id,actor_username,action,resource_id,resource_kind,resource_name,resource_port,created_at FROM audit_events ORDER BY id DESC LIMIT 200").fetch_all(&state.pool).await?))
}

#[derive(Serialize)]
struct PortLease {
    port: i64,
    rule_id: i64,
    // "active" while the lease's rule still listens on the port; "releasing"
    // after an edit or deletion, until the executor confirms the old runtime.
    state: &'static str,
}

#[derive(Serialize)]
struct PortUsage {
    owner_id: i64,
    port_start: i64,
    port_end: i64,
    reserved: Vec<u16>,
    leases: Vec<PortLease>,
}

async fn port_usage(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<i64>,
) -> Result<Json<PortUsage>, ApiError> {
    auth.ready()?;
    if auth.user.role != "admin" && auth.user.id != id {
        return Err(ApiError::not_found());
    }
    let owner: DbUser = sqlx::query_as("SELECT * FROM users WHERE id=?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let rows: Vec<(i64, i64, bool)> = sqlx::query_as("SELECT p.port,p.rule_id,EXISTS(SELECT 1 FROM rules r WHERE r.id=p.rule_id AND r.deleted_at IS NULL AND r.listen_port=p.port) FROM port_leases p WHERE p.owner_id=? ORDER BY p.port")
        .bind(owner.id)
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(PortUsage {
        owner_id: owner.id,
        port_start: owner.port_start,
        port_end: owner.port_end,
        reserved: state
            .config
            .reserved_ports
            .iter()
            .copied()
            .filter(|port| (owner.port_start..=owner.port_end).contains(&i64::from(*port)))
            .collect(),
        leases: rows
            .into_iter()
            .map(|(port, rule_id, active)| PortLease {
                port,
                rule_id,
                state: if active { "active" } else { "releasing" },
            })
            .collect(),
    }))
}

pub async fn initialize_admin(
    pool: &SqlitePool,
    username: &str,
    password: String,
) -> anyhow::Result<()> {
    policy::validate_username(username)?;
    policy::validate_password(&password)?;
    let hash = Credentials::new().hash_password(password).await?;
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role='admin'")
        .fetch_one(&mut *tx)
        .await?;
    anyhow::ensure!(count == 0, "an administrator already exists");
    sqlx::query("INSERT INTO users(username,password_hash,role,must_change_password,port_start,port_end,max_rules,created_at) VALUES(?,?,'admin',0,40000,40049,30,?)")
        .bind(username).bind(hash).bind(now()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn api_not_found() -> ApiError {
    ApiError::not_found()
}

pub fn router(state: AppState) -> Router {
    // Client-side routes (/rules/12, /accounts) are real pages: serve the SPA
    // shell with 200. Unknown API paths are answered by api_not_found instead.
    let static_files = tower_http::services::ServeDir::new(&state.config.frontend).fallback(
        tower_http::services::ServeFile::new(state.config.frontend.join("index.html")),
    );
    Router::new()
        .route("/api/login",post(login))
        .route("/api/session",get(session))
        .route("/api/logout",post(logout))
        .route("/api/password",put(change_password))
        .route("/api/mfa/setup",post(begin_mfa))
        .route("/api/mfa/confirm",post(confirm_mfa))
        .route("/api/mfa/disable",post(disable_mfa))
        .route("/api/users",get(list_users).post(create_user))
        .route("/api/users/{id}",put(update_user))
        .route("/api/users/{id}/password",post(reset_password))
        .route("/api/users/{id}/apply",post(retry_apply))
        .route("/api/users/{id}/ports",get(port_usage))
        .route("/api/preferences",put(preferences))
        .route("/api/audit",get(audit))
        .route("/api/health",get(health))
        .merge(crate::rules::routes())
        .route("/api",axum::routing::any(api_not_found))
        .route("/api/",axum::routing::any(api_not_found))
        .route("/api/{*path}",axum::routing::any(api_not_found))
        .fallback_service(static_files)
        .layer(axum::extract::DefaultBodyLimit::max(16*1024))
        .layer(axum::middleware::from_fn(|request:axum::extract::Request,next:axum::middleware::Next|async move{
            let mut response=next.run(request).await;
            let headers=response.headers_mut();
            headers.insert(header::CACHE_CONTROL,"no-store".parse().unwrap());
            headers.insert("x-content-type-options","nosniff".parse().unwrap());
            headers.insert("referrer-policy","no-referrer".parse().unwrap());
            headers.insert("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'".parse().unwrap());
            response
        }))
        .with_state(state)
}
