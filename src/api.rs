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
    extract::{ConnectInfo, FromRequestParts, MatchedPath, Path, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use sqlx::{Sqlite, SqlitePool, Transaction};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
    pub credentials: Credentials,
    pub mfa: crate::mfa::MfaService,
    pub upgrades: Option<Arc<dyn crate::upgrade::UpgradeChannel>>,
    pub connectivity: Arc<dyn crate::connectivity::CheckChannel>,
    dummy_hash: Arc<String>,
    network_limits: Arc<Mutex<crate::limits::Limits>>,
    account_limits: Arc<Mutex<crate::limits::Limits>>,
    account_failure_limits: Arc<Mutex<crate::limits::Limits>>,
    mutation_limits: Arc<Mutex<crate::limits::Limits>>,
}

impl AppState {
    pub async fn new(pool: SqlitePool, config: Config) -> anyhow::Result<Self> {
        let credentials = Credentials::new();
        let mfa = crate::mfa::MfaService::from_key_file(&config.mfa_key).map_err(|error| {
            anyhow::anyhow!("cannot load MFA key (initialize once with init-key): {error}")
        })?;
        let dummy_hash = credentials.hash_password(new_session_token()).await?;
        let upgrades = config.upgrade.as_ref().map(|config| {
            Arc::new(crate::upgrade::SocketChannel(config.socket.clone()))
                as Arc<dyn crate::upgrade::UpgradeChannel>
        });
        Ok(Self {
            connectivity: Arc::new(crate::broker::SocketDriver::new(
                std::env::var_os("RELAYDECK_BROKER_SOCKET")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| "/run/relaydeck/broker.sock".into()),
            )),
            upgrades,
            pool,
            config: Arc::new(config),
            credentials,
            mfa,
            dummy_hash: Arc::new(dummy_hash),
            network_limits: Arc::new(Mutex::new(crate::limits::Limits::new(4096))),
            account_limits: Arc::new(Mutex::new(crate::limits::Limits::new(4096))),
            account_failure_limits: Arc::new(Mutex::new(crate::limits::Limits::new(1024))),
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
            .find_map(|item| {
                item.trim()
                    .strip_prefix(&format!("{}=", cookie_name(&state.config)))
            })
            .ok_or_else(ApiError::unauthorized)?;
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ApiError::unauthorized());
        }
        let session_hash = token_hash(token);
        let row: Option<AuthRow> = sqlx::query_as(
            "SELECT u.*,s.csrf_token FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.auth_version=u.auth_version AND u.enabled=1 AND (u.expires_at IS NULL OR u.expires_at>?)"
        ).bind(&session_hash).bind(now()).bind(now()).fetch_optional(&state.pool).await?;
        let AuthRow { user, csrf_token } = row.ok_or_else(ApiError::unauthorized)?;
        // A tab carrying the previous account's CSRF token must not read data
        // using a cookie replaced by a different tab's login.
        if parts.method.is_safe()
            && parts
                .headers
                .get("x-csrf-token")
                .is_some_and(|value| value.to_str().ok() != Some(csrf_token.as_str()))
        {
            return Err(ApiError::unauthorized());
        }
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

fn cookie_name(config: &Config) -> &'static str {
    if config.secure_cookie {
        "__Host-relaydeck_session"
    } else {
        "relaydeck_session"
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

pub async fn record_system_audit(
    tx: &mut Transaction<'_, Sqlite>,
    action: &str,
    rule_id: i64,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO audit_events(actor_id,actor_username,action,resource_id,created_at,resource_kind,resource_name,resource_port) SELECT NULL,'系统',?,id,?,'rule',name,listen_port FROM rules WHERE id=?")
        .bind(action).bind(now()).bind(rule_id).execute(&mut **tx).await?;
    sqlx::query("DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT -1 OFFSET 10000)").execute(&mut **tx).await?;
    Ok(())
}

async fn record_authentication_failure(
    tx: &mut Transaction<'_, Sqlite>,
    user: &DbUser,
    action: &str,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO authentication_failures(user_id,username,action,bucket,count,last_seen) VALUES(?,?,?,?,1,?) ON CONFLICT(user_id,action,bucket) DO UPDATE SET count=count+1,last_seen=excluded.last_seen")
        .bind(user.id).bind(&user.username).bind(action).bind(now()/3600).bind(now()).execute(&mut **tx).await?;
    sqlx::query("DELETE FROM authentication_failures WHERE id IN (SELECT id FROM authentication_failures ORDER BY last_seen DESC,id DESC LIMIT -1 OFFSET 1000)").execute(&mut **tx).await?;
    Ok(())
}

pub async fn enqueue_apply(
    tx: &mut Transaction<'_, Sqlite>,
    owner_id: i64,
) -> Result<(), ApiError> {
    let revision: i64 = sqlx::query_scalar("UPDATE users SET desired_revision=MAX(desired_revision,(SELECT revision FROM runtime_slots WHERE id=COALESCE(users.runtime_slot,users.id)))+1 WHERE id=? RETURNING desired_revision")
        .bind(owner_id).fetch_one(&mut **tx).await?;
    sqlx::query("UPDATE runtime_slots SET revision=? WHERE id=(SELECT COALESCE(runtime_slot,id) FROM users WHERE id=?)").bind(revision).bind(owner_id).execute(&mut **tx).await?;
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
    can_upgrade: bool,
    user: UserView,
    csrf_token: String,
    mfa_required: bool,
    session_ref: String,
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
    let network = crate::limits::network_key(ip);
    if !state
        .network_limits
        .lock()
        .await
        .admit(network.clone(), 32, now())
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
            .admit(format!("{}:{network}", user.id), 8, now())
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
        // The wider account budget only gates failed credentials: distributed
        // guesses must never prevent a correct password on another network.
        if !state
            .account_failure_limits
            .lock()
            .await
            .admit(user.id.to_string(), 128, now())
        {
            return Err(ApiError::rate_limited());
        }
        record_authentication_failure(&mut tx, &user, "login_failed").await?;
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
    state
        .account_limits
        .lock()
        .await
        .reset(&format!("{}:{network}", user.id));
    state
        .account_failure_limits
        .lock()
        .await
        .reset(&user.id.to_string());
    let value = SessionView {
        can_upgrade: owner_identity(&state, &user),
        user: user_view(&state.pool, user.id).await?,
        csrf_token,
        session_ref: token_hash(&token),
        mfa_required: state.config.require_admin_mfa && user.role == "admin",
    };
    let mut response = Json(value).into_response();
    let secure = if state.config.secure_cookie {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800{secure}",
        cookie_name(&state.config)
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
        can_upgrade: owner_identity(&state, &auth.user),
        user: user_view(&state.pool, auth.user.id).await?,
        csrf_token: auth.csrf_token,
        session_ref: auth.session_hash,
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
        format!(
            "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}",
            cookie_name(&state.config)
        )
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
    record_authentication_failure(tx, user, action).await
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
    #[serde(default = "default_port_quota")]
    max_rules: i64,
    expires_at: Option<i64>,
    #[serde(default)]
    traffic: crate::traffic::TrafficBudget,
}

fn default_port_quota() -> i64 {
    10
}

async fn create_user(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(input): Json<CreateUser>,
) -> Result<(StatusCode, Json<UserView>), ApiError> {
    auth.admin()?;
    policy::validate_username(&input.username)?;
    input.traffic.validate()?;
    policy::validate_password(&input.password)?;
    policy::validate_port_grant(1024, 65535, input.max_rules)?;
    if input.expires_at.is_some() {
        return Err(ApiError::bad_request("订阅周期固定为30天"));
    }
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
    let slot: Option<i64> = sqlx::query_scalar("SELECT id FROM runtime_slots WHERE id NOT IN (SELECT COALESCE(runtime_slot,id) FROM users) ORDER BY id LIMIT 1").fetch_optional(&mut *tx).await?;
    let slot = slot.ok_or_else(|| ApiError::conflict("运行席位已满"))?;
    let id = crate::subscriptions::next_identity(&mut tx, "account").await?;
    let cycle = crate::subscriptions::next_identity(&mut tx, "subscription").await?;
    let start = now();
    let end = start + crate::subscriptions::PERIOD_SECONDS;
    sqlx::query("INSERT INTO users(id,username,password_hash,role,port_start,port_end,max_rules,expires_at,created_at,traffic_limit_bytes,traffic_mode,runtime_slot,subscription_id,subscription_started_at,traffic_period_start,traffic_reset_at) VALUES(?,?,?,'user',1024,65535,?,?,?,?,?,?,?,?,?,?)")
        .bind(id).bind(input.username).bind(hash).bind(input.max_rules).bind(end).bind(start)
        .bind(input.traffic.limit_bytes).bind(input.traffic.mode.as_str()).bind(slot).bind(cycle).bind(start).bind(start).bind(end)
        .execute(&mut *tx).await?;
    sqlx::query("UPDATE users SET desired_revision=(SELECT CASE WHEN revision=0 THEN 0 ELSE revision+1 END FROM runtime_slots WHERE id=?),applied_revision=(SELECT CASE WHEN revision=0 THEN 0 ELSE revision+1 END FROM runtime_slots WHERE id=?) WHERE id=?").bind(slot).bind(slot).bind(id).execute(&mut *tx).await?;
    sqlx::query("UPDATE runtime_slots SET revision=(SELECT desired_revision FROM users WHERE id=?) WHERE id=?").bind(id).bind(slot).execute(&mut *tx).await?;
    record_audit(&mut tx, &actor, "user_created", Some(id)).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(user_view(&state.pool, id).await?)))
}

async fn user_traffic(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<i64>,
) -> Result<Json<crate::traffic::TrafficView>, ApiError> {
    auth.ready()?;
    if auth.user.role != "admin" && auth.user.id != id {
        return Err(ApiError::not_found());
    }
    let user: DbUser = sqlx::query_as("SELECT * FROM users WHERE id=?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(ApiError::not_found)?;
    Ok(Json(crate::traffic::TrafficView::from_user(&user)))
}

pub async fn record_system_user_audit(
    tx: &mut Transaction<'_, Sqlite>,
    action: &str,
    id: i64,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO audit_events(actor_id,actor_username,action,resource_id,created_at,resource_kind,resource_name) SELECT NULL,'系统',?,id,?,'user',username FROM users WHERE id=?")
        .bind(action).bind(now()).bind(id).execute(&mut **tx).await?;
    sqlx::query("DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT -1 OFFSET 10000)").execute(&mut **tx).await?;
    Ok(())
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
        let mut view = UserView::from_user(user, count);
        if view.deletion_requested_at.is_some() {
            view.deletion_error =
                sqlx::query_scalar("SELECT last_error FROM runtime_states WHERE owner_id=?")
                    .bind(view.id)
                    .fetch_optional(&state.pool)
                    .await?
                    .flatten();
        }
        result.push(view);
    }
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateUser {
    enabled: bool,
    max_rules: i64,
    expires_at: Option<i64>,
    traffic: Option<crate::traffic::TrafficBudget>,
}

async fn update_user(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<i64>,
    Json(input): Json<UpdateUser>,
) -> Result<Json<UserView>, ApiError> {
    auth.admin()?;
    if let Some(budget) = &input.traffic {
        budget.validate()?;
    }
    policy::validate_port_grant(1024, 65535, input.max_rules)?;
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
    if target.deletion_requested_at.is_some() {
        return Err(ApiError::conflict("账户正在删除"));
    }
    if input.expires_at.is_some() && input.expires_at != target.expires_at {
        return Err(ApiError::bad_request("请通过续订延长订阅"));
    }
    if target.role == "admin" && (!input.enabled || input.expires_at.is_some()) {
        return Err(ApiError::bad_request("管理员不能停用或设置到期时间"));
    }
    if let Some(budget) = &input.traffic {
        sqlx::query("UPDATE users SET traffic_ready=CASE WHEN traffic_limit_bytes IS ? AND traffic_mode=? THEN traffic_ready ELSE 0 END,traffic_limit_bytes=?,traffic_mode=? WHERE id=?")
            .bind(budget.limit_bytes).bind(budget.mode.as_str())
            .bind(budget.limit_bytes)
            .bind(budget.mode.as_str())
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE users SET enabled=?,port_start=?,port_end=?,max_rules=?,auth_version=auth_version+1 WHERE id=?")
        .bind(input.enabled).bind(1024).bind(65535).bind(input.max_rules).bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM sessions WHERE user_id=?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    // Lowering the quota never leaves more active rules than authorized.
    sqlx::query("UPDATE rules SET enabled=0,updated_at=? WHERE id IN (SELECT id FROM rules WHERE owner_id=? AND deleted_at IS NULL AND enabled=1 ORDER BY created_at,id LIMIT -1 OFFSET ?)")
        .bind(now()).bind(id).bind(input.max_rules).execute(&mut *tx).await?;
    enqueue_apply(&mut tx, id).await?;
    record_audit(&mut tx, &actor, "user_updated", Some(id)).await?;
    tx.commit().await?;
    Ok(Json(user_view(&state.pool, id).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewSubscription {
    subscription_id: i64,
}

async fn renew_subscription(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<i64>,
    Json(input): Json<RenewSubscription>,
) -> Result<Json<UserView>, ApiError> {
    auth.admin()?;
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
    if target.role != "user" {
        return Err(ApiError::forbidden());
    }
    if target.deletion_requested_at.is_some() {
        return Err(ApiError::conflict("账户正在删除"));
    }
    if target.subscription_id != input.subscription_id {
        return Err(ApiError::conflict("订阅已变更，请刷新"));
    }
    let start = now();
    if target.expires_at.is_none_or(|end| end > start) {
        return Err(ApiError::conflict("订阅尚未到期"));
    }
    let end = start + crate::subscriptions::PERIOD_SECONDS;
    let cycle = crate::subscriptions::next_identity(&mut tx, "subscription").await?;
    sqlx::query("UPDATE users SET enabled=1,subscription_id=?,subscription_started_at=?,expires_at=?,auth_version=auth_version+1,traffic_in_bytes=0,traffic_out_bytes=0,traffic_used_bytes=0,traffic_period_start=?,traffic_reset_at=?,traffic_blocked=0,traffic_ready=0,traffic_observed_at=NULL,traffic_error=NULL WHERE id=?")
        .bind(cycle).bind(start).bind(end).bind(start).bind(end).bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM sessions WHERE user_id=?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    enqueue_apply(&mut tx, id).await?;
    record_audit(&mut tx, &actor, "subscription_renewed", Some(id)).await?;
    tx.commit().await?;
    Ok(Json(user_view(&state.pool, id).await?))
}

async fn delete_user(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<i64>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    auth.admin()?;
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
    if target.role != "user" || target.id == actor.id {
        return Err(ApiError::forbidden());
    }
    sqlx::query("UPDATE users SET enabled=0,deletion_requested_at=COALESCE(deletion_requested_at,?),auth_version=auth_version+1 WHERE id=?")
        .bind(now()).bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM sessions WHERE user_id=?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE rules SET enabled=0,deleted_at=COALESCE(deleted_at,?),updated_at=? WHERE owner_id=?")
        .bind(now()).bind(now()).bind(id).execute(&mut *tx).await?;
    enqueue_apply(&mut tx, id).await?;
    record_audit(&mut tx, &actor, "user_deletion_requested", Some(id)).await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"status":"deleting"})),
    ))
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
    if target.role == "admin" || target.deletion_requested_at.is_some() {
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
    failure_count: i64,
    id: i64,
    actor_username: String,
    action: String,
    resource_id: Option<i64>,
    // Event-time name of the referenced rule or account, so the log reads as
    // sentences rather than bare identifiers. Rules keep their name after
    // deletion; audit snapshots remain after account removal.
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
    Ok(Json(sqlx::query_as("SELECT * FROM (SELECT id,actor_username,action,resource_id,resource_kind,resource_name,resource_port,created_at,0 AS failure_count FROM audit_events ORDER BY id DESC LIMIT 200) UNION ALL SELECT * FROM (SELECT -id,username,action,user_id,'user',username,NULL,last_seen,count FROM authentication_failures ORDER BY last_seen DESC,id DESC LIMIT 50) ORDER BY created_at DESC,id DESC").fetch_all(&state.pool).await?))
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
        port_start: 1024,
        port_end: 65535,
        reserved: state
            .config
            .reserved_ports
            .iter()
            .copied()
            .filter(|port| *port >= 1024)
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
    let cycle = crate::subscriptions::next_identity(&mut tx, "subscription").await?;
    sqlx::query("INSERT INTO users(username,password_hash,role,must_change_password,port_start,port_end,max_rules,created_at,runtime_slot,subscription_id,subscription_started_at) VALUES(?,?,'admin',0,1024,65535,10,?,1,?,?)")
        .bind(username).bind(hash).bind(now()).bind(cycle).bind(now()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

fn owner_identity(state: &AppState, user: &DbUser) -> bool {
    user.role == "admin"
        && state
            .config
            .upgrade
            .as_ref()
            .is_some_and(|config| config.owner_id == user.id)
}

fn upgrade_owner(state: &AppState, auth: &AuthContext) -> Result<(), ApiError> {
    auth.admin()?;
    if !owner_identity(state, &auth.user) {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

async fn upgrade_request(
    state: &AppState,
    request: serde_json::Value,
) -> Result<Json<serde_json::Value>, ApiError> {
    let channel = state.upgrades.as_ref().ok_or_else(ApiError::unavailable)?;
    Ok(Json(channel.request(request).await?))
}

async fn upgrade_status(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<serde_json::Value>, ApiError> {
    upgrade_owner(&state, &auth)?;
    upgrade_request(&state, crate::upgrade::status_request()).await
}

async fn check_upgrade(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<serde_json::Value>, ApiError> {
    upgrade_owner(&state, &auth)?;
    sensitive_limit(&state, auth.user.id).await?;
    upgrade_request(&state, serde_json::json!({"op":"check"})).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpgradeRequest {
    offer: String,
    password: String,
    code: String,
    acknowledge: bool,
}

async fn start_upgrade(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(input): Json<UpgradeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    upgrade_owner(&state, &auth)?;
    if !input.acknowledge
        || input.offer.len() != 64
        || !input.offer.bytes().all(|byte| byte.is_ascii_hexdigit())
        || input.code.len() != 6
        || !input.code.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ApiError::bad_request("请确认转发中断并输入验证码"));
    }
    tracing::info!(
        owner_id = auth.user.id,
        stage = "password",
        "upgrade authorization started"
    );
    if let Err(mut error) = reauthenticate(&state, &auth, input.password).await {
        if error.code == "invalid_input" {
            let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
            let actor = mfa_actor(&mut tx, &auth).await?;
            record_authentication_failure(&mut tx, &actor, "panel_upgrade_password_failed").await?;
            tx.commit().await?;
            error.code = "password_invalid";
        }
        tracing::warn!(
            owner_id = auth.user.id,
            code = error.code,
            "upgrade password authorization rejected"
        );
        return Err(error);
    }
    tracing::info!(
        owner_id = auth.user.id,
        stage = "mfa",
        "upgrade password verified"
    );
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let actor = mfa_actor(&mut tx, &auth).await?;
    if !owner_identity(&state, &actor) || actor.mfa_secret.is_none() {
        return Err(ApiError::forbidden());
    }
    // Password verification must refer to this transaction's still-current credentials.
    if actor.password_hash != auth.user.password_hash {
        return Err(ApiError::unauthorized());
    }
    check_mfa_budget(&actor, &input.code)?;
    if !state
        .mfa
        .verify(&mut tx, actor.id, &input.code, now())
        .await?
    {
        record_mfa_failure(&mut tx, &actor, "panel_upgrade_mfa_failed").await?;
        tx.commit().await?;
        tracing::warn!(owner_id = actor.id, "upgrade MFA authorization rejected");
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "mfa_invalid",
            message: "验证码无效或已过期".into(),
        });
    }
    clear_mfa_failures(&mut tx, actor.id).await?;
    record_audit(&mut tx, &actor, "panel_upgrade_requested", Some(actor.id)).await?;
    tx.commit().await?;
    // The root-owned offer expires once accepted. No URLs, checksums, paths or commands cross this boundary.
    tracing::info!(
        owner_id = actor.id,
        stage = "submit",
        "upgrade authorization accepted"
    );
    let result = upgrade_request(
        &state,
        serde_json::json!({"op":"start","offer":input.offer}),
    )
    .await;
    match &result {
        Ok(_) => tracing::info!(owner_id = actor.id, "upgrade job acknowledged"),
        Err(error) => tracing::warn!(
            owner_id = actor.id,
            code = error.code,
            "upgrade job acknowledgement failed"
        ),
    }
    result
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
    let maintenance = state
        .config
        .upgrade
        .as_ref()
        .map(|config| config.maintenance.clone());
    Router::new()
        .route("/api/login",post(login))
        .route("/api/session",get(session))
        .route("/api/logout",post(logout))
        .route("/api/password",put(change_password))
        .route("/api/mfa/setup",post(begin_mfa))
        .route("/api/mfa/confirm",post(confirm_mfa))
        .route("/api/mfa/disable",post(disable_mfa))
        .route("/api/users",get(list_users).post(create_user))
        .route("/api/users/{id}",put(update_user).delete(delete_user))
        .route("/api/users/{id}/subscription",post(renew_subscription))
        .route("/api/users/{id}/password",post(reset_password))
        .route("/api/users/{id}/apply",post(retry_apply))
        .route("/api/users/{id}/ports",get(port_usage))
        .route("/api/users/{id}/traffic",get(user_traffic))
        .route("/api/preferences",put(preferences))
        .route("/api/audit",get(audit))
        .route("/api/health",get(health))
        .route("/api/system/update",get(upgrade_status).post(start_upgrade))
        .route("/api/system/update/check",post(check_upgrade))
        .merge(crate::rules::routes())
        .route("/api",axum::routing::any(api_not_found))
        .route("/api/",axum::routing::any(api_not_found))
        .route("/api/{*path}",axum::routing::any(api_not_found))
        .fallback_service(static_files)
        .layer(axum::extract::DefaultBodyLimit::max(16*1024))
        .layer(axum::middleware::from_fn(move |request:axum::extract::Request,next:axum::middleware::Next| {
            let maintenance = maintenance.clone();
            async move {
            let started = Instant::now();
            let method = request.method().clone();
            // Log route patterns only, never URLs, query strings, headers or request bodies.
            let route = request.extensions().get::<MatchedPath>().map(|path| path.as_str().to_owned()).unwrap_or_else(|| "static".into());
            let upgrade_mutation = method == axum::http::Method::POST && matches!(route.as_str(), "/api/system/update" | "/api/system/update/check");
            if upgrade_mutation { tracing::info!(%method, %route, "upgrade HTTP request received"); }
            // Once the snapshot is taken, reject external writes until commit or recovery completes.
            // New services may be serving health/read requests before the upgrade's final decision.
            let writing_api = request.uri().path().starts_with("/api/") && !matches!(*request.method(), axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS);
            let locked = match maintenance { Some(path) if writing_api => tokio::fs::try_exists(path).await.unwrap_or(true), _ => false };
            let mut response=if locked { ApiError::unavailable().into_response() } else { next.run(request).await };
            let elapsed_ms = started.elapsed().as_millis();
            let status = response.status().as_u16();
            if elapsed_ms >= 2000 || response.status().is_server_error() {
                tracing::warn!(%method, %route, status, elapsed_ms, "HTTP request slow or failed");
            } else if upgrade_mutation {
                tracing::info!(%method, %route, status, elapsed_ms, "upgrade HTTP request completed");
            }
            let headers=response.headers_mut();
            headers.insert(header::CACHE_CONTROL,"no-store".parse().unwrap());
            headers.insert("x-content-type-options","nosniff".parse().unwrap());
            headers.insert("referrer-policy","no-referrer".parse().unwrap());
            headers.insert("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'".parse().unwrap());
            response
        }}))
        .with_state(state)
}
