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
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
    pub credentials: Credentials,
    dummy_hash: Arc<String>,
    login_limits: Arc<Mutex<HashMap<String, (i64, u32)>>>,
}

impl AppState {
    pub async fn new(pool: SqlitePool, config: Config) -> anyhow::Result<Self> {
        let credentials = Credentials::new();
        let dummy_hash = credentials.hash_password(new_session_token()).await?;
        Ok(Self {
            pool,
            config: Arc::new(config),
            credentials,
            dummy_hash: Arc::new(dummy_hash),
            login_limits: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

pub struct AuthContext {
    pub user: DbUser,
    pub csrf_token: String,
    pub session_hash: String,
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
        let row: Option<(i64, String)> = sqlx::query_as(
            "SELECT s.user_id,s.csrf_token FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.auth_version=u.auth_version AND u.enabled=1 AND (u.expires_at IS NULL OR u.expires_at>?)"
        ).bind(&session_hash).bind(now()).bind(now()).fetch_optional(&state.pool).await?;
        let (id, csrf_token) = row.ok_or_else(ApiError::unauthorized)?;
        let user: DbUser = sqlx::query_as("SELECT * FROM users WHERE id=?")
            .bind(id)
            .fetch_one(&state.pool)
            .await?;
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
    let user: Option<DbUser> = sqlx::query_as("SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.id=? AND s.token_hash=? AND s.auth_version=u.auth_version AND s.expires_at>?")
        .bind(auth.user.id).bind(&auth.session_hash).bind(now()).fetch_optional(&mut **tx).await?;
    let user = user
        .filter(DbUser::available)
        .ok_or_else(ApiError::unauthorized)?;
    if user.must_change_password {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            code: "password_change_required",
            message: "请先修改密码".into(),
        });
    }
    Ok(user)
}

pub async fn record_audit(
    tx: &mut Transaction<'_, Sqlite>,
    actor: &DbUser,
    action: &str,
    resource_id: Option<i64>,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO audit_events(actor_id,actor_username,action,resource_id,created_at) VALUES(?,?,?,?,?)")
        .bind(actor.id).bind(&actor.username).bind(action).bind(resource_id).bind(now()).execute(&mut **tx).await?;
    Ok(())
}

pub async fn enqueue_apply(
    tx: &mut Transaction<'_, Sqlite>,
    owner_id: i64,
) -> Result<(), ApiError> {
    let revision: i64 = sqlx::query_scalar("UPDATE users SET desired_revision=desired_revision+1 WHERE id=? RETURNING desired_revision")
        .bind(owner_id).fetch_one(&mut **tx).await?;
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
}

#[derive(Serialize)]
struct SessionView {
    user: UserView,
    csrf_token: String,
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
    {
        let mut limits = state.login_limits.lock().await;
        let timestamp = now();
        limits.retain(|_, (start, _)| timestamp.saturating_sub(*start) < 60);
        let keys = [
            (format!("ip:{ip}"), 32),
            (format!("user:{}", input.username.to_ascii_lowercase()), 8),
        ];
        if limits.len() >= 1024
            || keys
                .iter()
                .any(|(key, max)| limits.get(key).is_some_and(|(_, n)| n >= max))
        {
            return Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                code: "rate_limited",
                message: "登录过于频繁".into(),
            });
        }
        for (key, _) in keys {
            let entry = limits.entry(key).or_insert((timestamp, 0));
            entry.1 += 1;
        }
    }
    let user: Option<DbUser> = sqlx::query_as("SELECT * FROM users WHERE username=?")
        .bind(&input.username)
        .fetch_optional(&state.pool)
        .await?;
    let hash = user
        .as_ref()
        .map(|u| u.password_hash.clone())
        .unwrap_or_else(|| (*state.dummy_hash).clone());
    let verified = state
        .credentials
        .verify_password(input.password, hash)
        .await?;
    let user = user
        .filter(|u| verified && u.available())
        .ok_or_else(ApiError::unauthorized)?;
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
    if target.role == "admin" {
        return Err(ApiError::forbidden());
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
    created_at: i64,
}

async fn audit(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<AuditView>>, ApiError> {
    auth.admin()?;
    Ok(Json(sqlx::query_as("SELECT id,actor_username,action,resource_id,created_at FROM audit_events ORDER BY id DESC LIMIT 200").fetch_all(&state.pool).await?))
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

pub fn router(state: AppState) -> Router {
    let static_files = tower_http::services::ServeDir::new(&state.config.frontend)
        .not_found_service(tower_http::services::ServeFile::new(
            state.config.frontend.join("index.html"),
        ));
    Router::new()
        .route("/api/login",post(login))
        .route("/api/session",get(session))
        .route("/api/logout",post(logout))
        .route("/api/password",put(change_password))
        .route("/api/users",get(list_users).post(create_user))
        .route("/api/users/{id}",put(update_user))
        .route("/api/users/{id}/password",post(reset_password))
        .route("/api/preferences",put(preferences))
        .route("/api/audit",get(audit))
        .route("/api/health",get(||async{Json(serde_json::json!({"status":"ok","name":"RelayDeck","version":env!("CARGO_PKG_VERSION"),"executor":"unconfigured"}))}))
        .merge(crate::rules::routes())
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
