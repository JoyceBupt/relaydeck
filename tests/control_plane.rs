use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use relaydeck::{
    api::{AppState, initialize_admin, router},
    config::Config,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const ADMIN_PASSWORD: &str = "only-testing-admin-password";
const INITIAL_PASSWORD: &str = "only-testing-initial-password";
const USER_PASSWORD: &str = "only-testing-user-password";
const ORIGIN: &str = "https://relaydeck.test:17443";

struct Login {
    cookie: String,
    csrf: String,
    user: Value,
}
struct Fixture {
    _dir: tempfile::TempDir,
    state: AppState,
    app: Router,
    admin: Login,
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    login: Option<&Login>,
    csrf: bool,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::ORIGIN, ORIGIN);
    if let Some(login) = login {
        request = request.header(header::COOKIE, &login.cookie);
        if csrf {
            request = request.header("x-csrf-token", &login.csrf);
        }
    }
    if body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(
                    body.map(|v| Body::from(v.to_string()))
                        .unwrap_or_else(Body::empty),
                )
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).expect("JSON API response")
    };
    (status, headers, value)
}

async fn sign_in(app: &Router, username: &str, password: &str) -> Login {
    let (status, headers, value) = call(
        app,
        "POST",
        "/api/login",
        Some(json!({"username":username,"password":password})),
        None,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(
        cookie.contains("HttpOnly")
            && cookie.contains("Secure")
            && cookie.contains("SameSite=Strict")
    );
    assert!(cookie.starts_with("__Host-relaydeck_session="));
    Login {
        cookie: cookie.split(';').next().unwrap().into(),
        csrf: value["csrf_token"].as_str().unwrap().into(),
        user: value["user"].clone(),
    }
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("data/relaydeck.db");
        let pool = relaydeck::db::connect(&database).await.unwrap();
        initialize_admin(&pool, "adminroot", ADMIN_PASSWORD.into())
            .await
            .unwrap();
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            mfa_key: database.with_file_name("mfa.key"),
            require_admin_mfa: false,
            upgrade: None,
            database,
            public_origin: ORIGIN.into(),
            secure_cookie: true,
            trust_proxy: false,
            reserved_ports: vec![22, 80, 443, 40005],
            local_ips: vec!["8.8.4.4".parse().unwrap()],
            frontend: dir.path().join("missing"),
        };
        relaydeck::mfa::MfaService::create_key_file(&config.mfa_key).unwrap();
        let state = AppState::new(pool, config).await.unwrap();
        let app = router(state.clone());
        let admin = sign_in(&app, "adminroot", ADMIN_PASSWORD).await;
        Self {
            _dir: dir,
            state,
            app,
            admin,
        }
    }
    async fn add_user(&self, username: &str, _start: i64) -> Login {
        let (status,_,value)=call(&self.app,"POST","/api/users",Some(json!({"username":username,"password":INITIAL_PASSWORD,"max_rules":3,"expires_at":null})),Some(&self.admin),true).await;
        assert_eq!(status, StatusCode::CREATED, "{value}");
        let initial = sign_in(&self.app, username, INITIAL_PASSWORD).await;
        let (status, _, value) = call(
            &self.app,
            "PUT",
            "/api/password",
            Some(json!({"current_password":INITIAL_PASSWORD,"new_password":USER_PASSWORD})),
            Some(&initial),
            true,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{value}");
        let (status, _, _) = call(
            &self.app,
            "GET",
            "/api/session",
            None,
            Some(&initial),
            false,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        sign_in(&self.app, username, USER_PASSWORD).await
    }
}

fn rule(port: i64) -> Value {
    json!({"name":"测试转发","listen_port":port,"target_host":"8.8.8.8","target_port":443,"protocol":"both","source_cidrs":["203.0.113.7/24"],"enabled":true})
}

async fn enroll(f: &Fixture, login: &Login, password: &str) -> (String, Vec<String>) {
    let (status, _, setup) = call(
        &f.app,
        "POST",
        "/api/mfa/setup",
        Some(json!({"password":password})),
        Some(login),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{setup}");
    let secret = setup["secret"].as_str().unwrap();
    let generator = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(secret).unwrap())
        .build()
        .unwrap();
    let code = generator.generate(relaydeck::db::now() as u64).to_string();
    let (status, _, confirmed) = call(
        &f.app,
        "POST",
        "/api/mfa/confirm",
        Some(json!({"code":code})),
        Some(login),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{confirmed}");
    let codes = confirmed["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    (code, codes)
}

#[tokio::test]
async fn mfa_login_requires_password_and_fresh_second_factor() {
    let f = Fixture::new().await;
    let (consumed_code, codes) = enroll(&f, &f.admin, ADMIN_PASSWORD).await;
    assert_eq!(codes.len(), 10);
    let (status, _, _) = call(&f.app, "GET", "/api/session", None, Some(&f.admin), false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, headers, result) = call(
        &f.app,
        "POST",
        "/api/login",
        Some(json!({"username":"adminroot","password":ADMIN_PASSWORD})),
        None,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(result["error"]["code"], "mfa_required");
    assert!(!headers.contains_key(header::SET_COOKIE));
    let (status, headers, _) = call(
        &f.app,
        "POST",
        "/api/login",
        Some(json!({"username":"adminroot","password":"incorrect-password","code":codes[0]})),
        None,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!headers.contains_key(header::SET_COOKIE));
    let (status, headers, _) = call(
        &f.app,
        "POST",
        "/api/login",
        Some(json!({"username":"adminroot","password":ADMIN_PASSWORD,"code":consumed_code})),
        None,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!headers.contains_key(header::SET_COOKIE));
    let (status, _, value) = call(
        &f.app,
        "POST",
        "/api/login",
        Some(json!({"username":"adminroot","password":ADMIN_PASSWORD,"code":codes[0]})),
        None,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["user"]["mfa_enabled"], true);
    assert!(value["user"].get("mfa_secret").is_none());
    let (status, headers, _) = call(
        &f.app,
        "POST",
        "/api/login",
        Some(json!({"username":"adminroot","password":ADMIN_PASSWORD,"code":codes[0]})),
        None,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!headers.contains_key(header::SET_COOKIE));
    let hashes: Vec<String> = sqlx::query_scalar("SELECT code_hash FROM mfa_recovery_codes")
        .fetch_all(&f.state.pool)
        .await
        .unwrap();
    assert!(
        hashes
            .iter()
            .all(|hash| !codes.iter().any(|code| code == hash))
    );
}

#[tokio::test]
async fn public_administrator_must_enroll_and_cannot_disable_mfa() {
    let mut f = Fixture::new().await;
    std::sync::Arc::make_mut(&mut f.state.config).require_admin_mfa = true;
    f.app = router(f.state.clone());
    let (status, _, value) = call(&f.app, "GET", "/api/users", None, Some(&f.admin), false).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(value["error"]["code"], "mfa_enrollment_required");
    let (_, codes) = enroll(&f, &f.admin, ADMIN_PASSWORD).await;
    let (status, headers, value) = call(
        &f.app,
        "POST",
        "/api/login",
        Some(json!({"username":"adminroot","password":ADMIN_PASSWORD,"code":codes[0]})),
        None,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let admin = Login {
        cookie: headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .into(),
        csrf: value["csrf_token"].as_str().unwrap().into(),
        user: value["user"].clone(),
    };
    let (status, _, _) = call(&f.app, "GET", "/api/users", None, Some(&admin), false).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = call(
        &f.app,
        "POST",
        "/api/mfa/disable",
        Some(json!({"password":ADMIN_PASSWORD,"code":codes[1]})),
        Some(&admin),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mfa_mutations_require_csrf_password_and_revoke_sessions() {
    let f = Fixture::new().await;
    let alice = f.add_user("alice", 41000).await;
    let (status, _, _) = call(
        &f.app,
        "POST",
        "/api/mfa/setup",
        Some(json!({"password":USER_PASSWORD})),
        Some(&alice),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = call(
        &f.app,
        "POST",
        "/api/mfa/setup",
        Some(json!({"password":"bad-password"})),
        Some(&alice),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, codes) = enroll(&f, &alice, USER_PASSWORD).await;
    let (status, headers, value) = call(
        &f.app,
        "POST",
        "/api/login",
        Some(json!({"username":"alice","password":USER_PASSWORD,"code":codes[0]})),
        None,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let active = Login {
        cookie: headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .into(),
        csrf: value["csrf_token"].as_str().unwrap().into(),
        user: value["user"].clone(),
    };
    let (status, _, _) = call(
        &f.app,
        "POST",
        "/api/mfa/disable",
        Some(json!({"password":USER_PASSWORD,"code":codes[1]})),
        Some(&active),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = call(&f.app, "GET", "/api/session", None, Some(&active), false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let after = sign_in(&f.app, "alice", USER_PASSWORD).await;
    assert_eq!(after.user["mfa_enabled"], false);
}

#[tokio::test]
async fn runtime_reports_only_current_confirmed_revision_and_scopes_retries() {
    let f = Fixture::new().await;
    let alice = f.add_user("alice", 41000).await;
    let bob = f.add_user("bob", 42000).await;
    let (_, _, created) = call(
        &f.app,
        "POST",
        "/api/rules",
        Some(rule(41000)),
        Some(&alice),
        true,
    )
    .await;
    assert_eq!(created["runtime_status"], "pending");
    let (status, _, _) = call(
        &f.app,
        "POST",
        &format!("/api/users/{}/apply", bob.user["id"]),
        None,
        Some(&alice),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let owner = alice.user["id"].as_i64().unwrap();
    sqlx::query("INSERT INTO executor_status VALUES(1,?,'running')")
        .bind(relaydeck::db::now())
        .execute(&f.state.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO runtime_states(owner_id,revision,status,last_error,updated_at) VALUES(?,1,'active',NULL,?)")
        .bind(owner)
        .bind(relaydeck::db::now())
        .execute(&f.state.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET applied_revision=desired_revision WHERE id=?")
        .bind(owner)
        .execute(&f.state.pool)
        .await
        .unwrap();
    let (_, _, rules) = call(&f.app, "GET", "/api/rules", None, Some(&alice), false).await;
    assert_eq!(rules[0]["runtime_status"], "active");
    sqlx::query("UPDATE apply_jobs SET status='applied' WHERE owner_id=?")
        .bind(owner)
        .execute(&f.state.pool)
        .await
        .unwrap();
    let (status, _, _) = call(
        &f.app,
        "POST",
        &format!("/api/users/{owner}/apply"),
        None,
        Some(&alice),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    sqlx::query("UPDATE runtime_states SET status='failed' WHERE owner_id=?")
        .bind(owner)
        .execute(&f.state.pool)
        .await
        .unwrap();
    let (status, _, _) = call(
        &f.app,
        "POST",
        &format!("/api/users/{owner}/apply"),
        None,
        Some(&alice),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (_, _, rules) = call(&f.app, "GET", "/api/rules", None, Some(&alice), false).await;
    assert_eq!(rules[0]["runtime_status"], "pending");
    sqlx::query("UPDATE runtime_states SET revision=2,status='failed' WHERE owner_id=?")
        .bind(owner)
        .execute(&f.state.pool)
        .await
        .unwrap();
    let (_, _, rules) = call(&f.app, "GET", "/api/rules", None, Some(&alice), false).await;
    assert_eq!(rules[0]["runtime_status"], "failed");
    sqlx::query("UPDATE executor_status SET last_seen=0")
        .execute(&f.state.pool)
        .await
        .unwrap();
    let (_, _, health) = call(&f.app, "GET", "/api/health", None, None, false).await;
    assert_eq!(health["executor"], "offline");
}

#[tokio::test]
async fn authentication_csrf_and_first_login_are_enforced() {
    let f = Fixture::new().await;
    assert_eq!(
        call(&f.app, "GET", "/api/users", None, None, false).await.0,
        StatusCode::UNAUTHORIZED
    );
    let input =
        json!({"username":"alice","password":INITIAL_PASSWORD,"max_rules":3,"expires_at":null});
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/users",
            Some(input.clone()),
            Some(&f.admin),
            false
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/users",
            Some(input),
            Some(&f.admin),
            true
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let alice = sign_in(&f.app, "alice", INITIAL_PASSWORD).await;
    let (status, _, body) = call(&f.app, "GET", "/api/rules", None, Some(&alice), false).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "password_change_required");
    assert!(alice.user.get("password_hash").is_none());
    assert!(alice.user.get("auth_version").is_none());
    let request = Request::builder()
        .method("POST")
        .uri("/api/login")
        .header(header::ORIGIN, "https://attacker.test")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"username":"adminroot","password":ADMIN_PASSWORD}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        f.app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn tenants_cannot_read_edit_delete_or_create_for_others() {
    let f = Fixture::new().await;
    let alice = f.add_user("alice", 41000).await;
    let bob = f.add_user("bob", 41100).await;
    assert_eq!(
        call(&f.app, "GET", "/api/users", None, Some(&alice), false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&f.app, "GET", "/api/audit", None, Some(&alice), false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, _, created) = call(
        &f.app,
        "POST",
        "/api/rules",
        Some(rule(41000)),
        Some(&alice),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["runtime_status"], "pending");
    assert_eq!(created["source_cidrs"], json!(["203.0.113.0/24"]));
    let path = format!("/api/rules/{}", created["id"]);
    assert_eq!(
        call(&f.app, "GET", "/api/rules", None, Some(&bob), false)
            .await
            .2,
        json!([])
    );
    assert_eq!(
        call(&f.app, "PUT", &path, Some(rule(41100)), Some(&bob), true)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&f.app, "DELETE", &path, None, Some(&bob), true)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let mut forged = rule(41001);
    forged["owner_id"] = bob.user["id"].clone();
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(forged),
            Some(&alice),
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn ports_targets_quotas_and_pending_leases_are_checked() {
    let f = Fixture::new().await;
    let alice = f.add_user("alice", 41000).await;
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(1023)),
            Some(&alice),
            true
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(40005)),
            Some(&f.admin),
            true
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    for target in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "::ffff:8.8.8.8",
        "8.8.4.4",
        "http://example.com",
        "2130706433",
    ] {
        let mut input = rule(41000);
        input["target_host"] = json!(target);
        let (status, _, body) = call(
            &f.app,
            "POST",
            "/api/rules",
            Some(input),
            Some(&alice),
            true,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{target}: {body}");
    }
    let (_, _, created) = call(
        &f.app,
        "POST",
        "/api/rules",
        Some(rule(41000)),
        Some(&alice),
        true,
    )
    .await;
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(41000)),
            Some(&alice),
            true
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(41001)),
            Some(&alice),
            true
        )
        .await
        .0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(41002)),
            Some(&alice),
            true
        )
        .await
        .0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(41003)),
            Some(&alice),
            true
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &f.app,
            "DELETE",
            &format!("/api/rules/{}", created["id"]),
            None,
            Some(&alice),
            true
        )
        .await
        .0,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(41000)),
            Some(&alice),
            true
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM port_leases WHERE port=41000")
        .fetch_one(&f.state.pool)
        .await
        .unwrap();
    assert_eq!(leases, 1);
    let applied: i64 = sqlx::query_scalar("SELECT applied_revision FROM users WHERE id=?")
        .bind(alice.user["id"].as_i64().unwrap())
        .fetch_one(&f.state.pool)
        .await
        .unwrap();
    assert_eq!(applied, 0);
}

#[tokio::test]
async fn concurrent_port_creation_has_only_one_winner() {
    let f = Fixture::new().await;
    let alice = f.add_user("alice", 41000).await;
    let (a, b) = tokio::join!(
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(41000)),
            Some(&alice),
            true
        ),
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(41000)),
            Some(&alice),
            true
        )
    );
    let statuses = [a.0, b.0];
    assert!(statuses.contains(&StatusCode::CREATED), "{statuses:?}");
    assert!(statuses.contains(&StatusCode::CONFLICT), "{statuses:?}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rules WHERE owner_id=?")
        .bind(alice.user["id"].as_i64().unwrap())
        .fetch_one(&f.state.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn disabling_resetting_and_expiring_revoke_sessions() {
    let f = Fixture::new().await;
    let alice = f.add_user("alice", 41000).await;
    let id = alice.user["id"].as_i64().unwrap();
    let update = json!({"enabled":false,"max_rules":3,"expires_at":null});
    assert_eq!(
        call(
            &f.app,
            "PUT",
            &format!("/api/users/{id}"),
            Some(update.clone()),
            Some(&f.admin),
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&f.app, "GET", "/api/session", None, Some(&alice), false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/login",
            Some(json!({"username":"alice","password":USER_PASSWORD})),
            None,
            false
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let mut update = update;
    update["enabled"] = json!(true);
    assert_eq!(
        call(
            &f.app,
            "PUT",
            &format!("/api/users/{id}"),
            Some(update),
            Some(&f.admin),
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    let alice = sign_in(&f.app, "alice", USER_PASSWORD).await;
    assert_eq!(
        call(
            &f.app,
            "POST",
            &format!("/api/users/{id}/password"),
            Some(json!({"password":INITIAL_PASSWORD})),
            Some(&f.admin),
            true
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&f.app, "GET", "/api/session", None, Some(&alice), false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let reset = sign_in(&f.app, "alice", INITIAL_PASSWORD).await;
    assert_eq!(
        call(&f.app, "GET", "/api/rules", None, Some(&reset), false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE users SET expires_at=? WHERE id=?")
        .bind(relaydeck::db::now() - 1)
        .bind(id)
        .execute(&f.state.pool)
        .await
        .unwrap();
    assert_eq!(
        call(&f.app, "GET", "/api/session", None, Some(&reset), false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn preferences_are_per_user_and_secrets_stay_out_of_audit() {
    let f = Fixture::new().await;
    let alice = f.add_user("alice", 41000).await;
    let bob = f.add_user("bob", 41100).await;
    assert_eq!(
        call(
            &f.app,
            "PUT",
            "/api/preferences",
            Some(json!({"view_mode":"cards"})),
            Some(&alice),
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&f.app, "GET", "/api/session", None, Some(&alice), false)
            .await
            .2["user"]["view_mode"],
        "cards"
    );
    assert_eq!(
        call(&f.app, "GET", "/api/session", None, Some(&bob), false)
            .await
            .2["user"]["view_mode"],
        "table"
    );
    let audit = call(&f.app, "GET", "/api/audit", None, Some(&f.admin), false)
        .await
        .2
        .to_string();
    assert!(
        !audit.contains(ADMIN_PASSWORD)
            && !audit.contains(INITIAL_PASSWORD)
            && !audit.contains("argon2")
    );
    let stored: Vec<String> = sqlx::query_scalar("SELECT token_hash FROM sessions")
        .fetch_all(&f.state.pool)
        .await
        .unwrap();
    assert!(!stored.iter().any(|s| f.admin.cookie.contains(s)));
    assert!(
        initialize_admin(&f.state.pool, "anotheradmin", ADMIN_PASSWORD.into())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rules_audit_and_ports_expose_readable_runtime_context() {
    let f = Fixture::new().await;
    let alice = f.add_user("alice", 41000).await;
    let bob = f.add_user("bob", 42000).await;
    let owner = alice.user["id"].as_i64().unwrap();
    let (status, _, created) = call(
        &f.app,
        "POST",
        "/api/rules",
        Some(rule(41000)),
        Some(&alice),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["runtime_error"], Value::Null);
    sqlx::query("INSERT INTO runtime_states(owner_id,revision,status,last_error,updated_at) SELECT id,desired_revision,'failed','listener mismatch',? FROM users WHERE id=?")
        .bind(relaydeck::db::now())
        .bind(owner)
        .execute(&f.state.pool)
        .await
        .unwrap();
    let (_, _, rules) = call(&f.app, "GET", "/api/rules", None, Some(&alice), false).await;
    assert_eq!(rules[0]["runtime_status"], "failed");
    assert_eq!(rules[0]["runtime_error"], "listener mismatch");
    assert!(rules[0]["runtime_updated_at"].is_i64());
    // A failure reported for an older revision is not presented as current.
    sqlx::query("UPDATE runtime_states SET revision=revision-1 WHERE owner_id=?")
        .bind(owner)
        .execute(&f.state.pool)
        .await
        .unwrap();
    let (_, _, rules) = call(&f.app, "GET", "/api/rules", None, Some(&alice), false).await;
    assert_eq!(rules[0]["runtime_error"], Value::Null);

    let path = format!("/api/rules/{}", created["id"]);
    let (status, _, moved) =
        call(&f.app, "PUT", &path, Some(rule(41001)), Some(&alice), true).await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    let ports_path = format!("/api/users/{owner}/ports");
    let (status, _, ports) = call(&f.app, "GET", &ports_path, None, Some(&alice), false).await;
    assert_eq!(status, StatusCode::OK, "{ports}");
    assert_eq!(ports["port_start"], 1024);
    assert_eq!(ports["port_end"], 65535);
    assert_eq!(
        ports["leases"],
        json!([
            {"port":41000,"rule_id":created["id"],"state":"releasing"},
            {"port":41001,"rule_id":created["id"],"state":"active"}
        ])
    );
    assert_eq!(
        call(&f.app, "GET", &ports_path, None, Some(&bob), false)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (status, _, admin_ports) = call(
        &f.app,
        "GET",
        "/api/users/1/ports",
        None,
        Some(&f.admin),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(admin_ports["reserved"], json!([40005]));
    assert_eq!(
        call(&f.app, "GET", &ports_path, None, Some(&f.admin), false)
            .await
            .0,
        StatusCode::OK
    );

    let (_, _, audit) = call(&f.app, "GET", "/api/audit", None, Some(&f.admin), false).await;
    let entries = audit.as_array().unwrap();
    let updated = entries
        .iter()
        .find(|entry| entry["action"] == "rule_updated")
        .unwrap();
    assert_eq!(updated["resource_kind"], "rule");
    assert_eq!(updated["resource_name"], "测试转发");
    assert_eq!(updated["resource_port"], 41001);
    let created_user = entries
        .iter()
        .find(|entry| entry["action"] == "user_created" && entry["resource_id"] == owner)
        .unwrap();
    assert_eq!(created_user["resource_kind"], "user");
    assert_eq!(created_user["resource_name"], "alice");
    assert_eq!(created_user["resource_port"], Value::Null);
}

#[tokio::test]
async fn unknown_api_paths_answer_json_not_the_spa_shell() {
    let f = Fixture::new().await;
    let (status, headers, body) = call(
        &f.app,
        "GET",
        "/api/no-such-endpoint",
        None,
        Some(&f.admin),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn anonymous_name_flood_does_not_block_other_accounts_or_mutations() {
    let mut f = Fixture::new().await;
    let mut config = (*f.state.config).clone();
    config.trust_proxy = true;
    f.state.config = std::sync::Arc::new(config);
    f.app = router(f.state.clone());
    let mut tasks = tokio::task::JoinSet::new();
    // The original shared 1024-entry table was exhausted by this exact pattern.
    for client in 1..=33 {
        let app = f.app.clone();
        tasks.spawn(async move {
            for name in 0..31 {
                let response = app.clone().oneshot(Request::builder().method("POST").uri("/api/login")
                    .header(header::ORIGIN, ORIGIN).header(header::CONTENT_TYPE,"application/json")
                    .header("x-relaydeck-client-ip",format!("198.51.100.{client}"))
                    .body(Body::from(json!({"username":format!("missing_{client}_{name}"),"password":"invalid-password"}).to_string())).unwrap()).await.unwrap();
                assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            }
        });
    }
    while let Some(task) = tasks.join_next().await {
        task.unwrap();
    }
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/login")
                .header(header::ORIGIN, ORIGIN)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-relaydeck-client-ip", "203.0.113.1")
                .body(Body::from(
                    json!({"username":"adminroot","password":ADMIN_PASSWORD}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        call(
            &f.app,
            "PUT",
            "/api/preferences",
            Some(json!({"view_mode":"cards"})),
            Some(&f.admin),
            true
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn mfa_failures_lock_totp_across_restart_but_recovery_still_works() {
    let f = Fixture::new().await;
    let (consumed, codes) = enroll(&f, &f.admin, ADMIN_PASSWORD).await;
    // Replay is a guaranteed invalid second factor, unlike a random six-digit guess.
    for _ in 0..5 {
        assert_eq!(
            call(
                &f.app,
                "POST",
                "/api/login",
                Some(json!({"username":"adminroot","password":ADMIN_PASSWORD,"code":consumed})),
                None,
                false
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let restarted = router(
        AppState::new(f.state.pool.clone(), (*f.state.config).clone())
            .await
            .unwrap(),
    );
    let (status, _, value) = call(
        &restarted,
        "POST",
        "/api/login",
        Some(json!({"username":"adminroot","password":ADMIN_PASSWORD,"code":consumed})),
        None,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(value["error"]["code"], "mfa_locked");
    assert_eq!(
        call(
            &restarted,
            "POST",
            "/api/login",
            Some(json!({"username":"adminroot","password":ADMIN_PASSWORD,"code":codes[0]})),
            None,
            false
        )
        .await
        .0,
        StatusCode::OK
    );
    let failures: i64 =
        sqlx::query_scalar("SELECT mfa_failures FROM users WHERE username='adminroot'")
            .fetch_one(&f.state.pool)
            .await
            .unwrap();
    assert_eq!(failures, 0);
    let audited: i64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(count),0) FROM authentication_failures WHERE action='login_mfa_failed'")
            .fetch_one(&f.state.pool)
            .await
            .unwrap();
    assert_eq!(audited, 5);
}

#[tokio::test]
async fn api_roots_are_json_errors_and_audit_keeps_event_time_names() {
    let f = Fixture::new().await;
    for path in ["/api", "/api/"] {
        let (status, headers, _) = call(&f.app, "GET", path, None, None, false).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            headers[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("application/json")
        );
    }
    let (_, _, created) = call(
        &f.app,
        "POST",
        "/api/rules",
        Some(rule(40000)),
        Some(&f.admin),
        true,
    )
    .await;
    let id = created["id"].as_i64().unwrap();
    let mut renamed = rule(40000);
    renamed["name"] = json!("新名称");
    assert_eq!(
        call(
            &f.app,
            "PUT",
            &format!("/api/rules/{id}"),
            Some(renamed),
            Some(&f.admin),
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, _, audit) = call(&f.app, "GET", "/api/audit", None, Some(&f.admin), false).await;
    let event = audit
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["action"] == "rule_created")
        .unwrap();
    assert_eq!(event["resource_name"], "测试转发");
}

#[tokio::test]
async fn production_health_route_and_outbound_port_policy_are_enforced() {
    let f = Fixture::new().await;
    let (status, _, health) = call(&f.app, "GET", "/api/health", None, None, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(health["name"], "RelayDeck");
    assert_eq!(health["executor"], "unconfigured");
    for target in [25, 465, 587] {
        let mut input = rule(40000);
        input["target_port"] = json!(target);
        assert_eq!(
            call(
                &f.app,
                "POST",
                "/api/rules",
                Some(input),
                Some(&f.admin),
                true
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn ddns_refresh_revalidates_targets_and_retains_leases_until_stop() {
    let f = Fixture::new().await;
    let (_, _, created) = call(
        &f.app,
        "POST",
        "/api/rules",
        Some(rule(40000)),
        Some(&f.admin),
        true,
    )
    .await;
    let id = created["id"].as_i64().unwrap();
    sqlx::query("UPDATE rules SET target_host='relay.example',dns_checked_at=0 WHERE id=?")
        .bind(id)
        .execute(&f.state.pool)
        .await
        .unwrap();
    relaydeck::worker::refresh_dns(&f.state.pool, &[], |_, _| async { Ok("1.1.1.1".into()) })
        .await
        .unwrap();
    let (_, _, rules) = call(&f.app, "GET", "/api/rules", None, Some(&f.admin), false).await;
    assert_eq!(rules[0]["target_ip"], "1.1.1.1");
    sqlx::query("UPDATE rules SET dns_checked_at=0 WHERE id=?")
        .bind(id)
        .execute(&f.state.pool)
        .await
        .unwrap();
    relaydeck::worker::refresh_dns(&f.state.pool, &[], |_, _| async { Ok("127.0.0.1".into()) })
        .await
        .unwrap();
    let (_, _, rules) = call(&f.app, "GET", "/api/rules", None, Some(&f.admin), false).await;
    assert_eq!(rules[0]["enabled"], true);
    assert_eq!(rules[0]["runtime_status"], "blocked");
    assert!(rules[0]["dns_error"].is_string());
    let leased: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM port_leases WHERE rule_id=?")
        .bind(id)
        .fetch_one(&f.state.pool)
        .await
        .unwrap();
    assert_eq!(leased, 1);
    let (_, _, audit) = call(&f.app, "GET", "/api/audit", None, Some(&f.admin), false).await;
    let blocked = audit
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["action"] == "rule_dns_blocked")
        .unwrap();
    assert_eq!(blocked["actor_username"], "系统");
    sqlx::query("UPDATE rules SET dns_checked_at=0 WHERE id=?")
        .bind(id)
        .execute(&f.state.pool)
        .await
        .unwrap();
    relaydeck::worker::refresh_dns(&f.state.pool, &[], |_, _| async { Ok("1.1.1.1".into()) })
        .await
        .unwrap();
    let (_, _, rules) = call(&f.app, "GET", "/api/rules", None, Some(&f.admin), false).await;
    assert!(rules[0]["dns_error"].is_null());
    assert_ne!(rules[0]["runtime_status"], "blocked");
}

#[tokio::test]
async fn administrator_grants_are_editable_without_allowing_self_revocation() {
    let f = Fixture::new().await;
    let id = f.admin.user["id"].as_i64().unwrap();
    let input = json!({"enabled":true,"max_rules":8,"expires_at":null});
    let (status, _, user) = call(
        &f.app,
        "PUT",
        &format!("/api/users/{id}"),
        Some(input),
        Some(&f.admin),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(user["max_rules"], 8);
    assert_eq!(user["port_start"], 1024);
    let fresh = sign_in(&f.app, "adminroot", ADMIN_PASSWORD).await;
    let input = json!({"enabled":false,"max_rules":8,"expires_at":null});
    assert_eq!(
        call(
            &f.app,
            "PUT",
            &format!("/api/users/{id}"),
            Some(input),
            Some(&fresh),
            true
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn stale_tab_cannot_read_with_another_accounts_cookie() {
    let f = Fixture::new().await;
    let alice = f.add_user("alice", 41000).await;
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/rules")
                .header(header::COOKIE, &alice.cookie)
                .header("x-csrf-token", &f.admin.csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        call(&f.app, "GET", "/api/rules", None, Some(&alice), false)
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn ipv6_rotation_within_one_subnet_cannot_bypass_network_limit() {
    let f = Fixture::new().await;
    let mut config = (*f.state.config).clone();
    config.trust_proxy = true;
    let app = router(AppState::new(f.state.pool.clone(), config).await.unwrap());
    for suffix in 1..=33 {
        let response=app.clone().oneshot(Request::builder().method("POST").uri("/api/login")
            .header(header::ORIGIN,ORIGIN).header(header::CONTENT_TYPE,"application/json")
            .header("x-relaydeck-client-ip",format!("2001:db8:1234:1::{suffix:x}"))
            .body(Body::from(json!({"username":format!("missing_{suffix}"),"password":"invalid-password"}).to_string())).unwrap()).await.unwrap();
        assert_eq!(
            response.status(),
            if suffix <= 32 {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
}

async fn login_from(app: &Router, ip: &str, password: &str) -> StatusCode {
    let request = Request::builder()
        .method("POST")
        .uri("/api/login")
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .extension(axum::extract::ConnectInfo(
            format!("{ip}:12345")
                .parse::<std::net::SocketAddr>()
                .unwrap(),
        ))
        .body(Body::from(
            json!({"username":"adminroot","password":password}).to_string(),
        ))
        .unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn one_network_cannot_lock_admin_elsewhere_and_success_resets_pair_budget() {
    let f = Fixture::new().await;
    for _ in 0..8 {
        assert_eq!(
            login_from(&f.app, "192.0.2.10", "wrong").await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        login_from(&f.app, "192.0.2.10", ADMIN_PASSWORD).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        login_from(&f.app, "192.0.2.11", ADMIN_PASSWORD).await,
        StatusCode::OK
    );
    for _ in 0..7 {
        assert_eq!(
            login_from(&f.app, "192.0.2.11", "wrong").await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        login_from(&f.app, "192.0.2.11", ADMIN_PASSWORD).await,
        StatusCode::OK
    );
    assert_eq!(
        login_from(&f.app, "192.0.2.11", "wrong").await,
        StatusCode::UNAUTHORIZED
    );
    // Exhaust the account-wide failed-credential budget across many networks.
    for index in 30..47 {
        for _ in 0..8 {
            login_from(&f.app, &format!("192.0.2.{index}"), "wrong").await;
        }
    }
    assert_eq!(
        login_from(&f.app, "192.0.2.90", ADMIN_PASSWORD).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn failed_logins_are_aggregated_without_evicting_operation_audit() {
    let f = Fixture::new().await;
    sqlx::query("DELETE FROM audit_events")
        .execute(&f.state.pool)
        .await
        .unwrap();
    sqlx::query("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<10000) INSERT INTO audit_events(actor_id,actor_username,action,created_at) SELECT 1,'adminroot','password_changed',x FROM n").execute(&f.state.pool).await.unwrap();
    for ip in ["192.0.2.20", "192.0.2.21"] {
        for _ in 0..8 {
            assert_eq!(
                login_from(&f.app, ip, "wrong").await,
                StatusCode::UNAUTHORIZED
            );
        }
    }
    let retained: (i64, i64) = sqlx::query_as("SELECT COUNT(*),MIN(id) FROM audit_events")
        .fetch_one(&f.state.pool)
        .await
        .unwrap();
    assert_eq!(retained, (10000, 1));
    let summary: (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*),SUM(count) FROM authentication_failures WHERE action='login_failed'",
    )
    .fetch_one(&f.state.pool)
    .await
    .unwrap();
    assert!((1..=2).contains(&summary.0));
    assert_eq!(summary.1, 16);
    let (_, _, audit) = call(&f.app, "GET", "/api/audit", None, Some(&f.admin), false).await;
    assert_eq!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["action"] == "password_changed")
            .count(),
        200
    );
    assert_eq!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["action"] == "login_failed")
            .map(|e| e["failure_count"].as_i64().unwrap())
            .sum::<i64>(),
        16
    );
}

struct TestUpgrader(std::sync::Mutex<Vec<Value>>);
impl relaydeck::upgrade::UpgradeChannel for TestUpgrader {
    fn request(&self, request: Value) -> relaydeck::upgrade::UpgradeFuture<'_> {
        self.0.lock().unwrap().push(request);
        Box::pin(async {
            Ok(json!({"current_version":"0.1.0","latest":null,"job":{"phase":"queued"}}))
        })
    }
}

#[tokio::test]
async fn panel_upgrade_is_scoped_to_the_pinned_owner_even_for_other_administrators() {
    let mut f = Fixture::new().await;
    let tenant = f.add_user("upgradeuser", 41000).await;
    let channel = std::sync::Arc::new(TestUpgrader(std::sync::Mutex::new(vec![])));
    std::sync::Arc::make_mut(&mut f.state.config).upgrade =
        Some(relaydeck::upgrade::UpgradeConfig {
            owner_id: 1,
            socket: "/unused".into(),
            maintenance: f._dir.path().join("upgrade-transaction.json"),
        });
    f.state.upgrades = Some(channel.clone());
    f.app = router(f.state.clone());
    for route in ["/api/system/update", "/api/system/update/check"] {
        let method = if route.ends_with("check") {
            "POST"
        } else {
            "GET"
        };
        let (status, _, _) = call(&f.app, method, route, None, None, false).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = call(&f.app, method, route, None, Some(&tenant), true).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        sqlx::query("UPDATE users SET role='admin' WHERE id=?")
            .bind(tenant.user["id"].as_i64().unwrap())
            .execute(&f.state.pool)
            .await
            .unwrap();
        let (status, _, _) = call(&f.app, method, route, None, Some(&tenant), true).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (_, _, session) = call(&f.app, "GET", "/api/session", None, Some(&tenant), false).await;
    assert_eq!(session["can_upgrade"], false);
    assert!(channel.0.lock().unwrap().is_empty());
    let (status, _, session) =
        call(&f.app, "GET", "/api/session", None, Some(&f.admin), false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(session["can_upgrade"], true);
    let (status, _, _) = call(
        &f.app,
        "GET",
        "/api/system/update",
        None,
        Some(&f.admin),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn panel_upgrade_requires_csrf_fresh_password_totp_and_interruption_consent() {
    let mut f = Fixture::new().await;
    std::sync::Arc::make_mut(&mut f.state.config).upgrade =
        Some(relaydeck::upgrade::UpgradeConfig {
            owner_id: 1,
            socket: "/unused".into(),
            maintenance: f._dir.path().join("upgrade-transaction.json"),
        });
    let channel = std::sync::Arc::new(TestUpgrader(std::sync::Mutex::new(vec![])));
    f.state.upgrades = Some(channel.clone());
    f.app = router(f.state.clone());
    let payload = json!({"offer":"a".repeat(64),"password":ADMIN_PASSWORD,"code":"123456","acknowledge":true});
    let (status, _, _) = call(
        &f.app,
        "POST",
        "/api/system/update",
        Some(payload.clone()),
        Some(&f.admin),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = call(
        &f.app,
        "POST",
        "/api/system/update",
        Some(payload),
        Some(&f.admin),
        true,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "MFA enrollment is mandatory even when local admin MFA policy is optional"
    );
    let (status, _, setup) = call(
        &f.app,
        "POST",
        "/api/mfa/setup",
        Some(json!({"password":ADMIN_PASSWORD})),
        Some(&f.admin),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let generator = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(setup["secret"].as_str().unwrap()).unwrap())
        .build()
        .unwrap();
    let current = generator.generate(relaydeck::db::now() as u64).to_string();
    let (_, _, codes) = call(
        &f.app,
        "POST",
        "/api/mfa/confirm",
        Some(json!({"code":current})),
        Some(&f.admin),
        true,
    )
    .await;
    let (status, headers, session) = call(&f.app, "POST", "/api/login", Some(json!({"username":"adminroot","password":ADMIN_PASSWORD,"code":codes["recovery_codes"][0]})), None, false).await;
    assert_eq!(status, StatusCode::OK);
    let owner = Login {
        cookie: headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .into(),
        csrf: session["csrf_token"].as_str().unwrap().into(),
        user: session["user"].clone(),
    };
    // The allowed next time step is fresh and avoids a wall-clock sleep.
    let fresh = generator
        .generate((relaydeck::db::now() + 30) as u64)
        .to_string();
    for input in [
        json!({"offer":"a".repeat(64),"password":"wrong-password","code":fresh,"acknowledge":true}),
        json!({"offer":"a".repeat(64),"password":ADMIN_PASSWORD,"code":fresh,"acknowledge":false}),
        json!({"offer":"https://attacker.test/archive","password":ADMIN_PASSWORD,"code":fresh,"acknowledge":true}),
    ] {
        let (status, _, _) = call(
            &f.app,
            "POST",
            "/api/system/update",
            Some(input),
            Some(&owner),
            true,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert!(channel.0.lock().unwrap().is_empty());
    let payload =
        json!({"offer":"a".repeat(64),"password":ADMIN_PASSWORD,"code":fresh,"acknowledge":true});
    let (status, _, _) = call(
        &f.app,
        "POST",
        "/api/system/update",
        Some(payload.clone()),
        Some(&owner),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        *channel.0.lock().unwrap(),
        vec![json!({"op":"start","offer":"a".repeat(64)})]
    );
    let (status, _, _) = call(
        &f.app,
        "POST",
        "/api/system/update",
        Some(payload),
        Some(&owner),
        true,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a consumed upgrade TOTP must not be replayed"
    );
    assert_eq!(channel.0.lock().unwrap().len(), 1);
    let audit: Vec<(String,)> =
        sqlx::query_as("SELECT action FROM audit_events WHERE action LIKE 'panel_upgrade%'")
            .fetch_all(&f.state.pool)
            .await
            .unwrap();
    assert_eq!(audit, vec![("panel_upgrade_requested".into(),)]);
    let failures: i64 = sqlx::query_scalar(
        "SELECT SUM(count) FROM authentication_failures WHERE action='panel_upgrade_mfa_failed'",
    )
    .fetch_one(&f.state.pool)
    .await
    .unwrap();
    assert_eq!(failures, 1);
}

#[tokio::test]
async fn panel_upgrade_snapshot_blocks_external_writes_until_commit() {
    let mut f = Fixture::new().await;
    let tenant = f.add_user("upgradewriter", 41000).await;
    let marker = f._dir.path().join("upgrade-transaction.json");
    std::sync::Arc::make_mut(&mut f.state.config).upgrade =
        Some(relaydeck::upgrade::UpgradeConfig {
            owner_id: 1,
            socket: "/unused".into(),
            maintenance: marker.clone(),
        });
    f.app = router(f.state.clone());
    std::fs::write(&marker, "{}").unwrap();
    for login in [&f.admin, &tenant] {
        let (status, _, _) = call(
            &f.app,
            "PUT",
            "/api/preferences",
            Some(json!({"view_mode":"cards"})),
            Some(login),
            true,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let (status, _, _) = call(&f.app, "GET", "/api/session", None, Some(login), true).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _, _) = call(&f.app, "GET", "/api/health", None, None, false).await;
    assert_eq!(status, StatusCode::OK);
    std::fs::remove_file(marker).unwrap();
    let (status, _, _) = call(
        &f.app,
        "PUT",
        "/api/preferences",
        Some(json!({"view_mode":"cards"})),
        Some(&tenant),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn default_quota_allows_ten_arbitrary_ports_in_shared_pool() {
    let f = Fixture::new().await;
    let (status, _, user) = call(
        &f.app,
        "POST",
        "/api/users",
        Some(json!({
            "username":"freeports", "password":INITIAL_PASSWORD, "expires_at":null
        })),
        Some(&f.admin),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{user}");
    assert_eq!(user["max_rules"], 10);
    assert_eq!(user["port_start"], 1024);
    assert_eq!(user["port_end"], 65535);
    for (index, port) in [
        13579, 25007, 62011, 16103, 22107, 45017, 49019, 52021, 57023, 61027,
    ]
    .into_iter()
    .enumerate()
    {
        let mut input = rule(port);
        input["owner_id"] = user["id"].clone();
        input["protocol"] = json!("both");
        input["enabled"] = json!(index != 0);
        let (status, _, value) = call(
            &f.app,
            "POST",
            "/api/rules",
            Some(input),
            Some(&f.admin),
            true,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{port}: {value}");
    }
    let mut input = rule(63029);
    input["owner_id"] = user["id"].clone();
    input["enabled"] = json!(false);
    let (status, _, value) = call(
        &f.app,
        "POST",
        "/api/rules",
        Some(input),
        Some(&f.admin),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{value}");
    assert_eq!(value["error"]["message"], "端口额度已满");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM port_leases WHERE owner_id=?")
        .bind(user["id"].as_i64().unwrap())
        .fetch_one(&f.state.pool)
        .await
        .unwrap();
    assert_eq!(count, 10);
}

#[tokio::test]
async fn host_tcp_udp_ipv4_ipv6_conflicts_leave_no_rules_or_leases() {
    let f = Fixture::new().await;
    let tcp4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp6 = std::net::TcpListener::bind("[::1]:0").unwrap();
    let udp4 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp6 = std::net::UdpSocket::bind("[::1]:0").unwrap();
    for port in [
        tcp4.local_addr().unwrap().port(),
        tcp6.local_addr().unwrap().port(),
        udp4.local_addr().unwrap().port(),
        udp6.local_addr().unwrap().port(),
    ] {
        let (status, _, value) = call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(i64::from(port))),
            Some(&f.admin),
            true,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{port}: {value}");
        assert_eq!(value["error"]["code"], "port_unavailable");
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains(&port.to_string())
        );
    }
    for table in ["rules", "port_leases"] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&f.state.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}

#[tokio::test]
async fn shared_port_and_quota_races_have_one_winner() {
    let f = Fixture::new().await;
    let alice = f.add_user("alice", 41000).await;
    let bob = f.add_user("bob", 41000).await;
    let (a, b) = tokio::join!(
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(63211)),
            Some(&alice),
            true
        ),
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(63211)),
            Some(&bob),
            true
        )
    );
    let mut statuses = [a.0.as_u16(), b.0.as_u16()];
    statuses.sort_unstable();
    assert_eq!(statuses, [201, 409]);
    let winner = if a.0 == StatusCode::CREATED {
        &alice
    } else {
        &bob
    };
    let owner = winner.user["id"].as_i64().unwrap();
    sqlx::query("UPDATE users SET max_rules=2 WHERE id=?")
        .bind(owner)
        .execute(&f.state.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(63213)),
            Some(winner),
            true
        ),
        call(
            &f.app,
            "POST",
            "/api/rules",
            Some(rule(63217)),
            Some(winner),
            true
        )
    );
    let mut statuses = [a.0.as_u16(), b.0.as_u16()];
    statuses.sort_unstable();
    assert_eq!(statuses, [201, 409]);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rules WHERE owner_id=?")
        .bind(owner)
        .fetch_one(&f.state.pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
}
