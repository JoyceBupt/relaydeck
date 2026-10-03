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
const ORIGIN: &str = "https://relaydeck.test";

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
    async fn add_user(&self, username: &str, start: i64) -> Login {
        let (status,_,value)=call(&self.app,"POST","/api/users",Some(json!({"username":username,"password":INITIAL_PASSWORD,"port_start":start,"port_end":start+9,"max_rules":3,"expires_at":null})),Some(&self.admin),true).await;
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
    sqlx::query("INSERT INTO runtime_states VALUES(?,1,'active',NULL,?)")
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
    let input = json!({"username":"alice","password":INITIAL_PASSWORD,"port_start":41000,"port_end":41009,"max_rules":3,"expires_at":null});
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
            Some(rule(41100)),
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
    let update = json!({"enabled":false,"port_start":41000,"port_end":41009,"max_rules":3,"expires_at":null});
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
