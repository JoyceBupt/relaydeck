use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn health_reports_the_runtime_boundary() {
    let response = relaydeck::health_router()
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["name"], "RelayDeck");
    assert_eq!(body["executor"], "unconfigured");
}

#[tokio::test]
async fn migrations_are_repeatable_and_constraints_hold() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data").join("relaydeck.db");
    let pool = relaydeck::db::connect(&path).await.unwrap();
    let insert = "INSERT INTO users (username,password_hash,role,port_start,port_end,max_rules,created_at) VALUES ('alice','unused','user',40000,40009,5,0)";
    sqlx::query(insert).execute(&pool).await.unwrap();
    assert!(sqlx::query(insert).execute(&pool).await.is_err());
    let invalid = "INSERT INTO users (username,password_hash,role,port_start,port_end,max_rules,created_at) VALUES ('bob','unused','superuser',40000,40009,5,0)";
    assert!(sqlx::query(invalid).execute(&pool).await.is_err());
    pool.close().await;
    let reopened = relaydeck::db::connect(&path).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&reopened)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[cfg(unix)]
#[tokio::test]
async fn database_refuses_symlinks_and_shared_writable_directories() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside");
    std::fs::write(&outside, "preserve").unwrap();
    let link = dir.path().join("link.db");
    symlink(&outside, &link).unwrap();
    assert!(relaydeck::db::connect(&link).await.is_err());
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "preserve");
    let shared = dir.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(relaydeck::db::connect(&shared.join("db")).await.is_err());
    assert!(!shared.join("db").exists());
    let existing = dir.path().join("existing");
    std::fs::create_dir(&existing).unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = existing.join("db");
    let pool = relaydeck::db::connect(&path).await.unwrap();
    assert_eq!(
        std::fs::metadata(&existing).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    pool.close().await;
}

#[test]
fn backend_refuses_public_http_even_with_an_https_origin() {
    let dir = tempfile::tempdir().unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_relaydeck"))
        .env("RELAYDECK_LISTEN", "0.0.0.0:7410")
        .env("RELAYDECK_ORIGIN", "https://relaydeck.test")
        .env("RELAYDECK_DATABASE", dir.path().join("unexpected.db"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("loopback"));
    assert!(!dir.path().join("unexpected.db").exists());
}
