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

#[tokio::test]
async fn live_backup_contains_wal_changes_and_mfa_key_without_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relaydeck.db");
    let key = dir.path().join("mfa.key");
    let pool = relaydeck::db::connect(&path).await.unwrap();
    relaydeck::mfa::MfaService::create_key_file(&key).unwrap();
    relaydeck::api::initialize_admin(&pool, "adminroot", "test-backup-password".into())
        .await
        .unwrap();
    sqlx::query("PRAGMA wal_autocheckpoint=0")
        .execute(&pool)
        .await
        .unwrap();
    let backup = dir.path().join("backup");
    relaydeck::db::backup(&pool, &key, &backup).await.unwrap();
    assert_eq!(
        std::fs::read(&key).unwrap(),
        std::fs::read(backup.join("mfa.key")).unwrap()
    );
    assert!(!backup.join("relaydeck.db-wal").exists());
    let restored = relaydeck::db::connect(&backup.join("relaydeck.db"))
        .await
        .unwrap();
    let name: String = sqlx::query_scalar("SELECT username FROM users")
        .fetch_one(&restored)
        .await
        .unwrap();
    assert_eq!(name, "adminroot");
    assert!(relaydeck::db::backup(&pool, &key, &backup).await.is_err());
    relaydeck::db::close(&restored).await.unwrap();
    relaydeck::db::close(&pool).await.unwrap();
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
