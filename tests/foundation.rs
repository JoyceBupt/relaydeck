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

#[test]
fn backend_refuses_zero_public_port_before_creating_data() {
    let dir = tempfile::tempdir().unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_relaydeck"))
        .env("RELAYDECK_ORIGIN", "https://relaydeck.test:0")
        .env("RELAYDECK_DATABASE", dir.path().join("unexpected.db"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("valid port"));
    assert!(!dir.path().join("unexpected.db").exists());
}

#[tokio::test]
async fn configured_https_port_is_reserved_and_login_requires_the_exact_origin() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    struct Server(std::process::Child);
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn request(
        address: std::net::SocketAddr,
        method: &str,
        path: &str,
        headers: &str,
        body: &str,
    ) -> String {
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: relaydeck.test\r\nConnection: close\r\nContent-Type: application/json\r\nX-RelayDeck-Client-IP: 192.0.2.1\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("relaydeck.db");
    let key = dir.path().join("mfa.key");
    let pool = relaydeck::db::connect(&database).await.unwrap();
    relaydeck::api::initialize_admin(&pool, "tenantroot", "only-testing-port-password".into())
        .await
        .unwrap();
    sqlx::query("UPDATE users SET role='user', port_start=17440, port_end=17449")
        .execute(&pool)
        .await
        .unwrap();
    relaydeck::mfa::MfaService::create_key_file(&key).unwrap();
    relaydeck::db::close(&pool).await.unwrap();
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_relaydeck"))
            .arg("serve")
            .env("RELAYDECK_LISTEN", address.to_string())
            .env("RELAYDECK_ORIGIN", "https://relaydeck.test:17443")
            .env("RELAYDECK_TRUST_PROXY", "true")
            .env("RELAYDECK_REQUIRE_ADMIN_MFA", "true")
            .env("RELAYDECK_DATABASE", &database)
            .env("RELAYDECK_MFA_KEY", &key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut ready = false;
    for _ in 0..100 {
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "backend exited before startup"
        );
        if TcpStream::connect(address).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(ready, "backend startup timed out");
    let credentials = r#"{"username":"tenantroot","password":"only-testing-port-password"}"#;
    let wrong = request(
        address,
        "POST",
        "/api/login",
        "Origin: https://relaydeck.test\r\n",
        credentials,
    );
    assert!(wrong.starts_with("HTTP/1.1 403"), "{wrong}");
    let login = request(
        address,
        "POST",
        "/api/login",
        "Origin: https://relaydeck.test:17443\r\n",
        credentials,
    );
    assert!(login.starts_with("HTTP/1.1 200"), "{login}");
    let cookie = login
        .lines()
        .find_map(|line| line.strip_prefix("set-cookie: "))
        .unwrap();
    assert!(cookie.starts_with("__Host-relaydeck_session=") && cookie.contains("Secure"));
    let session: serde_json::Value =
        serde_json::from_str(login.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let headers = format!(
        "Origin: https://relaydeck.test:17443\r\nCookie: {}\r\nx-csrf-token: {}\r\n",
        cookie.split(';').next().unwrap(),
        session["csrf_token"].as_str().unwrap()
    );
    let ports = request(address, "GET", "/api/users/1/ports", &headers, "");
    assert!(ports.starts_with("HTTP/1.1 200"), "{ports}");
    let value: serde_json::Value =
        serde_json::from_str(ports.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(value["reserved"], serde_json::json!([17443]));
    let body = r#"{"name":"reserved","listen_port":17443,"target_host":"8.8.8.8","target_port":443,"protocol":"tcp","source_cidrs":[],"enabled":true}"#;
    let rule = request(address, "POST", "/api/rules", &headers, body);
    assert!(rule.starts_with("HTTP/1.1 400"), "{rule}");
    assert!(rule.contains("17443"), "{rule}");
}
