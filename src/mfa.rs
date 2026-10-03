use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;
use thiserror::Error;
use totp_rs::{Algorithm, Builder, Totp};
use zeroize::Zeroizing;

const ENROLLMENT_TTL: i64 = 600;
const SECRET_BYTES: usize = 20;
const NONCE_BYTES: usize = 12;
const CIPHERTEXT_BYTES: usize = SECRET_BYTES + 16;
const RECOVERY_COUNT: usize = 10;

/// Holds a key loaded from a separate, owner-only file; never serialize or log it.
#[derive(Clone)]
pub struct MfaService {
    cipher: Aes256Gcm,
}

/// This response is shown only when starting an enrollment. Never persist the
/// plaintext secret or send the URI to an external QR-code provider.
#[derive(Serialize)]
pub struct Enrollment {
    pub secret: String,
    pub otpauth_uri: String,
}

#[derive(Debug, Error)]
pub enum MfaError {
    #[error("MFA is already enabled")]
    AlreadyEnabled,
    #[error("stored MFA data is invalid")]
    InvalidSecret,
    #[error("secure random generation failed")]
    RandomGeneration,
    #[error("MFA secret encryption failed")]
    Encryption,
    #[error("MFA profile is invalid")]
    InvalidProfile,
    #[error("MFA database operation failed")]
    Database(#[from] sqlx::Error),
}

impl MfaService {
    /// Read an existing 32-byte hex key. Fails closed for symlinks, wrong owner,
    /// permissions other than 0600, invalid length, or malformed contents.
    pub fn from_key_file(path: &Path) -> anyhow::Result<Self> {
        validate_key_directory(path)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut file = options.open(path)?;
        validate_key_file(&file)?;
        let mut contents = Zeroizing::new(Vec::with_capacity(65));
        Read::by_ref(&mut file)
            .take(66)
            .read_to_end(&mut contents)?;
        anyhow::ensure!(
            contents.len() == 64 || (contents.len() == 65 && contents[64] == b'\n'),
            "MFA key must contain exactly 32 bytes encoded as hex"
        );
        let mut key = Zeroizing::new([0_u8; 32]);
        hex::decode_to_slice(&contents[..64], &mut key[..])
            .map_err(|_| anyhow::anyhow!("MFA key must contain exactly 32 bytes encoded as hex"))?;
        Ok(Self {
            cipher: Aes256Gcm::new((&*key).into()),
        })
    }

    /// An explicit installation operation. It never overwrites a key and must
    /// not be called to replace a missing key for a database with enrolled users.
    pub fn create_key_file(path: &Path) -> anyhow::Result<()> {
        validate_key_directory(path)?;
        let mut key = Zeroizing::new([0_u8; 32]);
        OsRng
            .try_fill_bytes(&mut key[..])
            .map_err(|_| anyhow::anyhow!("secure random generation failed"))?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(path)?;
        validate_key_file(&file)?;
        let encoded = Zeroizing::new(hex::encode(&key[..]));
        file.write_all(encoded.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    /// All database methods must run in the caller's BEGIN IMMEDIATE transaction.
    /// The caller must first revalidate the session and password, and must commit
    /// only after auditing and revoking older sessions on successful enrollment.
    pub async fn begin_enrollment(
        &self,
        conn: &mut SqliteConnection,
        user_id: i64,
        username: &str,
        timestamp: i64,
    ) -> Result<Enrollment, MfaError> {
        let active: Option<String> = sqlx::query_scalar("SELECT mfa_secret FROM users WHERE id=?")
            .bind(user_id)
            .fetch_one(&mut *conn)
            .await?;
        if active.is_some() {
            return Err(MfaError::AlreadyEnabled);
        }
        if timestamp < 0 {
            return Err(MfaError::InvalidProfile);
        }
        let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
        OsRng
            .try_fill_bytes(&mut secret[..])
            .map_err(|_| MfaError::RandomGeneration)?;
        let totp = totp(&secret[..], username)?;
        let enrollment = Enrollment {
            secret: totp.secret().to_base32(),
            otpauth_uri: totp.to_url().map_err(|_| MfaError::InvalidProfile)?,
        };
        let encrypted = self.encrypt_secret(user_id, &secret[..])?;
        sqlx::query("UPDATE users SET mfa_pending_secret=?,mfa_pending_at=? WHERE id=? AND mfa_secret IS NULL")
            .bind(encrypted)
            .bind(timestamp)
            .bind(user_id)
            .execute(&mut *conn)
            .await?;
        Ok(enrollment)
    }

    /// Return recovery codes only on successful first confirmation. The same
    /// TOTP step is consumed here, so it cannot subsequently be used for login.
    pub async fn confirm_enrollment(
        &self,
        conn: &mut SqliteConnection,
        user_id: i64,
        code: &str,
        timestamp: i64,
    ) -> Result<Option<Vec<String>>, MfaError> {
        let (active, pending, created): (Option<String>, Option<String>, Option<i64>) =
            sqlx::query_as(
                "SELECT mfa_secret,mfa_pending_secret,mfa_pending_at FROM users WHERE id=?",
            )
            .bind(user_id)
            .fetch_one(&mut *conn)
            .await?;
        if active.is_some() {
            return Err(MfaError::AlreadyEnabled);
        }
        let (Some(pending), Some(created)) = (pending, created) else {
            return Ok(None);
        };
        if timestamp < created || timestamp.saturating_sub(created) >= ENROLLMENT_TTL {
            return Ok(None);
        }
        let secret = self.decrypt_secret(user_id, &pending)?;
        let Some(step) = matched_step(&secret, code, timestamp)? else {
            return Ok(None);
        };
        let recovery_codes = new_recovery_codes()?;
        let changed = sqlx::query("UPDATE users SET mfa_secret=mfa_pending_secret,mfa_pending_secret=NULL,mfa_pending_at=NULL,mfa_last_step=? WHERE id=? AND mfa_secret IS NULL AND mfa_pending_secret=? AND mfa_pending_at=?")
            .bind(step)
            .bind(user_id)
            .bind(pending)
            .bind(created)
            .execute(&mut *conn)
            .await?
            .rows_affected();
        if changed != 1 {
            return Ok(None);
        }
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id=?")
            .bind(user_id)
            .execute(&mut *conn)
            .await?;
        for code in &recovery_codes {
            sqlx::query("INSERT INTO mfa_recovery_codes(user_id,code_hash) VALUES(?,?)")
                .bind(user_id)
                .bind(recovery_hash(user_id, code).ok_or(MfaError::InvalidProfile)?)
                .execute(&mut *conn)
                .await?;
        }
        Ok(Some(recovery_codes))
    }

    /// Consume an active TOTP step or one recovery code in the caller's login
    /// transaction, before creating a session. Returns false when not enrolled.
    pub async fn verify(
        &self,
        conn: &mut SqliteConnection,
        user_id: i64,
        code: &str,
        timestamp: i64,
    ) -> Result<bool, MfaError> {
        let (encrypted, last_step): (Option<String>, Option<i64>) =
            sqlx::query_as("SELECT mfa_secret,mfa_last_step FROM users WHERE id=?")
                .bind(user_id)
                .fetch_one(&mut *conn)
                .await?;
        let Some(encrypted) = encrypted else {
            return Ok(false);
        };
        if timestamp < 0 {
            return Ok(false);
        }
        if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
            let secret = self.decrypt_secret(user_id, &encrypted)?;
            let Some(step) = matched_step(&secret, code, timestamp)? else {
                return Ok(false);
            };
            if last_step.is_some_and(|last| step <= last) {
                return Ok(false);
            }
            let changed = sqlx::query("UPDATE users SET mfa_last_step=? WHERE id=? AND mfa_secret=? AND (mfa_last_step IS NULL OR mfa_last_step<?)")
                .bind(step)
                .bind(user_id)
                .bind(encrypted)
                .bind(step)
                .execute(&mut *conn)
                .await?
                .rows_affected();
            return Ok(changed == 1);
        }
        let Some(hash) = recovery_hash(user_id, code) else {
            return Ok(false);
        };
        let changed = sqlx::query("UPDATE mfa_recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL AND EXISTS(SELECT 1 FROM users WHERE id=? AND mfa_secret=?)")
            .bind(timestamp)
            .bind(user_id)
            .bind(hash)
            .bind(user_id)
            .bind(encrypted)
            .execute(&mut *conn)
            .await?
            .rows_affected();
        Ok(changed == 1)
    }

    fn encrypt_secret(&self, user_id: i64, secret: &[u8]) -> Result<String, MfaError> {
        if secret.len() != SECRET_BYTES {
            return Err(MfaError::InvalidSecret);
        }
        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| MfaError::RandomGeneration)?;
        let aad = associated_data(user_id);
        let encrypted = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| MfaError::Encryption)?;
        let mut envelope = Vec::with_capacity(NONCE_BYTES + CIPHERTEXT_BYTES);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        Ok(format!("v1:{}", hex::encode(envelope)))
    }

    fn decrypt_secret(&self, user_id: i64, envelope: &str) -> Result<Zeroizing<Vec<u8>>, MfaError> {
        let payload = envelope
            .strip_prefix("v1:")
            .filter(|payload| payload.len() == 2 * (NONCE_BYTES + CIPHERTEXT_BYTES))
            .ok_or(MfaError::InvalidSecret)?;
        let payload = hex::decode(payload).map_err(|_| MfaError::InvalidSecret)?;
        let aad = associated_data(user_id);
        let secret = Zeroizing::new(
            self.cipher
                .decrypt(
                    Nonce::from_slice(&payload[..NONCE_BYTES]),
                    Payload {
                        msg: &payload[NONCE_BYTES..],
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| MfaError::InvalidSecret)?,
        );
        if secret.len() != SECRET_BYTES {
            return Err(MfaError::InvalidSecret);
        }
        Ok(secret)
    }
}

fn validate_key_directory(path: &Path) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = std::fs::symlink_metadata(parent)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "MFA key directory must be a regular directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "MFA key directory must be owned by the current user"
        );
        anyhow::ensure!(
            metadata.permissions().mode() & 0o022 == 0,
            "MFA key directory must not be writable by other users"
        );
    }
    Ok(())
}

fn validate_key_file(file: &File) -> anyhow::Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file(), "MFA key must be a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "MFA key must be owned by the current user"
        );
        anyhow::ensure!(
            metadata.permissions().mode() & 0o7777 == 0o600,
            "MFA key permissions must be 0600"
        );
        anyhow::ensure!(metadata.nlink() == 1, "MFA key must not have hard links");
    }
    Ok(())
}

fn associated_data(user_id: i64) -> String {
    format!("relaydeck:mfa:v1:{user_id}")
}

fn totp(secret: &[u8], username: &str) -> Result<Totp, MfaError> {
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .with_skew(1)
        .with_secret(secret)
        .with_account_name(username)
        .with_issuer(Some("RelayDeck"))
        .build()
        .map_err(|_| MfaError::InvalidProfile)
}

fn matched_step(secret: &[u8], code: &str, timestamp: i64) -> Result<Option<i64>, MfaError> {
    if timestamp < 0 || code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    Ok(totp(secret, "account")?
        .check(code, timestamp as u64)
        .and_then(|step| i64::try_from(step).ok()))
}

fn new_recovery_codes() -> Result<Vec<String>, MfaError> {
    (0..RECOVERY_COUNT)
        .map(|_| {
            let mut bytes = [0_u8; 16];
            OsRng
                .try_fill_bytes(&mut bytes)
                .map_err(|_| MfaError::RandomGeneration)?;
            let encoded = hex::encode(bytes);
            Ok(format!(
                "{}-{}-{}-{}",
                &encoded[..8],
                &encoded[8..16],
                &encoded[16..24],
                &encoded[24..]
            ))
        })
        .collect()
}

fn recovery_hash(user_id: i64, code: &str) -> Option<String> {
    if code.len() != 32 && code.len() != 35 {
        return None;
    }
    let mut normalized = String::with_capacity(32);
    for (index, byte) in code.bytes().enumerate() {
        if code.len() == 35 && matches!(index, 8 | 17 | 26) {
            if byte != b'-' {
                return None;
            }
        } else if byte.is_ascii_hexdigit() {
            normalized.push(byte.to_ascii_lowercase() as char);
        } else {
            return None;
        }
    }
    (normalized.len() == 32).then(|| {
        let mut digest = Sha256::new();
        digest.update(format!("relaydeck:recovery:v1:{user_id}:"));
        digest.update(normalized.as_bytes());
        hex::encode(digest.finalize())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
    use tempfile::TempDir;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    fn make_service() -> (TempDir, MfaService) {
        let directory = TempDir::new().expect("temporary key directory");
        let path = directory.path().join("mfa.key");
        MfaService::create_key_file(&path).expect("create test key");
        let service = MfaService::from_key_file(&path).expect("load test key");
        (directory, service)
    }

    async fn database() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("test database");
        sqlx::migrate!().run(&pool).await.expect("migrations");
        for username in ["alice", "bob"] {
            sqlx::query("INSERT INTO users(username,password_hash,role,must_change_password,port_start,port_end,created_at) VALUES(?,'test-only','user',0,40000,40049,0)")
                .bind(username).execute(&pool).await.expect("test user");
        }
        pool
    }

    #[test]
    fn standard_totp_vectors_and_window_boundaries() {
        for (timestamp, code) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(
                matched_step(RFC_SECRET, code, timestamp).expect("standard code"),
                Some(timestamp / 30)
            );
        }
        let code = totp(RFC_SECRET, "alice")
            .expect("profile")
            .generate(3000)
            .to_string();
        for timestamp in [2970, 3000, 3030] {
            assert_eq!(
                matched_step(RFC_SECRET, &code, timestamp).expect("window"),
                Some(100)
            );
        }
        for timestamp in [-1, 2940, 3060] {
            assert_eq!(
                matched_step(RFC_SECRET, &code, timestamp).expect("outside window"),
                None
            );
        }
        assert_eq!(
            matched_step(RFC_SECRET, "１２３４５６", 3000).expect("invalid token"),
            None
        );
    }

    #[tokio::test]
    async fn enrollment_requires_fresh_code_and_consumes_confirmation_step() {
        let (_directory, service) = make_service();
        let pool = database().await;
        let mut tx = pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .expect("transaction");
        let enrollment = service
            .begin_enrollment(&mut tx, 1, "alice", 3000)
            .await
            .expect("enrollment");
        let uri = url::Url::parse(&enrollment.otpauth_uri).expect("URI");
        assert_eq!(uri.scheme(), "otpauth");
        assert_eq!(uri.host_str(), Some("totp"));
        assert_eq!(
            uri.query_pairs()
                .find(|(name, _)| name == "secret")
                .expect("secret query")
                .1,
            enrollment.secret
        );
        assert!(
            service
                .confirm_enrollment(&mut tx, 1, "invalid", 3000)
                .await
                .expect("invalid confirmation")
                .is_none()
        );
        let secret = totp_rs::Secret::try_from_base32(&enrollment.secret).expect("base32");
        let code = totp(secret.as_bytes(), "alice")
            .expect("profile")
            .generate(3000)
            .to_string();
        let recovery = service
            .confirm_enrollment(&mut tx, 1, &code, 3000)
            .await
            .expect("confirm")
            .expect("success");
        assert_eq!(recovery.len(), RECOVERY_COUNT);
        assert!(
            !service
                .verify(&mut tx, 1, &code, 3000)
                .await
                .expect("confirmation reuse")
        );
        let next = totp(secret.as_bytes(), "alice")
            .expect("profile")
            .generate(3030)
            .to_string();
        assert!(
            service
                .verify(&mut tx, 1, &next, 3030)
                .await
                .expect("next step")
        );
        assert!(
            !service
                .verify(&mut tx, 1, &next, 3030)
                .await
                .expect("replayed step")
        );
        assert!(
            !service
                .verify(&mut tx, 1, &code, 3030)
                .await
                .expect("older step")
        );
        assert!(matches!(
            service.begin_enrollment(&mut tx, 1, "alice", 3060).await,
            Err(MfaError::AlreadyEnabled)
        ));
        tx.commit().await.expect("commit");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id=1 AND length(code_hash)=64 AND used_at IS NULL").fetch_one(&pool).await.expect("hashes");
        assert_eq!(count, RECOVERY_COUNT as i64);
        let active: String = sqlx::query_scalar("SELECT mfa_secret FROM users WHERE id=1")
            .fetch_one(&pool)
            .await
            .expect("encrypted secret");
        assert!(!active.contains(&enrollment.secret));
        assert!(service.decrypt_secret(2, &active).is_err());
    }

    #[tokio::test]
    async fn expired_and_replaced_pending_enrollments_cannot_be_confirmed() {
        let (_directory, service) = make_service();
        let pool = database().await;
        let mut tx = pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .expect("transaction");
        let first = service
            .begin_enrollment(&mut tx, 1, "alice", 3000)
            .await
            .expect("enrollment");
        let secret = totp_rs::Secret::try_from_base32(&first.secret).expect("base32");
        let profile = totp(secret.as_bytes(), "alice").expect("profile");
        let code = profile.generate(3600).to_string();
        assert!(
            service
                .confirm_enrollment(&mut tx, 1, &code, 3600)
                .await
                .expect("expired confirmation")
                .is_none()
        );
        let replacement = service
            .begin_enrollment(&mut tx, 1, "alice", 3600)
            .await
            .expect("replacement");
        assert_ne!(first.secret, replacement.secret);
        assert!(
            service
                .confirm_enrollment(&mut tx, 1, &code, 3600)
                .await
                .expect("old enrollment")
                .is_none()
        );
        let current = totp_rs::Secret::try_from_base32(&replacement.secret).expect("base32");
        let code = totp(current.as_bytes(), "alice")
            .expect("profile")
            .generate(3600)
            .to_string();
        assert!(
            service
                .confirm_enrollment(&mut tx, 1, &code, 3599)
                .await
                .expect("clock rollback")
                .is_none()
        );
        assert!(
            service
                .confirm_enrollment(&mut tx, 1, &code, 3600)
                .await
                .expect("current enrollment")
                .is_some()
        );
        tx.commit().await.expect("commit");
    }

    #[tokio::test]
    async fn recovery_codes_are_one_use_and_scoped_to_the_enrolled_user() {
        let (_directory, service) = make_service();
        let pool = database().await;
        let mut tx = pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .expect("transaction");
        let enrollment = service
            .begin_enrollment(&mut tx, 1, "alice", 3000)
            .await
            .expect("enrollment");
        let secret = totp_rs::Secret::try_from_base32(&enrollment.secret).expect("base32");
        let code = totp(secret.as_bytes(), "alice")
            .expect("profile")
            .generate(3000)
            .to_string();
        let recovery = service
            .confirm_enrollment(&mut tx, 1, &code, 3000)
            .await
            .expect("confirmation")
            .expect("recovery codes");
        assert!(
            !service
                .verify(&mut tx, 2, &recovery[0], 3000)
                .await
                .expect("other account")
        );
        assert!(
            service
                .verify(&mut tx, 1, &recovery[0].to_ascii_uppercase(), 3000)
                .await
                .expect("recovery")
        );
        assert!(
            !service
                .verify(&mut tx, 1, &recovery[0], 3000)
                .await
                .expect("recovery reuse")
        );
        tx.commit().await.expect("commit");
        let mut tx = pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .expect("next transaction");
        assert!(
            !service
                .verify(&mut tx, 1, &recovery[0], 6000)
                .await
                .expect("persistent reuse")
        );
        assert!(
            service
                .verify(&mut tx, 1, &recovery[1].replace('-', ""), 6000)
                .await
                .expect("next recovery")
        );
        tx.commit().await.expect("commit");
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id=1 AND used_at IS NULL",
        )
        .fetch_one(&pool)
        .await
        .expect("remaining");
        assert_eq!(remaining, 8);
    }

    #[tokio::test]
    async fn concurrent_logins_cannot_consume_the_same_totp_step() {
        let (directory, service) = make_service();
        let pool = crate::db::connect(&directory.path().join("replay.db"))
            .await
            .expect("file database");
        sqlx::query("INSERT INTO users(username,password_hash,role,must_change_password,port_start,port_end,mfa_secret,created_at) VALUES('alice','test-only','user',0,40000,40049,?,0)")
            .bind(service.encrypt_secret(1, RFC_SECRET).expect("encrypted secret"))
            .execute(&pool)
            .await
            .expect("enrolled test user");
        let verify = || async {
            let mut tx = pool
                .begin_with("BEGIN IMMEDIATE")
                .await
                .expect("login transaction");
            let result = service
                .verify(&mut tx, 1, "005924", 1_234_567_890)
                .await
                .expect("login code");
            tx.commit().await.expect("login commit");
            result
        };
        let (first, second) = tokio::join!(verify(), verify());
        assert_ne!(first, second);
    }

    #[test]
    fn secret_encryption_authenticates_user_ciphertext_and_key() {
        let (_directory, service) = make_service();
        let (_other_directory, other) = make_service();
        let first = service.encrypt_secret(1, RFC_SECRET).expect("encrypt");
        let second = service
            .encrypt_secret(1, RFC_SECRET)
            .expect("encrypt again");
        assert_ne!(first, second);
        assert_eq!(
            service
                .decrypt_secret(1, &first)
                .expect("decrypt")
                .as_slice(),
            RFC_SECRET
        );
        assert!(service.decrypt_secret(2, &first).is_err());
        assert!(other.decrypt_secret(1, &first).is_err());
        let mut tampered = first.into_bytes();
        tampered[30] = if tampered[30] == b'0' { b'1' } else { b'0' };
        assert!(
            service
                .decrypt_secret(1, std::str::from_utf8(&tampered).expect("hex"))
                .is_err()
        );
        for malformed in ["v1:", "v2:0000", "invalid"] {
            assert!(service.decrypt_secret(1, malformed).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn key_loading_rejects_unsafe_permissions_links_and_malformed_keys() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (directory, _) = make_service();
        let key = directory.path().join("mfa.key");
        assert!(MfaService::create_key_file(&key).is_err());
        let link = directory.path().join("key-link");
        symlink(&key, &link).expect("symlink");
        assert!(MfaService::from_key_file(&link).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640))
            .expect("unsafe permissions");
        assert!(MfaService::from_key_file(&key).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))
            .expect("safe permissions");
        std::fs::write(&key, "invalid").expect("malformed key");
        assert!(MfaService::from_key_file(&key).is_err());
        std::fs::write(&key, hex::encode([0x42; 32])).expect("valid key");
        std::fs::hard_link(&key, directory.path().join("hard-link")).expect("hard link");
        assert!(MfaService::from_key_file(&key).is_err());
    }
}
