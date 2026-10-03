use std::sync::Arc;

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{
        Error as PasswordHashError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::Semaphore;

const HASH_MEMORY_KIB: u32 = 19 * 1024;
const HASH_ITERATIONS: u32 = 2;
const HASH_PARALLELISM: u32 = 1;
const HASH_OUTPUT_BYTES: usize = 32;
const HASH_CONCURRENCY: usize = 2;
const MAX_PASSWORD_BYTES: usize = 1024;
const MAX_ENCODED_HASH_BYTES: usize = 512;

#[derive(Clone)]
pub struct Credentials {
    slots: Arc<Semaphore>,
}

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("password processing capacity is busy")]
    Busy,
    #[error("password exceeds the supported length")]
    PasswordTooLong,
    #[error("stored password hash is invalid or uses an unsupported profile")]
    InvalidHash,
    #[error("password hashing parameters are invalid")]
    InvalidParameters,
    #[error("secure random generation failed")]
    RandomGeneration,
    #[error("password hashing failed")]
    Hashing,
    #[error("password processing worker failed")]
    Worker,
}

impl Credentials {
    pub fn new() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(HASH_CONCURRENCY)),
        }
    }

    pub async fn hash_password(&self, password: String) -> Result<String, CredentialError> {
        check_password_length(&password)?;
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| CredentialError::Busy)?;

        tokio::task::spawn_blocking(move || {
            // Cancellation of the caller must not free a slot while hashing still runs.
            let _permit = permit;
            let mut salt_bytes = [0_u8; 16];
            OsRng
                .try_fill_bytes(&mut salt_bytes)
                .map_err(|_| CredentialError::RandomGeneration)?;
            let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| CredentialError::Hashing)?;
            password_hasher()?
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                .map_err(|_| CredentialError::Hashing)
        })
        .await
        .map_err(|_| CredentialError::Worker)?
    }

    pub async fn verify_password(
        &self,
        password: String,
        hash: String,
    ) -> Result<bool, CredentialError> {
        check_password_length(&password)?;
        if hash.len() > MAX_ENCODED_HASH_BYTES {
            return Err(CredentialError::InvalidHash);
        }
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| CredentialError::Busy)?;

        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let parsed = PasswordHash::new(&hash).map_err(|_| CredentialError::InvalidHash)?;

            // Validate raw costs before library parameter conversion, which can
            // overflow for malformed parallelism values in debug builds.
            // PasswordVerifier also reads its costs from this PHC string.
            if parsed.algorithm.as_str() != "argon2id"
                || parsed.version != Some(19)
                || parsed.salt.is_none()
                || parsed.hash.is_none()
                || parsed.params.iter().count() != 3
                || parsed.params.get_decimal("m") != Some(HASH_MEMORY_KIB)
                || parsed.params.get_decimal("t") != Some(HASH_ITERATIONS)
                || parsed.params.get_decimal("p") != Some(HASH_PARALLELISM)
            {
                return Err(CredentialError::InvalidHash);
            }
            let parameters = Params::try_from(&parsed).map_err(|_| CredentialError::InvalidHash)?;
            if parameters.output_len() != Some(HASH_OUTPUT_BYTES)
                || !parameters.keyid().is_empty()
                || !parameters.data().is_empty()
            {
                return Err(CredentialError::InvalidHash);
            }

            // The library compares digests in constant time. Only a genuine
            // password mismatch becomes false; malformed hashes remain errors.
            match password_hasher()?.verify_password(password.as_bytes(), &parsed) {
                Ok(()) => Ok(true),
                Err(PasswordHashError::Password) => Ok(false),
                Err(_) => Err(CredentialError::InvalidHash),
            }
        })
        .await
        .map_err(|_| CredentialError::Worker)?
    }
}

impl Default for Credentials {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a 256-bit bearer token. Persist only `token_hash(&token)`.
pub fn new_session_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn password_hasher() -> Result<Argon2<'static>, CredentialError> {
    let parameters = Params::new(
        HASH_MEMORY_KIB,
        HASH_ITERATIONS,
        HASH_PARALLELISM,
        Some(HASH_OUTPUT_BYTES),
    )
    .map_err(|_| CredentialError::InvalidParameters)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters))
}

fn check_password_length(password: &str) -> Result<(), CredentialError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(CredentialError::PasswordTooLong);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn password_verification_accepts_only_the_matching_password() {
        let credentials = Credentials::new();
        let password = "test-only password with unicode 密码";
        let hash = credentials
            .hash_password(password.to_owned())
            .await
            .expect("hash password");
        assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(
            credentials
                .verify_password(password.to_owned(), hash.clone())
                .await
                .expect("verify matching password")
        );
        assert!(
            !credentials
                .verify_password("incorrect password".to_owned(), hash)
                .await
                .expect("verify mismatching password")
        );
    }

    #[tokio::test]
    async fn malformed_and_excessive_cost_hashes_are_errors() {
        let credentials = Credentials::new();
        assert!(matches!(
            credentials
                .verify_password("password".to_owned(), "not-a-hash".to_owned())
                .await,
            Err(CredentialError::InvalidHash)
        ));

        let hash = credentials
            .hash_password("test-only password".to_owned())
            .await
            .expect("hash password");
        let excessive_cost = hash.replace("m=19456", "m=4294967295");
        assert!(matches!(
            credentials
                .verify_password("test-only password".to_owned(), excessive_cost)
                .await,
            Err(CredentialError::InvalidHash)
        ));
        let missing_cost = hash.replace("m=19456,", "");
        assert!(matches!(
            credentials
                .verify_password("test-only password".to_owned(), missing_cost)
                .await,
            Err(CredentialError::InvalidHash)
        ));
        let excessive_parallelism = hash.replace("p=1", "p=4294967295");
        assert!(matches!(
            credentials
                .verify_password("test-only password".to_owned(), excessive_parallelism)
                .await,
            Err(CredentialError::InvalidHash)
        ));
    }

    #[tokio::test]
    async fn overload_is_rejected_without_waiting_for_hash_capacity() {
        let credentials = Credentials::new();
        let clone = credentials.clone();
        let _permits = Arc::clone(&credentials.slots)
            .try_acquire_many_owned(HASH_CONCURRENCY as u32)
            .expect("reserve all hash capacity");
        assert!(matches!(
            clone.hash_password("test-only password".to_owned()).await,
            Err(CredentialError::Busy)
        ));
        assert!(matches!(
            clone
                .verify_password("test-only password".to_owned(), "not-a-hash".to_owned())
                .await,
            Err(CredentialError::Busy)
        ));
    }

    #[test]
    fn session_tokens_have_256_bits_and_are_not_reused() {
        let first = new_session_token();
        let second = new_session_token();
        assert_eq!(first.len(), 64);
        assert_eq!(hex::decode(&first).expect("hex token").len(), 32);
        assert_ne!(first, second);
        assert_ne!(token_hash(&first), first);
        assert_eq!(token_hash(&first).len(), 64);
        assert_ne!(token_hash(&first), token_hash(&second));
        assert_eq!(
            token_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
