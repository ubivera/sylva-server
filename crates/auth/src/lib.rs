use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{PasswordHash, SaltString, rand_core::OsRng},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("password hashing failed")]
    Hash(argon2::password_hash::Error),

    #[error("password hash is malformed")]
    MalformedHash(argon2::password_hash::Error),
}

pub type Result<T> = std::result::Result<T, AuthError>;

/// Hash a password (or password-derived key) using Argon2id with a fresh
/// random salt. Returns the standardized PHC string that embeds the
/// algorithm name, parameters, salt, and digest — store this directly in
/// `auth.credentials.password_hash`.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let phc = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(AuthError::Hash)?
        .to_string();
    Ok(phc)
}

/// Verify a password against a stored PHC string. Returns `Ok(true)` on
/// match, `Ok(false)` on mismatch, and `Err(MalformedHash)` if the stored
/// string cannot be parsed.
pub fn verify_password(password: &str, phc: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc).map_err(AuthError::MalformedHash)?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(err) => Err(AuthError::MalformedHash(err)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn correct_password_verifies() {
        let phc = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &phc).unwrap());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let phc = hash_password("hunter2").unwrap();
        assert!(!verify_password("hunter3", &phc).unwrap());
    }

    #[test]
    fn empty_password_round_trips() {
        let phc = hash_password("").unwrap();
        assert!(verify_password("", &phc).unwrap());
        assert!(!verify_password(" ", &phc).unwrap());
    }

    #[test]
    fn long_password_round_trips() {
        let pw = "a".repeat(512);
        let phc = hash_password(&pw).unwrap();
        assert!(verify_password(&pw, &phc).unwrap());
    }

    #[test]
    fn two_hashes_of_same_password_differ() {
        let a = hash_password("same").unwrap();
        let b = hash_password("same").unwrap();
        assert_ne!(a, b);
        assert!(verify_password("same", &a).unwrap());
        assert!(verify_password("same", &b).unwrap());
    }

    #[test]
    fn phc_string_starts_with_argon2id_marker() {
        let phc = hash_password("anything").unwrap();
        assert!(phc.starts_with("$argon2id$"), "got: {phc}");
    }

    #[test]
    fn malformed_phc_is_rejected_with_error() {
        let result = verify_password("anything", "not a phc string");
        assert!(matches!(result, Err(AuthError::MalformedHash(_))));
    }
}
