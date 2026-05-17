use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{PasswordHash, SaltString, rand_core::OsRng as ArgonOsRng},
};
use chrono::{DateTime, Duration, Utc};
use identity::{InstanceRole, User, UserId, UserLifecycle};
use rand::{RngCore, rngs::OsRng};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

pub mod recovery_code;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("password hashing failed")]
    Hash(argon2::password_hash::Error),

    #[error("password hash is malformed")]
    MalformedHash(argon2::password_hash::Error),

    #[error("database error")]
    Database(#[from] sqlx::Error),
}

pub type Result<T> = std::result::Result<T, AuthError>;

/// Hash a password (or password-derived key) using Argon2id with a fresh
/// random salt. Returns the standardized PHC string that embeds the
/// algorithm name, parameters, salt, and digest - store this directly in
/// `auth.credentials.password_hash`.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut ArgonOsRng);
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

/// Length of a session token in bytes (256 bits of entropy).
const TOKEN_BYTES: usize = 32;

/// Generate a new opaque session token: 32 random bytes from the OS CSPRNG,
/// hex-encoded to a 64-character ASCII string. The caller hands the raw
/// string to the client; only `hash_token(...)` ever goes into the DB.
pub fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

/// SHA-256 of a token's raw bytes - what's stored in `auth.sessions.token_hash`.
/// SHA-256 is fine here (not Argon2) because the token already has 256 bits
/// of entropy and there's nothing to brute-force.
pub fn hash_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Why a `verify_credentials` call returned no user. Surfaces enough
/// detail for the caller to emit the right audit event (`signin_failed_unknown_email`
/// vs `signin_failed_password`) - but should never be reflected back to
/// the client, who must only see "auth failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialOutcome {
    UnknownEmail,
    WrongPassword,
}

/// Look up a user by email (case-insensitive) and verify their password.
/// On success, returns the full `User` row from `identity.users`. On
/// failure, returns a `CredentialOutcome` indicating *which* failure
/// occurred so the audit log can record it.
///
/// Returns `Err(AuthError::Database)` on real DB failure.
///
/// Note: not currently constant-time wrt the "user doesn't exist" path;
/// an attacker can probe email existence via response timing. Mitigation
/// (run Argon2 against a dummy hash on no-user) lands when timing-attack
/// hardening becomes relevant.
/// Internal join row: user columns + password verifier.
#[derive(sqlx::FromRow)]
struct UserWithCredentials {
    id: UserId,
    email: String,
    display_name: String,
    lifecycle: UserLifecycle,
    instance_role: InstanceRole,
    locale: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    password_hash: String,
}

impl UserWithCredentials {
    fn into_user(self) -> User {
        User {
            id: self.id,
            email: self.email,
            display_name: self.display_name,
            lifecycle: self.lifecycle,
            instance_role: self.instance_role,
            locale: self.locale,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

pub async fn verify_credentials(
    pool: &PgPool,
    email: &str,
    password: &str,
) -> Result<std::result::Result<User, CredentialOutcome>> {
    let row: Option<UserWithCredentials> = sqlx::query_as(
        "SELECT u.id, u.email, u.display_name, u.lifecycle, u.instance_role, u.locale,
                u.created_at, u.updated_at,
                c.password_hash
         FROM identity.users u
         JOIN auth.credentials c ON c.user_id = u.id
         WHERE u.email_lower = lower($1)
           AND u.lifecycle = 'active'",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;

    match row {
        None => Ok(Err(CredentialOutcome::UnknownEmail)),
        Some(row) => {
            let password_ok = verify_password(password, &row.password_hash)?;
            if password_ok {
                Ok(Ok(row.into_user()))
            } else {
                Ok(Err(CredentialOutcome::WrongPassword))
            }
        }
    }
}

/// Update a user's password hash within the caller's transaction. Bumps
/// `updated_at`. The caller is responsible for verifying the *current*
/// password first; this function trusts the new hash.
pub async fn update_password_hash(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
    new_phc: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE auth.credentials
         SET password_hash = $2, updated_at = now()
         WHERE user_id = $1",
    )
    .bind(user_id)
    .bind(new_phc)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Delete a user's stored password hash. Called by the soft-delete and
/// purge lifecycle handlers — once a user account is gone, their password
/// material has no remaining purpose and must not survive the
/// transition. Idempotent (zero rows affected = already gone).
pub async fn delete_credentials(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
) -> Result<()> {
    sqlx::query("DELETE FROM auth.credentials WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Session lifetime for this checkpoint. The design spec eventually wants
/// a 15-minute access token + 90-day sliding refresh token; we use a flat
/// 24-hour session for now and refactor when refresh tokens land.
pub const DEFAULT_SESSION_TTL: Duration = Duration::hours(24);

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct SessionRepository {
    pool: PgPool,
}

impl SessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new session within the caller's transaction.
    ///
    /// Returns `(session_row, raw_token)`. The raw token is what to hand
    /// to the client; the DB only ever sees its SHA-256.
    pub async fn create(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: UserId,
        ttl: Duration,
    ) -> Result<(Session, String)> {
        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires_at = Utc::now() + ttl;

        let session: Session = sqlx::query_as(
            "INSERT INTO auth.sessions (user_id, token_hash, expires_at)
             VALUES ($1, $2, $3)
             RETURNING id, user_id, created_at, expires_at, revoked_at",
        )
        .bind(user_id.0)
        .bind(&token_hash[..])
        .bind(expires_at)
        .fetch_one(&mut **tx)
        .await?;

        Ok((session, token))
    }

    /// Look up an active session by raw token. Returns `Ok(None)` if no
    /// matching session exists, the session is revoked, expired, or its
    /// user isn't active.
    pub async fn find_active(&self, token: &str) -> Result<Option<Session>> {
        let token_hash = hash_token(token);
        let session: Option<Session> = sqlx::query_as(
            "SELECT s.id, s.user_id, s.created_at, s.expires_at, s.revoked_at
             FROM auth.sessions s
             JOIN identity.users u ON u.id = s.user_id
             WHERE s.token_hash = $1
               AND s.revoked_at IS NULL
               AND s.expires_at > now()
               AND u.lifecycle = 'active'",
        )
        .bind(&token_hash[..])
        .fetch_optional(&self.pool)
        .await?;
        Ok(session)
    }

    /// Mark a session revoked within the caller's transaction. Idempotent -
    /// already-revoked sessions stay revoked.
    pub async fn revoke(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        session_id: Uuid,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE auth.sessions
             SET revoked_at = COALESCE(revoked_at, now())
             WHERE id = $1",
        )
        .bind(session_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Revoke every active session for `user_id` except the given one.
    /// Returns the number of rows revoked (sessions that were already
    /// revoked or expired are not counted). Used by the password-change
    /// flow to invalidate stolen tokens elsewhere.
    pub async fn revoke_all_for_user_except(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: UserId,
        keep_session_id: Uuid,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE auth.sessions
             SET revoked_at = now()
             WHERE user_id = $1
               AND id <> $2
               AND revoked_at IS NULL
               AND expires_at > now()",
        )
        .bind(user_id)
        .bind(keep_session_id)
        .execute(&mut **tx)
        .await?;
        Ok(result.rows_affected())
    }

    /// Revoke every active session for `user_id`. Returns the number of
    /// rows revoked. Used by the admin lifecycle handlers (deactivate /
    /// delete / purge) — there is no "current" session to preserve from
    /// the target's perspective; the actor is the admin.
    pub async fn revoke_all_for_user(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: UserId,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE auth.sessions
             SET revoked_at = now()
             WHERE user_id = $1
               AND revoked_at IS NULL
               AND expires_at > now()",
        )
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
        Ok(result.rows_affected())
    }

    /// Count active (non-revoked, non-expired) sessions. Used by /health.
    pub async fn count_active(&self) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM auth.sessions
             WHERE revoked_at IS NULL AND expires_at > now()",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    /// List a user's sessions (active and historical), newest first.
    /// Includes revoked + expired so `/account/sessions` can show "this
    /// session was revoked" entries; the caller filters as needed.
    pub async fn list_for_user(&self, user_id: UserId) -> Result<Vec<Session>> {
        let sessions: Vec<Session> = sqlx::query_as(
            "SELECT id, user_id, created_at, expires_at, revoked_at
             FROM auth.sessions
             WHERE user_id = $1
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(sessions)
    }

    /// List every active session across all users, newest first.
    /// Intended for `/admin/sessions`.
    pub async fn list_all_active(&self) -> Result<Vec<Session>> {
        let sessions: Vec<Session> = sqlx::query_as(
            "SELECT id, user_id, created_at, expires_at, revoked_at
             FROM auth.sessions
             WHERE revoked_at IS NULL AND expires_at > now()
             ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(sessions)
    }

    /// Look up a single session row by id (no token-hash check). Returns
    /// the session regardless of revoked/expired state so callers can
    /// produce specific error messages.
    pub async fn find_by_id(&self, session_id: Uuid) -> Result<Option<Session>> {
        let session: Option<Session> = sqlx::query_as(
            "SELECT id, user_id, created_at, expires_at, revoked_at
             FROM auth.sessions
             WHERE id = $1",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(session)
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

    #[test]
    fn generate_token_is_64_hex_chars() {
        let t = generate_token();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()), "got: {t}");
    }

    #[test]
    fn two_generated_tokens_differ() {
        // 256-bit entropy; collision is computationally impossible.
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
    }

    #[test]
    fn hash_token_is_deterministic_and_distinct_per_input() {
        let t = generate_token();
        let h1 = hash_token(&t);
        let h2 = hash_token(&t);
        assert_eq!(h1, h2);

        let other = generate_token();
        let h3 = hash_token(&other);
        assert_ne!(h1, h3);
    }

    #[test]
    fn hex_encode_roundtrips_known_bytes() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]), "0123456789abcdef");
    }
}
