//! Per-user TOTP enrollment storage — **many authenticators per user**,
//! each with a user-chosen label. Secrets are *encrypted* at rest (via
//! [`crate::secretbox`]) rather than hashed, because the server must
//! recover the plaintext to compute the expected code at sign-in.
//!
//! A row exists from the moment enrollment starts; `verified_at` stays
//! NULL until the user confirms a code. Only verified rows count as
//! active factors, and 2FA is "on" for a user while at least one
//! verified row exists.

use chrono::{DateTime, Utc};
use identity::UserId;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::Result;
use crate::secretbox;

/// Upper bound on verified authenticators per user. Generous — a real
/// user is unlikely to approach it; it just stops unbounded growth.
pub const MAX_AUTHENTICATORS: i64 = 50;

/// A verified authenticator as shown in the Security tab. The secret
/// never appears here.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct TotpCredential {
    pub id: Uuid,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Begin enrollment of a new authenticator. Clears any half-finished
/// (unverified) rows for the user first, then inserts a fresh unverified
/// row and returns its id. The label is a placeholder until [`confirm`].
pub async fn start_enrollment(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &[u8; 32],
    user_id: UserId,
    raw_secret: &[u8],
) -> Result<Uuid> {
    sqlx::query("DELETE FROM auth.totp_credentials WHERE user_id = $1 AND verified_at IS NULL")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;

    let enc = secretbox::seal(key, raw_secret)?;
    let (id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO auth.totp_credentials (user_id, label, secret_enc)
         VALUES ($1, 'Authenticator', $2)
         RETURNING id",
    )
    .bind(user_id)
    .bind(&enc)
    .fetch_one(&mut **tx)
    .await?;
    Ok(id)
}

/// Mark a specific in-progress credential verified (active) and set its
/// label. Scoped to `user_id` + unverified so a tampered id can't touch
/// another user's or an already-active credential. Returns whether a row
/// matched.
pub async fn confirm(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
    cred_id: Uuid,
    label: &str,
) -> Result<bool> {
    let rows = sqlx::query(
        "UPDATE auth.totp_credentials
         SET verified_at = now(), label = $3
         WHERE id = $1 AND user_id = $2 AND verified_at IS NULL",
    )
    .bind(cred_id)
    .bind(user_id)
    .bind(label)
    .execute(&mut **tx)
    .await?;
    Ok(rows.rows_affected() > 0)
}

/// Decrypt the secret of a specific in-progress credential — used by the
/// enrollment confirm step.
pub async fn load_pending_secret(
    pool: &PgPool,
    key: &[u8; 32],
    user_id: UserId,
    cred_id: Uuid,
) -> Result<Option<Vec<u8>>> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT secret_enc FROM auth.totp_credentials
         WHERE id = $1 AND user_id = $2 AND verified_at IS NULL",
    )
    .bind(cred_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    match row {
        Some((enc,)) => Ok(Some(secretbox::open(key, &enc)?)),
        None => Ok(None),
    }
}

/// Whether the user has any active (verified) authenticator. Drives the
/// login branch and the Security-tab state.
pub async fn is_enrolled(pool: &PgPool, user_id: UserId) -> Result<bool> {
    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT EXISTS(
             SELECT 1 FROM auth.totp_credentials
             WHERE user_id = $1 AND verified_at IS NOT NULL
         )",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(matches!(row, Some((true,))))
}

/// All verified `(id, secret)` pairs for the user. The login challenge
/// tries each until one accepts the presented code.
pub async fn verified_secrets(
    pool: &PgPool,
    key: &[u8; 32],
    user_id: UserId,
) -> Result<Vec<(Uuid, Vec<u8>)>> {
    let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT id, secret_enc FROM auth.totp_credentials
         WHERE user_id = $1 AND verified_at IS NOT NULL",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, enc) in rows {
        out.push((id, secretbox::open(key, &enc)?));
    }
    Ok(out)
}

/// List the user's verified authenticators for the Security tab,
/// oldest first.
pub async fn list_verified(pool: &PgPool, user_id: UserId) -> Result<Vec<TotpCredential>> {
    let rows: Vec<TotpCredential> = sqlx::query_as(
        "SELECT id, label, created_at, last_used_at
         FROM auth.totp_credentials
         WHERE user_id = $1 AND verified_at IS NOT NULL
         ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Count of verified authenticators (enforces [`MAX_AUTHENTICATORS`]).
pub async fn count_verified(pool: &PgPool, user_id: UserId) -> Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM auth.totp_credentials
         WHERE user_id = $1 AND verified_at IS NOT NULL",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Rename a verified authenticator. Scoped to `user_id`.
pub async fn rename(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
    cred_id: Uuid,
    label: &str,
) -> Result<bool> {
    let rows = sqlx::query(
        "UPDATE auth.totp_credentials
         SET label = $3
         WHERE id = $1 AND user_id = $2 AND verified_at IS NOT NULL",
    )
    .bind(cred_id)
    .bind(user_id)
    .bind(label)
    .execute(&mut **tx)
    .await?;
    Ok(rows.rows_affected() > 0)
}

/// Stamp `last_used_at` on the credential that satisfied a sign-in.
pub async fn stamp_used(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    cred_id: Uuid,
) -> Result<()> {
    sqlx::query("UPDATE auth.totp_credentials SET last_used_at = now() WHERE id = $1")
        .bind(cred_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Remove one authenticator. Scoped to `user_id`. Returns whether a row
/// matched.
pub async fn delete(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
    cred_id: Uuid,
) -> Result<bool> {
    let rows = sqlx::query("DELETE FROM auth.totp_credentials WHERE id = $1 AND user_id = $2")
        .bind(cred_id)
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(rows.rows_affected() > 0)
}
