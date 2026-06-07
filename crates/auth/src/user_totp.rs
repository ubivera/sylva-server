//! Per-user TOTP enrollment storage. Mirrors [`crate::user_recovery_code`],
//! but the secret is *encrypted* at rest (via [`crate::secretbox`]) rather
//! than hashed, because the server must recover the plaintext to compute
//! the expected code at sign-in.
//!
//! A row exists from the moment enrollment starts; `verified_at` stays
//! NULL until the user confirms a code. Only a verified row counts as an
//! active second factor.

use chrono::{DateTime, Utc};
use identity::UserId;
use serde::Serialize;
use sqlx::PgPool;

use crate::Result;
use crate::secretbox;

/// Metadata about a user's TOTP enrollment. The secret never appears
/// here — the Security tab uses this to show "Enabled since …".
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct TotpRow {
    pub user_id: uuid::Uuid,
    pub created_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Store (or replace) a user's TOTP secret, encrypted and **unverified**.
/// UPSERT so restarting enrollment cleanly overwrites a half-finished
/// attempt. The row isn't an active factor until [`confirm`] runs.
pub async fn start_enrollment(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &[u8; 32],
    user_id: UserId,
    raw_secret: &[u8],
) -> Result<()> {
    let enc = secretbox::seal(key, raw_secret)?;
    sqlx::query(
        "INSERT INTO auth.totp_secrets (user_id, secret_enc, created_at, verified_at, last_used_at)
         VALUES ($1, $2, now(), NULL, NULL)
         ON CONFLICT (user_id) DO UPDATE
         SET secret_enc   = EXCLUDED.secret_enc,
             created_at   = now(),
             verified_at  = NULL,
             last_used_at = NULL",
    )
    .bind(user_id)
    .bind(&enc)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Mark the user's TOTP enrollment verified (active). Returns whether a
/// row was present to update.
pub async fn confirm(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
) -> Result<bool> {
    let rows = sqlx::query(
        "UPDATE auth.totp_secrets SET verified_at = now() WHERE user_id = $1",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await?;
    Ok(rows.rows_affected() > 0)
}

/// Whether TOTP is an active second factor for this user (enrolled AND
/// verified). Drives the login branch and the Security-tab state.
pub async fn is_enrolled(pool: &PgPool, user_id: UserId) -> Result<bool> {
    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT verified_at IS NOT NULL FROM auth.totp_secrets WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(matches!(row, Some((true,))))
}

/// Decrypt the stored secret regardless of verified state — used by the
/// enrollment confirm step (the row is still unverified at that point).
pub async fn load_secret(
    pool: &PgPool,
    key: &[u8; 32],
    user_id: UserId,
) -> Result<Option<Vec<u8>>> {
    load(pool, key, user_id, false).await
}

/// Decrypt the stored secret only if verified — used by the login
/// challenge so a half-finished enrollment can't satisfy 2FA.
pub async fn load_verified_secret(
    pool: &PgPool,
    key: &[u8; 32],
    user_id: UserId,
) -> Result<Option<Vec<u8>>> {
    load(pool, key, user_id, true).await
}

async fn load(
    pool: &PgPool,
    key: &[u8; 32],
    user_id: UserId,
    require_verified: bool,
) -> Result<Option<Vec<u8>>> {
    let sql = if require_verified {
        "SELECT secret_enc FROM auth.totp_secrets WHERE user_id = $1 AND verified_at IS NOT NULL"
    } else {
        "SELECT secret_enc FROM auth.totp_secrets WHERE user_id = $1"
    };
    let row: Option<(Vec<u8>,)> = sqlx::query_as(sql)
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    match row {
        Some((enc,)) => Ok(Some(secretbox::open(key, &enc)?)),
        None => Ok(None),
    }
}

/// Stamp `last_used_at` after a successful login challenge.
pub async fn stamp_used(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
) -> Result<()> {
    sqlx::query("UPDATE auth.totp_secrets SET last_used_at = now() WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Remove a user's TOTP enrollment entirely (turn off 2FA).
pub async fn disable(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
) -> Result<()> {
    sqlx::query("DELETE FROM auth.totp_secrets WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Verified-enrollment metadata for the Security tab ("Enabled since …").
/// Returns `None` when TOTP isn't active.
pub async fn metadata(pool: &PgPool, user_id: UserId) -> Result<Option<TotpRow>> {
    let row: Option<TotpRow> = sqlx::query_as(
        "SELECT user_id, created_at, verified_at, last_used_at
         FROM auth.totp_secrets
         WHERE user_id = $1 AND verified_at IS NOT NULL",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}
