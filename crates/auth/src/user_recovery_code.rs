use chrono::{DateTime, Utc};
use identity::UserId;
use serde::Serialize;
use sqlx::PgPool;

use crate::Result;
use crate::recovery_code::hash_code;

/// Metadata about a user's recovery code. The raw code never appears
/// here — `/me` uses this view to display "Generated YYYY-MM-DD" and
/// "Last used: …" without leaking anything sensitive.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct UserRecoveryCodeRow {
    pub user_id: uuid::Uuid,
    pub generated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Insert the very first recovery code for a freshly-created user.
/// Called from inside `perform_accept_invite`'s transaction. Fails if a
/// row already exists for this user (the primary key enforces one-per-
/// user) — callers needing replacement semantics should use [`rotate`]
/// instead.
pub async fn bootstrap(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
    raw_code: &str,
) -> Result<()> {
    let hash = hash_code(raw_code);
    sqlx::query(
        "INSERT INTO auth.user_recovery_codes (user_id, code_hash)
         VALUES ($1, $2)",
    )
    .bind(user_id)
    .bind(&hash[..])
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Replace a user's existing recovery code with a fresh one. UPSERTs so
/// the call is idempotent against "the user somehow doesn't have a code
/// yet". `generated_at` is reset; `last_used_at` is cleared because the
/// freshly-issued code has never been used.
pub async fn rotate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
    new_raw: &str,
) -> Result<()> {
    let hash = hash_code(new_raw);
    sqlx::query(
        "INSERT INTO auth.user_recovery_codes (user_id, code_hash, generated_at, last_used_at)
         VALUES ($1, $2, now(), NULL)
         ON CONFLICT (user_id) DO UPDATE
         SET code_hash    = EXCLUDED.code_hash,
             generated_at = now(),
             last_used_at = NULL",
    )
    .bind(user_id)
    .bind(&hash[..])
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Look up the active recovery code metadata for a user. Returns
/// `Ok(None)` when the user has no recovery code on file yet — only
/// happens for accounts created via a path that doesn't bootstrap a
/// code. Never returns the raw or the hash — those stay sealed in the DB.
pub async fn metadata(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Option<UserRecoveryCodeRow>> {
    let row: Option<UserRecoveryCodeRow> = sqlx::query_as(
        "SELECT user_id, generated_at, last_used_at
         FROM auth.user_recovery_codes
         WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Verify that `presented` is the active recovery code for `user_id`.
/// On match, stamps `last_used_at = now()` (atomically with the verify,
/// via the WHERE clause). Returns `Ok(true)` on success, `Ok(false)` on
/// mismatch or no-row.
///
/// Used by the forgot-password recovery flow — the caller is
/// responsible for whatever follows (issuing a single-use reset session,
/// requiring the user to set a new password, rotating the code to a
/// fresh one after the reset completes, etc.).
///
/// Operates inside a caller-provided transaction so the verify + stamp
/// commit together with whatever recovery action the caller takes. The
/// hash comparison is `code_hash = $2` against the canonical SHA-256;
/// no constant-time fuss is needed (256-bit hash space, no observable
/// timing channel).
pub async fn verify_and_stamp(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
    presented: &str,
) -> Result<bool> {
    let hash = hash_code(presented);
    let rows = sqlx::query(
        "UPDATE auth.user_recovery_codes
         SET last_used_at = now()
         WHERE user_id = $1 AND code_hash = $2",
    )
    .bind(user_id)
    .bind(&hash[..])
    .execute(&mut **tx)
    .await?;
    Ok(rows.rows_affected() > 0)
}
