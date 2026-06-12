//! Instance lifecycle — the `hearth_meta.instance` singleton + the
//! "scorch on the last user out" teardown.
//!
//! When the last active user closes their account, the instance is **closed**:
//! a terminal "this server has been closed" page is served on every web route
//! (see the closed-page middleware in the `web` crate, gated on the cached
//! `AppState::instance_closed` flag). A self-**Delete** additionally
//! **scorches** every data table — the whole point being "leave no trace" at
//! the instance level, audit log included. A self-**Anonymize** closes without
//! scorching, keeping the tombstone the user chose to leave behind.
//!
//! The closed flag lives in `hearth_meta` (not a data schema), so it survives
//! the scorch. Only `clean` (DROP DATABASE) clears it.

use sqlx::PgPool;

/// Every data-bearing table, across all schemas — the scorch target. Listed
/// explicitly (not derived) so adding a schema is a deliberate edit here.
/// `CASCADE` covers any FK-referenced row we didn't name; `RESTART IDENTITY`
/// resets sequences (e.g. `audit.events` seqno) so a re-provisioned instance
/// starts clean.
const SCORCH_SQL: &str = "TRUNCATE \
     identity.users, identity.invitations, \
     auth.credentials, auth.sessions, auth.recovery_codes, \
     auth.user_recovery_codes, auth.totp_credentials, \
     auth.webauthn_credentials, auth.webauthn_challenges, \
     audit.events, notifications.outbox, pending.transitions \
     RESTART IDENTITY CASCADE";

/// Read the persistent "closed" flag. Seeded by migration `0006`, so the row
/// should always exist; a missing row is treated as open.
pub async fn load_closed(db: &PgPool) -> anyhow::Result<bool> {
    let closed: Option<Option<chrono::DateTime<chrono::Utc>>> =
        sqlx::query_scalar("SELECT closed_at FROM hearth_meta.instance WHERE id = TRUE")
            .fetch_optional(db)
            .await?;
    Ok(matches!(closed, Some(Some(_))))
}

/// Mark the instance closed; when `scorch`, also wipe every data table (audit
/// log included) in the same transaction. `hearth_meta.instance` is in a
/// different schema, so the flag it just set survives the `TRUNCATE`.
pub async fn close(db: &PgPool, scorch: bool) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE hearth_meta.instance SET closed_at = now() WHERE id = TRUE")
        .execute(&mut *tx)
        .await?;
    if scorch {
        sqlx::query(SCORCH_SQL).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
