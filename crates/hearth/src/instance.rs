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

use crate::config::{self, NotificationsConfig, SmtpSettings, SmtpTls};

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

// ── Owner-editable instance settings ──────────────────────────────────────
//
// A subset of config is editable at runtime via the Owner Settings page and
// stored as overrides on the `hearth_meta.instance` singleton. NULL columns
// mean "fall back to the env/startup default" (`effective`); a set value wins.
// The SMTP password is sealed with the instance `secret_key` (never clear).

/// Raw override row (config columns of the singleton). Any field `None` = use
/// the env default.
#[derive(Debug, Default, sqlx::FromRow)]
struct SettingsRow {
    instance_name: Option<String>,
    notifications_mode: Option<String>,
    smtp_host: Option<String>,
    smtp_port: Option<i32>,
    smtp_tls: Option<String>,
    smtp_username: Option<String>,
    smtp_password_enc: Option<Vec<u8>>,
    smtp_from_email: Option<String>,
    smtp_from_name: Option<String>,
}

async fn load_settings(db: &PgPool) -> anyhow::Result<SettingsRow> {
    let row = sqlx::query_as::<_, SettingsRow>(
        "SELECT instance_name, notifications_mode, smtp_host, smtp_port, smtp_tls, \
                smtp_username, smtp_password_enc, smtp_from_email, smtp_from_name \
         FROM hearth_meta.instance WHERE id = TRUE",
    )
    .fetch_optional(db)
    .await?
    .unwrap_or_default();
    Ok(row)
}

/// The runtime-effective config: DB override where set, else the env default.
pub struct EffectiveConfig {
    pub instance_name: String,
    pub notifications: NotificationsConfig,
}

/// Compute the effective config by overlaying the DB overrides on the env
/// `Config`. The SMTP password is unsealed with `secret_key`.
pub async fn effective(
    db: &PgPool,
    env: &config::Config,
    secret_key: &[u8; 32],
) -> anyhow::Result<EffectiveConfig> {
    let row = load_settings(db).await?;
    let instance_name = row
        .instance_name
        .clone()
        .unwrap_or_else(|| env.instance_name.clone());
    let notifications = notifications_from_row(&row, env, secret_key)?;
    Ok(EffectiveConfig {
        instance_name,
        notifications,
    })
}

fn parse_tls(s: Option<&str>) -> SmtpTls {
    match s {
        Some("implicit") => SmtpTls::Implicit,
        Some("none") => SmtpTls::None,
        _ => SmtpTls::Starttls,
    }
}

fn notifications_from_row(
    row: &SettingsRow,
    env: &config::Config,
    secret_key: &[u8; 32],
) -> anyhow::Result<NotificationsConfig> {
    match row.notifications_mode.as_deref() {
        // No override → whatever env configured at startup.
        None => Ok(env.notifications.clone()),
        Some("disabled") => Ok(NotificationsConfig::Disabled),
        Some("log") => Ok(NotificationsConfig::Log),
        Some("smtp") => {
            let password = match &row.smtp_password_enc {
                Some(enc) => {
                    let bytes = auth::secretbox::open(secret_key, enc)
                        .map_err(|_| anyhow::anyhow!("decrypting stored SMTP password"))?;
                    String::from_utf8(bytes)?
                }
                None => String::new(),
            };
            Ok(NotificationsConfig::Smtp(SmtpSettings {
                host: row.smtp_host.clone().unwrap_or_default(),
                port: row.smtp_port.map(|p| p as u16).unwrap_or(587),
                tls: parse_tls(row.smtp_tls.as_deref()),
                username: row.smtp_username.clone().unwrap_or_default(),
                password,
                from_email: row.smtp_from_email.clone().unwrap_or_default(),
                from_name: row.smtp_from_name.clone(),
            }))
        }
        // Unknown stored mode → fall back to env rather than break.
        Some(_) => Ok(env.notifications.clone()),
    }
}

/// Set the instance display-name override (`None`/empty clears it → env
/// default). Executor-generic so callers can run it inside a transaction
/// (alongside an audit append) or directly on the pool.
pub async fn save_instance_name<'e, E>(db: E, name: Option<&str>) -> anyhow::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("UPDATE hearth_meta.instance SET instance_name = $1 WHERE id = TRUE")
        .bind(name.filter(|n| !n.is_empty()))
        .execute(db)
        .await?;
    Ok(())
}

/// SMTP fields posted from the settings form. `password = None` (or empty)
/// means "keep the currently-stored secret".
pub struct SmtpInput {
    pub host: String,
    pub port: i32,
    pub tls: String,
    pub username: String,
    pub from_email: String,
    pub from_name: Option<String>,
    pub password: Option<String>,
}

/// Persist the notifications override. `mode` is `disabled` | `log` | `smtp`;
/// `smtp` is only consulted (and required) when `mode == "smtp"`. The caller
/// validates field presence first (reusing the env rules).
pub async fn save_notifications<'e, E>(
    db: E,
    secret_key: &[u8; 32],
    mode: &str,
    smtp: Option<SmtpInput>,
) -> anyhow::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    let Some(s) = smtp.filter(|_| mode == "smtp") else {
        // disabled / log — just record the mode; stale SMTP columns are
        // harmless (only read when mode == "smtp").
        sqlx::query("UPDATE hearth_meta.instance SET notifications_mode = $1 WHERE id = TRUE")
            .bind(mode)
            .execute(db)
            .await?;
        return Ok(());
    };

    let sealed = match s.password.as_deref().filter(|p| !p.is_empty()) {
        Some(pw) => Some(
            auth::secretbox::seal(secret_key, pw.as_bytes())
                .map_err(|_| anyhow::anyhow!("sealing SMTP password"))?,
        ),
        None => None, // keep the existing secret
    };
    let from_name = s.from_name.filter(|n| !n.is_empty());

    if let Some(enc) = sealed {
        sqlx::query(
            "UPDATE hearth_meta.instance SET notifications_mode = 'smtp', \
                 smtp_host = $1, smtp_port = $2, smtp_tls = $3, smtp_username = $4, \
                 smtp_password_enc = $5, smtp_from_email = $6, smtp_from_name = $7 \
             WHERE id = TRUE",
        )
        .bind(&s.host)
        .bind(s.port)
        .bind(&s.tls)
        .bind(&s.username)
        .bind(&enc[..])
        .bind(&s.from_email)
        .bind(&from_name)
        .execute(db)
        .await?;
    } else {
        // No new password → leave `smtp_password_enc` untouched.
        sqlx::query(
            "UPDATE hearth_meta.instance SET notifications_mode = 'smtp', \
                 smtp_host = $1, smtp_port = $2, smtp_tls = $3, smtp_username = $4, \
                 smtp_from_email = $5, smtp_from_name = $6 \
             WHERE id = TRUE",
        )
        .bind(&s.host)
        .bind(s.port)
        .bind(&s.tls)
        .bind(&s.username)
        .bind(&s.from_email)
        .bind(&from_name)
        .execute(db)
        .await?;
    }
    Ok(())
}

/// Whether an SMTP password is currently stored (so the settings UI can show
/// "configured" vs "not set" without ever revealing it).
pub async fn smtp_password_is_set(db: &PgPool) -> anyhow::Result<bool> {
    let present: Option<bool> = sqlx::query_scalar(
        "SELECT smtp_password_enc IS NOT NULL FROM hearth_meta.instance WHERE id = TRUE",
    )
    .fetch_optional(db)
    .await?;
    Ok(present.unwrap_or(false))
}
