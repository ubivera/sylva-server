//! Owner Settings orchestration — persist an instance-config override, write
//! the audit trail, and hot-swap the live `AppState` cell so the change takes
//! effect without a restart. The storage primitives live in [`crate::instance`];
//! this module wraps them with audit + cache-swap (mirroring `account_logic`).
//!
//! Callers (the `web` settings handlers) validate form input first; these
//! functions assume validated input and focus on the persist→audit→swap flow.

use crate::app::AppState;
use crate::instance::{self, SmtpInput};

/// Persist the instance display-name override and swap the live cell. A `name`
/// of `None`/empty clears the override (reverts to the env default). The save
/// and the audit append commit atomically; the cell is then re-seeded from the
/// freshly-committed effective config.
pub async fn apply_instance_name(
    state: &AppState,
    actor: &audit::Actor,
    name: Option<&str>,
) -> anyhow::Result<()> {
    let cleared = name.map(|n| n.trim().is_empty()).unwrap_or(true);
    let mut tx = state.db.begin().await?;
    instance::save_instance_name(&mut *tx, name).await?;
    audit::append(
        &mut tx,
        Some(actor),
        None,
        "instance_settings_updated",
        serde_json::json!({ "field": "instance_name", "cleared": cleared }),
    )
    .await?;
    tx.commit().await?;

    let eff = instance::effective(&state.db, &state.env_config, &state.secret_key).await?;
    state
        .instance_name
        .store(std::sync::Arc::new(eff.instance_name));
    Ok(())
}

/// Persist the notifications override (mode + optional SMTP), seal the SMTP
/// password, write the audit trail (mode only — never the password), then
/// rebuild and swap the live notifier so the change applies on the next send.
pub async fn apply_notifications(
    state: &AppState,
    actor: &audit::Actor,
    mode: &str,
    smtp: Option<SmtpInput>,
) -> anyhow::Result<()> {
    let mut tx = state.db.begin().await?;
    instance::save_notifications(&mut *tx, &state.secret_key, mode, smtp).await?;
    audit::append(
        &mut tx,
        Some(actor),
        None,
        "notifications_configured",
        // Mode only — the SMTP password is sealed at rest and never logged.
        serde_json::json!({ "mode": mode }),
    )
    .await?;
    tx.commit().await?;

    let eff = instance::effective(&state.db, &state.env_config, &state.secret_key).await?;
    let notifier = crate::build_notifier(&eff.notifications)?;
    state.notifier.store(std::sync::Arc::new(notifier));
    Ok(())
}

/// Force the full instance teardown an Owner triggers from Settings — the same
/// scorch-and-close the last departing user causes: [`instance::close`] with
/// `scorch = true` wipes every data table (audit included), and the cached
/// closed flag flips so the closed-page middleware engages for all subsequent
/// requests. The caller (web handler) then ends the session + redirects.
pub async fn force_close_instance(state: &AppState) -> anyhow::Result<()> {
    instance::close(&state.db, /* scorch = */ true).await?;
    state
        .instance_closed
        .store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Result of a test-email send via the live notifier.
pub enum TestEmailOutcome {
    /// Handed to the SMTP server (or logged, in log mode).
    Sent,
    /// Notifications are disabled — nothing was sent.
    Disabled,
    /// The send failed; carries the error detail for display.
    Failed(String),
}

/// Send a one-off test message through the **currently live** notifier to `to`
/// (typically the Owner's own email), bypassing the outbox so the result can be
/// reported inline. Configure + save first — this uses the saved/live config,
/// not unsaved form values.
pub async fn send_test_email(state: &AppState, to: &str) -> TestEmailOutcome {
    let notifier = state.notifier.load();
    let msg = notifications::OutboundMessage {
        to: to.to_string(),
        subject: "Sylva Hearth test email".to_string(),
        body_text: "This is a test email from your Sylva Hearth instance. \
                     If you received it, outbound email is configured correctly."
            .to_string(),
        body_html: "<p>This is a test email from your Sylva Hearth instance. \
                     If you received it, outbound email is configured correctly.</p>"
            .to_string(),
    };
    match notifier.send(&msg).await {
        notifications::SendOutcome::Sent => TestEmailOutcome::Sent,
        notifications::SendOutcome::Skipped => TestEmailOutcome::Disabled,
        notifications::SendOutcome::Transient(e) => TestEmailOutcome::Failed(e),
    }
}
