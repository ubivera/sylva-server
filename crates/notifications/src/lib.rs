use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use identity::InstanceRole;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    address::Address,
    message::{Mailbox, MultiPart, header::ContentType},
    transport::smtp::authentication::Credentials,
};
use serde::Serialize;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum NotificationsError {
    #[error("database error")]
    Database(#[from] sqlx::Error),

    #[error("payload serialization failed")]
    Serialize(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, NotificationsError>;

/// Discriminator for outbox rows. Mirrors `notifications.outbox_kind` SQL enum.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, serde::Deserialize,
)]
#[sqlx(type_name = "notifications.outbox_kind", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum OutboxKind {
    Invitation,
    PendingRoleChangeInitiated,
    /// Fan-out variant sent to every active Owner *other* than the
    /// initiator and target when an Owner-on-Owner role change is
    /// queued. Lets the wider Owner cohort veto on behalf of the
    /// target without depending on the target seeing their own email.
    PendingRoleChangeInitiatedPeer,
    PendingRoleChangeVetoed,
    PendingRoleChangeApplied,
    PendingLifecycleInitiated,
    /// Companion fan-out variant for lifecycle pendings. See
    /// [`OutboxKind::PendingRoleChangeInitiatedPeer`] for the rationale.
    PendingLifecycleInitiatedPeer,
    PendingLifecycleVetoed,
    PendingLifecycleApplied,
}

/// Which lifecycle action a pending transition represents. Shared with
/// the `pending` crate (re-exported there) so the two layers agree on
/// the same enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    Deactivate,
    Anonymize,
    Delete,
}

impl LifecycleAction {
    /// Verb-form used in templates: "deactivation", "account anonymization",
    /// "account deletion".
    pub fn noun(self) -> &'static str {
        match self {
            LifecycleAction::Deactivate => "deactivation",
            LifecycleAction::Anonymize => "account anonymization",
            LifecycleAction::Delete => "account deletion",
        }
    }

    pub fn past_tense(self) -> &'static str {
        match self {
            LifecycleAction::Deactivate => "deactivated",
            LifecycleAction::Anonymize => "anonymized",
            LifecycleAction::Delete => "deleted",
        }
    }
}

/// Domain-level notification, before rendering. Each variant is a distinct
/// kind with its own template + payload shape.
#[derive(Debug, Clone)]
pub enum Notification {
    Invitation {
        recipient_email: String,
        inviter_display_name: String,
        accept_url: String,
        expires_at: DateTime<Utc>,
        instance_role: InstanceRole,
        invitation_id: Uuid,
    },
    /// Owner-on-Owner role-change has been initiated against `recipient`.
    /// They can veto from `veto_url` before `effective_at`.
    PendingRoleChangeInitiated {
        recipient_email: String,
        target_display_name: String,
        initiator_display_name: String,
        from_role: InstanceRole,
        to_role: InstanceRole,
        effective_at: DateTime<Utc>,
        veto_url: String,
        transition_id: Uuid,
    },
    /// Fan-out copy of [`Notification::PendingRoleChangeInitiated`]
    /// addressed to a peer Owner (anyone except the initiator + target).
    /// Same payload shape; the rendered subject + body frame it as
    /// "a peer Owner is being targeted" rather than "your account is
    /// being targeted".
    PendingRoleChangeInitiatedPeer {
        recipient_email: String,
        target_display_name: String,
        initiator_display_name: String,
        from_role: InstanceRole,
        to_role: InstanceRole,
        effective_at: DateTime<Utc>,
        veto_url: String,
        transition_id: Uuid,
    },
    /// An initiator's pending role-change was vetoed.
    PendingRoleChangeVetoed {
        recipient_email: String,
        initiator_display_name: String,
        target_display_name: String,
        vetoed_by_display_name: String,
        from_role: InstanceRole,
        to_role: InstanceRole,
        transition_id: Uuid,
    },
    /// A pending role-change has been applied — either because the timer
    /// expired without a veto, or because the recovery code was used to
    /// bypass the window. `transition_id` is `None` when the action took
    /// the bypass path (there was no pending row to reference).
    PendingRoleChangeApplied {
        recipient_email: String,
        target_display_name: String,
        initiator_display_name: String,
        applied_role: InstanceRole,
        via_recovery_bypass: bool,
        transition_id: Option<Uuid>,
    },
    /// Owner-on-Owner lifecycle action (deactivate / delete / purge) has
    /// been queued against `recipient`. Mirrors `PendingRoleChangeInitiated`
    /// but parameterized by lifecycle action rather than from/to roles.
    PendingLifecycleInitiated {
        recipient_email: String,
        target_display_name: String,
        initiator_display_name: String,
        action: LifecycleAction,
        effective_at: DateTime<Utc>,
        veto_url: String,
        transition_id: Uuid,
    },
    /// Fan-out copy of [`Notification::PendingLifecycleInitiated`]
    /// addressed to a peer Owner. See the role-change variant's
    /// `PendingRoleChangeInitiatedPeer` for rationale.
    PendingLifecycleInitiatedPeer {
        recipient_email: String,
        target_display_name: String,
        initiator_display_name: String,
        action: LifecycleAction,
        effective_at: DateTime<Utc>,
        veto_url: String,
        transition_id: Uuid,
    },
    /// An initiator's pending lifecycle action was vetoed.
    PendingLifecycleVetoed {
        recipient_email: String,
        initiator_display_name: String,
        target_display_name: String,
        vetoed_by_display_name: String,
        action: LifecycleAction,
        transition_id: Uuid,
    },
    /// A pending lifecycle action has been applied (timer or bypass).
    PendingLifecycleApplied {
        recipient_email: String,
        target_display_name: String,
        initiator_display_name: String,
        action: LifecycleAction,
        via_recovery_bypass: bool,
        transition_id: Option<Uuid>,
    },
}

/// What actually goes into the outbox row's text columns. Distinct from
/// [`Notification`] because the renderer is responsible for producing the
/// canonical subject/text/html the worker will hand to the transport.
pub struct Rendered {
    pub kind: OutboxKind,
    pub recipient_email: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: String,
    pub payload: serde_json::Value,
}

impl Notification {
    pub fn render(self) -> Rendered {
        match self {
            Notification::Invitation {
                recipient_email,
                inviter_display_name,
                accept_url,
                expires_at,
                instance_role,
                invitation_id,
            } => {
                let role_label = match instance_role {
                    InstanceRole::Owner => "Owner",
                    InstanceRole::Admin => "Admin",
                    InstanceRole::Member => "User",
                };
                let subject = format!("{inviter_display_name} invited you to Sylva Hearth");
                let body_text = format!(
                    "{inviter_display_name} has invited you to join their Sylva Hearth instance \
                     as a {role_label}.\n\n\
                     Accept the invitation here:\n  {accept_url}\n\n\
                     This invitation expires on {expires_at}.\n\n\
                     If you weren't expecting this, you can safely ignore this email.\n",
                    expires_at = expires_at.format("%Y-%m-%d %H:%M UTC"),
                );
                let body_html = format!(
                    "<!doctype html><html><body style=\"font-family:sans-serif;line-height:1.5;\">\
                     <p><strong>{inviter}</strong> has invited you to join their Sylva Hearth \
                     instance as a <strong>{role}</strong>.</p>\
                     <p><a href=\"{url}\" style=\"display:inline-block;padding:10px 16px;\
                     background:#1e6feb;color:#fff;text-decoration:none;border-radius:4px;\">\
                     Accept invitation</a></p>\
                     <p style=\"color:#666;font-size:13px;\">Or paste this link into your browser:\
                     <br><span style=\"font-family:monospace;\">{url}</span></p>\
                     <p style=\"color:#666;font-size:13px;\">This invitation expires on {expires}.</p>\
                     <p style=\"color:#999;font-size:12px;margin-top:24px;\">\
                     If you weren't expecting this, you can safely ignore this email.</p>\
                     </body></html>",
                    inviter = html_escape(&inviter_display_name),
                    role = role_label,
                    url = html_escape(&accept_url),
                    expires = expires_at.format("%Y-%m-%d %H:%M UTC"),
                );
                let payload = serde_json::json!({
                    "invitation_id": invitation_id,
                    "instance_role": instance_role,
                });
                Rendered {
                    kind: OutboxKind::Invitation,
                    recipient_email,
                    subject,
                    body_text,
                    body_html,
                    payload,
                }
            }
            Notification::PendingRoleChangeInitiated {
                recipient_email,
                target_display_name,
                initiator_display_name,
                from_role,
                to_role,
                effective_at,
                veto_url,
                transition_id,
            } => {
                let from = role_label(from_role);
                let to = role_label(to_role);
                let subject = format!(
                    "{initiator_display_name} has initiated a role change on your account"
                );
                let body_text = format!(
                    "{initiator_display_name} has initiated a pending role change on your \
                     Sylva Hearth account:\n\n\
                     \tFrom: {from}\n\
                     \tTo:   {to}\n\n\
                     If you don't take action, the change will be applied automatically on \
                     {effective_at}.\n\n\
                     If this was not expected, veto the change here:\n  {veto_url}\n\n\
                     Any other Owner on this instance can also veto it on your behalf.\n",
                    effective_at = effective_at.format("%Y-%m-%d %H:%M UTC"),
                );
                let body_html = format!(
                    "<!doctype html><html><body style=\"font-family:sans-serif;line-height:1.5;\">\
                     <p>Hi {target},</p>\
                     <p><strong>{initiator}</strong> has initiated a pending role change on \
                     your Sylva Hearth account:</p>\
                     <ul><li>From: <strong>{from}</strong></li>\
                     <li>To: <strong>{to}</strong></li></ul>\
                     <p>If you take no action, this will apply on <strong>{when}</strong>.</p>\
                     <p><a href=\"{url}\" style=\"display:inline-block;padding:10px 16px;\
                     background:#d83a3a;color:#fff;text-decoration:none;border-radius:4px;\">\
                     Veto this change</a></p>\
                     <p style=\"color:#666;font-size:13px;\">Or paste this link into your browser:\
                     <br><span style=\"font-family:monospace;\">{url}</span></p>\
                     <p style=\"color:#999;font-size:12px;margin-top:24px;\">\
                     Any other Owner can also veto on your behalf.</p>\
                     </body></html>",
                    target = html_escape(&target_display_name),
                    initiator = html_escape(&initiator_display_name),
                    from = from,
                    to = to,
                    when = effective_at.format("%Y-%m-%d %H:%M UTC"),
                    url = html_escape(&veto_url),
                );
                let payload = serde_json::json!({
                    "transition_id": transition_id,
                    "from_role": from_role,
                    "to_role": to_role,
                });
                Rendered {
                    kind: OutboxKind::PendingRoleChangeInitiated,
                    recipient_email,
                    subject,
                    body_text,
                    body_html,
                    payload,
                }
            }
            Notification::PendingRoleChangeInitiatedPeer {
                recipient_email,
                target_display_name,
                initiator_display_name,
                from_role,
                to_role,
                effective_at,
                veto_url,
                transition_id,
            } => {
                let from = role_label(from_role);
                let to = role_label(to_role);
                let subject = format!(
                    "Heads up: {initiator_display_name} has initiated a role change on \
                     {target_display_name}"
                );
                let body_text = format!(
                    "Another Owner action on your Sylva Hearth instance needs review.\n\n\
                     {initiator_display_name} has initiated a pending role change on \
                     {target_display_name}'s account:\n\n\
                     \tFrom: {from}\n\
                     \tTo:   {to}\n\n\
                     If you don't take action, this will apply automatically on \
                     {effective_at}.\n\n\
                     If this was not coordinated, any Owner can veto it here:\n  {veto_url}\n",
                    effective_at = effective_at.format("%Y-%m-%d %H:%M UTC"),
                );
                let body_html = format!(
                    "<!doctype html><html><body style=\"font-family:sans-serif;line-height:1.5;\">\
                     <p>Heads up — another Owner action on your Sylva Hearth instance needs review.</p>\
                     <p><strong>{initiator}</strong> has initiated a pending role change on \
                     <strong>{target}</strong>'s account:</p>\
                     <ul><li>From: <strong>{from}</strong></li>\
                     <li>To: <strong>{to}</strong></li></ul>\
                     <p>If you take no action, this will apply on <strong>{when}</strong>.</p>\
                     <p><a href=\"{url}\" style=\"display:inline-block;padding:10px 16px;\
                     background:#d83a3a;color:#fff;text-decoration:none;border-radius:4px;\">\
                     Veto this change</a></p>\
                     <p style=\"color:#666;font-size:13px;\">Or paste this link into your browser:\
                     <br><span style=\"font-family:monospace;\">{url}</span></p>\
                     </body></html>",
                    target = html_escape(&target_display_name),
                    initiator = html_escape(&initiator_display_name),
                    from = from,
                    to = to,
                    when = effective_at.format("%Y-%m-%d %H:%M UTC"),
                    url = html_escape(&veto_url),
                );
                let payload = serde_json::json!({
                    "transition_id": transition_id,
                    "from_role": from_role,
                    "to_role": to_role,
                    "target_display_name": target_display_name,
                });
                Rendered {
                    kind: OutboxKind::PendingRoleChangeInitiatedPeer,
                    recipient_email,
                    subject,
                    body_text,
                    body_html,
                    payload,
                }
            }
            Notification::PendingRoleChangeVetoed {
                recipient_email,
                initiator_display_name,
                target_display_name,
                vetoed_by_display_name,
                from_role,
                to_role,
                transition_id,
            } => {
                let from = role_label(from_role);
                let to = role_label(to_role);
                let subject =
                    format!("Your role change on {target_display_name} was vetoed");
                let body_text = format!(
                    "Hi {initiator_display_name},\n\n\
                     Your pending role change on {target_display_name}'s account \
                     ({from} → {to}) has been vetoed by {vetoed_by_display_name}.\n\n\
                     No change was applied. If you still believe this action is necessary, \
                     coordinate with the other Owners on this instance.\n",
                );
                let body_html = format!(
                    "<!doctype html><html><body style=\"font-family:sans-serif;line-height:1.5;\">\
                     <p>Hi {initiator},</p>\
                     <p>Your pending role change on <strong>{target}</strong>'s account \
                     (<strong>{from}</strong> → <strong>{to}</strong>) has been vetoed by \
                     <strong>{vetoer}</strong>.</p>\
                     <p>No change was applied. If you still believe this action is necessary, \
                     coordinate with the other Owners on this instance.</p>\
                     </body></html>",
                    initiator = html_escape(&initiator_display_name),
                    target = html_escape(&target_display_name),
                    vetoer = html_escape(&vetoed_by_display_name),
                    from = from,
                    to = to,
                );
                let payload = serde_json::json!({
                    "transition_id": transition_id,
                    "from_role": from_role,
                    "to_role": to_role,
                });
                Rendered {
                    kind: OutboxKind::PendingRoleChangeVetoed,
                    recipient_email,
                    subject,
                    body_text,
                    body_html,
                    payload,
                }
            }
            Notification::PendingRoleChangeApplied {
                recipient_email,
                target_display_name,
                initiator_display_name,
                applied_role,
                via_recovery_bypass,
                transition_id,
            } => {
                let role = role_label(applied_role);
                let how = if via_recovery_bypass {
                    "using the server recovery code"
                } else {
                    "after the 72-hour veto window expired"
                };
                let subject = format!("Your account role has been changed to {role}");
                let body_text = format!(
                    "Hi {target_display_name},\n\n\
                     Your role on Sylva Hearth has been changed to {role} by \
                     {initiator_display_name} {how}.\n\n\
                     If you believe this was unauthorized, contact another Owner immediately.\n",
                );
                let body_html = format!(
                    "<!doctype html><html><body style=\"font-family:sans-serif;line-height:1.5;\">\
                     <p>Hi {target},</p>\
                     <p>Your role on Sylva Hearth has been changed to <strong>{role}</strong> by \
                     <strong>{initiator}</strong> {how}.</p>\
                     <p style=\"color:#666;font-size:13px;\">If you believe this was \
                     unauthorized, contact another Owner immediately.</p>\
                     </body></html>",
                    target = html_escape(&target_display_name),
                    initiator = html_escape(&initiator_display_name),
                    role = role,
                    how = how,
                );
                let payload = serde_json::json!({
                    "transition_id": transition_id,
                    "applied_role": applied_role,
                    "via_recovery_bypass": via_recovery_bypass,
                });
                Rendered {
                    kind: OutboxKind::PendingRoleChangeApplied,
                    recipient_email,
                    subject,
                    body_text,
                    body_html,
                    payload,
                }
            }
            Notification::PendingLifecycleInitiated {
                recipient_email,
                target_display_name,
                initiator_display_name,
                action,
                effective_at,
                veto_url,
                transition_id,
            } => {
                let noun = action.noun();
                let subject = format!(
                    "{initiator_display_name} has initiated a pending {noun} on your account"
                );
                let body_text = format!(
                    "Hi {target_display_name},\n\n\
                     {initiator_display_name} has initiated a pending {noun} on your Sylva \
                     Hearth account.\n\n\
                     If you don't take action, this will be applied automatically on \
                     {effective_at}.\n\n\
                     If this was not expected, veto the action here:\n  {veto_url}\n\n\
                     Any other Owner on this instance can also veto it on your behalf.\n",
                    effective_at = effective_at.format("%Y-%m-%d %H:%M UTC"),
                );
                let body_html = format!(
                    "<!doctype html><html><body style=\"font-family:sans-serif;line-height:1.5;\">\
                     <p>Hi {target},</p>\
                     <p><strong>{initiator}</strong> has initiated a pending <strong>{noun}</strong> \
                     on your Sylva Hearth account.</p>\
                     <p>If you take no action, this will apply on <strong>{when}</strong>.</p>\
                     <p><a href=\"{url}\" style=\"display:inline-block;padding:10px 16px;\
                     background:#d83a3a;color:#fff;text-decoration:none;border-radius:4px;\">\
                     Veto this action</a></p>\
                     <p style=\"color:#666;font-size:13px;\">Or paste this link into your browser:\
                     <br><span style=\"font-family:monospace;\">{url}</span></p>\
                     <p style=\"color:#999;font-size:12px;margin-top:24px;\">\
                     Any other Owner can also veto on your behalf.</p>\
                     </body></html>",
                    target = html_escape(&target_display_name),
                    initiator = html_escape(&initiator_display_name),
                    noun = noun,
                    when = effective_at.format("%Y-%m-%d %H:%M UTC"),
                    url = html_escape(&veto_url),
                );
                let payload = serde_json::json!({
                    "transition_id": transition_id,
                    "action": action,
                });
                Rendered {
                    kind: OutboxKind::PendingLifecycleInitiated,
                    recipient_email,
                    subject,
                    body_text,
                    body_html,
                    payload,
                }
            }
            Notification::PendingLifecycleInitiatedPeer {
                recipient_email,
                target_display_name,
                initiator_display_name,
                action,
                effective_at,
                veto_url,
                transition_id,
            } => {
                let noun = action.noun();
                let subject = format!(
                    "Heads up: {initiator_display_name} has initiated a pending {noun} on \
                     {target_display_name}"
                );
                let body_text = format!(
                    "Another Owner action on your Sylva Hearth instance needs review.\n\n\
                     {initiator_display_name} has initiated a pending {noun} on \
                     {target_display_name}'s account.\n\n\
                     If you don't take action, this will apply automatically on \
                     {effective_at}.\n\n\
                     If this was not coordinated, any Owner can veto it here:\n  {veto_url}\n",
                    effective_at = effective_at.format("%Y-%m-%d %H:%M UTC"),
                );
                let body_html = format!(
                    "<!doctype html><html><body style=\"font-family:sans-serif;line-height:1.5;\">\
                     <p>Heads up — another Owner action on your Sylva Hearth instance needs review.</p>\
                     <p><strong>{initiator}</strong> has initiated a pending \
                     <strong>{noun}</strong> on <strong>{target}</strong>'s account.</p>\
                     <p>If you take no action, this will apply on <strong>{when}</strong>.</p>\
                     <p><a href=\"{url}\" style=\"display:inline-block;padding:10px 16px;\
                     background:#d83a3a;color:#fff;text-decoration:none;border-radius:4px;\">\
                     Veto this action</a></p>\
                     <p style=\"color:#666;font-size:13px;\">Or paste this link into your browser:\
                     <br><span style=\"font-family:monospace;\">{url}</span></p>\
                     </body></html>",
                    target = html_escape(&target_display_name),
                    initiator = html_escape(&initiator_display_name),
                    noun = noun,
                    when = effective_at.format("%Y-%m-%d %H:%M UTC"),
                    url = html_escape(&veto_url),
                );
                let payload = serde_json::json!({
                    "transition_id": transition_id,
                    "action": action,
                    "target_display_name": target_display_name,
                });
                Rendered {
                    kind: OutboxKind::PendingLifecycleInitiatedPeer,
                    recipient_email,
                    subject,
                    body_text,
                    body_html,
                    payload,
                }
            }
            Notification::PendingLifecycleVetoed {
                recipient_email,
                initiator_display_name,
                target_display_name,
                vetoed_by_display_name,
                action,
                transition_id,
            } => {
                let noun = action.noun();
                let subject = format!("Your {noun} of {target_display_name} was vetoed");
                let body_text = format!(
                    "Hi {initiator_display_name},\n\n\
                     Your pending {noun} of {target_display_name}'s account has been vetoed by \
                     {vetoed_by_display_name}.\n\n\
                     No change was applied. If you still believe this action is necessary, \
                     coordinate with the other Owners on this instance.\n",
                );
                let body_html = format!(
                    "<!doctype html><html><body style=\"font-family:sans-serif;line-height:1.5;\">\
                     <p>Hi {initiator},</p>\
                     <p>Your pending <strong>{noun}</strong> of <strong>{target}</strong>'s \
                     account has been vetoed by <strong>{vetoer}</strong>.</p>\
                     <p>No change was applied. If you still believe this action is necessary, \
                     coordinate with the other Owners on this instance.</p>\
                     </body></html>",
                    initiator = html_escape(&initiator_display_name),
                    target = html_escape(&target_display_name),
                    vetoer = html_escape(&vetoed_by_display_name),
                    noun = noun,
                );
                let payload = serde_json::json!({
                    "transition_id": transition_id,
                    "action": action,
                });
                Rendered {
                    kind: OutboxKind::PendingLifecycleVetoed,
                    recipient_email,
                    subject,
                    body_text,
                    body_html,
                    payload,
                }
            }
            Notification::PendingLifecycleApplied {
                recipient_email,
                target_display_name,
                initiator_display_name,
                action,
                via_recovery_bypass,
                transition_id,
            } => {
                let past = action.past_tense();
                let how = if via_recovery_bypass {
                    "using the server recovery code"
                } else {
                    "after the 72-hour veto window expired"
                };
                let subject = format!("Your account has been {past}");
                let body_text = format!(
                    "Hi {target_display_name},\n\n\
                     Your Sylva Hearth account has been {past} by {initiator_display_name} \
                     {how}.\n\n\
                     If you believe this was unauthorized, contact another Owner immediately.\n",
                );
                let body_html = format!(
                    "<!doctype html><html><body style=\"font-family:sans-serif;line-height:1.5;\">\
                     <p>Hi {target},</p>\
                     <p>Your Sylva Hearth account has been <strong>{past}</strong> by \
                     <strong>{initiator}</strong> {how}.</p>\
                     <p style=\"color:#666;font-size:13px;\">If you believe this was \
                     unauthorized, contact another Owner immediately.</p>\
                     </body></html>",
                    target = html_escape(&target_display_name),
                    initiator = html_escape(&initiator_display_name),
                    past = past,
                    how = how,
                );
                let payload = serde_json::json!({
                    "transition_id": transition_id,
                    "action": action,
                    "via_recovery_bypass": via_recovery_bypass,
                });
                Rendered {
                    kind: OutboxKind::PendingLifecycleApplied,
                    recipient_email,
                    subject,
                    body_text,
                    body_html,
                    payload,
                }
            }
        }
    }
}

fn role_label(r: InstanceRole) -> &'static str {
    match r {
        InstanceRole::Owner => "Owner",
        InstanceRole::Admin => "Admin",
        InstanceRole::Member => "User",
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Insert a notification into the outbox within the caller's transaction.
/// Returns the new outbox row id. State defaults to `pending` (SQL default);
/// the caller's notifier mode is consulted later by the worker — we don't
/// pre-mark as `skipped` here, because then the disabled-mode visibility
/// behaves the same as the enabled modes (rows exist, but the worker
/// short-circuits them).
pub async fn enqueue(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    notification: Notification,
) -> Result<Uuid> {
    let r = notification.render();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO notifications.outbox
             (kind, recipient_email, subject, body_text, body_html, payload)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id",
    )
    .bind(r.kind)
    .bind(&r.recipient_email)
    .bind(&r.subject)
    .bind(&r.body_text)
    .bind(&r.body_html)
    .bind(&r.payload)
    .fetch_one(&mut **tx)
    .await?;
    Ok(id)
}

// ────────────────────────────────────────────────────────────────────────
// Outbox row + state
// ────────────────────────────────────────────────────────────────────────

/// Mirrors `notifications.outbox_state`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, serde::Deserialize,
)]
#[sqlx(type_name = "notifications.outbox_state", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum OutboxState {
    Pending,
    Sending,
    Sent,
    Failed,
    Dead,
    Skipped,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct OutboxRow {
    pub id: Uuid,
    pub kind: OutboxKind,
    pub recipient_email: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: String,
    pub payload: serde_json::Value,
    pub state: OutboxState,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub next_attempt_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
}

/// List outbox rows newest-first, optionally filtered by state. Used by
/// `GET /admin/notifications`.
pub async fn list(
    pool: &PgPool,
    state_filter: Option<OutboxState>,
    limit: u32,
) -> Result<Vec<OutboxRow>> {
    let rows: Vec<OutboxRow> = sqlx::query_as(
        "SELECT id, kind, recipient_email, subject, body_text, body_html,
                payload, state, attempts, last_error, next_attempt_at,
                created_at, sent_at
         FROM notifications.outbox
         WHERE ($1::notifications.outbox_state IS NULL OR state = $1)
         ORDER BY created_at DESC
         LIMIT $2",
    )
    .bind(state_filter)
    .bind(i64::from(limit))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Outcome of a single send attempt.
#[derive(Debug)]
pub enum SendOutcome {
    /// Delivery to the SMTP server succeeded (or was logged in log mode).
    Sent,
    /// The notifier is configured `Disabled`; the worker should mark the
    /// row `skipped` instead of retrying.
    Skipped,
    /// Transient failure; the worker should backoff + retry.
    Transient(String),
}

/// The outbound shape handed to a notifier — distinct from the database
/// `OutboxRow` so notifiers don't depend on sqlx.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub to: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: String,
}

#[derive(Debug, Clone)]
pub struct FromAddress {
    pub email: String,
    pub name: Option<String>,
}

/// Enum-dispatched notifier. Picked once at startup from config; cloning
/// is cheap (`Arc::clone` for the SMTP variant; no-op for the others).
#[derive(Clone)]
pub enum NotifierImpl {
    Disabled,
    Log,
    /// SMTP transport is `Arc`-wrapped so the enum stays small and cheap
    /// to clone — lettre's `AsyncSmtpTransport` is already internally
    /// reference-counted, but the outer struct is large.
    Smtp(Arc<SmtpNotifier>),
    /// Test-only backend that always reports a transient failure with the
    /// given reason. Not used by production code; kept here (rather than
    /// `#[cfg(test)]`) so integration tests living in the `hearth` crate
    /// can reach it.
    #[doc(hidden)]
    AlwaysFail(String),
}

impl NotifierImpl {
    pub async fn send(&self, msg: &OutboundMessage) -> SendOutcome {
        match self {
            NotifierImpl::Disabled => SendOutcome::Skipped,
            NotifierImpl::Log => {
                tracing::info!(
                    target: "notifications::log",
                    to = %msg.to,
                    subject = %msg.subject,
                    body_preview = %truncate(&msg.body_text, 200),
                    "stub: would send notification"
                );
                SendOutcome::Sent
            }
            NotifierImpl::Smtp(s) => s.send(msg).await,
            NotifierImpl::AlwaysFail(reason) => SendOutcome::Transient(reason.clone()),
        }
    }
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

/// Real SMTP backend, built around `lettre`'s async tokio transport.
#[derive(Clone)]
pub struct SmtpNotifier {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: FromAddress,
}

#[derive(Debug, Clone, Copy)]
pub enum SmtpTls {
    /// STARTTLS upgrade on a plaintext connection (default for port 587).
    Starttls,
    /// Implicit TLS (SMTPS) — connect over TLS from the start (port 465).
    Implicit,
    /// No TLS at all. Only safe on loopback or trusted networks; we still
    /// honour authentication so test fixtures work.
    None,
}

pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub tls: SmtpTls,
    pub username: String,
    pub password: String,
    pub from: FromAddress,
}

impl SmtpNotifier {
    pub fn build(cfg: SmtpConfig) -> anyhow::Result<Self> {
        let builder = match cfg.tls {
            SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)?,
            SmtpTls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)?,
            SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host),
        };
        let transport = builder
            .port(cfg.port)
            .credentials(Credentials::new(cfg.username, cfg.password))
            .build();
        Ok(Self {
            transport,
            from: cfg.from,
        })
    }

    async fn send(&self, msg: &OutboundMessage) -> SendOutcome {
        let from_mb = match build_mailbox(&self.from.email, self.from.name.as_deref()) {
            Ok(m) => m,
            Err(err) => return SendOutcome::Transient(format!("invalid from address: {err}")),
        };
        let to_mb = match build_mailbox(&msg.to, None) {
            Ok(m) => m,
            Err(err) => return SendOutcome::Transient(format!("invalid recipient: {err}")),
        };

        let email = match Message::builder()
            .from(from_mb)
            .to(to_mb)
            .subject(&msg.subject)
            .multipart(MultiPart::alternative_plain_html(
                msg.body_text.clone(),
                msg.body_html.clone(),
            )) {
            Ok(e) => e,
            Err(err) => return SendOutcome::Transient(format!("building message: {err}")),
        };
        let _ = ContentType::TEXT_HTML; // unused-import shield; lettre re-exports it.

        match self.transport.send(email).await {
            Ok(_) => SendOutcome::Sent,
            Err(err) => SendOutcome::Transient(format!("smtp send failed: {err}")),
        }
    }
}

fn build_mailbox(email: &str, name: Option<&str>) -> anyhow::Result<Mailbox> {
    let addr: Address = email.parse()?;
    Ok(Mailbox::new(name.map(str::to_string), addr))
}

// ────────────────────────────────────────────────────────────────────────
// Worker
// ────────────────────────────────────────────────────────────────────────

/// Maximum number of attempts before a row goes `dead`.
pub const MAX_ATTEMPTS: i32 = 6;

/// Exponential-ish backoff schedule keyed off the `attempts` value AFTER the
/// failure has been recorded. Returns the delay until the next retry.
pub fn backoff_for(attempts: i32) -> Duration {
    match attempts {
        1 => Duration::from_secs(60),         //  1 min
        2 => Duration::from_secs(5 * 60),     //  5 min
        3 => Duration::from_secs(15 * 60),    // 15 min
        4 => Duration::from_secs(60 * 60),    //  1 hr
        5 => Duration::from_secs(6 * 60 * 60), //  6 hr
        _ => Duration::from_secs(24 * 60 * 60), // 24 hr
    }
}

#[derive(Clone)]
pub struct Worker {
    pool: PgPool,
    notifier: NotifierImpl,
}

impl Worker {
    pub fn new(pool: PgPool, notifier: NotifierImpl) -> Self {
        Self { pool, notifier }
    }

    /// Run one drain cycle: claim every pending row whose `next_attempt_at`
    /// has come due, attempt to send each, update state. Returns the number
    /// of rows processed.
    ///
    /// Tests call this directly so they don't depend on real time passing.
    /// Production wraps it in a poll loop.
    pub async fn process_pending(&self) -> Result<usize> {
        let claimed: Vec<OutboxRow> = sqlx::query_as(
            "UPDATE notifications.outbox
             SET state = 'sending'
             WHERE id IN (
                 SELECT id FROM notifications.outbox
                 WHERE state = 'pending' AND next_attempt_at <= now()
                 ORDER BY next_attempt_at
                 FOR UPDATE SKIP LOCKED
                 LIMIT 32
             )
             RETURNING id, kind, recipient_email, subject, body_text, body_html,
                       payload, state, attempts, last_error, next_attempt_at,
                       created_at, sent_at",
        )
        .fetch_all(&self.pool)
        .await?;

        let count = claimed.len();
        for row in claimed {
            let outcome = self
                .notifier
                .send(&OutboundMessage {
                    to: row.recipient_email.clone(),
                    subject: row.subject.clone(),
                    body_text: row.body_text.clone(),
                    body_html: row.body_html.clone(),
                })
                .await;
            self.apply_outcome(row.id, row.attempts, outcome).await?;
        }
        Ok(count)
    }

    async fn apply_outcome(
        &self,
        id: Uuid,
        prior_attempts: i32,
        outcome: SendOutcome,
    ) -> Result<()> {
        match outcome {
            SendOutcome::Sent => {
                sqlx::query(
                    "UPDATE notifications.outbox
                     SET state = 'sent', sent_at = now(), last_error = NULL
                     WHERE id = $1",
                )
                .bind(id)
                .execute(&self.pool)
                .await?;
            }
            SendOutcome::Skipped => {
                sqlx::query(
                    "UPDATE notifications.outbox
                     SET state = 'skipped', last_error = NULL
                     WHERE id = $1",
                )
                .bind(id)
                .execute(&self.pool)
                .await?;
            }
            SendOutcome::Transient(err) => {
                let new_attempts = prior_attempts + 1;
                if new_attempts >= MAX_ATTEMPTS {
                    sqlx::query(
                        "UPDATE notifications.outbox
                         SET state = 'dead', attempts = $2, last_error = $3
                         WHERE id = $1",
                    )
                    .bind(id)
                    .bind(new_attempts)
                    .bind(&err)
                    .execute(&self.pool)
                    .await?;
                } else {
                    // Schedule retry; sqlx-side `now() + interval` not needed
                    // since chrono can give us the exact ts.
                    let next = Utc::now() + chrono::Duration::from_std(backoff_for(new_attempts))
                        .unwrap_or_else(|_| chrono::Duration::hours(1));
                    sqlx::query(
                        "UPDATE notifications.outbox
                         SET state = 'pending',
                             attempts = $2,
                             last_error = $3,
                             next_attempt_at = $4
                         WHERE id = $1",
                    )
                    .bind(id)
                    .bind(new_attempts)
                    .bind(&err)
                    .bind(next)
                    .execute(&self.pool)
                    .await?;
                }
            }
        }
        Ok(())
    }

    /// Run forever, polling every `poll_interval`. Exits when `shutdown`
    /// resolves. Errors during a cycle are logged and the loop continues.
    pub async fn run_forever(
        self,
        poll_interval: Duration,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {
                    if let Err(err) = self.process_pending().await {
                        tracing::error!(?err, "notification worker cycle failed");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("notification worker shutting down");
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn html_escape_handles_quotes_and_angle_brackets() {
        assert_eq!(html_escape("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("hello world", 5), "hello");
        assert_eq!(truncate("short", 50), "short");
        // multibyte char — must not slice mid-utf8
        let s = "héllo";
        let t = truncate(s, 2);
        assert!(t == "hé" || t.is_empty() || t == "h"); // any boundary-respecting prefix
        assert!(s.is_char_boundary(t.len()));
    }

    #[test]
    fn backoff_increases_with_attempts() {
        assert!(backoff_for(1) < backoff_for(2));
        assert!(backoff_for(2) < backoff_for(3));
        assert!(backoff_for(5) < backoff_for(6));
        // Caps somewhere reasonable.
        assert!(backoff_for(99) <= Duration::from_secs(48 * 60 * 60));
    }

    #[test]
    fn invitation_renders_with_role_and_url() {
        let r = Notification::Invitation {
            recipient_email: "alice@example.com".into(),
            inviter_display_name: "Bob".into(),
            accept_url: "https://hearth.example.com/invite/abc".into(),
            expires_at: DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap(),
            instance_role: InstanceRole::Admin,
            invitation_id: Uuid::nil(),
        }
        .render();
        assert!(matches!(r.kind, OutboxKind::Invitation));
        assert!(r.subject.contains("Bob"));
        assert!(r.body_text.contains("Admin"));
        assert!(r.body_text.contains("https://hearth.example.com/invite/abc"));
        assert!(r.body_html.contains("Admin"));
        assert!(r.body_html.contains("https://hearth.example.com/invite/abc"));
    }

    #[test]
    fn invitation_html_escapes_inviter_name() {
        let r = Notification::Invitation {
            recipient_email: "a@b.c".into(),
            inviter_display_name: "<script>alert(1)</script>".into(),
            accept_url: "https://x.test/".into(),
            expires_at: Utc::now(),
            instance_role: InstanceRole::Member,
            invitation_id: Uuid::nil(),
        }
        .render();
        assert!(!r.body_html.contains("<script>"));
        assert!(r.body_html.contains("&lt;script&gt;"));
    }
}
