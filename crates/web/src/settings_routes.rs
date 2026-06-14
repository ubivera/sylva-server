//! Owner-only Settings page + handlers.
//!
//! `GET /settings` renders the page (Owner gate, defense-in-depth alongside
//! the sidebar `is_owner` gate). The three POSTs each re-check the Owner role:
//!
//! * `/settings/identity` — display-name override. CSRF only.
//! * `/settings/notifications` — mode + SMTP. CSRF **+ `require_sudo`** (it
//!   carries credentials); driven from the page via `REAUTH_CHAIN_JS`.
//! * `/settings/notifications/test` — send a test email via the live notifier.
//!
//! The persist + audit + live-swap happen in [`hearth::settings_logic`]; these
//! handlers validate input and translate the outcome into a toast + redirect.

use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use hearth::{app::AppState, csrf, settings_logic::TestEmailOutcome};
use identity::InstanceRole;
use serde::Deserialize;

use crate::{
    admin_routes::{is_htmx, redirect_or_hx_redirect, with_toast},
    routes::{
        BrowserAuth, account_closed_response, check_csrf_token, error_response,
        pending_count_for, require_critical_sudo, require_sudo,
    },
    views,
};

/// `GET /settings` — Owners-only instance configuration page.
pub async fn settings_page(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
) -> Response {
    if auth.user.instance_role != InstanceRole::Owner {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let eff =
        match hearth::instance::effective(&state.db, &state.env_config, &state.secret_key).await {
            Ok(e) => e,
            Err(err) => {
                tracing::error!(?err, "computing effective config for /settings");
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
            }
        };
    let pw_set = hearth::instance::smtp_password_is_set(&state.db)
        .await
        .unwrap_or(false);
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let pending_count = pending_count_for(&state, auth.user.instance_role).await;
    let ctx = views::ChromeContext {
        instance_name: state.instance_name.load_full(),
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count,
    };
    Html(views::settings_page(&ctx, &eff.notifications, pw_set).into_string()).into_response()
}

#[derive(Deserialize)]
pub struct SettingsIdentityForm {
    pub csrf_token: String,
    #[serde(default)]
    pub instance_name: String,
}

/// `POST /settings/identity` — set (or clear) the instance display name.
pub async fn settings_identity_submit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Form(form): Form<SettingsIdentityForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    if auth.user.instance_role != InstanceRole::Owner {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let htmx = is_htmx(&headers);

    let trimmed = form.instance_name.trim();
    if trimmed.chars().count() > 64 {
        return settings_error(htmx, "Instance name is too long (max 64 characters).");
    }
    // An empty value clears the override (reverts to the configured default).
    let name = (!trimmed.is_empty()).then_some(trimmed);

    let actor = audit::Actor {
        user_id: auth.user.id,
        display_name: auth.user.display_name.clone(),
    };
    match hearth::settings_logic::apply_instance_name(&state, &actor, name).await {
        Ok(()) => settings_success(htmx, "Saved", "Instance name updated."),
        Err(err) => {
            tracing::error!(?err, "applying instance name");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

#[derive(Deserialize)]
pub struct SettingsNotificationsForm {
    pub csrf_token: String,
    pub mode: String,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: String,
    #[serde(default)]
    pub smtp_tls: String,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub smtp_from_email: String,
    #[serde(default)]
    pub smtp_from_name: String,
}

/// `POST /settings/notifications` — set the delivery mode + SMTP config.
/// Reauth-gated: it persists credentials, so a fresh sudo grant is required
/// (minted by the `REAUTH_CHAIN_JS` step-up that fronts the Save button).
pub async fn settings_notifications_submit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Form(form): Form<SettingsNotificationsForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    if auth.user.instance_role != InstanceRole::Owner {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let htmx = is_htmx(&headers);

    // Step-up gate — saving outbound-mail credentials demands a fresh re-auth.
    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
    }

    let mode = form.mode.trim();
    if !matches!(mode, "disabled" | "log" | "smtp") {
        return settings_error(htmx, "Choose a valid delivery mode.");
    }

    let smtp = if mode == "smtp" {
        // Reuse the env-config validation rules (host/username/from required,
        // valid TLS, port in range). Password may be blank on update (keeps
        // the stored secret) but is required on first-time setup.
        let host = form.smtp_host.trim().to_string();
        let username = form.smtp_username.trim().to_string();
        let from_email = form.smtp_from_email.trim().to_string();
        let tls = form.smtp_tls.trim().to_string();
        let from_name = {
            let n = form.smtp_from_name.trim().to_string();
            (!n.is_empty()).then_some(n)
        };
        // Passwords are never trimmed — whitespace is significant.
        let password = (!form.smtp_password.is_empty()).then_some(form.smtp_password.clone());

        if host.is_empty() || username.is_empty() || from_email.is_empty() {
            return settings_error(htmx, "Fill in the SMTP host, username, and from-address.");
        }
        if !matches!(tls.as_str(), "starttls" | "implicit" | "none") {
            return settings_error(htmx, "Choose a valid encryption mode.");
        }
        let port: i32 = match form.smtp_port.trim().parse::<u16>() {
            Ok(p) if p > 0 => i32::from(p),
            _ => return settings_error(htmx, "Port must be a number between 1 and 65535."),
        };
        if password.is_none()
            && !hearth::instance::smtp_password_is_set(&state.db)
                .await
                .unwrap_or(false)
        {
            return settings_error(htmx, "Set an SMTP password — none is stored yet.");
        }

        Some(hearth::instance::SmtpInput {
            host,
            port,
            tls,
            username,
            from_email,
            from_name,
            password,
        })
    } else {
        None
    };

    let actor = audit::Actor {
        user_id: auth.user.id,
        display_name: auth.user.display_name.clone(),
    };
    match hearth::settings_logic::apply_notifications(&state, &actor, mode, smtp).await {
        Ok(()) => settings_success(htmx, "Saved", "Email settings updated."),
        Err(err) => {
            tracing::error!(?err, "applying notifications config");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

#[derive(Deserialize)]
pub struct SettingsTestForm {
    pub csrf_token: String,
}

/// `POST /settings/notifications/test` — send a test email to the Owner's own
/// address via the **saved/live** notifier, reporting the outcome inline.
pub async fn settings_test_email(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Form(form): Form<SettingsTestForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    if auth.user.instance_role != InstanceRole::Owner {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let htmx = is_htmx(&headers);
    let to = auth.user.email.clone();

    match hearth::settings_logic::send_test_email(&state, &to).await {
        TestEmailOutcome::Sent => {
            settings_success(htmx, "Test sent", &format!("Sent a test email to {to}."))
        }
        TestEmailOutcome::Disabled => {
            let toast = views::Toast::new(
                views::ToastKind::Info,
                "Notifications disabled",
                "Set the delivery mode to Log or SMTP, save, then try again.",
            );
            with_toast(redirect_or_hx_redirect("/settings", htmx), Some(toast))
        }
        TestEmailOutcome::Failed(e) => {
            settings_error(htmx, &format!("Test email failed: {e}"))
        }
    }
}

/// `GET /modals/settings/shutdown` — fetch the Owner's "close the whole
/// server" confirm dialog on demand (mirrors the account-close modal).
pub async fn settings_shutdown_modal(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
) -> Response {
    if auth.user.instance_role != InstanceRole::Owner {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let ctx = views::ChromeContext {
        instance_name: state.instance_name.load_full(),
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count: None,
    };
    Html(views::settings_shutdown_modal(&ctx).into_string()).into_response()
}

#[derive(Deserialize)]
pub struct SettingsShutdownForm {
    pub csrf_token: String,
}

/// `POST /settings/shutdown` — Owner force-closes the entire instance: scorch
/// every data table + flip the closed flag, then end the session and redirect
/// to the now-closed page. Always gated by a fresh **critical** re-auth (the
/// most destructive action there is) — the same grant a self-delete requires.
pub async fn settings_shutdown_submit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Form(form): Form<SettingsShutdownForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    if auth.user.instance_role != InstanceRole::Owner {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    if let Err(resp) = require_critical_sudo(&state, &headers, auth.user.id) {
        return resp;
    }
    if let Err(err) = hearth::settings_logic::force_close_instance(&state).await {
        tracing::error!(?err, "force-closing instance");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
    }
    account_closed_response(&state, "/")
}

/// Redirect back to `/settings` with a green success toast.
fn settings_success(htmx: bool, title: &str, message: &str) -> Response {
    let toast = views::Toast::new(views::ToastKind::Success, title, message);
    with_toast(redirect_or_hx_redirect("/settings", htmx), Some(toast))
}

/// Redirect back to `/settings` with a red error toast.
fn settings_error(htmx: bool, message: &str) -> Response {
    let toast = views::Toast::new(views::ToastKind::Error, "Couldn't save", message);
    with_toast(redirect_or_hx_redirect("/settings", htmx), Some(toast))
}
