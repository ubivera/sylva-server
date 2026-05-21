use identity::{InstanceRole, User, UserLifecycle};
use maud::{DOCTYPE, Markup, html};

/// Per-request context for authenticated chrome. Borrowed pointers so
/// handlers can pass references straight from `AppState` + the
/// authenticated user without cloning.
pub struct ChromeContext<'a> {
    pub instance_name: &'a str,
    pub user: &'a User,
    /// CSRF token for this session — derived via
    /// [`hearth::csrf::compute_token`]. Embed in every state-changing
    /// form via [`csrf_input`].
    pub csrf_token: &'a str,
}

/// Render the hidden `csrf_token` input for a form. Every state-changing
/// `<form method="post">` in the authed UI must include this; the route
/// handler then validates via `hearth::csrf::verify_token`.
pub fn csrf_input(token: &str) -> Markup {
    html! {
        input type="hidden" name="csrf_token" value=(token);
    }
}

/// Identifier for which nav entry should render as "current". The chrome
/// uses this to apply an `active` class to the matching link.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PageId {
    Profile,
    Users,
}

// ────────────────────────────────────────────────────────────────────────
// Public shell (login, error, install wizard)
// ────────────────────────────────────────────────────────────────────────

/// Minimal page shell with no chrome: used for routes that should not
/// expose any navigation (login page, error pages). Centered content,
/// brand wordmark at the top, footer with version.
pub fn shell_public(title: &str, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " · Hearth" }
                link rel="stylesheet" href="/assets/css/app.css";
                script src="/assets/vendor/htmx.min.js" defer {}
            }
            body class="public" {
                main class="narrow" {
                    p class="wordmark" { "Sylva Hearth" }
                    (content)
                }
                footer class="site" {
                    code { (env!("CARGO_PKG_VERSION")) }
                }
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// App shell (authenticated pages with left-nav chrome)
// ────────────────────────────────────────────────────────────────────────

/// Authenticated chrome: single-column left nav containing brand, search
/// trigger, page navigation, and the user card at the bottom. Main page
/// content fills the remaining width.
///
/// The search trigger is decorative for now (no modal wired up) — see
/// `hearth-web.md` for the follow-up scope that adds it.
pub fn shell_app(
    ctx: &ChromeContext,
    title: &str,
    current: PageId,
    content: Markup,
) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " · " (ctx.instance_name) }
                link rel="stylesheet" href="/assets/css/app.css";
                script src="/assets/vendor/htmx.min.js" defer {}
            }
            body class="app" {
                (sidebar(ctx, current))
                main class="app-main" {
                    h1 { (title) }
                    (content)
                }
                // Wire up [data-open-dialog] / [data-close-dialog] without
                // pulling in a framework. Vanilla, ~10 lines, executes on
                // every authed page (cheap when no dialogs are present).
                script {
                    (maud::PreEscaped(DIALOG_JS))
                }
            }
        }
    }
}

const DIALOG_JS: &str = r#"
document.addEventListener('click', function(e) {
    var openId = e.target.closest('[data-open-dialog]');
    if (openId) {
        e.preventDefault();
        var d = document.getElementById(openId.getAttribute('data-open-dialog'));
        if (d && typeof d.showModal === 'function') d.showModal();
        return;
    }
    var closeBtn = e.target.closest('[data-close-dialog]');
    if (closeBtn) {
        e.preventDefault();
        var dlg = closeBtn.closest('dialog');
        if (dlg && typeof dlg.close === 'function') dlg.close();
    }
});
"#;

fn sidebar(ctx: &ChromeContext, current: PageId) -> Markup {
    let is_admin = is_at_least_admin(ctx.user.instance_role);
    html! {
        aside class="sidebar" {
            div class="brand" {
                a href="/" {
                    span class="brand-prefix" { "Sylva" }
                    span class="brand-sep" { " · " }
                    span class="brand-instance" { (ctx.instance_name) }
                }
            }

            // Decorative search trigger. Clickable but currently inert —
            // the modal is a follow-up checkpoint. Cmd-K hint included so
            // when the modal lands users already know the shortcut.
            button class="search-trigger" type="button"
                   aria-label="Search (coming soon)" disabled {
                span class="search-icon" { "🔍" }
                span class="search-label" { "Search…" }
                span class="search-shortcut" { "⌘K" }
            }

            nav class="nav-links" {
                (nav_link("/me", "Profile", current == PageId::Profile))
                @if is_admin {
                    (nav_link("/users", "Users", current == PageId::Users))
                }
            }

            (user_card(ctx))
        }
    }
}

fn is_at_least_admin(role: InstanceRole) -> bool {
    matches!(role, InstanceRole::Admin | InstanceRole::Owner)
}

fn nav_link(href: &str, label: &str, active: bool) -> Markup {
    let class = if active { "nav-link active" } else { "nav-link" };
    html! {
        a class=(class) href=(href) { (label) }
    }
}

fn user_card(ctx: &ChromeContext) -> Markup {
    let user = ctx.user;
    let initial = display_initial(&user.display_name);
    let color = avatar_color(&user.id.0);
    let lifecycle_note: Option<&'static str> = match user.lifecycle {
        UserLifecycle::Active => None,
        UserLifecycle::Deactivated => Some("Account deactivated"),
        UserLifecycle::PendingInvite => Some("Pending invitation"),
        UserLifecycle::SoftDeleted => Some("Account deleted"),
        UserLifecycle::HardDeleted => Some("Account purged"),
    };

    html! {
        details class="user-card" {
            summary class="user-card-summary" {
                span class="avatar" style=(format!("background:{color}")) {
                    (initial)
                }
                span class="user-card-text" {
                    span class="user-name" { (user.display_name) }
                    span class="user-email" { (user.email) }
                }
            }
            div class="user-card-menu" {
                div class="user-card-role" {
                    span class=(role_class(user.instance_role)) {
                        (role_label(user.instance_role))
                    }
                    @if let Some(note) = lifecycle_note {
                        span class="user-card-note" { (note) }
                    }
                }
                a class="user-card-action" href="/me" { "Profile" }
                form method="post" action="/logout" class="user-card-action-form" {
                    (csrf_input(ctx.csrf_token))
                    button type="submit" class="user-card-signout" { "Sign out" }
                }
            }
        }
    }
}

fn display_initial(name: &str) -> char {
    name.chars()
        .next()
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or('?')
}

fn role_class(role: InstanceRole) -> &'static str {
    match role {
        InstanceRole::Owner => "role-badge role-owner",
        InstanceRole::Admin => "role-badge role-admin",
        InstanceRole::User => "role-badge role-user",
    }
}

fn role_label(role: InstanceRole) -> &'static str {
    match role {
        InstanceRole::Owner => "Owner",
        InstanceRole::Admin => "Admin",
        InstanceRole::User => "User",
    }
}

/// Compact status pill text + CSS class for the users table. The hard/soft
/// deleted arms are reachable in principle (e.g. a future view that opts
/// into them) but `UserRepository::list_all` filters them out today.
fn lifecycle_badge(lifecycle: UserLifecycle) -> (&'static str, &'static str) {
    match lifecycle {
        UserLifecycle::Active => ("status-badge status-active", "Active"),
        UserLifecycle::PendingInvite => ("status-badge status-pending", "Pending"),
        UserLifecycle::Deactivated => ("status-badge status-deactivated", "Deactivated"),
        UserLifecycle::SoftDeleted => ("status-badge status-deleted", "Deleted"),
        UserLifecycle::HardDeleted => ("status-badge status-deleted", "Purged"),
    }
}

/// Pick a stable accent color for an avatar from the user id's first
/// byte. Eight options chosen to be visually distinct on both light and
/// dark backgrounds.
fn avatar_color(user_id: &uuid::Uuid) -> &'static str {
    const COLORS: [&str; 8] = [
        "#1e6feb", "#e67e22", "#8e44ad", "#27ae60",
        "#c0392b", "#16a085", "#d35400", "#2980b9",
    ];
    let idx = (user_id.as_bytes()[0] as usize) % COLORS.len();
    COLORS[idx]
}

// ────────────────────────────────────────────────────────────────────────
// Pages
// ────────────────────────────────────────────────────────────────────────

/// `GET /login` page. `error` is rendered above the form when present
/// (e.g. after a failed credential submission). No left-nav chrome.
pub fn login_page(error: Option<&str>) -> Markup {
    let content = html! {
        h1 { "Sign in" }
        div class="card" {
            form method="post" action="/login" {
                @if let Some(msg) = error {
                    p class="error" { (msg) }
                }
                div class="field" {
                    label for="email" { "Email" }
                    input type="email" name="email" id="email" required
                          autocomplete="username" autofocus;
                }
                div class="field" {
                    label for="password" { "Password" }
                    input type="password" name="password" id="password" required
                          autocomplete="current-password";
                }
                button type="submit" { "Sign in" }
            }
        }
    };
    shell_public("Sign in", content)
}

/// `GET /me` page — the authenticated user's profile.
pub fn me_page(ctx: &ChromeContext) -> Markup {
    let user = ctx.user;
    let lifecycle_label = match user.lifecycle {
        UserLifecycle::Active => "Active",
        UserLifecycle::Deactivated => "Deactivated",
        UserLifecycle::PendingInvite => "Pending invitation",
        UserLifecycle::SoftDeleted => "Deleted",
        UserLifecycle::HardDeleted => "Purged",
    };
    let content = html! {
        div class="card" {
            dl class="meta" {
                dt { "Email" }   dd { (user.email) }
                dt { "Role" }    dd { (role_label(user.instance_role)) }
                dt { "Status" }  dd { (lifecycle_label) }
                @if let Some(locale) = &user.locale {
                    dt { "Locale" } dd { (locale) }
                }
            }
        }
    };
    shell_app(ctx, "Your account", PageId::Profile, content)
}

/// Banner inputs surfaced from `?action=...&target=...` (success) or
/// `?error=...` (failure) query params after a row-action redirect.
pub struct UsersBanner<'a> {
    pub action: Option<&'a str>,
    pub target: Option<&'a str>,
    pub error: Option<&'a str>,
}

/// `GET /users` page — admin-only directory of every non-purged account.
/// Renders as a table; soft/hard-deleted users are filtered out by
/// [`identity::UserRepository::list_all`]. Each row carries a kebab
/// (`<details>`) menu whose contents depend on the viewer's role and the
/// target's lifecycle (see [`available_actions`]).
pub fn users_page(ctx: &ChromeContext, users: &[User], banner: UsersBanner<'_>) -> Markup {
    let content = html! {
        (render_banner(&banner))
        @if users.is_empty() {
            div class="card" {
                p class="muted" { "No users yet." }
            }
        } @else {
            div class="card users-card" {
                table class="users-table" {
                    thead {
                        tr {
                            th { "User" }
                            th { "Role" }
                            th { "Status" }
                            th class="col-date" { "Joined" }
                            th class="col-actions" aria-label="Actions" { "" }
                        }
                    }
                    tbody {
                        @for u in users {
                            (user_row(ctx.user, u, ctx.csrf_token))
                        }
                    }
                }
            }
        }
    };
    shell_app(ctx, "Users", PageId::Users, content)
}

fn user_row(viewer: &User, target: &User, csrf_token: &str) -> Markup {
    let is_self = viewer.id == target.id;
    let initial = display_initial(&target.display_name);
    let color = avatar_color(&target.id.0);
    let (status_class, status_text) = lifecycle_badge(target.lifecycle);
    let joined = target.created_at.format("%Y-%m-%d").to_string();
    let actions = available_actions(
        viewer.instance_role,
        target.instance_role,
        target.lifecycle,
        is_self,
    );

    html! {
        tr class="user-row" {
            td class="user-row-cell" {
                div class="user-row-id" {
                    span class="avatar avatar-sm" style=(format!("background:{color}")) {
                        (initial)
                    }
                    div class="user-row-text" {
                        span class="user-name" {
                            (target.display_name)
                            @if is_self {
                                span class="row-self-tag" { "you" }
                            }
                        }
                        span class="user-email" { (target.email) }
                    }
                }
            }
            td { span class=(role_class(target.instance_role)) { (role_label(target.instance_role)) } }
            td { span class=(status_class) { (status_text) } }
            td class="col-date" { (joined) }
            td class="col-actions" {
                @if !actions.is_empty() {
                    (row_actions_kebab(target, csrf_token, &actions))
                }
            }
        }
    }
}

/// Available row actions for the given viewer/target combination.
/// Mirrors the authz rules in `admin_logic::resolve_lifecycle_target` +
/// the lifecycle-state gates inside each `perform_*`; the UI just hides
/// what the API would refuse so users don't see dead-end buttons.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RowAction {
    Deactivate,
    Reactivate,
    ChangeRole,
    Delete,
    Purge,
}

fn available_actions(
    viewer: InstanceRole,
    target_role: InstanceRole,
    target_lifecycle: UserLifecycle,
    is_self: bool,
) -> Vec<RowAction> {
    if is_self {
        return Vec::new();
    }
    // Admin can only act on Users (strict outrank). Owner can act on
    // anyone; Owner-on-Owner ops route through the pending flow at the
    // backend, but the UI surface is identical.
    let can_act = match viewer {
        InstanceRole::User => false,
        InstanceRole::Admin => matches!(target_role, InstanceRole::User),
        InstanceRole::Owner => true,
    };
    if !can_act {
        return Vec::new();
    }
    // PendingInvite users can't be acted on at all this round — the API
    // returns `not_active` for them. Future "Resend invite" / "Revoke
    // invite" actions live in the invitations checkpoint.
    if !matches!(
        target_lifecycle,
        UserLifecycle::Active | UserLifecycle::Deactivated
    ) {
        return Vec::new();
    }

    let mut actions = Vec::with_capacity(4);
    match target_lifecycle {
        UserLifecycle::Active => actions.push(RowAction::Deactivate),
        UserLifecycle::Deactivated => actions.push(RowAction::Reactivate),
        _ => {}
    }
    if matches!(viewer, InstanceRole::Owner) {
        actions.push(RowAction::ChangeRole);
    }
    actions.push(RowAction::Delete);
    actions.push(RowAction::Purge);
    actions
}

fn row_actions_kebab(target: &User, csrf_token: &str, actions: &[RowAction]) -> Markup {
    let id = target.id.0;
    html! {
        details class="row-actions" {
            summary class="row-actions-trigger" aria-label="Row actions" {
                span aria-hidden="true" { "⋯" }
            }
            div class="row-actions-menu" {
                @for action in actions {
                    (render_action_item(*action, target, csrf_token))
                }
            }
        }
        // Confirmation / role-change dialogs live as siblings of the
        // <details> so showModal() floats them over the page regardless
        // of whether the kebab is open. Only the dialog-opening actions
        // (Delete / Purge / Change Role) render a dialog; Deactivate /
        // Reactivate submit straight from the menu.
        @for action in actions {
            @if action_uses_dialog(*action) {
                (render_action_dialog(*action, target, csrf_token, id))
            }
        }
    }
}

fn action_uses_dialog(action: RowAction) -> bool {
    matches!(
        action,
        RowAction::ChangeRole | RowAction::Delete | RowAction::Purge
    )
}

fn render_action_item(action: RowAction, target: &User, csrf_token: &str) -> Markup {
    let id = target.id.0;
    match action {
        RowAction::Deactivate => html! {
            form method="post" action=(format!("/users/{id}/deactivate")) class="row-action-form" {
                (csrf_input(csrf_token))
                button type="submit" class="row-action-item" { "Deactivate" }
            }
        },
        RowAction::Reactivate => html! {
            form method="post" action=(format!("/users/{id}/reactivate")) class="row-action-form" {
                (csrf_input(csrf_token))
                button type="submit" class="row-action-item" { "Reactivate" }
            }
        },
        RowAction::ChangeRole => html! {
            button type="button" class="row-action-item"
                   data-open-dialog=(format!("dlg-role-{id}")) {
                "Change role…"
            }
        },
        RowAction::Delete => html! {
            button type="button" class="row-action-item row-action-danger"
                   data-open-dialog=(format!("dlg-delete-{id}")) {
                "Delete…"
            }
        },
        RowAction::Purge => html! {
            button type="button" class="row-action-item row-action-danger"
                   data-open-dialog=(format!("dlg-purge-{id}")) {
                "Purge…"
            }
        },
    }
}

fn render_action_dialog(action: RowAction, target: &User, csrf_token: &str, id: uuid::Uuid) -> Markup {
    let name = &target.display_name;
    match action {
        RowAction::ChangeRole => html! {
            dialog id=(format!("dlg-role-{id}")) class="action-dialog" {
                form method="post" action=(format!("/users/{id}/role")) {
                    h2 { "Change role for " (name) }
                    p class="dialog-note" {
                        "If the target is an Owner, a 72-hour veto window "
                        "begins instead of applying immediately."
                    }
                    label class="field" {
                        span { "New role" }
                        select name="role" required {
                            @let current = target.instance_role;
                            option value="user"  selected[current == InstanceRole::User]  { "User" }
                            option value="admin" selected[current == InstanceRole::Admin] { "Admin" }
                            option value="owner" selected[current == InstanceRole::Owner] { "Owner" }
                        }
                    }
                    (csrf_input(csrf_token))
                    div class="dialog-actions" {
                        button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                        button type="submit" { "Apply" }
                    }
                }
            }
        },
        RowAction::Delete => html! {
            dialog id=(format!("dlg-delete-{id}")) class="action-dialog" {
                form method="post" action=(format!("/users/{id}/delete")) {
                    h2 { "Delete " (name) "?" }
                    p {
                        "Revokes all sessions, removes their credentials, and "
                        "redacts their email. The account row is preserved so "
                        "their authored content keeps its byline."
                    }
                    p class="dialog-note" {
                        "If the target is an Owner, a 72-hour veto window begins "
                        "instead of applying immediately."
                    }
                    (csrf_input(csrf_token))
                    div class="dialog-actions" {
                        button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                        button type="submit" class="btn-danger" { "Delete" }
                    }
                }
            }
        },
        RowAction::Purge => html! {
            dialog id=(format!("dlg-purge-{id}")) class="action-dialog" {
                form method="post" action=(format!("/users/{id}/purge")) {
                    h2 { "Purge " (name) "?" }
                    p {
                        "Same row-level effect as delete today; once the apps "
                        "platform lands, this also drops every piece of their "
                        "content regardless of collaborators."
                    }
                    p class="dialog-note" {
                        "If the target is an Owner, a 72-hour veto window begins "
                        "instead of applying immediately."
                    }
                    (csrf_input(csrf_token))
                    div class="dialog-actions" {
                        button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                        button type="submit" class="btn-danger" { "Purge" }
                    }
                }
            }
        },
        _ => html! {},
    }
}

// ────────────────────────────────────────────────────────────────────────
// Banners
// ────────────────────────────────────────────────────────────────────────

fn render_banner(banner: &UsersBanner<'_>) -> Markup {
    if let Some(error_code) = banner.error {
        return error_banner(error_code);
    }
    if let Some(action) = banner.action {
        return action_banner(action, banner.target);
    }
    html! {}
}

fn action_banner(action: &str, target: Option<&str>) -> Markup {
    let name = target.unwrap_or("This user");
    let msg = match action {
        "deactivated" => format!("{name} has been deactivated."),
        "reactivated" => format!("{name} has been reactivated."),
        "deleted" => format!("{name}'s account has been deleted."),
        "purged" => format!("{name}'s account has been purged."),
        "role_changed" => format!("{name}'s role has been updated."),
        "pending_deactivate" => "A 72-hour veto window has begun for the requested deactivation. The target Owner and any other Owner can cancel during that time.".to_string(),
        "pending_delete" => "A 72-hour veto window has begun for the requested deletion.".to_string(),
        "pending_purge" => "A 72-hour veto window has begun for the requested purge.".to_string(),
        "pending_role_change" => "A 72-hour veto window has begun for the requested role change.".to_string(),
        _ => return html! {},
    };
    html! {
        div class="banner banner-success" role="status" { (msg) }
    }
}

fn error_banner(error: &str) -> Markup {
    let msg = match error {
        "cannot_target_self" => "You can't target yourself.",
        "cannot_target_peer_or_higher" => "You can't target a peer or higher role.",
        "already_deactivated" => "That user is already deactivated.",
        "already_active" => "That user is already active.",
        "already_in_role" => "That user is already in that role.",
        "user_not_found" => "User not found.",
        "not_active" => "That user is in pending invite state and can't be acted on.",
        "not_deactivated" => "That user isn't deactivated.",
        "pending_action_exists" => "An action is already pending against that user.",
        "forbidden" => "Only Owners can change roles.",
        "invalid_recovery_code" => "Invalid recovery code.",
        _ => "Something went wrong.",
    };
    html! {
        div class="banner banner-error" role="alert" { (msg) }
    }
}

/// Generic error page rendered when something goes very wrong. Uses the
/// public shell because errors may render before/without an authenticated
/// session.
pub fn error_page(status: u16, message: &str) -> Markup {
    let content = html! {
        h1 { (status) " · " (message) }
        p { a href="/" { "Back to home" } }
    };
    shell_public("Error", content)
}
