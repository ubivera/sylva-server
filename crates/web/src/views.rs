use identity::{InstanceRole, User, UserLifecycle};
use maud::{DOCTYPE, Markup, html};

/// Per-request context for authenticated chrome. Borrowed pointers so
/// handlers can pass references straight from `AppState` + the
/// authenticated user without cloning.
pub struct ChromeContext<'a> {
    pub instance_name: &'a str,
    pub user: &'a User,
}

/// Identifier for which nav entry should render as "current". The chrome
/// uses this to apply an `active` class to the matching link.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PageId {
    Profile,
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
            }
        }
    }
}

fn sidebar(ctx: &ChromeContext, current: PageId) -> Markup {
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
            }

            (user_card(ctx.user))
        }
    }
}

fn nav_link(href: &str, label: &str, active: bool) -> Markup {
    let class = if active { "nav-link active" } else { "nav-link" };
    html! {
        a class=(class) href=(href) { (label) }
    }
}

fn user_card(user: &User) -> Markup {
    let initial = user
        .display_name
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or('?');
    let color = avatar_color(&user.id.0);
    let role_class = match user.instance_role {
        InstanceRole::Owner => "role-badge role-owner",
        InstanceRole::Admin => "role-badge role-admin",
        InstanceRole::User => "role-badge role-user",
    };
    let role_label = match user.instance_role {
        InstanceRole::Owner => "Owner",
        InstanceRole::Admin => "Admin",
        InstanceRole::User => "User",
    };
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
                    span class=(role_class) { (role_label) }
                    @if let Some(note) = lifecycle_note {
                        span class="user-card-note" { (note) }
                    }
                }
                a class="user-card-action" href="/me" { "Profile" }
                form method="post" action="/logout" class="user-card-action-form" {
                    button type="submit" class="user-card-signout" { "Sign out" }
                }
            }
        }
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
    let role_label = match user.instance_role {
        InstanceRole::Owner => "Owner",
        InstanceRole::Admin => "Admin",
        InstanceRole::User => "User",
    };
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
                dt { "Role" }    dd { (role_label) }
                dt { "Status" }  dd { (lifecycle_label) }
                @if let Some(locale) = &user.locale {
                    dt { "Locale" } dd { (locale) }
                }
            }
        }
    };
    shell_app(ctx, "Your account", PageId::Profile, content)
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
