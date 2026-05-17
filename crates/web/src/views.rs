use maud::{DOCTYPE, Markup, html};

/// Standard page shell — doctype, head, header, main, footer. Inner
/// `content` is whatever the route renders.
pub fn shell(title: &str, narrow: bool, content: Markup) -> Markup {
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
            body {
                header class="site" {
                    div class="inner" {
                        a class="brand" href="/" { "Sylva Hearth" }
                    }
                }
                main class=(if narrow { "narrow" } else { "" }) {
                    (content)
                }
                footer class="site" {
                    "Sylva Hearth · "
                    code { (env!("CARGO_PKG_VERSION")) }
                }
            }
        }
    }
}

/// `GET /login` page. `error` is rendered above the form when present
/// (e.g. after a failed credential submission).
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
    shell("Sign in", true, content)
}

/// `GET /me` page — the authenticated user's profile + sign-out.
pub fn me_page(user: &identity::User) -> Markup {
    let role_label = match user.instance_role {
        identity::InstanceRole::Owner => "Owner",
        identity::InstanceRole::Admin => "Admin",
        identity::InstanceRole::User => "User",
    };
    let lifecycle_label = match user.lifecycle {
        identity::UserLifecycle::Active => "Active",
        identity::UserLifecycle::Deactivated => "Deactivated",
        identity::UserLifecycle::PendingInvite => "Pending invitation",
        identity::UserLifecycle::SoftDeleted => "Deleted",
        identity::UserLifecycle::HardDeleted => "Purged",
    };

    let content = html! {
        h1 { "Hi, " (user.display_name) }
        div class="card" {
            dl class="meta" {
                dt { "Email" }     dd { (user.email) }
                dt { "Role" }      dd { (role_label) }
                dt { "Status" }    dd { (lifecycle_label) }
                @if let Some(locale) = &user.locale {
                    dt { "Locale" }  dd { (locale) }
                }
            }
            form method="post" action="/logout" style="margin-top: 1.5rem;" {
                button type="submit" class="secondary" { "Sign out" }
            }
        }
    };
    shell("Your account", false, content)
}

/// Generic error page rendered when something goes very wrong.
pub fn error_page(status: u16, message: &str) -> Markup {
    let content = html! {
        h1 { (status) " · " (message) }
        p { a href="/" { "Back to home" } }
    };
    shell("Error", true, content)
}
