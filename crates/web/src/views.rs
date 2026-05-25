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
    Members,
}

/// Sortable column on `/users`. Default is `Joined` ascending, which
/// matches the historical behavior of `UserRepository::list_all`.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum SortColumn {
    Name,
    Role,
    Status,
    #[default]
    Joined,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum SortDirection {
    #[default]
    Asc,
    Desc,
}

#[derive(Clone, Copy, Default)]
pub struct SortState {
    pub column: SortColumn,
    pub direction: SortDirection,
}

impl SortColumn {
    /// URL token for `?sort=...`.
    pub fn as_str(self) -> &'static str {
        match self {
            SortColumn::Name => "name",
            SortColumn::Role => "role",
            SortColumn::Status => "status",
            SortColumn::Joined => "joined",
        }
    }
}

impl SortDirection {
    /// URL token for `?dir=...`.
    pub fn as_str(self) -> &'static str {
        match self {
            SortDirection::Asc => "asc",
            SortDirection::Desc => "desc",
        }
    }

    pub fn flip(self) -> Self {
        match self {
            SortDirection::Asc => SortDirection::Desc,
            SortDirection::Desc => SortDirection::Asc,
        }
    }
}

/// Allowed page sizes for the Members table. Values outside this list
/// get clamped to `DEFAULT_ROWS_PER_PAGE` by the route handler so the
/// dropdown options round-trip cleanly.
pub const ROWS_PER_PAGE_OPTIONS: &[u32] = &[10, 25, 50, 100];
pub const DEFAULT_ROWS_PER_PAGE: u32 = 10;

/// Pagination state for the Members table. Calculated server-side once
/// the row count is known; threaded through to the view so every link
/// in the pagination bar can target the right page.
#[derive(Clone, Copy)]
pub struct PaginationState {
    pub current_page: u32,
    pub total_pages: u32,
    pub rows_per_page: u32,
    pub total_rows: u32,
}

/// One slot in the pagination number row — either a clickable page
/// number or a non-clickable ellipsis. Width is bounded to ≤7 slots so
/// the bar's footprint stays constant once total_pages ≥ 7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageItem {
    Number(u32),
    Ellipsis,
}

/// Build the page-number sequence per the design spec:
/// * `total ≤ 7`         → every page, no ellipsis
/// * `current ≤ 4`       → `1 2 3 4 5 … last` (right-leaning)
/// * `current ≥ last-3`  → `1 … (last-4..last)` (left-leaning)
/// * otherwise           → `1 … cur-1 cur cur+1 … last` (centered, 3 around)
///
/// Returns exactly 7 items in the three overflow cases.
pub fn page_items(current: u32, total: u32) -> Vec<PageItem> {
    let mut items = Vec::new();
    if total == 0 {
        items.push(PageItem::Number(1));
        return items;
    }
    if total <= 7 {
        for p in 1..=total {
            items.push(PageItem::Number(p));
        }
        return items;
    }
    if current <= 4 {
        for p in 1..=5 {
            items.push(PageItem::Number(p));
        }
        items.push(PageItem::Ellipsis);
        items.push(PageItem::Number(total));
    } else if current >= total - 3 {
        items.push(PageItem::Number(1));
        items.push(PageItem::Ellipsis);
        for p in (total - 4)..=total {
            items.push(PageItem::Number(p));
        }
    } else {
        items.push(PageItem::Number(1));
        items.push(PageItem::Ellipsis);
        items.push(PageItem::Number(current - 1));
        items.push(PageItem::Number(current));
        items.push(PageItem::Number(current + 1));
        items.push(PageItem::Ellipsis);
        items.push(PageItem::Number(total));
    }
    items
}

/// One row in the Members table. Wraps the two underlying row sources
/// (existing members vs. pending invitations) so the handler can
/// combine + paginate them as a single sequence and the view dispatches
/// per-variant.
pub enum MemberRow<'a> {
    Member {
        user: &'a User,
        last_activity: Option<chrono::DateTime<chrono::Utc>>,
    },
    PendingInvite(&'a identity::Invitation),
}

/// Server-side filter for the Members directory. Renders as a dropdown
/// in the toolbar and round-trips via the `?filter=...` query param.
///
/// `All` is the default — same data set as the unfiltered listing
/// (`list_all`: Active + PendingInvite + Deactivated). `Status(Deleted)`
/// is the one filter that *expands* visibility (surfaces SoftDeleted
/// rows that `list_all` hides), via `list_with_lifecycle`.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum MemberFilter {
    #[default]
    All,
    Role(InstanceRole),
    Status(UserLifecycle),
}

impl MemberFilter {
    /// URL token for `?filter=...`. Round-trips with [`Self::from_str`].
    pub fn as_str(self) -> &'static str {
        match self {
            MemberFilter::All => "all",
            MemberFilter::Role(InstanceRole::Owner) => "role:owner",
            MemberFilter::Role(InstanceRole::Admin) => "role:admin",
            MemberFilter::Role(InstanceRole::Member) => "role:member",
            MemberFilter::Status(UserLifecycle::Active) => "status:active",
            MemberFilter::Status(UserLifecycle::PendingInvite) => "status:pending",
            MemberFilter::Status(UserLifecycle::Deactivated) => "status:deactivated",
            MemberFilter::Status(UserLifecycle::SoftDeleted) => "status:deleted",
            // HardDeleted is not surfaced in the UI — treat as "all".
            MemberFilter::Status(UserLifecycle::HardDeleted) => "all",
        }
    }

    /// Parse a `?filter=...` URL token. Unrecognised values fall back
    /// to `All` — same forgiving treatment as the sort params. Named
    /// `parse_token` rather than `from_str` to avoid the inherent-vs-
    /// `FromStr` trait collision clippy warns about.
    pub fn parse_token(s: &str) -> Self {
        match s {
            "role:owner" => MemberFilter::Role(InstanceRole::Owner),
            "role:admin" => MemberFilter::Role(InstanceRole::Admin),
            "role:member" => MemberFilter::Role(InstanceRole::Member),
            "status:active" => MemberFilter::Status(UserLifecycle::Active),
            "status:pending" => MemberFilter::Status(UserLifecycle::PendingInvite),
            "status:deactivated" => MemberFilter::Status(UserLifecycle::Deactivated),
            "status:deleted" => MemberFilter::Status(UserLifecycle::SoftDeleted),
            _ => MemberFilter::All,
        }
    }

    /// Human-readable label, used by the trigger button and menu items.
    pub fn label(self) -> &'static str {
        match self {
            MemberFilter::All => "View all",
            MemberFilter::Role(InstanceRole::Owner) => "Owners",
            MemberFilter::Role(InstanceRole::Admin) => "Admins",
            MemberFilter::Role(InstanceRole::Member) => "Members",
            MemberFilter::Status(UserLifecycle::Active) => "Active",
            MemberFilter::Status(UserLifecycle::PendingInvite) => "Pending invite",
            MemberFilter::Status(UserLifecycle::Deactivated) => "Deactivated",
            MemberFilter::Status(UserLifecycle::SoftDeleted) => "Deleted",
            MemberFilter::Status(UserLifecycle::HardDeleted) => "View all",
        }
    }
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
    shell_app_inner(ctx, title, current, content, /* wide = */ false)
}

/// Like [`shell_app`] but drops the 64rem max-width cap on the main
/// column so the page fills the viewport. Used by the Members table,
/// which is data-dense and benefits from horizontal room. Narrow
/// form-style pages (invite form, profile) keep the default capped
/// width — wider feels uncomfortable for short single-column content.
pub fn shell_app_wide(
    ctx: &ChromeContext,
    title: &str,
    current: PageId,
    content: Markup,
) -> Markup {
    shell_app_inner(ctx, title, current, content, /* wide = */ true)
}

fn shell_app_inner(
    ctx: &ChromeContext,
    title: &str,
    current: PageId,
    content: Markup,
    wide: bool,
) -> Markup {
    let main_class = if wide { "app-main app-main-wide" } else { "app-main" };
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
                main class=(main_class) {
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
                    (nav_link("/members", "Members", current == PageId::Members))
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
        InstanceRole::Member => "role-badge role-member",
    }
}

fn role_label(role: InstanceRole) -> &'static str {
    match role {
        InstanceRole::Owner => "Owner",
        InstanceRole::Admin => "Admin",
        InstanceRole::Member => "Member",
    }
}

/// Small colored dot rendered at the bottom-right of the member avatar,
/// communicating the lifecycle state in-line with the identity. Replaces
/// the dedicated Status column. The dot carries `title` + `aria-label`
/// so the lifecycle label is available on hover and to screen readers
/// even though the column header is gone.
fn avatar_status_dot(lifecycle: UserLifecycle) -> Markup {
    let (variant, label) = match lifecycle {
        UserLifecycle::Active => ("avatar-status-active", "Active"),
        UserLifecycle::PendingInvite => ("avatar-status-pending", "Pending invite"),
        UserLifecycle::Deactivated => ("avatar-status-deactivated", "Deactivated"),
        UserLifecycle::SoftDeleted => ("avatar-status-deleted", "Deleted"),
        UserLifecycle::HardDeleted => ("avatar-status-deleted", "Purged"),
    };
    let class = format!("avatar-status {variant}");
    html! {
        span class=(class) title=(label) aria-label=(label) {}
    }
}

/// "Mar 4, 2025"-style short date. Used for both Joined and Last
/// activity columns. `%-d` is a chrono-specific format token (not
/// strftime) that renders the day without leading zero, so we get
/// "Mar 4" rather than "Mar 04".
fn short_date(ts: chrono::DateTime<chrono::Utc>) -> String {
    ts.format("%b %-d, %Y").to_string()
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
                button type="submit" class="btn" { "Sign in" }
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

// ────────────────────────────────────────────────────────────────────────
// /members/invite — form + result pages
// ────────────────────────────────────────────────────────────────────────

/// `GET /members/invite` (and `POST` on validation failure) — render the
/// invitation form. `prefill_email` carries the caller's previous input
/// back into the form when re-rendering after an error so they don't
/// have to retype.
pub fn members_invite_form_page(
    ctx: &ChromeContext,
    prefill_email: &str,
    selected_role: InstanceRole,
    error: Option<&str>,
) -> Markup {
    let content = html! {
        @if let Some(code) = error {
            (error_banner(code))
        }
        div class="card invite-card" {
            form method="post" action="/members/invite" class="invite-form" {
                p class="invite-intro" {
                    "Sends a one-time acceptance link to the email below. "
                    "The link expires in 7 days. The invitee chooses a "
                    "display name and password when they accept."
                }
                (invite_form_fields(
                    ctx.csrf_token,
                    prefill_email,
                    selected_role,
                    ctx.user.instance_role,
                    /* autofocus_email = */ true,
                    /* id_prefix = */ "page",
                ))
                div class="invite-form-actions" {
                    a class="btn-secondary" href="/members" { "Cancel" }
                    button type="submit" class="btn" { "Send invitation" }
                }
            }
        }
    };
    shell_app(ctx, "Invite member", PageId::Members, content)
}

/// Shared invite form fields — email input + role picker + CSRF token.
/// Used by both the standalone /members/invite page and the modal on
/// /members. `id_prefix` keeps the input ids unique when both forms
/// are rendered on the same page (so `<label for>` resolves to the
/// right one).
///
/// Role picker behavior:
/// * Owner viewers see a segmented control with Member / Admin / Owner.
/// * Non-Owner viewers (Admin) see a hidden input pinning role=member.
///   That mirrors the design ref where "admins can only invite users
///   rank"; the backend still accepts admin-on-admin via the JSON API,
///   so this is a UI-only tightening.
fn invite_form_fields(
    csrf_token: &str,
    prefill_email: &str,
    selected_role: InstanceRole,
    inviter_role: InstanceRole,
    autofocus_email: bool,
    id_prefix: &str,
) -> Markup {
    let email_id = format!("invite-email-{id_prefix}");
    html! {
        div class="field" {
            label for=(email_id) { "Email address" }
            input type="email" name="email" id=(email_id)
                  value=(prefill_email)
                  autocomplete="email" required
                  autofocus[autofocus_email];
        }
        @if matches!(inviter_role, InstanceRole::Owner) {
            div class="field" {
                span class="field-label" { "Role" }
                (role_segmented_control(selected_role, id_prefix))
            }
        } @else {
            // Admin invokers see no choice — backend still validates,
            // but the UI presents one path: a new Member.
            input type="hidden" name="role" value="member";
        }
        (csrf_input(csrf_token))
    }
}

/// Invite-member modal — UUI-style `<dialog>` rendered always on the
/// Members page. The toolbar CTA opens it via `data-open-dialog`;
/// submitting POSTs to /members/invite where the existing handler
/// either renders the one-time URL result page (success) or the
/// standalone form page with an error banner (validation fail).
/// Always-rendered `<dialog>` on /members. The inner `<div>` carries
/// `id="invite-modal-content"` so the form's HTMX target swap stays
/// scoped to the modal body — the dialog itself + open state survive
/// the swap. Initial render shows the form; after a successful POST
/// HTMX swaps in [`invite_modal_content_success`] in place.
fn invite_modal(ctx: &ChromeContext) -> Markup {
    html! {
        dialog id="dlg-invite" class="action-dialog invite-dialog" {
            div id="invite-modal-content" {
                (invite_modal_content_form(ctx, "", InstanceRole::Member, None))
            }
        }
    }
}

/// Inner content of the invite modal in its "form" state. The form is
/// HTMX-enabled: on submit, the server returns either this same
/// helper (with an error banner on validation fail) or
/// [`invite_modal_content_success`] (on success), and HTMX swaps the
/// content in place. Native `action`/`method` are present so the form
/// still works if HTMX isn't loaded — the server falls back to
/// rendering the full standalone form/result page in that case.
pub fn invite_modal_content_form(
    ctx: &ChromeContext,
    prefill_email: &str,
    selected_role: InstanceRole,
    error: Option<&str>,
) -> Markup {
    html! {
        div class="dialog-header" {
            div class="dialog-icon dialog-icon-brand" {
                (user_plus_icon())
            }
            button type="button" class="dialog-close" data-close-dialog
                   aria-label="Close" {
                (close_icon())
            }
        }
        h2 { "Invite a member" }
        p class="dialog-description" {
            "Add a member by email. They'll receive a one-time link to "
            "set up their account."
        }
        @if let Some(code) = error {
            (error_banner(code))
        }
        form method="post" action="/members/invite"
             hx-post="/members/invite"
             hx-target="#invite-modal-content"
             hx-swap="innerHTML" {
            (invite_form_fields(
                ctx.csrf_token,
                prefill_email,
                selected_role,
                ctx.user.instance_role,
                /* autofocus_email = */ false,
                /* id_prefix = */ "modal",
            ))
            div class="dialog-actions" {
                button type="button" class="btn-secondary"
                       data-close-dialog { "Cancel" }
                button type="submit" class="btn" { "Send invitation" }
            }
        }
    }
}

/// Inner content of the invite modal in its "success" state — what
/// HTMX swaps in after a successful POST. Shows the one-time
/// acceptance link + Done / Invite-another buttons. Invite-another
/// uses HTMX to GET the partial form back into the modal, keeping the
/// whole flow on /members without a navigation.
pub fn invite_modal_content_success(
    ctx: &ChromeContext,
    invitee_email: &str,
    invited_role: InstanceRole,
    accept_url: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Markup {
    let expires_label = expires_at.format("%b %-d, %Y %H:%M UTC").to_string();
    let _ = ctx;
    html! {
        div class="dialog-header" {
            div class="dialog-icon dialog-icon-success" {
                (check_circle_icon())
            }
            button type="button" class="dialog-close" data-close-dialog
                   aria-label="Close" {
                (close_icon())
            }
        }
        h2 { "Invitation sent" }
        p class="dialog-description" {
            "Sent to " strong { (invitee_email) } " as "
            span class=(role_class(invited_role)) {
                (role_label(invited_role))
            }
            ". Expires " (expires_label) "."
        }
        div class="invite-link-block" {
            p class="invite-link-label" {
                "Save or share this acceptance link. "
                strong { "It is shown only once." }
                " A copy was also queued to the invitee's email if "
                "notifications are enabled."
            }
            div class="invite-link-row" {
                input type="text" id="invite-url-modal" class="invite-url-input"
                      value=(accept_url) readonly;
                button type="button" class="btn-secondary"
                       data-copy-target="invite-url-modal" { "Copy" }
            }
        }
        div class="dialog-actions" {
            button type="button" class="btn-secondary" data-close-dialog {
                "Done"
            }
            button type="button" class="btn"
                   hx-get="/members/invite"
                   hx-target="#invite-modal-content"
                   hx-swap="innerHTML" {
                "Invite another"
            }
        }
        // Re-bind the clipboard handler — INVITE_COPY_JS is delegated
        // on `document`, so it picks up the swapped-in [data-copy-target]
        // automatically. No re-init needed.
    }
}

/// 24px user-plus icon for the invite modal's feature-icon slot.
fn user_plus_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="22" height="22" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" {}
            circle cx="8.5" cy="7" r="4" {}
            line x1="20" y1="8" x2="20" y2="14" {}
            line x1="23" y1="11" x2="17" y2="11" {}
        }
    }
}

/// 22px check-in-circle icon for modal success state. Used by the
/// invite-sent success view; styled green via `.dialog-icon-success`.
fn check_circle_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="22" height="22" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            circle cx="12" cy="12" r="10" {}
            polyline points="8 12 11 15 16 9" {}
        }
    }
}

/// 16px × icon for the modal's top-right close button.
fn close_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="18" height="18" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            line x1="18" y1="6" x2="6" y2="18" {}
            line x1="6" y1="6" x2="18" y2="18" {}
        }
    }
}

/// 3-option segmented control for selecting the invite role. Rendered
/// only when the viewer is an Owner (Admins use a hidden input). The
/// hidden radio inputs let the form serialize naturally without JS.
fn role_segmented_control(selected: InstanceRole, id_prefix: &str) -> Markup {
    let options = [
        ("member", "Member", InstanceRole::Member),
        ("admin", "Admin", InstanceRole::Admin),
        ("owner", "Owner", InstanceRole::Owner),
    ];
    html! {
        div class="segmented-control" role="radiogroup" aria-label="Role" {
            @for (value, label, role) in options {
                @let id = format!("invite-role-{id_prefix}-{value}");
                input type="radio" name="role" id=(id)
                      class="segment-input" value=(value)
                      checked[selected == role];
                label class="segment" for=(id) { (label) }
            }
        }
    }
}

/// `POST /members/invite` success — render the one-time acceptance URL.
/// Reached as a direct render (no redirect) so the token doesn't leak
/// into the URL bar, browser history, referer header, or access logs.
pub fn members_invite_result_page(
    ctx: &ChromeContext,
    invitee_email: &str,
    invited_role: InstanceRole,
    accept_url: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Markup {
    let expires_label = expires_at.format("%Y-%m-%d %H:%M UTC").to_string();
    let content = html! {
        div class="card invite-result-card" {
            div class="invite-result-header" {
                h2 { "Invitation sent" }
                p class="invite-intro" {
                    (invitee_email) " · "
                    span class=(role_class(invited_role)) { (role_label(invited_role)) }
                    " · expires " (expires_label)
                }
            }
            div class="invite-link-block" {
                p class="invite-link-label" {
                    "Save or share this acceptance link. "
                    strong { "It is shown only once." }
                    " A copy is also queued to the invitee's email if "
                    "notifications are enabled."
                }
                div class="invite-link-row" {
                    input type="text" id="invite-url" class="invite-url-input"
                          value=(accept_url) readonly;
                    button type="button" class="btn-secondary"
                           data-copy-target="invite-url" { "Copy" }
                }
            }
            div class="invite-form-actions" {
                a class="btn-secondary" href="/members" { "Done" }
                a class="btn-primary-link" href="/members/invite" { "Invite another" }
            }
        }
        // Tiny clipboard wiring — `navigator.clipboard.writeText` is on
        // every modern browser; on the localhost dev server it works
        // because clipboard write is allowed from secure contexts AND
        // 127.0.0.1.
        script {
            (maud::PreEscaped(INVITE_COPY_JS))
        }
    };
    shell_app(ctx, "Invitation sent", PageId::Members, content)
}

// `can_invite_with_role` + `role_rank` were used by the old
// per-option `<select>` rendering; the new segmented control only
// branches between Owner (sees all 3 options) and non-Owner (gets a
// hidden Member input). The backend still gates with `authz::satisfies`
// — this helper just isn't needed at the view layer anymore.

const INVITE_COPY_JS: &str = r#"
document.addEventListener('click', function(e) {
    var btn = e.target.closest('[data-copy-target]');
    if (!btn) return;
    e.preventDefault();
    var input = document.getElementById(btn.getAttribute('data-copy-target'));
    if (!input) return;
    var text = input.value;
    var done = function() {
        var orig = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(function() { btn.textContent = orig; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function() {
            input.select(); document.execCommand('copy'); done();
        });
    } else {
        input.select(); document.execCommand('copy'); done();
    }
});
"#;

/// Banner inputs surfaced from `?action=...&target=...` (success) or
/// `?error=...` (failure) query params after a row-action redirect.
pub struct MembersBanner<'a> {
    pub action: Option<&'a str>,
    pub target: Option<&'a str>,
    pub error: Option<&'a str>,
}

/// `GET /members` page — admin-only directory of every non-purged Member.
/// Renders as a table; soft/hard-deleted accounts and Guests are filtered
/// out by [`identity::UserRepository::list_all`]. Each row carries a
/// kebab (`<details>`) menu whose contents depend on the viewer's role
/// and the target's lifecycle (see [`available_actions`]).
///
/// `sort` controls server-side row ordering (the handler in `routes.rs`
/// pre-sorts the slice before passing it in). The table headers render
/// as links that flip direction when clicked on the active column or
/// reset to ascending on a new column.
pub fn members_page(
    ctx: &ChromeContext,
    rows: &[MemberRow<'_>],
    banner: MembersBanner<'_>,
    sort: SortState,
    filter: MemberFilter,
    pagination: PaginationState,
) -> Markup {
    let content = html! {
        (render_banner(&banner))
        div class="users-toolbar" {
            input type="search" id="users-search" class="users-search"
                  placeholder="Search by name or email…" autocomplete="off"
                  aria-label="Search members";
            (filter_menu(filter, sort))
            button type="button" class="btn-secondary invite-cta"
                   data-open-dialog="dlg-invite" {
                (plus_icon())
                span { "Invite members" }
            }
        }
        @if rows.is_empty() && pagination.total_rows == 0 {
            div class="card" {
                p class="muted" { "No members match this filter." }
            }
        } @else {
            // No `.card` wrapper — the table sits directly on the page
            // background, with subtle row dividers carrying the visual
            // structure. See the design-ref screenshot.
            table class="users-table" {
                thead {
                    tr {
                        th class="col-select" {
                            input type="checkbox" id="select-all-members"
                                  class="member-checkbox member-checkbox-all"
                                  aria-label="Select all members";
                        }
                        (sortable_th("Member", SortColumn::Name, sort, filter, "col-member"))
                        (sortable_th("Type", SortColumn::Role, sort, filter, "col-role"))
                        (sortable_th("Joined", SortColumn::Joined, sort, filter, "col-date"))
                        th class="col-last-activity" { "Last activity" }
                        th class="col-actions" aria-label="Actions" { "" }
                    }
                }
                tbody {
                    @for row in rows {
                        @match row {
                            MemberRow::Member { user, last_activity } => {
                                (member_row(ctx.user, user, *last_activity, ctx.csrf_token))
                            }
                            MemberRow::PendingInvite(inv) => {
                                (pending_invite_row(inv, ctx.csrf_token))
                            }
                        }
                    }
                }
            }
        }
        // Inline page scripts: search filter + select-all wiring +
        // Pagination always renders, even at 1 page total — keeps the
        // toolbar/table rhythm stable as rows come and go and gives
        // the operator a fixed place to find the rows-per-page control.
        (pagination_bar(pagination, sort, filter))
        // Always-rendered invite modal — the "+ Invite members" CTA in
        // the toolbar above opens it via the shared dialog-open inline
        // JS in `shell_app`. Submitting POSTs to the same endpoint the
        // standalone form page uses; the result page still renders
        // full-screen so the one-time URL gets full attention.
        (invite_modal(ctx))
        // outside-click closes any open kebab. All vanilla JS, no
        // framework, no XHR.
        script {
            (maud::PreEscaped(MEMBERS_SEARCH_JS))
            (maud::PreEscaped(MEMBERS_SELECT_ALL_JS))
            (maud::PreEscaped(MEMBERS_KEBAB_OUTSIDE_CLICK_JS))
        }
    };
    shell_app_wide(ctx, "Members", PageId::Members, content)
}

/// Build a `/members?...` URL preserving sort + filter; page and rows
/// are passed in (so pagination links can target a different page or
/// row count). Used by every clickable affordance in the pagination
/// bar so navigation stays self-consistent.
fn members_url(sort: SortState, filter: MemberFilter, page: u32, rows: u32) -> String {
    format!(
        "/members?sort={}&dir={}&filter={}&page={}&rows={}",
        sort.column.as_str(),
        sort.direction.as_str(),
        filter.as_str(),
        page,
        rows,
    )
}

/// Three-column pagination bar at the foot of the Members table.
/// Mirrors the Untitled UI "card advanced center" pagination component:
/// editable "Page X of N" on the left, prev/page-numbers/next center,
/// rows-per-page dropdown on the right.
fn pagination_bar(
    state: PaginationState,
    sort: SortState,
    filter: MemberFilter,
) -> Markup {
    let cur = state.current_page;
    let total = state.total_pages;
    let rows = state.rows_per_page;
    let at_first = cur <= 1;
    let at_last = cur >= total;
    let prev_page = cur.saturating_sub(1).max(1);
    let next_page = (cur + 1).min(total);

    html! {
        nav class="pagination-bar" aria-label="Pagination" {
            // ── LEFT — editable page-jump form ──
            //
            // Submit-on-Enter takes the operator straight to the typed
            // page; hidden inputs preserve the other query params so
            // jumping doesn't drop the active sort/filter/rows.
            form method="get" action="/members" class="pagination-jump" {
                label class="pagination-jump-label" for="page-jump" { "Page" }
                input type="number" id="page-jump" name="page"
                      class="pagination-jump-input"
                      value=(cur) min="1" max=(total);
                span class="pagination-jump-of" { "of " (total) }
                input type="hidden" name="sort"   value=(sort.column.as_str());
                input type="hidden" name="dir"    value=(sort.direction.as_str());
                input type="hidden" name="filter" value=(filter.as_str());
                input type="hidden" name="rows"   value=(rows);
            }

            // ── CENTER — step + number controls ──
            div class="pagination-numbers" {
                (pagination_step(sort, filter, rows, 1, at_first, "first",
                                 chevron_double_left_icon()))
                (pagination_step(sort, filter, rows, prev_page, at_first, "previous",
                                 chevron_left_icon()))
                @for item in page_items(cur, total) {
                    @match item {
                        PageItem::Number(n) => (pagination_number(sort, filter, rows, n, n == cur)),
                        PageItem::Ellipsis => span class="pagination-ellipsis" aria-hidden="true" {
                            "…"
                        },
                    }
                }
                (pagination_step(sort, filter, rows, next_page, at_last, "next",
                                 chevron_right_icon()))
                (pagination_step(sort, filter, rows, total, at_last, "last",
                                 chevron_double_right_icon()))
            }

            // ── RIGHT — "Rows per page" label + dropdown for the number ──
            //
            // Per the design ref, only the number-with-chevron is the
            // dropdown trigger. The label sits as plain text to its
            // left so the operator can read the row as a phrase.
            div class="pagination-rows" {
                span class="pagination-rows-label" { "Rows per page" }
                details class="filter-menu pagination-rows-menu" {
                    summary class="filter-trigger pagination-rows-trigger" {
                        span class="filter-trigger-value" { (rows) }
                        (chevron_down_icon())
                    }
                    div class="filter-menu-list" {
                        @for option in ROWS_PER_PAGE_OPTIONS {
                            @let active = *option == rows;
                            @let class = if active {
                                "filter-menu-item filter-menu-item-active"
                            } else {
                                "filter-menu-item"
                            };
                            @let href = members_url(sort, filter, 1, *option);
                            a class=(class) href=(href) {
                                span { (option) }
                                @if active {
                                    (check_small_icon())
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// One number button in the pagination row. Renders the active page as
/// a non-link `<span>` so the cursor doesn't suggest navigation when
/// you're already there.
fn pagination_number(
    sort: SortState,
    filter: MemberFilter,
    rows: u32,
    page: u32,
    active: bool,
) -> Markup {
    if active {
        html! {
            span class="pagination-number pagination-number-active"
                 aria-current="page" { (page) }
        }
    } else {
        let href = members_url(sort, filter, page, rows);
        html! {
            a class="pagination-number" href=(href) { (page) }
        }
    }
}

/// Step button (first / prev / next / last). When `disabled` is true
/// renders as a non-link `<span>` so screen readers + keyboard users
/// don't treat it as actionable.
fn pagination_step(
    sort: SortState,
    filter: MemberFilter,
    rows: u32,
    page: u32,
    disabled: bool,
    label: &str,
    icon: Markup,
) -> Markup {
    let aria = format!("Go to {label} page");
    if disabled {
        html! {
            span class="pagination-step pagination-step-disabled"
                 aria-label=(aria) aria-disabled="true" {
                (icon)
            }
        }
    } else {
        let href = members_url(sort, filter, page, rows);
        html! {
            a class="pagination-step" href=(href) aria-label=(aria) {
                (icon)
            }
        }
    }
}

fn chevron_left_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg" width="14" height="14"
            viewBox="0 0 24 24" fill="none" stroke="currentColor"
            stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
            class="btn-icon" aria-hidden="true" {
            polyline points="15 18 9 12 15 6" {}
        }
    }
}
fn chevron_right_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg" width="14" height="14"
            viewBox="0 0 24 24" fill="none" stroke="currentColor"
            stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
            class="btn-icon" aria-hidden="true" {
            polyline points="9 18 15 12 9 6" {}
        }
    }
}
fn chevron_double_left_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg" width="14" height="14"
            viewBox="0 0 24 24" fill="none" stroke="currentColor"
            stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
            class="btn-icon" aria-hidden="true" {
            polyline points="11 17 6 12 11 7" {}
            polyline points="18 17 13 12 18 7" {}
        }
    }
}
fn chevron_double_right_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg" width="14" height="14"
            viewBox="0 0 24 24" fill="none" stroke="currentColor"
            stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
            class="btn-icon" aria-hidden="true" {
            polyline points="13 17 18 12 13 7" {}
            polyline points="6 17 11 12 6 7" {}
        }
    }
}

/// Render one sortable column header. Active column gets an asc/desc
/// indicator + `aria-sort`; inactive columns get a neutral indicator.
/// Clicking the active column flips direction; clicking an inactive
/// column resets to ascending. The current `filter` is round-tripped
/// in the href so sorting within a filtered view doesn't drop the
/// filter back to `All`.
fn sortable_th(
    label: &str,
    column: SortColumn,
    sort: SortState,
    filter: MemberFilter,
    extra_class: &str,
) -> Markup {
    let is_active = column == sort.column;
    let next_dir = if is_active {
        sort.direction.flip()
    } else {
        SortDirection::Asc
    };
    let href = format!(
        "/members?sort={}&dir={}&filter={}",
        column.as_str(),
        next_dir.as_str(),
        filter.as_str(),
    );
    let mut classes = String::from("col-sortable");
    if is_active {
        classes.push(' ');
        classes.push_str(match sort.direction {
            SortDirection::Asc => "col-sort-asc",
            SortDirection::Desc => "col-sort-desc",
        });
    }
    if !extra_class.is_empty() {
        classes.push(' ');
        classes.push_str(extra_class);
    }
    let aria_sort = if is_active {
        match sort.direction {
            SortDirection::Asc => "ascending",
            SortDirection::Desc => "descending",
        }
    } else {
        "none"
    };
    html! {
        th class=(classes) aria-sort=(aria_sort) {
            a href=(href) class="col-sort-link" { (label) }
        }
    }
}

const MEMBERS_SEARCH_JS: &str = r#"
(function() {
    var input = document.getElementById('users-search');
    if (!input) return;
    var rows = document.querySelectorAll('.users-table tbody tr');
    input.addEventListener('input', function() {
        var q = input.value.toLowerCase().trim();
        rows.forEach(function(tr) {
            var hay = tr.getAttribute('data-search') || '';
            tr.style.display = (q === '' || hay.indexOf(q) !== -1) ? '' : 'none';
        });
    });
})();
"#;

// Header checkbox toggles every enabled row checkbox. Disabled rows
// (Owners) stay disabled — selecting-all doesn't try to coerce them.
const MEMBERS_SELECT_ALL_JS: &str = r#"
(function() {
    var head = document.getElementById('select-all-members');
    if (!head) return;
    var rows = document.querySelectorAll('.member-checkbox-row:not(:disabled)');
    head.addEventListener('change', function() {
        rows.forEach(function(cb) { cb.checked = head.checked; });
    });
    rows.forEach(function(cb) {
        cb.addEventListener('change', function() {
            var all = true, none = true;
            rows.forEach(function(c) {
                if (c.checked) none = false;
                else all = false;
            });
            head.checked = all;
            head.indeterminate = !all && !none;
        });
    });
})();
"#;

// Close any open <details class="row-actions"> when the user clicks
// outside it. Without this the dropdown stays open until the user
// clicks the kebab again — confusing UX. Skip if the click landed
// inside the open details (so clicking a menu item still submits).
// Generalized outside-click handler — closes any open <details> menu
// (row-actions kebab, filter-menu, future dropdowns) when the user
// clicks outside it. New menus opt in by giving their <details> a
// matching class and adding it to the selector list.
const MEMBERS_KEBAB_OUTSIDE_CLICK_JS: &str = r#"
(function() {
    var selector = 'details.row-actions[open], details.filter-menu[open]';
    document.addEventListener('click', function(e) {
        document.querySelectorAll(selector).forEach(function(d) {
            if (!d.contains(e.target)) {
                d.open = false;
            }
        });
    });
})();
"#;

/// Filter dropdown rendered in the Members toolbar. Items round-trip
/// the current `sort` state in their href so flipping the filter
/// doesn't reset whichever column the operator was sorting by.
fn filter_menu(current: MemberFilter, sort: SortState) -> Markup {
    html! {
        details class="filter-menu" {
            summary class="filter-trigger" {
                span class="filter-trigger-label" { "Member type" }
                span class="filter-trigger-value" { (current.label()) }
                (chevron_down_icon())
            }
            div class="filter-menu-list" {
                (filter_menu_item(current, sort, MemberFilter::All))
                div class="filter-menu-section" { "Role" }
                (filter_menu_item(current, sort, MemberFilter::Role(InstanceRole::Owner)))
                (filter_menu_item(current, sort, MemberFilter::Role(InstanceRole::Admin)))
                (filter_menu_item(current, sort, MemberFilter::Role(InstanceRole::Member)))
                div class="filter-menu-section" { "Status" }
                (filter_menu_item(current, sort, MemberFilter::Status(UserLifecycle::Active)))
                (filter_menu_item(current, sort, MemberFilter::Status(UserLifecycle::PendingInvite)))
                (filter_menu_item(current, sort, MemberFilter::Status(UserLifecycle::Deactivated)))
                (filter_menu_item(current, sort, MemberFilter::Status(UserLifecycle::SoftDeleted)))
            }
        }
    }
}

fn filter_menu_item(current: MemberFilter, sort: SortState, option: MemberFilter) -> Markup {
    let active = current == option;
    let class = if active {
        "filter-menu-item filter-menu-item-active"
    } else {
        "filter-menu-item"
    };
    let href = format!(
        "/members?sort={}&dir={}&filter={}",
        sort.column.as_str(),
        sort.direction.as_str(),
        option.as_str(),
    );
    html! {
        a class=(class) href=(href) {
            span { (option.label()) }
            @if active {
                (check_small_icon())
            }
        }
    }
}

/// 14px chevron-down icon for the filter dropdown trigger.
fn chevron_down_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="14" height="14" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            class="btn-icon" aria-hidden="true" {
            polyline points="6 9 12 15 18 9" {}
        }
    }
}

/// Small check icon shown next to the currently-active filter option.
fn check_small_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="14" height="14" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2.5"
            stroke-linecap="round" stroke-linejoin="round"
            class="btn-icon" aria-hidden="true" {
            polyline points="20 6 9 17 4 12" {}
        }
    }
}

fn member_row(
    viewer: &User,
    target: &User,
    last_activity: Option<chrono::DateTime<chrono::Utc>>,
    csrf_token: &str,
) -> Markup {
    let is_self = viewer.id == target.id;
    let initial = display_initial(&target.display_name);
    let color = avatar_color(&target.id.0);
    let joined = short_date(target.created_at);
    // For the self row we render the menu the viewer *would* have on a
    // non-self target of their own role/lifecycle, but lock every item
    // visually so the operator sees what they can't do to themselves
    // instead of an absent kebab. `available_actions` returns the
    // would-be set when `is_self == true`; the renderer keys off the
    // same flag to lock vs. wire up each item.
    let actions = available_actions(
        viewer.instance_role,
        target.instance_role,
        target.lifecycle,
        is_self,
    );
    // Combined haystack the inline search JS scans against. Lowercased
    // once on the server so the client-side filter is plain substring.
    let search_hay = format!(
        "{} {}",
        target.display_name.to_lowercase(),
        target.email.to_lowercase()
    );

    // Owners can't be bulk-targeted, so their checkbox renders disabled.
    // The disabled state stays in the DOM (rather than being omitted)
    // for visual rhythm — every row contributes a checkbox slot.
    let checkbox_disabled = matches!(target.instance_role, InstanceRole::Owner);
    let aria_label = format!("Select {}", target.display_name);

    html! {
        tr class="user-row" data-search=(search_hay) {
            td class="col-select" {
                input type="checkbox" class="member-checkbox member-checkbox-row"
                      name="member_ids" value=(target.id.0)
                      aria-label=(aria_label)
                      disabled[checkbox_disabled];
            }
            td class="col-member user-row-cell" {
                div class="user-row-id" {
                    span class="avatar-wrapper" {
                        span class="avatar avatar-sm" style=(format!("background:{color}")) {
                            (initial)
                        }
                        (avatar_status_dot(target.lifecycle))
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
            td class="col-role" {
                span class=(role_class(target.instance_role)) {
                    (role_label(target.instance_role))
                }
            }
            td class="col-date" { (joined) }
            td class="col-last-activity" {
                @match last_activity {
                    Some(ts) => (short_date(ts)),
                    None => span class="muted-dash" { "—" },
                }
            }
            td class="col-actions" {
                @if !actions.is_empty() {
                    (row_actions_kebab(target, csrf_token, &actions, is_self))
                }
            }
        }
    }
}

/// Virtual row for a pending invitation. The invitee has no
/// `identity.users` row yet (we only create one on accept), so we
/// surface the invitation directly with its email standing in for both
/// display name + email, a "Pending" avatar dot, and a kebab whose
/// only option is "Revoke invite". Slots into the same `<tr>` shape as
/// `member_row` so the table layout is uniform.
fn pending_invite_row(invitation: &identity::Invitation, csrf_token: &str) -> Markup {
    let initial = display_initial(&invitation.email);
    let color = avatar_color(&invitation.id.0);
    let invited = short_date(invitation.created_at);
    let search_hay = invitation.email.to_lowercase();
    let id = invitation.id.0;
    let aria_label = format!("Select pending invite {}", invitation.email);

    html! {
        tr class="user-row pending-invite-row" data-search=(search_hay) {
            td class="col-select" {
                // Bulk-revoke isn't wired yet — disabled checkbox keeps
                // the column rhythm consistent across row types.
                input type="checkbox" class="member-checkbox member-checkbox-row"
                      aria-label=(aria_label) disabled;
            }
            td class="col-member user-row-cell" {
                div class="user-row-id" {
                    span class="avatar-wrapper" {
                        span class="avatar avatar-sm" style=(format!("background:{color}")) {
                            (initial)
                        }
                        (avatar_status_dot(UserLifecycle::PendingInvite))
                    }
                    div class="user-row-text" {
                        span class="user-name" { (invitation.email) }
                        span class="user-email" { "Pending invitation" }
                    }
                }
            }
            td class="col-role" {
                span class=(role_class(invitation.instance_role)) {
                    (role_label(invitation.instance_role))
                }
            }
            td class="col-date" { (invited) }
            td class="col-last-activity" {
                span class="muted-dash" { "—" }
            }
            td class="col-actions" {
                details class="row-actions" {
                    summary class="row-actions-trigger" aria-label="Row actions" {
                        span aria-hidden="true" { "⋮" }
                    }
                    div class="row-actions-menu" {
                        form method="post"
                             action=(format!("/members/invitations/{id}/revoke"))
                             class="row-action-form" {
                            (csrf_input(csrf_token))
                            button type="submit"
                                   class="row-action-item row-action-danger" {
                                "Revoke invite"
                            }
                        }
                    }
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
    // Self row: render the actions an admin would have on a non-self
    // target of the same role + lifecycle, so the caller can lock them
    // visually. Members never see the page so we leave their self
    // menu empty as a defensive default.
    if is_self {
        return self_row_actions(viewer, target_lifecycle);
    }
    // Admin can only act on Members (strict outrank). Owner can act on
    // anyone; Owner-on-Owner ops route through the pending flow at the
    // backend, but the UI surface is identical.
    let can_act = match viewer {
        InstanceRole::Member => false,
        InstanceRole::Admin => matches!(target_role, InstanceRole::Member),
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

/// What the self-row kebab shows. All entries are rendered locked at
/// render time; the list reflects what the viewer's rank *could* do to
/// a non-self target, so the operator sees an honest "you can't do
/// this to yourself" surface rather than an empty menu.
fn self_row_actions(viewer: InstanceRole, lifecycle: UserLifecycle) -> Vec<RowAction> {
    if matches!(viewer, InstanceRole::Member) {
        return Vec::new();
    }
    let mut actions = Vec::with_capacity(4);
    match lifecycle {
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

fn row_actions_kebab(
    target: &User,
    csrf_token: &str,
    actions: &[RowAction],
    locked: bool,
) -> Markup {
    let id = target.id.0;
    html! {
        details class="row-actions" {
            summary class="row-actions-trigger" aria-label="Row actions" {
                span aria-hidden="true" { "⋮" }
            }
            div class="row-actions-menu" {
                @for action in actions {
                    (render_action_item(*action, target, csrf_token, locked))
                }
            }
        }
        // Confirmation / role-change dialogs live as siblings of the
        // <details> so showModal() floats them over the page regardless
        // of whether the kebab is open. Only the dialog-opening actions
        // (Delete / Purge / Change Role) render a dialog; Deactivate /
        // Reactivate submit straight from the menu. Locked self-row
        // items never open a dialog or submit anything, so we skip the
        // dialog markup entirely in that case.
        @if !locked {
            @for action in actions {
                @if action_uses_dialog(*action) {
                    (render_action_dialog(*action, target, csrf_token, id))
                }
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

fn render_action_item(
    action: RowAction,
    target: &User,
    csrf_token: &str,
    locked: bool,
) -> Markup {
    if locked {
        return render_locked_item(action);
    }
    let id = target.id.0;
    match action {
        RowAction::Deactivate => html! {
            form method="post" action=(format!("/members/{id}/deactivate")) class="row-action-form" {
                (csrf_input(csrf_token))
                button type="submit" class="row-action-item" { "Deactivate" }
            }
        },
        RowAction::Reactivate => html! {
            form method="post" action=(format!("/members/{id}/reactivate")) class="row-action-form" {
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

/// Render a locked menu entry — visually present, lock-iconed, doesn't
/// submit or open a dialog. Used on the self row so the operator sees
/// the same shape they'd see for any other member but immediately
/// understands self-targeting is disallowed.
fn render_locked_item(action: RowAction) -> Markup {
    let (label, danger) = match action {
        RowAction::Deactivate => ("Deactivate", false),
        RowAction::Reactivate => ("Reactivate", false),
        RowAction::ChangeRole => ("Change role…", false),
        RowAction::Delete => ("Delete…", true),
        RowAction::Purge => ("Purge…", true),
    };
    let class = if danger {
        "row-action-item row-action-locked row-action-danger"
    } else {
        "row-action-item row-action-locked"
    };
    html! {
        button type="button" class=(class)
               aria-disabled="true" disabled
               title="You can't perform this action on yourself" {
            span { (label) }
            span class="row-action-icon" aria-hidden="true" {
                (lock_icon())
            }
        }
    }
}

/// Small inline lock SVG, sized to ~14px square. Uses `currentColor`
/// so it inherits the item's text color (and the locked opacity).
fn lock_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="14" height="14" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round" {
            rect x="4" y="11" width="16" height="10" rx="2" {}
            path d="M8 11V8a4 4 0 0 1 8 0v3" {}
        }
    }
}

/// 16px plus icon used as a leading icon for `+ Invite members`-style
/// CTAs. Stroke uses `currentColor` so the icon inherits the button's
/// label color and any hover/disabled state changes.
fn plus_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2.5"
            stroke-linecap="round" stroke-linejoin="round"
            class="btn-icon" aria-hidden="true" {
            line x1="12" y1="5" x2="12" y2="19" {}
            line x1="5" y1="12" x2="19" y2="12" {}
        }
    }
}

fn render_action_dialog(action: RowAction, target: &User, csrf_token: &str, id: uuid::Uuid) -> Markup {
    let name = &target.display_name;
    match action {
        RowAction::ChangeRole => html! {
            dialog id=(format!("dlg-role-{id}")) class="action-dialog" {
                form method="post" action=(format!("/members/{id}/role")) {
                    h2 { "Change role for " (name) }
                    p class="dialog-note" {
                        "If the target is an Owner, a 72-hour veto window "
                        "begins instead of applying immediately."
                    }
                    label class="field" {
                        span { "New role" }
                        select name="role" required {
                            @let current = target.instance_role;
                            option value="member" selected[current == InstanceRole::Member] { "Member" }
                            option value="admin"  selected[current == InstanceRole::Admin]  { "Admin" }
                            option value="owner"  selected[current == InstanceRole::Owner]  { "Owner" }
                        }
                    }
                    (csrf_input(csrf_token))
                    div class="dialog-actions" {
                        button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                        button type="submit" class="btn" { "Apply" }
                    }
                }
            }
        },
        RowAction::Delete => html! {
            dialog id=(format!("dlg-delete-{id}")) class="action-dialog" {
                form method="post" action=(format!("/members/{id}/delete")) {
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
                form method="post" action=(format!("/members/{id}/purge")) {
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

fn render_banner(banner: &MembersBanner<'_>) -> Markup {
    if let Some(error_code) = banner.error {
        return error_banner(error_code);
    }
    if let Some(action) = banner.action {
        return action_banner(action, banner.target);
    }
    html! {}
}

fn action_banner(action: &str, target: Option<&str>) -> Markup {
    let name = target.unwrap_or("This member");
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
        "invite_revoked" => "The invitation was revoked.".to_string(),
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
        "already_deactivated" => "That member is already deactivated.",
        "already_active" => "That member is already active.",
        "already_in_role" => "That member is already in that role.",
        "user_not_found" => "Member not found.",
        "not_active" => "That member is in pending invite state and can't be acted on.",
        "not_deactivated" => "That member isn't deactivated.",
        "pending_action_exists" => "An action is already pending against that member.",
        "forbidden" => "Only Owners can change roles.",
        "invalid_recovery_code" => "Invalid recovery code.",
        // Invite-form errors. These re-render the form with the input
        // preserved (see members_invite_form_page).
        "email_required" => "Enter an email address.",
        "cannot_invite_higher_role" => "You can't invite someone at a higher role than your own.",
        "email_already_in_use" => "A member with that email already exists.",
        "active_invite_exists" => "An open invitation already exists for that email.",
        // Revoke-invite errors. The kebab action redirects back here
        // with these codes when the underlying call refuses.
        "invite_not_found" => "That invitation no longer exists.",
        "invite_already_accepted" => "That invitation was already accepted.",
        _ => "Something went wrong.",
    };
    html! {
        div class="banner banner-error" role="alert" { (msg) }
    }
}

// ────────────────────────────────────────────────────────────────────────
// /invite/{token} — public acceptance page
// ────────────────────────────────────────────────────────────────────────

/// `GET /invite/{token}` (and `POST` on validation failure) — render the
/// acceptance form. Uses the **public** shell (no chrome) because the
/// invitee doesn't have an account yet. Email is shown read-only as a
/// confirmation that the link matches the right address.
///
/// The form `action` already embeds the token (it's in the URL path),
/// so we don't need to round-trip it in a hidden field. There's no
/// CSRF token either — the URL token *is* the credential, and a CSRF
/// attacker who has it doesn't need a victim to accept on their behalf
/// because they could already accept it themselves.
pub fn accept_invite_page(
    token: &str,
    invitation_email: &str,
    instance_role: InstanceRole,
    prefill_display_name: &str,
    error: Option<&str>,
) -> Markup {
    let action = format!("/invite/{token}");
    let content = html! {
        h1 { "Accept invitation" }
        div class="card invite-card" {
            form method="post" action=(action) class="invite-form" {
                p class="invite-intro" {
                    "You've been invited to join as "
                    span class=(role_class(instance_role)) { (role_label(instance_role)) }
                    "."
                }
                @if let Some(code) = error {
                    (accept_invite_error_banner(code))
                }
                div class="field" {
                    label for="email" { "Email" }
                    input type="email" name="email_readonly" id="email"
                          value=(invitation_email) readonly
                          autocomplete="email";
                }
                div class="field" {
                    label for="display_name" { "Display name" }
                    input type="text" name="display_name" id="display_name"
                          value=(prefill_display_name)
                          autocomplete="name" required autofocus;
                }
                div class="field" {
                    label for="password" { "Choose a password" }
                    input type="password" name="password" id="password"
                          autocomplete="new-password" required minlength="8";
                }
                div class="invite-form-actions" {
                    button type="submit" class="btn" { "Create account" }
                }
            }
        }
    };
    shell_public("Accept invitation", content)
}

/// Rendered when the token in the URL doesn't match an active invitation
/// — expired, revoked, already accepted, or never existed. We
/// intentionally don't distinguish these cases publicly to avoid leaking
/// which tokens ever existed.
pub fn accept_invite_invalid_page() -> Markup {
    let content = html! {
        h1 { "Invitation unavailable" }
        div class="card" {
            p {
                "This invitation link is invalid or has expired. Check with "
                "the person who invited you for a fresh link."
            }
            p {
                a href="/login" { "Go to sign in" }
            }
        }
    };
    shell_public("Invitation unavailable", content)
}

fn accept_invite_error_banner(code: &str) -> Markup {
    let msg = match code {
        "display_name_required" => "Enter a display name.",
        "password_required" => "Enter a password.",
        "invalid_or_expired_token" => {
            "This invitation link is invalid or has expired."
        }
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

#[cfg(test)]
mod tests {
    use super::{PageItem, page_items};

    fn nums(v: Vec<PageItem>) -> Vec<Option<u32>> {
        v.into_iter()
            .map(|i| match i {
                PageItem::Number(n) => Some(n),
                PageItem::Ellipsis => None,
            })
            .collect()
    }

    #[test]
    fn page_items_total_zero_shows_single_first() {
        assert_eq!(nums(page_items(1, 0)), vec![Some(1)]);
    }

    #[test]
    fn page_items_total_le_7_shows_every_page() {
        assert_eq!(nums(page_items(1, 7)),
                   vec![Some(1), Some(2), Some(3), Some(4), Some(5), Some(6), Some(7)]);
        assert_eq!(nums(page_items(3, 5)),
                   vec![Some(1), Some(2), Some(3), Some(4), Some(5)]);
    }

    #[test]
    fn page_items_current_le_4_is_right_leaning() {
        // 1 2 3 4 5 … 10
        assert_eq!(
            nums(page_items(1, 10)),
            vec![Some(1), Some(2), Some(3), Some(4), Some(5), None, Some(10)],
        );
        assert_eq!(
            nums(page_items(4, 10)),
            vec![Some(1), Some(2), Some(3), Some(4), Some(5), None, Some(10)],
        );
    }

    #[test]
    fn page_items_current_in_middle_is_centered() {
        // 1 … 4 5 6 … 10
        assert_eq!(
            nums(page_items(5, 10)),
            vec![Some(1), None, Some(4), Some(5), Some(6), None, Some(10)],
        );
        // 1 … 6 7 8 … 10 (current at last-3 boundary still middle)
        // wait — current=7 with total=10: total-3 = 7, so current >= total-3 triggers the
        // left-leaning case. Confirm:
        assert_eq!(
            nums(page_items(7, 10)),
            vec![Some(1), None, Some(6), Some(7), Some(8), Some(9), Some(10)],
        );
    }

    #[test]
    fn page_items_current_near_end_is_left_leaning() {
        // 1 … 6 7 8 9 10
        assert_eq!(
            nums(page_items(10, 10)),
            vec![Some(1), None, Some(6), Some(7), Some(8), Some(9), Some(10)],
        );
    }

    #[test]
    fn page_items_caps_at_7_slots_in_overflow_cases() {
        for cur in 1..=20 {
            let items = page_items(cur, 20);
            assert_eq!(
                items.len(),
                7,
                "expected 7 slots for cur={cur} total=20, got {}: {items:?}",
                items.len()
            );
        }
    }
}
