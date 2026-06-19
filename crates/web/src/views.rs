use identity::{InstanceRole, User, UserLifecycle};
use maud::{DOCTYPE, Markup, html};

/// Cache-bust suffix appended to every static asset URL. Computed
/// once at process startup so the value is stable for the lifetime
/// of the running server but changes on each restart — which lines
/// up with how operators iterate (every CSS / JS / template change
/// requires `cargo run`, so the rebuilt binary serves a new version).
///
/// Without this, browsers cache `app.css` aggressively (per the
/// default `tower_http::services::ServeDir` headers) and operators
/// see stale styles until they hard-refresh. The query-string form
/// is the standard "fingerprint" approach; the file content itself
/// doesn't need to change for the URL to look new.
fn asset_version() -> &'static str {
    use std::sync::OnceLock;
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("{secs:x}")
    })
}

/// Per-request context for authenticated chrome. Mostly borrowed pointers so
/// handlers can pass references straight from `AppState` + the authenticated
/// user without cloning; `instance_name` is a cheap `Arc<String>` snapshot of
/// the hot-swappable `AppState::instance_name` cell (Owner-editable at runtime).
pub struct ChromeContext<'a> {
    /// Instance display name, read from the live (Owner-editable) cell.
    pub instance_name: std::sync::Arc<String>,
    pub user: &'a User,
    /// CSRF token for this session — derived via
    /// [`server::csrf::compute_token`]. Embed in every state-changing
    /// form via [`csrf_input`].
    pub csrf_token: &'a str,
    /// Count of currently-pending Owner-on-Owner transitions. Sidebar
    /// renders a badge next to the "Pending review" nav entry when
    /// this is `Some(n)` with `n > 0`. Always `None` for non-Owner
    /// viewers — they don't see the entry at all, and we avoid the
    /// query for them too. Handlers that render the chrome can leave
    /// this unset (defaulting to `None`) when the count isn't readily
    /// available; the link still renders, just without a badge.
    pub pending_count: Option<u32>,
}

/// Render the hidden `csrf_token` input for a form. Every state-changing
/// `<form method="post">` in the authed UI must include this; the route
/// handler then validates via `server::csrf::verify_token`.
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
    Events,
    Pending,
    Apps,
    Settings,
}

/// Sortable column on `/users`. Default is `Joined` ascending, which
/// matches the ordering of `UserRepository::list_all`.
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
/// (`list_all`: Active + PendingInvite + Deactivated). `Status(Anonymized)`
/// is the one filter that *expands* visibility (surfaces `Anonymized`
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
            MemberFilter::Status(UserLifecycle::Anonymized) => "status:anonymized",
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
            "status:anonymized" => MemberFilter::Status(UserLifecycle::Anonymized),
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
            MemberFilter::Status(UserLifecycle::Anonymized) => "Anonymized",
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
                // Theme bootstrap — mirrored from the authed shell
                // so /login (and other public pages an operator
                // lands on after sign-out) honor the same
                // `data-theme` choice persisted in localStorage.
                // Without this, the quick-switch flow flashes
                // system theme on the login page before the user
                // signs back in.
                script {
                    (maud::PreEscaped(THEME_BOOT_JS))
                }
                link rel="stylesheet"
                     href=(format!("/assets/css/app.css?v={}", asset_version()));
                script src=(format!("/assets/vendor/htmx.min.js?v={}", asset_version()))
                       defer {}
            }
            body class="public" {
                main class="narrow" {
                    p class="wordmark" { "Sylva Hearth" }
                    (content)
                }
                footer class="site" {
                    code { (env!("CARGO_PKG_VERSION")) }
                }
                // Passkey ceremony glue — needed by the "Use a passkey"
                // button on /login/verify (and the passwordless button on
                // /login). Delegated + dormant on pages without passkeys.
                script {
                    (maud::PreEscaped(WEBAUTHN_JS))
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
/// The search trigger is decorative (no modal wired up).
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
                title { (title) " · " (ctx.instance_name.as_str()) }
                // Theme bootstrap runs before the stylesheet link so
                // it can stamp `<html data-theme>` ahead of the first
                // paint — no flash of system-theme before the saved
                // user choice applies.
                script {
                    (maud::PreEscaped(THEME_BOOT_JS))
                }
                link rel="stylesheet"
                     href=(format!("/assets/css/app.css?v={}", asset_version()));
                script src=(format!("/assets/vendor/htmx.min.js?v={}", asset_version()))
                       defer {}
            }
            body class="app" {
                (sidebar(ctx, current))
                main class=(main_class) {
                    h1 { (title) }
                    (content)
                    // Absolute positioning takes the graphic out of
                    // flex flow so it doesn't push pagination off the
                    // bottom.
                    @if wide {
                        div class="main-mark" aria-hidden="true" {}
                    }
                }
                // Modal host — the single injection point for all
                // on-demand modals. Empty at rest: no modal markup
                // ships in the page source. The client fetches a
                // modal's HTML from its `/modals/*` endpoint when it's
                // opened (appending the `<dialog>` here), then removes
                // it from the DOM on close.
                div id="modal-host" {}
                script {
                    (maud::PreEscaped(DIALOG_JS))
                }
                script {
                    (maud::PreEscaped(TOAST_JS))
                }
                script {
                    (maud::PreEscaped(THEME_SWITCH_JS))
                }
                script {
                    (maud::PreEscaped(MULTI_ACCOUNT_JS))
                }
                script {
                    (maud::PreEscaped(USER_CARD_OUTSIDE_CLICK_JS))
                }
                // Account-settings modal: the reauth-chain is needed
                // wherever the modal can be opened (i.e. every authed
                // page), since email change funnels through `dlg-
                // reauth`. The idempotency guard inside REAUTH_CHAIN_JS
                // makes the per-page load on `/members` a no-op
                // duplicate of this shell load. SETTINGS_TABS_JS wires
                // the left-rail tab switcher.
                script {
                    (maud::PreEscaped(REAUTH_CHAIN_JS))
                }
                script {
                    (maud::PreEscaped(SETTINGS_TABS_JS))
                }
                script {
                    (maud::PreEscaped(CHANGE_PASSWORD_GATE_JS))
                }
                // Data Control → Anonymize / Delete confirm gate (checkbox +
                // type-your-email). Delegated on document, dormant until a
                // close-account dialog appears.
                script {
                    (maud::PreEscaped(ACCOUNT_CLOSE_GATE_JS))
                }
                // Copy-to-clipboard for the recovery-code display that
                // can surface in the reauth modal after a regenerate
                // (Data Control tab). Delegated on document, so it's a
                // no-op until such a button appears.
                script {
                    (maud::PreEscaped(INVITE_COPY_JS))
                }
                // WebAuthn ceremony glue for passkey enrollment (and,
                // in the login step, authentication). Delegated, so it's
                // dormant until a passkey fragment appears.
                script {
                    (maud::PreEscaped(WEBAUTHN_JS))
                }
            }
        }
    }
}

// Theme bootstrap — inlined in `<head>` so it runs *before* the CSS
// is applied to the page. Reads `localStorage["sylva-theme"]` and
// stamps `<html data-theme="…">` accordingly; the matching
// `:root[data-theme="…"]` CSS rules then take effect on the
// initial paint, avoiding a flash of system-theme content before
// the user's choice is honored. Wrapped in try/catch because
// privacy-mode browsers can throw on localStorage access.
const THEME_BOOT_JS: &str = r#"
(function() {
    try {
        var t = localStorage.getItem('sylva-theme');
        if (t === 'dark' || t === 'light') {
            document.documentElement.dataset.theme = t;
        }
    } catch (e) {}
})();
"#;

// Theme switcher — wires the three buttons inside the user-card
// popover (`.user-card-theme-btn[data-theme-choice]`) to flip
// `<html data-theme="…">` and persist the choice in localStorage.
// `auto` removes the attribute and the saved value so the system
// preference takes over again. Runs once per page load.
const THEME_SWITCH_JS: &str = r#"
(function() {
    var KEY = 'sylva-theme';
    var html = document.documentElement;

    function current() {
        var t = html.dataset.theme;
        return (t === 'dark' || t === 'light') ? t : 'auto';
    }

    function refresh() {
        var c = current();
        document.querySelectorAll('.user-card-theme-btn').forEach(function(btn) {
            var choice = btn.dataset.themeChoice;
            var on = (choice === c);
            btn.classList.toggle('user-card-theme-btn-active', on);
            btn.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
    }

    document.addEventListener('click', function(e) {
        var btn = e.target.closest('.user-card-theme-btn');
        if (!btn) return;
        e.preventDefault();
        var choice = btn.dataset.themeChoice;
        try {
            if (choice === 'dark' || choice === 'light') {
                html.dataset.theme = choice;
                localStorage.setItem(KEY, choice);
            } else {
                delete html.dataset.theme;
                localStorage.removeItem(KEY);
            }
        } catch (err) {}
        refresh();
    });

    refresh();
})();
"#;

// Tab switcher for the account-settings modal. Click on a
// `.settings-tab` toggles `settings-tab-active` on the tab buttons
// and `settings-panel-active` on the matching panel, scoped to the
// containing `.settings-dialog` so a future second settings modal
// wouldn't interfere. No URL state — operator's choice resets on
// every open.
const SETTINGS_TABS_JS: &str = r#"
(function() {
    document.addEventListener('click', function(e) {
        var tab = e.target.closest('[data-settings-tab]');
        if (!tab) return;
        var dialog = tab.closest('.settings-dialog');
        if (!dialog) return;
        var name = tab.getAttribute('data-settings-tab');
        dialog.querySelectorAll('[data-settings-tab]').forEach(function(t) {
            var on = t.getAttribute('data-settings-tab') === name;
            t.classList.toggle('settings-tab-active', on);
            t.setAttribute('aria-selected', on ? 'true' : 'false');
        });
        dialog.querySelectorAll('[data-settings-panel]').forEach(function(p) {
            var on = p.getAttribute('data-settings-panel') === name;
            p.classList.toggle('settings-panel-active', on);
        });
    });
})();
"#;

// Change-password field glue:
//   • Gate — keep the Change-password button (which sits in the section
//     header, outside the form) disabled until the new password is >= 8
//     chars. The input carries `data-pw-gate="<form id>"`; the button is
//     found by `[data-reauth-confirm="<form id>"]`, document-wide.
//   • Reveal — the eye button (`[data-pw-toggle="<input id>"]`) flips the
//     input between password/text and swaps which eye glyph shows.
const CHANGE_PASSWORD_GATE_JS: &str = r#"
(function() {
    document.addEventListener('input', function(e) {
        var field = e.target.closest('[data-pw-gate]');
        if (!field) return;
        var btn = document.querySelector(
            '[data-reauth-confirm="' + field.getAttribute('data-pw-gate') + '"]'
        );
        if (btn) btn.disabled = field.value.length < 8;
    });

    document.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-pw-toggle]');
        if (!btn) return;
        e.preventDefault();
        var input = document.getElementById(btn.getAttribute('data-pw-toggle'));
        if (!input) return;
        var reveal = input.type === 'password';
        input.type = reveal ? 'text' : 'password';
        btn.classList.toggle('is-showing', reveal);
        btn.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
    });
})();
"#;

// WebAuthn (passkey) glue. Two delegated handlers:
//   • `[data-passkey-create]` (enrollment): read the embedded creation
//     options, run navigator.credentials.create, encode the result into
//     the hidden field, and submit the finish form (htmx swaps the
//     result + OOB-refreshes the passkeys list).
//   • `[data-passkey-auth]` (sign-in 2nd factor): wired in CP-B's login
//     step — reads request options, runs navigator.credentials.get.
// The base64url ↔ ArrayBuffer conversion is hand-rolled (no JS deps), as
// the WebAuthn API speaks ArrayBuffers but the wire format is base64url.
const WEBAUTHN_JS: &str = r#"
(function() {
    if (window.__sylvaWebauthnLoaded) return;
    window.__sylvaWebauthnLoaded = true;

    function b64urlToBuf(s) {
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        var pad = s.length % 4; if (pad) s += '='.repeat(4 - pad);
        var bin = atob(s); var buf = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
        return buf.buffer;
    }
    function bufToB64url(buf) {
        var bytes = new Uint8Array(buf); var bin = '';
        for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function showError(scope, msg) {
        var el = scope.querySelector('#passkey-error');
        if (el) { el.textContent = msg; el.hidden = false; }
    }
    function supported() {
        return !!(window.PublicKeyCredential && navigator.credentials);
    }

    // On a browser without WebAuthn, hide the sign-in passkey buttons so
    // we don't offer something that can't work (the handlers still guard).
    if (!supported()) {
        document.querySelectorAll('[data-passkey-auth]').forEach(function(b) {
            b.hidden = true;
        });
    }

    // Enrollment: navigator.credentials.create
    document.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-passkey-create]');
        if (!btn) return;
        e.preventDefault();
        var form = btn.closest('form');
        var optsEl = document.getElementById('passkey-options');
        if (!form || !optsEl) return;
        if (!supported()) { showError(form, 'This browser does not support passkeys.'); return; }

        var opts;
        try { opts = JSON.parse(optsEl.textContent).publicKey; }
        catch (_) { showError(form, 'Could not start passkey setup.'); return; }
        opts.challenge = b64urlToBuf(opts.challenge);
        if (opts.user && opts.user.id) opts.user.id = b64urlToBuf(opts.user.id);
        if (Array.isArray(opts.excludeCredentials)) {
            opts.excludeCredentials.forEach(function(c) { c.id = b64urlToBuf(c.id); });
        }

        btn.disabled = true;
        navigator.credentials.create({ publicKey: opts }).then(function(cred) {
            var out = {
                id: cred.id,
                rawId: bufToB64url(cred.rawId),
                type: cred.type,
                response: {
                    clientDataJSON: bufToB64url(cred.response.clientDataJSON),
                    attestationObject: bufToB64url(cred.response.attestationObject),
                },
                extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
            };
            var hidden = form.querySelector('#passkey-credential');
            if (hidden) hidden.value = JSON.stringify(out);
            if (typeof form.requestSubmit === 'function') form.requestSubmit();
            else form.submit();
        }).catch(function() {
            btn.disabled = false;
            showError(form, 'Passkey setup was cancelled or did not complete.');
        });
    });

    // Sign-in 2nd factor: fetch the challenge, run
    // navigator.credentials.get, then native-submit the assertion to the
    // verify endpoint (full-page POST → session + redirect).
    document.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-passkey-auth]');
        if (!btn) return;
        e.preventDefault();
        var startUrl = btn.getAttribute('data-passkey-auth');
        var form = document.getElementById(btn.getAttribute('data-passkey-form'));
        if (!form) return;
        if (!supported()) {
            showError(document, 'This browser does not support passkeys.');
            return;
        }
        btn.disabled = true;
        fetch(startUrl, { method: 'POST', headers: { 'Accept': 'application/json' } })
            .then(function(r) { if (!r.ok) throw new Error('start'); return r.json(); })
            .then(function(data) {
                var opts = data.options.publicKey;
                opts.challenge = b64urlToBuf(opts.challenge);
                if (Array.isArray(opts.allowCredentials)) {
                    opts.allowCredentials.forEach(function(c) { c.id = b64urlToBuf(c.id); });
                }
                return navigator.credentials.get({ publicKey: opts }).then(function(assertion) {
                    var out = {
                        id: assertion.id,
                        rawId: bufToB64url(assertion.rawId),
                        type: assertion.type,
                        response: {
                            authenticatorData: bufToB64url(assertion.response.authenticatorData),
                            clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
                            signature: bufToB64url(assertion.response.signature),
                            userHandle: assertion.response.userHandle
                                ? bufToB64url(assertion.response.userHandle) : null,
                        },
                        extensions: assertion.getClientExtensionResults
                            ? assertion.getClientExtensionResults() : {},
                    };
                    form.querySelector('[name="challenge_id"]').value = data.challenge_id;
                    form.querySelector('[name="passkey"]').value = JSON.stringify(out);
                    // requestSubmit fires a submit event htmx can intercept
                    // (reauth posts via hx-post); a plain native login form
                    // just submits. Both work.
                    if (typeof form.requestSubmit === 'function') form.requestSubmit();
                    else form.submit();
                });
            })
            .catch(function() {
                btn.disabled = false;
                showError(document, 'Passkey sign-in was cancelled or did not complete.');
            });
    });
})();
"#;

// Multi-account roster for the user-card popover. Reads the
// current account from `.user-card-accounts[data-current-account]`
// (a JSON blob stamped server-side), merges it into a
// localStorage list keyed `sylva-accounts`, then renders the
// *other* entries below the current row as `<a>` links. Clicking
// an other-account row navigates to `/login?email=…` so the
// email comes pre-filled — the closest we get to "quick switch"
// without a real shared-session backend. Capped at 5 stored
// accounts so the popover stays tidy. Wrapped in try/catch
// because privacy-mode browsers can throw on localStorage.
const MULTI_ACCOUNT_JS: &str = r#"
(function() {
    var KEY = 'sylva-accounts';
    var MAX = 5;

    var container = document.querySelector('.user-card-accounts');
    var tpl = document.getElementById('tpl-user-card-other-account');
    if (!container || !tpl) return;
    var raw = container.dataset.currentAccount;
    if (!raw) return;
    var current;
    try { current = JSON.parse(raw); } catch (e) { return; }
    if (!current || !current.id) return;

    function loadRoster() {
        try {
            var stored = localStorage.getItem(KEY);
            if (!stored) return [];
            var parsed = JSON.parse(stored);
            return Array.isArray(parsed) ? parsed : [];
        } catch (e) { return []; }
    }
    function saveRoster(r) {
        try { localStorage.setItem(KEY, JSON.stringify(r)); } catch (e) {}
    }

    var roster = loadRoster()
        .filter(function(a) { return a && a.id && a.id !== current.id; });
    roster.unshift(current);
    if (roster.length > MAX) roster = roster.slice(0, MAX);
    saveRoster(roster);

    container.querySelectorAll('.user-card-account-other')
        .forEach(function(el) { el.remove(); });

    function renderOther(acct) {
        var frag = tpl.content.cloneNode(true);
        var root = frag.querySelector('.user-card-account-other');
        if (!root) return null;
        root.dataset.otherAccount = acct.id;

        var avatar = frag.querySelector('[data-other-avatar]');
        if (avatar) {
            avatar.style.background = acct.color || '#888';
            avatar.textContent = acct.initial || '?';
        }
        var name = frag.querySelector('[data-other-name]');
        if (name) name.textContent = acct.name || '';
        var email = frag.querySelector('[data-other-email]');
        if (email) email.textContent = acct.email || '';
        var next = frag.querySelector('[data-other-next]');
        if (next) {
            next.value = '/login?email=' + encodeURIComponent(acct.email || '');
        }
        return frag;
    }

    roster.forEach(function(acct) {
        if (!acct || acct.id === current.id) return;
        var node = renderOther(acct);
        if (node) container.appendChild(node);
    });

    // Stops propagation so the surrounding form's submit button
    // doesn't also fire on the same click.
    container.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-other-delete]');
        if (!btn) return;
        e.preventDefault();
        e.stopPropagation();
        var row = btn.closest('.user-card-account-other');
        if (!row) return;
        var id = row.dataset.otherAccount;
        var next = loadRoster().filter(function(a) { return a && a.id !== id; });
        saveRoster(next);
        row.remove();
    });
})();
"#;

// Outside-click closes any open user-card popover. The kebab
// equivalent (`MEMBERS_KEBAB_OUTSIDE_CLICK_JS`) only targets
// `.row-actions` `<details>` elements, so we register a separate
// listener for the sidebar's user card. Clicking inside the
// popover (account rows, theme buttons, sign-out form) keeps it
// open; clicking the summary toggles it; anything else closes it.
const USER_CARD_OUTSIDE_CLICK_JS: &str = r#"
(function() {
    document.addEventListener('click', function(e) {
        var card = document.querySelector('details.user-card[open]');
        if (!card) return;
        if (card.contains(e.target)) return;
        card.removeAttribute('open');
    });
})();
"#;

// Dynamic toast system. No page-level toast markup is server-rendered.
// Three parts:
//
//   1. Server: action handlers attach an `HX-Trigger` header with a
//      `sylva-toast` event carrying `{kind, title, message}`.
//   2. Old-page listener: when HTMX fires `sylva-toast`, we push the
//      payload into sessionStorage so it survives the HX-Redirect
//      navigation that usually accompanies the trigger.
//   3. New-page bootstrap: drain anything queued in sessionStorage and
//      render each toast client-side into a `.toast-container`. The
//      container is created lazily on first toast, removed when empty.
//
// Properties this gives us:
//   - Reload doesn't re-render an old toast — the queue is consumed.
//   - Multiple actions in flight naturally stack — each pushes its own
//     entry; the next page render flushes them all.
//   - URL stays clean — no `?action=` or `?error=` pollution.
//   - 15s auto-dismiss for every kind, plus click-the-× to dismiss
//     immediately.
const TOAST_JS: &str = r#"
(function() {
    var STORAGE_KEY = 'sylva-toasts';
    var DURATION_MS = 15000;
    var MAX_AGE_MS = 30000;

    // Kept in sync with the Maud helpers (check_circle_icon /
    // info_circle_icon / alert_circle_icon / close_icon) — they're
    // small enough that a copy here beats fetching them dynamically.
    var ICONS = {
        success:
            '<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" ' +
            'viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
            'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ' +
            'aria-hidden="true"><circle cx="12" cy="12" r="10"></circle>' +
            '<polyline points="8 12 11 15 16 9"></polyline></svg>',
        info:
            '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" ' +
            'viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
            'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ' +
            'aria-hidden="true"><circle cx="12" cy="12" r="10"></circle>' +
            '<line x1="12" y1="11" x2="12" y2="16"></line>' +
            '<line x1="12" y1="7.5" x2="12" y2="7.5"></line></svg>',
        error:
            '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" ' +
            'viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
            'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ' +
            'aria-hidden="true"><circle cx="12" cy="12" r="10"></circle>' +
            '<line x1="12" y1="8" x2="12" y2="13"></line>' +
            '<line x1="12" y1="16.5" x2="12" y2="16.5"></line></svg>'
    };
    var CLOSE_ICON =
        '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" ' +
        'viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ' +
        'aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"></line>' +
        '<line x1="6" y1="6" x2="18" y2="18"></line></svg>';

    function ensureContainer() {
        var c = document.querySelector('.toast-container');
        if (c) return c;
        c = document.createElement('div');
        c.className = 'toast-container';
        document.body.appendChild(c);
        return c;
    }

    function dismissToast(toast) {
        if (toast.dataset.leaving === '1') return;
        toast.dataset.leaving = '1';
        if (toast._dismissTimer) clearTimeout(toast._dismissTimer);
        toast.classList.add('toast-leaving');
        setTimeout(function() {
            var container = toast.closest('.toast-container');
            toast.remove();
            if (container && !container.querySelector('.toast')) {
                container.remove();
            }
        }, 220);
    }

    function renderToast(data) {
        if (!data || typeof data !== 'object') return;
        var kind = data.kind === 'success' || data.kind === 'info' ||
                   data.kind === 'error' ? data.kind : 'info';
        var container = ensureContainer();
        var toast = document.createElement('div');
        toast.className = 'toast toast-' + kind;
        toast.setAttribute('role', kind === 'error' ? 'alert' : 'status');
        toast.innerHTML =
            '<div class="toast-icon">' + ICONS[kind] + '</div>' +
            '<div class="toast-body">' +
                '<div class="toast-title"></div>' +
                '<div class="toast-message"></div>' +
            '</div>' +
            '<button type="button" class="toast-close" aria-label="Dismiss">' +
                CLOSE_ICON + '</button>';
        // textContent (not innerHTML) so any server-controlled title /
        // message string can't smuggle markup or scripts into the page.
        toast.querySelector('.toast-title').textContent = String(data.title || '');
        toast.querySelector('.toast-message').textContent = String(data.message || '');
        container.appendChild(toast);
        toast._dismissTimer = setTimeout(function() {
            dismissToast(toast);
        }, DURATION_MS);
    }

    // Close-X delegation. One listener on document covers every toast,
    // including ones added later by the HX-Trigger flow.
    document.addEventListener('click', function(e) {
        var close = e.target.closest('.toast-close');
        if (!close) return;
        var toast = close.closest('.toast');
        if (toast) dismissToast(toast);
    });

    // Buffer toast payloads that arrive via HX-Trigger so they survive
    // the HX-Redirect navigation HTMX usually performs alongside.
    // HTMX dispatches the event synchronously before triggering the
    // redirect, so the sessionStorage write completes in time.
    //
    // **Important**: HTMX's event dispatcher mutates `event.detail` to
    // add an `elt` field pointing at the source DOM element. Including
    // that reference in what we hand to `JSON.stringify` makes the
    // call throw a TypeError (DOM nodes aren't JSON-serializable), and
    // the silent catch below would leave the queue empty — which is
    // exactly the "toasts never show up post-navigation" symptom.
    // Extract only the three fields we care about so the payload is
    // pure data and round-trips through JSON cleanly.
    document.body.addEventListener('sylva-toast', function(e) {
        var src = (e && e.detail) || {};
        var clean = {
            kind: src.kind,
            title: src.title,
            message: src.message
        };
        try {
            var queue = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || '[]');
            queue.push({ data: clean, ts: Date.now() });
            sessionStorage.setItem(STORAGE_KEY, JSON.stringify(queue));
        } catch (_) {
            // sessionStorage can throw in private mode or when quota is
            // exhausted. The toast is decorative; swallow the error.
        }
    });

    // Drain any queued toasts on every page load. Anything older than
    // 30 seconds is considered stale (the redirect-render flow is sub-
    // second; older entries are from a separate session and shouldn't
    // pop up unexpectedly).
    (function drain() {
        try {
            var raw = sessionStorage.getItem(STORAGE_KEY);
            if (!raw) return;
            sessionStorage.removeItem(STORAGE_KEY);
            var queue = JSON.parse(raw);
            if (!Array.isArray(queue)) return;
            var now = Date.now();
            queue.forEach(function(item) {
                if (item && (now - (item.ts || 0)) < MAX_AGE_MS) {
                    renderToast(item.data);
                }
            });
        } catch (_) {}
    })();
})();
"#;

const DIALOG_JS: &str = r#"
// ── On-demand modal host ───────────────────────────────────────────
// Shared modals (account-settings, reauth) ship no markup in the page.
// They're fetched from their `/modals/*` endpoint when opened, appended
// to `#modal-host`, HTMX-processed so their hx-* attributes fire, then
// removed from the DOM on close. `beforeend` append (not replace) lets
// modals stack — e.g. the reauth modal opening over the settings modal,
// both live in the dialog top layer, each removed on its own close.
window.sylvaOpenModal = function(url) {
    var host = document.getElementById('modal-host');
    if (!host) return Promise.resolve(null);
    return fetch(url, { credentials: 'same-origin' })
        .then(function(r) { return r.text(); })
        .then(function(html) {
            var tmp = document.createElement('div');
            tmp.innerHTML = html;
            var dlg = tmp.querySelector('dialog');
            if (!dlg) return null;
            host.appendChild(dlg);
            // htmx.min.js scans on DOMContentLoaded + its own swap
            // events, not raw DOM mutation. Process the injected
            // subtree so the modal's hx-post/hx-target start firing —
            // otherwise the form does a native POST and the server's
            // partial loads as a bare page.
            if (window.htmx && typeof window.htmx.process === 'function') {
                window.htmx.process(dlg);
            }
            return dlg;
        })
        .catch(function() { return null; });
};

// Fetch-if-missing variant. Used by the reauth chain, which may be
// re-entered while a previous reauth dialog is still mounted.
window.sylvaEnsureModal = function(id, url) {
    var live = document.getElementById(id);
    if (live) return Promise.resolve(live);
    return window.sylvaOpenModal(url);
};

document.addEventListener('click', function(e) {
    // Every modal opens on demand: fetch its fragment, inject it into
    // #modal-host, showModal(). `data-open-modal` is the only open path.
    var openModal = e.target.closest('[data-open-modal]');
    if (openModal) {
        e.preventDefault();
        window.sylvaOpenModal(openModal.getAttribute('data-open-modal'))
            .then(function(d) {
                if (d && typeof d.showModal === 'function') d.showModal();
            });
        return;
    }
    var closeBtn = e.target.closest('[data-close-dialog]');
    if (closeBtn) {
        e.preventDefault();
        var dlg = closeBtn.closest('dialog');
        if (dlg && typeof dlg.close === 'function') dlg.close();
    }
});

// Remove fetched modals from the DOM when they close, so nothing
// lingers between opens. Scoped to dialogs parented by `#modal-host`.
// Skips a close flagged `chainTransition` — that's a modal closing as
// part of a hand-off (the invite modal closing while reauth opens),
// which must survive to be reopened later. The flag is one-shot:
// cleared as it's honored, so the next *real* close removes the modal.
// Capture phase because `close` doesn't bubble.
document.addEventListener('close', function(e) {
    var dlg = e.target;
    if (!(dlg instanceof HTMLDialogElement)) return;
    if (dlg.parentElement && dlg.parentElement.id === 'modal-host') {
        if (dlg.dataset.chainTransition === '1') {
            dlg.dataset.chainTransition = '';
            return;
        }
        dlg.remove();
    }
}, true);
"#;

fn sidebar(ctx: &ChromeContext, current: PageId) -> Markup {
    let is_admin = is_at_least_admin(ctx.user.instance_role);
    html! {
        aside class="sidebar" {
            div class="brand" {
                a href="/" {
                    // Decorative; alt left empty so screen readers fall
                    // through to the "Sylva · {instance}" text that
                    // follows.
                    span class="brand-logo" aria-hidden="true" {
                        img src="/assets/img/sylva-logo.svg" alt="";
                    }
                    span class="brand-prefix" { "Sylva" }
                    span class="brand-sep" { " · " }
                    span class="brand-instance" { (ctx.instance_name.as_str()) }
                }
            }

            // Decorative search trigger — inert/disabled (no modal
            // wired up).
            button class="search-trigger" type="button"
                   aria-label="Search (coming soon)" disabled {
                span class="search-icon" { (search_glyph_icon()) }
                span class="search-label" { "Search…" }
                span class="search-shortcut" { "⌘K" }
            }

            nav class="nav-links" {
                (nav_link("/me", "Profile", current == PageId::Profile, user_icon()))
                @if is_admin {
                    // Members carries the pending-action count badge
                    // for Owner viewers. For Admin viewers the badge is
                    // None and the helper renders just the plain label.
                    (nav_link_with_badge(
                        "/members",
                        "Members",
                        current == PageId::Members,
                        ctx.pending_count,
                        users_icon(),
                    ))
                    // Audit log viewer — Admins + Owners. `/events` re-checks
                    // the role server-side.
                    (nav_link(
                        "/events",
                        "Events",
                        current == PageId::Events,
                        events_icon(),
                    ))
                }
                // Owner-only: registered apps + instance configuration. Admins
                // manage users; Owners manage the platform + instance.
                // Defense-in-depth — both pages re-check the role server-side.
                @if is_owner(ctx.user.instance_role) {
                    (nav_link(
                        "/apps",
                        "Apps",
                        current == PageId::Apps,
                        apps_icon(),
                    ))
                    (nav_link(
                        "/settings",
                        "Settings",
                        current == PageId::Settings,
                        settings_icon(),
                    ))
                }
            }

            // Decorative Sylva mark. Rendered as a `<div>` with the SVG
            // masked over a currentColor background so the mark inherits
            // the sidebar's text colour automatically across themes.
            div class="sidebar-mark" aria-hidden="true" {}

            (user_card(ctx))
        }
    }
}

fn is_at_least_admin(role: InstanceRole) -> bool {
    matches!(role, InstanceRole::Admin | InstanceRole::Owner)
}

fn is_owner(role: InstanceRole) -> bool {
    matches!(role, InstanceRole::Owner)
}

fn nav_link(href: &str, label: &str, active: bool, icon: Markup) -> Markup {
    let class = if active { "nav-link active" } else { "nav-link" };
    html! {
        a class=(class) href=(href) {
            span class="nav-link-icon" aria-hidden="true" { (icon) }
            span class="nav-link-label" { (label) }
        }
    }
}

/// Nav link with an optional count badge. The badge only renders when
/// `count` is `Some(n)` with `n > 0` — so the layout collapses cleanly
/// for the empty-queue case (the link still shows, just no number).
fn nav_link_with_badge(
    href: &str,
    label: &str,
    active: bool,
    count: Option<u32>,
    icon: Markup,
) -> Markup {
    let class = if active { "nav-link active" } else { "nav-link" };
    // Only render the badge when count is Some(n) with n > 0; binding
    // `n` here avoids unwrap() (the workspace denies `unwrap_used`).
    let badge_count = count.filter(|&n| n > 0);
    html! {
        a class=(class) href=(href) {
            span class="nav-link-icon" aria-hidden="true" { (icon) }
            span class="nav-link-label" { (label) }
            @if let Some(n) = badge_count {
                span class="nav-link-badge" aria-label=(format!("{n} pending")) {
                    (n)
                }
            }
        }
    }
}

fn user_card(ctx: &ChromeContext) -> Markup {
    let user = ctx.user;
    let initial = display_initial(&user.display_name);
    let color = avatar_color(&user.id.0);
    // JSON blob describing the current account — stamped onto the
    // `.user-card-accounts` container's data attribute so
    // `MULTI_ACCOUNT_JS` can read it without parsing HTML. The
    // value rides through Maud's attribute interpolation, which
    // HTML-escapes characters that could break out of the
    // attribute (quotes, `<`, `>`), so display names containing
    // any of those stay safely bottled.
    let current_account_json = serde_json::json!({
        "id": user.id.0.to_string(),
        "name": user.display_name,
        "email": user.email,
        "color": color,
        "initial": initial.to_string(),
    })
    .to_string();

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
                span class="user-card-summary-kebab" aria-hidden="true" {
                    (dots_vertical_icon())
                }
            }
            // Popover menu — positioned to the right of the sidebar
            // panel via `position: fixed` so it escapes the sidebar's
            // `overflow: hidden`. Layered as: signed-in accounts list,
            // separator, account-level actions (settings + theme
            // switcher + sign out).
            div class="user-card-menu" {
                // Multi-account list. The current account renders
                // server-side with a filled radio indicator; previous
                // accounts the operator has signed into on this
                // browser get appended client-side by
                // `MULTI_ACCOUNT_JS`, which reads the JSON blob on
                // `data-current-account` (below) plus the
                // browser-local roster in localStorage. Clicking an
                // other-account row navigates to `/login?email=…`
                // so the email comes pre-filled.
                div class="user-card-accounts" role="list"
                    data-current-account=(current_account_json) {
                    div class="user-card-account user-card-account-current"
                        role="listitem" {
                        span class="avatar" style=(format!("background:{color}")) {
                            (initial)
                        }
                        span class="user-card-text" {
                            span class="user-name" { (user.display_name) }
                            span class="user-email" { (user.email) }
                        }
                        span class="user-card-account-radio"
                             aria-label="Current account" {
                            (radio_on_icon())
                        }
                    }
                }
                div class="user-card-divider" {}
                // Theme switcher — three icon buttons (auto/dark/light)
                // on one horizontal row. Wired by `THEME_SWITCH_JS`.
                div class="user-card-theme" role="radiogroup"
                    aria-label="Theme" {
                    button type="button" class="user-card-theme-btn"
                           data-theme-choice="auto"
                           aria-label="Match system theme" {
                        (theme_auto_icon())
                    }
                    button type="button" class="user-card-theme-btn"
                           data-theme-choice="dark"
                           aria-label="Dark theme" {
                        (theme_dark_icon())
                    }
                    button type="button" class="user-card-theme-btn"
                           data-theme-choice="light"
                           aria-label="Light theme" {
                        (theme_light_icon())
                    }
                }
                // Rendered as a button (not an anchor) because there's
                // no URL to navigate to — the modal lives in-page.
                button type="button" class="user-card-action"
                       data-open-modal="/modals/account-settings" {
                    span class="user-card-action-icon" { (settings_icon()) }
                    span { "Account settings" }
                }
                form method="post" action="/logout"
                     class="user-card-action-form" {
                    (csrf_input(ctx.csrf_token))
                    button type="submit"
                           class="user-card-action user-card-signout" {
                        span class="user-card-action-icon" { (signout_icon()) }
                        span { "Sign out" }
                    }
                }
                // Template for the other-account rows rendered
                // client-side by `MULTI_ACCOUNT_JS`. Carries the
                // CSRF token + a logout form so clicking a row
                // actually signs the current session out and
                // bounces the operator to /login with the other
                // email pre-filled. The delete `<button>` (×) is
                // a sibling of the submit button so JS can wire
                // it without conflicting with form submission.
                template id="tpl-user-card-other-account" {
                    div class="user-card-account user-card-account-other"
                        data-other-account="" {
                        form method="post" action="/logout"
                             class="user-card-account-form" {
                            (csrf_input(ctx.csrf_token))
                            input type="hidden" name="next"
                                  value="" data-other-next;
                            button type="submit"
                                   class="user-card-account-body" {
                                span class="avatar" data-other-avatar {}
                                span class="user-card-text" {
                                    span class="user-name" data-other-name {}
                                    span class="user-email" data-other-email {}
                                }
                                span class="user-card-account-radio"
                                     aria-hidden="true" {
                                    (radio_off_icon())
                                }
                            }
                            button type="button"
                                   class="user-card-account-delete"
                                   data-other-delete
                                   aria-label="Remove from quick switch" {
                                (close_icon())
                            }
                        }
                    }
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

/// Renders the avatar circle inside the standard `.avatar-wrapper`.
/// Deactivated users get an extra treatment: the avatar dims to 50%
/// opacity and a small lock icon is overlaid in the middle so the
/// disabled state reads at a glance.
fn avatar_block(display_name: &str, user_id: &uuid::Uuid, lifecycle: UserLifecycle) -> Markup {
    let initial = display_initial(display_name);
    let color = avatar_color(user_id);
    let deactivated = matches!(lifecycle, UserLifecycle::Deactivated);
    let avatar_class = if deactivated {
        "avatar avatar-sm avatar-deactivated"
    } else {
        "avatar avatar-sm"
    };
    html! {
        span class="avatar-wrapper" {
            span class=(avatar_class) style=(format!("background:{color}")) {
                (initial)
            }
            @if deactivated {
                // Lock overlay sits above the avatar inside the same
                // wrapper. `aria-hidden` because the user-name
                // "Deactivated" tag already announces the state to
                // assistive tech.
                span class="avatar-lock" aria-hidden="true" {
                    (lock_icon())
                }
            }
        }
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
pub fn login_page(error: Option<&str>, prefill_email: Option<&str>) -> Markup {
    // When the user-card popover quick-switches to another account
    // it lands here with `?email=…`. Pre-fill the email input and
    // shift autofocus to the password field so the operator only
    // types the credential they actually need to.
    let has_prefill = prefill_email.is_some_and(|e| !e.is_empty());
    let content = html! {
        h1 { "Sign in" }
        div class="card" {
            form method="post" action="/login" {
                @if let Some(msg) = error {
                    p class="error" { (msg) }
                }
                div class="field" {
                    label for="email" { "Email" }
                    @if let Some(email) = prefill_email.filter(|e| !e.is_empty()) {
                        input type="email" name="email" id="email" required
                              autocomplete="username" value=(email);
                    } @else {
                        input type="email" name="email" id="email" required
                              autocomplete="username" autofocus;
                    }
                }
                div class="field" {
                    label for="password" { "Password" }
                    @if has_prefill {
                        input type="password" name="password" id="password" required
                              autocomplete="current-password" autofocus;
                    } @else {
                        input type="password" name="password" id="password" required
                              autocomplete="current-password";
                    }
                }
                button type="submit" class="btn" { "Sign in" }
            }
            p class="login-verify-or" { "or" }
            // Passwordless passkey sign-in. The hidden form is submitted by
            // WEBAUTHN_JS after the navigator.credentials.get ceremony
            // (reusing the [data-passkey-auth] handler); it posts the
            // assertion to /login/passkey/finish, which resolves the user
            // and issues a session.
            form id="form-passkey-login" method="post" action="/login/passkey/finish" {
                input type="hidden" name="challenge_id";
                input type="hidden" name="passkey";
            }
            p class="error" id="passkey-error" hidden {}
            button type="button" class="btn-secondary login-passkey-btn"
                   data-passkey-auth="/login/passkey/start"
                   data-passkey-form="form-passkey-login" {
                (fingerprint_icon())
                span { "Sign in with a passkey" }
            }
            p class="login-recover-link" {
                a href="/recover" { "Lost access?" }
            }
        }
    };
    shell_public("Sign in", content)
}

/// `GET /goodbye` — public confirmation shown after a user closes their own
/// account from Data Control. `mode == "deleted"` means the account and all
/// its data were permanently removed; anything else is the anonymize close
/// (the account is shut and the personal info scrubbed, data left in place).
/// Public: the session is gone by the time the browser lands here.
pub fn goodbye_page(mode: &str) -> Markup {
    let deleted = mode == "deleted";
    let (title, body) = if deleted {
        (
            "Your account has been deleted",
            "Everything tied to your account has been permanently removed from \
             this server, including anything you created or shared. There's \
             nothing left to recover. Thank you for having been here.",
        )
    } else {
        (
            "Your account has been closed",
            "Your account is closed and your personal information has been \
             removed from it. Anything you took part in stays in place, no \
             longer linked to you. Thank you for having been here.",
        )
    };
    let content = html! {
        h1 { (title) }
        div class="card" {
            p class="muted" { (body) }
            p class="login-recover-link" {
                a href="/login" { "Back to sign in" }
            }
        }
    };
    shell_public(title, content)
}

/// Terminal page served on **every** web route once the instance has been
/// closed (the last user left). No auth, no actions — there's nothing left to
/// do but read it. Styled via `/assets`, which the closed-page middleware
/// exempts. Reachable again only after a `clean` + re-`provision`.
pub fn instance_closed_page() -> Markup {
    let content = html! {
        h1 { "This server has been closed. Goodbye." }
        div class="card" {
            p class="muted" {
                "An owner has deleted this instance and all its data. This instance "
                "is no longer in use and there's nothing here anymore. For users, "
                "feel free to close this tab and move on. Desktop and mobile apps will "
                "no longer sync any of your data, and will switch to offline mode on "
                "next use. For owners, please shut down the server application one last  "
                "time and uninstall the software from the host."
            }
        }
    };
    shell_public("Server closed", content)
}

/// `GET /recover` — public start of the offline account-recovery flow.
/// The operator enters their email + the recovery code they saved at
/// invite acceptance (or last regeneration). `error` renders a generic
/// banner that never reveals which half was wrong.
pub fn recover_page(error: Option<&str>) -> Markup {
    let content = html! {
        h1 { "Recover your account" }
        div class="card" {
            p class="muted recover-intro" {
                "Enter your email and the recovery code you saved. We'll "
                "let you set a new password. Sylva is offline-first - "
                "there's no reset email, so the recovery code is the only "
                "way back in."
            }
            form method="post" action="/recover" {
                @if let Some(msg) = error {
                    p class="error" { (msg) }
                }
                div class="field" {
                    label for="email" { "Email" }
                    input type="email" name="email" id="email" required
                          autocomplete="username" autofocus;
                }
                div class="field" {
                    label for="recovery_code" { "Recovery code" }
                    input type="text" name="recovery_code" id="recovery_code"
                          required autocomplete="off" spellcheck="false"
                          placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX";
                }
                button type="submit" class="btn" { "Continue" }
            }
            p class="login-recover-link" {
                a href="/login" { "Back to sign in" }
            }
        }
    };
    shell_public("Recover your account", content)
}

/// `GET /recover/reset` (and POST re-render on error) — the
/// new-password step, reachable only with a valid reset cookie (minted
/// by `POST /recover`). Confirm-match is validated server-side so the
/// page works without JS.
pub fn recover_reset_page(error: Option<&str>) -> Markup {
    let content = html! {
        h1 { "Set a new password" }
        div class="card" {
            form method="post" action="/recover/reset" {
                @if let Some(msg) = error {
                    p class="error" { (msg) }
                }
                div class="field" {
                    label for="new_password" { "New password" }
                    input type="password" name="new_password" id="new_password"
                          required minlength="8" autocomplete="new-password"
                          autofocus;
                }
                div class="field" {
                    label for="confirm_password" { "Confirm new password" }
                    input type="password" name="confirm_password"
                          id="confirm_password" required minlength="8"
                          autocomplete="new-password";
                }
                button type="submit" class="btn" { "Set password" }
            }
        }
    };
    shell_public("Set a new password", content)
}

/// `GET /login/verify` — the second-factor challenge, reached after a
/// correct password when the user has TOTP enrolled. Reachable only with
/// a valid `sylva_mfa` cookie. Offers the authenticator code (primary)
/// and a recovery-code break-glass (in a native `<details>`, no JS).
pub fn login_verify_page(error: Option<&str>, has_totp: bool, has_passkey: bool) -> Markup {
    let content = html! {
        h1 { "Two-step verification" }
        div class="card" {
            @if let Some(msg) = error {
                p class="error" { (msg) }
            }
            @if has_passkey {
                p class="muted recover-intro" {
                    "Use one of your registered passkeys to finish signing in."
                }
                // Native form submitted by WEBAUTHN_JS after the
                // navigator.credentials.get ceremony (full-page POST, not
                // htmx — this is the public login flow).
                form method="post" action="/login/verify" id="form-passkey-login" {
                    input type="hidden" name="challenge_id";
                    input type="hidden" name="passkey";
                }
                p class="error" id="passkey-error" hidden {}
                button type="button" class="btn"
                       data-passkey-auth="/login/verify/passkey/start"
                       data-passkey-form="form-passkey-login" {
                    "Use a passkey"
                }
            }
            @if has_totp {
                @if has_passkey {
                    p class="login-verify-or" { "or enter a code" }
                }
                @else {
                    p class="muted recover-intro" {
                        "Enter the 6-digit code from your authenticator app "
                        "to finish signing in."
                    }
                }
                form method="post" action="/login/verify" {
                    div class="field" {
                        label for="code" { "Authenticator code" }
                        input type="text" name="code" id="code"
                              inputmode="numeric" autocomplete="one-time-code"
                              pattern="[0-9]*" maxlength="6" required;
                    }
                    button type="submit" class=(if has_passkey { "btn-secondary" } else { "btn" }) {
                        "Verify"
                    }
                }
            }
            details class="login-verify-alt" {
                summary { "Use a recovery code instead" }
                p class="muted" {
                    "If you've lost access to your second factor, enter one "
                    "of your saved recovery codes to sign in, then re-enroll "
                    "from settings."
                }
                form method="post" action="/login/verify" {
                    div class="field" {
                        label for="recovery_code" { "Recovery code" }
                        input type="text" name="recovery_code" id="recovery_code"
                              autocomplete="off" spellcheck="false" required;
                    }
                    button type="submit" class="btn-secondary" {
                        "Sign in with recovery code"
                    }
                }
            }
            p class="login-recover-link" {
                a href="/login" { "Back to sign in" }
            }
        }
    };
    shell_public("Two-step verification", content)
}

/// `GET /me` page — the authenticated user's profile. Read-only
/// summary; edits happen inside the shell-mounted account-settings
/// modal (opened by the "Manage account" button below or the user-
/// card popover's "Account settings" row).
pub fn me_page(ctx: &ChromeContext) -> Markup {
    let user = ctx.user;
    let lifecycle_label = match user.lifecycle {
        UserLifecycle::Active => "Active",
        UserLifecycle::Deactivated => "Deactivated",
        UserLifecycle::PendingInvite => "Pending invitation",
        UserLifecycle::Anonymized => "Anonymized",
    };
    let content = html! {
        div class="card me-card" {
            dl class="meta" {
                dt { "Email" }   dd { (user.email) }
                dt { "Role" }    dd { (role_label(user.instance_role)) }
                dt { "Status" }  dd { (lifecycle_label) }
            }
            div class="me-actions" {
                button type="button" class="btn"
                       data-open-modal="/modals/account-settings" {
                    "Manage account"
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
/// have to retype. The `selected_role` parameter is kept for backwards
/// signature compatibility with the modal handlers but is no longer
/// used in the UI — every invite goes out as Member.
pub fn members_invite_form_page(
    ctx: &ChromeContext,
    prefill_email: &str,
    _selected_role: InstanceRole,
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

/// Shared invite form fields — email input + CSRF token. Used by both
/// the standalone /members/invite page and the modal on /members.
/// `id_prefix` keeps the input ids unique when both forms are rendered
/// on the same page (so `<label for>` resolves to the right one).
///
/// All invites are issued as Member. Promotion to Admin or Owner
/// happens after the invitee accepts, via the change-role flow on
/// their row in the directory. That keeps the most-common path (just
/// add someone to the Hearth) to a single field, and the elevation
/// path explicit and reauth-gated.
fn invite_form_fields(
    csrf_token: &str,
    prefill_email: &str,
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
        // All invites are Member. Pinning as a hidden input keeps the
        // form serialization shape stable so the backend can keep its
        // existing `Form<InviteForm>` deserializer without an `Option`
        // around the role field.
        input type="hidden" name="role" value="member";
        // Password is collected by the shared reauth modal, not here.
        // See the `data-reauth-confirm` button on the modal flow.
        (csrf_input(csrf_token))
    }
}

// ────────────────────────────────────────────────────────────────────────
// Reauth modal — shared password-confirm gate for destructive actions
// ────────────────────────────────────────────────────────────────────────

/// Always-rendered `<dialog id="dlg-reauth">` on /members. The inner
/// `<div id="reauth-modal-content">` is HTMX's swap target; on wrong
/// password the server returns [`reauth_modal_content`] with an error
/// banner, keeping the modal open. On right password the server
/// responds with `HX-Redirect: /members?action=...` so HTMX navigates
/// the page.
///
/// The form's `action` attribute is empty at render time; the JS
/// chain in `REAUTH_CHAIN_JS` sets both `action` and `hx-post` to
/// whichever per-row action URL the operator initiated.
pub fn reauth_modal(
    ctx: &ChromeContext,
    has_totp: bool,
    has_passkey: bool,
    fresh: bool,
    critical: bool,
) -> Markup {
    html! {
        // A `critical` modal never advertises freshness, so the chain always
        // shows the factor prompt — irreversible account actions re-prove a
        // factor regardless of the ordinary 5-minute sudo window.
        dialog id="dlg-reauth" class="action-dialog reauth-dialog"
               data-sudo-fresh=[(fresh && !critical).then_some("1")] {
            div id="reauth-modal-content" {
                (reauth_modal_content(ctx, has_totp, has_passkey, None, critical))
            }
        }
    }
}

/// Inner content of the step-up reauth modal. Renders the factors the
/// account's assurance level demands (see `server-mfa.md`): a one-tap
/// passkey when enrolled, password (+ authenticator code when TOTP is
/// enrolled) otherwise. Both paths POST to `/me/reauth`, which verifies
/// the factor and mints the short-lived `sylva_sudo` grant; on success
/// the response fires `reauth-ok` and `REAUTH_CHAIN_JS` runs the original
/// action. `error` is a free-text retry message.
///
/// A password-only path is deliberately absent for a passkey-without-TOTP
/// account — falling back to the password alone would drop below the
/// account's AAL. Such a user verifies with the passkey (or signs out and
/// uses their recovery code).
pub fn reauth_modal_content(
    ctx: &ChromeContext,
    has_totp: bool,
    has_passkey: bool,
    error: Option<&str>,
    critical: bool,
) -> Markup {
    // Password path is offered when there's no passkey, or as the
    // fallback when a passkey user also has TOTP (still AAL2).
    let show_password = !has_passkey || has_totp;
    // The passkey view leads when a passkey is enrolled — unless a
    // password attempt just failed (the error belongs to the password
    // view), or there's no password fallback at all (then the passkey
    // view must stay up to host the server-side error).
    let passkey_default = has_passkey && (error.is_none() || !show_password);
    html! {
        // ── Passkey view (default when a passkey is enrolled) ──────────
        @if has_passkey {
            div class="reauth-view" data-reauth-view="passkey" hidden[!passkey_default] {
                div class="dialog-header" {
                    div class="dialog-icon dialog-icon-passkey" {
                        (fingerprint_icon())
                    }
                    button type="button" class="dialog-close" data-close-dialog
                           aria-label="Close" {
                        (close_icon())
                    }
                }
                h2 class="dialog-center-title" { "Confirm it's you" }
                p class="dialog-description dialog-center-text" {
                    "Use your passkey to continue."
                }
                // Hidden form holding the assertion; submitted by WEBAUTHN_JS
                // (the [data-passkey-auth] handler) after the get-ceremony.
                // REAUTH_CHAIN_JS auto-triggers the button when this view
                // opens, so the OS prompt appears without an extra click.
                form id="form-reauth-passkey" hx-post="/me/reauth"
                     hx-target="#reauth-modal-content" hx-swap="innerHTML" {
                    (csrf_input(ctx.csrf_token))
                    @if critical { input type="hidden" name="critical" value="1"; }
                    input type="hidden" name="challenge_id";
                    input type="hidden" name="passkey";
                }
                @if let Some(msg) = error {
                    p class="error" id="passkey-error" { (msg) }
                } @else {
                    p class="error" id="passkey-error" hidden {}
                }
                button type="button" class="btn login-passkey-btn reauth-passkey-btn"
                       data-passkey-auth="/me/reauth/passkey/start"
                       data-passkey-form="form-reauth-passkey" {
                    "Verify with passkey"
                }
                @if show_password {
                    button type="button" class="reauth-switch-link"
                           data-reauth-show-password {
                        "Use password instead"
                    }
                } @else {
                    p class="muted reauth-note" {
                        "Lost access to your passkey? Sign out and use your "
                        "saved recovery code to get back in."
                    }
                }
            }
        }

        // ── Password (+ TOTP) view ─────────────────────────────────────
        @if show_password {
            div class="reauth-view" data-reauth-view="password" hidden[passkey_default] {
                div class="dialog-header" {
                    div class="dialog-icon dialog-icon-shield" {
                        (shield_icon())
                    }
                    button type="button" class="dialog-close" data-close-dialog
                           aria-label="Close" {
                        (close_icon())
                    }
                }
                h2 class="dialog-center-title" { "Confirm it's you" }
                p class="dialog-description dialog-center-text" {
                    @if has_totp {
                        "Enter your password and authenticator code to continue."
                    } @else {
                        "Enter your password to continue."
                    }
                }
                @if let Some(msg) = error {
                    p class="error" { (msg) }
                }
                form id="form-reauth" hx-post="/me/reauth"
                     hx-target="#reauth-modal-content" hx-swap="innerHTML" {
                    (csrf_input(ctx.csrf_token))
                    @if critical { input type="hidden" name="critical" value="1"; }
                    div class="field" {
                        label for="reauth-password" { "Password" }
                        input type="password" id="reauth-password" name="password"
                              autocomplete="current-password" required;
                    }
                    @if has_totp {
                        div class="field" {
                            label for="reauth-code" { "Authenticator code" }
                            input type="text" id="reauth-code" name="code"
                                  inputmode="numeric" autocomplete="one-time-code"
                                  pattern="[0-9]*" maxlength="6" required;
                        }
                    }
                    div class="dialog-actions" {
                        button type="button" class="btn-secondary" data-close-dialog {
                            "Cancel"
                        }
                        button type="submit" class="btn" { "Verify" }
                    }
                }
                @if has_passkey {
                    button type="button" class="reauth-switch-link"
                           data-reauth-show-passkey {
                        "Use a passkey instead"
                    }
                }
            }
        }
    }
}

/// Confirmation rendered into the (kept-open) reauth modal after a
/// successful password change. Keeps the account-settings modal open
/// behind it rather than navigating away, so the operator sees the
/// change land. The current session stays signed in; others were
/// revoked server-side.
pub fn password_changed_success_content() -> Markup {
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
        h2 class="dialog-center-title" { "Password updated" }
        p class="dialog-description dialog-center-text" {
            "Your password has been changed. Other devices have been "
            "signed out; this one stays active."
        }
        div class="dialog-actions dialog-actions-centered" {
            button type="button" class="btn" data-close-dialog { "Done" }
        }
        // Out-of-band resets for the settings form left open behind this
        // modal: clear the typed password and re-disable the header button.
        (change_password_input(true))
        (change_password_button(true))
    }
}

/// Confirmation shown in the (kept-open) reauth modal after a second
/// factor (authenticator or passkey) is removed through the reauth chain.
/// The settings section behind it is refreshed out-of-band by the handler.
/// A neutral shield puck — removing a factor is a security downgrade, not a
/// celebratory success.
pub fn factor_removed_content(title: &str, message: &str) -> Markup {
    html! {
        div class="dialog-header" {
            div class="dialog-icon dialog-icon-shield" {
                (shield_icon())
            }
            button type="button" class="dialog-close" data-close-dialog
                   aria-label="Close" {
                (close_icon())
            }
        }
        h2 class="dialog-center-title" { (title) }
        p class="dialog-description dialog-center-text" { (message) }
        div class="dialog-actions dialog-actions-centered" {
            button type="button" class="btn" data-close-dialog { "Done" }
        }
    }
}

/// Laptop icon — leading glyph on the "Devices" tab. Reads as
/// "a device the user signs into". Stroke uses `currentColor`.
fn laptop_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="18" height="18" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            rect x="3" y="4" width="18" height="12" rx="2" ry="2" {}
            line x1="2" y1="20" x2="22" y2="20" {}
        }
    }
}

/// Key icon — leading glyph on the "Authenticators" tab. The
/// classic "shared secret" metaphor reads more universally than
/// the digit-grid alternative (which conflates with the 2FA code
/// itself rather than the factor).
fn key_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="18" height="18" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            path d="M21 2l-9.6 9.6" {}
            circle cx="7.5" cy="15.5" r="5.5" {}
            path d="M21 2l-2.5 2.5L21 7l-3 3-2.5-2.5" {}
        }
    }
}

/// Mobile-device glyph — leads the authenticators section + each row,
/// since TOTP codes come from a phone app (or password manager).
fn device_mobile_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="18" height="18" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            rect x="6" y="2" width="12" height="20" rx="2.5" {}
            path d="M11 18h2" {}
        }
    }
}

/// Circled-i info glyph for explanatory cards.
fn info_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="18" height="18" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            circle cx="12" cy="12" r="10" {}
            path d="M12 16v-4" {}
            path d="M12 8h.01" {}
        }
    }
}

/// Pencil glyph for the per-authenticator rename affordance.
fn pencil_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            path d="M12 20h9" {}
            path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z" {}
        }
    }
}


/// Database-cylinder icon — leading glyph on the "Data Control" tab
/// of the account-settings modal. Three stacked ovals approximating a
/// classic relational-database glyph; reads as "data" without forcing
/// us to commit to a more specific metaphor. Stroke uses
/// `currentColor`.
fn database_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="18" height="18" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            ellipse cx="12" cy="5" rx="9" ry="3" {}
            path d="M3 5v6c0 1.66 4.03 3 9 3s9-1.34 9-3V5" {}
            path d="M3 11v6c0 1.66 4.03 3 9 3s9-1.34 9-3v-6" {}
        }
    }
}

/// 22px shield icon for the reauth modal's feature-icon slot.
fn shield_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="22" height="22" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" {}
        }
    }
}

pub(crate) fn invite_modal(ctx: &ChromeContext) -> Markup {
    html! {
        // `action-dialog-centered` so invite_modal_content_form + the
        // post-create / post-reissue success bodies all render with
        // the same centered icon + centered title treatment as the
        // rest of the dialog set (delete, purge, veto, reissue confirm).
        dialog id="dlg-invite" class="action-dialog action-dialog-centered invite-dialog" {
            div id="invite-modal-content" {
                (invite_modal_content_form(ctx, "", InstanceRole::Member, None))
            }
        }
    }
}

/// `dlg-account-settings` — the global account settings modal. Opens
/// from the user-card popover's "Account settings" row and the /me
/// page's "Manage account" button (both via `data-open-dialog` →
/// `DIALOG_JS`). Mounted in every authed shell via a `<template>`
/// next to the invite + reauth ones, so it's available regardless of
/// the page the operator is on.
///
/// Layout is a **left-rail tab nav + right pane**. Tabs:
///
/// - **Profile** — display name (HTMX inline save) + email
///   (reauth-chained: clicking Update email hands off to `dlg-reauth`,
///   the operator re-enters their password there, and on success the
///   handler HX-Redirects to `/me`).
/// - **Security** (placeholder) — change password, sessions, etc.
/// - **Data Control** (placeholder) — recovery code, export,
///   account deletion.
///
/// Each panel's content lives in a `data-settings-panel="<tab>"`
/// container; `SETTINGS_TABS_JS` swaps `.settings-panel-active` +
/// `.settings-tab-active` on click. No URL state — operator's choice
/// is per-open, not persisted.
#[allow(clippy::too_many_arguments)]
pub fn account_settings_modal(
    ctx: &ChromeContext,
    recovery_meta: Option<&auth::user_recovery_code::UserRecoveryCodeRow>,
    totp_creds: &[auth::user_totp::TotpCredential],
    passkey_creds: &[server::webauthn::WebauthnCredentialRow],
    passkey_available: bool,
    sessions: &[auth::Session],
    current_session_id: uuid::Uuid,
    now: chrono::DateTime<chrono::Utc>,
    last_owner_blocked: bool,
) -> Markup {
    html! {
        dialog id="dlg-account-settings"
               class="action-dialog action-dialog-large settings-dialog" {
            div class="settings-header" {
                div class="settings-header-title" {
                    span class="settings-header-icon" aria-hidden="true" {
                        (settings_icon())
                    }
                    div class="settings-header-text" {
                        h2 { "Account settings" }
                        p class="settings-header-tagline" {
                            "Manage your preferences."
                        }
                    }
                }
                div class="settings-header-actions" {
                    // Sign-out lives at the top right of the modal
                    // so it's reachable from anywhere in the
                    // settings flow without backing out to the
                    // user-card popover. CSRF-protected like the
                    // user-card variant; same `/logout` target.
                    form method="post" action="/logout"
                         class="settings-header-signout-form" {
                        (csrf_input(ctx.csrf_token))
                        button type="submit"
                               class="btn-secondary settings-header-signout" {
                            (signout_icon())
                            span { "Sign out" }
                        }
                    }
                    button type="button" class="dialog-close"
                           data-close-dialog aria-label="Close" {
                        (close_icon())
                    }
                }
            }
            div class="settings-layout" {
                nav class="settings-tabs" role="tablist"
                    aria-label="Account settings sections" {
                    button type="button"
                           class="settings-tab settings-tab-active"
                           role="tab" aria-selected="true"
                           data-settings-tab="profile" {
                        span class="settings-tab-icon" { (user_icon()) }
                        span { "Profile" }
                    }
                    button type="button" class="settings-tab"
                           role="tab" aria-selected="false"
                           data-settings-tab="security" {
                        span class="settings-tab-icon" { (shield_icon()) }
                        span { "Security" }
                    }
                    button type="button" class="settings-tab"
                           role="tab" aria-selected="false"
                           data-settings-tab="devices" {
                        span class="settings-tab-icon" { (laptop_icon()) }
                        span { "Devices" }
                    }
                    button type="button" class="settings-tab"
                           role="tab" aria-selected="false"
                           data-settings-tab="data" {
                        span class="settings-tab-icon" { (database_icon()) }
                        span { "Data Control" }
                    }
                }
                div class="settings-panes" {
                    div class="settings-panel settings-panel-active"
                        role="tabpanel"
                        data-settings-panel="profile" {
                        (settings_profile_panel(ctx))
                    }
                    div class="settings-panel"
                        role="tabpanel"
                        data-settings-panel="security" {
                        (settings_security_panel(ctx, totp_creds, passkey_creds, passkey_available))
                    }
                    div class="settings-panel"
                        role="tabpanel"
                        data-settings-panel="devices" {
                        (sessions_section(ctx, sessions, current_session_id, now, SectionMode::Normal, false))
                    }
                    div class="settings-panel"
                        role="tabpanel"
                        data-settings-panel="data" {
                        (settings_data_panel(ctx, recovery_meta, last_owner_blocked))
                    }
                }
            }
        }
    }
}

/// Profile panel. One section card ("Account Information") with two
/// rows inside — display name (HTMX inline save) and email (reauth-
/// chained). The rows split on the reauth axis: the display name save
/// is frictionless; the email save funnels through `dlg-reauth`.
fn settings_profile_panel(ctx: &ChromeContext) -> Markup {
    html! {
        section class="settings-section" {
            div class="settings-section-header" {
                span class="settings-section-icon" aria-hidden="true" {
                    (user_icon())
                }
                div {
                    h3 { "Account Information" }
                    p class="settings-section-tagline" {
                        "Manage your identity and sign-in credentials."
                    }
                }
            }
            div class="settings-section-body" {
                div id="form-settings-name-wrap" {
                    (settings_name_form(ctx, None))
                }
                div class="settings-row-divider" {}
                div id="form-settings-email-wrap" {
                    (settings_email_form(ctx))
                }
            }
        }
    }
}

/// Eye glyph — "show password". Paired with [`eye_off_icon`] in the
/// password field's reveal toggle (CSS swaps which one is visible).
fn eye_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="18" height="18" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" {}
            circle cx="12" cy="12" r="3" {}
        }
    }
}

/// Eye-with-slash glyph — "hide password" (shown while the password is
/// revealed).
fn eye_off_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="18" height="18" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" {}
            path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" {}
            path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" {}
            line x1="2" x2="22" y1="2" y2="22" {}
        }
    }
}

/// The new-password input for the Security tab, with an inline show/hide
/// (eye) toggle in place of a separate confirm field. `oob` makes it an
/// `hx-swap-oob` carrier so a successful change can reset the field in
/// the still-open settings modal.
fn change_password_input(oob: bool) -> Markup {
    html! {
        div class="password-input-wrap" id="change-pw-field"
            hx-swap-oob=[oob.then_some("true")] {
            input type="password" id="change-pw-new" name="new_password"
                  data-pw-gate="form-change-password"
                  autocomplete="new-password" minlength="8"
                  placeholder="New password" required;
            button type="button" class="password-toggle"
                   data-pw-toggle="change-pw-new" aria-label="Show password" {
                span class="pw-eye" { (eye_icon()) }
                span class="pw-eye-off" { (eye_off_icon()) }
            }
        }
    }
}

/// The Change-password action button, rendered in the section header
/// (mirrors the authenticator section's Add button). Starts disabled —
/// `CHANGE_PASSWORD_GATE_JS` enables it once the field holds 8+ chars.
/// `oob` resets it back to disabled after a successful change.
fn change_password_button(oob: bool) -> Markup {
    html! {
        button type="button" id="change-pw-btn" class="btn-secondary"
               hx-swap-oob=[oob.then_some("true")]
               data-reauth-confirm="form-change-password"
               data-keep-source-open
               disabled {
            (key_icon())
            span { "Change password" }
        }
    }
}

/// Security panel — the Change password section. A single new-password
/// field (with a show/hide eye toggle) lives in the body; the action
/// button sits in the section header (like the authenticator section).
/// The current password is collected by the reauth modal. The button
/// stays disabled until the new password is at least 8 chars (see
/// `CHANGE_PASSWORD_GATE_JS`).
fn settings_security_panel(
    ctx: &ChromeContext,
    totp_creds: &[auth::user_totp::TotpCredential],
    passkey_creds: &[server::webauthn::WebauthnCredentialRow],
    passkey_available: bool,
) -> Markup {
    html! {
        section class="settings-section" {
            div class="settings-section-header settings-section-header-actions" {
                div class="settings-section-heading" {
                    span class="settings-section-icon" aria-hidden="true" {
                        (shield_icon())
                    }
                    div {
                        h3 { "Password" }
                        p class="settings-section-tagline" {
                            "Change the password you use to sign in."
                        }
                    }
                }
                // The button references the body form by id, so it can live
                // in the header (outside the form) and still drive the chain.
                (change_password_button(false))
            }
            div class="settings-section-body" {
                form id="form-change-password"
                     class="settings-row"
                     method="post"
                     action="/me/password" {
                    (csrf_input(ctx.csrf_token))
                    div class="settings-row-label" {
                        label for="change-pw-new" { "New password" }
                        p class="settings-row-hint" {
                            "At least 8 characters. Changing it signs out "
                            "your other devices."
                        }
                    }
                    div class="settings-row-control" {
                        (change_password_input(false))
                    }
                }
            }
        }

        hr class="settings-divider";

        (totp_authenticators_section(ctx, totp_creds, SectionMode::Normal, false))

        hr class="settings-divider";

        (passkey_credentials_section(ctx, passkey_creds, SectionMode::Normal, passkey_available, false))
    }
}

/// Which row of the authenticators island is in a special inline state.
/// Drives the HTMX-swap re-renders for rename / delete-confirm.
#[derive(Clone, Copy)]
pub enum SectionMode {
    Normal,
    Renaming(uuid::Uuid),
    ConfirmDelete(uuid::Uuid),
}

/// The "Registered Authenticators" island — an HTMX-swappable
/// `#totp-section` holding the list of enrolled authenticators, the
/// reauth-chained "Add Authenticator" button, and the explainer card.
/// Rename / delete re-render this whole section into itself.
pub fn totp_authenticators_section(
    ctx: &ChromeContext,
    creds: &[auth::user_totp::TotpCredential],
    mode: SectionMode,
    oob: bool,
) -> Markup {
    let at_max = creds.len() as i64 >= auth::user_totp::MAX_AUTHENTICATORS;
    // When delivered as a secondary (out-of-band) part of another
    // response — e.g. refreshing the list inside the still-open settings
    // modal after an enrollment that happened in the reauth modal.
    let oob_attr = oob.then_some("true");
    html! {
        section id="totp-section" class="settings-section" hx-swap-oob=[oob_attr] {
            div class="settings-section-header settings-section-header-actions" {
                div class="settings-section-heading" {
                    span class="settings-section-icon" aria-hidden="true" {
                        (device_mobile_icon())
                    }
                    div {
                        h3 { "Registered Authenticators" }
                        p class="settings-section-tagline" {
                            "Verification codes using apps or password managers."
                        }
                    }
                }
                // Reauth-chained add. The hidden form is the reauth source;
                // `display:contents` keeps it from disturbing the header flex.
                form id="form-totp-start" method="post" action="/me/totp/start"
                     style="display:contents" {
                    (csrf_input(ctx.csrf_token))
                    // keep-source-open: the settings modal stays open
                    // behind the reauth/QR modal; the enrollment response
                    // refreshes this list in place via hx-swap-oob.
                    button type="button" class="btn-secondary"
                           data-reauth-confirm="form-totp-start"
                           data-keep-source-open
                           disabled[at_max] {
                        (key_icon())
                        span { "Add Authenticator" }
                    }
                }
            }
            div class="settings-section-body" {
                @if creds.is_empty() {
                    p class="settings-row-hint totp-empty" {
                        "No authenticators yet. Add one to require a 6-digit "
                        "code at sign-in."
                    }
                } @else {
                    ul class="totp-list" {
                        @for cred in creds {
                            (totp_row(ctx, cred, mode, creds.len() == 1))
                        }
                    }
                }
                @if at_max {
                    p class="settings-row-hint" {
                        "You've reached the maximum of "
                        (auth::user_totp::MAX_AUTHENTICATORS)
                        " authenticators."
                    }
                }
                div class="settings-info" {
                    span class="settings-info-icon" aria-hidden="true" {
                        (info_icon())
                    }
                    div {
                        h4 { "What are authenticators?" }
                        p {
                            "Authenticators provide a second factor of "
                            "authentication (2FA) using temporary verification "
                            "codes (TOTP). These codes are 6 digits and refresh "
                            "every 30 seconds."
                        }
                    }
                }
            }
        }
    }
}

/// A single authenticator row, rendered per the active section `mode`.
fn totp_row(
    ctx: &ChromeContext,
    cred: &auth::user_totp::TotpCredential,
    mode: SectionMode,
    is_last: bool,
) -> Markup {
    let id = cred.id;
    match mode {
        SectionMode::Renaming(target) if target == id => html! {
            li class="totp-row totp-row-editing" {
                form class="totp-rename-form"
                     hx-post=(format!("/me/totp/{id}/rename"))
                     hx-target="#totp-section"
                     hx-swap="outerHTML" {
                    (csrf_input(ctx.csrf_token))
                    input type="text" name="label" value=(cred.label)
                          maxlength="60" required autofocus
                          class="totp-rename-input"
                          aria-label="Authenticator name";
                    div class="totp-row-actions" {
                        button type="submit" class="btn-secondary" { "Save" }
                        button type="button" class="btn-secondary"
                               hx-get="/me/totp/section"
                               hx-target="#totp-section" hx-swap="outerHTML" {
                            "Cancel"
                        }
                    }
                }
            }
        },
        SectionMode::ConfirmDelete(target) if target == id => html! {
            li class="totp-row totp-row-confirm" {
                div class="totp-row-main" {
                    span class="totp-row-name" { "Remove “" (cred.label) "”?" }
                    span class="totp-row-meta" {
                        @if is_last {
                            "This is your last authenticator — removing it "
                            "turns off two-factor sign-in."
                        } @else {
                            "You'll need to re-add it to use it again."
                        }
                    }
                }
                div class="totp-row-actions" {
                    // Removing a factor weakens the account, so it's reauth-
                    // gated like adding one: the chain mints a sudo grant,
                    // then the handler refreshes this section out-of-band.
                    form id=(format!("form-totp-delete-{id}")) method="post"
                         action=(format!("/me/totp/{id}/delete"))
                         style="display:contents" {
                        (csrf_input(ctx.csrf_token))
                        button type="button" class="btn-danger"
                               data-reauth-confirm=(format!("form-totp-delete-{id}"))
                               data-keep-source-open {
                            "Remove"
                        }
                    }
                    button type="button" class="btn-secondary"
                           hx-get="/me/totp/section"
                           hx-target="#totp-section" hx-swap="outerHTML" {
                        "Cancel"
                    }
                }
            }
        },
        _ => html! {
            li class="totp-row" {
                span class="totp-row-icon" aria-hidden="true" {
                    (device_mobile_icon())
                }
                div class="totp-row-main" {
                    span class="totp-row-name" { (cred.label) }
                    span class="totp-row-meta" {
                        "Added " (cred.created_at.format("%b %-d, %Y").to_string())
                        @match cred.last_used_at {
                            Some(used) => {
                                " • Last used "
                                (used.format("%b %-d, %Y").to_string())
                            }
                            None => { " • Never used" }
                        }
                    }
                }
                div class="totp-row-actions" {
                    button type="button" class="icon-btn"
                           aria-label="Rename authenticator"
                           hx-get=(format!("/me/totp/{id}/edit"))
                           hx-target="#totp-section" hx-swap="outerHTML" {
                        (pencil_icon())
                    }
                    button type="button" class="icon-btn icon-btn-danger"
                           aria-label="Remove authenticator"
                           hx-get=(format!("/me/totp/{id}/confirm-delete"))
                           hx-target="#totp-section" hx-swap="outerHTML" {
                        (trash_icon())
                    }
                }
            }
        },
    }
}

/// Fingerprint glyph — leads the Passkeys section + each passkey row.
/// Proper concentric-ridge fingerprint (Lucide-style), matching the
/// other icons' stroke conventions.
fn fingerprint_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="18" height="18" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4" {}
            path d="M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2" {}
            path d="M17.29 21.02c.12-.6.43-2.3.5-3.02" {}
            path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" {}
            path d="M8.65 22c.21-.66.45-1.32.57-2" {}
            path d="M14 13.12c0 2.38 0 6.38-1 8.88" {}
            path d="M2 16h.01" {}
            path d="M21.8 16c.2-2 .131-5.354 0-6" {}
            path d="M9 6.8a6 6 0 0 1 9 5.2c0 .47 0 1.17-.02 2" {}
        }
    }
}

/// The "Passkeys" island — HTMX-swappable `#passkey-section` mirroring the
/// authenticators section. Lists enrolled passkeys with rename/remove, a
/// reauth-chained "Add passkey" button (when WebAuthn is configurable),
/// and an explainer card. `available` is false when the RP can't be built
/// (e.g. a bare-IP base URL) — then we explain instead of offering enroll.
pub fn passkey_credentials_section(
    ctx: &ChromeContext,
    creds: &[server::webauthn::WebauthnCredentialRow],
    mode: SectionMode,
    available: bool,
    oob: bool,
) -> Markup {
    let at_max = creds.len() as i64 >= server::webauthn::MAX_PASSKEYS;
    let oob_attr = oob.then_some("true");
    html! {
        section id="passkey-section" class="settings-section" hx-swap-oob=[oob_attr] {
            div class="settings-section-header settings-section-header-actions" {
                div class="settings-section-heading" {
                    span class="settings-section-icon" aria-hidden="true" {
                        (fingerprint_icon())
                    }
                    div {
                        h3 { "Registered Passkeys" }
                        p class="settings-section-tagline" {
                            "Passwordless authentication using biometrics "
                            "or security keys."
                        }
                    }
                }
                @if available {
                    form id="form-passkey-start" method="post" action="/me/passkey/start"
                         style="display:contents" {
                        (csrf_input(ctx.csrf_token))
                        button type="button" class="btn-secondary"
                               data-reauth-confirm="form-passkey-start"
                               data-keep-source-open
                               disabled[at_max] {
                            (fingerprint_icon())
                            span { "Add passkey" }
                        }
                    }
                }
            }
            div class="settings-section-body" {
                @if !available {
                    p class="settings-row-hint" {
                        "Passkeys need this site to be reached over https or "
                        "at a hostname like localhost (not a bare IP "
                        "address). Set SYLVA_PUBLIC_BASE_URL accordingly to "
                        "enable them."
                    }
                } @else {
                    @if creds.is_empty() {
                        p class="settings-row-hint totp-empty" {
                            "No passkeys yet. Add one for passwordless, "
                            "phishing-resistant sign-in."
                        }
                    } @else {
                        ul class="totp-list" {
                            @for cred in creds {
                                (passkey_row(ctx, cred, mode, creds.len() == 1))
                            }
                        }
                    }
                    @if at_max {
                        p class="settings-row-hint" {
                            "You've reached the maximum of "
                            (server::webauthn::MAX_PASSKEYS)
                            " passkeys."
                        }
                    }
                }
                div class="settings-info" {
                    span class="settings-info-icon" aria-hidden="true" {
                        (info_icon())
                    }
                    div {
                        h4 { "What are passkeys?" }
                        p {
                            "Passkeys let you sign in with your device's "
                            "fingerprint, face, screen lock, or a security "
                            "key instead of (or on top of) a password. "
                            "They can't be phished or reused across sites."
                        }
                    }
                }
            }
        }
    }
}

fn passkey_row(
    ctx: &ChromeContext,
    cred: &server::webauthn::WebauthnCredentialRow,
    mode: SectionMode,
    is_last: bool,
) -> Markup {
    let id = cred.id;
    match mode {
        SectionMode::Renaming(target) if target == id => html! {
            li class="totp-row totp-row-editing" {
                form class="totp-rename-form"
                     hx-post=(format!("/me/passkey/{id}/rename"))
                     hx-target="#passkey-section"
                     hx-swap="outerHTML" {
                    (csrf_input(ctx.csrf_token))
                    input type="text" name="label" value=(cred.label)
                          maxlength="60" required autofocus
                          class="totp-rename-input"
                          aria-label="Passkey name";
                    div class="totp-row-actions" {
                        button type="submit" class="btn-secondary" { "Save" }
                        button type="button" class="btn-secondary"
                               hx-get="/me/passkey/section"
                               hx-target="#passkey-section" hx-swap="outerHTML" {
                            "Cancel"
                        }
                    }
                }
            }
        },
        SectionMode::ConfirmDelete(target) if target == id => html! {
            li class="totp-row totp-row-confirm" {
                div class="totp-row-main" {
                    span class="totp-row-name" { "Remove “" (cred.label) "”?" }
                    span class="totp-row-meta" {
                        @if is_last {
                            "This is your last passkey."
                        } @else {
                            "You'll need to re-add it to use it again."
                        }
                    }
                }
                div class="totp-row-actions" {
                    // Reauth-gated like the authenticator removal above.
                    form id=(format!("form-passkey-delete-{id}")) method="post"
                         action=(format!("/me/passkey/{id}/delete"))
                         style="display:contents" {
                        (csrf_input(ctx.csrf_token))
                        button type="button" class="btn-danger"
                               data-reauth-confirm=(format!("form-passkey-delete-{id}"))
                               data-keep-source-open {
                            "Remove"
                        }
                    }
                    button type="button" class="btn-secondary"
                           hx-get="/me/passkey/section"
                           hx-target="#passkey-section" hx-swap="outerHTML" {
                        "Cancel"
                    }
                }
            }
        },
        _ => html! {
            li class="totp-row" {
                span class="totp-row-icon" aria-hidden="true" {
                    (fingerprint_icon())
                }
                div class="totp-row-main" {
                    span class="totp-row-name" { (cred.label) }
                    span class="totp-row-meta" {
                        "Added " (cred.created_at.format("%b %-d, %Y").to_string())
                        @match cred.last_used_at {
                            Some(used) => {
                                " • Last used "
                                (used.format("%b %-d, %Y").to_string())
                            }
                            None => { " • Never used" }
                        }
                    }
                }
                div class="totp-row-actions" {
                    button type="button" class="icon-btn"
                           aria-label="Rename passkey"
                           hx-get=(format!("/me/passkey/{id}/edit"))
                           hx-target="#passkey-section" hx-swap="outerHTML" {
                        (pencil_icon())
                    }
                    button type="button" class="icon-btn icon-btn-danger"
                           aria-label="Remove passkey"
                           hx-get=(format!("/me/passkey/{id}/confirm-delete"))
                           hx-target="#passkey-section" hx-swap="outerHTML" {
                        (trash_icon())
                    }
                }
            }
        },
    }
}

/// Passkey enrollment fragment, swapped into the reauth modal after a
/// reauthenticated `POST /me/passkey/start`. Embeds the WebAuthn creation
/// options (JSON) + the challenge id; `WEBAUTHN_JS` runs the
/// `navigator.credentials.create` ceremony on "Create passkey", fills the
/// hidden credential field, and submits to finish.
pub fn passkey_enroll_modal_content(
    options_json: &str,
    challenge_id: uuid::Uuid,
    csrf_token: &str,
) -> Markup {
    html! {
        div class="dialog-header" {
            div class="dialog-icon" { (fingerprint_icon()) }
            button type="button" class="dialog-close" data-close-dialog
                   aria-label="Close" {
                (close_icon())
            }
        }
        h2 class="dialog-center-title" { "Add a passkey" }
        p class="dialog-description dialog-center-text" {
            "Name it, then follow your browser's prompt to create the "
            "passkey with your fingerprint, face, screen lock, or security "
            "key."
        }
        script type="application/json" id="passkey-options" {
            (maud::PreEscaped(options_json.to_string()))
        }
        form id="form-passkey-finish"
             hx-post="/me/passkey/finish"
             hx-target="#reauth-modal-content"
             hx-swap="innerHTML" {
            (csrf_input(csrf_token))
            input type="hidden" name="challenge_id" value=(challenge_id.to_string());
            input type="hidden" name="credential" id="passkey-credential";
            div class="field" {
                label for="passkey-label" { "Name" }
                input type="text" name="label" id="passkey-label"
                      value="Passkey" maxlength="60" required
                      autocomplete="off"
                      placeholder="e.g. MacBook Touch ID, YubiKey";
            }
            p class="error" id="passkey-error" hidden {}
            div class="dialog-actions" {
                button type="button" class="btn" data-passkey-create {
                    "Create passkey"
                }
            }
        }
    }
}

/// Shown once a passkey is registered (swapped into the reauth modal).
pub fn passkey_enrolled_success_content() -> Markup {
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
        h2 class="dialog-center-title" { "Passkey added" }
        p class="dialog-description dialog-center-text" {
            "You can use this passkey to sign in. If you ever lose access "
            "to it, use another passkey, an authenticator code, or your "
            "recovery code."
        }
        div class="dialog-actions" {
            button type="button" class="btn" data-close-dialog {
                "Done"
            }
        }
    }
}

/// Generic error fragment for the reauth modal slot (e.g. a passkey
/// ceremony that failed server-side). Centered, with a close button.
pub fn passkey_error_content(message: &str) -> Markup {
    html! {
        div class="dialog-header" {
            div class="dialog-icon dialog-alert" { (alert_circle_icon()) }
            button type="button" class="dialog-close" data-close-dialog
                   aria-label="Close" {
                (close_icon())
            }
        }
        h2 class="dialog-center-title" { "Couldn't add passkey" }
        p class="dialog-description dialog-center-text" { (message) }
        div class="dialog-actions" {
            button type="button" class="btn" data-close-dialog { "Close" }
        }
    }
}

/// Shown when a user tries to add a passkey past the cap (near-impossible
/// — the Add button disables at the limit).
pub fn passkey_limit_reached_content() -> Markup {
    html! {
        div class="dialog-header" {
            div class="dialog-icon" { (fingerprint_icon()) }
            button type="button" class="dialog-close" data-close-dialog
                   aria-label="Close" {
                (close_icon())
            }
        }
        h2 class="dialog-center-title" { "Passkey limit reached" }
        p class="dialog-description dialog-center-text" {
            "You already have the maximum number of passkeys. Remove one "
            "before adding another."
        }
        div class="dialog-actions" {
            button type="button" class="btn" data-close-dialog { "Close" }
        }
    }
}

/// Data Control panel — currently the offline recovery code section.
/// Shows when the code was generated + last used (if a row exists),
/// and a reauth-chained "Regenerate" button. Regenerating mints a
/// fresh code (invalidating the old one) and shows it once via
/// [`recovery_code_modal_content`] swapped into the reauth modal.
fn settings_data_panel(
    ctx: &ChromeContext,
    recovery_meta: Option<&auth::user_recovery_code::UserRecoveryCodeRow>,
    last_owner_blocked: bool,
) -> Markup {
    html! {
        section class="settings-section" {
            div class="settings-section-header" {
                span class="settings-section-icon" aria-hidden="true" {
                    (database_icon())
                }
                div {
                    h3 { "Recovery code" }
                    p class="settings-section-tagline" {
                        "Your offline way back in if you forget your "
                        "password or lose a second factor."
                    }
                }
            }
            div class="settings-section-body" {
                form id="form-regenerate-recovery"
                     class="settings-row"
                     method="post"
                     action="/me/recovery-code/regenerate" {
                    (csrf_input(ctx.csrf_token))
                    div class="settings-row-label" {
                        label { "Status" }
                        (recovery_status(recovery_meta, false))
                    }
                    div class="settings-row-control" {
                        p class="settings-row-hint" {
                            "Regenerating shows a new code once and "
                            "immediately invalidates the old one. You'll "
                            "confirm it's you first."
                        }
                        div class="settings-row-actions" {
                            button type="button" class="btn-secondary"
                                   data-reauth-confirm="form-regenerate-recovery"
                                   data-keep-source-open {
                                "Regenerate"
                            }
                        }
                    }
                }
            }
        }
        // Danger zone — close your own account. Anonymize keeps the data
        // under a closed account; Delete erases everything. Both gate on a
        // forced critical re-auth, and are disabled (with a transfer-first
        // note) while the caller is the last owner with other users present.
        (account_close_section(false, last_owner_blocked))
        (account_close_section(true, last_owner_blocked))
    }
}

/// The "Status" line of the Data Control recovery section, wrapped in an
/// id'd element. `oob` makes it an `hx-swap-oob` carrier so the regenerate
/// handler can flip it from "No recovery code on file" to "Generated …"
/// in place — the new code shows in the reauth modal while this line
/// updates behind it, without the user reopening the panel.
pub fn recovery_status(
    recovery_meta: Option<&auth::user_recovery_code::UserRecoveryCodeRow>,
    oob: bool,
) -> Markup {
    html! {
        div id="recovery-status" hx-swap-oob=[oob.then_some("true")] {
            @match recovery_meta {
                Some(meta) => {
                    p class="settings-row-hint" {
                        "Generated "
                        (meta.generated_at.format("%b %-d, %Y").to_string())
                        ". "
                        @match meta.last_used_at {
                            Some(used) => {
                                "Last used "
                                (used.format("%b %-d, %Y").to_string())
                                "."
                            }
                            None => { "Never used." }
                        }
                    }
                }
                None => {
                    p class="settings-row-hint" {
                        "No recovery code on file. Generate one "
                        "now so you can recover this account later."
                    }
                }
            }
        }
    }
}

/// One Data Control "danger zone" section — Anonymize (`delete_mode =
/// false`) or Delete (`delete_mode = true`). Each is a short explainer plus
/// a button that opens the matching confirm dialog on demand
/// (`/modals/account/{anonymize|delete}`). The real gating (acknowledge +
/// type-email + forced re-auth) lives in that dialog.
fn account_close_section(delete_mode: bool, blocked: bool) -> Markup {
    let (title, tagline, hint, label, modal) = if delete_mode {
        (
            "Delete my account",
            "Permanently erase your account and everything you created \
             across the ecosystem.",
            "Everything tied to your account is removed from the server, \
             even data shared with others. This cannot be undone.",
            "Delete my account",
            "/modals/account/delete",
        )
    } else {
        (
            "Anonymize my account",
            "Close your account and strip your personal information, leaving \
             anything you took part in under a closed account.",
            "Your sign-in is removed and the account can't be reopened; your \
             data stays in place, no longer linked to you. This cannot be undone.",
            "Anonymize my account",
            "/modals/account/anonymize",
        )
    };
    html! {
        section class="settings-section settings-section-danger" {
            div class="settings-section-header" {
                span class="settings-section-icon" aria-hidden="true" {
                    @if delete_mode { (trash_icon()) } @else { (incognito_icon()) }
                }
                div {
                    h3 { (title) }
                    p class="settings-section-tagline" { (tagline) }
                }
            }
            div class="settings-section-body" {
                div class="settings-danger-row" {
                    p class="settings-row-hint" { (hint) }
                    @if blocked {
                        p class="settings-row-note" {
                            "You're the last owner. Transfer ownership to someone "
                            "first (Members \u{2192} \u{22ef} \u{2192} Change role "
                            "\u{2192} Owner), then you can close your account."
                        }
                        div class="settings-row-actions" {
                            button type="button" class="btn-danger-ghost" disabled {
                                (label)
                            }
                        }
                    } @else {
                        div class="settings-row-actions" {
                            button type="button" class="btn-danger-ghost"
                                   data-open-modal=(modal) {
                                (label)
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Inner content shown when a close is blocked because the caller is the last
/// owner with other users still present. Rendered both inside the confirm
/// dialog (`account_close_modal`, `blocked = true`) and as the server-side
/// backstop swapped into `#reauth-modal-content` if the action is reached
/// anyway.
pub fn account_close_blocked_content() -> Markup {
    html! {
        div class="dialog-header" {
            div class="dialog-icon dialog-alert" { (alert_circle_icon()) }
            button type="button" class="dialog-close" data-close-dialog
                   aria-label="Close" {
                (close_icon())
            }
        }
        h2 class="dialog-center-title" { "Transfer ownership first" }
        p class="dialog-description dialog-center-text" {
            "You're the last owner of this server. Make someone else an owner "
            "(Members \u{2192} \u{22ef} \u{2192} Change role \u{2192} Owner) before "
            "you close your account, so the instance isn't left without an "
            "administrator."
        }
        div class="dialog-actions dialog-actions-centered" {
            button type="button" class="btn" data-close-dialog { "Got it" }
        }
    }
}

/// Confirm dialog for closing your own account — fetched on demand into
/// `#modal-host` from `/modals/account/{anonymize|delete}`. Mirrors the admin
/// destructive dialogs (centered danger chrome + alert + type-to-confirm) but
/// stacks two gates before the action button enables: an "I understand"
/// checkbox (`data-close-ack`) *and* typing your own email
/// (`data-close-email`), wired by `ACCOUNT_CLOSE_GATE_JS`. The confirm button
/// then drives the **critical** re-auth (`data-reauth-critical`), which always
/// re-prompts regardless of the sudo window. When `blocked` (last owner with
/// others present), the dangerous form is replaced by a "transfer first" note.
pub fn account_close_modal(ctx: &ChromeContext, delete_mode: bool, blocked: bool) -> Markup {
    if blocked {
        let slug = if delete_mode { "delete" } else { "anonymize" };
        return html! {
            dialog id=(format!("dlg-account-{slug}"))
                   class="action-dialog action-dialog-centered" {
                (account_close_blocked_content())
            }
        };
    }
    let (slug, action, title, lead, alert, button) = if delete_mode {
        (
            "delete",
            "/me/account/delete",
            "Delete your account",
            "Everything you created across the ecosystem is permanently \
             removed, even data shared with others, leaving no trace of your \
             footprint. Your account becomes inaccessible right away.",
            "This permanently deletes your account and all of its data. It \
             cannot be undone.",
            "Delete my account",
        )
    } else {
        (
            "anonymize",
            "/me/account/anonymize",
            "Anonymize your account",
            "Your account is closed and your personal information is removed \
             from it. Anything you took part in stays in place under a closed \
             account, no longer linked to you. Your account becomes \
             inaccessible right away.",
            "This permanently closes your account. It cannot be undone.",
            "Anonymize my account",
        )
    };
    let form_id = format!("form-account-{slug}");
    let input_id = format!("confirm-email-{slug}");
    let email = &ctx.user.email;
    html! {
        dialog id=(format!("dlg-account-{slug}"))
               class="action-dialog action-dialog-centered" {
            form id=(form_id) method="post" action=(action) {
                div class="dialog-header" {
                    div class="dialog-icon dialog-icon-danger" {
                        @if delete_mode { (trash_icon()) } @else { (incognito_icon()) }
                    }
                    button type="button" class="dialog-close" data-close-dialog
                           aria-label="Close" {
                        (close_icon())
                    }
                }
                h2 class="dialog-center-title" { (title) }
                p class="dialog-description dialog-center-text" { (lead) }
                div class="dialog-alert dialog-alert-danger" role="alert" {
                    (alert_circle_icon())
                    span { (alert) }
                }
                (csrf_input(ctx.csrf_token))
                label class="confirm-checkbox-field" {
                    input type="checkbox" class="member-checkbox" data-close-ack;
                    span { "I understand this is permanent and that I won't be able to sign in again." }
                }
                div class="field confirm-name-field" {
                    label for=(input_id) {
                        "Type your email " strong { "\"" (email) "\"" } " to confirm"
                    }
                    input type="text" id=(input_id) data-close-email=(email)
                          autocomplete="off" spellcheck="false" autocapitalize="off";
                }
                div class="dialog-actions" {
                    button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                    button type="button" class="btn-danger"
                           data-reauth-confirm=(form_id)
                           data-reauth-critical
                           disabled {
                        (button)
                    }
                }
            }
        }
    }
}

/// One-time display of a freshly regenerated recovery code, swapped
/// into the reauth modal (`#reauth-modal-content`) after a successful
/// `POST /me/recovery-code/regenerate`. The code rides this single
/// HTTP response and is never re-rendered — same "shown once" contract
/// as the invite-acceptance interstitial. Reuses `INVITE_COPY_JS` via
/// the `data-copy-target` hook (loaded in the shell).
pub fn recovery_code_modal_content(recovery_code: &str) -> Markup {
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
        h2 class="dialog-center-title" { "Your new recovery code" }
        p class="dialog-description dialog-center-text" {
            "Save this somewhere safe. The previous code no longer "
            "works, and we won't show this one again."
        }
        div class="recovery-code-display" {
            input id="recovery-code"
                  type="text"
                  class="recovery-code-input"
                  value=(recovery_code)
                  readonly
                  aria-label="Account recovery code";
            button type="button" class="btn-secondary"
                   data-copy-target="recovery-code" {
                "Copy"
            }
        }
        div class="dialog-actions" {
            button type="button" class="btn" data-close-dialog {
                "Done"
            }
        }
    }
}

/// TOTP enrollment fragment, swapped into the reauth modal after a
/// reauthenticated `POST /me/totp/start`. Shows the QR (rendered server-
/// side as SVG) plus a copyable manual key, and a confirm-code form that
/// HTMX-posts back into the same modal slot. `error` re-renders inline
/// when the confirmation code didn't match.
pub fn totp_enroll_modal_content(
    qr_svg: &str,
    secret_b32: &str,
    cred_id: uuid::Uuid,
    csrf_token: &str,
    error: Option<&str>,
) -> Markup {
    html! {
        div class="dialog-header" {
            div class="dialog-icon" { (device_mobile_icon()) }
            button type="button" class="dialog-close" data-close-dialog
                   aria-label="Close" {
                (close_icon())
            }
        }
        h2 class="dialog-center-title" { "Add an authenticator" }
        p class="dialog-description dialog-center-text" {
            "Scan this with your authenticator app, name it, then enter "
            "the 6-digit code it shows to finish."
        }
        div class="totp-qr" aria-hidden="true" {
            (maud::PreEscaped(qr_svg.to_string()))
        }
        details class="login-verify-alt" {
            summary { "Can't scan? Enter this key" }
            div class="recovery-code-display" {
                input id="totp-secret"
                      type="text"
                      class="recovery-code-input"
                      value=(secret_b32)
                      readonly
                      aria-label="Authenticator setup key";
                button type="button" class="btn-secondary"
                       data-copy-target="totp-secret" {
                    "Copy"
                }
            }
        }
        form id="form-totp-confirm"
             method="post"
             action="/me/totp/confirm"
             hx-post="/me/totp/confirm"
             hx-target="#reauth-modal-content"
             hx-swap="innerHTML" {
            (csrf_input(csrf_token))
            input type="hidden" name="cred_id" value=(cred_id.to_string());
            @if let Some(msg) = error {
                p class="error" { (msg) }
            }
            div class="field" {
                label for="totp-label" { "Name" }
                input type="text" name="label" id="totp-label"
                      value="Authenticator" maxlength="60" required
                      autocomplete="off"
                      placeholder="e.g. 1Password, Ente Auth";
            }
            div class="field" {
                label for="totp-confirm-code" { "6-digit code" }
                input type="text" name="code" id="totp-confirm-code"
                      inputmode="numeric" autocomplete="one-time-code"
                      pattern="[0-9]*" maxlength="6" required;
            }
            div class="dialog-actions" {
                button type="submit" class="btn" { "Add authenticator" }
            }
        }
    }
}

/// Shown once TOTP enrollment is confirmed. Swapped into the reauth
/// modal slot in place of the QR fragment.
pub fn totp_enrolled_success_content() -> Markup {
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
        h2 class="dialog-center-title" { "Authenticator added" }
        p class="dialog-description dialog-center-text" {
            "You'll enter a code from one of your authenticators the next "
            "time you sign in. If you ever lose access, use your recovery "
            "code to get back in."
        }
        div class="dialog-actions" {
            button type="button" class="btn" data-close-dialog {
                "Done"
            }
        }
    }
}

/// Shown when a user tries to add an authenticator past the cap. Only
/// reachable by a direct POST (the Add button disables itself at the
/// limit).
pub fn totp_limit_reached_content() -> Markup {
    html! {
        div class="dialog-header" {
            div class="dialog-icon" { (device_mobile_icon()) }
            button type="button" class="dialog-close" data-close-dialog
                   aria-label="Close" {
                (close_icon())
            }
        }
        h2 class="dialog-center-title" { "Authenticator limit reached" }
        p class="dialog-description dialog-center-text" {
            "You already have the maximum number of authenticators. Remove "
            "one before adding another."
        }
        div class="dialog-actions" {
            button type="button" class="btn" data-close-dialog {
                "Close"
            }
        }
    }
}

/// Turn a raw `User-Agent` into a friendly "Browser on OS" label for the
/// Devices panel. Hand-rolled heuristics (no UA-parser dependency) — good
/// enough to tell a Chrome-on-Windows session from a Safari-on-iPhone one.
/// Order matters: Edge/Opera UAs also contain "Chrome", and Chrome UAs also
/// contain "Safari", so the more specific tokens are checked first.
pub fn device_label(user_agent: &str) -> String {
    if user_agent.trim().is_empty() {
        return "Unknown device".to_string();
    }
    let browser = if user_agent.contains("Edg/") || user_agent.contains("Edge") {
        Some("Edge")
    } else if user_agent.contains("OPR/") || user_agent.contains("Opera") {
        Some("Opera")
    } else if user_agent.contains("Chrome/") || user_agent.contains("Chromium") {
        Some("Chrome")
    } else if user_agent.contains("Firefox/") {
        Some("Firefox")
    } else if user_agent.contains("Safari/") {
        Some("Safari")
    } else {
        None
    };
    let os = if user_agent.contains("Windows") {
        Some("Windows")
    } else if user_agent.contains("iPhone") || user_agent.contains("iPad") {
        Some("iOS")
    } else if user_agent.contains("Mac OS X") || user_agent.contains("Macintosh") {
        Some("macOS")
    } else if user_agent.contains("Android") {
        Some("Android")
    } else if user_agent.contains("Linux") {
        Some("Linux")
    } else {
        None
    };
    match (browser, os) {
        (Some(b), Some(o)) => format!("{b} on {o}"),
        (Some(b), None) => b.to_string(),
        (None, Some(o)) => o.to_string(),
        (None, None) => "Unknown device".to_string(),
    }
}

/// True when the User-Agent looks like a phone/tablet (picks the row icon).
fn device_is_mobile(user_agent: &str) -> bool {
    user_agent.contains("Android")
        || user_agent.contains("iPhone")
        || user_agent.contains("iPad")
}

/// Coarse "x ago" for the last-active line. Past the week mark it falls back
/// to an absolute date. `now` is passed in so the function stays pure.
fn relative_time(then: chrono::DateTime<chrono::Utc>, now: chrono::DateTime<chrono::Utc>) -> String {
    let secs = (now - then).num_seconds().max(0);
    let plural = |n: i64| if n == 1 { "" } else { "s" };
    if secs < 60 {
        "just now".to_string()
    } else if secs < 3600 {
        let m = secs / 60;
        format!("{m} minute{} ago", plural(m))
    } else if secs < 86_400 {
        let h = secs / 3600;
        format!("{h} hour{} ago", plural(h))
    } else if secs < 7 * 86_400 {
        let d = secs / 86_400;
        format!("{d} day{} ago", plural(d))
    } else {
        then.format("%b %-d, %Y").to_string()
    }
}

/// The Devices panel island (`#devices-section`): one row per active session
/// with a "Sign out" action, the current session flagged "This device", and
/// a "Sign out all other devices" header action. `oob` makes it an
/// `hx-swap-oob` carrier so the revoke handlers can refresh it in place.
/// Sign-out is direct HTMX (CSRF-only, no reauth — it's a protective action).
pub fn sessions_section(
    ctx: &ChromeContext,
    sessions: &[auth::Session],
    current_session_id: uuid::Uuid,
    now: chrono::DateTime<chrono::Utc>,
    mode: SectionMode,
    oob: bool,
) -> Markup {
    let has_others = sessions.iter().any(|s| s.id != current_session_id);
    let oob_attr = oob.then_some("true");
    html! {
        section id="devices-section" class="settings-section" hx-swap-oob=[oob_attr] {
            div class="settings-section-header settings-section-header-actions" {
                div class="settings-section-heading" {
                    span class="settings-section-icon" aria-hidden="true" {
                        (laptop_icon())
                    }
                    div {
                        h3 { "Devices" }
                        p class="settings-section-tagline" {
                            "Browsers and devices signed in to your account."
                        }
                    }
                }
                // No `id` on the form → the reauth Enter-handler skips it and
                // htmx posts it directly (CSRF rides along from the input).
                @if has_others {
                    form method="post" action="/me/sessions/revoke-others"
                         hx-post="/me/sessions/revoke-others"
                         hx-target="#devices-section" hx-swap="outerHTML"
                         style="display:contents" {
                        (csrf_input(ctx.csrf_token))
                        button type="submit" class="btn-secondary" {
                            "Sign out all other devices"
                        }
                    }
                }
            }
            div class="settings-section-body" {
                ul class="totp-list" {
                    @for s in sessions {
                        (session_row(ctx, s, s.id == current_session_id, now, mode))
                    }
                }
                div class="settings-info" {
                    span class="settings-info-icon" aria-hidden="true" {
                        (info_icon())
                    }
                    div {
                        h4 { "Don't recognise a device?" }
                        p {
                            "Sign it out, then change your password. Signing a "
                            "device out ends its session immediately — it has to "
                            "sign in again with your password and any second factor."
                        }
                    }
                }
            }
        }
    }
}

/// One device row. The current session shows a "This device" badge and no
/// sign-out button (use the normal Sign out to end this one). A pencil opens
/// an inline rename to set a custom nickname; in `Renaming` mode the row
/// becomes that form.
fn session_row(
    ctx: &ChromeContext,
    s: &auth::Session,
    is_current: bool,
    now: chrono::DateTime<chrono::Utc>,
    mode: SectionMode,
) -> Markup {
    let id = s.id;
    let ua = s.user_agent.as_deref().unwrap_or("");
    let auto = device_label(ua);
    // A blank/whitespace label counts as "no nickname".
    let custom = s.label.as_deref().map(str::trim).filter(|l| !l.is_empty());

    if let SectionMode::Renaming(target) = mode
        && target == id
    {
        return html! {
            li class="totp-row totp-row-editing" {
                form class="totp-rename-form"
                     hx-post=(format!("/me/sessions/{id}/rename"))
                     hx-target="#devices-section" hx-swap="outerHTML" {
                    (csrf_input(ctx.csrf_token))
                    // Optional: clearing it reverts to the auto label (shown
                    // as the placeholder). Not `required`.
                    input type="text" name="label" value=[custom]
                          placeholder=(auto) maxlength="60" autofocus
                          class="totp-rename-input" aria-label="Device name";
                    div class="totp-row-actions" {
                        button type="submit" class="btn-secondary" { "Save" }
                        button type="button" class="btn-secondary"
                               hx-get="/me/sessions/section"
                               hx-target="#devices-section" hx-swap="outerHTML" {
                            "Cancel"
                        }
                    }
                }
            }
        };
    }

    html! {
        li class="totp-row" {
            span class="totp-row-icon" aria-hidden="true" {
                @if device_is_mobile(ua) { (device_mobile_icon()) } @else { (laptop_icon()) }
            }
            div class="totp-row-main" {
                span class="totp-row-name" {
                    (custom.unwrap_or(auto.as_str()))
                    @if is_current {
                        span class="device-current-badge" { "This device" }
                    }
                }
                span class="totp-row-meta" {
                    // When a nickname is set, still surface the detected device.
                    @if custom.is_some() { (auto) " • " }
                    @if let Some(ip) = &s.ip_address { (ip) " • " }
                    @match s.last_seen_at {
                        Some(seen) => { "Last active " (relative_time(seen, now)) }
                        None => { "Signed in " (s.created_at.format("%b %-d, %Y").to_string()) }
                    }
                }
            }
            div class="totp-row-actions" {
                button type="button" class="icon-btn"
                       aria-label="Rename device"
                       hx-get=(format!("/me/sessions/{id}/edit"))
                       hx-target="#devices-section" hx-swap="outerHTML" {
                    (pencil_icon())
                }
                @if !is_current {
                    form method="post" action=(format!("/me/sessions/{id}/revoke"))
                         hx-post=(format!("/me/sessions/{id}/revoke"))
                         hx-target="#devices-section" hx-swap="outerHTML"
                         style="display:contents" {
                        (csrf_input(ctx.csrf_token))
                        button type="submit" class="btn-secondary" { "Sign out" }
                    }
                }
            }
        }
    }
}

/// Display-name row inside the Account Information section. No
/// reauth — display name isn't security-relevant, and the friction
/// of "type your password to rename yourself" would feel hostile.
/// HTMX-targeted to its own wrapper so the email row next to it
/// doesn't disturb. `feedback` renders an inline tile above the row
/// after a save.
pub fn settings_name_form(
    ctx: &ChromeContext,
    feedback: Option<&SettingsFeedback>,
) -> Markup {
    let user = ctx.user;
    html! {
        @if let Some(fb) = feedback {
            (settings_feedback_tile(fb))
        }
        form id="form-settings-name"
             class="settings-row"
             method="post"
             action="/me/profile"
             hx-post="/me/profile"
             hx-target="#form-settings-name-wrap"
             hx-swap="innerHTML" {
            (csrf_input(ctx.csrf_token))
            div class="settings-row-label" {
                label for="settings-display-name" { "Display name" }
                p class="settings-row-hint" {
                    "How you appear to others on \
                     this instance."
                }
            }
            div class="settings-row-control" {
                input type="text"
                      id="settings-display-name"
                      name="display_name"
                      value=(user.display_name)
                      autocomplete="name"
                      required;
                div class="settings-row-actions" {
                    button type="submit" class="btn-secondary" {
                        "Save"
                    }
                }
            }
        }
    }
}

/// Email row inside the Account Information section. Submit is
/// gated by the reauth chain: clicking `Update email` opens
/// `dlg-reauth` with the staged new email in a hidden input. The
/// operator enters their current password in the reauth modal; on
/// success the handler HX-Redirects to /me with an "Email updated"
/// toast. Inline password is intentionally absent — re-using the
/// existing reauth pattern keeps "security-sensitive edits live in
/// the reauth modal" as a one-sentence story.
pub fn settings_email_form(ctx: &ChromeContext) -> Markup {
    let user = ctx.user;
    html! {
        form id="form-settings-email"
             class="settings-row"
             method="post"
             action="/me/email" {
            (csrf_input(ctx.csrf_token))
            div class="settings-row-label" {
                label for="settings-email" { "Email address" }
                p class="settings-row-hint" {
                    "The address you sign in with."
                }
            }
            div class="settings-row-control" {
                input type="email"
                      id="settings-email"
                      name="email"
                      value=(user.email)
                      autocomplete="email"
                      required;
                div class="settings-row-actions" {
                    button type="button" class="btn-secondary"
                           data-reauth-confirm="form-settings-email" {
                        "Update email"
                    }
                }
            }
        }
    }
}

/// Post-save feedback tile rendered above a form after an HTMX swap.
/// Two flavours: success (green tick + the change summary) and error
/// (red banner with the inline message). Kept distinct from the
/// generic `error_banner` so the green success state matches.
#[derive(Debug, Clone)]
pub enum SettingsFeedback {
    Success(String),
    Error(String),
}

fn settings_feedback_tile(fb: &SettingsFeedback) -> Markup {
    match fb {
        SettingsFeedback::Success(msg) => html! {
            div class="settings-feedback settings-feedback-success" role="status" {
                (check_circle_icon())
                span { (msg) }
            }
        },
        SettingsFeedback::Error(msg) => html! {
            div class="settings-feedback settings-feedback-error" role="alert" {
                (alert_circle_icon())
                span { (msg) }
            }
        },
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
    _selected_role: InstanceRole,
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
            "set up their account. You can change their role after they "
            "accept."
        }
        @if let Some(code) = error {
            (error_banner(code))
        }
        // No `hx-post` here — the Continue button chains to the
        // shared reauth modal (dlg-reauth) via REAUTH_CHAIN_JS. The
        // staged email + role=member + csrf get copied into the reauth
        // form as hidden inputs, and that form is what actually POSTs.
        // On success the server uses HX-Retarget + HX-Trigger to swap
        // the response back into THIS modal, not the reauth modal.
        form id="form-invite-modal"
             method="post" action="/members/invite" {
            (invite_form_fields(
                ctx.csrf_token,
                prefill_email,
                /* autofocus_email = */ false,
                /* id_prefix = */ "modal",
            ))
            div class="dialog-actions" {
                button type="button" class="btn-secondary"
                       data-close-dialog { "Cancel" }
                // `data-keep-source`: the reauth chain must NOT remove
                // the invite modal when it opens reauth — the invite
                // success partial is HX-Retargeted back into this
                // modal's `#invite-modal-content`, so the modal has to
                // survive (closed, hidden in #modal-host) until the
                // switch-to-invite-modal event reopens it.
                button type="button" class="btn"
                       data-reauth-confirm="form-invite-modal"
                       data-keep-source {
                    "Send invitation"
                }
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
            // Single "Close" action — invite flow is one-at-a-time. If
            // the operator wants to invite another member they re-open
            // the modal from the toolbar CTA, which gives them a fresh
            // form (and a fresh password prompt).
            button type="button" class="btn" data-close-dialog {
                "Close"
            }
        }
        // Re-bind the clipboard handler — INVITE_COPY_JS is delegated
        // on `document`, so it picks up the swapped-in [data-copy-target]
        // automatically. No re-init needed.
    }
}

/// 22px simple person silhouette — used for the "Member" segment in
/// the change-role picker.
fn user_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="22" height="22" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" {}
            circle cx="12" cy="7" r="4" {}
        }
    }
}

/// 22px person + shield — "Admin" segment in the change-role picker.
/// A shield (rather than a gear) reads as "elevated privileges
/// constrained by guardrails", which matches the Admin role's mid-tier
/// authority better than a settings/gear glyph would.
fn user_shield_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="22" height="22" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            path d="M3 21v-2a4 4 0 0 1 4-4h6" {}
            circle cx="10" cy="7" r="4" {}
            path d="M19 11l3 1v3c0 2-3 4-3 4s-3-2-3-4v-3l3-1z" {}
        }
    }
}

/// 22px crown — "Owner" segment in the change-role picker, plus the
/// feature icon on the Owner-promotion confirmation modal.
fn crown_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="22" height="22" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            path d="M3 7l4 5 5-7 5 7 4-5v11H3z" {}
            path d="M3 21h18" {}
        }
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

/// 22px circle-with-lowercase-i icon used as the leading glyph on
/// the pending-actions alert card. Same outline weight as
/// `alert_circle_icon` but with an "i" body, matching the toast
/// info palette so the alert reads as part of the same family.
fn info_circle_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="22" height="22" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            circle cx="12" cy="12" r="10" {}
            line x1="12" y1="11" x2="12" y2="16" {}
            line x1="12" y1="7.5" x2="12" y2="7.5" {}
        }
    }
}

/// Card-style alert rendered between the /members h1 and the
/// toolbar when at least one Owner-on-Owner pending transition is in
/// flight. Replaces the dedicated `/pending` sidebar item — the
/// pattern follows the Untitled UI feature-callout shape (icon puck
/// on left, title + description in the middle, CTA on the right).
///
/// Counts pluralize naturally — "1 pending action" vs "3 pending
/// actions". Caller is responsible for only calling this when
/// `count > 0`; we render unconditionally so the visible state is
/// data-driven from the call site.
fn pending_alert_card(count: u32) -> Markup {
    let title = if count == 1 {
        "1 pending action awaiting review".to_string()
    } else {
        format!("{count} pending actions awaiting review")
    };
    html! {
        section class="alert-card alert-card-primary" role="status" {
            div class="alert-card-icon" { (info_circle_icon()) }
            div class="alert-card-body" {
                div class="alert-card-title" { (title) }
                div class="alert-card-message" {
                    "Owner-initiated changes wait 72 hours so any Owner can "
                    "veto before they apply. Review now to act before the "
                    "window expires."
                }
            }
            div class="alert-card-actions" {
                a class="btn" href="/pending" { "Review" }
            }
        }
    }
}

/// 16px circle-with-exclamation icon used as the leading glyph on
/// `.dialog-alert` strips. Sized smaller than the dialog feature
/// icons because it sits inline with body copy, not as a focal
/// element. Stroke uses `currentColor` so it picks up the alert's
/// red tint automatically.
fn alert_circle_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            class="dialog-alert-icon" aria-hidden="true" {
            circle cx="12" cy="12" r="10" {}
            line x1="12" y1="8" x2="12" y2="13" {}
            line x1="12" y1="16.5" x2="12" y2="16.5" {}
        }
    }
}

/// 22px trash-can icon used as the centered feature icon on the
/// Delete modal (terminal full removal). Stroke uses `currentColor`
/// so the icon inherits the `.dialog-icon-danger` red tint without
/// needing a dedicated fill rule.
fn trash_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="22" height="22" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            polyline points="3 6 5 6 21 6" {}
            path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" {}
            path d="M10 11v6" {}
            path d="M14 11v6" {}
            path d="M9 6V4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2" {}
        }
    }
}

/// Multi-user silhouette — used on the `/members` nav link. Same
/// shoulder + head construction as `user_icon` but with a second
/// (partial) person stepped behind so the glyph reads as a group.
/// Stroke uses `currentColor` so the icon picks up the nav-link's
/// active/inactive tint without per-state overrides.
fn users_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="20" height="20" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" {}
            circle cx="9" cy="7" r="4" {}
            path d="M22 21v-2a4 4 0 0 0-3-3.87" {}
            path d="M16 3.13a4 4 0 0 1 0 7.75" {}
        }
    }
}

/// Magnifying-glass glyph used as the leading icon on the
/// sidebar's search trigger. Replaces the previous "🔍" emoji,
/// which rendered with the OS's pictorial emoji palette and
/// clashed with the monochrome nav chrome. Stroke uses
/// `currentColor`.
fn search_glyph_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            circle cx="11" cy="11" r="7" {}
            line x1="21" y1="21" x2="16.65" y2="16.65" {}
        }
    }
}

/// 22px incognito glyph (fedora + sunglasses) used as the feature
/// icon on the Anonymize modal. The classic browser-incognito
/// imagery telegraphs "identity is scrubbed; the row stays" more
/// accurately than a trash can, which reads as terminal delete and
/// blurs the distinction with the Delete modal. Stroke + fill both
/// use `currentColor` so the icon inherits the
/// `.dialog-icon-danger` red tint; the sunglass lenses fill solid
/// for the iconic dark-lens silhouette.
fn incognito_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="22" height="22" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            // Hat crown — a flat-topped arch from shoulder to shoulder.
            path d="M6 10 Q6 5 12 5 Q18 5 18 10" {}
            // Hat brim — straight line wider than the crown.
            line x1="3" y1="11" x2="21" y2="11" {}
            // Left sunglass lens (filled).
            circle cx="7.5" cy="16" r="3" fill="currentColor" {}
            // Right sunglass lens (filled).
            circle cx="16.5" cy="16" r="3" fill="currentColor" {}
            // Bridge connecting the two lenses.
            line x1="10.5" y1="16" x2="13.5" y2="16" {}
        }
    }
}

/// Gear icon — leading glyph on the user-card popover's "Account
/// settings" row. Stroke uses `currentColor`.
fn settings_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            circle cx="12" cy="12" r="3" {}
            path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33h0a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51h0a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v0a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" {}
        }
    }
}

/// Door + arrow — leading glyph on the user-card popover's
/// "Sign out" row. Suggests "leave this session" without resorting
/// to a power-button glyph (which could be misread as "shut down
/// the instance"). Stroke uses `currentColor`.
fn signout_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" {}
            polyline points="16 17 21 12 16 7" {}
            line x1="21" y1="12" x2="9" y2="12" {}
        }
    }
}

/// Half-shaded circle — "Auto" theme button in the user-card
/// theme switcher. The left half is filled, the right half is
/// outlined, so the glyph reads as "system-controlled, neither
/// pinned to light nor dark". Stroke + fill use `currentColor`.
fn theme_auto_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            circle cx="12" cy="12" r="9" {}
            // Half-fill the left side of the circle so the icon
            // reads as a dial split between two modes.
            path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor" stroke="none" {}
        }
    }
}

/// Crescent moon — "Dark" theme button in the user-card theme
/// switcher. Stroke uses `currentColor`.
fn theme_dark_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" {}
        }
    }
}

/// Vertical 3-dot affordance — placed on the right of the
/// user-card summary to telegraph that the row opens a menu.
/// Three small filled circles stacked vertically, in
/// `currentColor` so the dots pick up the summary's text colour.
fn dots_vertical_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="currentColor"
            aria-hidden="true" {
            circle cx="12" cy="5"  r="1.6" {}
            circle cx="12" cy="12" r="1.6" {}
            circle cx="12" cy="19" r="1.6" {}
        }
    }
}

/// Filled radio — current-account indicator on the user-card
/// popover. Outer ring + filled inner dot. Stroke + fill use
/// `currentColor`. Pairs with `radio_off_icon` (hollow) for the
/// "other accounts" rows below.
fn radio_on_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            circle cx="12" cy="12" r="9" {}
            circle cx="12" cy="12" r="4" fill="currentColor" stroke="none" {}
        }
    }
}

/// Hollow radio — "other accounts" indicator on the user-card
/// popover. Just the outer ring, no inner dot. Stroke uses
/// `currentColor`.
fn radio_off_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            circle cx="12" cy="12" r="9" {}
        }
    }
}

/// Sun with rays — "Light" theme button in the user-card theme
/// switcher. Stroke uses `currentColor`.
fn theme_light_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            circle cx="12" cy="12" r="4" {}
            // Eight evenly-spaced rays.
            line x1="12" y1="2"  x2="12" y2="4"  {}
            line x1="12" y1="20" x2="12" y2="22" {}
            line x1="2"  y1="12" x2="4"  y2="12" {}
            line x1="20" y1="12" x2="22" y2="12" {}
            line x1="4.93" y1="4.93"   x2="6.34"  y2="6.34"  {}
            line x1="17.66" y1="17.66" x2="19.07" y2="19.07" {}
            line x1="4.93" y1="19.07"  x2="6.34"  y2="17.66" {}
            line x1="17.66" y1="6.34"  x2="19.07" y2="4.93"  {}
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

// Copy-URL handler for the invite + reissue result modals.
//
// The `execCommand` fallback appends a temporary off-screen textarea
// *into the dialog itself* (same top layer as the click), focuses +
// selects that, then runs execCommand('copy'). Selecting an input
// from a click that originated on a sibling button inside an open
// `<dialog>` (its own top layer) doesn't reliably update the platform
// selection, so the textarea has to live in the same top layer. The
// modern `navigator.clipboard.writeText` path is tried first — in a
// secure context it's preferred — and we only fall back if writeText
// rejects or the API isn't exposed (insecure context).
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
    var fallback = function() {
        // Mount the temp textarea inside whatever dialog the button
        // lives in (or the body, if there is none) so the selection +
        // execCommand run inside the same top layer.
        var host = btn.closest('dialog') || document.body;
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '0';
        ta.style.left = '0';
        ta.style.width = '1px';
        ta.style.height = '1px';
        ta.style.opacity = '0';
        ta.style.pointerEvents = 'none';
        host.appendChild(ta);
        try {
            ta.focus();
            ta.select();
            // Some browsers ignore .select() for textareas without
            // an explicit setSelectionRange — set it defensively.
            ta.setSelectionRange(0, ta.value.length);
            var ok = document.execCommand('copy');
            if (ok) done();
        } catch (_) {
            // Last resort: leave the URL selected in the original
            // input so the operator can hit Ctrl/Cmd+C themselves.
            input.focus();
            input.select();
        } finally {
            host.removeChild(ta);
        }
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, fallback);
    } else {
        fallback();
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

/// `GET /members` page — admin-only directory of live Members.
/// Renders as a table; anonymized accounts and Guests are filtered
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
    // Bucketed view of active pending transitions keyed by target
    // user id. Empty map → no decoration; lookup returns the row's
    // pending transition (if any) for rendering the "Pending …" pill
    // on the affected row.
    pending_by_target: &std::collections::HashMap<uuid::Uuid, &pending::TransitionRow>,
) -> Markup {
    let content = html! {
        (render_banner(&banner))
        // Pending-actions alert. Renders for Owner viewers when at
        // least one Owner-on-Owner action is in flight; sits between
        // the page header and the toolbar so it's the first thing the
        // operator sees on entering the directory.
        @if is_owner(ctx.user.instance_role)
            && let Some(n) = ctx.pending_count
            && n > 0
        {
            (pending_alert_card(n))
        }
        div class="users-toolbar" {
            input type="search" id="users-search" class="users-search"
                  placeholder="Search by name or email…" autocomplete="off"
                  aria-label="Search members";
            (filter_menu(filter, sort))
            button type="button" class="btn-secondary invite-cta"
                   data-open-modal="/modals/invite" {
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
            // structure.
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
                        // "Joined" column intentionally hidden in the
                        // UI — created_at still lives on the User row
                        // and powers the default sort, but operators
                        // don't need the absolute date visible by
                        // default. Last-activity carries the more
                        // useful "is this person still around" signal.
                        th class="col-last-activity" { "Last activity" }
                        th class="col-actions" aria-label="Actions" { "" }
                    }
                }
                tbody {
                    @for row in rows {
                        @match row {
                            MemberRow::Member { user, last_activity } => {
                                (member_row(
                                    ctx.user,
                                    user,
                                    *last_activity,
                                    ctx.csrf_token,
                                    pending_by_target.get(&user.id.0).copied(),
                                ))
                            }
                            MemberRow::PendingInvite(inv) => {
                                (pending_invite_row(inv, ctx.csrf_token))
                            }
                        }
                    }
                }
            }
        }
        // Pagination always renders, even at 1 page total — keeps the
        // toolbar/table rhythm stable as rows come and go and gives
        // the operator a fixed place to find the rows-per-page control.
        (pagination_bar(pagination, sort, filter))
        // All modals on this page are fetched on demand into the
        // shell's `#modal-host`: the invite modal from `/modals/invite`,
        // each per-row action dialog from `/members/{id}/modal/{action}`,
        // and the reauth modal from `/modals/reauth` (via the chain).
        // Nothing ships in the page source. The reauth chain is also
        // wired at the shell level so it can fire from anywhere; the
        // per-page load here is deduped by REAUTH_CHAIN_JS's guard.
        script {
            (maud::PreEscaped(MEMBERS_SEARCH_JS))
            (maud::PreEscaped(MEMBERS_SELECT_ALL_JS))
            (maud::PreEscaped(MEMBERS_KEBAB_OUTSIDE_CLICK_JS))
            (maud::PreEscaped(DROPDOWN_FLIP_JS))
            (maud::PreEscaped(REAUTH_CHAIN_JS))
            (maud::PreEscaped(CONFIRM_NAME_JS))
            (maud::PreEscaped(ROLE_PICKER_GATE_JS))
            (maud::PreEscaped(CONFIRM_CHECKBOX_JS))
            (maud::PreEscaped(INVITE_SWAP_TO_INVITE_JS))
            (maud::PreEscaped(INVITE_REFRESH_ON_CLOSE_JS))
            // Copy-URL handler — needed on /members because the
            // invite-sent success modal that opens via HX-Retarget
            // renders inside dlg-invite here. The standalone
            // /members/invite fallback page loads it separately.
            (maud::PreEscaped(INVITE_COPY_JS))
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

// Dropdown viewport-flip. Every <details>-based dropdown opens its
// menu downward + right-aligned by default. Near the bottom of the
// viewport (rows-per-page in the pinned pagination, kebab on the
// last row of a table) or near the right edge that overflows the
// visible area, so we flip the menu by adding `.flip-up` / `.flip-
// left` classes the CSS uses to swap the anchoring offsets.
//
// Uses the `toggle` event which fires after `<details>` opens/closes.
// `toggle` doesn't bubble, so we attach in the capture phase. The
// measure-then-flip happens synchronously inside the handler, so the
// browser doesn't paint the default position before the flipped one.
const DROPDOWN_FLIP_JS: &str = r#"
(function() {
    var GUTTER = 8;  // viewport-edge margin we always keep clear

    function flipIfNeeded(details) {
        if (!details.open) {
            details.classList.remove('flip-up', 'flip-left');
            return;
        }
        var menu = details.querySelector(
            '.filter-menu-list, .row-actions-menu'
        );
        if (!menu) return;
        // Strip any prior flip so the measurement reflects the
        // default-anchored position.
        details.classList.remove('flip-up', 'flip-left');
        var rect = menu.getBoundingClientRect();
        if (rect.bottom + GUTTER > window.innerHeight) {
            details.classList.add('flip-up');
        }
        if (rect.left - GUTTER < 0) {
            details.classList.add('flip-left');
        }
    }

    document.addEventListener('toggle', function(e) {
        var d = e.target;
        if (!(d instanceof HTMLDetailsElement)) return;
        if (!(d.matches('details.filter-menu, details.row-actions'))) return;
        flipIfNeeded(d);
    }, true);
})();
"#;

// Invite chain post-reauth handoff. The reauth modal's POST returns
// content targeted at #invite-modal-content (via HX-Retarget) and
// fires `switch-to-invite-modal`. We close the reauth dialog and open
// the invite dialog so the swapped-in content (success or
// validation-error form) is what's visible.
const INVITE_SWAP_TO_INVITE_JS: &str = r#"
(function() {
    document.body.addEventListener('switch-to-invite-modal', function() {
        // The reauth modal just POSTed the invite successfully; the
        // server HX-Retargeted the success partial back into the kept
        // invite modal's #invite-modal-content. Close reauth (which
        // removes it) and reopen the invite modal — it survived in
        // #modal-host via `data-keep-source` while reauth was up.
        var reauth = document.getElementById('dlg-reauth');
        var invite = document.getElementById('dlg-invite');
        if (reauth && reauth.open) reauth.close();
        if (invite && !invite.open) invite.showModal();
    });
})();
"#;

// When an invite is created the new pending row needs to appear in the
// table. We can't reload immediately (the modal still shows the
// one-time URL the operator must copy), so:
//   1. The server fires `invite-success` via HX-Trigger after the
//      successful POST.
//   2. We flip a flag when that event reaches the body.
//   3. When the invite dialog is then closed by the operator (Close
//      button → data-close-dialog → dialog.close() → 'close' event),
//      we reload the page so the new pending invite is visible.
const INVITE_REFRESH_ON_CLOSE_JS: &str = r#"
(function() {
    var needsRefresh = false;
    document.body.addEventListener('invite-success', function() {
        needsRefresh = true;
    });
    // dlg-invite is lazily materialized so we can't bind directly to
    // its `close` event at script-load time. Capture-phase document
    // listener catches the close from whichever live dialog matches
    // (close events don't bubble, hence `true` for capture).
    document.addEventListener('close', function(e) {
        if (e.target && e.target.id === 'dlg-invite' && needsRefresh) {
            window.location.reload();
        }
    }, true);
})();
"#;

const CONFIRM_NAME_JS: &str = r#"
(function() {
    document.addEventListener('input', function(e) {
        var input = e.target.closest('[data-confirm-name]');
        if (!input) return;
        var dialog = input.closest('dialog');
        if (!dialog) return;
        var btn = dialog.querySelector('[data-reauth-confirm]');
        if (!btn) return;
        btn.disabled = (input.value !== input.getAttribute('data-confirm-name'));
    });
    // Reset the input + re-disable the button whenever the dialog
    // closes, so reopening always starts from scratch.
    document.addEventListener('close', function(e) {
        var dialog = e.target;
        if (!(dialog instanceof HTMLDialogElement)) return;
        var input = dialog.querySelector('[data-confirm-name]');
        if (input) input.value = '';
        var btn = dialog.querySelector('[data-reauth-confirm]');
        if (btn && input) btn.disabled = true;
    }, true);
})();
"#;

// Change-role dialog: the Modify Role button starts disabled. It
// enables when the operator picks any non-disabled role radio. On
// dialog close, reset to the initial state (no radio picked, button
// disabled) so reopening always starts fresh.
const ROLE_PICKER_GATE_JS: &str = r#"
(function() {
    document.addEventListener('change', function(e) {
        var radio = e.target;
        if (!(radio instanceof HTMLInputElement)) return;
        if (radio.name !== 'role' || !radio.classList.contains('role-icon-input')) return;
        var dialog = radio.closest('dialog');
        if (!dialog) return;
        var btn = dialog.querySelector('[data-role-aware][data-reauth-confirm]');
        if (btn) btn.disabled = false;
    });
    document.addEventListener('close', function(e) {
        var dialog = e.target;
        if (!(dialog instanceof HTMLDialogElement)) return;
        // The owner-confirm intercept closes the role dialog before
        // opening the owner-confirm modal — but Make Owner then needs
        // to read the still-checked 'owner' radio back off form-role-id
        // when it fires the reauth chain. If we reset on every close
        // we wipe that selection mid-chain, the chain stages no role,
        // and the Verify POST is missing required form data (which
        // surfaces as "Verify did nothing"). REAUTH_CHAIN_JS sets a
        // `chainTransition` flag on the dialog before closing it as
        // part of the intercept; honour that flag here.
        if (dialog.dataset.chainTransition === '1') {
            dialog.dataset.chainTransition = '';
            return;
        }
        var radios = dialog.querySelectorAll('input.role-icon-input:not(:disabled)');
        radios.forEach(function(r) { r.checked = false; });
        var btn = dialog.querySelector('[data-role-aware][data-reauth-confirm]');
        if (btn) btn.disabled = true;
    }, true);
})();
"#;

// Owner-confirmation dialog: the Make Owner button enables only when
// the "I understand…" checkbox is ticked. Reset on close.
const CONFIRM_CHECKBOX_JS: &str = r#"
(function() {
    document.addEventListener('change', function(e) {
        var cb = e.target.closest('[data-confirm-checkbox]');
        if (!cb) return;
        var dialog = cb.closest('dialog');
        if (!dialog) return;
        var btn = dialog.querySelector('[data-reauth-confirm]');
        if (btn) btn.disabled = !cb.checked;
    });
    document.addEventListener('close', function(e) {
        var dialog = e.target;
        if (!(dialog instanceof HTMLDialogElement)) return;
        var cb = dialog.querySelector('[data-confirm-checkbox]');
        if (cb) cb.checked = false;
        var btn = dialog.querySelector('[data-reauth-confirm]');
        if (cb && btn) btn.disabled = true;
    }, true);
})();
"#;

// Account-close confirm dialogs (Data Control → Anonymize / Delete): the
// danger button enables only when BOTH gates pass — the "I understand"
// checkbox (data-close-ack) is ticked AND the typed value matches the account
// email (data-close-email, case-insensitive + trimmed). Deliberately distinct
// attribute names from CONFIRM_NAME_JS / CONFIRM_CHECKBOX_JS so the gates never
// fight when both scripts are present (the settings modal can be opened from
// /members, which loads those). Reset on dialog close.
const ACCOUNT_CLOSE_GATE_JS: &str = r#"
(function() {
    function refresh(dialog) {
        if (!dialog) return;
        var email = dialog.querySelector('[data-close-email]');
        var ack = dialog.querySelector('[data-close-ack]');
        var btn = dialog.querySelector('[data-reauth-confirm]');
        if (!btn) return;
        var want = ((email && email.getAttribute('data-close-email')) || '').trim().toLowerCase();
        var got = ((email && email.value) || '').trim().toLowerCase();
        var emailOk = want.length > 0 && got === want;
        var ackOk = !!(ack && ack.checked);
        btn.disabled = !(emailOk && ackOk);
    }
    document.addEventListener('input', function(e) {
        var el = e.target.closest('[data-close-email]');
        if (el) refresh(el.closest('dialog'));
    });
    document.addEventListener('change', function(e) {
        var el = e.target.closest('[data-close-ack]');
        if (el) refresh(el.closest('dialog'));
    });
    document.addEventListener('close', function(e) {
        var dialog = e.target;
        if (!(dialog instanceof HTMLDialogElement)) return;
        var email = dialog.querySelector('[data-close-email]');
        if (email) email.value = '';
        var ack = dialog.querySelector('[data-close-ack]');
        if (ack) ack.checked = false;
        var btn = dialog.querySelector('[data-reauth-confirm]');
        if (btn && (email || ack)) btn.disabled = true;
    }, true);
})();
"#;

// Chains action dialog → reauth modal. Any button with
// `data-reauth-confirm="<form-id>"` does:
//   1. Read the named form's action URL + payload (skipping the form's
//      own csrf_token + any password field).
//   2. Copy the payload into the reauth modal's form as hidden inputs
//      (clearing any previously-staged inputs from a prior chain).
//   3. Point the reauth form's `action` + `hx-post` at the same URL.
//   4. Close the source dialog, open `#dlg-reauth`, focus the password
//      input. HTMX takes over on submit.
const REAUTH_CHAIN_JS: &str = r#"
(function() {
    // Idempotency guard — the shell wires this for every authed page and
    // /members loads it again; double-binding would run the chain twice.
    if (window.__sylvaReauthChainLoaded) return;
    window.__sylvaReauthChainLoaded = true;

    // The source form's payload minus the password — under the sudo-grant
    // model the action is authorized by the sylva_sudo cookie, not a
    // password field, so the action handlers no longer accept one.
    function payloadOf(sourceForm) {
        var values = {};
        new FormData(sourceForm).forEach(function(value, key) {
            if (key === 'password') return;
            values[key] = value;
        });
        return values;
    }

    // Run the original action via htmx (POST). A single #reauth-modal-content
    // target serves every action: admin actions drive their outcome with
    // HX-Redirect, invite with HX-Retarget, and TOTP/passkey enrollment
    // renders its QR straight into the (open) reauth modal.
    function runAction(actionUrl, values) {
        if (window.htmx && typeof window.htmx.ajax === 'function') {
            window.htmx.ajax('POST', actionUrl, {
                target: '#reauth-modal-content',
                swap: 'innerHTML',
                values: values
            });
        }
    }

    // Dispose the *source* dialog per its hand-off mode (unchanged intent):
    //   • keep-source-open (TOTP/passkey enrollment) → leave it open behind
    //     the reauth modal (the action's response refreshes it via OOB).
    //   • keep-source (invite) → close with the chainTransition flag so it
    //     survives in #modal-host to be reopened by switch-to-invite-modal.
    //   • default (per-row) → remove it; the action redirects away anyway.
    function disposeSource(sourceDialog, keepSource, keepSourceOpen) {
        if (!sourceDialog) return;
        if (keepSourceOpen) return;
        if (keepSource) {
            sourceDialog.dataset.chainTransition = '1';
            if (typeof sourceDialog.close === 'function') sourceDialog.close();
        } else {
            sourceDialog.remove();
        }
    }

    document.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-reauth-confirm]');
        if (!btn) return;
        e.preventDefault();
        var sourceForm = document.getElementById(btn.getAttribute('data-reauth-confirm'));
        if (!sourceForm) return;
        // Surface form invalidity (e.g. malformed email) before prompting.
        if (typeof sourceForm.checkValidity === 'function' && !sourceForm.checkValidity()) {
            if (typeof sourceForm.reportValidity === 'function') sourceForm.reportValidity();
            return;
        }

        // Owner-promotion intercept — route owner role changes through the
        // dedicated confirm fragment instead of straight to reauth.
        if (btn.hasAttribute('data-role-aware')) {
            var roleInput = sourceForm.querySelector('input[name="role"]:checked');
            if (roleInput && roleInput.value === 'owner') {
                var targetId = btn.getAttribute('data-target-id');
                var roleDialog = btn.closest('dialog');
                window.sylvaOpenModal('/members/' + targetId + '/modal/role-owner-confirm')
                    .then(function(oc) {
                        if (oc && typeof oc.showModal === 'function') oc.showModal();
                        if (roleDialog) roleDialog.remove();
                    });
                return;
            }
        }

        var actionUrl = sourceForm.getAttribute('action') || '';
        var values = payloadOf(sourceForm);
        var sourceDialog = btn.closest('dialog');
        var keepSource = btn.hasAttribute('data-keep-source');
        var keepSourceOpen = btn.hasAttribute('data-keep-source-open');
        // Irreversible account actions (self anonymize / delete) demand a
        // *critical* re-auth: the modal then never reports a fresh grant, so
        // the factor prompt always shows, and the verify mints the separate
        // short-lived grant those handlers require.
        var critical = btn.hasAttribute('data-reauth-critical');
        var reauthUrl = critical ? '/modals/reauth?critical=1' : '/modals/reauth';

        // (Re)fetch the reauth modal — it carries data-sudo-fresh telling us
        // whether a recent step-up still covers this action. Drop a stale
        // one first so the flag is current.
        var stale = document.getElementById('dlg-reauth');
        if (stale) stale.remove();
        window.sylvaOpenModal(reauthUrl).then(function(dlg) {
            if (!dlg) return;
            var fresh = dlg.dataset.sudoFresh === '1';

            if (fresh) {
                // Within the sudo window — skip the factor step. For the
                // open-hosting actions (enrollment QR, recovery code,
                // password-changed), blank the modal first so it doesn't
                // flash the now-unnecessary factor prompt before the
                // action's result swaps in.
                if (keepSourceOpen && typeof dlg.showModal === 'function') {
                    var rc = dlg.querySelector('#reauth-modal-content');
                    if (rc) rc.innerHTML = '';
                    dlg.showModal();
                }
                disposeSource(sourceDialog, keepSource, keepSourceOpen);
                runAction(actionUrl, values);
                return;
            }

            // Step-up required. Run the action once POST /me/reauth mints
            // the grant (fires reauth-ok). Keep the listener across failed
            // attempts; drop it if the user cancels (modal close).
            function onOk() {
                document.removeEventListener('reauth-ok', onOk);
                // Enrollment keeps the reauth modal open to host its QR;
                // everything else redirects/retargets, so close it.
                if (!keepSourceOpen && typeof dlg.close === 'function') dlg.close();
                disposeSource(sourceDialog, keepSource, keepSourceOpen);
                runAction(actionUrl, values);
            }
            document.addEventListener('reauth-ok', onOk);
            dlg.addEventListener('close', function() {
                document.removeEventListener('reauth-ok', onOk);
            }, { once: true });
            if (typeof dlg.showModal === 'function') dlg.showModal();
            // Passkey-first: auto-trigger the get-ceremony when the modal
            // opens on the passkey view, so the OS prompt appears without an
            // extra tap. Runs inside the original click's activation window
            // (the preceding fetches are local + fast); if a browser blocks
            // it, the visible "Verify with passkey" button is the fallback.
            var autoPk = dlg.querySelector(
                '[data-reauth-view="passkey"]:not([hidden]) [data-passkey-auth]'
            );
            if (autoPk) { try { autoPk.click(); } catch (_) {} }
        });
    });

    // Passkey ↔ password view toggle inside the reauth modal. "Use password
    // instead" / "Use a passkey instead" just flip which view is visible —
    // no re-fetch, so the in-flight challenge + chain listener survive.
    document.addEventListener('click', function(e) {
        var toPw = e.target.closest('[data-reauth-show-password]');
        var toPk = e.target.closest('[data-reauth-show-passkey]');
        if (!toPw && !toPk) return;
        e.preventDefault();
        var root = (toPw || toPk).closest('#reauth-modal-content') || document;
        var pkView = root.querySelector('[data-reauth-view="passkey"]');
        var pwView = root.querySelector('[data-reauth-view="password"]');
        if (toPw) {
            if (pkView) pkView.hidden = true;
            if (pwView) {
                pwView.hidden = false;
                var inp = pwView.querySelector('input[name="password"]');
                if (inp) inp.focus();
            }
        } else {
            if (pwView) pwView.hidden = true;
            if (pkView) pkView.hidden = false;
        }
    });

    // Enter-in-a-textfield submits the source form natively; re-route it
    // through the chain by clicking the matching confirm button. (A click
    // on a disabled button is a no-op, so type-to-confirm/role gates hold.)
    // The reauth modal's own factor forms have no such button, so this
    // skips them and lets htmx post them to /me/reauth.
    document.addEventListener('submit', function(e) {
        var form = e.target;
        if (!(form instanceof HTMLFormElement) || !form.id) return;
        // The confirm button may live outside the form (the change-password
        // button sits in the section header), so search the whole document
        // for a button bound to this form id. Forms with no such button
        // (e.g. the reauth modal's own factor form) fall through to their
        // native/htmx submit.
        var btn = document.querySelector('[data-reauth-confirm="' + form.id + '"]');
        if (btn) {
            e.preventDefault();
            btn.click();
        }
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
                (filter_menu_item(current, sort, MemberFilter::Status(UserLifecycle::Anonymized)))
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
    pending: Option<&pending::TransitionRow>,
) -> Markup {
    let is_self = viewer.id == target.id;
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
                    (avatar_block(&target.display_name, &target.id.0, target.lifecycle))
                    div class="user-row-text" {
                        span class="user-name" {
                            (target.display_name)
                            @if is_self {
                                span class="row-self-tag" { "you" }
                            }
                        }
                        span class="user-email" { (target.email) }
                        // Pending-action pill — only renders when this
                        // member is the target of a currently-pending
                        // Owner-on-Owner transition. Links to the
                        // matching row on /pending via fragment.
                        @if let Some(p) = pending {
                            (member_pending_pill(p))
                        }
                    }
                }
            }
            td class="col-role" {
                span class=(role_class(target.instance_role)) {
                    (role_label(target.instance_role))
                }
            }
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
fn pending_invite_row(invitation: &identity::Invitation, _csrf_token: &str) -> Markup {
    // `_csrf_token` is unused — the reissue/revoke dialogs are fetched
    // on demand and each fragment renders its own CSRF input. Kept on
    // the signature so the members-page call site doesn't need a
    // special case.
    let initial = display_initial(&invitation.email);
    let color = avatar_color(&invitation.id.0);
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
            td class="col-last-activity" {
                span class="muted-dash" { "—" }
            }
            td class="col-actions" {
                details class="row-actions" {
                    summary class="row-actions-trigger" aria-label="Row actions" {
                        span aria-hidden="true" { "⋮" }
                    }
                    div class="row-actions-menu" {
                        // Same dialog-chain pattern as the member-row
                        // actions: kebab opens a confirmation, which
                        // chains into the reauth modal. The backend
                        // enforces re-auth too (LifecycleActionForm
                        // requires `password`), so even a forged
                        // direct POST won't bypass the gate.
                        //
                        // Reissue sits above Revoke because it's the
                        // more common operator action — recovering a
                        // lost URL is routine; revoking is terminal.
                        button type="button"
                               class="row-action-item"
                               data-open-modal=(format!("/members/invitations/{id}/modal/reissue")) {
                            "Reissue invitation…"
                        }
                        button type="button"
                               class="row-action-item row-action-danger"
                               data-open-modal=(format!("/members/invitations/{id}/modal/revoke")) {
                            "Revoke invite…"
                        }
                    }
                }
            }
        }
    }
}

/// Confirmation dialog for the Reissue invitation row action on
/// pending invitations. Centered chrome with the shield feature icon
/// so it reads as a "you're about to invalidate something" gate, not
/// destructive. The dialog spells out the implication (old URL stops
/// working) before chaining into the reauth modal.
pub(crate) fn reissue_invite_dialog(id: uuid::Uuid, email: &str, csrf_token: &str) -> Markup {
    html! {
        dialog id=(format!("dlg-reissue-invite-{id}"))
               class="action-dialog action-dialog-centered" {
            form id=(format!("form-reissue-invite-{id}"))
                 method="post"
                 action=(format!("/members/invitations/{id}/reissue")) {
                div class="dialog-header" {
                    div class="dialog-icon dialog-icon-shield" {
                        (shield_icon())
                    }
                    button type="button" class="dialog-close" data-close-dialog
                           aria-label="Close" {
                        (close_icon())
                    }
                }
                h2 { "Reissue invitation?" }
                p class="dialog-description" {
                    "A fresh acceptance URL will be generated for "
                    strong { (email) } ". The previous URL stops working "
                    "immediately. The new URL is shown to you once "
                    "(and emailed to the invitee if notifications are enabled)."
                }
                (csrf_input(csrf_token))
                div class="dialog-actions" {
                    button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                    button type="button" class="btn"
                           data-reauth-confirm=(format!("form-reissue-invite-{id}")) {
                        "Reissue"
                    }
                }
            }
        }
    }
}

/// Inner content of the invite modal in its post-reissue "success"
/// state. Same Copy-URL chrome as [`invite_modal_content_success`] but
/// the headline + caption are reissue-specific so the operator
/// understands the old URL is dead. Renders inside #invite-modal-content
/// after HX-Retarget swaps this body into the existing invite dialog.
pub fn reissue_modal_content_success(
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
        h2 { "Invitation reissued" }
        p class="dialog-description" {
            "A new acceptance URL has been generated for "
            strong { (invitee_email) } " as "
            span class=(role_class(invited_role)) {
                (role_label(invited_role))
            }
            ". The previous URL no longer works. New URL expires "
            (expires_label) "."
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
            button type="button" class="btn" data-close-dialog {
                "Close"
            }
        }
    }
}

/// Confirmation dialog for the Revoke invite row action on pending
/// invitations. Centered chrome with the warning-amber feature icon —
/// terminal-but-recoverable, same palette as Deactivate. Sits as a
/// sibling of the Reissue dialog on the same row; the operator picks
/// which one fits their intent from the kebab.
pub(crate) fn revoke_invite_dialog(id: uuid::Uuid, email: &str, csrf_token: &str) -> Markup {
    html! {
        dialog id=(format!("dlg-revoke-invite-{id}"))
               class="action-dialog action-dialog-centered" {
            form id=(format!("form-revoke-invite-{id}"))
                 method="post"
                 action=(format!("/members/invitations/{id}/revoke")) {
                div class="dialog-header" {
                    div class="dialog-icon dialog-icon-shield" {
                        (shield_icon())
                    }
                    button type="button" class="dialog-close" data-close-dialog
                           aria-label="Close" {
                        (close_icon())
                    }
                }
                h2 { "Revoke invitation?" }
                p class="dialog-description" {
                    "The pending invitation for " strong { (email) } " will "
                    "stop working. They won't be able to use the acceptance "
                    "link they received. You can send a new invitation any "
                    "time."
                }
                (csrf_input(csrf_token))
                div class="dialog-actions" {
                    button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                    button type="button" class="btn-danger"
                           data-reauth-confirm=(format!("form-revoke-invite-{id}")) {
                        "Revoke invite"
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
pub(crate) enum RowAction {
    Deactivate,
    Reactivate,
    ChangeRole,
    Anonymize,
    Delete,
}

/// Map a member-action modal path segment to the `RowAction` it gates
/// against. `"role-owner-confirm"` maps to `ChangeRole` because the
/// owner-promotion confirm step is reachable only when Change Role is
/// permitted. Returns `None` for unrecognized segments so the modal
/// endpoint can 404 cleanly.
pub(crate) fn row_action_for_segment(seg: &str) -> Option<RowAction> {
    match seg {
        "deactivate" => Some(RowAction::Deactivate),
        "reactivate" => Some(RowAction::Reactivate),
        "role" | "role-owner-confirm" => Some(RowAction::ChangeRole),
        "anonymize" => Some(RowAction::Anonymize),
        "delete" => Some(RowAction::Delete),
        _ => None,
    }
}

/// Render the dialog fragment for a member-action modal segment. The
/// fetch endpoint serves this on demand; the client injects it into
/// `#modal-host` and removes it on close. `"role-owner-confirm"` is a
/// distinct fragment from `"role"` (the owner-promotion intercept
/// fetches it separately once the operator picks Owner). Returns
/// `None` for unrecognized segments.
pub(crate) fn member_action_modal(
    seg: &str,
    target: &User,
    csrf_token: &str,
) -> Option<Markup> {
    let id = target.id.0;
    match seg {
        "deactivate" => Some(render_action_dialog(RowAction::Deactivate, target, csrf_token, id)),
        "reactivate" => Some(render_action_dialog(RowAction::Reactivate, target, csrf_token, id)),
        "role" => Some(render_action_dialog(RowAction::ChangeRole, target, csrf_token, id)),
        "role-owner-confirm" => {
            Some(role_owner_confirm_dialog(id, &target.display_name, csrf_token))
        }
        "anonymize" => Some(render_action_dialog(RowAction::Anonymize, target, csrf_token, id)),
        "delete" => Some(render_action_dialog(RowAction::Delete, target, csrf_token, id)),
        _ => None,
    }
}

pub(crate) fn available_actions(
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
    // PendingInvite users can't be acted on at all — the API returns
    // `not_active` for them.
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
    actions.push(RowAction::Anonymize);
    actions.push(RowAction::Delete);
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
    actions.push(RowAction::Anonymize);
    actions.push(RowAction::Delete);
    actions
}

fn row_actions_kebab(
    target: &User,
    csrf_token: &str,
    actions: &[RowAction],
    locked: bool,
) -> Markup {
    // No inline dialog markup. Each kebab item opens its dialog on
    // demand via `data-open-modal="/members/{id}/modal/{action}"`
    // (see `render_action_item`); the client fetches the fragment,
    // injects it into `#modal-host`, and removes it on close. This
    // keeps the members table free of N×actions dialog markup per row.
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
    }
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
    let _ = csrf_token; // dialogs render the csrf input themselves
    match action {
        RowAction::Deactivate => html! {
            button type="button" class="row-action-item"
                   data-open-modal=(format!("/members/{id}/modal/deactivate")) {
                "Deactivate…"
            }
        },
        RowAction::Reactivate => html! {
            button type="button" class="row-action-item"
                   data-open-modal=(format!("/members/{id}/modal/reactivate")) {
                "Reactivate…"
            }
        },
        RowAction::ChangeRole => html! {
            button type="button" class="row-action-item"
                   data-open-modal=(format!("/members/{id}/modal/role")) {
                "Change role…"
            }
        },
        // Anonymize — keeps shared content under an anonymized (redacted)
        // account.
        RowAction::Anonymize => html! {
            button type="button" class="row-action-item row-action-danger"
                   data-open-modal=(format!("/members/{id}/modal/anonymize")) {
                "Anonymize…"
            }
        },
        // Delete — the terminal, total action: physically removes the row.
        RowAction::Delete => html! {
            button type="button" class="row-action-item row-action-danger"
                   data-open-modal=(format!("/members/{id}/modal/delete")) {
                "Delete…"
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
        RowAction::Anonymize => ("Anonymize…", true),
        RowAction::Delete => ("Delete…", true),
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

/// 3-up segmented role picker for the change-role dialog. Each segment
/// stacks an icon over its label; the active segment fills with the
/// primary tint. The segment matching the target's current role is
/// rendered `disabled` (greyed) — picking the same role is a no-op
/// the API would refuse anyway, so we just remove the dead-end choice.
/// Nothing is pre-checked so the operator must explicitly pick one of
/// the two remaining roles before the Modify Role button enables.
fn role_icon_picker(id: uuid::Uuid, current: InstanceRole) -> Markup {
    let options = [
        ("member", "Member", InstanceRole::Member),
        ("admin", "Admin", InstanceRole::Admin),
        ("owner", "Owner", InstanceRole::Owner),
    ];
    html! {
        div class="role-icon-picker" role="radiogroup" aria-label="New role" {
            @for (value, label, role) in options {
                @let input_id = format!("role-{id}-{value}");
                @let is_current = current == role;
                input type="radio" name="role" id=(input_id)
                      class="role-icon-input" value=(value)
                      disabled[is_current];
                label class="role-icon-segment" for=(input_id)
                      title=[is_current.then_some("This member is already in this role")] {
                    span class="role-icon-glyph" aria-hidden="true" {
                        @match role {
                            InstanceRole::Member => (user_icon()),
                            InstanceRole::Admin => (user_shield_icon()),
                            InstanceRole::Owner => (crown_icon()),
                        }
                    }
                    span class="role-icon-label" {
                        (label)
                        @if is_current {
                            span class="role-icon-current-tag" { "current" }
                        }
                    }
                }
            }
        }
    }
}

/// Owner-promotion confirmation modal. Sits as a sibling of the
/// change-role dialog and opens when the operator picks "Owner" in
/// the picker and clicks Modify Role. The Make Owner button here
/// chains directly to the reauth modal — Member/Admin paths skip
/// this step. Uses the centered-icon dialog chrome so the warning
/// icon reads as the focal point.
///
/// The Make Owner button stays disabled until the operator ticks
/// the "I understand…" checkbox (wired by CONFIRM_CHECKBOX_JS) — a
/// second deliberate confirmation step on top of the password
/// re-auth that follows.
pub(crate) fn role_owner_confirm_dialog(
    id: uuid::Uuid,
    name: &str,
    csrf_token: &str,
) -> Markup {
    html! {
        dialog id=(format!("dlg-role-owner-confirm-{id}"))
               class="action-dialog action-dialog-centered" {
            // Self-contained form — carries its own role=owner + csrf
            // rather than borrowing the role picker's `form-role-{id}`.
            // Under the on-demand modal model the role picker dialog is
            // removed from the DOM once this owner-confirm is fetched,
            // so this dialog can't depend on the picker's form still
            // existing. The reauth chain stages `role=owner` straight
            // off this form.
            form id=(format!("form-role-owner-{id}"))
                 method="post" action=(format!("/members/{id}/role")) {
                div class="dialog-header" {
                    div class="dialog-icon dialog-icon-shield" {
                        (crown_icon())
                    }
                    button type="button" class="dialog-close" data-close-dialog
                           aria-label="Close" {
                        (close_icon())
                    }
                }
                h2 { "Make " (name) " an Owner?" }
                p class="dialog-description" {
                    "Owners have full control of this Hearth: they can change "
                    "any member's role, deactivate or delete accounts, read the "
                    "audit log, and rotate the server-level recovery code. "
                    "Promoting someone to Owner means sharing your authority "
                    "with them. They'll be able to deactivate or remove you."
                }
                label class="confirm-checkbox-field" {
                    input type="checkbox" class="member-checkbox"
                          data-confirm-checkbox;
                    span {
                        "I understand the impact of making " strong { (name) }
                        " an Owner of this Hearth instance."
                    }
                }
                input type="hidden" name="role" value="owner";
                (csrf_input(csrf_token))
                div class="dialog-actions" {
                    button type="button" class="btn-secondary" data-close-dialog {
                        "Cancel"
                    }
                    // Chains to the reauth modal off this form's own
                    // role=owner payload. No `data-role-aware` — the
                    // owner decision is already made, so it proceeds
                    // straight to reauth.
                    button type="button" class="btn"
                           data-reauth-confirm=(format!("form-role-owner-{id}"))
                           disabled {
                        "Make Owner"
                    }
                }
            }
        }
    }
}

/// Confirmation field for destructive actions — requires the operator
/// to type the target's display name verbatim before the Continue
/// button (sibling, with `[data-reauth-confirm]`) enables. Pure UX
/// guard; the real security is the password reauth that follows.
/// Input deliberately has no `name=` so it doesn't get submitted.
///
/// The name is wrapped in literal double-quote characters (GitHub
/// repo-deletion style) so the operator sees exactly the string they
/// need to type, including any surrounding whitespace or punctuation
/// in the display name. The quotes themselves are not part of the
/// expected typed value — `data-confirm-name` still holds the raw
/// name, and CONFIRM_NAME_JS compares against that.
fn confirm_name_field(id: uuid::Uuid, name: &str, verb: &str) -> Markup {
    let input_id = format!("confirm-name-{verb}-{id}");
    html! {
        div class="field confirm-name-field" {
            label for=(input_id) {
                "Type " strong { "\"" (name) "\"" } " to confirm"
            }
            input type="text" id=(input_id)
                  data-confirm-name=(name)
                  autocomplete="off" spellcheck="false";
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

pub(crate) fn render_action_dialog(action: RowAction, target: &User, csrf_token: &str, id: uuid::Uuid) -> Markup {
    let name = &target.display_name;
    match action {
        // Deactivate uses the centered-icon chrome shared with the
        // rest of the destructive row dialogs (change role, delete,
        // purge, reissue). Warning-amber feature icon because
        // deactivate is impactful (kicks active sessions) but
        // reversible — the more saturated red of `dialog-icon-danger`
        // is reserved for the terminal trio.
        RowAction::Deactivate => html! {
            dialog id=(format!("dlg-deactivate-{id}"))
                   class="action-dialog action-dialog-centered" {
                form id=(format!("form-deactivate-{id}"))
                     method="post" action=(format!("/members/{id}/deactivate")) {
                    div class="dialog-header" {
                        div class="dialog-icon dialog-icon-warning" {
                            (shield_icon())
                        }
                        button type="button" class="dialog-close" data-close-dialog
                               aria-label="Close" {
                            (close_icon())
                        }
                    }
                    h2 { "Deactivate " (name) "?" }
                    p class="dialog-description" {
                        "Revokes all of " (name) "'s active sessions. Their "
                        "credentials stay in place so reactivation later "
                        "doesn't need a password reset."
                    }
                    (csrf_input(csrf_token))
                    div class="dialog-actions" {
                        button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                        button type="button" class="btn"
                               data-reauth-confirm=(format!("form-deactivate-{id}")) {
                            "Deactivate"
                        }
                    }
                }
            }
        },
        // Reactivate uses the same centered chrome as Deactivate so
        // the pair reads symmetric in the operator's mental model.
        // Neutral shield palette (not warning) because this is the
        // restoring-access half of the flip; the dramatic colour is
        // saved for the action that actually cuts access.
        RowAction::Reactivate => html! {
            dialog id=(format!("dlg-reactivate-{id}"))
                   class="action-dialog action-dialog-centered" {
                form id=(format!("form-reactivate-{id}"))
                     method="post" action=(format!("/members/{id}/reactivate")) {
                    div class="dialog-header" {
                        div class="dialog-icon dialog-icon-shield" {
                            (shield_icon())
                        }
                        button type="button" class="dialog-close" data-close-dialog
                               aria-label="Close" {
                            (close_icon())
                        }
                    }
                    h2 { "Reactivate " (name) "?" }
                    p class="dialog-description" {
                        "Re-enables sign-in for " (name) ". Their existing "
                        "password still works. They'll need to sign in again "
                        "(any prior sessions were revoked at deactivation)."
                    }
                    (csrf_input(csrf_token))
                    div class="dialog-actions" {
                        button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                        button type="button" class="btn"
                               data-reauth-confirm=(format!("form-reactivate-{id}")) {
                            "Reactivate"
                        }
                    }
                }
            }
        },
        RowAction::ChangeRole => html! {
            dialog id=(format!("dlg-role-{id}")) class="action-dialog action-dialog-centered" {
                form id=(format!("form-role-{id}"))
                     method="post" action=(format!("/members/{id}/role")) {
                    div class="dialog-header" {
                        div class="dialog-icon dialog-icon-shield" {
                            (user_shield_icon())
                        }
                        button type="button" class="dialog-close" data-close-dialog
                               aria-label="Close" {
                            (close_icon())
                        }
                    }
                    h2 { "Change role for " (name) }
                    p class="dialog-description" {
                        "Roles control what someone can do across this "
                        "Hearth instance, like inviting members, "
                        "deactivating accounts, and configuring server "
                        "settings. App-level permissions (Tasks lists, "
                        "notes, etc.) are managed separately."
                    }
                    (role_icon_picker(id, target.instance_role))
                    (csrf_input(csrf_token))
                    div class="dialog-actions" {
                        button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                        // `data-role-aware` tells REAUTH_CHAIN_JS to peek at
                        // the form's role selection: if "owner", route to
                        // the owner-confirmation dialog first instead of
                        // chaining straight to reauth. The button starts
                        // disabled and only enables once the operator
                        // picks a role that isn't the current one.
                        button type="button" class="btn"
                               data-reauth-confirm=(format!("form-role-{id}"))
                               data-role-aware="true"
                               data-target-id=(id)
                               data-role-form=(format!("form-role-{id}"))
                               disabled {
                            "Modify Role"
                        }
                    }
                }
            }
            // Owner-confirm is not rendered inline — the owner-promotion
            // intercept fetches `/members/{id}/modal/role-owner-confirm`
            // separately once the operator picks Owner. See
            // REAUTH_CHAIN_JS.
        },
        // RowAction::Anonymize — the account row stays so any non-orphaned
        // content (comments on shared docs, shared list ownership, etc.)
        // keeps its byline; just the person's identity is scrubbed. Centered
        // chrome + danger-red feature icon so the destructive nature is
        // immediately visible.
        RowAction::Anonymize => html! {
            dialog id=(format!("dlg-anonymize-{id}"))
                   class="action-dialog action-dialog-centered" {
                form id=(format!("form-anonymize-{id}"))
                     method="post" action=(format!("/members/{id}/anonymize")) {
                    div class="dialog-header" {
                        div class="dialog-icon dialog-icon-danger" {
                            // Incognito glyph (not trash) — the row is
                            // *anonymized*, not deleted. Trash is reserved
                            // for the Delete modal below.
                            (incognito_icon())
                        }
                        button type="button" class="dialog-close" data-close-dialog
                               aria-label="Close" {
                            (close_icon())
                        }
                    }
                    h2 { "Anonymize " (name) "?" }
                    p class="dialog-description" {
                        "Sign-in is revoked, credentials are removed, and "
                        "the email is redacted. Any content " (name) " "
                        "created that other members still rely on stays "
                        "in place, attributed to the anonymized account."
                    }
                    div class="dialog-alert dialog-alert-danger" role="alert" {
                        (alert_circle_icon())
                        span { "This action is permanent and cannot be undone." }
                    }
                    (confirm_name_field(id, name, "anonymize"))
                    (csrf_input(csrf_token))
                    div class="dialog-actions" {
                        button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                        button type="button" class="btn-danger"
                               data-reauth-confirm=(format!("form-anonymize-{id}"))
                               disabled {
                            "Anonymize"
                        }
                    }
                }
            }
        },
        // RowAction::Delete = full removal. The account and every piece of
        // content it created is dropped, even if other members were
        // collaborating on that content. Heavier hammer than Anonymize; same
        // chrome so the two read as a pair, same alert because both are terminal.
        RowAction::Delete => html! {
            dialog id=(format!("dlg-delete-{id}"))
                   class="action-dialog action-dialog-centered" {
                form id=(format!("form-delete-{id}"))
                     method="post" action=(format!("/members/{id}/delete")) {
                    div class="dialog-header" {
                        div class="dialog-icon dialog-icon-danger" {
                            (trash_icon())
                        }
                        button type="button" class="dialog-close" data-close-dialog
                               aria-label="Close" {
                            (close_icon())
                        }
                    }
                    h2 { "Delete " (name) "?" }
                    p class="dialog-description" {
                        "Fully removes the account and every piece of "
                        "content " (name) " created, regardless of whether "
                        "other members were collaborating on it. Use "
                        "Anonymize instead if you only want to scrub the "
                        "identity but keep the shared content."
                    }
                    div class="dialog-alert dialog-alert-danger" role="alert" {
                        (alert_circle_icon())
                        span { "This action is permanent and cannot be undone." }
                    }
                    (confirm_name_field(id, name, "delete"))
                    (csrf_input(csrf_token))
                    div class="dialog-actions" {
                        button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                        button type="button" class="btn-danger"
                               data-reauth-confirm=(format!("form-delete-{id}"))
                               disabled {
                            "Delete"
                        }
                    }
                }
            }
        },
    }
}

// ────────────────────────────────────────────────────────────────────────
// Banners
// ────────────────────────────────────────────────────────────────────────

/// No-op — toasts are dispatched client-side via HX-Trigger (see
/// [`TOAST_JS`]). Kept on the signature so the page-render path keeps
/// the same shape, leaving room to bring back server-side rendered
/// banners for a niche case.
fn render_banner(_banner: &MembersBanner<'_>) -> Markup {
    html! {}
}

// ── Events (audit log) page ───────────────────────────────────────────────

/// Audit-log viewer state passed to [`events_page`] — the active search/filter
/// plus everything needed to render the toolbar and the pagination bar.
pub struct EventsView<'a> {
    /// Current free-text search (empty = none).
    pub search: &'a str,
    /// Current event-type filter (empty = all types).
    pub type_filter: &'a str,
    /// Distinct event types present in the log — populates the filter select.
    pub types: &'a [String],
    pub pagination: PaginationState,
}

/// Admin/Owner-only audit-log viewer. Read-only table of events, newest first,
/// with a search + event-type filter (the toolbar) and an offset pagination bar
/// pinned at the foot (the same component as Members). Rows open a detail modal.
/// Wide chrome so the details column has room.
pub fn events_page(
    ctx: &ChromeContext,
    events: &[audit::AuditEvent],
    now: chrono::DateTime<chrono::Utc>,
    view: &EventsView<'_>,
) -> Markup {
    let filtering = !view.search.is_empty() || !view.type_filter.is_empty();
    let content = html! {
        (events_toolbar(view))
        @if events.is_empty() {
            div class="card" {
                p class="muted" {
                    @if filtering { "No events match these filters." }
                    @else { "No events recorded yet." }
                }
            }
        } @else {
            table class="users-table events-table" {
                thead {
                    tr {
                        th class="col-time" { "Time" }
                        th class="col-actor" { "Actor" }
                        th class="col-event" { "Event" }
                        th class="col-details" { "Details" }
                    }
                }
                tbody {
                    @for ev in events {
                        (event_row(ev, now))
                    }
                }
            }
        }
        // Pagination always renders (even at one page) so the foot of the page
        // stays put as rows come and go — same behaviour as Members.
        (events_pagination_bar(view.pagination, view.search, view.type_filter))
    };
    shell_app_wide(ctx, "Events", PageId::Events, content)
}

/// Search + event-type filter bar. A single GET form so Enter (or Apply)
/// submits both and resets to page 1; `rows` rides a hidden input so the
/// current page size survives a search.
fn events_toolbar(view: &EventsView<'_>) -> Markup {
    html! {
        form method="get" action="/events" class="users-toolbar events-toolbar" {
            input type="search" name="q" value=(view.search) class="users-search"
                  placeholder="Search events…" autocomplete="off" aria-label="Search events";
            select name="type" class="settings-select events-type-select"
                   aria-label="Filter by event type" {
                option value="" selected[view.type_filter.is_empty()] { "All event types" }
                @for t in view.types {
                    option value=(t) selected[t.as_str() == view.type_filter] {
                        (humanize_event_type(t))
                    }
                }
            }
            input type="hidden" name="rows" value=(view.pagination.rows_per_page);
            button type="submit" class="btn-secondary" { "Apply" }
        }
    }
}

/// One audit-event row: relative time (absolute in the tooltip), actor (or
/// "System" for actor-less events), the humanized event type (raw type in the
/// tooltip), and a compact key/value rendering of the event data.
fn event_row(ev: &audit::AuditEvent, now: chrono::DateTime<chrono::Utc>) -> Markup {
    let absolute = ev.occurred_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    html! {
        // Whole row opens the detail modal (handled by the shell's
        // `data-open-modal` delegate → `#modal-host`).
        tr class="events-row" data-open-modal=(format!("/events/{}/modal", ev.seqno)) {
            td class="col-time" title=(absolute) { (relative_time(ev.occurred_at, now)) }
            td class="col-actor" {
                @match &ev.actor_display_name {
                    Some(name) => (name),
                    None => span class="event-actor-system" { "System" },
                }
            }
            td class="col-event" title=(ev.event_type) { (humanize_event_type(&ev.event_type)) }
            td class="col-details" { (event_details(&ev.event_data)) }
        }
    }
}

/// Turn a snake_case event type into a sentence, e.g. `instance_settings_updated`
/// → "Instance settings updated". Event types are ASCII identifiers.
fn humanize_event_type(event_type: &str) -> String {
    let mut s = event_type.replace('_', " ");
    if let Some(first) = s.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    s
}

/// Compact, single-line rendering of an event's `event_data`. Flat objects
/// (the common case) render as `key: value · key: value`; anything else falls
/// back to a dash.
fn event_details(data: &serde_json::Value) -> Markup {
    match data.as_object() {
        Some(map) if !map.is_empty() => html! {
            span class="event-meta" {
                @for (i, (key, value)) in map.iter().enumerate() {
                    @if i > 0 { " · " }
                    span class="event-meta-key" { (key) ": " }
                    (value_compact(value))
                }
            }
        },
        _ => html! { span class="muted-dash" { "—" } },
    }
}

/// Render a JSON value compactly for the details cell — strings unquoted,
/// scalars as-is, nested arrays/objects as compact JSON.
fn value_compact(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// Offset pagination bar at the foot of the Events table — the same chrome as
/// the Members bar (editable "Page X of N", step + number controls, rows-per-
/// page dropdown), but its links carry the events query (`q` / `type` / `rows`).
fn events_pagination_bar(state: PaginationState, search: &str, type_filter: &str) -> Markup {
    let cur = state.current_page;
    let total = state.total_pages;
    let rows = state.rows_per_page;
    let at_first = cur <= 1;
    let at_last = cur >= total;
    let prev_page = cur.saturating_sub(1).max(1);
    let next_page = (cur + 1).min(total);

    let step = |page: u32, disabled: bool, label: &str, icon: Markup| -> Markup {
        let aria = format!("Go to {label} page");
        if disabled {
            html! {
                span class="pagination-step pagination-step-disabled"
                     aria-label=(aria) aria-disabled="true" { (icon) }
            }
        } else {
            let href = events_url(search, type_filter, page, rows);
            html! { a class="pagination-step" href=(href) aria-label=(aria) { (icon) } }
        }
    };
    let number = |page: u32, active: bool| -> Markup {
        if active {
            html! {
                span class="pagination-number pagination-number-active"
                     aria-current="page" { (page) }
            }
        } else {
            let href = events_url(search, type_filter, page, rows);
            html! { a class="pagination-number" href=(href) { (page) } }
        }
    };

    html! {
        nav class="pagination-bar" aria-label="Pagination" {
            form method="get" action="/events" class="pagination-jump" {
                label class="pagination-jump-label" for="page-jump" { "Page" }
                input type="number" id="page-jump" name="page" class="pagination-jump-input"
                      value=(cur) min="1" max=(total);
                span class="pagination-jump-of" { "of " (total) }
                input type="hidden" name="q" value=(search);
                input type="hidden" name="type" value=(type_filter);
                input type="hidden" name="rows" value=(rows);
            }
            div class="pagination-numbers" {
                (step(1, at_first, "first", chevron_double_left_icon()))
                (step(prev_page, at_first, "previous", chevron_left_icon()))
                @for item in page_items(cur, total) {
                    @match item {
                        PageItem::Number(n) => (number(n, n == cur)),
                        PageItem::Ellipsis => span class="pagination-ellipsis" aria-hidden="true" { "…" },
                    }
                }
                (step(next_page, at_last, "next", chevron_right_icon()))
                (step(total, at_last, "last", chevron_double_right_icon()))
            }
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
                            @let href = events_url(search, type_filter, 1, *option);
                            a class=(class) href=(href) {
                                span { (option) }
                                @if active { (check_small_icon()) }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Build a `/events?…` URL preserving the active search + type filter.
fn events_url(search: &str, type_filter: &str, page: u32, rows: u32) -> String {
    let mut url = format!("/events?page={page}&rows={rows}");
    if !search.is_empty() {
        url.push_str(&format!("&q={}", query_encode(search)));
    }
    if !type_filter.is_empty() {
        url.push_str(&format!("&type={}", query_encode(type_filter)));
    }
    url
}

/// Percent-encode a query-string value (RFC 3986 unreserved set kept literal).
fn query_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Detail modal for one audit event — the full `event_data` (pretty JSON) plus
/// the chain fields (seqno + prev_hash/hash hex), fetched on demand into
/// `#modal-host` when a row is clicked. Read-only; no actions.
pub fn event_detail_modal(ev: &audit::AuditEvent) -> Markup {
    let pretty =
        serde_json::to_string_pretty(&ev.event_data).unwrap_or_else(|_| ev.event_data.to_string());
    let absolute = ev.occurred_at.format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string();
    html! {
        dialog id="dlg-event-detail" class="action-dialog" {
            div class="dialog-header" {
                h2 { "Event #" (ev.seqno) }
                button type="button" class="dialog-close" data-close-dialog
                       aria-label="Close" { (close_icon()) }
            }
            div class="event-detail" {
                (detail_pair("Time", html! { (absolute) }))
                (detail_pair("Actor", html! {
                    @match &ev.actor_display_name {
                        Some(name) => (name),
                        None => span class="event-actor-system" { "System" },
                    }
                    @if let Some(id) = ev.actor_user_id {
                        span class="event-detail-sub" { " · " (id) }
                    }
                }))
                (detail_pair("Event", html! {
                    (humanize_event_type(&ev.event_type))
                    span class="event-detail-sub" { " · " (ev.event_type) }
                }))
                @if let Some(app) = &ev.app_id {
                    (detail_pair("App", html! { (app) }))
                }
            }
            div class="event-detail-block" {
                span class="event-detail-label" { "Data" }
                pre class="event-detail-json" { (pretty) }
            }
            div class="event-detail-block" {
                span class="event-detail-label" { "Chain" }
                div class="event-hash-row" {
                    span class="event-hash-key" { "seqno" }
                    span class="event-hash-val" { (ev.seqno) }
                }
                div class="event-hash-row" {
                    span class="event-hash-key" { "prev_hash" }
                    span class="event-hash-val" { (hex_encode(&ev.prev_hash)) }
                }
                div class="event-hash-row" {
                    span class="event-hash-key" { "hash" }
                    span class="event-hash-val" { (hex_encode(&ev.hash)) }
                }
            }
            div class="dialog-actions" {
                button type="button" class="btn" data-close-dialog { "Close" }
            }
        }
    }
}

/// One label/value row in the event detail modal's summary block.
fn detail_pair(label: &str, value: Markup) -> Markup {
    html! {
        div class="event-detail-pair" {
            span class="event-detail-label" { (label) }
            span class="event-detail-value" { (value) }
        }
    }
}

/// Lowercase hex of a byte slice (chain hashes).
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// List glyph for the Events nav entry. Stroke uses `currentColor`.
fn events_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            line x1="8" y1="6" x2="21" y2="6" {}
            line x1="8" y1="12" x2="21" y2="12" {}
            line x1="8" y1="18" x2="21" y2="18" {}
            line x1="3" y1="6" x2="3.01" y2="6" {}
            line x1="3" y1="12" x2="3.01" y2="12" {}
            line x1="3" y1="18" x2="3.01" y2="18" {}
        }
    }
}

/// Four-tile grid glyph for the Apps nav entry.
fn apps_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            rect x="3" y="3" width="7" height="7" rx="1" {}
            rect x="14" y="3" width="7" height="7" rx="1" {}
            rect x="14" y="14" width="7" height="7" rx="1" {}
            rect x="3" y="14" width="7" height="7" rx="1" {}
        }
    }
}

// ── Owner Apps admin page ─────────────────────────────────────────────────

/// Owner-only registered-apps page (CP1 — read-only). One row per app in
/// `platform.registered_apps` with a live count of the (non-deleted) resources
/// it stores. Registration happens over the platform gRPC API; lifecycle
/// controls (enable/disable, uninstall) and a resource browser land in later
/// checkpoints. Wide chrome so the columns have room.
pub fn apps_page(
    ctx: &ChromeContext,
    apps: &[platform::registry::AppListItem],
    now: chrono::DateTime<chrono::Utc>,
) -> Markup {
    let content = html! {
        p class="muted apps-lead" {
            "Apps that have registered on this instance and the encrypted resources they store. "
            "Registration happens over the platform gRPC API. "
            a href="/apps/publishers" { "Manage trusted publishers →" }
        }
        @if apps.is_empty() {
            div class="card" {
                p class="muted" { "No apps have registered yet." }
            }
        } @else {
            table class="users-table apps-table" {
                thead {
                    tr {
                        th class="col-app" { "App" }
                        th class="col-publisher" { "Publisher" }
                        th class="col-status" { "Status" }
                        th class="col-types" { "Resource types" }
                        th class="col-count" { "Resources" }
                        th class="col-registered" { "Registered" }
                        th class="col-actions" aria-label="Actions" { "" }
                    }
                }
                tbody {
                    @for app in apps {
                        (app_row(app, now))
                    }
                }
            }
        }
    };
    shell_app_wide(ctx, "Apps", PageId::Apps, content)
}

/// One registered-app row: name + identifier stacked, publisher, status pill,
/// declared resource-type chips, the live resource count, and when it first
/// registered (absolute time in the tooltip).
fn app_row(app: &platform::registry::AppListItem, now: chrono::DateTime<chrono::Utc>) -> Markup {
    let registered = app.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    html! {
        tr {
            td class="col-app" {
                div class="user-row-text" {
                    span class="user-name" { (app.display_name) }
                    span class="user-email" { (app.app_identifier) }
                }
            }
            td class="col-publisher" { (app.publisher) }
            td class="col-status" { (app_status_badge(&app.status)) }
            td class="col-types" {
                @if app.resource_types.is_empty() {
                    span class="muted-dash" { "—" }
                } @else {
                    span class="app-types" {
                        @for t in &app.resource_types {
                            span class="app-type-chip" { (t) }
                        }
                    }
                }
            }
            td class="col-count" {
                // Link through to the per-app resource browser when there's
                // anything to see; a bare "0" stays plain.
                @if app.resource_count > 0 {
                    a href=(format!("/apps/{}/resources", app.id)) { (app.resource_count) }
                } @else {
                    (app.resource_count)
                }
            }
            td class="col-registered" title=(registered) { (relative_time(app.created_at, now)) }
            td class="col-actions" { (app_actions_kebab(app)) }
        }
    }
}

/// Per-row kebab for an app: the status toggle (Enable/Disable, whichever the
/// current status allows) plus Uninstall. Each item opens its confirmation
/// dialog on demand (`data-open-modal`), matching the Members-row pattern; the
/// dialogs chain into the reauth modal and the handlers re-check the role +
/// sudo grant, so the kebab is purely a convenience surface.
fn app_actions_kebab(app: &platform::registry::AppListItem) -> Markup {
    let id = app.id;
    html! {
        details class="row-actions" {
            summary class="row-actions-trigger" aria-label="Row actions" {
                span aria-hidden="true" { "⋮" }
            }
            div class="row-actions-menu" {
                @if app.status == "enabled" {
                    button type="button" class="row-action-item"
                           data-open-modal=(format!("/apps/{id}/modal/disable")) {
                        "Disable app…"
                    }
                } @else {
                    button type="button" class="row-action-item"
                           data-open-modal=(format!("/apps/{id}/modal/enable")) {
                        "Enable app…"
                    }
                }
                button type="button" class="row-action-item row-action-danger"
                       data-open-modal=(format!("/apps/{id}/modal/uninstall")) {
                    "Uninstall app…"
                }
            }
        }
    }
}

/// Confirmation dialog for an app lifecycle action (`enable` / `disable` /
/// `uninstall`). Fetched on demand into `#modal-host`; the primary button
/// chains into the shared reauth modal (`data-reauth-confirm`). `resource_count`
/// is only used by the uninstall copy. Returns `None` for unknown segments.
pub(crate) fn app_action_dialog(
    seg: &str,
    app: &platform::registry::RegisteredAppRow,
    resource_count: i64,
    csrf_token: &str,
) -> Option<Markup> {
    let id = app.id;
    let name = &app.display_name;
    match seg {
        "disable" => Some(html! {
            dialog id=(format!("dlg-app-disable-{id}"))
                   class="action-dialog action-dialog-centered" {
                form id=(format!("form-app-disable-{id}"))
                     method="post" action=(format!("/apps/{id}/disable")) {
                    div class="dialog-header" {
                        div class="dialog-icon dialog-icon-warning" { (shield_icon()) }
                        button type="button" class="dialog-close" data-close-dialog
                               aria-label="Close" { (close_icon()) }
                    }
                    h2 { "Disable " (name) "?" }
                    p class="dialog-description" {
                        strong { (name) } " will be blocked from creating or modifying "
                        "resources until you re-enable it. Existing data is kept, and the "
                        "app stays registered."
                    }
                    (csrf_input(csrf_token))
                    div class="dialog-actions" {
                        button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                        button type="button" class="btn"
                               data-reauth-confirm=(format!("form-app-disable-{id}")) {
                            "Disable app"
                        }
                    }
                }
            }
        }),
        "enable" => Some(html! {
            dialog id=(format!("dlg-app-enable-{id}"))
                   class="action-dialog action-dialog-centered" {
                form id=(format!("form-app-enable-{id}"))
                     method="post" action=(format!("/apps/{id}/enable")) {
                    div class="dialog-header" {
                        div class="dialog-icon dialog-icon-shield" { (shield_icon()) }
                        button type="button" class="dialog-close" data-close-dialog
                               aria-label="Close" { (close_icon()) }
                    }
                    h2 { "Enable " (name) "?" }
                    p class="dialog-description" {
                        "Re-enables " strong { (name) } " to create and modify resources again."
                    }
                    (csrf_input(csrf_token))
                    div class="dialog-actions" {
                        button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                        button type="button" class="btn"
                               data-reauth-confirm=(format!("form-app-enable-{id}")) {
                            "Enable app"
                        }
                    }
                }
            }
        }),
        "uninstall" => Some(html! {
            dialog id=(format!("dlg-app-uninstall-{id}"))
                   class="action-dialog action-dialog-centered" {
                form id=(format!("form-app-uninstall-{id}"))
                     method="post" action=(format!("/apps/{id}/uninstall")) {
                    div class="dialog-header" {
                        div class="dialog-icon dialog-icon-danger" { (trash_icon()) }
                        button type="button" class="dialog-close" data-close-dialog
                               aria-label="Close" { (close_icon()) }
                    }
                    h2 { "Uninstall " (name) "?" }
                    p class="dialog-description" {
                        "Permanently removes " strong { (name) } ", its registration, and "
                        @if resource_count == 1 {
                            "the " strong { "1 resource" } " it stores"
                        } @else {
                            "all " strong { (resource_count) " resources" } " it stores"
                        }
                        ". This can't be undone."
                    }
                    (csrf_input(csrf_token))
                    div class="dialog-actions" {
                        button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                        button type="button" class="btn-danger"
                               data-reauth-confirm=(format!("form-app-uninstall-{id}")) {
                            "Uninstall app"
                        }
                    }
                }
            }
        }),
        _ => None,
    }
}

/// Status pill for an app: "enabled" reuses the green `.status-active` badge,
/// anything else (e.g. "disabled") the muted `.status-deactivated` one. Label
/// is the raw status with a leading capital.
fn app_status_badge(status: &str) -> Markup {
    let class = if status == "enabled" {
        "status-badge status-active"
    } else {
        "status-badge status-deactivated"
    };
    let mut label = status.to_string();
    if let Some(first) = label.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    html! { span class=(class) { (label) } }
}

// ── Owner Apps → resource browser (CP3) ────────────────────────────────────

/// State for the per-app resource browser.
pub struct AppResourcesView<'a> {
    pub app: &'a platform::registry::RegisteredAppRow,
    pub rows: &'a [platform::resources::AdminResourceRow],
    /// Total matching the filters (may exceed the rendered page).
    pub total: i64,
    /// The newest-N cap applied to the listing.
    pub cap: i64,
    pub type_filter: &'a str,
    pub search: &'a str,
    pub include_deleted: bool,
    pub now: chrono::DateTime<chrono::Utc>,
}

/// Owner-only per-app resource browser. Lists an app's stored resources (all
/// owners) with type / resource-ID / include-deleted filters; rows open a
/// metadata detail modal that offers a permanent delete. Capped at the newest
/// `cap`; the GUID search reaches any single resource regardless of position.
pub fn app_resources_page(ctx: &ChromeContext, v: &AppResourcesView<'_>) -> Markup {
    let filtering = !v.search.is_empty() || !v.type_filter.is_empty() || v.include_deleted;
    let truncated = v.total > v.rows.len() as i64;
    let content = html! {
        p class="muted apps-lead" {
            "Resources stored by " strong { (v.app.display_name) } " ("
            (v.app.app_identifier) "). Content is encrypted — the server only sees "
            "metadata. " a href="/apps" { "← Back to Apps" }
        }
        (app_resources_toolbar(v))
        @if v.rows.is_empty() {
            div class="card" {
                p class="muted" {
                    @if filtering { "No resources match these filters." }
                    @else { "This app hasn't stored any resources yet." }
                }
            }
        } @else {
            table class="users-table apps-table resources-table" {
                thead {
                    tr {
                        th class="col-rtype" { "Type" }
                        th class="col-rid" { "Resource ID" }
                        th class="col-owner" { "Owner" }
                        th class="col-size" { "Size" }
                        th class="col-updated" { "Updated" }
                        th class="col-rstatus" { "Status" }
                    }
                }
                tbody {
                    @for r in v.rows {
                        (app_resource_row(v.app.id, r, v.now))
                    }
                }
            }
            p class="muted resources-count" {
                "Showing " (v.rows.len()) " of " (v.total)
                @if v.total == 1 { " resource." } @else { " resources." }
                @if truncated {
                    " Newest " (v.cap) " shown — narrow with the filters above to reach the rest."
                }
            }
        }
    };
    shell_app_wide(ctx, "Resources", PageId::Apps, content)
}

/// Type / resource-ID / include-deleted filter bar. A single GET form so Enter
/// or Apply submits all three.
fn app_resources_toolbar(v: &AppResourcesView<'_>) -> Markup {
    html! {
        form method="get" action=(format!("/apps/{}/resources", v.app.id))
             class="users-toolbar events-toolbar" {
            input type="search" name="q" value=(v.search) class="users-search"
                  placeholder="Resource ID (UUID)…" autocomplete="off"
                  aria-label="Search by resource ID";
            select name="type" class="settings-select events-type-select"
                   aria-label="Filter by resource type" {
                option value="" selected[v.type_filter.is_empty()] { "All types" }
                @for t in &v.app.resource_types {
                    option value=(t) selected[t.as_str() == v.type_filter] { (t) }
                }
            }
            label class="resources-include-deleted" {
                input type="checkbox" name="deleted" value="1" checked[v.include_deleted];
                " Include deleted"
            }
            button type="submit" class="btn-secondary" { "Apply" }
        }
    }
}

/// One resource row — opens the detail modal on click (the shell's
/// `data-open-modal` delegate). The `app_resource_id` (the app's own GUID) is
/// the operator-facing identifier shown in the cell.
fn app_resource_row(
    app_id: uuid::Uuid,
    r: &platform::resources::AdminResourceRow,
    now: chrono::DateTime<chrono::Utc>,
) -> Markup {
    let updated_abs = r.updated_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    html! {
        tr class="events-row"
           data-open-modal=(format!("/apps/{app_id}/resources/{}/modal", r.id)) {
            td class="col-rtype" { span class="app-type-chip" { (r.resource_type) } }
            td class="col-rid" { code class="resource-id" { (r.app_resource_id) } }
            td class="col-owner" {
                @match &r.owner_display_name {
                    Some(n) => (n),
                    None => span class="muted-dash" { "—" },
                }
            }
            td class="col-size" { (format_bytes(r.content_len)) }
            td class="col-updated" title=(updated_abs) { (relative_time(r.updated_at, now)) }
            td class="col-rstatus" {
                @if r.deleted_at.is_some() {
                    span class="status-badge status-deleted" { "Deleted" }
                } @else {
                    span class="status-badge status-active" { "Live" }
                }
            }
        }
    }
}

/// Read-only metadata detail for one resource, plus a permanent-delete action
/// (chains into the reauth modal). The encrypted blob is never shown — only its
/// size — because the server can't read it.
pub(crate) fn app_resource_detail_modal(
    app_id: uuid::Uuid,
    r: &platform::resources::AdminResourceRow,
    csrf_token: &str,
) -> Markup {
    let pair = |label: &str, value: Markup| -> Markup {
        html! {
            div class="event-detail-pair" {
                span class="event-detail-label" { (label) }
                span class="event-detail-value" { (value) }
            }
        }
    };
    let owner = r.owner_display_name.clone().unwrap_or_else(|| "—".to_string());
    html! {
        dialog id="dlg-resource-detail" class="action-dialog action-dialog-centered" {
            div class="dialog-header" {
                div class="dialog-icon dialog-icon-shield" { (apps_icon()) }
                button type="button" class="dialog-close" data-close-dialog
                       aria-label="Close" { (close_icon()) }
            }
            h2 { "Resource" }
            div class="event-detail" {
                (pair("Type", html! { span class="app-type-chip" { (r.resource_type) } }))
                (pair("Resource ID", html! { code { (r.app_resource_id) } }))
                (pair("Server ID", html! { code { (r.id) } }))
                (pair("Owner", html! { (owner) }))
                (pair("Parent", match r.parent_resource_id {
                    Some(p) => html! { code { (p) } },
                    None => html! { span class="muted-dash" { "—" } },
                }))
                (pair("Schema version", html! { (r.schema_version) }))
                (pair("Content", html! {
                    (format_bytes(r.content_len)) " · encrypted (not shown)"
                }))
                (pair("Signature", html! { (format_bytes(r.signature_len)) }))
                (pair("Created", html! { (r.created_at.format("%Y-%m-%d %H:%M:%S UTC")) }))
                (pair("Updated", html! { (r.updated_at.format("%Y-%m-%d %H:%M:%S UTC")) }))
                @if let Some(d) = r.deleted_at {
                    (pair("Deleted", html! { (d.format("%Y-%m-%d %H:%M:%S UTC")) }))
                }
            }
            p class="dialog-description resource-delete-note" {
                "Deleting purges this resource entirely — its owner and their "
                "other devices won't receive a tombstone. This can't be undone."
            }
            // The reauth-confirm button (below) submits this form by id.
            form id="form-resource-delete" method="post"
                 action=(format!("/apps/{app_id}/resources/{}/delete", r.id)) {
                (csrf_input(csrf_token))
            }
            div class="dialog-actions" {
                button type="button" class="btn-secondary" data-close-dialog { "Close" }
                button type="button" class="btn-danger"
                       data-reauth-confirm="form-resource-delete" {
                    "Delete permanently"
                }
            }
        }
    }
}

/// Human byte size for a resource's blob/signature length.
fn format_bytes(n: i32) -> String {
    let n = f64::from(n.max(0));
    if n < 1024.0 {
        format!("{} B", n as i64)
    } else if n < 1024.0 * 1024.0 {
        format!("{:.1} KB", n / 1024.0)
    } else {
        format!("{:.1} MB", n / (1024.0 * 1024.0))
    }
}

// ── Owner Apps → trusted publishers (CP4) ──────────────────────────────────

/// Owner-only trusted-publisher management. An inline add form (name + hex key,
/// chained into the reauth modal) over a table of current publishers, each with
/// a Remove action. Wide chrome to match the rest of the Apps surface.
pub fn trusted_publishers_page(
    ctx: &ChromeContext,
    publishers: &[platform::registry::TrustedPublisherListItem],
    now: chrono::DateTime<chrono::Utc>,
) -> Markup {
    let content = html! {
        p class="muted apps-lead" {
            "Publishers whose Ed25519 key may sign app registrations on this instance. "
            "Removing one doesn't affect already-registered apps. "
            a href="/apps" { "← Back to Apps" }
        }
        div class="card publisher-add-card" {
            h2 { "Add a trusted publisher" }
            form id="form-add-publisher" method="post" action="/apps/publishers" {
                (csrf_input(ctx.csrf_token))
                div class="field" {
                    label for="pub-name" { "Publisher" }
                    input type="text" name="publisher" id="pub-name" required
                          autocomplete="off" placeholder="e.g. Ubivera, LLC";
                }
                div class="field" {
                    label for="pub-key" {
                        "Public key " span class="muted" { "(64-character hex Ed25519)" }
                    }
                    input type="text" name="public_key" id="pub-key" required
                          autocomplete="off" spellcheck="false"
                          class="publisher-key-input" placeholder="0123abcd…";
                }
                div class="dialog-actions" {
                    button type="button" class="btn" data-reauth-confirm="form-add-publisher" {
                        "Add publisher"
                    }
                }
            }
        }
        @if publishers.is_empty() {
            div class="card" {
                p class="muted" {
                    "No trusted publishers yet. Add one above before any app can register."
                }
            }
        } @else {
            table class="users-table apps-table publishers-table" {
                thead {
                    tr {
                        th class="col-pub" { "Publisher" }
                        th class="col-key" { "Public key" }
                        th class="col-addedby" { "Added by" }
                        th class="col-added" { "Added" }
                        th class="col-actions" aria-label="Actions" { "" }
                    }
                }
                tbody {
                    @for p in publishers {
                        (publisher_row(p, now))
                    }
                }
            }
        }
    };
    shell_app_wide(ctx, "Trusted publishers", PageId::Apps, content)
}

/// One trusted-publisher row: name, the key (short hex, full value in the
/// tooltip), who added it + when, and a Remove kebab.
fn publisher_row(
    p: &platform::registry::TrustedPublisherListItem,
    now: chrono::DateTime<chrono::Utc>,
) -> Markup {
    let key_hex = hex_encode(&p.public_key);
    let added_abs = p.added_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let remove_url = format!(
        "/apps/publishers/remove-modal?publisher={}",
        query_encode(&p.publisher)
    );
    html! {
        tr {
            td class="col-pub" { (p.publisher) }
            td class="col-key" { code class="resource-id" title=(key_hex) { (key_short(&key_hex)) } }
            td class="col-addedby" {
                @match &p.added_by_name {
                    Some(n) => (n),
                    None => span class="muted-dash" { "—" },
                }
            }
            td class="col-added" title=(added_abs) { (relative_time(p.added_at, now)) }
            td class="col-actions" {
                details class="row-actions" {
                    summary class="row-actions-trigger" aria-label="Row actions" {
                        span aria-hidden="true" { "⋮" }
                    }
                    div class="row-actions-menu" {
                        button type="button" class="row-action-item row-action-danger"
                               data-open-modal=(remove_url) {
                            "Remove…"
                        }
                    }
                }
            }
        }
    }
}

/// Remove-publisher confirmation (chains into reauth). Carries the publisher
/// name in a hidden field — the PK is the name, so the POST identifies it that
/// way rather than via a path segment (names contain spaces/commas).
pub(crate) fn remove_publisher_dialog(publisher: &str, csrf_token: &str) -> Markup {
    html! {
        dialog id="dlg-remove-publisher" class="action-dialog action-dialog-centered" {
            form id="form-remove-publisher" method="post" action="/apps/publishers/remove" {
                div class="dialog-header" {
                    div class="dialog-icon dialog-icon-warning" { (shield_icon()) }
                    button type="button" class="dialog-close" data-close-dialog
                           aria-label="Close" { (close_icon()) }
                }
                h2 { "Remove " (publisher) "?" }
                p class="dialog-description" {
                    "Apps signed by " strong { (publisher) } " won't be able to register from "
                    "now on. Already-registered apps keep working, and you can add the "
                    "publisher back any time."
                }
                (csrf_input(csrf_token))
                input type="hidden" name="publisher" value=(publisher);
                div class="dialog-actions" {
                    button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                    button type="button" class="btn-danger"
                           data-reauth-confirm="form-remove-publisher" {
                        "Remove publisher"
                    }
                }
            }
        }
    }
}

/// Truncate a long hex string to `head…tail` for table display.
fn key_short(hex: &str) -> String {
    if hex.len() > 20 {
        format!("{}…{}", &hex[..12], &hex[hex.len() - 6..])
    } else {
        hex.to_string()
    }
}

// ── Owner Settings page ───────────────────────────────────────────────────

/// Owner-only instance configuration page. Two sections: instance identity
/// (display name) and email/notifications (mode + SMTP). The notifications
/// save is reauth-gated (it carries credentials); identity is CSRF-only. Both
/// apply live — the handlers swap the hot-reloadable `AppState` cells.
pub fn settings_page(
    ctx: &ChromeContext,
    notifications: &server::config::NotificationsConfig,
    smtp_password_set: bool,
    recovery_created_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Markup {
    let content = html! {
        (settings_identity_section(ctx))
        hr class="settings-divider";
        (settings_notifications_section(ctx, notifications, smtp_password_set))
        hr class="settings-divider";
        (settings_recovery_section(recovery_created_at))
        hr class="settings-divider";
        (settings_danger_section())
        script { (maud::PreEscaped(SETTINGS_SMTP_TOGGLE_JS)) }
    };
    shell_app_wide(ctx, "Settings", PageId::Settings, content)
}

/// Instance-identity section: the display-name override. CSRF-only (no
/// credentials change), submitted via htmx; the handler redirects back with a
/// toast so the re-rendered sidebar brand reflects the new name immediately.
fn settings_identity_section(ctx: &ChromeContext) -> Markup {
    html! {
        section class="settings-section" {
            div class="settings-section-header" {
                span class="settings-section-icon" aria-hidden="true" { (settings_icon()) }
                div {
                    h3 { "Instance" }
                    p class="settings-section-tagline" {
                        "The name shown in the sidebar and on page titles."
                    }
                }
            }
            div class="settings-section-body" {
                form id="form-settings-identity"
                     class="settings-row"
                     hx-post="/settings/identity"
                     hx-swap="none" {
                    (csrf_input(ctx.csrf_token))
                    div class="settings-row-label" {
                        label for="settings-instance-name" { "Display name" }
                        p class="settings-row-hint" {
                            "Up to 64 characters. Leaving it blank restores the "
                            "configured default."
                        }
                    }
                    div class="settings-row-control" {
                        input type="text" id="settings-instance-name"
                              name="instance_name" value=(ctx.instance_name.as_str())
                              maxlength="64" autocomplete="off";
                        button type="submit" class="btn-secondary" { "Save" }
                    }
                }
            }
        }
    }
}

/// Email / notifications section: mode select + SMTP fields. Reauth-gated — the
/// Save button (in the header) drives `REAUTH_CHAIN_JS` via `data-reauth-confirm`,
/// which re-posts the form over htmx after a step-up. The password field is
/// write-only (`smtp_password`, never the literal `password` the chain strips)
/// and shows "saved" vs "not set" without revealing the secret.
fn settings_notifications_section(
    ctx: &ChromeContext,
    notifications: &server::config::NotificationsConfig,
    smtp_password_set: bool,
) -> Markup {
    use server::config::{NotificationsConfig, SmtpTls};
    let smtp = match notifications {
        NotificationsConfig::Smtp(s) => Some(s),
        _ => None,
    };
    let mode = match notifications {
        NotificationsConfig::Disabled => "disabled",
        NotificationsConfig::Log => "log",
        NotificationsConfig::Smtp(_) => "smtp",
    };
    let port = smtp.map(|s| s.port).unwrap_or(587);
    let port_str = port.to_string();
    let tls_val = match smtp.map(|s| s.tls) {
        Some(SmtpTls::Implicit) => "implicit",
        Some(SmtpTls::None) => "none",
        _ => "starttls",
    };
    let host = smtp.map(|s| s.host.as_str()).unwrap_or_default();
    let username = smtp.map(|s| s.username.as_str()).unwrap_or_default();
    let from_email = smtp.map(|s| s.from_email.as_str()).unwrap_or_default();
    let from_name = smtp.and_then(|s| s.from_name.as_deref()).unwrap_or_default();
    let pw_placeholder = if smtp_password_set {
        "Saved — leave blank to keep"
    } else {
        "SMTP password"
    };
    let smtp_hidden = mode != "smtp";

    html! {
        section class="settings-section" {
            div class="settings-section-header settings-section-header-actions" {
                div class="settings-section-heading" {
                    span class="settings-section-icon" aria-hidden="true" { (mail_icon()) }
                    div {
                        h3 { "Email" }
                        p class="settings-section-tagline" {
                            "How the instance sends mail — invitations and "
                            "account notifications."
                        }
                    }
                }
                // Carries credentials → reauth-gated. The button references the
                // form by id; REAUTH_CHAIN_JS re-posts it after the step-up.
                button type="button" class="btn-secondary"
                       data-reauth-confirm="form-settings-notifications" {
                    "Save email settings"
                }
            }
            div class="settings-section-body" {
                form id="form-settings-notifications"
                     method="post" action="/settings/notifications" {
                    (csrf_input(ctx.csrf_token))
                    div class="settings-row" {
                        div class="settings-row-label" {
                            label for="settings-notifications-mode" { "Delivery mode" }
                            p class="settings-row-hint" {
                                "Disabled sends nothing. Log records without "
                                "sending. SMTP delivers real email."
                            }
                        }
                        div class="settings-row-control" {
                            select name="mode" id="settings-notifications-mode"
                                   class="settings-select" {
                                option value="disabled" selected[mode == "disabled"] {
                                    "Disabled"
                                }
                                option value="log" selected[mode == "log"] { "Log only" }
                                option value="smtp" selected[mode == "smtp"] { "SMTP" }
                            }
                        }
                    }
                    div data-smtp-fields hidden[smtp_hidden] {
                        (settings_text_row("settings-smtp-host", "smtp_host",
                            "SMTP host", "text", host, "mail.example.com"))
                        (settings_text_row("settings-smtp-port", "smtp_port",
                            "Port", "number", &port_str, "587"))
                        div class="settings-row" {
                            div class="settings-row-label" {
                                label for="settings-smtp-tls" { "Encryption" }
                            }
                            div class="settings-row-control" {
                                select name="smtp_tls" id="settings-smtp-tls"
                                       class="settings-select" {
                                    option value="starttls" selected[tls_val == "starttls"] {
                                        "STARTTLS"
                                    }
                                    option value="implicit" selected[tls_val == "implicit"] {
                                        "Implicit TLS"
                                    }
                                    option value="none" selected[tls_val == "none"] { "None" }
                                }
                            }
                        }
                        (settings_text_row("settings-smtp-username", "smtp_username",
                            "Username", "text", username, "user@example.com"))
                        div class="settings-row" {
                            div class="settings-row-label" {
                                label for="settings-smtp-password" { "Password" }
                                p class="settings-row-hint" {
                                    "Stored encrypted. Leave blank to keep the "
                                    "current password."
                                }
                            }
                            div class="settings-row-control" {
                                input type="password" id="settings-smtp-password"
                                      name="smtp_password" placeholder=(pw_placeholder)
                                      autocomplete="off";
                            }
                        }
                        (settings_text_row("settings-smtp-from-email", "smtp_from_email",
                            "From address", "email", from_email, "noreply@example.com"))
                        (settings_text_row("settings-smtp-from-name", "smtp_from_name",
                            "From name", "text", from_name, "Sylva Hearth"))
                    }
                }

                // Sends through the *saved* notifier (configure → save → test),
                // not unsaved form values. CSRF-only; reports the result inline.
                form class="settings-row"
                     hx-post="/settings/notifications/test" hx-swap="none" {
                    (csrf_input(ctx.csrf_token))
                    div class="settings-row-label" {
                        label { "Test delivery" }
                        p class="settings-row-hint" {
                            "Sends a test message to your address using the saved "
                            "settings."
                        }
                    }
                    div class="settings-row-control" {
                        button type="submit" class="btn-secondary" {
                            "Send test email"
                        }
                    }
                }
            }
        }
    }
}

/// Danger zone: the Owner can permanently close the whole instance. Mirrors
/// the account-close section's restrained-red styling; the button opens the
/// confirm dialog fetched from `/modals/settings/shutdown`.
fn settings_danger_section() -> Markup {
    html! {
        section class="settings-section settings-section-danger" {
            div class="settings-section-header" {
                span class="settings-section-icon" aria-hidden="true" { (trash_icon()) }
                div {
                    h3 { "Close this server" }
                    p class="settings-section-tagline" {
                        "Permanently shut down the whole instance and erase all of \
                         its data, for everyone."
                    }
                }
            }
            div class="settings-section-body" {
                div class="settings-danger-row" {
                    p class="settings-row-hint" {
                        "Every account and everything created on this server is "
                        "removed, the server is closed for all members, and this "
                        "cannot be undone — the same teardown as the last member "
                        "deleting their account. Use it only to decommission the "
                        "instance."
                    }
                    div class="settings-row-actions" {
                        button type="button" class="btn-danger-ghost"
                               data-open-modal="/modals/settings/shutdown" {
                            "Close this server"
                        }
                    }
                }
            }
        }
    }
}

/// Confirm dialog for closing the whole server — fetched into `#modal-host`
/// from `/modals/settings/shutdown`. Two gates before the button enables (an
/// "I understand" checkbox + typing the server's name, wired by
/// `ACCOUNT_CLOSE_GATE_JS`), then the **critical** re-auth
/// (`data-reauth-critical`) always re-prompts before the scorch runs.
pub fn settings_shutdown_modal(ctx: &ChromeContext) -> Markup {
    let name = ctx.instance_name.as_str();
    html! {
        dialog id="dlg-settings-shutdown" class="action-dialog action-dialog-centered" {
            form id="form-settings-shutdown" method="post" action="/settings/shutdown" {
                div class="dialog-header" {
                    div class="dialog-icon dialog-icon-danger" { (trash_icon()) }
                    button type="button" class="dialog-close" data-close-dialog
                           aria-label="Close" {
                        (close_icon())
                    }
                }
                h2 class="dialog-center-title" { "Close this server" }
                p class="dialog-description dialog-center-text" {
                    "This permanently shuts down " strong { (name) } " and erases "
                    "every account and all data on it. Everyone is signed out and "
                    "the server shows a closed page from now on."
                }
                div class="dialog-alert dialog-alert-danger" role="alert" {
                    (alert_circle_icon())
                    span { "This wipes all data for everyone and cannot be undone." }
                }
                (csrf_input(ctx.csrf_token))
                label class="confirm-checkbox-field" {
                    input type="checkbox" class="member-checkbox" data-close-ack;
                    span { "I understand this permanently closes the server for all members." }
                }
                div class="field confirm-name-field" {
                    label for="confirm-shutdown-name" {
                        "Type the server name " strong { "\"" (name) "\"" } " to confirm"
                    }
                    input type="text" id="confirm-shutdown-name" data-close-email=(name)
                          autocomplete="off" spellcheck="false" autocapitalize="off";
                }
                div class="dialog-actions" {
                    button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                    button type="button" class="btn-danger"
                           data-reauth-confirm="form-settings-shutdown"
                           data-reauth-critical
                           disabled {
                        "Close this server"
                    }
                }
            }
        }
    }
}

/// Server recovery-code section: shows when the active code was last generated
/// and an Owner-only "Rotate" trigger. Rotating needs the current code (the
/// proof of possession), collected in the modal.
fn settings_recovery_section(created_at: Option<chrono::DateTime<chrono::Utc>>) -> Markup {
    html! {
        section class="settings-section" {
            div class="settings-section-header" {
                span class="settings-section-icon" aria-hidden="true" { (key_icon()) }
                div {
                    h3 { "Server recovery code" }
                    p class="settings-section-tagline" {
                        "The break-glass key: it unlocks owner recovery and forcing "
                        "owner changes past the veto window. Rotate it if it may be "
                        "exposed."
                    }
                }
            }
            div class="settings-section-body" {
                div class="settings-row" {
                    div class="settings-row-label" {
                        @match created_at {
                            Some(at) => {
                                span { "Active code generated " (at.format("%b %-d, %Y").to_string()) "." }
                            }
                            None => span { "No active recovery code." }
                        }
                        p class="settings-row-hint" {
                            "Rotating shows the new code once and immediately "
                            "invalidates the old one."
                        }
                    }
                    div class="settings-row-control" {
                        button type="button" class="btn-secondary"
                               data-open-modal="/modals/settings/recovery-code" {
                            "Rotate recovery code"
                        }
                    }
                }
            }
        }
    }
}

/// Confirm dialog for rotating the server recovery code — fetched into
/// `#modal-host` from `/modals/settings/recovery-code`. The form posts the
/// current code; the response swaps the dialog content in place: the new code
/// (shown once) on success, or the form with an inline error on a wrong code.
pub fn recovery_rotate_modal(ctx: &ChromeContext) -> Markup {
    html! {
        dialog id="dlg-recovery-rotate" class="action-dialog action-dialog-centered" {
            div id="recovery-rotate-content" {
                (recovery_rotate_form(ctx.csrf_token, None))
            }
        }
    }
}

/// The rotate form fragment (also re-rendered with `error` set when the
/// supplied current code didn't match).
pub fn recovery_rotate_form(csrf_token: &str, error: Option<&str>) -> Markup {
    html! {
        form id="form-recovery-rotate"
             hx-post="/settings/recovery-code/rotate"
             hx-target="#recovery-rotate-content" hx-swap="innerHTML" {
            div class="dialog-header" {
                div class="dialog-icon" { (key_icon()) }
                button type="button" class="dialog-close" data-close-dialog
                       aria-label="Close" { (close_icon()) }
            }
            h2 class="dialog-center-title" { "Rotate the server recovery code" }
            p class="dialog-description dialog-center-text" {
                "This generates a new server recovery code and immediately "
                "invalidates the current one. Enter the current code to confirm."
            }
            @if let Some(err) = error {
                div class="dialog-alert dialog-alert-danger" role="alert" {
                    (alert_circle_icon())
                    span { (err) }
                }
            }
            (csrf_input(csrf_token))
            div class="field" {
                label for="rotate-current-code" { "Current recovery code" }
                input type="text" id="rotate-current-code" name="current_code"
                      autocomplete="off" spellcheck="false" autocapitalize="off"
                      placeholder="XXXX-XXXX-XXXX-…" required;
            }
            div class="dialog-actions" {
                button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                button type="submit" class="btn-danger" { "Rotate code" }
            }
        }
    }
}

/// One label+input row for the SMTP form.
fn settings_text_row(
    id: &str,
    name: &str,
    label_text: &str,
    input_type: &str,
    value: &str,
    placeholder: &str,
) -> Markup {
    html! {
        div class="settings-row" {
            div class="settings-row-label" {
                label for=(id) { (label_text) }
            }
            div class="settings-row-control" {
                input type=(input_type) id=(id) name=(name) value=(value)
                      placeholder=(placeholder) autocomplete="off";
            }
        }
    }
}

/// Envelope glyph for the Email section header. Stroke uses `currentColor`.
fn mail_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg"
            width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" {
            rect x="2" y="4" width="20" height="16" rx="2" {}
            path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" {}
        }
    }
}

/// Toggles the SMTP field block based on the delivery-mode select, on load +
/// change, so the credential fields only show when mode is SMTP.
const SETTINGS_SMTP_TOGGLE_JS: &str = r#"
(function() {
  var sel = document.querySelector('select[name="mode"]');
  var fields = document.querySelector('[data-smtp-fields]');
  if (!sel || !fields) return;
  function sync() { fields.hidden = (sel.value !== 'smtp'); }
  sel.addEventListener('change', sync);
  sync();
})();
"#;

/// Kind of toast — drives the icon + colour palette. Three flavours:
///
/// * **Success** (green ✓) — a positive outcome (reactivated, role
///   updated, veto applied successfully).
/// * **Info** (neutral grey ⓘ) — a negative-but-reversible outcome
///   (deactivated, invitation revoked, pending review queued for a
///   reversible action). Matches the visual language operators
///   already use for "noted, here's what happened" notifications.
/// * **Error** (red !) — either a failed action or a completed but
///   truly irreversible negative outcome (deleted, purged, or a
///   pending row that will end in a delete/purge).
///
/// Serialized as snake_case on the wire so the client-side toast
/// renderer can switch on the same token.
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToastKind {
    Success,
    Info,
    Error,
}

/// Toast payload sent from server → client via the `sylva-toast`
/// HX-Trigger event. The client (see [`TOAST_JS`]) buffers it into
/// sessionStorage so it survives the HX-Redirect navigation that
/// usually accompanies the trigger, then renders it on the next
/// page load. Drained-on-read so a manual reload doesn't replay a
/// stale message.
#[derive(serde::Serialize)]
pub struct Toast {
    pub kind: ToastKind,
    pub title: String,
    pub message: String,
}

impl Toast {
    pub fn new(kind: ToastKind, title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            title: title.into(),
            message: message.into(),
        }
    }
}

/// Build a [`Toast`] payload for a successful action. Returns `None`
/// for unrecognised tokens so a forged request can't surface an
/// arbitrary banner via the HX-Trigger channel.
///
/// Kind picks the colour, following the reversibility rule:
///
/// * Positive outcome → `Success` (green): reactivated, role updated,
///   veto applied.
/// * Negative-but-reversible → `Info` (grey): deactivated, invitation
///   revoked, plus pending versions of those.
/// * Truly destructive → `Error` (red): deleted, purged, plus
///   pending versions of those (the 72h window can veto, but the
///   eventual outcome is permanent).
pub fn toast_for_action(action: &str, target: Option<&str>) -> Option<Toast> {
    let name = target.unwrap_or("This member");
    let (kind, title, message): (ToastKind, &str, String) = match action {
        // Reversible negatives — grey info palette.
        "deactivated" => (
            ToastKind::Info,
            "Deactivated",
            format!("{name} can no longer sign in."),
        ),
        "invite_revoked" => (
            ToastKind::Info,
            "Invitation revoked",
            "The pending invitation was revoked.".to_string(),
        ),
        "invitation_reissued" => (
            ToastKind::Info,
            "Invitation reissued",
            "A fresh acceptance URL was generated.".to_string(),
        ),
        "pending_deactivate" => (
            ToastKind::Info,
            "Awaiting review",
            "A 72-hour veto window has begun for the requested deactivation.".to_string(),
        ),
        "pending_role_change" => (
            ToastKind::Info,
            "Awaiting review",
            "A 72-hour veto window has begun for the requested role change.".to_string(),
        ),

        // Positive outcomes — green success palette.
        "reactivated" => (
            ToastKind::Success,
            "Reactivated",
            format!("{name} can sign in again."),
        ),
        "role_changed" => (
            ToastKind::Success,
            "Role updated",
            format!("{name}'s role has been updated."),
        ),
        "vetoed" => (
            ToastKind::Success,
            "Action vetoed",
            "The pending action was cancelled.".to_string(),
        ),

        // Irreversible negatives — red error palette. The pending
        // variants are red too because the eventual outcome (after
        // the 72h window if no one vetoes) is destructive — the
        // operator should still feel the weight of having queued it.
        //
        // "anonymized" keeps shared content under a redacted tombstone;
        // "deleted" is the full physical removal. The vocabulary is now
        // consistent end-to-end (routes, audit events, enums all match).
        "anonymized" => (
            ToastKind::Error,
            "Account anonymized",
            format!("{name}'s identity has been scrubbed."),
        ),
        "deleted" => (
            ToastKind::Error,
            "Account deleted",
            format!("{name}'s account has been fully removed."),
        ),
        "pending_anonymize" => (
            ToastKind::Error,
            "Awaiting review",
            "A 72-hour veto window has begun for the requested anonymization.".to_string(),
        ),
        "pending_delete" => (
            ToastKind::Error,
            "Awaiting review",
            "A 72-hour veto window has begun for the requested deletion.".to_string(),
        ),

        // /me account-settings outcomes — Profile and Email edits
        // emit these from POST /me/profile and POST /me/email after
        // their respective updates land. Green success palette to
        // match other positive outcomes.
        "profile_updated" => (
            ToastKind::Success,
            "Profile updated",
            "Your display name has been saved.".to_string(),
        ),
        "email_updated" => (
            ToastKind::Success,
            "Email updated",
            "Sign-in will use the new address from now on.".to_string(),
        ),
        "email_unchanged" => (
            ToastKind::Info,
            "Nothing to update",
            "That's already your email.".to_string(),
        ),
        "password_changed" => (
            ToastKind::Success,
            "Password changed",
            "Your password has been updated. Other devices were signed out.".to_string(),
        ),

        // Apps admin (Owner) — app lifecycle. `name` is the app's display name.
        "app_enabled" => (
            ToastKind::Success,
            "App enabled",
            format!("{name} can create and modify resources again."),
        ),
        "app_disabled" => (
            ToastKind::Info,
            "App disabled",
            format!("{name} can no longer create or modify resources. Its data is kept."),
        ),
        "app_uninstalled" => (
            ToastKind::Error,
            "App uninstalled",
            format!("{name} and all of its stored data have been removed."),
        ),
        "resource_deleted" => (
            ToastKind::Error,
            "Resource deleted",
            "The resource was permanently removed.".to_string(),
        ),
        "publisher_added" => (
            ToastKind::Success,
            "Publisher added",
            format!("{name} can now sign app registrations."),
        ),
        "publisher_removed" => (
            ToastKind::Info,
            "Publisher removed",
            format!("{name} can no longer sign new app registrations."),
        ),

        _ => return None,
    };
    Some(Toast::new(kind, title, message))
}

/// Build a red error toast payload from one of the codes in the
/// shared [`error_banner_message`] catalog.
pub fn toast_for_error(error_code: &str) -> Toast {
    Toast::new(
        ToastKind::Error,
        "Action failed",
        error_banner_message(error_code),
    )
}

/// Inline banner — for form-validation contexts that render _inside_
/// a modal or card (e.g. the invite modal's "email already in use"
/// feedback). Page-level success/error notifications go through
/// [`toast`]; this is only for scoped messages that need to sit next
/// to a specific input.
fn error_banner(error: &str) -> Markup {
    let msg = error_banner_message(error);
    html! {
        div class="banner banner-error" role="alert" { (msg) }
    }
}

/// Shared catalog of human-readable copy for every error code the
/// admin flows surface via `?error=` or inline form feedback. Pulled
/// out so the inline [`error_banner`] and the page-level
/// [`error_toast_for`] render the exact same wording — no drift
/// between "missing email" said one way in a banner and another way
/// in a toast.
fn error_banner_message(error: &str) -> &'static str {
    match error {
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
        "invalid_password" => "Incorrect password. Please try again.",
        // Invite-form errors. These re-render the form with the input
        // preserved (see members_invite_form_page).
        "email_required" => "Enter an email address.",
        "new_password_required" => "Enter a new password.",
        "totp_setup_expired" => "Two-factor setup expired. Start again from Security.",
        "cannot_invite_higher_role" => "You can't invite someone at a higher role than your own.",
        "email_already_in_use" => "A member with that email already exists.",
        "active_invite_exists" => "An open invitation already exists for that email.",
        // Revoke-invite errors. The kebab action redirects back here
        // with these codes when the underlying call refuses.
        "invite_not_found" => "That invitation no longer exists.",
        "invite_already_accepted" => "That invitation was already accepted.",
        "invite_expired" => {
            "That invitation has expired. Send a new one from the toolbar instead."
        }
        // /pending veto errors.
        "transition_not_found" => "That pending action no longer exists.",
        "not_pending" => {
            "That action is no longer pending. Another Owner may have just resolved it."
        }
        // Apps admin.
        "app_not_found" => "That app is no longer registered.",
        "resource_not_found" => "That resource no longer exists.",
        "publisher_name_required" => "Enter a publisher name.",
        "invalid_publisher_key" => "Enter a 64-character hex Ed25519 public key.",
        "publisher_not_found" => "That publisher is no longer in the list.",
        _ => "Something went wrong.",
    }
}

// ────────────────────────────────────────────────────────────────────────
// /pending — Owners-only veto review queue
// ────────────────────────────────────────────────────────────────────────

/// URL-driven banner state for the /pending page. Set by the veto
/// handler's redirect after the action (vetoed / error). Pattern
/// mirrors `MembersBanner`.
#[derive(Default)]
pub struct PendingBanner<'a> {
    pub action: Option<&'a str>,
    pub error: Option<&'a str>,
}

/// No-op — toasts are dispatched client-side. Same shape as
/// [`render_banner`]; both stay so the page renderers can keep their
/// existing call without churn.
fn render_pending_banner(_banner: &PendingBanner<'_>) -> Markup {
    html! {}
}


/// `GET /pending` — Owners-only directory of the currently-pending
/// Owner-on-Owner transitions. Each row shows who's being targeted,
/// what the action is, who started it, and how much of the 72-hour
/// window remains. The Veto button opens a confirmation dialog whose
/// Continue chains into the shared reauth modal.
///
/// Query params recognised by this page:
/// * `action=vetoed` — success banner after a successful veto.
/// * `error=transition_not_found` / `error=not_pending` — failure
///   banners after a race with another Owner / the 72h sweeper.
pub fn pending_page(
    ctx: &ChromeContext,
    active: &[pending::TransitionRow],
    history: &[pending::TransitionRow],
    users: &[identity::User],
    banner: PendingBanner<'_>,
) -> Markup {
    use std::collections::HashMap;
    let by_id: HashMap<uuid::Uuid, &identity::User> =
        users.iter().map(|u| (u.id.0, u)).collect();

    let content = html! {
        (render_pending_banner(&banner))
        // `tpl-dlg-reauth` is mounted once at the shell level (see
        // `shell_app_inner`); REAUTH_CHAIN_JS materializes `dlg-reauth`
        // from it on the first chain run. No per-page copy needed.

        @if active.is_empty() {
            (pending_empty_state())
        } @else {
            div class="card pending-card" {
                table class="users-table pending-table" {
                    thead {
                        tr {
                            th class="col-pending-target" { "Target" }
                            th class="col-pending-action" { "Action" }
                            th class="col-pending-initiator" { "Initiated by" }
                            th class="col-pending-remaining" { "Time remaining" }
                            th class="col-pending-actions" { span class="sr-only" { "Actions" } }
                        }
                    }
                    tbody {
                        @for row in active {
                            (pending_active_row(ctx, row, &by_id))
                        }
                    }
                }
            }
        }

        // History section — recently-resolved transitions. Hidden
        // entirely when empty so a fresh install doesn't show an
        // empty "History" header for no reason.
        @if !history.is_empty() {
            h2 class="pending-history-header" { "History" }
            div class="card pending-card" {
                table class="users-table pending-table pending-history-table" {
                    thead {
                        tr {
                            th class="col-pending-target" { "Target" }
                            th class="col-pending-action" { "Action" }
                            th class="col-pending-resolution" { "Resolution" }
                            th class="col-pending-initiator" { "Resolved by" }
                            th class="col-pending-remaining" { "Resolved" }
                        }
                    }
                    tbody {
                        @for row in history {
                            (pending_history_row(row, &by_id))
                        }
                    }
                }
            }
        }

        // Wire up the dialog open/close + reauth chain JS used by the
        // per-row Veto buttons. Same constants the Members page uses.
        script { (maud::PreEscaped(REAUTH_CHAIN_JS)) }
    };

    shell_app_wide(ctx, "Pending review", PageId::Pending, content)
}

/// Empty state for the /pending page — no active pending transitions.
/// Shown both when the queue starts empty and after the operator
/// vetoes the last item.
fn pending_empty_state() -> Markup {
    html! {
        div class="card pending-empty" {
            div class="dialog-icon dialog-icon-shield pending-empty-icon" {
                (shield_icon())
            }
            h2 { "Nothing pending" }
            p {
                "Owner-on-Owner deactivations, anonymizations, deletes, and "
                "role changes wait here for 72 hours so any Owner can veto. "
                "When something gets queued, it shows up on this page."
            }
        }
    }
}

/// One row of the active /pending table. Renders the target and
/// initiator using the standard avatar + name treatment, the action
/// verb (e.g. "Promote to Owner", "Delete"), a time-remaining pill,
/// and a Veto button that opens a per-row confirmation dialog. The
/// row has `id="row-{transition_id}"` so the member-row badge on
/// `/members` can deep-link straight to it via fragment.
fn pending_active_row(
    _ctx: &ChromeContext,
    row: &pending::TransitionRow,
    by_id: &std::collections::HashMap<uuid::Uuid, &identity::User>,
) -> Markup {
    // `_ctx` is unused — the veto dialog is fetched on demand and the
    // fragment endpoint renders its own CSRF input. Kept on the
    // signature so the /pending page call site stays uniform.
    let target = row.target_user_id.and_then(|id| by_id.get(&id).copied());
    let initiator = row.initiator_user_id.and_then(|id| by_id.get(&id).copied());
    let action_label = pending_action_label(row);

    html! {
        tr class="pending-row" id=(format!("row-{}", row.id)) {
            td class="col-pending-target" {
                @if let Some(u) = target {
                    (user_cell(u))
                } @else {
                    span class="muted-dash" { "(unknown member)" }
                }
            }
            td class="col-pending-action" { (action_label) }
            td class="col-pending-initiator" {
                @if let Some(u) = initiator {
                    span class="user-name" { (u.display_name) }
                } @else {
                    span class="muted-dash" { "—" }
                }
            }
            td class="col-pending-remaining" {
                (time_remaining_pill(row.effective_at))
            }
            td class="col-pending-actions" {
                button type="button" class="btn-secondary"
                       data-open-modal=(format!("/pending/{}/modal/veto", row.id)) {
                    "Veto"
                }
                // Break-glass: force the action through now (bypass the veto
                // window) with the server recovery code.
                button type="button" class="btn-danger-ghost"
                       data-open-modal=(format!("/pending/{}/modal/force-apply", row.id)) {
                    "Force apply"
                }
            }
        }
    }
}

/// One row of the /pending History table — terminal rows (vetoed,
/// cancelled, or applied by the 72h sweeper). Shares avatar + action
/// styling with the active row but swaps the "time remaining" pill
/// for a resolution badge + when-resolved timestamp, and drops the
/// Veto column entirely (the row is already final).
fn pending_history_row(
    row: &pending::TransitionRow,
    by_id: &std::collections::HashMap<uuid::Uuid, &identity::User>,
) -> Markup {
    use pending::TransitionState;
    let target = row.target_user_id.and_then(|id| by_id.get(&id).copied());
    let resolver = row.resolved_by_user_id.and_then(|id| by_id.get(&id).copied());
    let action_label = pending_action_label(row);
    let (resolution_label, resolution_class) = match row.state {
        TransitionState::Vetoed => ("Vetoed", "resolution-badge resolution-vetoed"),
        TransitionState::Cancelled => ("Cancelled", "resolution-badge resolution-cancelled"),
        TransitionState::Applied => ("Applied", "resolution-badge resolution-applied"),
        // Active rows never reach this helper, but render a sensible
        // fallback rather than panicking if the data layer hands one
        // through.
        TransitionState::Pending => ("Pending", "resolution-badge"),
    };

    html! {
        tr class="pending-row pending-history-row" {
            td class="col-pending-target" {
                @if let Some(u) = target {
                    (user_cell(u))
                } @else {
                    span class="muted-dash" { "(unknown member)" }
                }
            }
            td class="col-pending-action" { (action_label) }
            td class="col-pending-resolution" {
                span class=(resolution_class) { (resolution_label) }
            }
            td class="col-pending-initiator" {
                @match (row.state, resolver) {
                    // System-applied (72h timer) has no human resolver
                    // — render a neutral label instead of a blank.
                    (TransitionState::Applied, None) => {
                        span class="muted-dash" { "Timer (72h)" }
                    }
                    (_, Some(u)) => span class="user-name" { (u.display_name) }
                    _ => span class="muted-dash" { "—" }
                }
            }
            td class="col-pending-remaining" {
                @if let Some(ts) = row.resolved_at {
                    span class="muted" { (short_date(ts)) }
                } @else {
                    span class="muted-dash" { "—" }
                }
            }
        }
    }
}

/// Small chip rendered on `/members` rows whose target has a
/// currently-pending Owner-on-Owner transition. Links to the matching
/// row on `/pending` via `#row-{transition_id}` fragment so Owners can
/// jump straight to the Veto button. Time-remaining suffix borrows
/// the same compact format used in the active /pending table.
fn member_pending_pill(p: &pending::TransitionRow) -> Markup {
    let action = pending_action_label(p);
    let remaining = time_remaining_short(p.effective_at);
    let href = format!("/pending#row-{}", p.id);
    let label = format!("Pending: {action} · {remaining}");
    html! {
        a class="member-pending-pill"
          href=(href)
          title=("View on Pending review") {
            (label)
        }
    }
}

/// Compact "47h" / "8m" / "soon" rendering used in the inline
/// member-row pill. Drops the "left" suffix that the full table uses
/// since the chip is already labeled "Pending: …".
fn time_remaining_short(effective_at: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let delta = effective_at - now;
    if delta.num_seconds() <= 0 {
        "soon".to_string()
    } else if delta.num_hours() >= 1 {
        format!("{}h", delta.num_hours())
    } else {
        format!("{}m", delta.num_minutes().max(1))
    }
}

/// Avatar + name + email cell shared between the active and history
/// tables. Factored out so the two row renderers stay symmetric.
fn user_cell(u: &identity::User) -> Markup {
    html! {
        div class="user-row-id" {
            (avatar_block(&u.display_name, &u.id.0, u.lifecycle))
            div class="user-row-text" {
                span class="user-name" { (u.display_name) }
                span class="user-email" { (u.email) }
            }
        }
    }
}

/// Per-row Veto confirmation dialog. Centered chrome with a warning
/// (amber) feature icon; chains into the shared reauth modal via the
/// standard `data-reauth-confirm` attribute.
pub(crate) fn veto_pending_dialog(
    transition_id: uuid::Uuid,
    target_name: &str,
    action_label: &str,
    csrf_token: &str,
) -> Markup {
    html! {
        dialog id=(format!("dlg-veto-{transition_id}"))
               class="action-dialog action-dialog-centered" {
            form id=(format!("form-veto-{transition_id}"))
                 method="post"
                 action=(format!("/pending/{transition_id}/veto")) {
                div class="dialog-header" {
                    div class="dialog-icon dialog-icon-shield" {
                        (shield_icon())
                    }
                    button type="button" class="dialog-close" data-close-dialog
                           aria-label="Close" {
                        (close_icon())
                    }
                }
                h2 { "Veto this pending action?" }
                p class="dialog-description" {
                    "Stops the pending " strong { (action_label) } " on "
                    strong { (target_name) } ". The initiator will be "
                    "notified that you cancelled it. The action can be "
                    "started again from the Members page."
                }
                (csrf_input(csrf_token))
                div class="dialog-actions" {
                    button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                    button type="button" class="btn"
                           data-reauth-confirm=(format!("form-veto-{transition_id}")) {
                        "Veto"
                    }
                }
            }
        }
    }
}

/// Confirm dialog for force-applying a pending transition with the server
/// recovery code — fetched into `#modal-host` from
/// `/pending/{id}/modal/force-apply`. Wraps the form in a swappable content
/// div so a wrong code can re-render inline.
pub(crate) fn force_apply_dialog(
    transition_id: uuid::Uuid,
    target_name: &str,
    action_label: &str,
    csrf_token: &str,
) -> Markup {
    html! {
        dialog id=(format!("dlg-force-apply-{transition_id}"))
               class="action-dialog action-dialog-centered" {
            div id=(format!("force-apply-content-{transition_id}")) {
                (force_apply_form(transition_id, target_name, action_label, csrf_token, None))
            }
        }
    }
}

/// The force-apply form fragment (re-rendered with `error` when the supplied
/// recovery code didn't match). Posts the recovery code; the response either
/// redirects to `/pending` (success / already-resolved) or swaps this fragment
/// back in with the error.
pub(crate) fn force_apply_form(
    transition_id: uuid::Uuid,
    target_name: &str,
    action_label: &str,
    csrf_token: &str,
    error: Option<&str>,
) -> Markup {
    html! {
        form id=(format!("form-force-apply-{transition_id}"))
             hx-post=(format!("/pending/{transition_id}/force-apply"))
             hx-target=(format!("#force-apply-content-{transition_id}"))
             hx-swap="innerHTML" {
            div class="dialog-header" {
                div class="dialog-icon dialog-icon-danger" { (alert_circle_icon()) }
                button type="button" class="dialog-close" data-close-dialog
                       aria-label="Close" { (close_icon()) }
            }
            h2 class="dialog-center-title" { "Force this action through?" }
            p class="dialog-description dialog-center-text" {
                "Applies the pending " strong { (action_label) } " on "
                strong { (target_name) } " immediately, bypassing the 72-hour "
                "veto window — the target can no longer veto it. Use this only to "
                "remove an owner who's lost access or gone rogue. It can't be undone."
            }
            @if let Some(err) = error {
                div class="dialog-alert dialog-alert-danger" role="alert" {
                    (alert_circle_icon())
                    span { (err) }
                }
            }
            (csrf_input(csrf_token))
            div class="field" {
                label for=(format!("force-code-{transition_id}")) {
                    "Server recovery code"
                }
                input type="text" id=(format!("force-code-{transition_id}"))
                      name="recovery_code" autocomplete="off" spellcheck="false"
                      autocapitalize="off" placeholder="XXXX-XXXX-XXXX-…" required;
            }
            div class="dialog-actions" {
                button type="button" class="btn-secondary" data-close-dialog { "Cancel" }
                button type="submit" class="btn-danger" { "Force apply" }
            }
        }
    }
}

/// Human-readable verb for a pending transition. Lifecycle kinds
/// render as the action name; role-change kinds render as
/// "Promote to Owner", "Demote to Member", etc., based on the
/// payload's target role.
pub(crate) fn pending_action_label(row: &pending::TransitionRow) -> String {
    use pending::TransitionKind;
    match row.kind {
        TransitionKind::Deactivate => "Deactivate".to_string(),
        TransitionKind::Anonymize => "Anonymize".to_string(),
        TransitionKind::Delete => "Delete".to_string(),
        TransitionKind::RoleChange => match row.role_payload() {
            Ok(payload) => match payload.to_role {
                InstanceRole::Owner => "Promote to Owner".to_string(),
                InstanceRole::Admin => "Change to Admin".to_string(),
                InstanceRole::Member => "Demote to Member".to_string(),
            },
            // Bad payload is logged at apply time; in the UI we just
            // fall back to a generic label so the row still renders.
            Err(_) => "Change role".to_string(),
        },
    }
}

/// Small pill rendering "47h left" / "8m left" / "Imminent". When the
/// remaining duration is below 1 hour the pill switches to minutes;
/// once `effective_at` has already passed (the sweeper hasn't run yet)
/// it shows "Imminent" instead of a negative count.
fn time_remaining_pill(effective_at: chrono::DateTime<chrono::Utc>) -> Markup {
    let now = chrono::Utc::now();
    let delta = effective_at - now;
    let (text, class) = if delta.num_seconds() <= 0 {
        ("Imminent".to_string(), "time-pill time-pill-urgent")
    } else if delta.num_hours() >= 1 {
        (format!("{}h left", delta.num_hours()), "time-pill")
    } else {
        let mins = delta.num_minutes().max(1);
        (format!("{mins}m left"), "time-pill time-pill-urgent")
    };
    html! {
        span class=(class) { (text) }
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

/// `POST /invite/{token}` success — the one-time recovery-code
/// interstitial. Rendered as the POST response body (not a redirect)
/// so the code rides exactly one HTTP exchange and never lands in the
/// URL bar, browser history, referer header, or access log. The
/// session cookie is already set by the caller before this view
/// renders, so the new user is signed in — clicking "Continue" is a
/// plain GET to `/me`.
///
/// Refresh-safety: refreshing this page re-posts the original form, the
/// invitation is already accepted, and the route renders
/// [`accept_invite_invalid_page`] instead. The code never re-renders.
pub fn accept_invite_recovery_code_page(recovery_code: &str) -> Markup {
    let content = html! {
        h1 { "Save your recovery code" }
        div class="card recovery-code-card" {
            p class="recovery-code-intro" {
                "This is your account recovery code. You'll need it if "
                "you ever forget your password or lose access to a second "
                "factor. Sylva is offline-first — we won't email you a "
                "reset link, so this code is the only way back in."
            }
            div class="recovery-code-display" {
                // Readonly text input so INVITE_COPY_JS (loaded below)
                // can grab the value via the same `data-copy-target`
                // pattern used by the invite-URL copy button.
                input id="recovery-code"
                      type="text"
                      class="recovery-code-input"
                      value=(recovery_code)
                      readonly
                      aria-label="Account recovery code";
                button type="button"
                       class="btn-secondary"
                       data-copy-target="recovery-code" {
                    "Copy"
                }
            }
            div class="dialog-alert dialog-alert-danger" role="alert" {
                (alert_circle_icon())
                span {
                    "Save it somewhere safe before continuing. We won't "
                    "show this code again. If you lose it, regenerating "
                    "a new one from settings will replace this one — any "
                    "saved copy will stop working."
                }
            }
            form method="get" action="/me" class="recovery-code-actions" {
                label class="recovery-code-confirm" {
                    input type="checkbox"
                          class="member-checkbox"
                          required;
                    span {
                        "I've saved my recovery code somewhere safe."
                    }
                }
                button type="submit" class="btn" {
                    "Continue to your account"
                }
            }
        }
        script {
            (maud::PreEscaped(INVITE_COPY_JS))
        }
    };
    shell_public("Save your recovery code", content)
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
    use super::{PageItem, device_label, page_items};

    #[test]
    fn device_label_parses_common_user_agents() {
        // Edge/Opera UAs also contain "Chrome"; Chrome UAs also contain
        // "Safari" — the ordering in `device_label` must disambiguate.
        assert_eq!(
            device_label("Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.0 Safari/537.36"),
            "Chrome on Windows"
        );
        assert_eq!(
            device_label(
                "Mozilla/5.0 (Windows NT 10.0) AppleWebKit Chrome/120 Safari Edg/120.0"
            ),
            "Edge on Windows"
        );
        assert_eq!(
            device_label(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17.0 Safari/604.1"
            ),
            "Safari on iOS"
        );
        assert_eq!(
            device_label("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Firefox/121.0"),
            "Firefox on macOS"
        );
        assert_eq!(
            device_label("Mozilla/5.0 (Linux; Android 14) Chrome/120 Mobile"),
            "Chrome on Android"
        );
        assert_eq!(device_label(""), "Unknown device");
        assert_eq!(device_label("curl/8.4.0"), "Unknown device");
    }

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
        // current=7, total=10: total-3 = 7, so current >= total-3
        // triggers the left-leaning case → 1 … 6 7 8 9 10.
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
