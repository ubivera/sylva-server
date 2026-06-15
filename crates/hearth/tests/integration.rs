#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

#[path = "integration/common.rs"]
mod common;

#[path = "integration/account.rs"]
mod account;
#[path = "integration/admin.rs"]
mod admin;
#[path = "integration/apps.rs"]
mod apps;
#[path = "integration/audit_chain.rs"]
mod audit_chain;
#[path = "integration/auth.rs"]
mod auth;
#[path = "integration/events.rs"]
mod events;
#[path = "integration/notifications.rs"]
mod notifications;
#[path = "integration/pending_transitions.rs"]
mod pending_transitions;
#[path = "integration/platform_grpc.rs"]
mod platform_grpc;
#[path = "integration/recovery.rs"]
mod recovery;
#[path = "integration/settings.rs"]
mod settings;
#[path = "integration/web.rs"]
mod web;
#[path = "integration/web_admin_actions.rs"]
mod web_admin_actions;
