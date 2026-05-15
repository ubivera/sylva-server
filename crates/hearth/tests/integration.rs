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
#[path = "integration/audit_chain.rs"]
mod audit_chain;
#[path = "integration/auth.rs"]
mod auth;
