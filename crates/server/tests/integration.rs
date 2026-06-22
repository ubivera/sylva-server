#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

#[path = "integration/common.rs"]
mod common;

#[path = "integration/account_grpc.rs"]
mod account_grpc;
#[path = "integration/audit_chain.rs"]
mod audit_chain;
#[path = "integration/discovery.rs"]
mod discovery;
#[path = "integration/enrollment.rs"]
mod enrollment;
#[path = "integration/platform_grpc.rs"]
mod platform_grpc;
#[path = "integration/machine_grpc.rs"]
mod machine_grpc;
// Cross-stack e2e — only built with `--features e2e` (pulls the sibling sylva-sdk).
#[cfg(feature = "e2e")]
#[path = "integration/sdk_e2e.rs"]
mod sdk_e2e;
