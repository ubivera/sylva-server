//! Generated gRPC stubs for the Sylva Hearth platform API.
//!
//! This crate is codegen output (protox + tonic-prost-build, see `build.rs`).
//! It deliberately does not inherit the workspace deny-lints — generated code
//! is not hand-audited and would otherwise trip `unwrap_used`/etc.
#![allow(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(rust_2018_idioms, unused_qualifications)]
#![allow(missing_docs)]

pub mod platform {
    pub mod v1 {
        // tonic-prost-build writes `<package>.rs` to OUT_DIR.
        include!(concat!(env!("OUT_DIR"), "/sylva.platform.v1.rs"));
    }
}
