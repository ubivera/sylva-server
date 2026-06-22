//! Generate the gRPC stubs from the canonical `.proto` at the repo root.
//!
//! Uses `protox` (a pure-Rust protobuf compiler) to produce a
//! `FileDescriptorSet`, then hands it to `tonic-prost-build` — so the build
//! needs no system `protoc` binary (important on the locked-down Windows env).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Paths are relative to this crate's dir (crates/proto); the canonical
    // protos live at the workspace root under `proto/`.
    const PLATFORM_PROTO: &str = "../../proto/platform/v1/platform.proto";
    const ACCOUNT_PROTO: &str = "../../proto/account/v1/account.proto";
    const MACHINE_PROTO: &str = "../../proto/machine/v1/machine.proto";
    const INCLUDE: &str = "../../proto";

    println!("cargo:rerun-if-changed={PLATFORM_PROTO}");
    println!("cargo:rerun-if-changed={ACCOUNT_PROTO}");
    println!("cargo:rerun-if-changed={MACHINE_PROTO}");
    println!("cargo:rerun-if-changed={INCLUDE}");

    // protox compiles the files into one FileDescriptorSet; tonic-prost-build
    // then emits one `<package>.rs` per package into OUT_DIR.
    let file_descriptors = protox::compile([PLATFORM_PROTO, ACCOUNT_PROTO, MACHINE_PROTO], [INCLUDE])?;
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_fds(file_descriptors)?;
    Ok(())
}
