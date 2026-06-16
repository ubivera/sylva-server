//! Generate the gRPC stubs from the canonical `.proto` at the repo root.
//!
//! Uses `protox` (a pure-Rust protobuf compiler) to produce a
//! `FileDescriptorSet`, then hands it to `tonic-prost-build` — so the build
//! needs no system `protoc` binary (important on the locked-down Windows env).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Paths are relative to this crate's dir (crates/proto); the canonical
    // protos live at the workspace root under `proto/`.
    const PROTO: &str = "../../proto/platform/v1/platform.proto";
    const INCLUDE: &str = "../../proto";

    println!("cargo:rerun-if-changed={PROTO}");
    println!("cargo:rerun-if-changed={INCLUDE}");

    let file_descriptors = protox::compile([PROTO], [INCLUDE])?;
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_fds(file_descriptors)?;
    Ok(())
}
