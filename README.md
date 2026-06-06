![Hearth hero image](docs/images/header.png)

<h1 align="center">
    Ubivera.Sylva.Hearth
</h1>

The server for the Sylva ecosystem; a self-hosted, privacy-first, end-to-end encrypted modular monolith.

## Build Prerequisites

Windows + MSVC toolchain + Rust 1.95 via `rustup`.

```bash
cargo run --bin bootstrap
cargo run --bin hearth
cargo run --bin clean
```

```bash
cargo clippy --all-targets -- -D warnings
cargo test --workspace --lib
cargo test --test integration
```