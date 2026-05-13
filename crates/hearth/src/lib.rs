pub mod app;
pub mod config;
pub mod health;
pub mod shutdown;
pub mod telemetry;

use anyhow::Context;

pub fn run() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build Tokio runtime")?;
    runtime.block_on(run_async())
}

async fn run_async() -> anyhow::Result<()> {
    let config = config::Config::from_env()?;
    telemetry::init(&config)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        listen = %config.listen_addr,
        "starting hearth"
    );

    let started_at = std::time::Instant::now();
    let router = app::router(started_at);

    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.listen_addr))?;

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown::signal())
        .await
        .context("server error")?;

    tracing::info!("hearth shut down cleanly");
    Ok(())
}
