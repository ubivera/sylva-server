pub mod app;
pub mod auth_routes;
pub mod config;
pub mod db;
pub mod health;
#[cfg(windows)]
pub mod job_object;
pub mod postgres;
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
        data_dir = %config.data_dir.display(),
        "starting hearth"
    );

    #[cfg(windows)]
    match job_object::JobObject::assign_current_process_for_kill_on_close() {
        Ok(job) => {
            std::mem::forget(job);
            tracing::info!("installed Windows job-object safety net for child cleanup");
        }
        Err(err) => {
            tracing::warn!(
                ?err,
                "could not install Windows job-object safety net; \
                 hard-kill cleanup of bundled postgres may leave orphan workers"
            );
        }
    }

    let started_at = std::time::Instant::now();

    let postgres = postgres::PostgresProcess::start(
        config.pg_bin_dir(),
        config.pg_data_dir(),
        config.postgres_port(),
    )
    .await
    .context("starting bundled postgres")?;

    let serve_result = serve(&config, started_at).await;

    if let Err(err) = postgres.stop().await {
        tracing::warn!(?err, "error stopping postgres");
    }

    serve_result
}

async fn serve(config: &config::Config, started_at: std::time::Instant) -> anyhow::Result<()> {
    let pool = db::connect(&config.postgres_url).await?;
    db::run_migrations(&pool).await?;
    tracing::info!("migrations up to date");

    let users = identity::UserRepository::new(pool.clone());
    let sessions = auth::SessionRepository::new(pool.clone());
    let router = app::router(started_at, pool.clone(), users, sessions);

    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.listen_addr))?;

    tracing::info!(listen = %config.listen_addr, "http server listening");

    let serve_outcome = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown::signal())
        .await
        .context("server error");

    pool.close().await;
    tracing::info!("hearth http server stopped");
    serve_outcome
}
