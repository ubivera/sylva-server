pub mod account_routes;
pub mod admin_routes;
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
pub mod views;

use anyhow::Context;

/// Type of the UI-router builder passed in by the bin crate. Given the
/// composed [`app::AppState`], returns an `axum::Router` to be merged
/// alongside the JSON API at server boot.
pub type UiRouterFn = fn(app::AppState) -> axum::Router;

/// Entry point used by `hearth-server`'s `main`. The `ui_router` parameter
/// lets the binary plug in the [`web`](https://docs.rs/web) crate's HTML
/// router without `hearth` having a circular dependency on it.
pub fn run(ui_router: UiRouterFn) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build Tokio runtime")?;
    runtime.block_on(run_async(ui_router))
}

async fn run_async(ui_router: UiRouterFn) -> anyhow::Result<()> {
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

    let serve_result = serve(&config, started_at, ui_router).await;

    if let Err(err) = postgres.stop().await {
        tracing::warn!(?err, "error stopping postgres");
    }

    serve_result
}

async fn serve(
    config: &config::Config,
    started_at: std::time::Instant,
    ui_router: UiRouterFn,
) -> anyhow::Result<()> {
    let pool = db::connect(&config.postgres_url).await?;
    db::run_migrations(&pool).await?;
    tracing::info!("migrations up to date");

    let users = identity::UserRepository::new(pool.clone());
    let sessions = auth::SessionRepository::new(pool.clone());
    let invitations = identity::InvitationRepository::new(pool.clone());

    let notifier = build_notifier(&config.notifications)?;
    let notif_worker = notifications::Worker::new(pool.clone(), notifier);
    let (worker_shutdown_tx, worker_shutdown_rx) =
        tokio::sync::watch::channel::<bool>(false);
    let notif_handle = tokio::spawn(
        notif_worker.run_forever(std::time::Duration::from_secs(5), worker_shutdown_rx.clone()),
    );
    tracing::info!(
        mode = ?notifications_mode_label(&config.notifications),
        "notification worker started"
    );

    let pending_worker = pending::Worker::new(pool.clone());
    let pending_handle = tokio::spawn(
        pending_worker.run_forever(std::time::Duration::from_secs(30), worker_shutdown_rx),
    );
    tracing::info!("pending-transition worker started");

    let state = app::AppState {
        started_at,
        db: pool.clone(),
        users,
        sessions,
        invitations,
        public_base_url: config.public_base_url.clone(),
    };

    let health = axum::Router::new()
        .route("/health", axum::routing::get(health::handler))
        .with_state(state.clone());

    let router = axum::Router::new()
        .nest("/api", app::api_router(state.clone()))
        .merge(ui_router(state))
        .merge(health)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.listen_addr))?;

    tracing::info!(listen = %config.listen_addr, "http server listening");

    let serve_outcome = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown::signal())
        .await
        .context("server error");

    // Tell the workers to wind down, then await them (best-effort).
    let _ = worker_shutdown_tx.send(true);
    if let Err(err) = notif_handle.await {
        tracing::warn!(?err, "notification worker join failed");
    }
    if let Err(err) = pending_handle.await {
        tracing::warn!(?err, "pending-transition worker join failed");
    }

    pool.close().await;
    tracing::info!("hearth http server stopped");
    serve_outcome
}

fn build_notifier(cfg: &config::NotificationsConfig) -> anyhow::Result<notifications::NotifierImpl> {
    match cfg {
        config::NotificationsConfig::Disabled => Ok(notifications::NotifierImpl::Disabled),
        config::NotificationsConfig::Log => Ok(notifications::NotifierImpl::Log),
        config::NotificationsConfig::Smtp(s) => {
            let smtp = notifications::SmtpNotifier::build(notifications::SmtpConfig {
                host: s.host.clone(),
                port: s.port,
                tls: match s.tls {
                    config::SmtpTls::Starttls => notifications::SmtpTls::Starttls,
                    config::SmtpTls::Implicit => notifications::SmtpTls::Implicit,
                    config::SmtpTls::None => notifications::SmtpTls::None,
                },
                username: s.username.clone(),
                password: s.password.clone(),
                from: notifications::FromAddress {
                    email: s.from_email.clone(),
                    name: s.from_name.clone(),
                },
            })?;
            Ok(notifications::NotifierImpl::Smtp(std::sync::Arc::new(smtp)))
        }
    }
}

fn notifications_mode_label(cfg: &config::NotificationsConfig) -> &'static str {
    match cfg {
        config::NotificationsConfig::Disabled => "disabled",
        config::NotificationsConfig::Log => "log",
        config::NotificationsConfig::Smtp(_) => "smtp",
    }
}
