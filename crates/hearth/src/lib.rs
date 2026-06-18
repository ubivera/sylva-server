pub mod account_logic;
pub mod account_routes;
pub mod admin_logic;
pub mod admin_routes;
pub mod app;
pub mod auth_routes;
pub mod config;
pub mod csrf;
pub mod db;
pub mod health;
pub mod instance;
#[cfg(windows)]
pub mod job_object;
pub mod mfa;
pub mod postgres;
pub mod rate_limit;
pub mod settings_logic;
pub mod shutdown;
pub mod signed_token;
pub mod webauthn;
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

    // Postgres opens its TCP listener before the SQL layer accepts queries
    // (especially after an unclean prior shutdown — crash recovery + fsync
    // of the data dir can take 20+ seconds). Without this gate, the very
    // first pool acquire below races and times out.
    db::wait_until_ready(&config.postgres_url)
        .await
        .context("waiting for postgres SQL layer to come up")?;
    tracing::info!("bundled postgres SQL layer ready");

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

    // Effective config = DB overrides (Owner Settings page) layered over the
    // env defaults. Seeds the hot-swappable `instance_name` + `notifier` cells;
    // the notifier cell is shared with the worker so a live SMTP change applies
    // on the next send.
    let secret_key = std::sync::Arc::new(config.load_secret_key()?);
    let effective = instance::effective(&pool, config, &secret_key).await?;
    let notifier = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(build_notifier(
        &effective.notifications,
    )?));
    let instance_name =
        std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(effective.instance_name));
    let notif_worker = notifications::Worker::new(pool.clone(), notifier.clone());
    // One shutdown signal fans out to both servers (HTTP + gRPC) and both
    // background workers. `shutdown::signal()` can only be awaited once, so a
    // bridge task awaits it and flips this watch; everyone else observes it.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel::<bool>(false);
    {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            shutdown::signal().await;
            let _ = shutdown_tx.send(true);
        });
    }
    let notif_handle = tokio::spawn(
        notif_worker.run_forever(std::time::Duration::from_secs(5), shutdown_rx.clone()),
    );
    tracing::info!(
        mode = ?notifications_mode_label(&effective.notifications),
        "notification worker started"
    );

    let pending_worker = pending::Worker::new(pool.clone());
    let pending_handle = tokio::spawn(
        pending_worker.run_forever(std::time::Duration::from_secs(30), shutdown_rx.clone()),
    );
    tracing::info!("pending-transition worker started");

    // Seed the cached closed flag from the persistent singleton so a restart
    // of an already-closed instance keeps serving the closed page.
    let instance_closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
        instance::load_closed(&pool).await.unwrap_or(false),
    ));

    // Context for the gRPC platform services — clones of the same repositories
    // the REST layer uses (cheap; each just wraps the pool). Built before the
    // AppState literal below moves the originals.
    let platform_ctx = platform::PlatformContext {
        sessions: sessions.clone(),
        users: users.clone(),
        resources: platform::resources::ResourceRepository::new(pool.clone()),
        user_keys: identity::UserKeyRepository::new(pool.clone()),
        devices: identity::DeviceRepository::new(pool.clone()),
        pool: pool.clone(),
        secret_key: secret_key.clone(),
    };

    let state = app::AppState {
        started_at,
        db: pool.clone(),
        users,
        sessions,
        invitations,
        public_base_url: config.public_base_url.clone(),
        instance_name,
        notifier,
        env_config: std::sync::Arc::new(config.clone()),
        csrf_secret: std::sync::Arc::new(csrf::generate_secret()),
        rate_limiter: std::sync::Arc::new(rate_limit::RateLimiter::auth_default()),
        secret_key,
        trust_proxy: config.trust_proxy,
        instance_closed,
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

    // gRPC platform API on its own listener (separate port; a reverse proxy
    // routes HTTP/2 here in production). Shares the same shutdown watch.
    let grpc_listener = tokio::net::TcpListener::bind(config.grpc_listen_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.grpc_listen_addr))?;
    tracing::info!(listen = %config.grpc_listen_addr, "grpc server listening");
    let grpc_handle = {
        let mut grpc_shutdown_rx = shutdown_rx.clone();
        tokio::spawn(platform::serve_grpc(platform_ctx, grpc_listener, async move {
            let _ = grpc_shutdown_rx.changed().await;
        }))
    };

    // `into_make_service_with_connect_info` surfaces the socket peer
    // address to handlers (via `ConnectInfo`), which the `ClientIp`
    // extractor uses for rate-limit keying when no trusted proxy is set.
    let mut axum_shutdown_rx = shutdown_rx.clone();
    let serve_outcome = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = axum_shutdown_rx.changed().await;
    })
    .await
    .context("server error");

    // Axum has drained. Make sure the rest winds down too (idempotent if the
    // signal already fired), then join — gRPC first, since in-flight RPCs
    // borrow the pool, which must be closed LAST.
    let _ = shutdown_tx.send(true);
    match grpc_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::warn!(?err, "grpc server error"),
        Err(err) => tracing::warn!(?err, "grpc server join failed"),
    }
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
