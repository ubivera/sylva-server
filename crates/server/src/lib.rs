pub mod config;
pub mod db;
pub mod discovery;
pub mod health;
pub mod instance;
#[cfg(windows)]
pub mod job_object;
pub mod postgres;
pub mod shutdown;
pub mod telemetry;

use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use auth::SessionRepository;
use identity::{InvitationRepository, UserRepository};
use sqlx::PgPool;

/// Minimal state for the public discovery endpoint (`/.well-known/sylva-discovery`).
/// Holds only what the signed payload needs: the instance display name, the
/// advertised gRPC port, and the server identity keypair to sign with. Cloning
/// is cheap (every field is a handle or `Copy`).
#[derive(Clone)]
pub struct DiscoveryState {
    /// Operator-chosen display name for this instance, advertised in discovery.
    /// Seeded at startup from the DB override or `SYLVA_INSTANCE_NAME`.
    pub instance_name: String,
    /// The gRPC port clients dial after discovery.
    pub grpc_port: u16,
    /// The server's Ed25519 identity keypair — the trust anchor native clients
    /// (Sylva Hub) TOFU-pin; used to sign the discovery response. See
    /// [`crate::instance::ServerIdentity`] + [`crate::discovery`].
    pub server_identity: Arc<crate::instance::ServerIdentity>,
}

/// Minimal state for the `/health` ops endpoint. Holds the pool plus the
/// repositories whose counts the health body reports, and the process start
/// instant for uptime.
#[derive(Clone)]
pub struct HealthState {
    pub started_at: Instant,
    pub db: PgPool,
    pub users: UserRepository,
    pub sessions: SessionRepository,
    pub invitations: InvitationRepository,
}

/// Entry point used by `sylva-server`'s `main`. The server exposes only the
/// gRPC platform API plus the public discovery + `/health` endpoints on the
/// HTTP listener; there is no web/REST surface.
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
        "starting server"
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
    let invitations = identity::InvitationRepository::new(pool.clone());

    // Instance display name = DB override (if set) layered over the env default.
    // Advertised in the discovery payload.
    let secret_key = std::sync::Arc::new(config.load_secret_key()?);
    let instance_name = instance::server_name(&pool, config).await?;

    // One shutdown signal fans out to both servers (HTTP + gRPC).
    // `shutdown::signal()` can only be awaited once, so a bridge task awaits it
    // and flips this watch; everyone else observes it.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel::<bool>(false);
    {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            shutdown::signal().await;
            let _ = shutdown_tx.send(true);
        });
    }

    // Load (or, on first run, generate + persist) the server identity keypair —
    // the trust anchor native clients pin and the key the discovery endpoint
    // signs with.
    let server_identity =
        std::sync::Arc::new(instance::ensure_server_identity(&pool, &secret_key).await?);

    // Auth limiter for the gRPC `Account.Bootstrap`/`Login` RPCs — a single
    // per-IP bucket bounding brute-force attempts.
    let auth_rate_limiter =
        std::sync::Arc::new(auth::ratelimit::RateLimiter::auth_default());

    // Context for the gRPC platform services — clones of the same repositories
    // (cheap; each just wraps the pool).
    let platform_ctx = platform::PlatformContext {
        sessions: sessions.clone(),
        users: users.clone(),
        resources: platform::resources::ResourceRepository::new(pool.clone()),
        user_keys: identity::UserKeyRepository::new(pool.clone()),
        devices: identity::DeviceRepository::new(pool.clone()),
        user_avatars: identity::UserAvatarRepository::new(pool.clone()),
        pool: pool.clone(),
        secret_key: secret_key.clone(),
        auth_rate_limiter,
        trust_proxy: config.trust_proxy,
    };

    let health_state = HealthState {
        started_at,
        db: pool.clone(),
        users,
        sessions,
        invitations,
    };
    let health = axum::Router::new()
        .route("/health", axum::routing::get(health::handler))
        .with_state(health_state);

    // Public, unauthenticated discovery — mounted at the root (like /health) so
    // it bypasses any prefix and auth.
    let discovery_state = DiscoveryState {
        instance_name,
        grpc_port: config.grpc_listen_addr.port(),
        server_identity,
    };
    let discovery = discovery::router(discovery_state);

    let router = axum::Router::new()
        .merge(health)
        .merge(discovery)
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

    // `into_make_service_with_connect_info` surfaces the socket peer address to
    // handlers (via `ConnectInfo`); kept for parity with the gRPC rate-limit
    // keying path.
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

    pool.close().await;
    tracing::info!("server http server stopped");
    serve_outcome
}
