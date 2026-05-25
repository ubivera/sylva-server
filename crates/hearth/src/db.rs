use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use sqlx::{Connection, PgPool};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

const MAX_CONNECTIONS: u32 = 20;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time to wait for the Postgres SQL layer to become ready after
/// the TCP listener opens. Generous enough to cover crash recovery + fsync
/// on a large data dir (the integration-test cluster regularly takes
/// 20–30s after a hard kill from the test runner).
const SQL_READY_TIMEOUT: Duration = Duration::from_secs(120);

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

pub async fn connect(url: &str) -> Result<PgPool> {
    let opts: PgConnectOptions = url
        .parse()
        .with_context(|| format!("parsing postgres url {url}"))?;
    let opts = opts.options([("search_path", "hearth_meta,public")]);

    PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect_with(opts)
        .await
        .with_context(|| format!("connecting to postgres at {url}"))
}

/// Block until Postgres at `url` answers `SELECT 1`. Retries SQLSTATE 57*
/// (operator-intervention class, including `57P03 the database system is
/// starting up`) and IO errors with exponential backoff, up to
/// [`SQL_READY_TIMEOUT`].
///
/// `PostgresProcess::start` only waits for the TCP listener — Postgres
/// opens that early during startup and rejects queries while crash
/// recovery / data-dir fsync are still running. Without this gate, the
/// first call into the pool fails with a pool acquire timeout on every
/// boot after an unclean prior shutdown (test runner hard-kills, OS
/// reboots, kill -9, etc.).
pub async fn wait_until_ready(url: &str) -> Result<()> {
    let deadline = std::time::Instant::now() + SQL_READY_TIMEOUT;
    let mut delay = Duration::from_millis(100);
    let mut last_err: Option<sqlx::Error> = None;
    loop {
        let attempt: Result<(), sqlx::Error> = async {
            let mut c = sqlx::PgConnection::connect(url).await?;
            let _: (i32,) = sqlx::query_as("SELECT 1").fetch_one(&mut c).await?;
            c.close().await
        }
        .await;
        match attempt {
            Ok(()) => return Ok(()),
            Err(err) => {
                let transient = matches!(
                    &err,
                    sqlx::Error::Database(dbe)
                        if dbe.code().as_deref().is_some_and(|c| c.starts_with("57"))
                ) || matches!(&err, sqlx::Error::Io(_));
                if transient && std::time::Instant::now() < deadline {
                    last_err = Some(err);
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_millis(500));
                    continue;
                }
                let detail = last_err
                    .map(|e| format!("last transient error: {e}"))
                    .unwrap_or_else(|| "no prior transient error captured".to_string());
                return Err(anyhow!(err)).with_context(|| {
                    format!(
                        "postgres at {url} never became SQL-ready within {}s ({detail})",
                        SQL_READY_TIMEOUT.as_secs(),
                    )
                });
            }
        }
    }
}

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    MIGRATOR
        .run(pool)
        .await
        .context("running sqlx migrations")?;
    Ok(())
}
