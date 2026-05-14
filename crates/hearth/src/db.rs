use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

const MAX_CONNECTIONS: u32 = 20;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(10);

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

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    MIGRATOR
        .run(pool)
        .await
        .context("running sqlx migrations")?;
    Ok(())
}
