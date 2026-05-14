use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

const MAX_CONNECTIONS: u32 = 20;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(10);

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

pub async fn connect(url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect(url)
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
