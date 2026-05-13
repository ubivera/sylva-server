use anyhow::Context;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::{Config, LogFormat};

pub fn init(config: &Config) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(&config.log_filter)
        .with_context(|| format!("invalid log filter: {}", config.log_filter))?;

    let registry = tracing_subscriber::registry().with(filter);

    match config.log_format {
        LogFormat::Json => registry.with(fmt::layer().json()).try_init(),
        LogFormat::Pretty => registry.with(fmt::layer().pretty()).try_init(),
    }
    .context("failed to initialize tracing subscriber")?;

    Ok(())
}
