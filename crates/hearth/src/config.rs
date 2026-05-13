use std::{env, net::SocketAddr};

use anyhow::{bail, Context};

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub log_format: LogFormat,
    pub log_filter: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8443";
const DEFAULT_LOG_FORMAT: &str = "json";
const DEFAULT_LOG_FILTER: &str = "info,hearth=debug";

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let listen_addr_str =
            env::var("HEARTH_LISTEN_ADDR").unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string());
        let listen_addr: SocketAddr = listen_addr_str
            .parse()
            .with_context(|| format!("invalid HEARTH_LISTEN_ADDR: {listen_addr_str}"))?;

        let log_format_str =
            env::var("HEARTH_LOG_FORMAT").unwrap_or_else(|_| DEFAULT_LOG_FORMAT.to_string());
        let log_format = match log_format_str.as_str() {
            "json" => LogFormat::Json,
            "pretty" => LogFormat::Pretty,
            other => {
                bail!("invalid HEARTH_LOG_FORMAT: {other}; expected 'json' or 'pretty'");
            }
        };

        let log_filter =
            env::var("HEARTH_LOG_FILTER").unwrap_or_else(|_| DEFAULT_LOG_FILTER.to_string());

        Ok(Self {
            listen_addr,
            log_format,
            log_filter,
        })
    }
}
