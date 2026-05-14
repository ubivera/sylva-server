use std::{env, net::SocketAddr, path::PathBuf};

use anyhow::{Context, bail};

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub log_format: LogFormat,
    pub log_filter: String,
    pub data_dir: PathBuf,
    pub postgres_url: String,
    pub postgres_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8443";
const DEFAULT_LOG_FORMAT: &str = "json";
const DEFAULT_LOG_FILTER: &str = "info,hearth=debug";
const DEFAULT_DATA_DIR: &str = "./data";
const DEFAULT_POSTGRES_URL: &str = "postgresql://hearth@127.0.0.1:15432/hearth";
const DEFAULT_POSTGRES_PORT: u16 = 15432;

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

        let data_dir =
            PathBuf::from(env::var("HEARTH_DATA_DIR").unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string()));

        let postgres_url =
            env::var("HEARTH_POSTGRES_URL").unwrap_or_else(|_| DEFAULT_POSTGRES_URL.to_string());

        let postgres_port = match env::var("HEARTH_POSTGRES_PORT") {
            Ok(raw) => raw
                .parse()
                .with_context(|| format!("invalid HEARTH_POSTGRES_PORT: {raw}"))?,
            Err(_) => DEFAULT_POSTGRES_PORT,
        };

        Ok(Self {
            listen_addr,
            log_format,
            log_filter,
            data_dir,
            postgres_url,
            postgres_port,
        })
    }

    pub fn pg_bin_dir(&self) -> PathBuf {
        self.data_dir.join("postgres")
    }

    pub fn pg_data_dir(&self) -> PathBuf {
        self.data_dir.join("postgres-data")
    }
}
