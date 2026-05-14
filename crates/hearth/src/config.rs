use std::{env, net::SocketAddr, path::PathBuf};

use anyhow::{Context, bail};
use sqlx::postgres::PgConnectOptions;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub log_format: LogFormat,
    pub log_filter: String,
    pub data_dir: PathBuf,
    pub postgres_url: String,
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

impl Config {
    /// Build a Config from process environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_env_lookup(|key| env::var(key).ok())
    }

    /// Same as `from_env` but takes any lookup function — used by tests to
    /// avoid mutating real process environment (which is shared across tests).
    pub fn from_env_lookup<F>(get: F) -> anyhow::Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let listen_addr_str = get("HEARTH_LISTEN_ADDR")
            .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_string());
        let listen_addr: SocketAddr = listen_addr_str
            .parse()
            .with_context(|| format!("invalid HEARTH_LISTEN_ADDR: {listen_addr_str}"))?;

        let log_format_str = get("HEARTH_LOG_FORMAT")
            .unwrap_or_else(|| DEFAULT_LOG_FORMAT.to_string());
        let log_format = match log_format_str.as_str() {
            "json" => LogFormat::Json,
            "pretty" => LogFormat::Pretty,
            other => {
                bail!("invalid HEARTH_LOG_FORMAT: {other}; expected 'json' or 'pretty'");
            }
        };

        let log_filter = get("HEARTH_LOG_FILTER")
            .unwrap_or_else(|| DEFAULT_LOG_FILTER.to_string());

        let data_dir = PathBuf::from(
            get("HEARTH_DATA_DIR").unwrap_or_else(|| DEFAULT_DATA_DIR.to_string()),
        );

        let postgres_url = get("HEARTH_POSTGRES_URL")
            .unwrap_or_else(|| DEFAULT_POSTGRES_URL.to_string());

        let _: PgConnectOptions = postgres_url
            .parse()
            .with_context(|| format!("invalid HEARTH_POSTGRES_URL: {postgres_url}"))?;

        Ok(Self {
            listen_addr,
            log_format,
            log_filter,
            data_dir,
            postgres_url,
        })
    }

    pub fn pg_bin_dir(&self) -> PathBuf {
        self.data_dir.join("postgres")
    }

    pub fn pg_data_dir(&self) -> PathBuf {
        self.data_dir.join("postgres-data")
    }

    /// Extract the TCP port from `postgres_url` for the readiness poll.
    /// The URL is already validated in `from_env_lookup`, so this never fails.
    pub fn postgres_port(&self) -> u16 {
        self.postgres_url
            .parse::<PgConnectOptions>()
            .map(|opts| opts.get_port())
            .unwrap_or(15432)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::collections::HashMap;

    fn lookup<'a>(map: &'a HashMap<&'a str, &'a str>) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| map.get(key).map(|s| (*s).to_string())
    }

    #[test]
    fn defaults_when_no_env_vars_set() {
        let empty: HashMap<&str, &str> = HashMap::new();
        let cfg = Config::from_env_lookup(lookup(&empty)).expect("defaults parse");
        assert_eq!(cfg.listen_addr.to_string(), "127.0.0.1:8443");
        assert_eq!(cfg.log_format, LogFormat::Json);
        assert_eq!(cfg.log_filter, "info,hearth=debug");
        assert_eq!(cfg.data_dir, PathBuf::from("./data"));
        assert_eq!(cfg.postgres_url, "postgresql://hearth@127.0.0.1:15432/hearth");
        assert_eq!(cfg.postgres_port(), 15432);
    }

    #[test]
    fn parses_listen_addr_override() {
        let env: HashMap<&str, &str> =
            HashMap::from([("HEARTH_LISTEN_ADDR", "127.0.0.1:9000")]);
        let cfg = Config::from_env_lookup(lookup(&env)).expect("parse");
        assert_eq!(cfg.listen_addr.to_string(), "127.0.0.1:9000");
    }

    #[test]
    fn rejects_invalid_listen_addr() {
        let env: HashMap<&str, &str> = HashMap::from([("HEARTH_LISTEN_ADDR", "not-a-socket")]);
        let err = Config::from_env_lookup(lookup(&env)).unwrap_err();
        assert!(err.to_string().contains("HEARTH_LISTEN_ADDR"));
    }

    #[test]
    fn accepts_json_and_pretty_log_formats() {
        let json: HashMap<&str, &str> = HashMap::from([("HEARTH_LOG_FORMAT", "json")]);
        assert_eq!(
            Config::from_env_lookup(lookup(&json)).unwrap().log_format,
            LogFormat::Json
        );

        let pretty: HashMap<&str, &str> = HashMap::from([("HEARTH_LOG_FORMAT", "pretty")]);
        assert_eq!(
            Config::from_env_lookup(lookup(&pretty)).unwrap().log_format,
            LogFormat::Pretty,
        );
    }

    #[test]
    fn rejects_unknown_log_format() {
        let env: HashMap<&str, &str> = HashMap::from([("HEARTH_LOG_FORMAT", "JSON")]);
        let err = Config::from_env_lookup(lookup(&env)).unwrap_err();
        assert!(err.to_string().contains("HEARTH_LOG_FORMAT"));
    }

    #[test]
    fn preserves_postgres_url_override() {
        let env: HashMap<&str, &str> = HashMap::from([(
            "HEARTH_POSTGRES_URL",
            "postgresql://someone@db.example.internal:9999/custom",
        )]);
        let cfg = Config::from_env_lookup(lookup(&env)).expect("parse");
        assert_eq!(
            cfg.postgres_url,
            "postgresql://someone@db.example.internal:9999/custom"
        );
        assert_eq!(cfg.postgres_port(), 9999);
    }

    #[test]
    fn postgres_port_reflects_url_override() {
        let env: HashMap<&str, &str> = HashMap::from([(
            "HEARTH_POSTGRES_URL",
            "postgresql://hearth@127.0.0.1:25432/hearth",
        )]);
        let cfg = Config::from_env_lookup(lookup(&env)).expect("parse");
        assert_eq!(cfg.postgres_port(), 25432);
    }

    #[test]
    fn pg_bin_and_data_dirs_derive_from_data_dir() {
        let env: HashMap<&str, &str> = HashMap::from([("HEARTH_DATA_DIR", "/tmp/hearth-data")]);
        let cfg = Config::from_env_lookup(lookup(&env)).expect("parse");
        assert_eq!(cfg.pg_bin_dir(), PathBuf::from("/tmp/hearth-data/postgres"));
        assert_eq!(
            cfg.pg_data_dir(),
            PathBuf::from("/tmp/hearth-data/postgres-data")
        );
    }
}
