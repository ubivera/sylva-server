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
    /// Public-facing base URL used when constructing links inside outbound
    /// emails (e.g., invitation accept URLs). Distinct from `listen_addr`
    /// because production sits behind a reverse proxy on a different host.
    pub public_base_url: String,
    pub notifications: NotificationsConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone)]
pub enum NotificationsConfig {
    /// No emails ever sent. Outbox rows are still inserted at the call site
    /// and the worker marks them `skipped` for admin visibility.
    Disabled,
    /// Dev/test backend that emits a tracing line per "send."
    Log,
    /// Real SMTP delivery. All fields validated at startup.
    Smtp(SmtpSettings),
}

#[derive(Debug, Clone)]
pub struct SmtpSettings {
    pub host: String,
    pub port: u16,
    pub tls: SmtpTls,
    pub username: String,
    pub password: String,
    pub from_email: String,
    pub from_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    Starttls,
    Implicit,
    None,
}

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8443";
const DEFAULT_LOG_FORMAT: &str = "json";
const DEFAULT_LOG_FILTER: &str = "info,hearth=debug";
const DEFAULT_DATA_DIR: &str = "./data";
const DEFAULT_POSTGRES_URL: &str = "postgresql://hearth@127.0.0.1:15432/hearth";
const DEFAULT_PUBLIC_BASE_URL: &str = "http://127.0.0.1:8443";
const DEFAULT_NOTIFICATIONS_MODE: &str = "disabled";
const DEFAULT_SMTP_PORT: u16 = 587;
const DEFAULT_SMTP_TLS: &str = "starttls";

impl Config {
    /// Build a Config from process environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_env_lookup(|key| env::var(key).ok())
    }

    /// Same as `from_env` but takes any lookup function - used by tests to
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

        let public_base_url = get("HEARTH_PUBLIC_BASE_URL")
            .unwrap_or_else(|| DEFAULT_PUBLIC_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();

        let notifications = parse_notifications(&get)?;

        Ok(Self {
            listen_addr,
            log_format,
            log_filter,
            data_dir,
            postgres_url,
            public_base_url,
            notifications,
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

fn parse_notifications<F>(get: &F) -> anyhow::Result<NotificationsConfig>
where
    F: Fn(&str) -> Option<String>,
{
    let mode = get("HEARTH_NOTIFICATIONS_MODE")
        .unwrap_or_else(|| DEFAULT_NOTIFICATIONS_MODE.to_string());

    match mode.as_str() {
        "disabled" => Ok(NotificationsConfig::Disabled),
        "log" => Ok(NotificationsConfig::Log),
        "smtp" => {
            let host = required(get, "HEARTH_SMTP_HOST")?;
            let port = match get("HEARTH_SMTP_PORT") {
                Some(s) => s
                    .parse::<u16>()
                    .with_context(|| format!("HEARTH_SMTP_PORT not a port number: {s}"))?,
                None => DEFAULT_SMTP_PORT,
            };
            let tls_str = get("HEARTH_SMTP_TLS").unwrap_or_else(|| DEFAULT_SMTP_TLS.to_string());
            let tls = match tls_str.as_str() {
                "starttls" => SmtpTls::Starttls,
                "implicit" => SmtpTls::Implicit,
                "none" => SmtpTls::None,
                other => bail!(
                    "invalid HEARTH_SMTP_TLS: {other}; expected 'starttls', 'implicit', or 'none'"
                ),
            };
            let username = required(get, "HEARTH_SMTP_USERNAME")?;
            let password = required(get, "HEARTH_SMTP_PASSWORD")?;
            let from_email = required(get, "HEARTH_SMTP_FROM_EMAIL")?;
            let from_name = get("HEARTH_SMTP_FROM_NAME");

            Ok(NotificationsConfig::Smtp(SmtpSettings {
                host,
                port,
                tls,
                username,
                password,
                from_email,
                from_name,
            }))
        }
        other => bail!(
            "invalid HEARTH_NOTIFICATIONS_MODE: {other}; expected 'disabled', 'log', or 'smtp'"
        ),
    }
}

fn required<F>(get: &F, key: &str) -> anyhow::Result<String>
where
    F: Fn(&str) -> Option<String>,
{
    get(key).ok_or_else(|| {
        anyhow::anyhow!(
            "{key} is required when HEARTH_NOTIFICATIONS_MODE=smtp"
        )
    })
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
