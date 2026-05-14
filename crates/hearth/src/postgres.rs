use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

const READY_POLL_INTERVAL: Duration = Duration::from_millis(500);
const READY_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);

/// Filename for the captured postgres stderr log (lives inside the cluster's
/// data directory; truncated on every hearth startup so the tail is always
/// from the current run).
const STDERR_LOG_FILENAME: &str = "postgres.stderr.log";

/// Max bytes of the stderr log we surface in error messages.
const LOG_TAIL_BYTES: usize = 2048;

pub struct PostgresProcess {
    child: Option<Child>,
    pg_bin_dir: PathBuf,
    data_dir: PathBuf,
}

impl PostgresProcess {
    /// Spawn `postgres.exe -D <data_dir>` and wait for the listener to come up.
    pub async fn start(pg_bin_dir: PathBuf, data_dir: PathBuf, port: u16) -> Result<Self> {
        let postgres_exe = pg_bin_dir.join("bin").join("postgres.exe");
        if !postgres_exe.exists() {
            bail!(
                "postgres.exe not found at {}. Run `cargo run --bin bootstrap` first.",
                postgres_exe.display()
            );
        }
        if !data_dir.exists() {
            bail!(
                "Postgres data directory {} does not exist. Run `cargo run --bin bootstrap` first.",
                data_dir.display()
            );
        }

        let stderr_log_path = data_dir.join(STDERR_LOG_FILENAME);
        let stderr_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&stderr_log_path)
            .with_context(|| {
                format!("opening postgres stderr log {}", stderr_log_path.display())
            })?;

        tracing::info!(
            postgres_exe = %postgres_exe.display(),
            data_dir = %data_dir.display(),
            stderr_log = %stderr_log_path.display(),
            port,
            "spawning bundled postgres",
        );

        let mut child = Command::new(&postgres_exe)
            .arg("-D")
            .arg(&data_dir)
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .with_context(|| format!("spawning {}", postgres_exe.display()))?;

        let ready = wait_until_ready(&mut child, port, &stderr_log_path);
        match timeout(READY_TIMEOUT, ready).await {
            Ok(Ok(())) => {
                tracing::info!(port, "bundled postgres ready");
                Ok(Self {
                    child: Some(child),
                    pg_bin_dir,
                    data_dir,
                })
            }
            Ok(Err(err)) => {
                let _ = child.start_kill();
                Err(err)
            }
            Err(_) => {
                let _ = child.start_kill();
                let tail = read_log_tail(&stderr_log_path, LOG_TAIL_BYTES);
                bail!(
                    "postgres did not start accepting connections on 127.0.0.1:{port} within {}s\n\
                     Recent stderr from {}:\n{}",
                    READY_TIMEOUT.as_secs(),
                    stderr_log_path.display(),
                    tail_or_placeholder(&tail),
                );
            }
        }
    }

    /// Graceful shutdown: ask Postgres to stop via pg_ctl, fall back to kill.
    pub async fn stop(mut self) -> Result<()> {
        let pg_ctl = self.pg_bin_dir.join("bin").join("pg_ctl.exe");
        if pg_ctl.exists() {
            let stop_status = Command::new(&pg_ctl)
                .args(["stop", "-m", "fast", "-w", "-t", "10", "-D"])
                .arg(&self.data_dir)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await;
            match stop_status {
                Ok(status) if status.success() => {
                    tracing::info!("pg_ctl stop succeeded");
                }
                Ok(status) => {
                    tracing::warn!(?status, "pg_ctl stop returned non-zero status");
                }
                Err(err) => {
                    tracing::warn!(?err, "failed to invoke pg_ctl stop");
                }
            }
        } else {
            tracing::warn!(
                pg_ctl = %pg_ctl.display(),
                "pg_ctl.exe missing; will rely on direct child shutdown"
            );
        }

        if let Some(mut child) = self.child.take() {
            match timeout(SHUTDOWN_TIMEOUT, child.wait()).await {
                Ok(Ok(status)) => {
                    tracing::info!(?status, "postgres exited");
                }
                Ok(Err(err)) => {
                    tracing::warn!(?err, "error waiting for postgres exit");
                }
                Err(_) => {
                    tracing::warn!("postgres did not exit in time, killing");
                    let _ = child.kill().await;
                }
            }
        }
        Ok(())
    }
}

async fn wait_until_ready(child: &mut Child, port: u16, log_path: &Path) -> Result<()> {
    loop {
        if let Some(status) = child
            .try_wait()
            .context("checking postgres child status")?
        {
            let tail = read_log_tail(log_path, LOG_TAIL_BYTES);
            bail!(
                "postgres exited before becoming ready: {status}\n\
                 Recent stderr from {}:\n{}",
                log_path.display(),
                tail_or_placeholder(&tail),
            );
        }
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(());
        }
        sleep(READY_POLL_INTERVAL).await;
    }
}

/// Reads up to `max_bytes` of trailing content from a log file. Best-effort:
/// returns an empty string on any error rather than masking the real failure.
fn read_log_tail(path: &Path, max_bytes: usize) -> String {
    let Ok(contents) = fs::read_to_string(path) else {
        return String::new();
    };
    if contents.len() <= max_bytes {
        return contents;
    }

    let raw_start = contents.len() - max_bytes;
    let safe_start = (raw_start..=contents.len())
        .find(|&i| contents.is_char_boundary(i))
        .unwrap_or(contents.len());
    format!("...(truncated)\n{}", &contents[safe_start..])
}

fn tail_or_placeholder(tail: &str) -> &str {
    if tail.is_empty() {
        "(empty log)"
    } else {
        tail
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::{read_log_tail, tail_or_placeholder};
    use std::fs;
    use std::path::PathBuf;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hearth-postgres-test-{}-{label}",
            std::process::id()
        ))
    }

    #[test]
    fn read_log_tail_returns_empty_for_missing_file() {
        let path = temp_path("missing");
        let _ = fs::remove_file(&path);
        assert_eq!(read_log_tail(&path, 1024), "");
    }

    #[test]
    fn read_log_tail_returns_full_content_when_under_limit() {
        let path = temp_path("small");
        fs::write(&path, "hello world").unwrap();
        let tail = read_log_tail(&path, 1024);
        let _ = fs::remove_file(&path);
        assert_eq!(tail, "hello world");
    }

    #[test]
    fn read_log_tail_truncates_when_over_limit() {
        let path = temp_path("large");
        let big = "x".repeat(4000);
        fs::write(&path, &big).unwrap();
        let tail = read_log_tail(&path, 100);
        let _ = fs::remove_file(&path);
        assert!(tail.starts_with("...(truncated)\n"));
        assert!(tail.len() < big.len() + "...(truncated)\n".len());
    }

    #[test]
    fn read_log_tail_snaps_to_char_boundary_with_multibyte_input() {
        let path = temp_path("utf8");
        let content = "é".repeat(50); // 100 bytes
        fs::write(&path, &content).unwrap();
        let tail = read_log_tail(&path, 25); // mid-multibyte
        let _ = fs::remove_file(&path);
        assert!(tail.starts_with("...(truncated)\n"));
        assert!(tail.contains("é"));
    }

    #[test]
    fn tail_or_placeholder_swaps_empty() {
        assert_eq!(tail_or_placeholder(""), "(empty log)");
        assert_eq!(tail_or_placeholder("hello"), "hello");
    }
}
