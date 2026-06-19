#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]

use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

type CleanResult<T> = Result<T, Box<dyn Error>>;

const DEFAULT_DATABASE: &str = "sylva";
const META_SCHEMA: &str = "sylva_meta";

fn main() {
    if let Err(err) = run() {
        eprintln!("clean: error: {err}");
        let mut source = err.source();
        while let Some(inner) = source {
            eprintln!("  caused by: {inner}");
            source = inner.source();
        }
        std::process::exit(1);
    }
}

fn run() -> CleanResult<()> {
    let workspace_root = locate_workspace_root()?;
    let data_dir = workspace_root.join("data");
    let pg_dir = data_dir.join("postgres");
    let pg_data_dir = data_dir.join("postgres-data");

    println!("clean: workspace = {}", workspace_root.display());

    if !pg_dir.exists() || !pg_data_dir.exists() {
        return Err(format!(
            "Postgres not set up at {}.\nRun `cargo run --bin bootstrap` first.",
            data_dir.display()
        )
        .into());
    }

    let auto_yes = std::env::args().any(|a| a == "--yes" || a == "-y");

    let pid_file = pg_data_dir.join("postmaster.pid");
    if pid_file.exists() {
        match read_postmaster_pid(&pid_file) {
            Some(pid) if pid_is_running(pid) => {
                return Err(format!(
                    "Postgres is running (PID {pid}; lock file {}).\n\
                     Stop server first (Ctrl+C in the server window).",
                    pid_file.display()
                )
                .into());
            }
            Some(pid) => {
                eprintln!(
                    "clean: stale lock file from PID {pid} (not running); removing and proceeding."
                );
                fs::remove_file(&pid_file).map_err(|e| {
                    format!("removing stale lock {}: {e}", pid_file.display())
                })?;
            }
            None => {
                eprintln!(
                    "clean: lock file present but unparseable; removing and proceeding."
                );
                fs::remove_file(&pid_file).map_err(|e| {
                    format!("removing unparseable lock {}: {e}", pid_file.display())
                })?;
            }
        }
    }

    if !auto_yes {
        println!();
        println!("This will drop the '{DEFAULT_DATABASE}' database and recreate it empty.");
        println!("All Hearth application data will be lost.");
        print!("Type 'yes' to continue: ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim() != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();
    println!("Dropping and recreating '{DEFAULT_DATABASE}'...");
    reset_database(&pg_dir, &pg_data_dir, DEFAULT_DATABASE)?;

    println!();
    println!("Done. Next `cargo run --bin sylva-server` re-applies migrations against the fresh database.");
    Ok(())
}

fn locate_workspace_root() -> CleanResult<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or("could not derive workspace root from CARGO_MANIFEST_DIR")?;
    Ok(workspace_root.to_path_buf())
}

fn reset_database(pg_dir: &Path, data_dir: &Path, db_name: &str) -> CleanResult<()> {
    let postgres_exe = pg_dir.join("bin").join("postgres.exe");
    if !postgres_exe.exists() {
        return Err(format!("postgres.exe not found at {}", postgres_exe.display()).into());
    }

    let quoted = quote_ident(db_name);
    run_single_user_sql(
        &postgres_exe,
        data_dir,
        "postgres",
        &[
            &format!("DROP DATABASE IF EXISTS {quoted};"),
            &format!("CREATE DATABASE {quoted};"),
        ],
    )?;

    run_single_user_sql(
        &postgres_exe,
        data_dir,
        db_name,
        &[&format!("CREATE SCHEMA {};", quote_ident(META_SCHEMA))],
    )?;
    Ok(())
}

fn run_single_user_sql(
    postgres_exe: &Path,
    data_dir: &Path,
    database: &str,
    statements: &[&str],
) -> CleanResult<()> {
    let mut child = Command::new(postgres_exe)
        .arg("--single")
        .arg("-D")
        .arg(data_dir)
        .arg(database)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawning postgres --single: {e}"))?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or("postgres --single stdin not piped")?;
        for stmt in statements {
            writeln!(stdin, "{stmt}")
                .map_err(|e| format!("writing to postgres stdin: {e}"))?;
        }
    }
    drop(child.stdin.take());

    let status = child
        .wait()
        .map_err(|e| format!("waiting for postgres --single: {e}"))?;
    if !status.success() {
        return Err(format!("postgres --single exited with status {status}").into());
    }
    Ok(())
}

/// Reads the first line of `postmaster.pid` and parses it as the master PID.
fn read_postmaster_pid(path: &Path) -> Option<u32> {
    let contents = fs::read_to_string(path).ok()?;
    contents.lines().next()?.trim().parse::<u32>().ok()
}

/// Returns true if a process with the given PID is currently running.
/// Uses `tasklist.exe` (Windows-shipped). Returns false on any error.
fn pid_is_running(pid: u32) -> bool {
    let output = Command::new("tasklist.exe")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            !stdout.trim().is_empty() && !stdout.contains("INFO:")
        }
        _ => false,
    }
}

fn quote_ident(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        if ch == '"' {
            out.push('"');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::{quote_ident, read_postmaster_pid};
    use std::fs;
    use std::path::PathBuf;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sylva-clean-test-{}-{label}",
            std::process::id()
        ))
    }

    #[test]
    fn quote_ident_wraps_and_escapes() {
        assert_eq!(quote_ident("server"), "\"server\"");
        assert_eq!(quote_ident("a\"b"), "\"a\"\"b\"");
        assert_eq!(quote_ident(""), "\"\"");
    }

    #[test]
    fn read_postmaster_pid_parses_first_line() {
        let path = temp_path("good-pid");
        fs::write(&path, "12345\n/some/path\n1700000000\n5432\n").unwrap();
        let pid = read_postmaster_pid(&path);
        let _ = fs::remove_file(&path);
        assert_eq!(pid, Some(12345));
    }

    #[test]
    fn read_postmaster_pid_returns_none_for_garbage() {
        let path = temp_path("bad-pid");
        fs::write(&path, "not-a-number\n").unwrap();
        let pid = read_postmaster_pid(&path);
        let _ = fs::remove_file(&path);
        assert_eq!(pid, None);
    }

    #[test]
    fn read_postmaster_pid_returns_none_for_missing_file() {
        let path = temp_path("missing-pid");
        let _ = fs::remove_file(&path);
        assert_eq!(read_postmaster_pid(&path), None);
    }
}
