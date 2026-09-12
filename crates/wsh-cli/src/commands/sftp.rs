//! `wsh sftp [user@]host` — interactive session over the structured file
//! channel (wsh #58), driving `list`/`upload`/`download`/`remove`
//! (wsh #59) the way `sftp` drives its own protocol.
//!
//! Supports: `ls [path]`, `cd <path>`, `pwd`, `get <remote> [local]`,
//! `put <local> [remote]`, `lls [path]`, `lcd <path>`, `rm <remote>`
//! (where the server allows it), `exit`/`quit`. Also `-b <batchfile>` for
//! non-interactive scripted runs, the same shape real `sftp -b` has.
//!
//! Path handling for `get`/`put`/`ls`/`cd`/`rm` reuses `common::
//! parse_endpoint` only for the initial `[user@]host` target -- paths
//! typed inside the session are resolved against a remote/local "current
//! directory" tracked here, the same way an interactive `sftp` session
//! works.

use anyhow::{Context, Result};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::debug;
use wsh_client::file_transfer;
use wsh_client::WshClient;

use crate::commands::common::{connect_client, resolve_target};
use crate::commands::fs_display::format_entry_line;
use crate::config::parse_target;

/// Run an interactive (or batch, if `batch_file` is given) sftp session.
pub async fn run(
    target: &str,
    port: u16,
    identity: &str,
    transport: Option<&str>,
    batch_file: Option<&str>,
) -> Result<()> {
    let (user, host) = parse_target(target)?;
    let target_str = format!("{user}@{host}");
    let resolved = resolve_target(&target_str, port, transport)?;
    let client = connect_client(&resolved, identity).await?;
    debug!(url = %resolved.url, "sftp");

    let mut session = Session {
        client: &client,
        remote_cwd: ".".to_string(),
        local_cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };

    let result = if let Some(path) = batch_file {
        run_batch(&mut session, path).await
    } else {
        run_interactive(&mut session).await
    };

    let _ = client.disconnect().await;
    result
}

struct Session<'a> {
    client: &'a WshClient,
    remote_cwd: String,
    local_cwd: PathBuf,
}

/// Interactive loop: prompt, read a line from stdin, execute, repeat.
async fn run_interactive(session: &mut Session<'_>) -> Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        print!("wsh-sftp> ");
        io_flush();

        let line = match lines.next_line().await.context("reading command")? {
            Some(l) => l,
            None => {
                println!();
                break; // EOF (Ctrl-D)
            }
        };

        match execute_line(session, line.trim()).await {
            Ok(ExecOutcome::Continue) => {}
            Ok(ExecOutcome::Exit) => break,
            Err(e) => eprintln!("wsh-sftp: {e:#}"),
        }
    }
    Ok(())
}

/// Batch mode: run each line of `path` in order, aborting on the first
/// error -- the same default `sftp -b` itself has (a batch is a script,
/// and a command that silently failed partway through a script is worse
/// than a script that stopped).
async fn run_batch(session: &mut Session<'_>, path: &str) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read batch file {path:?}"))?;

    for (lineno, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        println!("wsh-sftp> {line}");
        match execute_line(session, line).await {
            Ok(ExecOutcome::Continue) => {}
            Ok(ExecOutcome::Exit) => break,
            Err(e) => {
                anyhow::bail!("batch file {path:?} line {}: {e:#}", lineno + 1);
            }
        }
    }
    Ok(())
}

fn io_flush() {
    let _ = std::io::stdout().flush();
}

enum ExecOutcome {
    Continue,
    Exit,
}

async fn execute_line(session: &mut Session<'_>, line: &str) -> Result<ExecOutcome> {
    if line.is_empty() {
        return Ok(ExecOutcome::Continue);
    }

    // Deliberately simple whitespace splitting (no quoting support) --
    // matches the scope of every other CLI command in this crate
    // (`scp`'s [user@]host:path has the same limitation); a path with a
    // literal space isn't handled here.
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    let args: Vec<&str> = parts.collect();

    match cmd {
        "exit" | "quit" | "bye" => Ok(ExecOutcome::Exit),

        "pwd" => {
            println!("Remote directory: {}", session.remote_cwd);
            Ok(ExecOutcome::Continue)
        }

        "lls" => {
            let dir = match args.first() {
                Some(p) => resolve_local(&session.local_cwd, p),
                None => session.local_cwd.clone(),
            };
            list_local(&dir)?;
            Ok(ExecOutcome::Continue)
        }

        "lcd" => {
            let target = args
                .first()
                .ok_or_else(|| anyhow::anyhow!("usage: lcd <path>"))?;
            let new_dir = resolve_local(&session.local_cwd, target);
            let meta = std::fs::metadata(&new_dir)
                .with_context(|| format!("cannot access local {}", new_dir.display()))?;
            if !meta.is_dir() {
                anyhow::bail!("{} is not a directory", new_dir.display());
            }
            session.local_cwd = new_dir;
            println!("Local directory now {}", session.local_cwd.display());
            Ok(ExecOutcome::Continue)
        }

        "cd" => {
            let target = args
                .first()
                .ok_or_else(|| anyhow::anyhow!("usage: cd <path>"))?;
            session.remote_cwd = resolve_remote(&session.remote_cwd, target);
            println!("Remote directory now {}", session.remote_cwd);
            Ok(ExecOutcome::Continue)
        }

        "ls" => {
            let path = match args.first() {
                Some(p) => resolve_remote(&session.remote_cwd, p),
                None => session.remote_cwd.clone(),
            };
            let entries = file_transfer::list(session.client, &path)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))
                .with_context(|| format!("ls {path}"))?;
            if entries.is_empty() {
                println!("(empty directory)");
            } else {
                for entry in &entries {
                    println!("{}", format_entry_line(entry));
                }
            }
            Ok(ExecOutcome::Continue)
        }

        "get" => {
            let remote = args
                .first()
                .ok_or_else(|| anyhow::anyhow!("usage: get <remote> [local]"))?;
            let remote_path = resolve_remote(&session.remote_cwd, remote);
            let local_path = match args.get(1) {
                Some(p) => resolve_local(&session.local_cwd, p),
                None => {
                    let basename = remote_path.rsplit('/').next().unwrap_or(&remote_path);
                    session.local_cwd.join(basename)
                }
            };

            let data = file_transfer::download(session.client, &remote_path)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))
                .with_context(|| format!("get {remote_path}"))?;
            std::fs::write(&local_path, &data)
                .with_context(|| format!("cannot write {}", local_path.display()))?;
            println!(
                "Downloaded {remote_path} -> {} ({} bytes)",
                local_path.display(),
                data.len()
            );
            Ok(ExecOutcome::Continue)
        }

        "put" => {
            let local = args
                .first()
                .ok_or_else(|| anyhow::anyhow!("usage: put <local> [remote]"))?;
            let local_path = resolve_local(&session.local_cwd, local);
            let remote_path = match args.get(1) {
                Some(p) => resolve_remote(&session.remote_cwd, p),
                None => {
                    let basename = local_path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| local.to_string());
                    resolve_remote(&session.remote_cwd, &basename)
                }
            };

            let data = std::fs::read(&local_path)
                .with_context(|| format!("cannot read {}", local_path.display()))?;
            let len = data.len();
            file_transfer::upload(session.client, &data, &remote_path, |_, _| {})
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))
                .with_context(|| format!("put {remote_path}"))?;
            println!(
                "Uploaded {} -> {remote_path} ({len} bytes)",
                local_path.display()
            );
            Ok(ExecOutcome::Continue)
        }

        "rm" => {
            let remote = args
                .first()
                .ok_or_else(|| anyhow::anyhow!("usage: rm <remote>"))?;
            let remote_path = resolve_remote(&session.remote_cwd, remote);
            // "where the capability allows it" (wsh #58): a server that
            // refuses this (today, every wsh-server does -- only "list" is
            // implemented over FileOp so far) surfaces as a named error
            // here, not a silent no-op.
            file_transfer::remove(session.client, &remote_path)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))
                .with_context(|| format!("rm {remote_path}"))?;
            println!("Removed {remote_path}");
            Ok(ExecOutcome::Continue)
        }

        "help" | "?" => {
            print_help();
            Ok(ExecOutcome::Continue)
        }

        other => {
            anyhow::bail!("unknown command: {other:?} (type 'help' for a list)");
        }
    }
}

fn print_help() {
    println!(
        "Commands: ls [path], cd <path>, pwd, get <remote> [local], put <local> [remote],\n\
         lls [path], lcd <path>, rm <remote>, exit/quit"
    );
}

/// Resolve a remote path typed inside the session against the tracked
/// remote "current directory". Absolute paths (leading `/`) pass through
/// unchanged; anything else is joined onto `cwd`.
fn resolve_remote(cwd: &str, input: &str) -> String {
    if input.starts_with('/') {
        return input.to_string();
    }
    if input == "." {
        return cwd.to_string();
    }
    if cwd.ends_with('/') {
        format!("{cwd}{input}")
    } else {
        format!("{cwd}/{input}")
    }
}

fn resolve_local(cwd: &Path, input: &str) -> PathBuf {
    let p = Path::new(input);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

fn list_local(dir: &Path) -> Result<()> {
    let read = std::fs::read_dir(dir).with_context(|| format!("cannot list {}", dir.display()))?;
    let mut names: Vec<String> = Vec::new();
    for entry in read {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let marker = if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            "/"
        } else {
            ""
        };
        names.push(format!("{name}{marker}"));
    }
    names.sort();
    for name in names {
        println!("{name}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_remote_absolute_passes_through() {
        assert_eq!(resolve_remote("/home/alice", "/etc/hosts"), "/etc/hosts");
    }

    #[test]
    fn resolve_remote_relative_joins_cwd() {
        assert_eq!(resolve_remote("/home/alice", "docs"), "/home/alice/docs");
    }

    #[test]
    fn resolve_remote_dot_returns_cwd() {
        assert_eq!(resolve_remote("/home/alice", "."), "/home/alice");
    }

    #[test]
    fn resolve_remote_handles_trailing_slash_cwd() {
        assert_eq!(resolve_remote("/home/alice/", "docs"), "/home/alice/docs");
    }

    #[test]
    fn resolve_local_absolute_passes_through() {
        let cwd = PathBuf::from("/tmp/x");
        assert_eq!(
            resolve_local(&cwd, "/etc/hosts"),
            PathBuf::from("/etc/hosts")
        );
    }

    #[test]
    fn resolve_local_relative_joins_cwd() {
        let cwd = PathBuf::from("/tmp/x");
        assert_eq!(
            resolve_local(&cwd, "file.txt"),
            PathBuf::from("/tmp/x/file.txt")
        );
    }
}
