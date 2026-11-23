//! `wsh user@host command` — one-off remote command execution.
//!
//! Connects to the remote host, opens an exec channel with the given command,
//! pipes the command's output to the local stdout/stderr, and exits with the remote
//! exit code. Local stdin goes to the command, and signals sent to `wsh` are passed on
//! to it; with `--tty` the command gets a terminal, and terminal resizes follow.
//!
//! What reaches the command depends on what the host offers:
//!
//! - stdin that is a pipe or a file (not a terminal) on a host advertising
//!   `exec-pipes`: the command runs on plain pipes, so its stdout and stderr stay apart
//!   and the end of stdin reaches it as EOF.
//! - stdin that is a pipe or a file on a host without `exec-pipes`: the bytes are
//!   forwarded, but such a host has no way to be told that stdin ended.
//! - stdin that is a terminal and no `--tty`: nothing is forwarded (the command runs as
//!   it always did, on the host's terminal); use `--tty` or `wsh connect` to type to it.

use std::io::{IsTerminal as _, Write as _};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::AsyncReadExt as _;
use tracing::{debug, info};
use wsh_client::client::EXEC_PIPES_FEATURE;
use wsh_client::session::SessionOpts;
use wsh_client::WshSession;
use wsh_core::messages::ChannelKind;

use crate::commands::common::{connect_client, resolve_target, save_last_session};
use crate::commands::interactive;
use crate::terminal as term;

/// Size of the read buffers for output and stdin.
const OUTPUT_BUFFER: usize = 64 * 1024;

/// Execute a remote command and print its output.
pub async fn run(
    target: &str,
    command: &str,
    port: u16,
    identity: &str,
    transport: Option<&str>,
    tty: bool,
) -> Result<()> {
    let resolved = resolve_target(target, port, transport)?;
    info!(user = %resolved.user, host = %resolved.host, command = %command, "exec");
    debug!(url = %crate::commands::common::redact_rendezvous(&resolved.url), "transport URL");

    let stdin_is_tty = std::io::stdin().is_terminal();
    let want_tty = tty && stdin_is_tty;
    if tty && !stdin_is_tty {
        eprintln!("wsh: --tty ignored: standard input is not a terminal");
    }

    let client = connect_client(&resolved, identity).await?;
    let use_pipes = !want_tty && !stdin_is_tty && client.has_feature(EXEC_PIPES_FEATURE).await;
    let (cols, rows) = if want_tty {
        let (cols, rows) = term::get_terminal_size();
        (Some(cols), Some(rows))
    } else {
        (None, None)
    };
    let session = client
        .open_session(SessionOpts {
            kind: ChannelKind::Exec,
            command: Some(command.to_string()),
            cols,
            rows,
            env: None,
            stdio: use_pipes.then(|| "pipes".to_string()),
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to open exec session")?;
    save_last_session(&resolved, port, identity)?;

    forward_signals(session.clone());

    if want_tty {
        // A terminal for the command: raw keys out, output and resizes handled by the
        // same loop `wsh connect` runs, without its banners.
        interactive::run_session_with(session.clone(), None).await?;
    } else {
        if !stdin_is_tty {
            forward_stdin(session.clone());
        }
        copy_output(&session).await?;
    }

    let exit_code = session.exit_code().await;
    let _ = session.close().await;
    let _ = client.disconnect().await;

    let code = match exit_code {
        Some(code) => code,
        None => {
            eprintln!("wsh: the connection closed before the command reported an exit status");
            255
        }
    };
    if code != 0 {
        eprintln!("wsh: remote command exited with code {code}");
    }
    // Exit here rather than return: the stdin reader is blocked in a read nothing can
    // cancel, and returning would wait for it.
    std::io::stdout().flush().ok();
    crate::commands::forward::cleanup();
    std::process::exit(code);
}

/// Copy the command's stdout and stderr to ours until both end.
///
/// The handles are not `.lock()`ed: a lock held across an `await` blocks every other
/// thread that prints (the client's own `eprintln!` for an exit, the tracing output),
/// and the client's dispatch loop is one of them -- it would wait for a lock that this
/// task releases only after the dispatch loop delivers the data.
async fn copy_output(session: &Arc<WshSession>) -> Result<()> {
    let stdout_side = async {
        let mut stdout = std::io::stdout();
        let mut buf = vec![0u8; OUTPUT_BUFFER];
        loop {
            let n = session
                .read(&mut buf)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))
                .context("failed reading exec output")?;
            if n == 0 {
                return Ok::<(), anyhow::Error>(());
            }
            stdout
                .write_all(&buf[..n])
                .context("failed writing exec output")?;
            stdout.flush().context("failed flushing stdout")?;
        }
    };
    // Drained alongside stdout: stderr that nobody reads would fill its queue and
    // stall the whole connection.
    let stderr_side = async {
        let mut stderr = std::io::stderr();
        let mut buf = vec![0u8; OUTPUT_BUFFER];
        loop {
            let n = session
                .read_stderr(&mut buf)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))
                .context("failed reading exec stderr")?;
            if n == 0 {
                return Ok::<(), anyhow::Error>(());
            }
            stderr
                .write_all(&buf[..n])
                .context("failed writing exec stderr")?;
            stderr.flush().context("failed flushing stderr")?;
        }
    };
    let (out, err) = tokio::join!(stdout_side, stderr_side);
    out.and(err)
}

/// Send local stdin to the command, and its end as EOF where the host can take it.
fn forward_stdin(session: Arc<WshSession>) {
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; OUTPUT_BUFFER];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if session.write(&buf[..n]).await.is_err() {
                        // The command is gone: nothing left to feed.
                        return;
                    }
                }
            }
        }
        match session.close_stdin().await {
            Ok(true) => debug!("stdin closed on the remote command"),
            Ok(false) => debug!("host cannot be told stdin ended"),
            Err(e) => debug!("closing remote stdin failed: {e}"),
        }
    });
}

/// Pass SIGINT, SIGTERM and SIGHUP to the remote command instead of dying with them.
/// The same signal twice means the user wants out and the command is not listening:
/// leave, with the conventional 128 + signal status.
#[cfg(unix)]
fn forward_signals(session: Arc<WshSession>) {
    use tokio::signal::unix::{signal, SignalKind};

    for (kind, name, number) in [
        (SignalKind::interrupt(), "SIGINT", 2),
        (SignalKind::terminate(), "SIGTERM", 15),
        (SignalKind::hangup(), "SIGHUP", 1),
    ] {
        let Ok(mut stream) = signal(kind) else {
            continue;
        };
        let session = session.clone();
        tokio::spawn(async move {
            let mut seen = 0;
            while stream.recv().await.is_some() {
                seen += 1;
                if seen > 1 {
                    eprintln!("\nwsh: {name} again: disconnecting");
                    let _ = session.close().await;
                    crate::commands::forward::cleanup();
                    std::process::exit(128 + number);
                }
                if let Err(e) = session.signal(name).await {
                    debug!("forwarding {name} failed: {e}");
                } else {
                    eprintln!("wsh: {name} sent to the remote command (again to disconnect)");
                }
            }
        });
    }
}

#[cfg(not(unix))]
fn forward_signals(_session: Arc<WshSession>) {}
