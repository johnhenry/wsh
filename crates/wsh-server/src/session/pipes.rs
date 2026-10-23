//! Plain-pipe exec backend (`Open.stdio = "pipes"`, feature `exec-pipes`).
//!
//! The PTY backend merges stdout and stderr, echoes input and rewrites
//! newlines, and has no way to say "end of input". A non-interactive `exec`
//! that wants to feed a command its stdin (`cat > file`, `sh -s`, `wc -c`)
//! needs the opposite: separate stdout/stderr, byte-exact stdin, and an EOF.
//! Interactive sessions (`pty`, shells) never use this module.

use super::pty::{command_spec, PtyHandle};
use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStderr, ChildStdout, Command};
use tokio::sync::mpsc;
use tracing::info;
use wsh_core::{WshError, WshResult};

/// Everything the output pump needs to own once the session is running.
pub struct PipeParts {
    pub child: Child,
    pub stdout: ChildStdout,
    pub stderr: ChildStderr,
    pub kill_rx: mpsc::UnboundedReceiver<()>,
}

/// A command running on plain pipes.
pub struct PipeHandle {
    /// `Some(bytes)` is stdin data, `None` is EOF. Unbounded so a control
    /// message never blocks the connection loop (a blocked loop could not
    /// drain the output the command needs to make progress).
    stdin_tx: mpsc::UnboundedSender<Option<Vec<u8>>>,
    kill_tx: mpsc::UnboundedSender<()>,
    parts: std::sync::Mutex<Option<PipeParts>>,
}

impl PipeHandle {
    /// Spawn `command` (run as `$SHELL -c`, like the PTY backend) on pipes.
    /// Must be called inside a tokio runtime.
    pub fn spawn(command: Option<&str>, env: Option<&HashMap<String, String>>) -> WshResult<Self> {
        let Some(command) = command else {
            return Err(WshError::Other("stdio pipes needs a command".into()));
        };
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let (program, args) = command_spec(Some(command), &shell)?;
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(env) = env {
            cmd.envs(env);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| WshError::Other(format!("failed to spawn command: {e}")))?;
        let mut stdin = child.stdin.take().expect("stdin piped");
        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");

        let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<Option<Vec<u8>>>();
        tokio::spawn(async move {
            while let Some(Some(data)) = stdin_rx.recv().await {
                if stdin.write_all(&data).await.is_err() {
                    // The command closed its stdin (or exited): drop the rest.
                    break;
                }
            }
            // Dropping `stdin` closes the pipe: that is the EOF.
            let _ = stdin.shutdown().await;
        });

        let (kill_tx, kill_rx) = mpsc::unbounded_channel();
        info!("exec spawned on pipes");
        Ok(Self {
            stdin_tx,
            kill_tx,
            parts: std::sync::Mutex::new(Some(PipeParts {
                child,
                stdout,
                stderr,
                kill_rx,
            })),
        })
    }

    /// Queue stdin bytes.
    pub fn write(&self, data: &[u8]) -> WshResult<()> {
        self.stdin_tx
            .send(Some(data.to_vec()))
            .map_err(|_| WshError::Other("stdin is closed".into()))
    }

    /// Close the command's stdin (EOF). Idempotent.
    pub fn close_stdin(&self) {
        let _ = self.stdin_tx.send(None);
    }

    pub fn kill(&self) {
        let _ = self.kill_tx.send(());
    }

    /// Hand the pump the child and its output pipes (once).
    pub fn take_parts(&self) -> Option<PipeParts> {
        self.parts.lock().ok()?.take()
    }
}

/// What backs a session: a PTY (shells, interactive, historical exec) or
/// plain pipes (`exec` that asked for `stdio: "pipes"`).
pub enum SessionIo {
    Pty(PtyHandle),
    Pipes(PipeHandle),
}

impl SessionIo {
    /// Client input. On pipes a zero-length write is the EOF signal; on a PTY
    /// it stays a (harmless) empty write, exactly as before.
    pub fn write_input(&self, data: &[u8]) -> WshResult<()> {
        match self {
            SessionIo::Pty(p) => p.write_blocking(data),
            SessionIo::Pipes(p) => {
                if data.is_empty() {
                    p.close_stdin();
                    Ok(())
                } else {
                    p.write(data)
                }
            }
        }
    }

    pub fn kill(&self) -> WshResult<()> {
        match self {
            SessionIo::Pty(p) => p.kill(),
            SessionIo::Pipes(p) => {
                p.kill();
                Ok(())
            }
        }
    }

    pub fn as_pty(&self) -> Option<&PtyHandle> {
        match self {
            SessionIo::Pty(p) => Some(p),
            SessionIo::Pipes(_) => None,
        }
    }

    pub fn is_pipes(&self) -> bool {
        matches!(self, SessionIo::Pipes(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    async fn run(cmd: &str, input: &[&[u8]]) -> (Vec<u8>, Vec<u8>, i32) {
        let io = SessionIo::Pipes(PipeHandle::spawn(Some(cmd), None).unwrap());
        let SessionIo::Pipes(h) = &io else {
            unreachable!()
        };
        let mut parts = h.take_parts().unwrap();
        for chunk in input {
            io.write_input(chunk).unwrap();
        }
        // A zero-length write is the EOF.
        io.write_input(&[]).unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let (a, b) = tokio::join!(
            parts.stdout.read_to_end(&mut out),
            parts.stderr.read_to_end(&mut err)
        );
        a.unwrap();
        b.unwrap();
        let code = parts.child.wait().await.unwrap().code().unwrap();
        (out, err, code)
    }

    #[tokio::test]
    async fn eof_ends_cat_and_input_is_byte_exact() {
        let (out, err, code) = run("cat", &[b"a\nb\n", b"\x00\xff"]).await;
        assert_eq!(out, b"a\nb\n\x00\xff");
        assert!(err.is_empty());
        assert_eq!(code, 0);
    }

    #[tokio::test]
    async fn stderr_is_kept_apart_and_the_exit_code_is_reported() {
        let (out, err, code) = run("echo out; echo err >&2; exit 3", &[]).await;
        assert_eq!(out, b"out\n");
        assert_eq!(err, b"err\n");
        assert_eq!(code, 3);
    }

    #[tokio::test]
    async fn pipes_need_a_command() {
        assert!(PipeHandle::spawn(None, None).is_err());
    }
}
