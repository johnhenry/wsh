//! PTY wrapper using portable-pty.
//!
//! Opens a pseudo-terminal with a given command and size, providing
//! async read/write and resize operations.

use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};
use wsh_core::{WshError, WshResult};

/// A managed PTY instance.
pub struct PtyHandle {
    /// The master side of the PTY (read/write).
    master_reader: Arc<Mutex<Box<dyn Read + Send>>>,
    master_writer: Arc<Mutex<Box<dyn Write + Send>>>,
    /// The master for resize operations (Mutex because MasterPty is not Sync).
    master: Arc<std::sync::Mutex<Box<dyn MasterPty + Send>>>,
    /// Child process handle.
    child: Arc<Mutex<Box<dyn portable_pty::Child + Send>>>,
    /// Current terminal size.
    cols: u16,
    rows: u16,
}

impl PtyHandle {
    /// Spawn a new PTY with the given command and terminal size.
    ///
    /// If `command` is None, the user's default shell is used.
    pub fn spawn(
        command: Option<&str>,
        cols: u16,
        rows: u16,
        env: Option<&std::collections::HashMap<String, String>>,
    ) -> WshResult<Self> {
        let pty_system = native_pty_system();

        let size = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };

        let pair = pty_system
            .openpty(size)
            .map_err(|e| WshError::Other(format!("failed to open PTY: {e}")))?;

        let mut cmd = build_command_builder(command)?;

        // Set environment variables
        if let Some(env_map) = env {
            for (key, value) in env_map {
                cmd.env(key, value);
            }
        }

        // Set TERM if not already in env
        cmd.env("TERM", "xterm-256color");

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| WshError::Other(format!("failed to spawn command: {e}")))?;

        info!(cols, rows, "PTY spawned");

        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| WshError::Other(format!("failed to clone PTY reader: {e}")))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| WshError::Other(format!("failed to take PTY writer: {e}")))?;

        Ok(Self {
            master_reader: Arc::new(Mutex::new(reader)),
            master_writer: Arc::new(Mutex::new(writer)),
            master: Arc::new(std::sync::Mutex::new(pair.master)),
            child: Arc::new(Mutex::new(child)),
            cols,
            rows,
        })
    }

    /// Read from the PTY output (blocking — call from a spawn_blocking context).
    pub fn read_blocking(&self, buf: &mut [u8]) -> WshResult<usize> {
        let mut reader = self
            .master_reader
            .try_lock()
            .map_err(|_| WshError::Other("PTY reader lock contention".into()))?;
        reader.read(buf).map_err(|e| WshError::Io(e))
    }

    /// Write to the PTY input (blocking — call from a spawn_blocking context).
    pub fn write_blocking(&self, data: &[u8]) -> WshResult<()> {
        let mut writer = self
            .master_writer
            .try_lock()
            .map_err(|_| WshError::Other("PTY writer lock contention".into()))?;
        writer.write_all(data).map_err(|e| WshError::Io(e))?;
        writer.flush().map_err(|e| WshError::Io(e))?;
        Ok(())
    }

    /// Resize the PTY.
    pub fn resize(&mut self, cols: u16, rows: u16) -> WshResult<()> {
        let size = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };
        let master = self
            .master
            .lock()
            .map_err(|_| WshError::Other("PTY master lock poisoned".into()))?;
        master
            .resize(size)
            .map_err(|e| WshError::Other(format!("PTY resize failed: {e}")))?;
        drop(master);
        self.cols = cols;
        self.rows = rows;
        debug!(cols, rows, "PTY resized");
        Ok(())
    }

    /// Wait for the child process to exit. Returns the exit code.
    pub async fn wait(&self) -> WshResult<i32> {
        let child = self.child.clone();
        let status = tokio::task::spawn_blocking(move || {
            let mut child = child.blocking_lock();
            child.wait()
        })
        .await
        .map_err(|e| WshError::Other(format!("join error: {e}")))?
        .map_err(|e| WshError::Other(format!("wait error: {e}")))?;

        let code = status.exit_code().try_into().unwrap_or(-1);
        info!(code, "PTY child exited");
        Ok(code as i32)
    }

    /// Kill the child process.
    pub fn kill(&self) -> WshResult<()> {
        let mut child = self
            .child
            .try_lock()
            .map_err(|_| WshError::Other("child lock contention".into()))?;
        child
            .kill()
            .map_err(|e| WshError::Other(format!("kill failed: {e}")))?;
        Ok(())
    }

    /// Get a clone of the reader Arc for use in spawned tasks.
    pub fn reader(&self) -> Arc<Mutex<Box<dyn Read + Send>>> {
        self.master_reader.clone()
    }

    /// Get a clone of the writer Arc for use in spawned tasks.
    pub fn writer(&self) -> Arc<Mutex<Box<dyn Write + Send>>> {
        self.master_writer.clone()
    }

    /// Get a clone of the child process handle Arc, for waiting on exit from
    /// a spawned task without holding a borrow of the owning `Session`/`PtyHandle`.
    pub fn child_handle(&self) -> Arc<Mutex<Box<dyn portable_pty::Child + Send>>> {
        self.child.clone()
    }

    /// Current terminal size.
    pub fn size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }
}

fn build_command_builder(command: Option<&str>) -> WshResult<CommandBuilder> {
    let shell = default_shell();
    let (program, args) = command_spec(command, &shell)?;
    let mut builder = CommandBuilder::new(program);
    for arg in args {
        builder.arg(arg);
    }
    Ok(builder)
}

fn command_spec(command: Option<&str>, shell: &str) -> WshResult<(String, Vec<String>)> {
    match command {
        Some(command) => {
            let trimmed = command.trim();
            if trimmed.is_empty() {
                return Err(WshError::Other("empty command".into()));
            }
            Ok((shell.to_string(), vec!["-c".to_string(), trimmed.to_string()]))
        }
        None => Ok((shell.to_string(), Vec::new())),
    }
}

fn default_shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
}

/// Detect OSC 52 clipboard escape sequences in PTY output.
///
/// OSC 52 format: `\x1b]52;c;<base64-data>\x07` or `\x1b]52;c;<base64-data>\x1b\\`
/// Returns the base64-encoded clipboard data if found.
pub fn detect_osc52(data: &[u8]) -> Option<String> {
    // Look for ESC ] 52 ; c ; ... (ST)
    // ST can be BEL (0x07) or ESC \ (0x1b 0x5c)
    let prefix = b"\x1b]52;c;";
    let start = data.windows(prefix.len()).position(|w| w == prefix)?;
    let payload_start = start + prefix.len();

    // Find the string terminator
    let remaining = &data[payload_start..];

    // Look for BEL or ESC backslash
    let end = remaining
        .iter()
        .position(|&b| b == 0x07)
        .or_else(|| remaining.windows(2).position(|w| w == b"\x1b\\"))?;

    let payload = &remaining[..end];
    String::from_utf8(payload.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::{command_spec, default_shell};

    #[test]
    fn command_spec_uses_shell_c_for_commands() {
        let (program, args) = command_spec(Some("echo hello"), "/bin/sh").unwrap();
        assert_eq!(program, "/bin/sh");
        assert_eq!(args, vec!["-c".to_string(), "echo hello".to_string()]);
    }

    #[test]
    fn command_spec_preserves_shell_syntax_in_single_argument() {
        let command = r#"echo "a b" | sed 's/ /_/g' > out.txt"#;
        let (_program, args) = command_spec(Some(command), "/bin/sh").unwrap();
        assert_eq!(args[1], command);
    }

    #[test]
    fn command_spec_uses_default_shell_for_interactive_sessions() {
        let shell = default_shell();
        let (program, args) = command_spec(None, &shell).unwrap();
        assert_eq!(program, shell);
        assert!(args.is_empty());
    }
}
