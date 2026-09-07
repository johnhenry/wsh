//! Shared interactive PTY loop for direct and reverse connections.

use std::io::Write as _;
use std::sync::Arc;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use wsh_client::WshSession;

use crate::terminal as term;

/// Run the interactive terminal loop for an already-open session.
pub async fn run_session(session: Arc<WshSession>, label: &str) -> Result<()> {
    let _guard = term::RawModeGuard::enter().context("failed to enter raw terminal mode")?;

    let (tx_input, mut rx_input) = mpsc::channel::<Vec<u8>>(64);
    let (tx_resize, mut rx_resize) = mpsc::channel::<(u16, u16)>(8);
    let (tx_quit, mut rx_quit) = mpsc::channel::<()>(1);

    let input_handle = tokio::task::spawn_blocking(move || loop {
        match event::read() {
            Ok(Event::Key(key_event)) => {
                if key_event.modifiers.contains(KeyModifiers::CONTROL)
                    && key_event.code == KeyCode::Char(']')
                {
                    let _ = tx_quit.blocking_send(());
                    break;
                }

                if let Some(bytes) = key_event_to_bytes(&key_event) {
                    if tx_input.blocking_send(bytes).is_err() {
                        break;
                    }
                }
            }
            Ok(Event::Resize(new_cols, new_rows)) => {
                let _ = tx_resize.blocking_send((new_cols, new_rows));
            }
            Ok(_) => {}
            Err(e) => {
                warn!("crossterm event error: {e}");
                break;
            }
        }
    });

    eprintln!("Connected to {label}. Press Ctrl+] to exit.\r");

    let mut stdout = std::io::stdout();
    let mut read_buf = vec![0_u8; 8192];

    loop {
        tokio::select! {
            result = session.read(&mut read_buf) => {
                let n = result.map_err(|e| anyhow::anyhow!("{e}"))?;
                if n == 0 {
                    break;
                }
                stdout
                    .write_all(&read_buf[..n])
                    .context("failed to write PTY output to stdout")?;
                stdout.flush().context("failed to flush stdout")?;
            }
            Some(bytes) = rx_input.recv() => {
                session
                    .write(&bytes)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))
                    .context("failed to send input to PTY session")?;
            }
            Some((cols, rows)) = rx_resize.recv() => {
                session
                    .resize(cols, rows)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))
                    .context("failed to resize PTY session")?;
                debug!(cols, rows, "terminal resized");
            }
            _ = rx_quit.recv() => {
                info!("disconnect requested");
                break;
            }
        }
    }

    input_handle.abort();
    let _ = session.close().await;
    eprintln!("\r\nConnection to {label} closed.");

    Ok(())
}

/// Convert a crossterm key event to raw bytes suitable for a PTY.
pub(crate) fn key_event_to_bytes(event: &KeyEvent) -> Option<Vec<u8>> {
    match event.code {
        KeyCode::Char(c) => {
            if event.modifiers.contains(KeyModifiers::CONTROL) {
                let byte = (c as u8).wrapping_sub(b'a').wrapping_add(1);
                if byte <= 26 {
                    return Some(vec![byte]);
                }
            }
            let mut buf = [0_u8; 4];
            let s = c.encode_utf8(&mut buf);
            Some(s.as_bytes().to_vec())
        }
        KeyCode::Enter => Some(vec![b'\r']),
        KeyCode::Backspace => Some(vec![0x7f]),
        KeyCode::Tab => Some(vec![b'\t']),
        KeyCode::Esc => Some(vec![0x1b]),
        KeyCode::Up => Some(b"\x1b[A".to_vec()),
        KeyCode::Down => Some(b"\x1b[B".to_vec()),
        KeyCode::Right => Some(b"\x1b[C".to_vec()),
        KeyCode::Left => Some(b"\x1b[D".to_vec()),
        KeyCode::Home => Some(b"\x1b[H".to_vec()),
        KeyCode::End => Some(b"\x1b[F".to_vec()),
        KeyCode::PageUp => Some(b"\x1b[5~".to_vec()),
        KeyCode::PageDown => Some(b"\x1b[6~".to_vec()),
        KeyCode::Insert => Some(b"\x1b[2~".to_vec()),
        KeyCode::Delete => Some(b"\x1b[3~".to_vec()),
        KeyCode::F(n) => {
            let seq = match n {
                1 => "\x1bOP",
                2 => "\x1bOQ",
                3 => "\x1bOR",
                4 => "\x1bOS",
                5 => "\x1b[15~",
                6 => "\x1b[17~",
                7 => "\x1b[18~",
                8 => "\x1b[19~",
                9 => "\x1b[20~",
                10 => "\x1b[21~",
                11 => "\x1b[23~",
                12 => "\x1b[24~",
                _ => return None,
            };
            Some(seq.as_bytes().to_vec())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::key_event_to_bytes;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    #[test]
    fn ctrl_key_converts_to_control_byte() {
        let event = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(key_event_to_bytes(&event), Some(vec![3]));
    }

    #[test]
    fn arrow_key_converts_to_escape_sequence() {
        let event = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(key_event_to_bytes(&event), Some(b"\x1b[A".to_vec()));
    }
}
