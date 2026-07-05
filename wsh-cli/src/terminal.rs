//! Terminal utilities for raw mode, terminal size, and resize events.
//!
//! Wraps crossterm's terminal operations and provides a RAII guard that
//! automatically restores the terminal state on drop.

use anyhow::{Context, Result};
use crossterm::terminal;

/// RAII guard that restores the terminal to its original mode on drop.
///
/// When entered, raw mode is enabled and the alternate screen can optionally
/// be activated. On drop, the terminal is restored to cooked mode.
pub struct RawModeGuard {
    _private: (),
}

impl RawModeGuard {
    /// Enter raw terminal mode.
    ///
    /// Returns a guard that will automatically restore the terminal when dropped.
    pub fn enter() -> Result<Self> {
        terminal::enable_raw_mode().context("failed to enable raw terminal mode")?;
        Ok(Self { _private: () })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        // Best-effort restore — if this fails, the user's terminal may be
        // in a bad state, but there's nothing we can do about it in a Drop impl.
        let _ = terminal::disable_raw_mode();
    }
}

/// Enter raw terminal mode.
///
/// Returns `Ok(())` on success. Caller is responsible for calling
/// `exit_raw_mode()` to restore the terminal.
pub fn enter_raw_mode() -> Result<()> {
    terminal::enable_raw_mode().context("failed to enable raw terminal mode")?;
    Ok(())
}

/// Exit raw terminal mode, restoring normal (cooked) mode.
pub fn exit_raw_mode() -> Result<()> {
    terminal::disable_raw_mode().context("failed to disable raw terminal mode")?;
    Ok(())
}

/// Get the current terminal size as (columns, rows).
///
/// Falls back to (80, 24) if the size cannot be determined.
pub fn get_terminal_size() -> (u16, u16) {
    terminal::size().unwrap_or((80, 24))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_size_returns_nonzero() {
        let (cols, rows) = get_terminal_size();
        // In a CI environment or pipe, we may get the fallback values.
        assert!(cols > 0);
        assert!(rows > 0);
    }
}
