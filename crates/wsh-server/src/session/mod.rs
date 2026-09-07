//! Session management: PTY lifecycle, ring buffer, recording.

pub mod manager;
pub mod pty;
pub mod recording;
pub mod ring_buffer;

pub use manager::{Session, SessionInfo, SessionManager};
pub use pty::PtyHandle;
pub use recording::{RecordingEntry, RecordingEvent, SessionRecorder};
pub use ring_buffer::RingBuffer;
