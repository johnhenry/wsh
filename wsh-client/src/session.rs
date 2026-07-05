//! Client-side wsh session.
//!
//! A `WshSession` wraps either a transport byte stream or a virtual-session
//! message queue and provides read/write/resize/signal/close operations on a
//! single channel.

use std::sync::Arc;

use tokio::sync::Mutex;
use wsh_core::error::{WshError, WshResult};
use wsh_core::messages::{
    ChannelKind, EchoAckPayload, EchoStatePayload, Envelope, Payload, SessionDataMode,
    TermDiffPayload, TermSyncPayload,
};
use wsh_core::transport::ByteStream;

use crate::virtual_session::VirtualSessionBackend;

/// The state of a session channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// The channel is open and active.
    Open,
    /// The channel is closing (sent close, waiting for confirmation).
    Closing,
    /// The channel is fully closed.
    Closed,
}

/// Options for opening a new session.
#[derive(Debug, Clone)]
pub struct SessionOpts {
    /// Channel kind (pty, exec, meta, file).
    pub kind: ChannelKind,
    /// Command to execute (for exec channels).
    pub command: Option<String>,
    /// Terminal columns (for pty channels).
    pub cols: Option<u16>,
    /// Terminal rows (for pty channels).
    pub rows: Option<u16>,
    /// Environment variables to set.
    pub env: Option<std::collections::HashMap<String, String>>,
}

impl Default for SessionOpts {
    fn default() -> Self {
        Self {
            kind: ChannelKind::Pty,
            command: None,
            cols: Some(80),
            rows: Some(24),
            env: None,
        }
    }
}

/// Information about an existing session.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session identifier.
    pub session_id: String,
    /// Channel ID.
    pub channel_id: u32,
    /// Channel kind.
    pub kind: ChannelKind,
    /// Current state.
    pub state: SessionState,
    /// Human-readable name (if set).
    pub name: Option<String>,
}

/// A client-side wsh session wrapping a data stream.
///
/// Provides buffered read/write operations plus control actions
/// (resize, signal, close) that are dispatched via the control channel.
pub struct WshSession {
    /// Channel ID assigned by the server.
    channel_id: u32,
    /// Channel kind.
    kind: ChannelKind,
    /// Session data mode negotiated in `OpenOk`.
    data_mode: SessionDataMode,
    /// Server-advertised capabilities for this session.
    capabilities: Vec<String>,
    /// Current state.
    state: Arc<Mutex<SessionState>>,
    /// Last known remote exit code, when available.
    exit_code: Arc<Mutex<Option<i32>>>,
    /// The session backend for stream-backed or virtual-backed data.
    backend: SessionBackend,
    /// Sender for control messages (resize, signal, close) — sent to the client's
    /// control dispatch loop.
    control_tx: tokio::sync::mpsc::Sender<ControlAction>,
}

enum SessionBackend {
    Stream(Arc<Mutex<Box<dyn ByteStream>>>),
    Virtual(Arc<VirtualSessionBackend>),
}

/// Internal control actions that the session sends to the client dispatch loop.
#[derive(Debug)]
pub enum ControlAction {
    Data {
        channel_id: u32,
        data: Vec<u8>,
    },
    Resize {
        channel_id: u32,
        cols: u16,
        rows: u16,
    },
    Signal {
        channel_id: u32,
        signal: String,
    },
    Close {
        channel_id: u32,
    },
}

impl WshSession {
    /// Create a new stream-backed session.
    pub(crate) fn new_stream(
        channel_id: u32,
        kind: ChannelKind,
        stream: Box<dyn ByteStream>,
        control_tx: tokio::sync::mpsc::Sender<ControlAction>,
        capabilities: Vec<String>,
    ) -> Self {
        Self {
            channel_id,
            kind,
            data_mode: SessionDataMode::Stream,
            capabilities,
            state: Arc::new(Mutex::new(SessionState::Open)),
            exit_code: Arc::new(Mutex::new(None)),
            backend: SessionBackend::Stream(Arc::new(Mutex::new(stream))),
            control_tx,
        }
    }

    /// Create a new virtual-session-backed session.
    pub(crate) fn new_virtual(
        channel_id: u32,
        kind: ChannelKind,
        control_tx: tokio::sync::mpsc::Sender<ControlAction>,
        capabilities: Vec<String>,
    ) -> Self {
        Self {
            channel_id,
            kind,
            data_mode: SessionDataMode::Virtual,
            capabilities,
            state: Arc::new(Mutex::new(SessionState::Open)),
            exit_code: Arc::new(Mutex::new(None)),
            backend: SessionBackend::Virtual(Arc::new(VirtualSessionBackend::new())),
            control_tx,
        }
    }

    /// The channel ID assigned by the server.
    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    /// The kind of this channel.
    pub fn kind(&self) -> &ChannelKind {
        &self.kind
    }

    /// The negotiated data mode for this session.
    pub fn data_mode(&self) -> &SessionDataMode {
        &self.data_mode
    }

    /// Server-advertised capabilities for this session.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Current session state.
    pub async fn state(&self) -> SessionState {
        *self.state.lock().await
    }

    /// Last known remote process exit code, if one has been reported.
    pub async fn exit_code(&self) -> Option<i32> {
        *self.exit_code.lock().await
    }

    /// Last echo acknowledgement received for this session, if available.
    pub async fn last_echo_ack(&self) -> Option<EchoAckPayload> {
        match &self.backend {
            SessionBackend::Virtual(backend) => backend.last_echo_ack().await,
            SessionBackend::Stream(_) => None,
        }
    }

    /// Last echo state received for this session, if available.
    pub async fn last_echo_state(&self) -> Option<EchoStatePayload> {
        match &self.backend {
            SessionBackend::Virtual(backend) => backend.last_echo_state().await,
            SessionBackend::Stream(_) => None,
        }
    }

    /// Last terminal sync hash received for this session, if available.
    pub async fn last_term_sync(&self) -> Option<TermSyncPayload> {
        match &self.backend {
            SessionBackend::Virtual(backend) => backend.last_term_sync().await,
            SessionBackend::Stream(_) => None,
        }
    }

    /// Last terminal diff received for this session, if available.
    pub async fn last_term_diff(&self) -> Option<TermDiffPayload> {
        match &self.backend {
            SessionBackend::Virtual(backend) => backend.last_term_diff().await,
            SessionBackend::Stream(_) => None,
        }
    }

    /// Write data to the session's data stream.
    pub async fn write(&self, data: &[u8]) -> WshResult<()> {
        let state = self.state.lock().await;
        if *state != SessionState::Open {
            return Err(WshError::Channel(format!(
                "channel {} is not open (state: {:?})",
                self.channel_id, *state
            )));
        }
        drop(state);

        match &self.backend {
            SessionBackend::Stream(stream) => {
                let mut stream = stream.lock().await;
                stream.write_all(data).await
            }
            SessionBackend::Virtual(_) => self
                .control_tx
                .send(ControlAction::Data {
                    channel_id: self.channel_id,
                    data: data.to_vec(),
                })
                .await
                .map_err(|_| WshError::Channel("control channel closed".into())),
        }
    }

    /// Read data from the session's data stream.
    ///
    /// Returns the number of bytes read. Returns 0 on EOF.
    pub async fn read(&self, buf: &mut [u8]) -> WshResult<usize> {
        match &self.backend {
            SessionBackend::Stream(stream) => {
                let mut stream = stream.lock().await;
                stream.read(buf).await
            }
            SessionBackend::Virtual(backend) => backend.read(buf).await,
        }
    }

    /// Resize the terminal (for pty sessions).
    pub async fn resize(&self, cols: u16, rows: u16) -> WshResult<()> {
        self.control_tx
            .send(ControlAction::Resize {
                channel_id: self.channel_id,
                cols,
                rows,
            })
            .await
            .map_err(|_| WshError::Channel("control channel closed".into()))
    }

    /// Send a signal to the session process.
    pub async fn signal(&self, sig: &str) -> WshResult<()> {
        self.control_tx
            .send(ControlAction::Signal {
                channel_id: self.channel_id,
                signal: sig.to_string(),
            })
            .await
            .map_err(|_| WshError::Channel("control channel closed".into()))
    }

    /// Close this session.
    pub async fn close(&self) -> WshResult<()> {
        {
            let mut state = self.state.lock().await;
            if *state == SessionState::Closed {
                return Ok(());
            }
            *state = SessionState::Closing;
        }

        self.control_tx
            .send(ControlAction::Close {
                channel_id: self.channel_id,
            })
            .await
            .map_err(|_| WshError::Channel("control channel closed".into()))?;

        match &self.backend {
            SessionBackend::Stream(stream) => {
                let mut stream = stream.lock().await;
                stream.close().await?;
            }
            SessionBackend::Virtual(backend) => {
                backend.close().await;
            }
        }

        {
            let mut state = self.state.lock().await;
            *state = SessionState::Closed;
        }

        Ok(())
    }

    /// Mark this session as closed (called externally when an Exit message is received).
    pub(crate) async fn mark_closed(&self) {
        if let SessionBackend::Virtual(backend) = &self.backend {
            backend.close().await;
        }
        let mut state = self.state.lock().await;
        *state = SessionState::Closed;
    }

    /// Mark this session closed with a known remote exit code.
    pub(crate) async fn mark_exited(&self, code: i32) {
        {
            let mut exit = self.exit_code.lock().await;
            *exit = Some(code);
        }
        self.mark_closed().await;
    }

    /// Mark this session as open (called when transitioning from a connecting state).
    #[allow(dead_code)]
    pub(crate) async fn mark_open(&self) {
        let mut state = self.state.lock().await;
        *state = SessionState::Open;
    }

    /// Handle a session-specific control message from the server.
    pub(crate) async fn handle_control(&self, envelope: &Envelope) -> WshResult<()> {
        match &envelope.payload {
            Payload::SessionData(data) => match &self.backend {
                SessionBackend::Virtual(backend) => backend.push_data(data.data.clone()).await,
                SessionBackend::Stream(_) => Ok(()),
            },
            Payload::Close(_) => {
                self.mark_closed().await;
                Ok(())
            }
            Payload::Exit(exit) => {
                self.mark_exited(exit.code).await;
                Ok(())
            }
            Payload::EchoAck(payload) => {
                if let SessionBackend::Virtual(backend) = &self.backend {
                    backend.record_echo_ack(payload.clone()).await;
                }
                Ok(())
            }
            Payload::EchoState(payload) => {
                if let SessionBackend::Virtual(backend) = &self.backend {
                    backend.record_echo_state(payload.clone()).await;
                }
                Ok(())
            }
            Payload::TermSync(payload) => {
                if let SessionBackend::Virtual(backend) = &self.backend {
                    backend.record_term_sync(payload.clone()).await;
                }
                Ok(())
            }
            Payload::TermDiff(payload) => {
                if let SessionBackend::Virtual(backend) = &self.backend {
                    backend.record_term_diff(payload.clone()).await;
                }
                Ok(())
            }
            _ => Err(WshError::InvalidMessage(format!(
                "unsupported session control payload for channel {}",
                self.channel_id
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;
    use wsh_core::messages::{
        ChannelKind, ClosePayload, EchoAckPayload, EchoStatePayload, Envelope, ExitPayload,
        MsgType, Payload, TermDiffPayload, TermSyncPayload,
    };

    use super::{ControlAction, SessionState, WshSession};

    #[tokio::test]
    async fn virtual_session_write_sends_session_data_action() {
        let (control_tx, mut control_rx) = mpsc::channel(4);
        let session = WshSession::new_virtual(7, ChannelKind::Pty, control_tx, vec![]);

        session.write(b"pwd\n").await.unwrap();

        let action = control_rx.recv().await.unwrap();
        assert!(matches!(
            action,
            ControlAction::Data { channel_id, data } if channel_id == 7 && data == b"pwd\n"
        ));
    }

    #[tokio::test]
    async fn virtual_session_reads_incoming_session_data() {
        let (control_tx, _control_rx) = mpsc::channel(4);
        let session = WshSession::new_virtual(8, ChannelKind::Pty, control_tx, vec![]);
        let envelope = Envelope {
            msg_type: MsgType::SessionData,
            payload: Payload::SessionData(wsh_core::messages::SessionDataPayload {
                channel_id: 8,
                data: b"ls\n".to_vec(),
            }),
        };

        session.handle_control(&envelope).await.unwrap();

        let mut buf = [0_u8; 8];
        let n = session.read(&mut buf).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..n], b"ls\n");
    }

    #[tokio::test]
    async fn close_payload_marks_virtual_session_closed() {
        let (control_tx, _control_rx) = mpsc::channel(4);
        let session = WshSession::new_virtual(9, ChannelKind::Pty, control_tx, vec![]);
        let envelope = Envelope {
            msg_type: MsgType::Close,
            payload: Payload::Close(ClosePayload { channel_id: 9 }),
        };

        session.handle_control(&envelope).await.unwrap();

        assert_eq!(session.state().await, SessionState::Closed);
        let mut buf = [0_u8; 1];
        assert_eq!(session.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn exit_payload_tracks_remote_exit_code() {
        let (control_tx, _control_rx) = mpsc::channel(4);
        let session = WshSession::new_virtual(10, ChannelKind::Exec, control_tx, vec![]);
        let envelope = Envelope {
            msg_type: MsgType::Exit,
            payload: Payload::Exit(ExitPayload {
                channel_id: 10,
                code: 17,
            }),
        };

        session.handle_control(&envelope).await.unwrap();

        assert_eq!(session.exit_code().await, Some(17));
        assert_eq!(session.state().await, SessionState::Closed);
    }

    #[tokio::test]
    async fn virtual_session_tracks_echo_and_terminal_metadata() {
        let (control_tx, _control_rx) = mpsc::channel(4);
        let session = WshSession::new_virtual(11, ChannelKind::Pty, control_tx, vec![]);

        session
            .handle_control(&Envelope {
                msg_type: MsgType::EchoAck,
                payload: Payload::EchoAck(EchoAckPayload {
                    channel_id: 11,
                    echo_seq: 9,
                }),
            })
            .await
            .unwrap();
        session
            .handle_control(&Envelope {
                msg_type: MsgType::EchoState,
                payload: Payload::EchoState(EchoStatePayload {
                    channel_id: 11,
                    echo_seq: 9,
                    cursor_x: 2,
                    cursor_y: 1,
                    pending: 0,
                }),
            })
            .await
            .unwrap();
        session
            .handle_control(&Envelope {
                msg_type: MsgType::TermSync,
                payload: Payload::TermSync(TermSyncPayload {
                    channel_id: 11,
                    frame_seq: 4,
                    state_hash: vec![1, 2, 3],
                }),
            })
            .await
            .unwrap();
        session
            .handle_control(&Envelope {
                msg_type: MsgType::TermDiff,
                payload: Payload::TermDiff(TermDiffPayload {
                    channel_id: 11,
                    frame_seq: 4,
                    base_seq: 3,
                    patch: vec![4, 5],
                }),
            })
            .await
            .unwrap();

        assert_eq!(session.last_echo_ack().await.unwrap().echo_seq, 9);
        assert_eq!(session.last_echo_state().await.unwrap().cursor_y, 1);
        assert_eq!(session.last_term_sync().await.unwrap().frame_seq, 4);
        assert_eq!(session.last_term_diff().await.unwrap().base_seq, 3);
    }
}
