//! Message-backed session backend for browser virtual terminals.

use std::collections::VecDeque;

use tokio::sync::{mpsc, Mutex};

use wsh_core::error::{WshError, WshResult};
use wsh_core::messages::{EchoAckPayload, EchoStatePayload, TermDiffPayload, TermSyncPayload};

const DEFAULT_BUFFERED_CHUNKS: usize = 256;

/// Buffered byte queue for a virtual session's incoming `SessionData` frames.
pub struct VirtualSessionBackend {
    incoming_tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    incoming_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    pending: Mutex<VecDeque<u8>>,
    echo_ack: Mutex<Option<EchoAckPayload>>,
    echo_state: Mutex<Option<EchoStatePayload>>,
    term_sync: Mutex<Option<TermSyncPayload>>,
    term_diff: Mutex<Option<TermDiffPayload>>,
}

impl VirtualSessionBackend {
    /// Create an empty virtual-session backend.
    #[must_use]
    pub fn new() -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel(DEFAULT_BUFFERED_CHUNKS);
        Self {
            incoming_tx: Mutex::new(Some(incoming_tx)),
            incoming_rx: Mutex::new(incoming_rx),
            pending: Mutex::new(VecDeque::new()),
            echo_ack: Mutex::new(None),
            echo_state: Mutex::new(None),
            term_sync: Mutex::new(None),
            term_diff: Mutex::new(None),
        }
    }

    /// Queue a new data chunk for later reads.
    pub async fn push_data(&self, data: Vec<u8>) -> WshResult<()> {
        if data.is_empty() {
            return Ok(());
        }

        let sender = self.incoming_tx.lock().await.clone();
        let Some(sender) = sender else {
            return Ok(());
        };

        sender
            .send(data)
            .await
            .map_err(|_| WshError::Channel("virtual session input closed".into()))
    }

    /// Read the next available bytes into `buf`.
    pub async fn read(&self, buf: &mut [u8]) -> WshResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            {
                let mut pending = self.pending.lock().await;
                if !pending.is_empty() {
                    let to_copy = pending.len().min(buf.len());
                    for slot in buf.iter_mut().take(to_copy) {
                        if let Some(byte) = pending.pop_front() {
                            *slot = byte;
                        }
                    }
                    return Ok(to_copy);
                }
            }

            let next_chunk = {
                let mut incoming_rx = self.incoming_rx.lock().await;
                incoming_rx.recv().await
            };

            match next_chunk {
                Some(chunk) => {
                    let mut pending = self.pending.lock().await;
                    pending.extend(chunk);
                }
                None => return Ok(0),
            }
        }
    }

    /// Close the backend. Subsequent reads return EOF once buffered data is drained.
    pub async fn close(&self) {
        self.incoming_tx.lock().await.take();
    }

    /// Record the latest echo acknowledgement for this session.
    pub async fn record_echo_ack(&self, payload: EchoAckPayload) {
        *self.echo_ack.lock().await = Some(payload);
    }

    /// Record the latest echo state for this session.
    pub async fn record_echo_state(&self, payload: EchoStatePayload) {
        *self.echo_state.lock().await = Some(payload);
    }

    /// Record the latest terminal sync hash for this session.
    pub async fn record_term_sync(&self, payload: TermSyncPayload) {
        *self.term_sync.lock().await = Some(payload);
    }

    /// Record the latest terminal diff for this session.
    pub async fn record_term_diff(&self, payload: TermDiffPayload) {
        *self.term_diff.lock().await = Some(payload);
    }

    /// Last echo acknowledgement received for this session.
    pub async fn last_echo_ack(&self) -> Option<EchoAckPayload> {
        self.echo_ack.lock().await.clone()
    }

    /// Last echo state received for this session.
    pub async fn last_echo_state(&self) -> Option<EchoStatePayload> {
        self.echo_state.lock().await.clone()
    }

    /// Last terminal sync hash received for this session.
    pub async fn last_term_sync(&self) -> Option<TermSyncPayload> {
        self.term_sync.lock().await.clone()
    }

    /// Last terminal diff received for this session.
    pub async fn last_term_diff(&self) -> Option<TermDiffPayload> {
        self.term_diff.lock().await.clone()
    }
}

impl Default for VirtualSessionBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use wsh_core::messages::{EchoAckPayload, EchoStatePayload, TermDiffPayload, TermSyncPayload};

    use super::VirtualSessionBackend;

    #[tokio::test]
    async fn read_returns_buffered_virtual_data() {
        let backend = VirtualSessionBackend::new();
        backend.push_data(b"hello".to_vec()).await.unwrap();

        let mut buf = [0_u8; 8];
        let n = backend.read(&mut buf).await.unwrap();

        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn close_returns_eof_after_pending_bytes_are_drained() {
        let backend = VirtualSessionBackend::new();
        backend.push_data(b"ok".to_vec()).await.unwrap();
        backend.close().await;

        let mut buf = [0_u8; 8];
        let first = backend.read(&mut buf).await.unwrap();
        let second = backend.read(&mut buf).await.unwrap();

        assert_eq!(first, 2);
        assert_eq!(&buf[..first], b"ok");
        assert_eq!(second, 0);
    }

    #[tokio::test]
    async fn tracks_echo_and_terminal_metadata() {
        let backend = VirtualSessionBackend::new();

        backend
            .record_echo_ack(EchoAckPayload {
                channel_id: 9,
                echo_seq: 3,
            })
            .await;
        backend
            .record_echo_state(EchoStatePayload {
                channel_id: 9,
                echo_seq: 3,
                cursor_x: 4,
                cursor_y: 1,
                pending: 0,
            })
            .await;
        backend
            .record_term_sync(TermSyncPayload {
                channel_id: 9,
                frame_seq: 7,
                state_hash: vec![1, 2, 3],
            })
            .await;
        backend
            .record_term_diff(TermDiffPayload {
                channel_id: 9,
                frame_seq: 7,
                base_seq: 6,
                patch: vec![4, 5],
            })
            .await;

        assert_eq!(backend.last_echo_ack().await.unwrap().echo_seq, 3);
        assert_eq!(backend.last_echo_state().await.unwrap().cursor_x, 4);
        assert_eq!(backend.last_term_sync().await.unwrap().frame_seq, 7);
        assert_eq!(backend.last_term_diff().await.unwrap().base_seq, 6);
    }
}
