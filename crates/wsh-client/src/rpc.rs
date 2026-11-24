//! Typed rpc channels (wsh #85) from the client side: `Open { kind: "rpc", command: <protocol> }`,
//! answered `OpenOk` with `data_mode: stream`, after which the client opens one QMux data stream whose
//! payload, in both directions, is a CBOR sequence (RFC 8742) of JSON-RPC 2.0 messages. This is the
//! Rust twin of `WshClient.openRpc` / `RpcChannel` in `src/client.mjs` and `src/rpc.mjs`, and speaks
//! to the hosts that serve them (`createWshServer({ rpc })`, `createMemoryHost({ rpc })`, `wsh-server`).
//!
//! The channel is deliberately thin: it moves JSON-RPC messages (`serde_json::Value`) and enforces the
//! host's `rpc-max-message:<n>` bound in both directions; it does not correlate requests (the caller
//! owns ids) or interpret `$/cancel` / `$/progress`, because the user of an `mcp` channel
//! (`wsh mcp`) passes MCP messages through verbatim.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde_json::Value;
use tokio::sync::{mpsc, oneshot, Mutex};
use wsh_core::error::{WshError, WshResult};
use wsh_core::rpc_codec::{encode_message, CborSequenceDecoder};
use wsh_core::transport::ByteStream;

use crate::session::WshSession;

/// `ServerHello` feature: the host serves `rpc` channels.
pub const RPC_FEATURE: &str = "rpc";
/// `ServerHello` feature prefix: one `rpc-protocol:<name>` per protocol the host serves.
pub const RPC_PROTOCOL_PREFIX: &str = "rpc-protocol:";
/// `ServerHello` feature prefix: `rpc-max-message:<bytes>`, the largest single message the host accepts.
pub const RPC_MAX_MESSAGE_PREFIX: &str = "rpc-max-message:";
/// Largest message when the host does not say (1 MiB).
pub const RPC_DEFAULT_MAX_MESSAGE: usize = 1024 * 1024;

/// What a host's `ServerHello.features` say about rpc.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RpcOffer {
    /// The host lists `rpc` at all.
    pub enabled: bool,
    /// The protocols it serves (`mcp`, `wsh-host`, `wsh-fs`, an embedder's own), in advertised order.
    pub protocols: Vec<String>,
    /// The largest single message it accepts and will send.
    pub max_message_bytes: usize,
}

impl RpcOffer {
    pub fn parse(features: &[String]) -> Self {
        let mut offer = RpcOffer {
            enabled: false,
            protocols: Vec::new(),
            max_message_bytes: RPC_DEFAULT_MAX_MESSAGE,
        };
        for f in features {
            if f == RPC_FEATURE {
                offer.enabled = true;
            } else if let Some(name) = f.strip_prefix(RPC_PROTOCOL_PREFIX) {
                offer.protocols.push(name.to_string());
            } else if let Some(n) = f.strip_prefix(RPC_MAX_MESSAGE_PREFIX) {
                if let Ok(n) = n.parse::<usize>() {
                    if n > 0 {
                        offer.max_message_bytes = n;
                    }
                }
            }
        }
        offer
    }

    /// Whether the host serves `protocol`.
    pub fn serves(&self, protocol: &str) -> bool {
        self.enabled && self.protocols.iter().any(|p| p == protocol)
    }
}

/// A protocol name travels in a feature string and in `Open.command`: `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`.
pub fn valid_protocol_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 64 || !b[0].is_ascii_alphanumeric() {
        return false;
    }
    b[1..]
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

enum Command {
    Write(Vec<u8>, oneshot::Sender<WshResult<()>>),
    Close,
}

/// An open rpc channel: JSON-RPC messages out with [`send`](Self::send), in with [`recv`](Self::recv).
pub struct RpcChannel {
    commands: mpsc::Sender<Command>,
    incoming: Mutex<mpsc::Receiver<WshResult<Value>>>,
    max_message_bytes: usize,
    closed: Arc<AtomicBool>,
    /// Stands for the channel in the client's session table, so the host's `Close` finds it.
    stub: Arc<WshSession>,
}

impl RpcChannel {
    pub(crate) fn start(
        stream: Box<dyn ByteStream>,
        max_message_bytes: usize,
        stub: Arc<WshSession>,
    ) -> Self {
        let (commands, command_rx) = mpsc::channel(64);
        let (incoming_tx, incoming) = mpsc::channel(256);
        let closed = Arc::new(AtomicBool::new(false));
        tokio::spawn(pump(
            stream,
            command_rx,
            incoming_tx,
            max_message_bytes,
            closed.clone(),
        ));
        Self {
            commands,
            incoming: Mutex::new(incoming),
            max_message_bytes,
            closed,
            stub,
        }
    }

    /// The largest single message either side may send on this channel.
    pub fn max_message_bytes(&self) -> usize {
        self.max_message_bytes
    }

    /// Whether the channel has ended (the host closed it, the connection dropped, or [`close`](Self::close)).
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Send one JSON-RPC message. A message over the host's bound is refused here, before anything
    /// is written (the host would close the channel on it).
    pub async fn send(&self, message: &Value) -> WshResult<()> {
        let bytes = encode_message(message).map_err(|e| WshError::Other(e.to_string()))?;
        if bytes.len() > self.max_message_bytes {
            return Err(WshError::Other(format!(
                "message of {} bytes exceeds the {} byte rpc message limit",
                bytes.len(),
                self.max_message_bytes
            )));
        }
        let (ack, done) = oneshot::channel();
        self.commands
            .send(Command::Write(bytes, ack))
            .await
            .map_err(|_| WshError::Channel("rpc channel is closed".into()))?;
        done.await
            .map_err(|_| WshError::Channel("rpc channel is closed".into()))?
    }

    /// The next message from the host. `None` once the channel has ended and everything it sent has
    /// been read; `Some(Err(..))` once, last, when the stream could not be decoded or failed.
    pub async fn recv(&self) -> Option<WshResult<Value>> {
        self.incoming.lock().await.recv().await
    }

    /// Close the channel: the host is told (`Close`) and the data stream finished.
    pub async fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let _ = self.commands.send(Command::Close).await;
        let _ = self.stub.close().await;
    }
}

impl Drop for RpcChannel {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        let _ = self.commands.try_send(Command::Close);
    }
}

/// Owns the stream: writes what `send` queues and decodes what arrives, in one task so a read that is
/// waiting never holds the stream against a write (`read` is cancel-safe on every stream this client has).
async fn pump(
    mut stream: Box<dyn ByteStream>,
    mut commands: mpsc::Receiver<Command>,
    incoming: mpsc::Sender<WshResult<Value>>,
    max_message_bytes: usize,
    closed: Arc<AtomicBool>,
) {
    let mut decoder = CborSequenceDecoder::new(max_message_bytes);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            biased;
            command = commands.recv() => match command {
                Some(Command::Write(bytes, ack)) => {
                    let result = stream.write_all(&bytes).await;
                    let failed = result.is_err();
                    let _ = ack.send(result);
                    if failed {
                        break;
                    }
                }
                Some(Command::Close) | None => {
                    let _ = stream.close().await;
                    break;
                }
            },
            read = stream.read(&mut buf) => match read {
                Ok(0) => break,
                Ok(n) => match decoder.feed(&buf[..n]) {
                    Ok(messages) => {
                        for message in messages {
                            if incoming.send(Ok(message)).await.is_err() {
                                closed.store(true, Ordering::Relaxed);
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        let _ = incoming.send(Err(WshError::Other(format!("rpc stream: {e}")))).await;
                        let _ = stream.close().await;
                        break;
                    }
                },
                Err(e) => {
                    let _ = incoming.send(Err(e)).await;
                    break;
                }
            },
        }
    }
    closed.store(true, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn features(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_offer_reads_protocols_and_the_bound() {
        let o = RpcOffer::parse(&features(&[
            "mcp-call-id",
            "rpc",
            "rpc-protocol:wsh-host",
            "rpc-protocol:mcp",
            "rpc-max-message:4096",
        ]));
        assert!(o.enabled);
        assert_eq!(o.protocols, vec!["wsh-host", "mcp"]);
        assert_eq!(o.max_message_bytes, 4096);
        assert!(o.serves("mcp") && !o.serves("wsh-fs"));
    }

    #[test]
    fn a_host_without_rpc_serves_nothing_even_if_a_protocol_is_listed() {
        let o = RpcOffer::parse(&features(&["rpc-protocol:mcp"]));
        assert!(!o.enabled && !o.serves("mcp"));
        assert_eq!(o.max_message_bytes, RPC_DEFAULT_MAX_MESSAGE);
    }

    #[test]
    fn a_nonsense_bound_is_ignored() {
        for bad in [
            "rpc-max-message:0",
            "rpc-max-message:-1",
            "rpc-max-message:x",
        ] {
            assert_eq!(
                RpcOffer::parse(&features(&["rpc", bad])).max_message_bytes,
                RPC_DEFAULT_MAX_MESSAGE
            );
        }
    }

    #[test]
    fn protocol_names_are_boring() {
        assert!(
            valid_protocol_name("mcp")
                && valid_protocol_name("wsh-fs")
                && valid_protocol_name("a.b_c-1")
        );
        for bad in ["", "-x", ".x", "a b", "a/b", "a\0", &"x".repeat(65)] {
            assert!(!valid_protocol_name(bad), "{bad:?}");
        }
    }
}
