//! TCP/UDP forwarding — handles `OpenTcp` / `OpenUdp` / `ResolveDns` by
//! connecting to remote hosts, relaying data bidirectionally, and resolving
//! hostnames.
//!
//! Each outbound connection is tracked by `gateway_id` and can be cancelled
//! via the [`GatewayForwarder::close`] method, which sends a signal through
//! an `mpsc` channel to the spawned relay task.

use super::policy::GatewayPolicyEnforcer;
use super::resolver::DnsResolver;
use super::GatewayEvent;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{self, Duration, Instant};
use tracing::{debug, info, warn};
use wsh_core::messages::*;

/// Idle timeout for UDP relay channels. If no data is sent or received for
/// this duration, the relay shuts down automatically to prevent resource leaks.
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Manages active gateway forwarding connections (TCP, UDP) and DNS lookups.
///
/// Holds a shared [`GatewayPolicyEnforcer`] for access-control checks and
/// maintains maps of active connections keyed by `gateway_id`.
pub struct GatewayForwarder {
    /// Shared policy enforcer for destination checks and connection counting.
    policy: Arc<GatewayPolicyEnforcer>,
    /// Active TCP connections: `gateway_id` to cancel-signal sender.
    tcp_connections: Mutex<HashMap<u32, mpsc::Sender<()>>>,
    /// Active UDP sockets: `gateway_id` to cancel-signal sender.
    udp_connections: Mutex<HashMap<u32, mpsc::Sender<()>>>,
    /// Write channels for client→TCP data: `gateway_id` to data sender.
    write_channels: Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>,
}

impl GatewayForwarder {
    /// Create a new forwarder backed by the given policy enforcer.
    ///
    /// # Arguments
    ///
    /// * `policy` - Shared [`GatewayPolicyEnforcer`] used for every
    ///   connection and listen check.
    pub fn new(policy: Arc<GatewayPolicyEnforcer>) -> Self {
        Self {
            policy,
            tcp_connections: Mutex::new(HashMap::new()),
            udp_connections: Mutex::new(HashMap::new()),
            write_channels: Mutex::new(HashMap::new()),
        }
    }

    /// Handle an `OpenTcp` message: policy check, connect, spawn relay, respond.
    ///
    /// Returns the response message to send back to the client
    /// ([`MsgType::GatewayOk`] or [`MsgType::GatewayFail`]).
    ///
    /// # Arguments
    ///
    /// * `gateway_id` - Client-assigned identifier for this gateway connection.
    /// * `host` - Target hostname or IP address.
    /// * `port` - Target TCP port.
    /// * `data_tx` - Channel for sending TCP→client data events back to the session loop.
    pub async fn handle_open_tcp(
        &self,
        gateway_id: u32,
        host: &str,
        port: u16,
        data_tx: mpsc::Sender<GatewayEvent>,
    ) -> Envelope {
        // Policy check
        if let Err(reason) = self.policy.check_connect(host, port) {
            return build_gateway_fail(gateway_id, 4, &reason); // POLICY_DENIED
        }

        // Connect
        let addr = format!("{}:{}", host, port);
        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                let resolved_addr = stream
                    .peer_addr()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_default();

                let guard = self.policy.acquire();

                // Create cancel channel
                let (cancel_tx, cancel_rx) = mpsc::channel::<()>(1);
                self.tcp_connections
                    .lock()
                    .await
                    .insert(gateway_id, cancel_tx);

                // Create write channel (client→TCP)
                let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(64);
                self.write_channels
                    .lock()
                    .await
                    .insert(gateway_id, write_tx);

                info!(gateway_id, addr = %addr, "TCP connection established");

                // Spawn bidirectional relay task — guard lives until relay ends
                let gateway_id_copy = gateway_id;
                tokio::spawn(async move {
                    let _guard = guard; // keep alive for connection counting
                    Self::tcp_relay(stream, cancel_rx, write_rx, data_tx, gateway_id_copy).await;
                    debug!(gateway_id = gateway_id_copy, "TCP relay ended");
                });

                build_gateway_ok(gateway_id, Some(&resolved_addr))
            }
            Err(e) => {
                warn!(gateway_id, addr = %addr, error = %e, "TCP connect failed");
                build_gateway_fail(gateway_id, 1, &e.to_string()) // CONNECTION_REFUSED
            }
        }
    }

    /// Handle an `OpenUdp` message: policy check, bind local socket, connect to remote,
    /// and spawn a bidirectional UDP relay task.
    ///
    /// Returns [`MsgType::GatewayOk`] on success or [`MsgType::GatewayFail`]
    /// on policy denial or bind failure.
    ///
    /// # Arguments
    ///
    /// * `gateway_id` - Client-assigned identifier for this gateway connection.
    /// * `host` - Target hostname or IP address.
    /// * `port` - Target UDP port.
    /// * `data_tx` - Channel for sending UDP→client data events back to the session loop.
    pub async fn handle_open_udp(
        &self,
        gateway_id: u32,
        host: &str,
        port: u16,
        data_tx: mpsc::Sender<GatewayEvent>,
    ) -> Envelope {
        if let Err(reason) = self.policy.check_connect(host, port) {
            return build_gateway_fail(gateway_id, 4, &reason);
        }

        let addr = format!("{}:{}", host, port);

        match UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => {
                if let Err(e) = socket.connect(&addr).await {
                    return build_gateway_fail(gateway_id, 1, &e.to_string());
                }

                let guard = self.policy.acquire();

                let (cancel_tx, cancel_rx) = mpsc::channel::<()>(1);
                self.udp_connections
                    .lock()
                    .await
                    .insert(gateway_id, cancel_tx);

                // Create write channel (client→UDP)
                let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(64);
                self.write_channels
                    .lock()
                    .await
                    .insert(gateway_id, write_tx);

                info!(gateway_id, addr = %addr, "UDP socket opened");

                // Spawn bidirectional UDP relay task
                let gateway_id_copy = gateway_id;
                tokio::spawn(async move {
                    let _guard = guard;
                    Self::udp_relay(socket, cancel_rx, write_rx, data_tx, gateway_id_copy).await;
                    debug!(gateway_id = gateway_id_copy, "UDP relay ended");
                });

                build_gateway_ok(gateway_id, None)
            }
            Err(e) => {
                warn!(gateway_id, error = %e, "UDP bind failed");
                build_gateway_fail(gateway_id, 1, &e.to_string())
            }
        }
    }

    /// Handle a `ResolveDns` message by delegating to [`DnsResolver`].
    ///
    /// Returns a [`MsgType::DnsResult`] envelope on success or
    /// [`MsgType::GatewayFail`] (code 3 = `DNS_FAILED`) on error.
    ///
    /// # Arguments
    ///
    /// * `gateway_id` - Client-assigned identifier for this request.
    /// * `name` - The hostname to resolve.
    /// * `record_type` - DNS record type filter (`"A"` or `"AAAA"`).
    pub async fn handle_resolve_dns(
        &self,
        gateway_id: u32,
        name: &str,
        record_type: &str,
    ) -> Envelope {
        match DnsResolver::resolve(name, record_type).await {
            Ok((addresses, ttl)) => build_dns_result(gateway_id, addresses, ttl),
            Err(reason) => build_gateway_fail(gateway_id, 3, &reason), // DNS_FAILED
        }
    }

    /// Close a gateway connection (TCP or UDP) by `gateway_id`.
    ///
    /// Sends a cancel signal to the relay task (if one exists) and removes
    /// the entry from all connection maps. Safe to call even if the
    /// `gateway_id` does not correspond to an active connection.
    ///
    /// # Arguments
    ///
    /// * `gateway_id` - The identifier of the connection to close.
    pub async fn close(&self, gateway_id: u32) {
        if let Some(tx) = self.tcp_connections.lock().await.remove(&gateway_id) {
            let _ = tx.send(()).await;
        }
        if let Some(tx) = self.udp_connections.lock().await.remove(&gateway_id) {
            let _ = tx.send(()).await;
        }
        self.write_channels.lock().await.remove(&gateway_id);
    }

    /// Forward data from the client to an active TCP connection.
    ///
    /// Looks up the write channel for the given `gateway_id` and sends the
    /// data through it. The relay task will write it to the TCP socket.
    ///
    /// # Arguments
    ///
    /// * `gateway_id` - The identifier of the gateway connection.
    /// * `data` - The payload bytes to forward to the remote TCP peer.
    pub async fn handle_gateway_data(&self, gateway_id: u32, data: Vec<u8>) {
        let channels = self.write_channels.lock().await;
        if let Some(tx) = channels.get(&gateway_id) {
            if tx.send(data).await.is_err() {
                debug!(gateway_id, "write channel closed, relay ended");
            }
        } else {
            debug!(gateway_id, "no write channel for gateway_id");
        }
    }

    /// Register a write channel for a gateway_id (used by listener for inbound connections).
    pub async fn register_write_channel(&self, gateway_id: u32, tx: mpsc::Sender<Vec<u8>>) {
        self.write_channels.lock().await.insert(gateway_id, tx);
    }

    /// Bidirectional TCP relay (runs in a spawned task).
    ///
    /// Three concurrent branches:
    /// - **Cancel**: Shuts down the relay when the gateway connection is closed.
    /// - **TCP→Client**: Reads from the remote TCP peer and sends `GatewayEvent::Data`
    ///   through `data_tx` for forwarding to the wsh client.
    /// - **Client→TCP**: Reads from `write_rx` (data sent by the client via `GatewayData`)
    ///   and writes it to the remote TCP peer.
    pub(super) async fn tcp_relay(
        stream: TcpStream,
        mut cancel_rx: mpsc::Receiver<()>,
        mut write_rx: mpsc::Receiver<Vec<u8>>,
        data_tx: mpsc::Sender<GatewayEvent>,
        gateway_id: u32,
    ) {
        let (mut read_half, mut write_half) = stream.into_split();
        let mut buf = vec![0u8; 8192];

        loop {
            tokio::select! {
                _ = cancel_rx.recv() => {
                    debug!(gateway_id, "TCP relay cancelled");
                    break;
                }
                result = read_half.read(&mut buf) => {
                    match result {
                        Ok(0) => {
                            debug!(gateway_id, "TCP peer closed connection");
                            let _ = data_tx.send(GatewayEvent::Closed { gateway_id }).await;
                            break;
                        }
                        Ok(n) => {
                            let chunk = buf[..n].to_vec();
                            if data_tx.send(GatewayEvent::Data { gateway_id, data: chunk }).await.is_err() {
                                debug!(gateway_id, "data_tx closed, ending relay");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(gateway_id, error = %e, "TCP read error");
                            let _ = data_tx.send(GatewayEvent::Closed { gateway_id }).await;
                            break;
                        }
                    }
                }
                Some(data) = write_rx.recv() => {
                    if let Err(e) = write_half.write_all(&data).await {
                        warn!(gateway_id, error = %e, "TCP write error");
                        let _ = data_tx.send(GatewayEvent::Closed { gateway_id }).await;
                        break;
                    }
                }
            }
        }

        // Cleanup
        let _ = write_half.shutdown().await;
    }

    /// Bidirectional UDP relay (runs in a spawned task).
    ///
    /// Three concurrent branches:
    /// - **Cancel**: Shuts down the relay when the gateway connection is closed.
    /// - **UDP→Client**: Receives datagrams from the remote peer and sends
    ///   `GatewayEvent::Data` through `data_tx`.
    /// - **Client→UDP**: Reads from `write_rx` (data sent by the client via
    ///   `GatewayData`) and sends it as a UDP datagram.
    async fn udp_relay(
        socket: UdpSocket,
        mut cancel_rx: mpsc::Receiver<()>,
        mut write_rx: mpsc::Receiver<Vec<u8>>,
        data_tx: mpsc::Sender<GatewayEvent>,
        gateway_id: u32,
    ) {
        let mut buf = vec![0u8; 65536]; // max UDP datagram size
        let idle_deadline = time::sleep(UDP_IDLE_TIMEOUT);
        tokio::pin!(idle_deadline);

        loop {
            tokio::select! {
                _ = cancel_rx.recv() => {
                    debug!(gateway_id, "UDP relay cancelled");
                    break;
                }
                () = &mut idle_deadline => {
                    info!(gateway_id, timeout_secs = UDP_IDLE_TIMEOUT.as_secs(), "UDP relay idle timeout");
                    let _ = data_tx.send(GatewayEvent::Closed { gateway_id }).await;
                    break;
                }
                result = socket.recv(&mut buf) => {
                    match result {
                        Ok(n) => {
                            idle_deadline.as_mut().reset(Instant::now() + UDP_IDLE_TIMEOUT);
                            let chunk = buf[..n].to_vec();
                            if data_tx.send(GatewayEvent::Data { gateway_id, data: chunk }).await.is_err() {
                                debug!(gateway_id, "data_tx closed, ending UDP relay");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(gateway_id, error = %e, "UDP recv error");
                            let _ = data_tx.send(GatewayEvent::Closed { gateway_id }).await;
                            break;
                        }
                    }
                }
                Some(data) = write_rx.recv() => {
                    idle_deadline.as_mut().reset(Instant::now() + UDP_IDLE_TIMEOUT);
                    if let Err(e) = socket.send(&data).await {
                        warn!(gateway_id, error = %e, "UDP send error");
                        let _ = data_tx.send(GatewayEvent::Closed { gateway_id }).await;
                        break;
                    }
                }
            }
        }
    }
}

// ── Message builders ─────────────────────────────────────────────────

/// Build a [`MsgType::GatewayOk`] envelope indicating a successful connection.
///
/// * `gateway_id` - The client-assigned connection identifier.
/// * `resolved_addr` - The resolved IP address of the remote peer, if available.
fn build_gateway_ok(gateway_id: u32, resolved_addr: Option<&str>) -> Envelope {
    Envelope {
        msg_type: MsgType::GatewayOk,
        payload: Payload::GatewayOk(GatewayOkPayload {
            gateway_id,
            resolved_addr: resolved_addr.map(|s| s.to_string()),
        }),
    }
}

/// Build a [`MsgType::GatewayFail`] envelope for a failed connection attempt.
///
/// Common error codes:
/// - `1` — `CONNECTION_REFUSED` (TCP connect or UDP bind failure)
/// - `3` — `DNS_FAILED`
/// - `4` — `POLICY_DENIED`
/// - `5` — `GATEWAY_DISABLED`
fn build_gateway_fail(gateway_id: u32, code: u32, message: &str) -> Envelope {
    Envelope {
        msg_type: MsgType::GatewayFail,
        payload: Payload::GatewayFail(GatewayFailPayload {
            gateway_id,
            code,
            message: message.to_string(),
        }),
    }
}

/// Build a [`MsgType::DnsResult`] envelope containing resolved addresses.
///
/// * `gateway_id` - The client-assigned request identifier.
/// * `addresses` - Resolved IP address strings.
/// * `ttl` - DNS time-to-live (currently always `None`; see [`DnsResolver`]).
fn build_dns_result(gateway_id: u32, addresses: Vec<String>, ttl: Option<u32>) -> Envelope {
    Envelope {
        msg_type: MsgType::DnsResult,
        payload: Payload::DnsResult(DnsResultPayload {
            gateway_id,
            addresses,
            ttl,
        }),
    }
}
