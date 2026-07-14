//! Reverse-host runtime for `wsh reverse`.
//!
//! Accepts relay-forwarded OPEN/SESSION_DATA/RESIZE/SIGNAL/CLOSE messages and
//! serves them from a local PTY so another client can remote into this machine
//! through a relay.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{Context, Result};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};
use wsh_client::WshClient;
use wsh_core::messages::*;

const DEFAULT_PTY_REPLAY_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseHostOptions {
    pub capabilities: Vec<String>,
    pub peer_type: String,
    pub shell_backend: String,
    pub supports_attach: bool,
    pub supports_replay: bool,
    pub supports_echo: bool,
    pub supports_term_sync: bool,
}

impl Default for ReverseHostOptions {
    fn default() -> Self {
        Self {
            capabilities: vec!["shell".to_string(), "exec".to_string()],
            peer_type: "host".to_string(),
            shell_backend: "pty".to_string(),
            supports_attach: false,
            supports_replay: false,
            supports_echo: false,
            supports_term_sync: false,
        }
    }
}

impl ReverseHostOptions {
    pub fn reverse_register_payload(
        &self,
        username: String,
        public_key: Vec<u8>,
    ) -> ReverseRegisterPayload {
        ReverseRegisterPayload {
            username,
            capabilities: self.capabilities.clone(),
            peer_type: self.peer_type.clone(),
            shell_backend: self.shell_backend.clone(),
            supports_attach: self.supports_attach,
            supports_replay: self.supports_replay,
            supports_echo: self.supports_echo,
            supports_term_sync: self.supports_term_sync,
            public_key,
        }
    }

    fn reverse_accept_payload(&self, request: ReverseConnectPayload) -> ReverseAcceptPayload {
        ReverseAcceptPayload {
            target_fingerprint: request.target_fingerprint,
            username: request.username,
            capabilities: self.capabilities.clone(),
            peer_type: self.peer_type.clone(),
            shell_backend: self.shell_backend.clone(),
            supports_attach: self.supports_attach,
            supports_replay: self.supports_replay,
            supports_echo: self.supports_echo,
            supports_term_sync: self.supports_term_sync,
        }
    }

    fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|value| value == capability)
    }

    fn allows_kind(&self, kind: ChannelKind) -> bool {
        match kind {
            ChannelKind::Pty => self.has_capability("shell"),
            ChannelKind::Exec => self.has_capability("exec") || self.has_capability("shell"),
            ChannelKind::File => self.has_capability("fs"),
            _ => false,
        }
    }
}

fn same_reverse_request(left: &ReverseConnectPayload, right: &ReverseConnectPayload) -> bool {
    left.username == right.username && left.target_fingerprint == right.target_fingerprint
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReverseHostRunOutcome {
    Interrupted,
    TransportClosed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReverseHostStatusEvent {
    ReverseConnectionAccepted {
        requester: String,
        target_fingerprint: String,
    },
    SessionCountChanged {
        active_sessions: usize,
    },
}

pub async fn run_with_options(
    client: Arc<WshClient>,
    mut reverse_connect_rx: mpsc::Receiver<Envelope>,
    mut relay_message_rx: mpsc::Receiver<Envelope>,
    options: ReverseHostOptions,
    status_tx: Option<mpsc::Sender<ReverseHostStatusEvent>>,
) -> Result<ReverseHostRunOutcome> {
    let mut service = ReverseHostService::new(options);
    let outcome = run_with_service(
        &mut service,
        client,
        &mut reverse_connect_rx,
        &mut relay_message_rx,
        status_tx,
    )
    .await;
    service.shutdown().await;
    outcome
}

pub async fn run_with_service(
    service: &mut ReverseHostService,
    client: Arc<WshClient>,
    reverse_connect_rx: &mut mpsc::Receiver<Envelope>,
    relay_message_rx: &mut mpsc::Receiver<Envelope>,
    status_tx: Option<mpsc::Sender<ReverseHostStatusEvent>>,
) -> Result<ReverseHostRunOutcome> {
    service.attach_client(client, status_tx).await;
    let mut reverse_channel_closed = false;
    let mut relay_channel_closed = false;

    loop {
        tokio::select! {
            envelope = reverse_connect_rx.recv(), if !reverse_channel_closed => {
                match envelope {
                    Some(envelope) => service.runtime.handle_reverse_connect(envelope).await?,
                    None => reverse_channel_closed = true,
                }
            }
            envelope = relay_message_rx.recv(), if !relay_channel_closed => {
                match envelope {
                    Some(envelope) => service.runtime.handle_relay_message(envelope).await?,
                    None => relay_channel_closed = true,
                }
            }
            Some(event) = service.event_rx.recv() => {
                service.runtime.handle_runtime_event(event).await?;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("reverse host runtime received Ctrl+C");
                service.shutdown().await;
                return Ok(ReverseHostRunOutcome::Interrupted);
            }
        }

        if reverse_channel_closed && relay_channel_closed {
            info!("reverse host runtime transport closed");
            service.detach_client().await;
            return Ok(ReverseHostRunOutcome::TransportClosed);
        }
    }
}

pub struct ReverseHostService {
    runtime: ReverseHostRuntime,
    event_tx: mpsc::UnboundedSender<RuntimeEvent>,
    event_rx: mpsc::UnboundedReceiver<RuntimeEvent>,
}

impl ReverseHostService {
    pub fn new(options: ReverseHostOptions) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        Self {
            runtime: ReverseHostRuntime::new(options),
            event_tx,
            event_rx,
        }
    }

    async fn attach_client(
        &mut self,
        client: Arc<WshClient>,
        status_tx: Option<mpsc::Sender<ReverseHostStatusEvent>>,
    ) {
        self.runtime
            .attach_client(client, status_tx, self.event_tx.clone())
            .await;
    }

    async fn detach_client(&mut self) {
        self.runtime.detach_client().await;
    }

    pub async fn shutdown(&mut self) {
        self.runtime.shutdown().await;
    }
}

struct ReverseHostRuntime {
    client: Option<Arc<WshClient>>,
    event_tx: Option<mpsc::UnboundedSender<RuntimeEvent>>,
    options: ReverseHostOptions,
    status_tx: Option<mpsc::Sender<ReverseHostStatusEvent>>,
    active_request: Option<ReverseConnectPayload>,
    sessions: HashMap<u32, ReverseHostSession>,
    gateway_connections: HashMap<u32, ReverseGatewayConnection>,
    mcp: LocalMcpBridge,
    next_channel_id: u32,
}

impl ReverseHostRuntime {
    fn new(options: ReverseHostOptions) -> Self {
        Self {
            options,
            client: None,
            event_tx: None,
            status_tx: None,
            active_request: None,
            sessions: HashMap::new(),
            gateway_connections: HashMap::new(),
            mcp: LocalMcpBridge::default(),
            next_channel_id: 1,
        }
    }

    async fn attach_client(
        &mut self,
        client: Arc<WshClient>,
        status_tx: Option<mpsc::Sender<ReverseHostStatusEvent>>,
        event_tx: mpsc::UnboundedSender<RuntimeEvent>,
    ) {
        self.client = Some(client);
        self.event_tx = Some(event_tx.clone());
        self.status_tx = status_tx;
        self.emit_session_count().await;
    }

    async fn detach_client(&mut self) {
        self.client = None;
        self.event_tx = None;
        self.status_tx = None;
        for session in self.sessions.values_mut() {
            session.set_notifier(None);
        }
        let gateway_ids: Vec<u32> = self.gateway_connections.keys().copied().collect();
        for gateway_id in gateway_ids {
            self.close_gateway_connection(gateway_id).await;
        }
    }

    fn client(&self) -> Result<Arc<WshClient>> {
        self.client
            .clone()
            .context("reverse host runtime is not currently bound to a relay client")
    }

    async fn handle_reverse_connect(&mut self, envelope: Envelope) -> Result<()> {
        let Payload::ReverseConnect(request) = envelope.payload else {
            return Ok(());
        };

        if self.active_request.is_some() || !self.sessions.is_empty() {
            if self
                .active_request
                .as_ref()
                .is_some_and(|existing| same_reverse_request(existing, &request))
            {
                info!(
                    requester = %request.username,
                    target = %request.target_fingerprint,
                    "reattaching reverse host connection"
                );
                self.active_request = Some(request.clone());
                self.client()?
                    .send_fire_and_forget(Envelope {
                        msg_type: MsgType::ReverseAccept,
                        payload: Payload::ReverseAccept(self.options.reverse_accept_payload(request)),
                    })
                    .await
                    .map_err(|err| anyhow::anyhow!("{err}"))?;
                return Ok(());
            }

            self.client()?
                .send_fire_and_forget(Envelope {
                    msg_type: MsgType::ReverseReject,
                    payload: Payload::ReverseReject(ReverseRejectPayload {
                        target_fingerprint: request.target_fingerprint.clone(),
                        username: request.username.clone(),
                        reason: "reverse host is busy".to_string(),
                    }),
                })
                .await
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            return Ok(());
        }

        info!(
            requester = %request.username,
            target = %request.target_fingerprint,
            "accepting reverse host connection"
        );
        self.notify_status(ReverseHostStatusEvent::ReverseConnectionAccepted {
            requester: request.username.clone(),
            target_fingerprint: request.target_fingerprint.clone(),
        })
        .await;
        self.active_request = Some(request.clone());
        self.client()?
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::ReverseAccept,
                payload: Payload::ReverseAccept(self.options.reverse_accept_payload(request)),
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;

        Ok(())
    }

    async fn handle_relay_message(
        &mut self,
        envelope: Envelope,
    ) -> Result<()> {
        match envelope.payload {
            Payload::Open(open) => self.handle_open(open).await,
            Payload::SessionData(data) => self.handle_session_data(data).await,
            Payload::Resize(resize) => self.handle_resize(resize).await,
            Payload::Signal(signal) => self.handle_signal(signal).await,
            Payload::Close(close) => self.handle_close(close).await,
            Payload::McpDiscover(_) => self.handle_mcp_discover().await,
            Payload::McpCall(call) => self.handle_mcp_call(call).await,
            Payload::OpenTcp(open) => self.handle_open_tcp(open).await,
            Payload::OpenUdp(open) => self.handle_open_udp(open).await,
            Payload::ResolveDns(resolve) => self.handle_resolve_dns(resolve).await,
            Payload::GatewayData(data) => self.handle_gateway_data(data).await,
            Payload::GatewayClose(close) => self.handle_gateway_close(close).await,
            Payload::ListenRequest(request) => self.handle_listen_request(request).await,
            Payload::InboundAccept(accept) => self.handle_inbound_accept(accept).await,
            Payload::InboundReject(reject) => self.handle_inbound_reject(reject).await,
            other => {
                debug!("ignoring unsupported reverse-host relay message: {:?}", other);
                Ok(())
            }
        }
    }

    async fn handle_runtime_event(&mut self, event: RuntimeEvent) -> Result<()> {
        match event {
            RuntimeEvent::OutputReady { channel_id } => {
                let Some(session) = self.sessions.get_mut(&channel_id) else {
                    return Ok(());
                };

                for data in session.take_pending_output() {
                    self.client()?
                        .send_fire_and_forget(Envelope {
                            msg_type: MsgType::SessionData,
                            payload: Payload::SessionData(SessionDataPayload { channel_id, data }),
                        })
                        .await
                        .map_err(|err| anyhow::anyhow!("{err}"))?;
                }
            }
            RuntimeEvent::Exited { channel_id, code } => {
                if self.client.is_some() {
                    self.client()?
                        .send_fire_and_forget(Envelope {
                            msg_type: MsgType::Exit,
                            payload: Payload::Exit(ExitPayload { channel_id, code }),
                        })
                        .await
                        .map_err(|err| anyhow::anyhow!("{err}"))?;
                    self.client()?
                        .send_fire_and_forget(Envelope {
                            msg_type: MsgType::Close,
                            payload: Payload::Close(ClosePayload { channel_id }),
                        })
                        .await
                        .map_err(|err| anyhow::anyhow!("{err}"))?;
                    self.drop_session(channel_id).await;
                }
            }
            RuntimeEvent::ReadFailed { channel_id, error } => {
                warn!(channel_id, "reverse host PTY read failed: {error}");
                if self.client.is_some() {
                    self.client()?
                        .send_fire_and_forget(Envelope {
                            msg_type: MsgType::Exit,
                            payload: Payload::Exit(ExitPayload {
                                channel_id,
                                code: -1,
                            }),
                        })
                        .await
                        .map_err(|err| anyhow::anyhow!("{err}"))?;
                    self.client()?
                        .send_fire_and_forget(Envelope {
                            msg_type: MsgType::Close,
                            payload: Payload::Close(ClosePayload { channel_id }),
                        })
                        .await
                        .map_err(|err| anyhow::anyhow!("{err}"))?;
                    self.drop_session(channel_id).await;
                }
            }
        }

        Ok(())
    }

    async fn handle_open(&mut self, open: OpenPayload) -> Result<()> {
        let kind = open.kind.clone();
        if !self.options.allows_kind(kind.clone()) {
            let reason = match kind {
                ChannelKind::Pty => "shell access not permitted for this reverse host",
                ChannelKind::Exec => "exec access not permitted for this reverse host",
                ChannelKind::File => "file transfer not permitted for this reverse host",
                _ => "unsupported channel kind for this reverse host",
            };
            return self.send_open_fail(reason).await;
        }

        if self.try_reattach_channel(&open).await? {
            return Ok(());
        }

        let channel_id = self.next_channel_id;
        self.next_channel_id += 1;

        let capabilities = match kind {
            ChannelKind::Pty | ChannelKind::Exec => {
                let cols = open.cols.unwrap_or(80);
                let rows = open.rows.unwrap_or(24);
                let command = open.command.clone();
                let env = open.env.clone();

                let pty = LocalPty::spawn(command.as_deref(), cols, rows, env.as_ref())
                    .with_context(|| format!("failed to spawn local PTY for channel {channel_id}"))?;
                let pty = Arc::new(pty);
                let notifier = self.event_tx.clone();
                let session = ReverseHostPtySession::spawn(
                    channel_id,
                    kind.clone(),
                    command.clone(),
                    cols,
                    rows,
                    pty,
                    notifier,
                );
                self.sessions.insert(channel_id, ReverseHostSession::Pty(session));

                match kind {
                    ChannelKind::Pty => vec!["resize".into(), "signal".into()],
                    ChannelKind::Exec => vec!["signal".into()],
                    _ => vec![],
                }
            }
            ChannelKind::File => {
                let file_session = ReverseHostFileSession::from_command(open.command.as_deref())
                    .with_context(|| format!("failed to prepare file channel {channel_id}"))?;
                self.sessions
                    .insert(channel_id, ReverseHostSession::File(file_session));
                Vec::new()
            }
            _ => {
                return self
                    .send_open_fail("reverse host currently supports only pty, exec, and file channels")
                    .await;
            }
        };

        self.client()?
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::OpenOk,
                payload: Payload::OpenOk(OpenOkPayload {
                    channel_id,
                    stream_ids: vec![],
                    data_mode: SessionDataMode::Virtual,
                    capabilities,
                }),
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        self.emit_session_count().await;

        Ok(())
    }

    async fn handle_session_data(&mut self, data: SessionDataPayload) -> Result<()> {
        let client = self.client.clone();
        let Some(session) = self.sessions.get_mut(&data.channel_id) else {
            return Ok(());
        };

        match session {
            ReverseHostSession::Pty(session) => {
                let pty = session.pty.clone();
                tokio::task::spawn_blocking(move || pty.write_blocking(&data.data))
                    .await
                    .map_err(|err| anyhow::anyhow!("join error: {err}"))?
                    .with_context(|| format!("failed to write to PTY channel {}", data.channel_id))
            }
            ReverseHostSession::File(session) => {
                let responses = session
                    .handle_data(&data.data)
                    .with_context(|| format!("failed to handle file channel {}", data.channel_id))?;

                for response in responses {
                    client
                        .as_ref()
                        .context("reverse host runtime is not currently bound to a relay client")?
                        .send_fire_and_forget(Envelope {
                            msg_type: MsgType::SessionData,
                            payload: Payload::SessionData(SessionDataPayload {
                                channel_id: data.channel_id,
                                data: response,
                            }),
                        })
                        .await
                        .map_err(|err| anyhow::anyhow!("{err}"))?;
                }

                if session.should_close() {
                    client
                        .as_ref()
                        .context("reverse host runtime is not currently bound to a relay client")?
                        .send_fire_and_forget(Envelope {
                            msg_type: MsgType::Close,
                            payload: Payload::Close(ClosePayload {
                                channel_id: data.channel_id,
                            }),
                        })
                        .await
                        .map_err(|err| anyhow::anyhow!("{err}"))?;
                    self.drop_session(data.channel_id).await;
                }
                Ok(())
            }
        }
    }

    async fn handle_resize(&mut self, resize: ResizePayload) -> Result<()> {
        let Some(session) = self.sessions.get(&resize.channel_id) else {
            return Ok(());
        };

        match session {
            ReverseHostSession::Pty(session) => {
                let pty = session.pty.clone();
                tokio::task::spawn_blocking(move || pty.resize_blocking(resize.cols, resize.rows))
                    .await
                    .map_err(|err| anyhow::anyhow!("join error: {err}"))?
                    .with_context(|| format!("failed to resize PTY channel {}", resize.channel_id))
            }
            ReverseHostSession::File(_) => Ok(()),
        }
    }

    async fn handle_signal(&mut self, signal: SignalPayload) -> Result<()> {
        let Some(session) = self.sessions.get(&signal.channel_id) else {
            return Ok(());
        };

        match session {
            ReverseHostSession::Pty(session) => {
                let pty = session.pty.clone();
                let signal_name = signal.signal.clone();
                tokio::task::spawn_blocking(move || pty.signal_blocking(&signal_name))
                    .await
                    .map_err(|err| anyhow::anyhow!("join error: {err}"))?
                    .with_context(|| format!("failed to signal PTY channel {}", signal.channel_id))
            }
            ReverseHostSession::File(_) => Ok(()),
        }
    }

    async fn handle_close(&mut self, close: ClosePayload) -> Result<()> {
        self.drop_session(close.channel_id).await;
        Ok(())
    }

    async fn handle_mcp_discover(&self) -> Result<()> {
        let tools = if self.options.has_capability("tools") {
            self.mcp.list_tools()
        } else {
            Vec::new()
        };
        self.client()?
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::McpTools,
                payload: Payload::McpTools(McpToolsPayload { tools }),
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        Ok(())
    }

    async fn handle_mcp_call(&self, call: McpCallPayload) -> Result<()> {
        let result = if self.options.has_capability("tools") {
            self.mcp.call(&call).await
        } else {
            McpResultPayload {
                result: json!({
                    "error": "tool access not permitted for this reverse host",
                }),
            }
        };
        self.client()?
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::McpResult,
                payload: Payload::McpResult(result),
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        Ok(())
    }

    async fn handle_open_tcp(&mut self, open: OpenTcpPayload) -> Result<()> {
        if !self.options.has_capability("gateway") {
            return self
                .send_gateway_fail(open.gateway_id, 5, "gateway access not permitted for this reverse host")
                .await;
        }
        if self.gateway_connections.contains_key(&open.gateway_id) {
            return self
                .send_gateway_fail(open.gateway_id, 4, "gateway id already in use")
                .await;
        }

        match TcpStream::connect((open.host.as_str(), open.port)).await {
            Ok(stream) => {
                let resolved_addr = stream.peer_addr().ok().map(|addr| addr.to_string());
                let connection =
                    spawn_tcp_gateway(self.client()?, open.gateway_id, stream);
                self.gateway_connections.insert(open.gateway_id, connection);
                self.client()?
                    .send_fire_and_forget(Envelope {
                        msg_type: MsgType::GatewayOk,
                        payload: Payload::GatewayOk(GatewayOkPayload {
                            gateway_id: open.gateway_id,
                            resolved_addr,
                        }),
                    })
                    .await
                    .map_err(|err| anyhow::anyhow!("{err}"))?;
                Ok(())
            }
            Err(err) => {
                self.send_gateway_fail(open.gateway_id, 1, &err.to_string())
                    .await
            }
        }
    }

    async fn handle_open_udp(&mut self, open: OpenUdpPayload) -> Result<()> {
        if !self.options.has_capability("gateway") {
            return self
                .send_gateway_fail(open.gateway_id, 5, "gateway access not permitted for this reverse host")
                .await;
        }
        if self.gateway_connections.contains_key(&open.gateway_id) {
            return self
                .send_gateway_fail(open.gateway_id, 4, "gateway id already in use")
                .await;
        }

        let bind_addr = if open.host.contains(':') { "[::]:0" } else { "0.0.0.0:0" };
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(socket) => socket,
            Err(err) => {
                return self
                    .send_gateway_fail(open.gateway_id, 1, &err.to_string())
                    .await;
            }
        };
        if let Err(err) = socket.connect((open.host.as_str(), open.port)).await {
            return self
                .send_gateway_fail(open.gateway_id, 1, &err.to_string())
                .await;
        }

        let resolved_addr = socket.peer_addr().ok().map(|addr| addr.to_string());
        let connection = spawn_udp_gateway(self.client()?, open.gateway_id, socket);
        self.gateway_connections.insert(open.gateway_id, connection);
        self.client()?
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::GatewayOk,
                payload: Payload::GatewayOk(GatewayOkPayload {
                    gateway_id: open.gateway_id,
                    resolved_addr,
                }),
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        Ok(())
    }

    async fn handle_resolve_dns(&self, resolve: ResolveDnsPayload) -> Result<()> {
        if !self.options.has_capability("gateway") {
            return self
                .send_gateway_fail(
                    resolve.gateway_id,
                    5,
                    "gateway access not permitted for this reverse host",
                )
                .await;
        }

        match lookup_host((resolve.name.as_str(), 0)).await {
            Ok(addresses) => {
                let addresses = filter_dns_addresses(addresses.map(|addr| addr.ip()), &resolve.record_type);
                self.client()?
                    .send_fire_and_forget(Envelope {
                        msg_type: MsgType::DnsResult,
                        payload: Payload::DnsResult(DnsResultPayload {
                            gateway_id: resolve.gateway_id,
                            addresses,
                            ttl: None,
                        }),
                    })
                    .await
                    .map_err(|err| anyhow::anyhow!("{err}"))?;
                Ok(())
            }
            Err(err) => self
                .send_gateway_fail(resolve.gateway_id, 3, &err.to_string())
                .await,
        }
    }

    async fn handle_gateway_data(&mut self, data: GatewayDataPayload) -> Result<()> {
        let Some(connection) = self.gateway_connections.get(&data.gateway_id) else {
            return Ok(());
        };
        if connection.write_tx.send(data.data).await.is_err() {
            self.gateway_connections.remove(&data.gateway_id);
            self.send_gateway_close(data.gateway_id, Some("gateway closed".to_string()))
                .await?;
        }
        Ok(())
    }

    async fn handle_gateway_close(&mut self, close: GatewayClosePayload) -> Result<()> {
        self.close_gateway_connection(close.gateway_id).await;
        Ok(())
    }

    async fn handle_listen_request(&self, request: ListenRequestPayload) -> Result<()> {
        self.client()?
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::ListenFail,
                payload: Payload::ListenFail(ListenFailPayload {
                    listener_id: request.listener_id,
                    reason: "reverse host listeners are not implemented yet".to_string(),
                }),
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        Ok(())
    }

    async fn handle_inbound_accept(&self, accept: InboundAcceptPayload) -> Result<()> {
        debug!(channel_id = accept.channel_id, "ignoring inbound accept for unsupported reverse listener");
        Ok(())
    }

    async fn handle_inbound_reject(&self, reject: InboundRejectPayload) -> Result<()> {
        debug!(channel_id = reject.channel_id, "ignoring inbound reject for unsupported reverse listener");
        Ok(())
    }

    async fn close_gateway_connection(&mut self, gateway_id: u32) {
        if let Some(connection) = self.gateway_connections.remove(&gateway_id) {
            connection.task.abort();
        }
    }

    async fn send_gateway_fail(&self, gateway_id: u32, code: u32, message: &str) -> Result<()> {
        self.client()?
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::GatewayFail,
                payload: Payload::GatewayFail(GatewayFailPayload {
                    gateway_id,
                    code,
                    message: message.to_string(),
                }),
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        Ok(())
    }

    async fn send_gateway_close(&self, gateway_id: u32, reason: Option<String>) -> Result<()> {
        self.client()?
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::GatewayClose,
                payload: Payload::GatewayClose(GatewayClosePayload { gateway_id, reason }),
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        Ok(())
    }

    async fn send_open_fail(&self, reason: &str) -> Result<()> {
        self.client()?
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::OpenFail,
                payload: Payload::OpenFail(OpenFailPayload {
                    reason: reason.to_string(),
                }),
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        Ok(())
    }

    async fn drop_session(&mut self, channel_id: u32) {
        if let Some(session) = self.sessions.remove(&channel_id) {
            match session {
                ReverseHostSession::Pty(session) => {
                    let pty = session.pty.clone();
                    let _ = tokio::task::spawn_blocking(move || pty.kill_blocking()).await;
                    session.output_task.abort();
                    session.wait_task.abort();
                }
                ReverseHostSession::File(_) => {}
            }
        }

        if self.sessions.is_empty() {
            self.active_request = None;
        }
        self.emit_session_count().await;
    }

    async fn shutdown(&mut self) {
        let channel_ids: Vec<u32> = self.sessions.keys().copied().collect();
        for channel_id in channel_ids {
            self.drop_session(channel_id).await;
        }
        let gateway_ids: Vec<u32> = self.gateway_connections.keys().copied().collect();
        for gateway_id in gateway_ids {
            self.close_gateway_connection(gateway_id).await;
        }
    }

    async fn notify_status(&self, event: ReverseHostStatusEvent) {
        if let Some(status_tx) = &self.status_tx {
            let _ = status_tx.send(event).await;
        }
    }

    async fn emit_session_count(&self) {
        self.notify_status(ReverseHostStatusEvent::SessionCountChanged {
            active_sessions: self.sessions.len(),
        })
        .await;
    }

    async fn try_reattach_channel(&mut self, open: &OpenPayload) -> Result<bool> {
        let client = self.client()?;
        let matching_ids = self
            .sessions
            .iter()
            .filter_map(|(channel_id, session)| {
                session
                    .matches_reattach(&open.kind, open.command.as_deref())
                    .then_some(*channel_id)
            })
            .collect::<Vec<_>>();

        if matching_ids.is_empty() {
            return Ok(false);
        }
        if matching_ids.len() > 1 {
            self.send_open_fail("multiple resumable sessions match this request")
                .await?;
            return Ok(true);
        }

        let channel_id = matching_ids[0];
        let Some(session) = self.sessions.get_mut(&channel_id) else {
            return Ok(false);
        };
        if let Some((cols, rows)) = open.cols.zip(open.rows) {
            session.resize(cols, rows)?;
        }
        let capabilities = session.capabilities();
        client
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::OpenOk,
                payload: Payload::OpenOk(OpenOkPayload {
                    channel_id,
                    stream_ids: vec![],
                    data_mode: SessionDataMode::Virtual,
                    capabilities,
                }),
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        session.replay_to_client(&client, channel_id).await?;
        if let Some(code) = session.exit_code() {
            client
                .send_fire_and_forget(Envelope {
                    msg_type: MsgType::Exit,
                    payload: Payload::Exit(ExitPayload { channel_id, code }),
                })
                .await
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            client
                .send_fire_and_forget(Envelope {
                    msg_type: MsgType::Close,
                    payload: Payload::Close(ClosePayload { channel_id }),
                })
                .await
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            self.drop_session(channel_id).await;
        } else if let Some(event_tx) = self.event_tx.clone() {
            session.set_notifier(Some(event_tx));
        }
        Ok(true)
    }
}

enum ReverseHostSession {
    Pty(ReverseHostPtySession),
    File(ReverseHostFileSession),
}

impl ReverseHostSession {
    fn set_notifier(&mut self, notifier: Option<mpsc::UnboundedSender<RuntimeEvent>>) {
        if let Self::Pty(session) = self {
            session.set_notifier(notifier);
        }
    }

    fn matches_reattach(&self, kind: &ChannelKind, command: Option<&str>) -> bool {
        match self {
            Self::Pty(session) => session.matches_reattach(kind, command),
            Self::File(_) => false,
        }
    }

    fn capabilities(&self) -> Vec<String> {
        match self {
            Self::Pty(session) => session.capabilities(),
            Self::File(_) => Vec::new(),
        }
    }

    fn take_pending_output(&self) -> Vec<Vec<u8>> {
        match self {
            Self::Pty(session) => session.take_pending_output(),
            Self::File(_) => Vec::new(),
        }
    }

    fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        match self {
            Self::Pty(session) => session.resize(cols, rows),
            Self::File(_) => Ok(()),
        }
    }

    async fn replay_to_client(&self, client: &Arc<WshClient>, channel_id: u32) -> Result<()> {
        if let Self::Pty(session) = self {
            let replay = session.replay_bytes();
            session.clear_pending_output();
            if !replay.is_empty() {
                client
                    .send_fire_and_forget(Envelope {
                        msg_type: MsgType::SessionData,
                        payload: Payload::SessionData(SessionDataPayload {
                            channel_id,
                            data: replay,
                        }),
                    })
                    .await
                    .map_err(|err| anyhow::anyhow!("{err}"))?;
            }
        }
        Ok(())
    }

    fn exit_code(&self) -> Option<i32> {
        match self {
            Self::Pty(session) => session.exit_code(),
            Self::File(_) => None,
        }
    }
}

struct ReverseHostPtySession {
    kind: ChannelKind,
    command: Option<String>,
    capabilities: Vec<String>,
    pty: Arc<LocalPty>,
    output_task: tokio::task::JoinHandle<()>,
    wait_task: tokio::task::JoinHandle<()>,
    replay: Arc<StdMutex<Vec<u8>>>,
    pending_output: Arc<StdMutex<VecDeque<Vec<u8>>>>,
    exit_code: Arc<StdMutex<Option<i32>>>,
    notifier: Arc<StdMutex<Option<mpsc::UnboundedSender<RuntimeEvent>>>>,
}

struct ReverseGatewayConnection {
    write_tx: mpsc::Sender<Vec<u8>>,
    task: tokio::task::JoinHandle<()>,
}

enum RuntimeEvent {
    OutputReady { channel_id: u32 },
    Exited { channel_id: u32, code: i32 },
    ReadFailed { channel_id: u32, error: String },
}

impl ReverseHostPtySession {
    fn spawn(
        channel_id: u32,
        kind: ChannelKind,
        command: Option<String>,
        _cols: u16,
        _rows: u16,
        pty: Arc<LocalPty>,
        notifier: Option<mpsc::UnboundedSender<RuntimeEvent>>,
    ) -> Self {
        let replay = Arc::new(StdMutex::new(Vec::new()));
        let pending_output = Arc::new(StdMutex::new(VecDeque::new()));
        let exit_code = Arc::new(StdMutex::new(None));
        let notifier = Arc::new(StdMutex::new(notifier));
        let output_task = spawn_output_task(
            channel_id,
            pty.clone(),
            replay.clone(),
            pending_output.clone(),
            notifier.clone(),
            exit_code.clone(),
        );
        let wait_task = spawn_wait_task(
            channel_id,
            pty.clone(),
            notifier.clone(),
            exit_code.clone(),
        );
        Self {
            kind: kind.clone(),
            command,
            capabilities: match kind {
                ChannelKind::Pty => vec!["resize".into(), "signal".into()],
                ChannelKind::Exec => vec!["signal".into()],
                _ => Vec::new(),
            },
            pty,
            output_task,
            wait_task,
            replay,
            pending_output,
            exit_code,
            notifier,
        }
    }

    fn set_notifier(&self, notifier: Option<mpsc::UnboundedSender<RuntimeEvent>>) {
        *self
            .notifier
            .lock()
            .expect("reverse host notifier lock poisoned") = notifier;
    }

    fn matches_reattach(&self, kind: &ChannelKind, command: Option<&str>) -> bool {
        if &self.kind != kind {
            return false;
        }
        match kind {
            ChannelKind::Exec => self.command.as_deref() == Some(command.unwrap_or_default()),
            _ => true,
        }
    }

    fn capabilities(&self) -> Vec<String> {
        self.capabilities.clone()
    }

    fn take_pending_output(&self) -> Vec<Vec<u8>> {
        let mut pending = self
            .pending_output
            .lock()
            .expect("reverse host pending output lock poisoned");
        pending.drain(..).collect()
    }

    fn clear_pending_output(&self) {
        self.pending_output
            .lock()
            .expect("reverse host pending output lock poisoned")
            .clear();
    }

    fn replay_bytes(&self) -> Vec<u8> {
        self.replay
            .lock()
            .expect("reverse host replay lock poisoned")
            .clone()
    }

    fn exit_code(&self) -> Option<i32> {
        *self
            .exit_code
            .lock()
            .expect("reverse host exit code lock poisoned")
    }

    fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.pty.resize_blocking(cols, rows)
    }
}

fn spawn_output_task(
    channel_id: u32,
    pty: Arc<LocalPty>,
    replay: Arc<StdMutex<Vec<u8>>>,
    pending_output: Arc<StdMutex<VecDeque<Vec<u8>>>>,
    notifier: Arc<StdMutex<Option<mpsc::UnboundedSender<RuntimeEvent>>>>,
    exit_code: Arc<StdMutex<Option<i32>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let pty = pty.clone();
            let read_result = tokio::task::spawn_blocking(move || {
                let mut buf = vec![0_u8; 8192];
                match pty.read_blocking(&mut buf) {
                    Ok(0) => Ok(None),
                    Ok(n) => {
                        buf.truncate(n);
                        Ok(Some(buf))
                    }
                    Err(err) => Err(err.to_string()),
                }
            })
            .await;

            match read_result {
                Ok(Ok(Some(data))) => {
                    append_replay(&replay, &data);
                    if notifier
                        .lock()
                        .expect("reverse host notifier lock poisoned")
                        .is_some()
                    {
                        pending_output
                            .lock()
                            .expect("reverse host pending output lock poisoned")
                            .push_back(data);
                        notify_runtime(&notifier, RuntimeEvent::OutputReady { channel_id });
                    }
                }
                Ok(Ok(None)) => break,
                Ok(Err(error)) => {
                    *exit_code
                        .lock()
                        .expect("reverse host exit code lock poisoned") = Some(-1);
                    notify_runtime(&notifier, RuntimeEvent::ReadFailed { channel_id, error });
                    break;
                }
                Err(join_error) => {
                    *exit_code
                        .lock()
                        .expect("reverse host exit code lock poisoned") = Some(-1);
                    notify_runtime(
                        &notifier,
                        RuntimeEvent::ReadFailed {
                            channel_id,
                            error: join_error.to_string(),
                        },
                    );
                    break;
                }
            }
        }
    })
}

fn spawn_wait_task(
    channel_id: u32,
    pty: Arc<LocalPty>,
    notifier: Arc<StdMutex<Option<mpsc::UnboundedSender<RuntimeEvent>>>>,
    exit_code: Arc<StdMutex<Option<i32>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        match tokio::task::spawn_blocking(move || pty.wait_blocking()).await {
            Ok(Ok(code)) => {
                *exit_code
                    .lock()
                    .expect("reverse host exit code lock poisoned") = Some(code);
                notify_runtime(&notifier, RuntimeEvent::Exited { channel_id, code });
            }
            Ok(Err(err)) => {
                *exit_code
                    .lock()
                    .expect("reverse host exit code lock poisoned") = Some(-1);
                notify_runtime(
                    &notifier,
                    RuntimeEvent::ReadFailed {
                        channel_id,
                        error: err.to_string(),
                    },
                );
            }
            Err(join_err) => {
                *exit_code
                    .lock()
                    .expect("reverse host exit code lock poisoned") = Some(-1);
                notify_runtime(
                    &notifier,
                    RuntimeEvent::ReadFailed {
                        channel_id,
                        error: join_err.to_string(),
                    },
                );
            }
        }
    })
}

fn append_replay(replay: &Arc<StdMutex<Vec<u8>>>, data: &[u8]) {
    let mut replay = replay.lock().expect("reverse host replay lock poisoned");
    replay.extend_from_slice(data);
    if replay.len() > DEFAULT_PTY_REPLAY_LIMIT {
        let excess = replay.len() - DEFAULT_PTY_REPLAY_LIMIT;
        replay.drain(0..excess);
    }
}

fn notify_runtime(
    notifier: &Arc<StdMutex<Option<mpsc::UnboundedSender<RuntimeEvent>>>>,
    event: RuntimeEvent,
) {
    if let Some(sender) = notifier
        .lock()
        .expect("reverse host notifier lock poisoned")
        .as_ref()
        .cloned()
    {
        let _ = sender.send(event);
    }
}

#[derive(Default)]
struct LocalMcpBridge;

impl LocalMcpBridge {
    fn list_tools(&self) -> Vec<McpToolSpec> {
        vec![
            McpToolSpec {
                name: "shell.exec".to_string(),
                description: "Execute a shell command on the reverse host".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "command": { "type": "string", "description": "Shell command to execute" },
                        "cwd": { "type": "string", "description": "Optional working directory" }
                    },
                    "required": ["command"],
                }),
            },
            McpToolSpec {
                name: "fs.read_file".to_string(),
                description: "Read a UTF-8 text file from the reverse host".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute or relative file path" }
                    },
                    "required": ["path"],
                }),
            },
            McpToolSpec {
                name: "fs.write_file".to_string(),
                description: "Write a UTF-8 text file on the reverse host".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute or relative file path" },
                        "content": { "type": "string", "description": "Text content to write" },
                        "append": { "type": "boolean", "description": "Append instead of overwrite" }
                    },
                    "required": ["path", "content"],
                }),
            },
            McpToolSpec {
                name: "fs.list_dir".to_string(),
                description: "List entries in a directory on the reverse host".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Directory path" }
                    },
                    "required": ["path"],
                }),
            },
        ]
    }

    async fn call(&self, call: &McpCallPayload) -> McpResultPayload {
        let result = match call.tool.as_str() {
            "shell.exec" => self.exec_tool(&call.arguments).await,
            "fs.read_file" => self.read_file_tool(&call.arguments).await,
            "fs.write_file" => self.write_file_tool(&call.arguments).await,
            "fs.list_dir" => self.list_dir_tool(&call.arguments).await,
            _ => Err(anyhow::anyhow!("unknown tool: {}", call.tool)),
        };

        match result {
            Ok(result) => McpResultPayload { result },
            Err(err) => McpResultPayload {
                result: json!({ "error": err.to_string() }),
            },
        }
    }

    async fn exec_tool(&self, arguments: &Value) -> Result<Value> {
        let command = required_string_arg(arguments, "command")?;
        let mut cmd = tokio::process::Command::new(default_shell());
        cmd.arg("-c").arg(command);
        if let Some(cwd) = optional_string_arg(arguments, "cwd")? {
            cmd.current_dir(cwd);
        }

        let output = timeout(Duration::from_secs(30), cmd.output())
            .await
            .context("shell.exec timed out")?
            .context("shell.exec failed")?;
        Ok(json!({
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr),
            "exit_code": output.status.code().unwrap_or(-1),
        }))
    }

    async fn read_file_tool(&self, arguments: &Value) -> Result<Value> {
        let path = required_string_arg(arguments, "path")?;
        let content = tokio::fs::read_to_string(path)
            .await
            .context("failed to read file")?;
        Ok(json!({ "path": path, "content": content }))
    }

    async fn write_file_tool(&self, arguments: &Value) -> Result<Value> {
        let path = required_string_arg(arguments, "path")?;
        let content = required_string_arg(arguments, "content")?;
        let append = arguments
            .get("append")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        ensure_parent_dir(path).await?;
        if append {
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
                .context("failed to open file for append")?;
            file.write_all(content.as_bytes())
                .await
                .context("failed to append file")?;
        } else {
            tokio::fs::write(path, content)
                .await
                .context("failed to write file")?;
        }
        Ok(json!({ "path": path, "bytes_written": content.len(), "append": append }))
    }

    async fn list_dir_tool(&self, arguments: &Value) -> Result<Value> {
        let path = required_string_arg(arguments, "path")?;
        let mut dir = tokio::fs::read_dir(path)
            .await
            .context("failed to read directory")?;
        let mut entries = Vec::new();
        while let Some(entry) = dir.next_entry().await.context("failed to iterate directory")? {
            let metadata = entry.metadata().await.context("failed to stat directory entry")?;
            entries.push(json!({
                "name": entry.file_name().to_string_lossy().to_string(),
                "path": entry.path(),
                "is_dir": metadata.is_dir(),
                "size": metadata.len(),
            }));
        }
        Ok(json!({ "path": path, "entries": entries }))
    }
}

struct ReverseHostFileSession {
    state: FileSessionState,
}

impl ReverseHostFileSession {
    fn from_command(command: Option<&str>) -> Result<Self> {
        let command = command.unwrap_or_default();
        let Some((mode, path)) = command.split_once(':') else {
            anyhow::bail!("file channels require upload:<path> or download:<path>");
        };
        let path = PathBuf::from(path);
        let state = match mode {
            "upload" => FileSessionState::Upload(UploadState::new(path)),
            "download" => FileSessionState::Download(DownloadState::new(path)),
            _ => anyhow::bail!("unsupported file mode `{mode}`"),
        };
        Ok(Self { state })
    }

    fn handle_data(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>> {
        match &mut self.state {
            FileSessionState::Upload(state) => {
                state.ingest(chunk)?;
                if state.is_complete() {
                    return Ok(vec![b"ok".to_vec()]);
                }
                Ok(Vec::new())
            }
            FileSessionState::Download(state) => state.ingest(chunk),
        }
    }

    fn should_close(&self) -> bool {
        match &self.state {
            FileSessionState::Upload(state) => state.is_complete(),
            FileSessionState::Download(state) => state.sent,
        }
    }
}

enum FileSessionState {
    Upload(UploadState),
    Download(DownloadState),
}

struct UploadState {
    requested_path: PathBuf,
    header_buf: Vec<u8>,
    writer: Option<File>,
    expected_size: Option<u64>,
    received: u64,
    complete: bool,
}

impl UploadState {
    fn new(path: PathBuf) -> Self {
        Self {
            requested_path: path,
            header_buf: Vec::new(),
            writer: None,
            expected_size: None,
            received: 0,
            complete: false,
        }
    }

    fn ingest(&mut self, chunk: &[u8]) -> Result<()> {
        if self.complete {
            return Ok(());
        }

        let mut remaining: Vec<u8> = chunk.to_vec();
        if self.expected_size.is_none() {
            self.header_buf.extend_from_slice(chunk);
            let Some((path, total_size, consumed)) = try_parse_upload_header(&self.header_buf)? else {
                return Ok(());
            };
            if path != self.requested_path {
                anyhow::bail!(
                    "upload path mismatch: requested {}, header {}",
                    self.requested_path.display(),
                    path.display()
                );
            }
            ensure_parent_dir_sync(&path)?;
            let writer = File::create(&path)
                .with_context(|| format!("failed to create {}", path.display()))?;
            self.writer = Some(writer);
            self.expected_size = Some(total_size);
            remaining = self.header_buf[consumed..].to_vec();
            self.header_buf.clear();
        }

        if !remaining.is_empty() {
            let writer = self
                .writer
                .as_mut()
                .context("upload writer not initialized")?;
            writer.write_all(&remaining)?;
            writer.flush()?;
            self.received += remaining.len() as u64;
        }

        if self.received >= self.expected_size.unwrap_or(0) {
            self.complete = true;
        }

        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

struct DownloadState {
    requested_path: PathBuf,
    header_buf: Vec<u8>,
    sent: bool,
}

impl DownloadState {
    fn new(path: PathBuf) -> Self {
        Self {
            requested_path: path,
            header_buf: Vec::new(),
            sent: false,
        }
    }

    fn ingest(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>> {
        if self.sent {
            return Ok(Vec::new());
        }

        self.header_buf.extend_from_slice(chunk);
        let Some((path, _consumed)) = try_parse_download_header(&self.header_buf)? else {
            return Ok(Vec::new());
        };
        if path != self.requested_path {
            anyhow::bail!(
                "download path mismatch: requested {}, header {}",
                self.requested_path.display(),
                path.display()
            );
        }

        let data = std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let mut payload = Vec::with_capacity(8 + data.len());
        payload.extend_from_slice(&(data.len() as u64).to_be_bytes());
        payload.extend_from_slice(&data);
        self.sent = true;
        Ok(vec![payload])
    }
}

fn try_parse_upload_header(buf: &[u8]) -> Result<Option<(PathBuf, u64, usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let path_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + path_len + 8 {
        return Ok(None);
    }
    let path = std::str::from_utf8(&buf[4..4 + path_len]).context("invalid upload path header")?;
    let total_offset = 4 + path_len;
    let total_size = u64::from_be_bytes(
        buf[total_offset..total_offset + 8]
            .try_into()
            .expect("header slice length should be 8"),
    );
    Ok(Some((PathBuf::from(path), total_size, total_offset + 8)))
}

fn try_parse_download_header(buf: &[u8]) -> Result<Option<(PathBuf, usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let path_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + path_len {
        return Ok(None);
    }
    let path = std::str::from_utf8(&buf[4..4 + path_len]).context("invalid download path header")?;
    Ok(Some((PathBuf::from(path), 4 + path_len)))
}

fn spawn_tcp_gateway(
    client: Arc<WshClient>,
    gateway_id: u32,
    stream: TcpStream,
) -> ReverseGatewayConnection {
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(64);
    let task = tokio::spawn(async move {
        let (mut reader, mut writer) = stream.into_split();
        let mut buf = vec![0_u8; 8192];
        loop {
            tokio::select! {
                read = reader.read(&mut buf) => {
                    match read {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = buf[..n].to_vec();
                            let _ = client
                                .send_fire_and_forget(Envelope {
                                    msg_type: MsgType::GatewayData,
                                    payload: Payload::GatewayData(GatewayDataPayload { gateway_id, data }),
                                })
                                .await;
                        }
                        Err(err) => {
                            warn!(gateway_id, "reverse host TCP gateway read failed: {err}");
                            break;
                        }
                    }
                }
                payload = write_rx.recv() => {
                    match payload {
                        Some(payload) => {
                            if let Err(err) = writer.write_all(&payload).await {
                                warn!(gateway_id, "reverse host TCP gateway write failed: {err}");
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }

        let _ = client
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::GatewayClose,
                payload: Payload::GatewayClose(GatewayClosePayload {
                    gateway_id,
                    reason: Some("gateway stream closed".to_string()),
                }),
            })
            .await;
    });

    ReverseGatewayConnection { write_tx, task }
}

fn spawn_udp_gateway(
    client: Arc<WshClient>,
    gateway_id: u32,
    socket: UdpSocket,
) -> ReverseGatewayConnection {
    let socket = Arc::new(socket);
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(64);
    let task = tokio::spawn(async move {
        let mut buf = vec![0_u8; 8192];
        loop {
            tokio::select! {
                read = socket.recv(&mut buf) => {
                    match read {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = buf[..n].to_vec();
                            let _ = client
                                .send_fire_and_forget(Envelope {
                                    msg_type: MsgType::GatewayData,
                                    payload: Payload::GatewayData(GatewayDataPayload { gateway_id, data }),
                                })
                                .await;
                        }
                        Err(err) => {
                            warn!(gateway_id, "reverse host UDP gateway recv failed: {err}");
                            break;
                        }
                    }
                }
                payload = write_rx.recv() => {
                    match payload {
                        Some(payload) => {
                            if let Err(err) = socket.send(&payload).await {
                                warn!(gateway_id, "reverse host UDP gateway send failed: {err}");
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }

        let _ = client
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::GatewayClose,
                payload: Payload::GatewayClose(GatewayClosePayload {
                    gateway_id,
                    reason: Some("gateway datagram stream closed".to_string()),
                }),
            })
            .await;
    });

    ReverseGatewayConnection { write_tx, task }
}

fn filter_dns_addresses(addresses: impl Iterator<Item = IpAddr>, record_type: &str) -> Vec<String> {
    let record_type = record_type.trim().to_ascii_uppercase();
    addresses
        .filter(|address| match record_type.as_str() {
            "A" => address.is_ipv4(),
            "AAAA" => address.is_ipv6(),
            _ => true,
        })
        .map(|address| address.to_string())
        .collect()
}

fn required_string_arg<'a>(arguments: &'a Value, key: &str) -> Result<&'a str> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing required string argument `{key}`"))
}

fn optional_string_arg<'a>(arguments: &'a Value, key: &str) -> Result<Option<&'a str>> {
    match arguments.get(key) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => anyhow::bail!("argument `{key}` must be a string"),
        None => Ok(None),
    }
}

async fn ensure_parent_dir(path: &str) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    Ok(())
}

fn ensure_parent_dir_sync(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    Ok(())
}

struct LocalPty {
    master_reader: std::sync::Mutex<Box<dyn Read + Send>>,
    master_writer: std::sync::Mutex<Box<dyn Write + Send>>,
    master: std::sync::Mutex<Box<dyn MasterPty + Send>>,
    child: std::sync::Mutex<Box<dyn portable_pty::Child + Send>>,
}

impl LocalPty {
    fn spawn(
        command: Option<&str>,
        cols: u16,
        rows: u16,
        env: Option<&HashMap<String, String>>,
    ) -> Result<Self> {
        let pty_system = native_pty_system();
        let size = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };
        let pair = pty_system
            .openpty(size)
            .context("failed to allocate PTY pair")?;

        let mut cmd = build_command_builder(command)?;

        if let Some(env_map) = env {
            for (key, value) in env_map {
                cmd.env(key, value);
            }
        }
        cmd.env("TERM", "xterm-256color");

        let child = pair
            .slave
            .spawn_command(cmd)
            .context("failed to spawn PTY command")?;

        let reader = pair
            .master
            .try_clone_reader()
            .context("failed to clone PTY reader")?;
        let writer = pair.master.take_writer().context("failed to take PTY writer")?;

        Ok(Self {
            master_reader: std::sync::Mutex::new(reader),
            master_writer: std::sync::Mutex::new(writer),
            master: std::sync::Mutex::new(pair.master),
            child: std::sync::Mutex::new(child),
        })
    }

    fn read_blocking(&self, buf: &mut [u8]) -> Result<usize> {
        let mut reader = self
            .master_reader
            .lock()
            .map_err(|_| anyhow::anyhow!("PTY reader lock poisoned"))?;
        let n = reader.read(buf)?;
        Ok(n)
    }

    fn write_blocking(&self, data: &[u8]) -> Result<()> {
        let mut writer = self
            .master_writer
            .lock()
            .map_err(|_| anyhow::anyhow!("PTY writer lock poisoned"))?;
        writer.write_all(data)?;
        writer.flush()?;
        Ok(())
    }

    fn resize_blocking(&self, cols: u16, rows: u16) -> Result<()> {
        let master = self
            .master
            .lock()
            .map_err(|_| anyhow::anyhow!("PTY master lock poisoned"))?;
        master.resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        Ok(())
    }

    fn signal_blocking(&self, signal: &str) -> Result<()> {
        match signal {
            "SIGINT" | "INT" => self.write_blocking(&[3]),
            "SIGTERM" | "TERM" | "SIGKILL" | "KILL" => self.kill_blocking(),
            _ => Ok(()),
        }
    }

    fn kill_blocking(&self) -> Result<()> {
        let mut child = self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("PTY child lock poisoned"))?;
        child.kill()?;
        Ok(())
    }

    fn wait_blocking(&self) -> Result<i32> {
        let mut child = self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("PTY child lock poisoned"))?;
        let status = child.wait()?;
        Ok(status.exit_code() as i32)
    }
}

fn build_command_builder(command: Option<&str>) -> Result<CommandBuilder> {
    let shell = default_shell();
    let (program, args) = command_spec(command, &shell)?;
    let mut builder = CommandBuilder::new(program);
    for arg in args {
        builder.arg(arg);
    }
    Ok(builder)
}

fn command_spec(command: Option<&str>, shell: &str) -> Result<(String, Vec<String>)> {
    match command {
        Some(command) => {
            let trimmed = command.trim();
            if trimmed.is_empty() {
                anyhow::bail!("empty command");
            }
            Ok((shell.to_string(), vec!["-c".to_string(), trimmed.to_string()]))
        }
        None => Ok((shell.to_string(), Vec::new())),
    }
}

fn default_shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex as StdMutex};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use serde_json::json;
    use tokio::sync::mpsc;
    use wsh_core::messages::{ChannelKind, ReverseConnectPayload};

    use super::{
        append_replay, command_spec, filter_dns_addresses, same_reverse_request,
        try_parse_download_header, try_parse_upload_header, LocalMcpBridge, LocalPty,
        ReverseHostFileSession, ReverseHostOptions, ReverseHostPtySession, RuntimeEvent,
    };

    #[test]
    fn reverse_host_command_spec_uses_shell_c() {
        let (program, args) = command_spec(Some("printf hello"), "/bin/sh").unwrap();
        assert_eq!(program, "/bin/sh");
        assert_eq!(args, vec!["-c".to_string(), "printf hello".to_string()]);
    }

    #[test]
    fn reverse_host_command_spec_preserves_quotes_and_redirects() {
        let command = r#"echo "a b" > hello.txt"#;
        let (_program, args) = command_spec(Some(command), "/bin/sh").unwrap();
        assert_eq!(args[1], command);
    }

    #[test]
    fn reverse_host_options_gate_channel_kinds() {
        let options = ReverseHostOptions {
            capabilities: vec!["shell".into(), "fs".into()],
            ..ReverseHostOptions::default()
        };
        assert!(options.allows_kind(wsh_core::messages::ChannelKind::Pty));
        assert!(options.allows_kind(wsh_core::messages::ChannelKind::Exec));
        assert!(options.allows_kind(wsh_core::messages::ChannelKind::File));
        assert!(!ReverseHostOptions {
            capabilities: vec!["fs".into()],
            ..ReverseHostOptions::default()
        }
        .allows_kind(wsh_core::messages::ChannelKind::Exec));
    }

    #[test]
    fn same_reverse_request_requires_matching_requester_and_target() {
        let left = ReverseConnectPayload {
            target_fingerprint: "fp".into(),
            username: "alice".into(),
        };
        let right = ReverseConnectPayload {
            target_fingerprint: "fp".into(),
            username: "alice".into(),
        };
        let wrong_user = ReverseConnectPayload {
            target_fingerprint: "fp".into(),
            username: "bob".into(),
        };

        assert!(same_reverse_request(&left, &right));
        assert!(!same_reverse_request(&left, &wrong_user));
    }

    #[test]
    fn append_replay_keeps_only_the_tail_of_large_output() {
        let replay = Arc::new(StdMutex::new(Vec::new()));
        append_replay(&replay, &vec![b'a'; super::DEFAULT_PTY_REPLAY_LIMIT]);
        append_replay(&replay, b"tail");

        let stored = replay.lock().unwrap().clone();
        assert_eq!(stored.len(), super::DEFAULT_PTY_REPLAY_LIMIT);
        assert_eq!(&stored[stored.len() - 4..], b"tail");
    }

    #[tokio::test]
    async fn reverse_host_pty_session_matches_exec_reconnects_by_command() {
        let pty = Arc::new(LocalPty::spawn(Some("sleep 10"), 80, 24, None).unwrap());
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<RuntimeEvent>();
        let session = ReverseHostPtySession::spawn(
            7,
            ChannelKind::Exec,
            Some("printf hello".into()),
            80,
            24,
            pty.clone(),
            Some(event_tx),
        );

        assert!(session.matches_reattach(&ChannelKind::Exec, Some("printf hello")));
        assert!(!session.matches_reattach(&ChannelKind::Exec, Some("pwd")));
        assert!(!session.matches_reattach(&ChannelKind::Pty, None));

        let _ = pty.kill_blocking();
        session.output_task.abort();
        session.wait_task.abort();
        while event_rx.try_recv().is_ok() {}
    }

    #[test]
    fn upload_header_parser_extracts_path_and_size() {
        let path = "/tmp/demo.txt";
        let total_size = 42_u64;
        let mut header = Vec::new();
        header.extend_from_slice(&(path.len() as u32).to_be_bytes());
        header.extend_from_slice(path.as_bytes());
        header.extend_from_slice(&total_size.to_be_bytes());

        let parsed = try_parse_upload_header(&header).unwrap().unwrap();
        assert_eq!(parsed.0, std::path::PathBuf::from(path));
        assert_eq!(parsed.1, total_size);
        assert_eq!(parsed.2, header.len());
    }

    #[test]
    fn download_header_parser_extracts_path() {
        let path = "/tmp/demo.txt";
        let mut header = Vec::new();
        header.extend_from_slice(&(path.len() as u32).to_be_bytes());
        header.extend_from_slice(path.as_bytes());

        let parsed = try_parse_download_header(&header).unwrap().unwrap();
        assert_eq!(parsed.0, std::path::PathBuf::from(path));
        assert_eq!(parsed.1, header.len());
    }

    #[test]
    fn download_session_returns_size_prefixed_payload() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("hello.txt");
        std::fs::write(&path, b"hello").unwrap();
        let mut session =
            ReverseHostFileSession::from_command(Some(&format!("download:{}", path.display())))
                .unwrap();
        let mut header = Vec::new();
        let path_str = path.to_string_lossy();
        header.extend_from_slice(&(path_str.len() as u32).to_be_bytes());
        header.extend_from_slice(path_str.as_bytes());

        let responses = session.handle_data(&header).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(
            u64::from_be_bytes(responses[0][..8].try_into().unwrap()),
            5
        );
        assert_eq!(&responses[0][8..], b"hello");
        assert!(session.should_close());
    }

    #[tokio::test]
    async fn local_mcp_bridge_lists_and_executes_tools() {
        let bridge = LocalMcpBridge;
        let tools = bridge.list_tools();
        assert!(tools.iter().any(|tool| tool.name == "shell.exec"));

        let result = bridge
            .call(&wsh_core::messages::McpCallPayload {
                tool: "shell.exec".to_string(),
                arguments: json!({ "command": "printf hello" }),
            })
            .await;
        assert_eq!(result.result["stdout"], "hello");
    }

    #[test]
    fn dns_filter_respects_record_type() {
        let addresses = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        assert_eq!(filter_dns_addresses(addresses.clone().into_iter(), "A"), vec!["127.0.0.1"]);
        assert_eq!(filter_dns_addresses(addresses.into_iter(), "AAAA"), vec!["::1"]);
    }
}
