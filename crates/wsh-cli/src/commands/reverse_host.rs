//! Reverse-host runtime for `wsh reverse`.
//!
//! Accepts relay-forwarded OPEN/SESSION_DATA/RESIZE/SIGNAL/CLOSE messages and
//! serves them from a local PTY so another client can remote into this machine
//! through a relay.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};
use wsh_client::WshClient;
use wsh_core::messages::*;
use wsh_core::peer_record::{build_peer_record_transcript, PeerRecord};

pub use super::reverse_gateway::RelayGateway;

/// What an operator is told when this host has a gateway but no `--relay-gateway-allow` rule reaches it (wsh #296).
const NO_RULE_FOR_OPERATOR: &str = "this reverse host has no gateway rule for this operator";
use super::reverse_gateway::{GatewayLink, OperatorGateway};

const DEFAULT_PTY_REPLAY_LIMIT: usize = 256 * 1024;
/// How long an exited child's output reader may take to reach the pty's EOF before Exit goes out.
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(1);

/// The host's own identity key (the one it logs in to the relay with): it signs the
/// `ReverseChallenge` that makes an operator prove who it is (wsh #117).
#[derive(Clone)]
pub struct IdentityKey(pub Arc<SigningKey>);

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityKey(<redacted>)")
    }
}

impl PartialEq for IdentityKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.verifying_key() == other.0.verifying_key()
    }
}
impl Eq for IdentityKey {}

/// The relay connection as one runtime uses it.
///
/// With `to` set (a peer that serves several operators, wsh #93) every message that crosses a bridge
/// is written as a `RelayForward` addressed to that operator, and the relay delivers the inner
/// message stamped with this peer's key; the handshake messages (`ReverseAccept`, `ReverseReject`)
/// go as they are, the relay pairs them with the request they answer. Without it, a message is sent
/// as it always was.
#[derive(Clone)]
struct PeerLink {
    client: Arc<WshClient>,
    to: Option<String>,
}

impl PeerLink {
    fn new(client: Arc<WshClient>) -> Self {
        Self { client, to: None }
    }

    fn addressed(client: Arc<WshClient>, operator: String) -> Self {
        Self {
            client,
            to: Some(operator),
        }
    }

    /// Does this link serve one of several operators?
    fn is_multi(&self) -> bool {
        self.to.is_some()
    }

    async fn send_fire_and_forget(&self, envelope: Envelope) -> wsh_core::WshResult<()> {
        let crosses_bridge = (is_relay_forwardable(envelope.msg_type)
            || is_relay_gateway_forwardable(envelope.msg_type))
            && !matches!(
                envelope.msg_type,
                MsgType::ReverseAccept | MsgType::ReverseReject
            );
        match &self.to {
            Some(operator) if crosses_bridge => {
                let inner = wsh_core::cbor_encode(&envelope)?;
                self.client
                    .send_fire_and_forget(Envelope {
                        msg_type: MsgType::RelayForward,
                        payload: Payload::RelayForward(RelayForwardPayload {
                            // the relay stamps the real sender; this is never read
                            from_fingerprint: String::new(),
                            inner,
                            to_fingerprint: Some(operator.clone()),
                        }),
                    })
                    .await
            }
            _ => self.client.send_fire_and_forget(envelope).await,
        }
    }

    async fn has_feature(&self, feature: &str) -> bool {
        self.client.has_feature(feature).await
    }

    async fn trust_relay_peer(&self, fingerprint: String) {
        self.client.trust_relay_peer(fingerprint).await;
    }

    async fn untrust_relay_peer(&self, fingerprint: &str) {
        self.client.untrust_relay_peer(fingerprint).await;
    }

    fn begin_sealing_as_responder(
        &self,
        session_id: String,
        must: bool,
        responder: wsh_client::E2eResponder,
    ) {
        self.client
            .begin_sealing_as_responder(session_id, must, responder);
    }

    /// The seal is one per connection: a link that serves one of several operators never has one.
    fn end_sealing(&self) {
        if !self.is_multi() {
            self.client.end_sealing();
        }
    }

    async fn bridge_sealed_event(&self) {
        self.client.bridge_sealed_event().await;
    }

    async fn bridge_failed(&self) {
        self.client.bridge_failed().await;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseHostOptions {
    /// How many operators this host serves at once (`--max-operators`). Above 1 it states
    /// `relay-multi-operator` to a relay that advertises it (wsh #93); a relay that does not
    /// is served one operator at a time, as before. Default 1.
    pub max_operators: usize,
    pub capabilities: Vec<String>,
    pub peer_type: String,
    pub shell_backend: String,
    pub supports_attach: bool,
    pub supports_replay: bool,
    pub supports_echo: bool,
    pub supports_term_sync: bool,
    /// Ask every operator that offers it for proof of its identity, and refuse one that cannot
    /// give it (`--require-operator-proof`). Needs `identity`.
    pub require_operator_proof: bool,
    /// Fingerprints (or prefixes of at least 8 hex digits) of the operators this host serves;
    /// empty = anyone the relay lets through. Checked against the PROVEN key when the operator
    /// proved one, otherwise against what the relay stamped -- which is the relay's word.
    pub allowed_operators: Vec<String>,
    /// This host's identity key. Without it no challenge can be issued.
    pub identity: Option<IdentityKey>,
    /// Offer X25519+ML-KEM-768 to an operator that asks for it (it may still seal with X25519 alone).
    pub hybrid: bool,
    /// The gateway for an operator behind the relay (wsh #289): `None` (the default) serves none, and the host does not say
    /// `relay-gateway`. Set by `--relay-gateway-allow`; needs the `gateway` capability.
    pub gateway: Option<RelayGateway>,
    /// State `gateway-lossless-close` to the operator (wsh #286). `--no-lossless-close` sets it false: neither the statement nor the
    /// acknowledgement is made, and the operator's connections behave as before the feature. Default true.
    pub lossless_close: bool,
}

impl Default for ReverseHostOptions {
    fn default() -> Self {
        Self {
            max_operators: 1,
            capabilities: vec!["shell".to_string(), "exec".to_string()],
            peer_type: "host".to_string(),
            shell_backend: "pty".to_string(),
            supports_attach: false,
            supports_replay: false,
            supports_echo: false,
            supports_term_sync: false,
            require_operator_proof: false,
            allowed_operators: Vec::new(),
            identity: None,
            hybrid: true,
            gateway: None,
            lossless_close: true,
        }
    }
}

impl ReverseHostOptions {
    /// May this operator (`fingerprint`, proven or as stamped by the relay) be served?
    pub fn allows_operator(&self, fingerprint: &str) -> bool {
        self.allowed_operators.is_empty()
            || self
                .allowed_operators
                .iter()
                .any(|a| a.len() >= 8 && fingerprint.starts_with(a.as_str()))
    }

    /// Build a self-signed `ReverseRegister` payload (wsh #17: signed peer
    /// records). `signing_key` is the caller's own identity key -- the
    /// server verifies the resulting `record_signature` against the raw
    /// `public_key` fingerprint of *this same connection's* authenticated
    /// identity, so a mismatched or missing signature is rejected outright
    /// (`crates/wsh-server/src/server.rs`'s `ReverseRegister` handler).
    ///
    /// `seq` is the signing peer's own monotonic counter -- current-time-
    /// millis, matching `@johnhenry/wsh`'s `connectReverse()` (`src/
    /// client.mjs`) and `wsh_core::peer_record`'s doc comment. The transcript
    /// construction (`build_peer_record_transcript`) is crypto-library-
    /// agnostic (just produces the bytes to sign), so signing directly with
    /// this crate's `ed25519_dalek` key -- rather than going through
    /// `wsh_core::peer_record::sign_peer_record`, which expects a `ring`
    /// key pair -- still produces a byte-identical, correctly-verifiable
    /// signature.
    pub fn reverse_register_payload(
        &self,
        username: String,
        public_key: Vec<u8>,
        signing_key: &SigningKey,
    ) -> ReverseRegisterPayload {
        let seq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        // A host that can issue a challenge says so, so an operator knows it may state
        // `operator-proof` (a released host cannot decode `ReverseConnect.features`).
        let mut capabilities = self.capabilities.clone();
        if self.identity.is_some() {
            capabilities.push(wsh_core::operator_proof::OPERATOR_PROOF_FEATURE.to_string());
        }
        let record = PeerRecord {
            username: username.clone(),
            peer_type: self.peer_type.clone(),
            shell_backend: self.shell_backend.clone(),
            capabilities: capabilities.clone(),
            supports_attach: self.supports_attach,
            supports_replay: self.supports_replay,
            supports_echo: self.supports_echo,
            supports_term_sync: self.supports_term_sync,
            seq,
        };
        let transcript = build_peer_record_transcript(&record);
        let record_signature = signing_key.sign(&transcript).to_bytes().to_vec();

        ReverseRegisterPayload {
            username,
            capabilities,
            peer_type: self.peer_type.clone(),
            shell_backend: self.shell_backend.clone(),
            supports_attach: self.supports_attach,
            supports_replay: self.supports_replay,
            supports_echo: self.supports_echo,
            supports_term_sync: self.supports_term_sync,
            public_key,
            seq,
            record_signature,
        }
    }

    /// `sealable`: this bridge can be sealed (the operator proved its key), so the accept says so
    /// (`e2e`, `e2e-sign`, `e2e-sealed`): an operator that asks for a sealed bridge needs it.
    /// `multi`: this host serves several operators on this relay, and says so
    /// (`relay-multi-operator`): the relay then addresses each operator's messages to it and tells
    /// it with `ReverseClose` when one leaves.
    fn reverse_accept_payload(
        &self,
        request: ReverseConnectPayload,
        sealable: bool,
        multi: bool,
        gateway: bool,
    ) -> ReverseAcceptPayload {
        let mut features = Vec::new();
        // `gateway`: the owner turned the gateway on AND the relay carries it (wsh #289): this bridge's operator may use it.
        // `relay-gateway` implies `gateway-credit`; the two others say what a client would read from a ServerHello.
        if gateway {
            features.extend([
                wsh_core::RELAY_GATEWAY_FEATURE.to_string(),
                "gateway".to_string(),
                wsh_core::gateway_credit::GATEWAY_CREDIT_FEATURE.to_string(),
            ]);
            // The reason `released` on a GatewayClose (wsh #286), understood by this host's gateway session; `--no-lossless-close` does not state it.
            if self.lossless_close {
                features.push(wsh_core::gateway_credit::GATEWAY_LOSSLESS_FEATURE.to_string());
            }
            // The acknowledgement (wsh #286): only when the operator's own `gateway-lossless-close` reached this host (a relay may have dropped it),
            // so an operator relies on the feature behind a relay only when this is here. `--no-lossless-close` states neither.
            if self.lossless_close
                && request.features.as_ref().is_some_and(|f| {
                    f.iter()
                        .any(|x| x == wsh_core::gateway_credit::GATEWAY_LOSSLESS_FEATURE)
                })
            {
                features.push(wsh_core::gateway_credit::GATEWAY_LOSSLESS_ACK_FEATURE.to_string());
            }
        }
        if sealable {
            features.extend([
                wsh_core::e2e_exchange::E2E_FEATURE.to_string(),
                wsh_core::e2e_exchange::E2E_SIGN_FEATURE.to_string(),
                wsh_core::operator_proof::E2E_SEALED_FEATURE.to_string(),
            ]);
        }
        if multi {
            features.push(wsh_core::RELAY_MULTI_OPERATOR_FEATURE.to_string());
        }
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
            // absent, not empty, when there is nothing to say: a host without either feature
            // sends the accept it always sent
            features: (!features.is_empty()).then_some(features),
        }
    }

    pub fn has_capability(&self, capability: &str) -> bool {
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
    // A host that may serve several operators does so only on a relay that says it can
    // (`relay-multi-operator` in its ServerHello); on any other it serves one, as it always did.
    if service.runtime.options.max_operators > 1
        && client
            .has_feature(wsh_core::RELAY_MULTI_OPERATOR_FEATURE)
            .await
    {
        info!(
            max_operators = service.runtime.options.max_operators,
            "serving several operators on this relay"
        );
        service.enter_multi(client, status_tx);
    } else {
        service.attach_client(client, status_tx).await;
    }
    let mut reverse_channel_closed = false;
    let mut relay_channel_closed = false;

    loop {
        let proof_deadline = service.proof_deadline();
        tokio::select! {
            envelope = reverse_connect_rx.recv(), if !reverse_channel_closed => {
                match envelope {
                    Some(envelope) => service.on_reverse_envelope(envelope).await?,
                    None => reverse_channel_closed = true,
                }
            }
            envelope = relay_message_rx.recv(), if !relay_channel_closed => {
                match envelope {
                    Some(envelope) => service.on_relay_envelope(envelope).await?,
                    None => relay_channel_closed = true,
                }
            }
            _ = async {
                match proof_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                service.expire_proofs().await?;
            }
            Some(event) = service.event_rx.recv() => {
                service.runtime.handle_runtime_event(event).await?;
            }
            Some((operator, event)) = service.operator_event_rx.recv() => {
                service.on_operator_event(operator, event).await;
            }
            // A sealed frame that does not open (forged, tampered with, replayed): the relay is
            // not honest, and the bridge is over.
            _ = service.runtime.bridge_sealed_event() => {
                service.runtime.on_sealed();
            }
            _ = service.runtime.bridge_failed() => {
                warn!("a sealed frame did not open: ending the bridge");
                service.runtime.end_bridge().await?;
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

/// One operator of a host that serves several (wsh #93): its own runtime, so its channels,
/// processes and files are its own, and the task that tags the runtime's events with the operator.
struct OperatorRuntime {
    runtime: ReverseHostRuntime,
    forwarder: tokio::task::JoinHandle<()>,
}

/// The relay connection of a host that serves several operators.
struct MultiOperator {
    client: Arc<WshClient>,
    status_tx: Option<mpsc::Sender<ReverseHostStatusEvent>>,
    /// By the operator's fingerprint, as the relay stamped it.
    operators: HashMap<String, OperatorRuntime>,
    reported_sessions: usize,
}

pub struct ReverseHostService {
    runtime: ReverseHostRuntime,
    event_tx: mpsc::UnboundedSender<RuntimeEvent>,
    event_rx: mpsc::UnboundedReceiver<RuntimeEvent>,
    /// Set while this host serves several operators on the relay it is connected to; the
    /// single `runtime` is then not used.
    multi: Option<MultiOperator>,
    operator_event_tx: mpsc::UnboundedSender<(String, RuntimeEvent)>,
    operator_event_rx: mpsc::UnboundedReceiver<(String, RuntimeEvent)>,
}

impl ReverseHostService {
    pub fn new(options: ReverseHostOptions) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (operator_event_tx, operator_event_rx) = mpsc::unbounded_channel();
        Self {
            runtime: ReverseHostRuntime::new(options),
            event_tx,
            event_rx,
            multi: None,
            operator_event_tx,
            operator_event_rx,
        }
    }

    async fn attach_client(
        &mut self,
        client: Arc<WshClient>,
        status_tx: Option<mpsc::Sender<ReverseHostStatusEvent>>,
    ) {
        self.runtime
            .attach_client(PeerLink::new(client), status_tx, self.event_tx.clone())
            .await;
    }

    fn enter_multi(
        &mut self,
        client: Arc<WshClient>,
        status_tx: Option<mpsc::Sender<ReverseHostStatusEvent>>,
    ) {
        // Each relayed message then arrives with the operator that wrote it.
        client.tag_relay_origin(true);
        self.multi = Some(MultiOperator {
            client,
            status_tx,
            operators: HashMap::new(),
            reported_sessions: 0,
        });
    }

    async fn detach_client(&mut self) {
        if let Some(mut multi) = self.multi.take() {
            for (_, mut op) in multi.operators.drain() {
                op.runtime.shutdown().await;
                op.forwarder.abort();
            }
            return;
        }
        self.runtime.detach_client().await;
    }

    pub async fn shutdown(&mut self) {
        if let Some(multi) = self.multi.as_mut() {
            for (_, mut op) in multi.operators.drain() {
                op.runtime.shutdown().await;
                op.forwarder.abort();
            }
        }
        self.runtime.shutdown().await;
    }

    /// A `ReverseConnect`, `ReverseProof` (or, with several operators, `ReverseClose`) from the relay.
    async fn on_reverse_envelope(&mut self, envelope: Envelope) -> Result<()> {
        if self.multi.is_none() {
            return match envelope.payload {
                Payload::ReverseProof(proof) => self.runtime.handle_reverse_proof(proof).await,
                _ => self.runtime.handle_reverse_connect(envelope).await,
            };
        }
        match &envelope.payload {
            Payload::ReverseConnect(request) => {
                let operator = request.from_fingerprint.clone();
                self.operator_for(&operator, Some(request)).await?;
                if let Some(op) = self.operator_mut(&operator) {
                    if let Err(err) = op.runtime.handle_reverse_connect(envelope).await {
                        warn!(operator = %short(&operator), "serving a reverse connect failed: {err:#}");
                    }
                }
            }
            Payload::ReverseProof(proof) => {
                let operator = proof.from_fingerprint.clone().unwrap_or_default();
                if let Payload::ReverseProof(proof) = envelope.payload {
                    if let Some(op) = self.operator_mut(&operator) {
                        if let Err(err) = op.runtime.handle_reverse_proof(proof).await {
                            warn!(operator = %short(&operator), "an operator proof failed: {err:#}");
                        }
                    }
                }
            }
            // That operator left: its processes go with it; the others carry on.
            Payload::ReverseClose(close) => {
                let operator = close.target_fingerprint.clone();
                debug!(operator = %short(&operator), "relay: an operator left");
                if let Some(multi) = self.multi.as_mut() {
                    // nothing from it is heard any more, whether or not it had a runtime
                    multi.client.untrust_relay_peer(&operator).await;
                    if let Some(mut op) = multi.operators.remove(&operator) {
                        info!(operator = %short(&operator), "operator left: ending its bridge");
                        let _ = op.runtime.end_bridge().await;
                        op.runtime.shutdown().await;
                        op.forwarder.abort();
                    }
                }
            }
            _ => {}
        }
        self.settle().await;
        Ok(())
    }

    /// A relayed message (tagged with the operator that wrote it) with several operators; the bare
    /// message, as always, otherwise.
    async fn on_relay_envelope(&mut self, envelope: Envelope) -> Result<()> {
        if self.multi.is_none() {
            return self.runtime.handle_relay_message(envelope).await;
        }
        let Payload::RelayForward(forward) = envelope.payload else {
            return Ok(());
        };
        let Some(op) = self.operator_mut(&forward.from_fingerprint) else {
            debug!(
                from = %short(&forward.from_fingerprint),
                "dropping a message from an operator this host is not serving"
            );
            return Ok(());
        };
        match wsh_core::decode_envelope(&forward.inner) {
            Ok(inner) => {
                if let Err(err) = op.runtime.handle_relay_message(inner).await {
                    warn!(operator = %short(&forward.from_fingerprint), "serving an operator's message failed: {err:#}");
                }
            }
            Err(err) => warn!("dropping a relayed message that does not decode: {err}"),
        }
        self.settle().await;
        Ok(())
    }

    async fn on_operator_event(&mut self, operator: String, event: RuntimeEvent) {
        if let Some(op) = self.operator_mut(&operator) {
            if let Err(err) = op.runtime.handle_runtime_event(event).await {
                warn!(operator = %short(&operator), "serving a session event failed: {err:#}");
            }
        }
        self.settle().await;
    }

    fn operator_mut(&mut self, operator: &str) -> Option<&mut OperatorRuntime> {
        self.multi.as_mut()?.operators.get_mut(operator)
    }

    /// The runtime for `operator`, made when it is new. A new operator over the host's cap is
    /// refused with the reason the relay gives at its own cap.
    async fn operator_for(
        &mut self,
        operator: &str,
        request: Option<&ReverseConnectPayload>,
    ) -> Result<()> {
        let max = self.runtime.options.max_operators;
        let Some(multi) = self.multi.as_mut() else {
            return Ok(());
        };
        if multi.operators.contains_key(operator) {
            return Ok(());
        }
        if multi.operators.len() >= max {
            if let Some(request) = request {
                let link = PeerLink::new(multi.client.clone());
                link.send_fire_and_forget(Envelope {
                    msg_type: MsgType::ReverseReject,
                    payload: Payload::ReverseReject(ReverseRejectPayload {
                        target_fingerprint: request.target_fingerprint.clone(),
                        username: request.username.clone(),
                        reason: format!("busy: this host already serves its maximum of {max} operators (retry when one leaves)"),
                    }),
                })
                .await
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            }
            return Ok(());
        }
        let mut runtime = ReverseHostRuntime::new(self.runtime.options.clone());
        // This operator's events reach the run loop tagged with it.
        let (tx, mut rx) = mpsc::unbounded_channel::<RuntimeEvent>();
        let tagged = self.operator_event_tx.clone();
        let name = operator.to_string();
        let forwarder = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if tagged.send((name.clone(), event)).is_err() {
                    break;
                }
            }
        });
        runtime
            .attach_client(
                PeerLink::addressed(multi.client.clone(), operator.to_string()),
                multi.status_tx.clone(),
                tx,
            )
            .await;
        multi
            .operators
            .insert(operator.to_string(), OperatorRuntime { runtime, forwarder });
        Ok(())
    }

    /// After something happened to the operators: forget those that have nothing (a refused
    /// request leaves an empty runtime) and report the sessions of all of them together.
    async fn settle(&mut self) {
        let Some(multi) = self.multi.as_mut() else {
            return;
        };
        let idle: Vec<String> = multi
            .operators
            .iter()
            .filter(|(_, op)| op.runtime.is_idle())
            .map(|(fp, _)| fp.clone())
            .collect();
        for fp in idle {
            if let Some(op) = multi.operators.remove(&fp) {
                op.forwarder.abort();
            }
        }
        let sessions: usize = multi
            .operators
            .values()
            .map(|op| op.runtime.sessions.len())
            .sum();
        if sessions != multi.reported_sessions {
            multi.reported_sessions = sessions;
            if let Some(tx) = &multi.status_tx {
                let _ = tx
                    .send(ReverseHostStatusEvent::SessionCountChanged {
                        active_sessions: sessions,
                    })
                    .await;
            }
        }
    }

    /// When the earliest pending challenge or sealing deadline of any operator falls due.
    fn proof_deadline(&self) -> Option<tokio::time::Instant> {
        let single = self.runtime.proof_deadline();
        let many = self
            .multi
            .iter()
            .flat_map(|m| m.operators.values())
            .filter_map(|op| op.runtime.proof_deadline())
            .min();
        match (single, many) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    async fn expire_proofs(&mut self) -> Result<()> {
        self.runtime.expire_proof().await?;
        if let Some(multi) = self.multi.as_mut() {
            for (fp, op) in multi.operators.iter_mut() {
                if let Err(err) = op.runtime.expire_proof().await {
                    warn!(operator = %short(fp), "expiring a challenge failed: {err:#}");
                }
            }
        }
        self.settle().await;
        Ok(())
    }
}

fn short(fingerprint: &str) -> &str {
    &fingerprint[..fingerprint.len().min(12)]
}

/// How long an operator has to answer a challenge.
const PROOF_TIMEOUT: Duration = Duration::from_secs(5);

struct PendingProof {
    request: ReverseConnectPayload,
    issued: wsh_core::operator_proof::IssuedChallenge,
    deadline: tokio::time::Instant,
}

/// A bridge with a proven operator that may be sealed (wsh #117, #145): this host answers the
/// operator's signed `KeyExchange` for the challenge's session id.
struct HostSealing {
    session_id: String,
    /// Set with `--require-operator-proof`: the bridge is dropped if no key exchange arrives by then.
    give_up: Option<tokio::time::Instant>,
    sealed: bool,
}

struct ReverseHostRuntime {
    /// The bridge being sealed, or sealed, with the operator served now.
    sealing: Option<HostSealing>,
    client: Option<PeerLink>,
    event_tx: Option<mpsc::UnboundedSender<RuntimeEvent>>,
    options: ReverseHostOptions,
    status_tx: Option<mpsc::Sender<ReverseHostStatusEvent>>,
    active_request: Option<ReverseConnectPayload>,
    /// This runtime accepted its operator and has not ended the bridge (it outlives the operator's
    /// sessions: `active_request` is cleared with the last one). Only a host serving several
    /// operators reads it.
    bridged: bool,
    /// A request whose operator has been challenged and has not answered yet (wsh #117).
    pending_proof: Option<PendingProof>,
    sessions: HashMap<u32, ReverseHostSession>,
    /// This operator's gateway (wsh #289): present only when the owner turned it on and the relay carries it.
    gateway: Option<OperatorGateway>,
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
            bridged: false,
            sealing: None,
            pending_proof: None,
            sessions: HashMap::new(),
            gateway: None,
            mcp: LocalMcpBridge::default(),
            next_channel_id: 1,
        }
    }

    async fn attach_client(
        &mut self,
        client: PeerLink,
        status_tx: Option<mpsc::Sender<ReverseHostStatusEvent>>,
        event_tx: mpsc::UnboundedSender<RuntimeEvent>,
    ) {
        self.client = Some(client);
        self.event_tx = Some(event_tx.clone());
        self.status_tx = status_tx;
        self.emit_session_count().await;
    }

    async fn detach_client(&mut self) {
        self.sealing = None;
        if let Some(client) = &self.client {
            client.end_sealing();
        }
        self.client = None;
        self.event_tx = None;
        self.status_tx = None;
        for session in self.sessions.values_mut() {
            session.set_notifier(None);
        }
        // Dropping the gateway closes every connection and listener it opened.
        self.gateway = None;
    }

    fn client(&self) -> Result<PeerLink> {
        self.client
            .clone()
            .context("reverse host runtime is not currently bound to a relay client")
    }

    async fn handle_reverse_connect(&mut self, envelope: Envelope) -> Result<()> {
        let Payload::ReverseConnect(request) = envelope.payload else {
            return Ok(());
        };

        // Does this request offer proof, and will this host ask for it?
        let proof_offered = request.features.as_ref().is_some_and(|f| {
            f.iter()
                .any(|f| f == wsh_core::operator_proof::OPERATOR_PROOF_FEATURE)
        }) && self
            .client()?
            .has_feature(wsh_core::operator_proof::OPERATOR_PROOF_FEATURE)
            .await
            && self.options.identity.is_some();
        let needs_proof = self.options.require_operator_proof || proof_offered;

        let busy = self.active_request.is_some() || !self.sessions.is_empty();
        let same_operator = self.active_request.as_ref().is_some_and(|existing| {
            same_reverse_request(existing, &request)
                && existing.from_fingerprint == request.from_fingerprint
        });
        // The same operator coming back reattaches without a new proof only when no proof is in
        // play; otherwise it proves itself again.
        if self.pending_proof.is_some() || (busy && !(same_operator && needs_proof)) {
            if same_operator && !needs_proof && self.pending_proof.is_none() {
                info!(
                    requester = %request.username,
                    target = %request.target_fingerprint,
                    "reattaching reverse host connection"
                );
                self.active_request = Some(request.clone());
                let client = self.client()?;
                client
                    .trust_relay_peer(request.from_fingerprint.clone())
                    .await;
                let gateway = self.prepare_gateway(false).await?;
                client
                    .send_fire_and_forget(Envelope {
                        msg_type: MsgType::ReverseAccept,
                        payload: Payload::ReverseAccept(self.options.reverse_accept_payload(
                            request,
                            false,
                            client.is_multi(),
                            gateway,
                        )),
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

        // Who is this operator? The relay says (`from_fingerprint`); with proof the operator says
        // so itself, and the host takes the identity from the proof, not from the relay.
        let client = self.client()?;
        let identity = self.options.identity.clone();
        if self.options.require_operator_proof && !proof_offered {
            return self.reject(&request, "operator proof required").await;
        }
        if let (true, Some(identity)) = (proof_offered, identity) {
            let (challenge, issued) = wsh_core::operator_proof::create_challenge(
                &identity.0,
                &request.from_fingerprint,
                &request.from_fingerprint,
            );
            self.pending_proof = Some(PendingProof {
                request,
                issued,
                deadline: tokio::time::Instant::now() + PROOF_TIMEOUT,
            });
            client
                .send_fire_and_forget(Envelope {
                    msg_type: MsgType::ReverseChallenge,
                    payload: Payload::ReverseChallenge(challenge),
                })
                .await
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            return Ok(());
        }
        let from = request.from_fingerprint.clone();
        if !self.options.allows_operator(&from) {
            return self.reject(&request, "operator not allowed").await;
        }
        self.accept_request(request, None).await
    }

    async fn reject(&mut self, request: &ReverseConnectPayload, reason: &str) -> Result<()> {
        info!(requester = %request.username, reason, "refusing reverse host connection");
        self.client()?
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::ReverseReject,
                payload: Payload::ReverseReject(ReverseRejectPayload {
                    target_fingerprint: request.target_fingerprint.clone(),
                    username: request.username.clone(),
                    reason: reason.to_string(),
                }),
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))
    }

    async fn accept_request(
        &mut self,
        request: ReverseConnectPayload,
        proven: Option<(wsh_core::operator_proof::ProvenOperator, String)>,
    ) -> Result<()> {
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
        self.bridged = true;
        let client = self.client()?;
        client
            .trust_relay_peer(request.from_fingerprint.clone())
            .await;
        // A proven operator may seal the bridge: its signed `KeyExchange` for the challenge's
        // session id is answered here. With `--require-operator-proof` nothing else is heard,
        // or sent, until it has (the gate is on before the accept leaves).
        self.sealing = None;
        client.end_sealing();
        // (A host that serves several operators cannot: the seal is one per connection.)
        let sealable = match (&proven, &self.options.identity) {
            (Some((operator, session_id)), Some(identity)) if !client.is_multi() => {
                let must = self.options.require_operator_proof;
                let responder = wsh_client::E2eResponder::new(
                    Some((*identity.0).clone()),
                    self.options.hybrid,
                    Some(identity.0.verifying_key().to_bytes()),
                    Some(wsh_client::InitiatorAuth {
                        public_key: operator.public_key,
                        require: true,
                    }),
                );
                client.begin_sealing_as_responder(session_id.clone(), must, responder);
                self.sealing = Some(HostSealing {
                    session_id: session_id.clone(),
                    give_up: must.then(|| tokio::time::Instant::now() + PROOF_TIMEOUT * 2),
                    sealed: false,
                });
                true
            }
            _ => false,
        };
        // A new operator gets a gateway of its own (and the one of the last is gone with its connections).
        let gateway = self.prepare_gateway(true).await?;
        client
            .send_fire_and_forget(Envelope {
                msg_type: MsgType::ReverseAccept,
                payload: Payload::ReverseAccept(self.options.reverse_accept_payload(
                    request,
                    sealable,
                    client.is_multi(),
                    gateway,
                )),
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        Ok(())
    }

    /// Is the gateway on for the bridge being accepted (wsh #289)? Only when the owner turned it on (`--relay-gateway-allow`) AND the
    /// relay carries it (it lists `relay-gateway`): any other relay would answer the requests itself. `fresh`: a new operator, so a
    /// new gateway (and none of the last operator's connections); otherwise the one this bridge already has is kept.
    async fn prepare_gateway(&mut self, fresh: bool) -> Result<bool> {
        let Some(options) = self.options.gateway.clone() else {
            return Ok(false);
        };
        let client = self.client()?;
        if !client.has_feature(wsh_core::RELAY_GATEWAY_FEATURE).await {
            self.gateway = None;
            return Ok(false);
        }
        if fresh || self.gateway.is_none() {
            // The operator's own statement of `gateway-lossless-close` (wsh #286), as the relay passed it on in ReverseConnect.features.
            let operator_lossless = self.options.lossless_close
                && self
                    .active_request
                    .as_ref()
                    .and_then(|r| r.features.as_ref())
                    .is_some_and(|f| {
                        f.iter()
                            .any(|x| x == wsh_core::gateway_credit::GATEWAY_LOSSLESS_FEATURE)
                    });
            // Per operator (wsh #296): the rules scoped to this operator and the unscoped ones. An operator no rule reaches gets none,
            // and its requests are refused with a sentence that says so. The host still states `relay-gateway` (it is a statement about
            // the host, which the relay keeps per peer connection: a statement that differed per operator would switch the relay's
            // carrying off for the operators that have a gateway).
            let from = self
                .active_request
                .as_ref()
                .map(|r| r.from_fingerprint.clone())
                .unwrap_or_default();
            self.gateway = options
                .for_operator(&from)
                .map(|own| OperatorGateway::new(&own, client, operator_lossless));
        }
        Ok(true)
    }

    /// Resolves when the bridge being set up is sealed; never when none is.
    async fn bridge_sealed_event(&self) {
        match (
            &self.client,
            self.sealing.as_ref().is_some_and(|s| !s.sealed),
        ) {
            (Some(client), true) => client.bridge_sealed_event().await,
            _ => std::future::pending::<()>().await,
        }
    }

    fn on_sealed(&mut self) {
        if let Some(sealing) = self.sealing.as_mut() {
            sealing.sealed = true;
            sealing.give_up = None;
        }
        println!("Bridge sealed: the relay carries ciphertext only.");
    }

    /// Resolves when the sealed bridge failed; never when there is none.
    async fn bridge_failed(&self) {
        match (&self.client, self.sealing.is_some()) {
            (Some(client), true) => client.bridge_failed().await,
            _ => std::future::pending::<()>().await,
        }
    }

    /// Drop the bridge: its processes, its key, and the operator's claim on this host.
    async fn end_bridge(&mut self) -> Result<()> {
        self.sealing = None;
        if let Some(client) = &self.client {
            client.end_sealing();
            // Nothing this operator (or a relay speaking for it) sends is heard any more.
            if let Some(request) = &self.active_request {
                client.untrust_relay_peer(&request.from_fingerprint).await;
            }
        }
        let ids: Vec<u32> = self.sessions.keys().copied().collect();
        for id in ids {
            self.drop_session(id).await;
        }
        // This operator's connections and listeners go with it.
        self.gateway = None;
        self.active_request = None;
        self.bridged = false;
        Ok(())
    }

    /// The operator's answer to the challenge this host issued (wsh #117).
    async fn handle_reverse_proof(&mut self, proof: ReverseProofPayload) -> Result<()> {
        let Some(pending) = self.pending_proof.as_ref() else {
            return Ok(());
        };
        // A proof for some other challenge is ignored, not a reason to drop the real one.
        if proof.nonce != pending.issued.nonce {
            return Ok(());
        }
        let pending = self.pending_proof.take().expect("checked above");
        let request = pending.request;
        let Some(proven) = wsh_core::operator_proof::verify_proof(&proof, &pending.issued) else {
            return self
                .reject(&request, "operator proof does not verify")
                .await;
        };
        // The relay's claim and the operator's own must agree: a relay that rewrote
        // `from_fingerprint` is caught here.
        if proven.fingerprint != request.from_fingerprint {
            warn!(
                proof = %&proven.fingerprint[..12.min(proven.fingerprint.len())],
                relay = %&request.from_fingerprint[..12.min(request.from_fingerprint.len())],
                "operator proof is by another key than the relay asserted"
            );
            return self
                .reject(
                    &request,
                    "operator proof does not match the identity the relay asserted",
                )
                .await;
        }
        if proven.username != request.username {
            return self
                .reject(
                    &request,
                    "operator proof names another username than the relay asserted",
                )
                .await;
        }
        if !self.options.allows_operator(&proven.fingerprint) {
            return self.reject(&request, "operator not allowed").await;
        }
        let session_id = pending.issued.session_id.clone();
        self.accept_request(request, Some((proven, session_id)))
            .await
    }

    /// When the pending challenge stops waiting (for the run loop's timer).
    fn proof_deadline(&self) -> Option<tokio::time::Instant> {
        let proof = self.pending_proof.as_ref().map(|p| p.deadline);
        let seal = self.sealing.as_ref().and_then(|s| s.give_up);
        match (proof, seal) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    async fn expire_proof(&mut self) -> Result<()> {
        let now = tokio::time::Instant::now();
        if let Some(p) = self.pending_proof.as_ref() {
            if p.deadline <= now {
                let p = self.pending_proof.take().expect("checked above");
                return self
                    .reject(&p.request, "operator did not answer the challenge")
                    .await;
            }
        }
        if self
            .sealing
            .as_ref()
            .and_then(|s| s.give_up)
            .is_some_and(|t| t <= now)
        {
            warn!("no key exchange in time: dropping the bridge that must be sealed");
            return self.end_bridge().await;
        }
        Ok(())
    }

    async fn handle_relay_message(&mut self, envelope: Envelope) -> Result<()> {
        match envelope.payload {
            Payload::Open(open) => self.handle_open(open).await,
            Payload::SessionData(data) => self.handle_session_data(data).await,
            Payload::Resize(resize) => self.handle_resize(resize).await,
            Payload::Signal(signal) => self.handle_signal(signal).await,
            Payload::Close(close) => self.handle_close(close).await,
            Payload::McpDiscover(_) => self.handle_mcp_discover().await,
            Payload::McpCall(call) => self.handle_mcp_call(call).await,
            Payload::OpenTcp(_)
            | Payload::OpenUdp(_)
            | Payload::ResolveDns(_)
            | Payload::ListenRequest(_)
            | Payload::ListenClose(_)
            | Payload::InboundAccept(_)
            | Payload::InboundReject(_)
            | Payload::GatewayData(_)
            | Payload::GatewayCredit(_)
            | Payload::GatewayClose(_) => self.handle_gateway_message(envelope).await,
            other => {
                debug!(
                    "ignoring unsupported reverse-host relay message: {:?}",
                    other
                );
                Ok(())
            }
        }
    }

    async fn handle_runtime_event(&mut self, event: RuntimeEvent) -> Result<()> {
        match event {
            RuntimeEvent::OutputReady { channel_id } => {
                self.flush_output(channel_id).await?;
            }
            RuntimeEvent::Exited { channel_id, code } => {
                if self.client.is_some() {
                    self.drain_output(channel_id).await?;
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
                    self.drain_output(channel_id).await?;
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

    /// Send what the session's output reader has queued, in order.
    async fn flush_output(&mut self, channel_id: u32) -> Result<()> {
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
        Ok(())
    }

    /// The child has exited, but the output reader runs on its own and may not have taken the
    /// last of its output out of the pty yet (a child that writes and exits at once, under load,
    /// lost that output when Exit and Close went out first and the session was dropped). Give
    /// the reader until the pty's EOF, bounded because a grandchild can keep the pty open, then
    /// send what it queued, so that Exit follows all the output.
    async fn drain_output(&mut self, channel_id: u32) -> Result<()> {
        if let Some(ReverseHostSession::Pty(session)) = self.sessions.get_mut(&channel_id) {
            let _ = timeout(OUTPUT_DRAIN_GRACE, &mut session.output_task).await;
        }
        self.flush_output(channel_id).await
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
                    .with_context(|| {
                        format!("failed to spawn local PTY for channel {channel_id}")
                    })?;
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
                self.sessions
                    .insert(channel_id, ReverseHostSession::Pty(session));

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
                    .send_open_fail(
                        "reverse host currently supports only pty, exec, and file channels",
                    )
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
                    // Reverse-host channels aren't tracked by the main
                    // server's session-management surface (no ACLs, no
                    // Attach/Resume support here), so there's no
                    // session_id/token to mint.
                    session_id: None,
                    token: None,
                    stderr_channel_id: None,
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
                let responses = session.handle_data(&data.data).with_context(|| {
                    format!("failed to handle file channel {}", data.channel_id)
                })?;

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
                call_id: call.call_id.clone(),
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

    /// A message of the gateway (wsh #289). Served only when this host's owner turned the gateway on and the relay carries it
    /// (`self.gateway` exists); otherwise a request is refused, so an operator that sent one anyway (it should not have) is told.
    async fn handle_gateway_message(&mut self, envelope: Envelope) -> Result<()> {
        if let Some(gateway) = &self.gateway {
            gateway.handle(envelope).await;
            return Ok(());
        }
        let fail = match &envelope.payload {
            Payload::OpenTcp(p) => Some(self.gateway_fail(p.gateway_id)),
            Payload::OpenUdp(p) => Some(self.gateway_fail(p.gateway_id)),
            Payload::ResolveDns(p) => Some(self.gateway_fail(p.gateway_id)),
            Payload::ListenRequest(p) => Some(Envelope {
                msg_type: MsgType::ListenFail,
                payload: Payload::ListenFail(ListenFailPayload {
                    listener_id: p.listener_id,
                    reason: if self.options.gateway.is_some() {
                        NO_RULE_FOR_OPERATOR.to_string()
                    } else {
                        "the gateway is not enabled on this reverse host".to_string()
                    },
                }),
            }),
            _ => None,
        };
        if let Some(fail) = fail {
            self.client()?
                .send_fire_and_forget(fail)
                .await
                .map_err(|err| anyhow::anyhow!("{err}"))?;
        }
        Ok(())
    }

    fn gateway_fail(&self, gateway_id: u32) -> Envelope {
        // The host has a gateway but none for this operator (wsh #296): a policy refusal, not a disabled gateway.
        if self.options.gateway.is_some() {
            return Envelope {
                msg_type: MsgType::GatewayFail,
                payload: Payload::GatewayFail(GatewayFailPayload {
                    gateway_id,
                    code: 4,
                    message: NO_RULE_FOR_OPERATOR.to_string(),
                }),
            };
        }
        Envelope {
            msg_type: MsgType::GatewayFail,
            payload: Payload::GatewayFail(GatewayFailPayload {
                gateway_id,
                // GATEWAY_DISABLED
                code: 5,
                message: "the gateway is not enabled on this reverse host".to_string(),
            }),
        }
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
        self.gateway = None;
    }

    async fn notify_status(&self, event: ReverseHostStatusEvent) {
        if let Some(status_tx) = &self.status_tx {
            let _ = status_tx.send(event).await;
        }
    }

    /// Nothing is bridged, pending or running here (a runtime made for a request that was refused).
    fn is_idle(&self) -> bool {
        !self.bridged
            && self.active_request.is_none()
            && self.pending_proof.is_none()
            && self.sessions.is_empty()
            && self
                .gateway
                .as_ref()
                .is_none_or(|g| g.open_connections() == 0)
    }

    async fn emit_session_count(&self) {
        // One of several operators: the service reports all of them together.
        if self.client.as_ref().is_some_and(|c| c.is_multi()) {
            return;
        }
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
                    session_id: None,
                    token: None,
                    stderr_channel_id: None,
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

    async fn replay_to_client(&self, client: &PeerLink, channel_id: u32) -> Result<()> {
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
        let wait_task =
            spawn_wait_task(channel_id, pty.clone(), notifier.clone(), exit_code.clone());
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
            Ok(result) => McpResultPayload {
                call_id: call.call_id.clone(),
                result,
            },
            Err(err) => McpResultPayload {
                call_id: call.call_id.clone(),
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
        while let Some(entry) = dir
            .next_entry()
            .await
            .context("failed to iterate directory")?
        {
            let metadata = entry
                .metadata()
                .await
                .context("failed to stat directory entry")?;
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
            let Some((path, total_size, consumed)) = try_parse_upload_header(&self.header_buf)?
            else {
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

        let data =
            std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
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
    let path =
        std::str::from_utf8(&buf[4..4 + path_len]).context("invalid download path header")?;
    Ok(Some((PathBuf::from(path), 4 + path_len)))
}

impl GatewayLink for PeerLink {
    async fn send(&self, envelope: Envelope) {
        let _ = self.send_fire_and_forget(envelope).await;
    }
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
    /// Kills the child without the `child` lock: the task that waits for the child holds that
    /// lock until the child exits, so a kill that took it waited for the very process it was to kill.
    killer: std::sync::Mutex<Box<dyn portable_pty::ChildKiller + Send + Sync>>,
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
        let writer = pair
            .master
            .take_writer()
            .context("failed to take PTY writer")?;

        let killer = child.clone_killer();
        Ok(Self {
            master_reader: std::sync::Mutex::new(reader),
            master_writer: std::sync::Mutex::new(writer),
            master: std::sync::Mutex::new(pair.master),
            child: std::sync::Mutex::new(child),
            killer: std::sync::Mutex::new(killer),
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
        let mut killer = self
            .killer
            .lock()
            .map_err(|_| anyhow::anyhow!("PTY killer lock poisoned"))?;
        killer.kill()?;
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
            Ok((
                shell.to_string(),
                vec!["-c".to_string(), trimmed.to_string()],
            ))
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

    use serde_json::json;
    use tokio::sync::mpsc;
    use wsh_core::messages::{ChannelKind, ReverseConnectPayload};

    use super::{
        append_replay, command_spec, same_reverse_request, try_parse_download_header,
        try_parse_upload_header, LocalMcpBridge, LocalPty, ReverseHostFileSession,
        ReverseHostOptions, ReverseHostPtySession, RuntimeEvent,
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
            from_fingerprint: "operator".into(),
            features: None,
        };
        let right = ReverseConnectPayload {
            target_fingerprint: "fp".into(),
            username: "alice".into(),
            from_fingerprint: "operator".into(),
            features: None,
        };
        let wrong_user = ReverseConnectPayload {
            target_fingerprint: "fp".into(),
            username: "bob".into(),
            from_fingerprint: "operator".into(),
            features: None,
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
        assert_eq!(u64::from_be_bytes(responses[0][..8].try_into().unwrap()), 5);
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
                call_id: Some("call-1".to_string()),
            })
            .await;
        assert_eq!(result.result["stdout"], "hello");
        // The caller correlates concurrent calls on this; a responder that
        // drops it forces them back on "first result wins".
        assert_eq!(result.call_id.as_deref(), Some("call-1"));
    }

    #[tokio::test]
    async fn local_mcp_bridge_echoes_call_id_on_failure_too() {
        let bridge = LocalMcpBridge;
        let result = bridge
            .call(&wsh_core::messages::McpCallPayload {
                tool: "no.such.tool".to_string(),
                arguments: json!({}),
                call_id: Some("call-2".to_string()),
            })
            .await;
        assert!(result.result["error"].is_string());
        // An error still answers one specific call.
        assert_eq!(result.call_id.as_deref(), Some("call-2"));
    }

    #[tokio::test]
    async fn local_mcp_bridge_omits_call_id_when_the_call_carried_none() {
        let bridge = LocalMcpBridge;
        let result = bridge
            .call(&wsh_core::messages::McpCallPayload {
                tool: "shell.exec".to_string(),
                arguments: json!({ "command": "printf hello" }),
                call_id: None,
            })
            .await;
        assert_eq!(result.call_id, None);
    }
}
