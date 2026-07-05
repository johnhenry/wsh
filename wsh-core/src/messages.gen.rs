// wsh protocol control message types.
// AUTO-GENERATED from wsh-v1.yaml — do not edit.
// Run: node web/packages/wsh/spec/codegen.mjs

use serde::{Deserialize, Serialize};

/// Numeric message type tags — must match JS `MSG` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
#[repr(u8)]
pub enum MsgType {
    Hello = 0x01,
    ServerHello = 0x02,
    Challenge = 0x03,
    AuthMethods = 0x04,
    Auth = 0x05,
    AuthOk = 0x06,
    AuthFail = 0x07,

    Open = 0x10,
    OpenOk = 0x11,
    OpenFail = 0x12,
    Resize = 0x13,
    Signal = 0x14,
    Exit = 0x15,
    Close = 0x16,
    SessionData = 0x17,

    Error = 0x20,
    Ping = 0x21,
    Pong = 0x22,

    Attach = 0x30,
    Resume = 0x31,
    Rename = 0x32,
    IdleWarning = 0x33,
    Shutdown = 0x34,
    Snapshot = 0x35,
    Presence = 0x36,
    ControlChanged = 0x37,
    Metrics = 0x38,
    Clipboard = 0x39,
    RecordingExport = 0x3a,
    CommandJournal = 0x3b,
    MetricsRequest = 0x3c,
    SuspendSession = 0x3d,
    RestartPty = 0x3e,
    SessionListRequest = 0x3f,

    McpDiscover = 0x40,
    McpTools = 0x41,
    McpCall = 0x42,
    McpResult = 0x43,

    ReverseRegister = 0x50,
    ReverseList = 0x51,
    ReversePeers = 0x52,
    ReverseConnect = 0x53,
    ReverseAccept = 0x54,
    ReverseReject = 0x55,

    SessionList = 0x5f,
    Detach = 0x60,
    DetachOk = 0x61,
    DetachFail = 0x62,

    OpenTcp = 0x70,
    OpenUdp = 0x71,
    ResolveDns = 0x72,
    GatewayOk = 0x73,
    GatewayFail = 0x74,
    GatewayClose = 0x75,
    InboundOpen = 0x76,
    InboundAccept = 0x77,
    InboundReject = 0x78,
    DnsResult = 0x79,
    ListenRequest = 0x7a,
    ListenOk = 0x7b,
    ListenFail = 0x7c,
    ListenClose = 0x7d,
    GatewayData = 0x7e,

    GuestInvite = 0x80,
    GuestJoin = 0x81,
    GuestRevoke = 0x82,

    ShareSession = 0x83,
    ShareRevoke = 0x84,

    CompressBegin = 0x85,
    CompressAck = 0x86,

    RateControl = 0x87,
    RateWarning = 0x88,

    SessionLink = 0x89,
    SessionUnlink = 0x8a,

    CopilotAttach = 0x8b,
    CopilotSuggest = 0x8c,
    CopilotDetach = 0x8d,

    KeyExchange = 0x8e,
    EncryptedFrame = 0x8f,

    EchoAck = 0x90,
    EchoState = 0x91,

    TermSync = 0x92,
    TermDiff = 0x93,

    NodeAnnounce = 0x94,
    NodeRedirect = 0x95,

    SessionGrant = 0x96,
    SessionRevoke = 0x97,

    FileOp = 0x98,
    FileResult = 0x99,
    FileChunk = 0x9a,

    PolicyEval = 0x9b,
    PolicyResult = 0x9c,
    PolicyUpdate = 0x9d,

    TerminalConfig = 0x9e,
}

impl From<MsgType> for u8 {
    fn from(m: MsgType) -> u8 {
        m as u8
    }
}

impl TryFrom<u8> for MsgType {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, String> {
        match v {
            0x01 => Ok(Self::Hello),
            0x02 => Ok(Self::ServerHello),
            0x03 => Ok(Self::Challenge),
            0x04 => Ok(Self::AuthMethods),
            0x05 => Ok(Self::Auth),
            0x06 => Ok(Self::AuthOk),
            0x07 => Ok(Self::AuthFail),
            0x10 => Ok(Self::Open),
            0x11 => Ok(Self::OpenOk),
            0x12 => Ok(Self::OpenFail),
            0x13 => Ok(Self::Resize),
            0x14 => Ok(Self::Signal),
            0x15 => Ok(Self::Exit),
            0x16 => Ok(Self::Close),
            0x17 => Ok(Self::SessionData),
            0x20 => Ok(Self::Error),
            0x21 => Ok(Self::Ping),
            0x22 => Ok(Self::Pong),
            0x30 => Ok(Self::Attach),
            0x31 => Ok(Self::Resume),
            0x32 => Ok(Self::Rename),
            0x33 => Ok(Self::IdleWarning),
            0x34 => Ok(Self::Shutdown),
            0x35 => Ok(Self::Snapshot),
            0x36 => Ok(Self::Presence),
            0x37 => Ok(Self::ControlChanged),
            0x38 => Ok(Self::Metrics),
            0x39 => Ok(Self::Clipboard),
            0x3a => Ok(Self::RecordingExport),
            0x3b => Ok(Self::CommandJournal),
            0x3c => Ok(Self::MetricsRequest),
            0x3d => Ok(Self::SuspendSession),
            0x3e => Ok(Self::RestartPty),
            0x3f => Ok(Self::SessionListRequest),
            0x40 => Ok(Self::McpDiscover),
            0x41 => Ok(Self::McpTools),
            0x42 => Ok(Self::McpCall),
            0x43 => Ok(Self::McpResult),
            0x50 => Ok(Self::ReverseRegister),
            0x51 => Ok(Self::ReverseList),
            0x52 => Ok(Self::ReversePeers),
            0x53 => Ok(Self::ReverseConnect),
            0x54 => Ok(Self::ReverseAccept),
            0x55 => Ok(Self::ReverseReject),
            0x5f => Ok(Self::SessionList),
            0x60 => Ok(Self::Detach),
            0x61 => Ok(Self::DetachOk),
            0x62 => Ok(Self::DetachFail),
            0x70 => Ok(Self::OpenTcp),
            0x71 => Ok(Self::OpenUdp),
            0x72 => Ok(Self::ResolveDns),
            0x73 => Ok(Self::GatewayOk),
            0x74 => Ok(Self::GatewayFail),
            0x75 => Ok(Self::GatewayClose),
            0x76 => Ok(Self::InboundOpen),
            0x77 => Ok(Self::InboundAccept),
            0x78 => Ok(Self::InboundReject),
            0x79 => Ok(Self::DnsResult),
            0x7a => Ok(Self::ListenRequest),
            0x7b => Ok(Self::ListenOk),
            0x7c => Ok(Self::ListenFail),
            0x7d => Ok(Self::ListenClose),
            0x7e => Ok(Self::GatewayData),
            0x80 => Ok(Self::GuestInvite),
            0x81 => Ok(Self::GuestJoin),
            0x82 => Ok(Self::GuestRevoke),
            0x83 => Ok(Self::ShareSession),
            0x84 => Ok(Self::ShareRevoke),
            0x85 => Ok(Self::CompressBegin),
            0x86 => Ok(Self::CompressAck),
            0x87 => Ok(Self::RateControl),
            0x88 => Ok(Self::RateWarning),
            0x89 => Ok(Self::SessionLink),
            0x8a => Ok(Self::SessionUnlink),
            0x8b => Ok(Self::CopilotAttach),
            0x8c => Ok(Self::CopilotSuggest),
            0x8d => Ok(Self::CopilotDetach),
            0x8e => Ok(Self::KeyExchange),
            0x8f => Ok(Self::EncryptedFrame),
            0x90 => Ok(Self::EchoAck),
            0x91 => Ok(Self::EchoState),
            0x92 => Ok(Self::TermSync),
            0x93 => Ok(Self::TermDiff),
            0x94 => Ok(Self::NodeAnnounce),
            0x95 => Ok(Self::NodeRedirect),
            0x96 => Ok(Self::SessionGrant),
            0x97 => Ok(Self::SessionRevoke),
            0x98 => Ok(Self::FileOp),
            0x99 => Ok(Self::FileResult),
            0x9a => Ok(Self::FileChunk),
            0x9b => Ok(Self::PolicyEval),
            0x9c => Ok(Self::PolicyResult),
            0x9d => Ok(Self::PolicyUpdate),
            0x9e => Ok(Self::TerminalConfig),
            _ => Err(format!("unknown message type: 0x{v:02x}")),
        }
    }
}

/// ChannelKind enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ChannelKind {
    #[default]
    Pty,
    Exec,
    Meta,
    File,
    Tcp,
    Udp,
    Job,
}

/// AuthMethod enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    #[default]
    Pubkey,
    Password,
}

/// SessionDataMode enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SessionDataMode {
    #[default]
    Stream,
    Virtual,
}

/// Protocol version string.
pub const PROTOCOL_VERSION: &str = "wsh-v1";

// ── Message payloads ──────────────────────────────────────────────────

/// Envelope: every control message has a `type` plus a payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(rename = "type")]
    pub msg_type: MsgType,

    #[serde(flatten)]
    pub payload: Payload,
}

/// All possible message payloads (untagged for CBOR compatibility).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Payload {
    Hello(HelloPayload),
    ServerHello(ServerHelloPayload),
    Challenge(ChallengePayload),
    AuthMethods(AuthMethodsPayload),
    Auth(AuthPayload),
    AuthOk(AuthOkPayload),
    AuthFail(AuthFailPayload),
    Open(OpenPayload),
    OpenOk(OpenOkPayload),
    OpenFail(OpenFailPayload),
    Resize(ResizePayload),
    Signal(SignalPayload),
    Exit(ExitPayload),
    Close(ClosePayload),
    SessionData(SessionDataPayload),
    Error(ErrorPayload),
    PingPong(PingPongPayload),
    Attach(AttachPayload),
    Resume(ResumePayload),
    Rename(RenamePayload),
    IdleWarning(IdleWarningPayload),
    Shutdown(ShutdownPayload),
    Snapshot(SnapshotPayload),
    Presence(PresencePayload),
    ControlChanged(ControlChangedPayload),
    Metrics(MetricsPayload),
    Clipboard(ClipboardPayload),
    RecordingExport(RecordingExportPayload),
    CommandJournal(CommandJournalPayload),
    MetricsRequest(MetricsRequestPayload),
    SuspendSession(SuspendSessionPayload),
    RestartPty(RestartPtyPayload),
    SessionListRequest(SessionListRequestPayload),
    McpDiscover(McpDiscoverPayload),
    McpTools(McpToolsPayload),
    McpCall(McpCallPayload),
    McpResult(McpResultPayload),
    ReverseRegister(ReverseRegisterPayload),
    ReverseList(ReverseListPayload),
    ReversePeers(ReversePeersPayload),
    ReverseConnect(ReverseConnectPayload),
    ReverseAccept(ReverseAcceptPayload),
    ReverseReject(ReverseRejectPayload),
    SessionList(SessionListPayload),
    Detach(DetachPayload),
    DetachOk(DetachOkPayload),
    DetachFail(DetachFailPayload),
    OpenTcp(OpenTcpPayload),
    OpenUdp(OpenUdpPayload),
    ResolveDns(ResolveDnsPayload),
    GatewayOk(GatewayOkPayload),
    GatewayFail(GatewayFailPayload),
    GatewayClose(GatewayClosePayload),
    InboundOpen(InboundOpenPayload),
    InboundAccept(InboundAcceptPayload),
    InboundReject(InboundRejectPayload),
    DnsResult(DnsResultPayload),
    ListenRequest(ListenRequestPayload),
    ListenOk(ListenOkPayload),
    ListenFail(ListenFailPayload),
    ListenClose(ListenClosePayload),
    GatewayData(GatewayDataPayload),
    GuestInvite(GuestInvitePayload),
    GuestJoin(GuestJoinPayload),
    GuestRevoke(GuestRevokePayload),
    ShareSession(ShareSessionPayload),
    ShareRevoke(ShareRevokePayload),
    CompressBegin(CompressBeginPayload),
    CompressAck(CompressAckPayload),
    RateControl(RateControlPayload),
    RateWarning(RateWarningPayload),
    SessionLink(SessionLinkPayload),
    SessionUnlink(SessionUnlinkPayload),
    CopilotAttach(CopilotAttachPayload),
    CopilotSuggest(CopilotSuggestPayload),
    CopilotDetach(CopilotDetachPayload),
    KeyExchange(KeyExchangePayload),
    EncryptedFrame(EncryptedFramePayload),
    EchoAck(EchoAckPayload),
    EchoState(EchoStatePayload),
    TermSync(TermSyncPayload),
    TermDiff(TermDiffPayload),
    NodeAnnounce(NodeAnnouncePayload),
    NodeRedirect(NodeRedirectPayload),
    SessionGrant(SessionGrantPayload),
    SessionRevoke(SessionRevokePayload),
    FileOp(FileOpPayload),
    FileResult(FileResultPayload),
    FileChunk(FileChunkPayload),
    PolicyEval(PolicyEvalPayload),
    PolicyResult(PolicyResultPayload),
    PolicyUpdate(PolicyUpdatePayload),
    TerminalConfig(TerminalConfigPayload),
    Empty(EmptyPayload),
}

impl Payload {
    pub fn decode_for_msg_type(
        msg_type: MsgType,
        data: &[u8],
    ) -> Result<Self, ciborium::de::Error<std::io::Error>> {
        let cursor = std::io::Cursor::new(data);
        match msg_type {
            MsgType::Ping | MsgType::Pong => Ok(Self::PingPong(ciborium::from_reader(cursor)?)),
            MsgType::Hello => Ok(Self::Hello(ciborium::from_reader(cursor)?)),
            MsgType::ServerHello => Ok(Self::ServerHello(ciborium::from_reader(cursor)?)),
            MsgType::Challenge => Ok(Self::Challenge(ciborium::from_reader(cursor)?)),
            MsgType::AuthMethods => Ok(Self::AuthMethods(ciborium::from_reader(cursor)?)),
            MsgType::Auth => Ok(Self::Auth(ciborium::from_reader(cursor)?)),
            MsgType::AuthOk => Ok(Self::AuthOk(ciborium::from_reader(cursor)?)),
            MsgType::AuthFail => Ok(Self::AuthFail(ciborium::from_reader(cursor)?)),
            MsgType::Open => Ok(Self::Open(ciborium::from_reader(cursor)?)),
            MsgType::OpenOk => Ok(Self::OpenOk(ciborium::from_reader(cursor)?)),
            MsgType::OpenFail => Ok(Self::OpenFail(ciborium::from_reader(cursor)?)),
            MsgType::Resize => Ok(Self::Resize(ciborium::from_reader(cursor)?)),
            MsgType::Signal => Ok(Self::Signal(ciborium::from_reader(cursor)?)),
            MsgType::Exit => Ok(Self::Exit(ciborium::from_reader(cursor)?)),
            MsgType::Close => Ok(Self::Close(ciborium::from_reader(cursor)?)),
            MsgType::SessionData => Ok(Self::SessionData(ciborium::from_reader(cursor)?)),
            MsgType::Error => Ok(Self::Error(ciborium::from_reader(cursor)?)),
            MsgType::Attach => Ok(Self::Attach(ciborium::from_reader(cursor)?)),
            MsgType::Resume => Ok(Self::Resume(ciborium::from_reader(cursor)?)),
            MsgType::Rename => Ok(Self::Rename(ciborium::from_reader(cursor)?)),
            MsgType::IdleWarning => Ok(Self::IdleWarning(ciborium::from_reader(cursor)?)),
            MsgType::Shutdown => Ok(Self::Shutdown(ciborium::from_reader(cursor)?)),
            MsgType::Snapshot => Ok(Self::Snapshot(ciborium::from_reader(cursor)?)),
            MsgType::Presence => Ok(Self::Presence(ciborium::from_reader(cursor)?)),
            MsgType::ControlChanged => Ok(Self::ControlChanged(ciborium::from_reader(cursor)?)),
            MsgType::Metrics => Ok(Self::Metrics(ciborium::from_reader(cursor)?)),
            MsgType::Clipboard => Ok(Self::Clipboard(ciborium::from_reader(cursor)?)),
            MsgType::RecordingExport => Ok(Self::RecordingExport(ciborium::from_reader(cursor)?)),
            MsgType::CommandJournal => Ok(Self::CommandJournal(ciborium::from_reader(cursor)?)),
            MsgType::MetricsRequest => Ok(Self::MetricsRequest(ciborium::from_reader(cursor)?)),
            MsgType::SuspendSession => Ok(Self::SuspendSession(ciborium::from_reader(cursor)?)),
            MsgType::RestartPty => Ok(Self::RestartPty(ciborium::from_reader(cursor)?)),
            MsgType::SessionListRequest => Ok(Self::SessionListRequest(ciborium::from_reader(cursor)?)),
            MsgType::McpDiscover => Ok(Self::McpDiscover(ciborium::from_reader(cursor)?)),
            MsgType::McpTools => Ok(Self::McpTools(ciborium::from_reader(cursor)?)),
            MsgType::McpCall => Ok(Self::McpCall(ciborium::from_reader(cursor)?)),
            MsgType::McpResult => Ok(Self::McpResult(ciborium::from_reader(cursor)?)),
            MsgType::ReverseRegister => Ok(Self::ReverseRegister(ciborium::from_reader(cursor)?)),
            MsgType::ReverseList => Ok(Self::ReverseList(ciborium::from_reader(cursor)?)),
            MsgType::ReversePeers => Ok(Self::ReversePeers(ciborium::from_reader(cursor)?)),
            MsgType::ReverseConnect => Ok(Self::ReverseConnect(ciborium::from_reader(cursor)?)),
            MsgType::ReverseAccept => Ok(Self::ReverseAccept(ciborium::from_reader(cursor)?)),
            MsgType::ReverseReject => Ok(Self::ReverseReject(ciborium::from_reader(cursor)?)),
            MsgType::SessionList => Ok(Self::SessionList(ciborium::from_reader(cursor)?)),
            MsgType::Detach => Ok(Self::Detach(ciborium::from_reader(cursor)?)),
            MsgType::DetachOk => Ok(Self::DetachOk(ciborium::from_reader(cursor)?)),
            MsgType::DetachFail => Ok(Self::DetachFail(ciborium::from_reader(cursor)?)),
            MsgType::OpenTcp => Ok(Self::OpenTcp(ciborium::from_reader(cursor)?)),
            MsgType::OpenUdp => Ok(Self::OpenUdp(ciborium::from_reader(cursor)?)),
            MsgType::ResolveDns => Ok(Self::ResolveDns(ciborium::from_reader(cursor)?)),
            MsgType::GatewayOk => Ok(Self::GatewayOk(ciborium::from_reader(cursor)?)),
            MsgType::GatewayFail => Ok(Self::GatewayFail(ciborium::from_reader(cursor)?)),
            MsgType::GatewayClose => Ok(Self::GatewayClose(ciborium::from_reader(cursor)?)),
            MsgType::InboundOpen => Ok(Self::InboundOpen(ciborium::from_reader(cursor)?)),
            MsgType::InboundAccept => Ok(Self::InboundAccept(ciborium::from_reader(cursor)?)),
            MsgType::InboundReject => Ok(Self::InboundReject(ciborium::from_reader(cursor)?)),
            MsgType::DnsResult => Ok(Self::DnsResult(ciborium::from_reader(cursor)?)),
            MsgType::ListenRequest => Ok(Self::ListenRequest(ciborium::from_reader(cursor)?)),
            MsgType::ListenOk => Ok(Self::ListenOk(ciborium::from_reader(cursor)?)),
            MsgType::ListenFail => Ok(Self::ListenFail(ciborium::from_reader(cursor)?)),
            MsgType::ListenClose => Ok(Self::ListenClose(ciborium::from_reader(cursor)?)),
            MsgType::GatewayData => Ok(Self::GatewayData(ciborium::from_reader(cursor)?)),
            MsgType::GuestInvite => Ok(Self::GuestInvite(ciborium::from_reader(cursor)?)),
            MsgType::GuestJoin => Ok(Self::GuestJoin(ciborium::from_reader(cursor)?)),
            MsgType::GuestRevoke => Ok(Self::GuestRevoke(ciborium::from_reader(cursor)?)),
            MsgType::ShareSession => Ok(Self::ShareSession(ciborium::from_reader(cursor)?)),
            MsgType::ShareRevoke => Ok(Self::ShareRevoke(ciborium::from_reader(cursor)?)),
            MsgType::CompressBegin => Ok(Self::CompressBegin(ciborium::from_reader(cursor)?)),
            MsgType::CompressAck => Ok(Self::CompressAck(ciborium::from_reader(cursor)?)),
            MsgType::RateControl => Ok(Self::RateControl(ciborium::from_reader(cursor)?)),
            MsgType::RateWarning => Ok(Self::RateWarning(ciborium::from_reader(cursor)?)),
            MsgType::SessionLink => Ok(Self::SessionLink(ciborium::from_reader(cursor)?)),
            MsgType::SessionUnlink => Ok(Self::SessionUnlink(ciborium::from_reader(cursor)?)),
            MsgType::CopilotAttach => Ok(Self::CopilotAttach(ciborium::from_reader(cursor)?)),
            MsgType::CopilotSuggest => Ok(Self::CopilotSuggest(ciborium::from_reader(cursor)?)),
            MsgType::CopilotDetach => Ok(Self::CopilotDetach(ciborium::from_reader(cursor)?)),
            MsgType::KeyExchange => Ok(Self::KeyExchange(ciborium::from_reader(cursor)?)),
            MsgType::EncryptedFrame => Ok(Self::EncryptedFrame(ciborium::from_reader(cursor)?)),
            MsgType::EchoAck => Ok(Self::EchoAck(ciborium::from_reader(cursor)?)),
            MsgType::EchoState => Ok(Self::EchoState(ciborium::from_reader(cursor)?)),
            MsgType::TermSync => Ok(Self::TermSync(ciborium::from_reader(cursor)?)),
            MsgType::TermDiff => Ok(Self::TermDiff(ciborium::from_reader(cursor)?)),
            MsgType::NodeAnnounce => Ok(Self::NodeAnnounce(ciborium::from_reader(cursor)?)),
            MsgType::NodeRedirect => Ok(Self::NodeRedirect(ciborium::from_reader(cursor)?)),
            MsgType::SessionGrant => Ok(Self::SessionGrant(ciborium::from_reader(cursor)?)),
            MsgType::SessionRevoke => Ok(Self::SessionRevoke(ciborium::from_reader(cursor)?)),
            MsgType::FileOp => Ok(Self::FileOp(ciborium::from_reader(cursor)?)),
            MsgType::FileResult => Ok(Self::FileResult(ciborium::from_reader(cursor)?)),
            MsgType::FileChunk => Ok(Self::FileChunk(ciborium::from_reader(cursor)?)),
            MsgType::PolicyEval => Ok(Self::PolicyEval(ciborium::from_reader(cursor)?)),
            MsgType::PolicyResult => Ok(Self::PolicyResult(ciborium::from_reader(cursor)?)),
            MsgType::PolicyUpdate => Ok(Self::PolicyUpdate(ciborium::from_reader(cursor)?)),
            MsgType::TerminalConfig => Ok(Self::TerminalConfig(ciborium::from_reader(cursor)?)),
        }
    }
}

// ── Individual payload structs ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyPayload {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PingPongPayload {
    pub id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloPayload {
    pub version: String,
    pub username: String,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<AuthMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerHelloPayload {
    pub session_id: String,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengePayload {
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthMethodsPayload {
    pub methods: Vec<AuthMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthPayload {
    pub method: AuthMethod,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "option_bytes")]
    pub signature: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "option_bytes")]
    pub public_key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthOkPayload {
    pub session_id: String,
    #[serde(with = "serde_bytes")]
    pub token: Vec<u8>,
    pub ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthFailPayload {
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenPayload {
    pub kind: ChannelKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cols: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenOkPayload {
    pub channel_id: u32,
    #[serde(default)]
    pub stream_ids: Vec<u32>,
    #[serde(default)]
    pub data_mode: SessionDataMode,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenFailPayload {
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResizePayload {
    pub channel_id: u32,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalPayload {
    pub channel_id: u32,
    pub signal: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitPayload {
    pub channel_id: u32,
    pub code: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosePayload {
    pub channel_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionDataPayload {
    pub channel_id: u32,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorPayload {
    pub code: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachPayload {
    pub session_id: String,
    #[serde(with = "serde_bytes")]
    pub token: Vec<u8>,
    #[serde(default = "default_attach_mode")]
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
}

fn default_attach_mode() -> String {
    "control".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumePayload {
    pub session_id: String,
    #[serde(with = "serde_bytes")]
    pub token: Vec<u8>,
    pub last_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenamePayload {
    pub session_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdleWarningPayload {
    pub expires_in: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownPayload {
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPayload {
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresencePayload {
    pub attachments: Vec<AttachmentInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlChangedPayload {
    pub new_controller: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPayload {
    pub direction: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingExportPayload {
    pub session_id: String,
    #[serde(default = "default_recording_export_format")]
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

fn default_recording_export_format() -> String {
    "jsonl".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandJournalPayload {
    pub session_id: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsRequestPayload {
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspendSessionPayload {
    pub session_id: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartPtyPayload {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionListRequestPayload {
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpDiscoverPayload {
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolsPayload {
    pub tools: Vec<McpToolSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCallPayload {
    pub tool: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpResultPayload {
    pub result: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseRegisterPayload {
    pub username: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default = "default_reverse_register_peer_type")]
    pub peer_type: String,
    #[serde(default = "default_reverse_register_shell_backend")]
    pub shell_backend: String,
    #[serde(default)]
    pub supports_attach: bool,
    #[serde(default)]
    pub supports_replay: bool,
    #[serde(default)]
    pub supports_echo: bool,
    #[serde(default)]
    pub supports_term_sync: bool,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

fn default_reverse_register_peer_type() -> String {
    "host".to_string()
}

fn default_reverse_register_shell_backend() -> String {
    "pty".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseListPayload {
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReversePeersPayload {
    pub peers: Vec<PeerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseConnectPayload {
    pub target_fingerprint: String,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseAcceptPayload {
    pub target_fingerprint: String,
    pub username: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default = "default_reverse_accept_peer_type")]
    pub peer_type: String,
    #[serde(default = "default_reverse_accept_shell_backend")]
    pub shell_backend: String,
    #[serde(default)]
    pub supports_attach: bool,
    #[serde(default)]
    pub supports_replay: bool,
    #[serde(default)]
    pub supports_echo: bool,
    #[serde(default)]
    pub supports_term_sync: bool,
}

fn default_reverse_accept_peer_type() -> String {
    "host".to_string()
}

fn default_reverse_accept_shell_backend() -> String {
    "pty".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseRejectPayload {
    pub target_fingerprint: String,
    pub username: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionListPayload {
    pub sessions: Vec<SessionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachPayload {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachOkPayload {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachFailPayload {
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenTcpPayload {
    pub gateway_id: u32,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenUdpPayload {
    pub gateway_id: u32,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveDnsPayload {
    pub gateway_id: u32,
    pub name: String,
    #[serde(default = "default_resolve_dns_record_type")]
    pub record_type: String,
}

fn default_resolve_dns_record_type() -> String {
    "A".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayOkPayload {
    pub gateway_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayFailPayload {
    pub gateway_id: u32,
    pub code: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayClosePayload {
    pub gateway_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundOpenPayload {
    pub listener_id: u32,
    pub channel_id: u32,
    pub peer_addr: String,
    pub peer_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundAcceptPayload {
    pub channel_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundRejectPayload {
    pub channel_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsResultPayload {
    pub gateway_id: u32,
    pub addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenRequestPayload {
    pub listener_id: u32,
    pub port: u16,
    #[serde(default = "default_listen_request_bind_addr")]
    pub bind_addr: String,
}

fn default_listen_request_bind_addr() -> String {
    "0.0.0.0".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenOkPayload {
    pub listener_id: u32,
    pub actual_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenFailPayload {
    pub listener_id: u32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenClosePayload {
    pub listener_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayDataPayload {
    pub gateway_id: u32,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestInvitePayload {
    pub session_id: String,
    pub ttl: u64,
    #[serde(default = "default_guest_invite_permissions")]
    pub permissions: Vec<String>,
}

fn default_guest_invite_permissions() -> Vec<String> {
    vec!["read".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestJoinPayload {
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRevokePayload {
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareSessionPayload {
    pub session_id: String,
    #[serde(default = "default_share_session_mode")]
    pub mode: String,
    pub ttl: u64,
}

fn default_share_session_mode() -> String {
    "read".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareRevokePayload {
    pub share_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressBeginPayload {
    pub algorithm: String,
    #[serde(default = "default_compress_begin_level")]
    pub level: u32,
}

fn default_compress_begin_level() -> u32 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressAckPayload {
    pub algorithm: String,
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateControlPayload {
    pub session_id: String,
    pub max_bytes_per_sec: u64,
    #[serde(default = "default_rate_control_policy")]
    pub policy: String,
}

fn default_rate_control_policy() -> String {
    "pause".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateWarningPayload {
    pub session_id: String,
    pub queued_bytes: u64,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLinkPayload {
    pub source_session: String,
    pub target_host: String,
    pub target_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_user: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionUnlinkPayload {
    pub link_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopilotAttachPayload {
    pub session_id: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopilotSuggestPayload {
    pub session_id: String,
    pub suggestion: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopilotDetachPayload {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyExchangePayload {
    pub algorithm: String,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedFramePayload {
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EchoAckPayload {
    pub channel_id: u32,
    pub echo_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EchoStatePayload {
    pub channel_id: u32,
    pub echo_seq: u64,
    pub cursor_x: u16,
    pub cursor_y: u16,
    pub pending: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermSyncPayload {
    pub channel_id: u32,
    pub frame_seq: u64,
    #[serde(with = "serde_bytes")]
    pub state_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermDiffPayload {
    pub channel_id: u32,
    pub frame_seq: u64,
    pub base_seq: u64,
    #[serde(with = "serde_bytes")]
    pub patch: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAnnouncePayload {
    pub node_id: String,
    pub endpoint: String,
    pub load: f64,
    pub capacity: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRedirectPayload {
    pub target_node: String,
    pub target_endpoint: String,
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantPayload {
    pub session_id: String,
    pub principal: String,
    #[serde(default = "default_session_grant_permissions")]
    pub permissions: Vec<String>,
}

fn default_session_grant_permissions() -> Vec<String> {
    vec!["read".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRevokePayload {
    pub session_id: String,
    pub principal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileOpPayload {
    pub channel_id: u32,
    pub op: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileResultPayload {
    pub channel_id: u32,
    pub success: bool,
    #[serde(default)]
    pub metadata: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileChunkPayload {
    pub channel_id: u32,
    pub offset: u64,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    pub is_final: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvalPayload {
    pub request_id: String,
    pub action: String,
    pub principal: String,
    #[serde(default)]
    pub context: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResultPayload {
    pub request_id: String,
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdatePayload {
    pub policy_id: String,
    pub rules: serde_json::Value,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalConfigPayload {
    pub channel_id: u32,
    pub frontend: String,
    #[serde(default)]
    pub options: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentInfo {
    pub session_id: String,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub fingerprint: String,
    pub fingerprint_short: String,
    pub username: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub peer_type: String,
    #[serde(default)]
    pub shell_backend: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub supports_attach: bool,
    #[serde(default)]
    pub supports_replay: bool,
    #[serde(default)]
    pub supports_echo: bool,
    #[serde(default)]
    pub supports_term_sync: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolSpec {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub username: String,
    pub fingerprint_short: String,
    pub created_at_secs: u64,
    pub idle_secs: u64,
    pub attached_count: u32,
}

// ── Helper for optional bytes serde ──────────────────────────────────

mod option_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => super::serde_bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<super::serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        Ok(opt.map(|b: super::serde_bytes::ByteBuf| b.into_vec()))
    }
}

// serde_json::Value is used in McpToolSpec / McpCallPayload / McpResultPayload.

mod serde_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    #[allow(dead_code)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let buf: ByteBuf = Deserialize::deserialize(deserializer)?;
        Ok(buf.into_vec())
    }

    #[derive(Debug)]
    pub struct ByteBuf(Vec<u8>);

    impl ByteBuf {
        pub fn into_vec(self) -> Vec<u8> {
            self.0
        }
    }

    impl<'de> Deserialize<'de> for ByteBuf {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct ByteBufVisitor;

            impl<'de> serde::de::Visitor<'de> for ByteBufVisitor {
                type Value = ByteBuf;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("bytes")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> {
                    Ok(ByteBuf(v.to_vec()))
                }

                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                    Ok(ByteBuf(v))
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    let mut bytes = Vec::new();
                    while let Some(b) = seq.next_element::<u8>()? {
                        bytes.push(b);
                    }
                    Ok(ByteBuf(bytes))
                }
            }

            deserializer.deserialize_any(ByteBufVisitor)
        }
    }
}
