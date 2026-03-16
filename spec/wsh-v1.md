# wsh Protocol Specification — wsh-v1

> Auto-generated from `wsh-v1.yaml`. Do not edit.
> Run: `node web/packages/wsh/spec/codegen.mjs`

## Table of Contents

1. [Overview](#overview)
2. [Enums](#enums)
3. [Message Types](#message-types)
4. [Message Details](#message-details)
5. [Nested Types](#nested-types)
6. [Crypto Primitives](#crypto-primitives)
7. [Transport Bindings](#transport-bindings)

## Overview

- **Protocol**: wsh
- **Version**: `wsh-v1`
- **Wire format**: CBOR
- **Framing**: length prefixed be32
- **Total message types**: 95 (including WS_DATA framing marker)

## Enums

### ChannelKind

Type: `string`

| Value |
|-------|
| `pty` |
| `exec` |
| `meta` |
| `file` |
| `tcp` |
| `udp` |
| `job` |

### AuthMethod

Type: `string`

| Value |
|-------|
| `pubkey` |
| `password` |

### SessionDataMode

Type: `string`

| Value |
|-------|
| `stream` |
| `virtual` |

## Message Types

| Code | Name | Category |
|------|------|----------|
| `0x01` | Hello | handshake |
| `0x02` | ServerHello | handshake |
| `0x03` | Challenge | handshake |
| `0x04` | AuthMethods | handshake |
| `0x05` | Auth | handshake |
| `0x06` | AuthOk | handshake |
| `0x07` | AuthFail | handshake |
| `0x10` | Open | channel |
| `0x11` | OpenOk | channel |
| `0x12` | OpenFail | channel |
| `0x13` | Resize | channel |
| `0x14` | Signal | channel |
| `0x15` | Exit | channel |
| `0x16` | Close | channel |
| `0x17` | SessionData | channel |
| `0x20` | Error | transport |
| `0x21` | Ping | transport |
| `0x22` | Pong | transport |
| `0x30` | Attach | session |
| `0x31` | Resume | session |
| `0x32` | Rename | session |
| `0x33` | IdleWarning | session |
| `0x34` | Shutdown | session |
| `0x35` | Snapshot | session |
| `0x36` | Presence | session |
| `0x37` | ControlChanged | session |
| `0x38` | Metrics | session |
| `0x39` | Clipboard | session |
| `0x3a` | RecordingExport | session |
| `0x3b` | CommandJournal | session |
| `0x3c` | MetricsRequest | session |
| `0x3d` | SuspendSession | session |
| `0x3e` | RestartPty | session |
| `0x3f` | SessionListRequest | session |
| `0x40` | McpDiscover | mcp |
| `0x41` | McpTools | mcp |
| `0x42` | McpCall | mcp |
| `0x43` | McpResult | mcp |
| `0x50` | ReverseRegister | reverse |
| `0x51` | ReverseList | reverse |
| `0x52` | ReversePeers | reverse |
| `0x53` | ReverseConnect | reverse |
| `0x54` | ReverseAccept | reverse |
| `0x55` | ReverseReject | reverse |
| `0x5f` | SessionList | session |
| `0x60` | Detach | session |
| `0x60` | WsData | framing |
| `0x61` | DetachOk | session |
| `0x62` | DetachFail | session |
| `0x70` | OpenTcp | gateway |
| `0x71` | OpenUdp | gateway |
| `0x72` | ResolveDns | gateway |
| `0x73` | GatewayOk | gateway |
| `0x74` | GatewayFail | gateway |
| `0x75` | GatewayClose | gateway |
| `0x76` | InboundOpen | gateway |
| `0x77` | InboundAccept | gateway |
| `0x78` | InboundReject | gateway |
| `0x79` | DnsResult | gateway |
| `0x7a` | ListenRequest | gateway |
| `0x7b` | ListenOk | gateway |
| `0x7c` | ListenFail | gateway |
| `0x7d` | ListenClose | gateway |
| `0x7e` | GatewayData | gateway |
| `0x80` | GuestInvite | guest |
| `0x81` | GuestJoin | guest |
| `0x82` | GuestRevoke | guest |
| `0x83` | ShareSession | sharing |
| `0x84` | ShareRevoke | sharing |
| `0x85` | CompressBegin | compression |
| `0x86` | CompressAck | compression |
| `0x87` | RateControl | ratecontrol |
| `0x88` | RateWarning | ratecontrol |
| `0x89` | SessionLink | linking |
| `0x8a` | SessionUnlink | linking |
| `0x8b` | CopilotAttach | copilot |
| `0x8c` | CopilotSuggest | copilot |
| `0x8d` | CopilotDetach | copilot |
| `0x8e` | KeyExchange | e2e |
| `0x8f` | EncryptedFrame | e2e |
| `0x90` | EchoAck | echo |
| `0x91` | EchoState | echo |
| `0x92` | TermSync | termsync |
| `0x93` | TermDiff | termsync |
| `0x94` | NodeAnnounce | scaling |
| `0x95` | NodeRedirect | scaling |
| `0x96` | SessionGrant | principals |
| `0x97` | SessionRevoke | principals |
| `0x98` | FileOp | filechannel |
| `0x99` | FileResult | filechannel |
| `0x9a` | FileChunk | filechannel |
| `0x9b` | PolicyEval | policy |
| `0x9c` | PolicyResult | policy |
| `0x9d` | PolicyUpdate | policy |
| `0x9e` | TerminalConfig | terminal |

## Message Details

### Hello (`0x01`)

Category: **handshake**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `version` | `string` | yes | — |
| `username` | `string` | yes | — |
| `features` | `string[]` | no | `[]` |
| `auth_method` | `AuthMethod` | no | — |

### ServerHello (`0x02`)

Category: **handshake**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `features` | `string[]` | no | `[]` |
| `fingerprints` | `string[]` | no | `[]` |

### Challenge (`0x03`)

Category: **handshake**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `nonce` | `bytes` | yes | — |

### AuthMethods (`0x04`)

Category: **handshake**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `methods` | `AuthMethod[]` | yes | — |

### Auth (`0x05`)

Category: **handshake**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `method` | `AuthMethod` | yes | — |
| `signature` | `bytes` | no | — |
| `public_key` | `bytes` | no | — |
| `password` | `string` | no | — |

### AuthOk (`0x06`)

Category: **handshake**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `token` | `bytes` | yes | — |
| `ttl` | `u64` | yes | — |

### AuthFail (`0x07`)

Category: **handshake**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `reason` | `string` | yes | — |

### Open (`0x10`)

Category: **channel**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `kind` | `ChannelKind` | yes | — |
| `command` | `string` | no | — |
| `cols` | `u16` | no | — |
| `rows` | `u16` | no | — |
| `env` | `map<string,string>` | no | — |

### OpenOk (`0x11`)

Category: **channel**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `stream_ids` | `u32[]` | no | `[]` |
| `data_mode` | `SessionDataMode` | no | `"stream"` |
| `capabilities` | `string[]` | no | `[]` |

### OpenFail (`0x12`)

Category: **channel**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `reason` | `string` | yes | — |

### Resize (`0x13`)

Category: **channel**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `cols` | `u16` | yes | — |
| `rows` | `u16` | yes | — |

### Signal (`0x14`)

Category: **channel**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `signal` | `string` | yes | — |

### Exit (`0x15`)

Category: **channel**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `code` | `i32` | yes | — |

### Close (`0x16`)

Category: **channel**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |

### SessionData (`0x17`)

Category: **channel**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `data` | `bytes` | yes | — |

### Error (`0x20`)

Category: **transport**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `code` | `u32` | yes | — |
| `message` | `string` | yes | — |

### Ping (`0x21`)

Category: **transport**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `id` | `u64` | yes | — |

### Pong (`0x22`)

Category: **transport**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `id` | `u64` | yes | — |

### Attach (`0x30`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `token` | `bytes` | yes | — |
| `mode` | `string` | no | `"control"` |
| `device_label` | `string` | no | — |

### Resume (`0x31`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `token` | `bytes` | yes | — |
| `last_seq` | `u64` | yes | — |

### Rename (`0x32`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `name` | `string` | yes | — |

### IdleWarning (`0x33`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `expires_in` | `u64` | yes | — |

### Shutdown (`0x34`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `reason` | `string` | yes | — |
| `retry_after` | `u64` | no | — |

### Snapshot (`0x35`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `label` | `string` | yes | — |

### Presence (`0x36`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `attachments` | `AttachmentInfo[]` | yes | — |

### ControlChanged (`0x37`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `new_controller` | `string` | yes | — |

### Metrics (`0x38`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `cpu` | `f64` | no | — |
| `memory` | `u64` | no | — |
| `sessions` | `u32` | no | — |
| `rtt` | `u64` | no | — |

### Clipboard (`0x39`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `direction` | `string` | yes | — |
| `data` | `string` | yes | — |

### RecordingExport (`0x3a`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `format` | `string` | no | `"jsonl"` |
| `data` | `string` | no | — |

### CommandJournal (`0x3b`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `command` | `string` | yes | — |
| `exit_code` | `i32` | no | — |
| `duration_ms` | `u64` | no | — |
| `cwd` | `string` | no | — |
| `timestamp` | `u64` | yes | — |

### MetricsRequest (`0x3c`)

Category: **session**

> >

*No fields.*

### SuspendSession (`0x3d`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `action` | `string` | yes | — |

### RestartPty (`0x3e`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `command` | `string` | no | — |

### SessionListRequest (`0x3f`)

Category: **session**

> >

*No fields.*

### McpDiscover (`0x40`)

Category: **mcp**

> >

*No fields.*

### McpTools (`0x41`)

Category: **mcp**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `tools` | `McpToolSpec[]` | yes | — |

### McpCall (`0x42`)

Category: **mcp**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `tool` | `string` | yes | — |
| `arguments` | `json` | yes | — |

### McpResult (`0x43`)

Category: **mcp**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `result` | `json` | yes | — |

### ReverseRegister (`0x50`)

Category: **reverse**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `username` | `string` | yes | — |
| `capabilities` | `string[]` | no | `[]` |
| `peer_type` | `string` | no | `"host"` |
| `shell_backend` | `string` | no | `"pty"` |
| `supports_attach` | `bool` | no | `false` |
| `supports_replay` | `bool` | no | `false` |
| `supports_echo` | `bool` | no | `false` |
| `supports_term_sync` | `bool` | no | `false` |
| `public_key` | `bytes` | yes | — |

### ReverseList (`0x51`)

Category: **reverse**

> >

*No fields.*

### ReversePeers (`0x52`)

Category: **reverse**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `peers` | `PeerInfo[]` | yes | — |

### ReverseConnect (`0x53`)

Category: **reverse**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `target_fingerprint` | `string` | yes | — |
| `username` | `string` | yes | — |

### ReverseAccept (`0x54`)

Category: **reverse**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `target_fingerprint` | `string` | yes | — |
| `username` | `string` | yes | — |
| `capabilities` | `string[]` | no | `[]` |
| `peer_type` | `string` | no | `"host"` |
| `shell_backend` | `string` | no | `"pty"` |
| `supports_attach` | `bool` | no | `false` |
| `supports_replay` | `bool` | no | `false` |
| `supports_echo` | `bool` | no | `false` |
| `supports_term_sync` | `bool` | no | `false` |

### ReverseReject (`0x55`)

Category: **reverse**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `target_fingerprint` | `string` | yes | — |
| `username` | `string` | yes | — |
| `reason` | `string` | yes | — |

### SessionList (`0x5f`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `sessions` | `SessionSummary[]` | yes | — |

### Detach (`0x60`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |

### WsData (`0x60`)

Category: **framing**

> WebSocket multiplexing framing marker, not a CBOR message

*No fields.*

### DetachOk (`0x61`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |

### DetachFail (`0x62`)

Category: **session**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `reason` | `string` | yes | — |

### OpenTcp (`0x70`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `gateway_id` | `u32` | yes | — |
| `host` | `string` | yes | — |
| `port` | `u16` | yes | — |

### OpenUdp (`0x71`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `gateway_id` | `u32` | yes | — |
| `host` | `string` | yes | — |
| `port` | `u16` | yes | — |

### ResolveDns (`0x72`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `gateway_id` | `u32` | yes | — |
| `name` | `string` | yes | — |
| `record_type` | `string` | no | `"A"` |

### GatewayOk (`0x73`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `gateway_id` | `u32` | yes | — |
| `resolved_addr` | `string` | no | — |

### GatewayFail (`0x74`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `gateway_id` | `u32` | yes | — |
| `code` | `u32` | yes | — |
| `message` | `string` | yes | — |

### GatewayClose (`0x75`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `gateway_id` | `u32` | yes | — |
| `reason` | `string` | no | — |

### InboundOpen (`0x76`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `listener_id` | `u32` | yes | — |
| `channel_id` | `u32` | yes | — |
| `peer_addr` | `string` | yes | — |
| `peer_port` | `u16` | yes | — |

### InboundAccept (`0x77`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `gateway_id` | `u32` | no | — |

### InboundReject (`0x78`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `reason` | `string` | no | — |

### DnsResult (`0x79`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `gateway_id` | `u32` | yes | — |
| `addresses` | `string[]` | yes | — |
| `ttl` | `u32` | no | — |

### ListenRequest (`0x7a`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `listener_id` | `u32` | yes | — |
| `port` | `u16` | yes | — |
| `bind_addr` | `string` | no | `"0.0.0.0"` |

### ListenOk (`0x7b`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `listener_id` | `u32` | yes | — |
| `actual_port` | `u16` | yes | — |

### ListenFail (`0x7c`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `listener_id` | `u32` | yes | — |
| `reason` | `string` | yes | — |

### ListenClose (`0x7d`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `listener_id` | `u32` | yes | — |

### GatewayData (`0x7e`)

Category: **gateway**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `gateway_id` | `u32` | yes | — |
| `data` | `bytes` | yes | — |

### GuestInvite (`0x80`)

Category: **guest**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `ttl` | `u64` | yes | — |
| `permissions` | `string[]` | no | `["read"]` |

### GuestJoin (`0x81`)

Category: **guest**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `token` | `string` | yes | — |
| `device_label` | `string` | no | — |

### GuestRevoke (`0x82`)

Category: **guest**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `token` | `string` | yes | — |
| `reason` | `string` | no | — |

### ShareSession (`0x83`)

Category: **sharing**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `mode` | `string` | no | `"read"` |
| `ttl` | `u64` | yes | — |

### ShareRevoke (`0x84`)

Category: **sharing**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `share_id` | `string` | yes | — |
| `reason` | `string` | no | — |

### CompressBegin (`0x85`)

Category: **compression**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `algorithm` | `string` | yes | — |
| `level` | `u32` | no | `3` |

### CompressAck (`0x86`)

Category: **compression**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `algorithm` | `string` | yes | — |
| `accepted` | `bool` | yes | — |

### RateControl (`0x87`)

Category: **ratecontrol**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `max_bytes_per_sec` | `u64` | yes | — |
| `policy` | `string` | no | `"pause"` |

### RateWarning (`0x88`)

Category: **ratecontrol**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `queued_bytes` | `u64` | yes | — |
| `action` | `string` | yes | — |

### SessionLink (`0x89`)

Category: **linking**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `source_session` | `string` | yes | — |
| `target_host` | `string` | yes | — |
| `target_port` | `u16` | yes | — |
| `target_user` | `string` | no | — |

### SessionUnlink (`0x8a`)

Category: **linking**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `link_id` | `string` | yes | — |
| `reason` | `string` | no | — |

### CopilotAttach (`0x8b`)

Category: **copilot**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `model` | `string` | yes | — |
| `context_window` | `u64` | no | — |

### CopilotSuggest (`0x8c`)

Category: **copilot**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `suggestion` | `string` | yes | — |
| `confidence` | `f64` | no | — |

### CopilotDetach (`0x8d`)

Category: **copilot**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `reason` | `string` | no | — |

### KeyExchange (`0x8e`)

Category: **e2e**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `algorithm` | `string` | yes | — |
| `public_key` | `bytes` | yes | — |
| `session_id` | `string` | yes | — |

### EncryptedFrame (`0x8f`)

Category: **e2e**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `nonce` | `bytes` | yes | — |
| `ciphertext` | `bytes` | yes | — |
| `session_id` | `string` | yes | — |

### EchoAck (`0x90`)

Category: **echo**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `echo_seq` | `u64` | yes | — |

### EchoState (`0x91`)

Category: **echo**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `echo_seq` | `u64` | yes | — |
| `cursor_x` | `u16` | yes | — |
| `cursor_y` | `u16` | yes | — |
| `pending` | `u32` | yes | — |

### TermSync (`0x92`)

Category: **termsync**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `frame_seq` | `u64` | yes | — |
| `state_hash` | `bytes` | yes | — |

### TermDiff (`0x93`)

Category: **termsync**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `frame_seq` | `u64` | yes | — |
| `base_seq` | `u64` | yes | — |
| `patch` | `bytes` | yes | — |

### NodeAnnounce (`0x94`)

Category: **scaling**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `node_id` | `string` | yes | — |
| `endpoint` | `string` | yes | — |
| `load` | `f64` | yes | — |
| `capacity` | `u32` | yes | — |

### NodeRedirect (`0x95`)

Category: **scaling**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `target_node` | `string` | yes | — |
| `target_endpoint` | `string` | yes | — |
| `session_id` | `string` | yes | — |
| `reason` | `string` | no | — |

### SessionGrant (`0x96`)

Category: **principals**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `principal` | `string` | yes | — |
| `permissions` | `string[]` | no | `["read"]` |

### SessionRevoke (`0x97`)

Category: **principals**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `principal` | `string` | yes | — |
| `reason` | `string` | no | — |

### FileOp (`0x98`)

Category: **filechannel**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `op` | `string` | yes | — |
| `path` | `string` | yes | — |
| `offset` | `u64` | no | — |
| `length` | `u64` | no | — |

### FileResult (`0x99`)

Category: **filechannel**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `success` | `bool` | yes | — |
| `metadata` | `json` | no | `{}` |
| `error_message` | `string` | no | — |

### FileChunk (`0x9a`)

Category: **filechannel**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `offset` | `u64` | yes | — |
| `data` | `bytes` | yes | — |
| `is_final` | `bool` | yes | — |

### PolicyEval (`0x9b`)

Category: **policy**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `request_id` | `string` | yes | — |
| `action` | `string` | yes | — |
| `principal` | `string` | yes | — |
| `context` | `json` | no | `{}` |

### PolicyResult (`0x9c`)

Category: **policy**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `request_id` | `string` | yes | — |
| `allowed` | `bool` | yes | — |
| `reason` | `string` | no | — |

### PolicyUpdate (`0x9d`)

Category: **policy**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `policy_id` | `string` | yes | — |
| `rules` | `json` | yes | — |
| `version` | `u64` | yes | — |

### TerminalConfig (`0x9e`)

Category: **terminal**

> >

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `channel_id` | `u32` | yes | — |
| `frontend` | `string` | yes | — |
| `options` | `json` | no | `{}` |

## Nested Types

### AttachmentInfo

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `mode` | `string` | yes | — |
| `username` | `string` | no | — |

### PeerInfo

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `fingerprint` | `string` | yes | — |
| `fingerprint_short` | `string` | yes | — |
| `username` | `string` | yes | — |
| `capabilities` | `string[]` | no | `[]` |
| `peer_type` | `string` | no | `"host"` |
| `shell_backend` | `string` | no | `"pty"` |
| `source` | `string` | no | `"wsh-relay"` |
| `supports_attach` | `bool` | no | `false` |
| `supports_replay` | `bool` | no | `false` |
| `supports_echo` | `bool` | no | `false` |
| `supports_term_sync` | `bool` | no | `false` |
| `last_seen` | `u64` | no | — |

### McpToolSpec

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `name` | `string` | yes | — |
| `description` | `string` | yes | — |
| `parameters` | `json` | no | `{}` |

### SessionSummary

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `session_id` | `string` | yes | — |
| `name` | `string` | no | — |
| `username` | `string` | yes | — |
| `fingerprint_short` | `string` | yes | — |
| `created_at_secs` | `u64` | yes | — |
| `idle_secs` | `u64` | yes | — |
| `attached_count` | `u32` | yes | — |

## Crypto Primitives

### Auth Transcript

- **Algorithm**: SHA-256
- **Formula**: `SHA-256(PROTOCOL_VERSION || " " || session_id || nonce)`
- **Note**: channelBinding can be appended but defaults to empty

### Fingerprint

- **Algorithm**: SHA-256
- **Input**: raw_ed25519_public_key_32_bytes
- **Output**: hex_encoded_64_chars

### Session Token

- **Format**: `[8B expiry_be][32B HMAC-SHA256(secret, session_id || expiry)]`
- **Total bytes**: 40

### Key Type: Ed25519

- **SSH wire format**: `[4B len]["ssh-ed25519"][4B len][32B raw_key]`

## Transport Bindings

### WebTransport

QUIC streams as channels. 1 bidi = control. Per channel: 1 bidi + optional uni.

### WebSocket

- **Framing**: `[1B msg_type][4B stream_id][payload]`
- **WS_DATA type**: `0x60`
