//! QMux wire codec — QUIC-v1 frame encoding running directly over an
//! existing reliable, ordered, authenticated byte stream (a WebSocket
//! connection), per draft-ietf-quic-qmux-02, plus RESET_STREAM_AT from
//! draft-ietf-quic-reliable-stream-reset-09.
//!
//! Rust port of `qmux.mjs` in the `@johnhenry/wsh` npm package (the
//! canonical spec-source implementation) — see that file's doc comment
//! for the full rationale. This module is the wire codec only: varint
//! encode/decode, the QMux Record framing (`{Size varint, Frames}`),
//! and encode/decode for every frame type wsh uses. No stream state
//! machine or flow-control accounting here — see `qmux_connection`.
//!
//! Because QMux's underlying transport already guarantees in-order,
//! lossless delivery (unlike raw QUIC over UDP), this codec omits
//! everything raw QUIC needs to survive an unreliable network: packet
//! numbers, ACK frames, retransmission, and reordering/reassembly.

use std::fmt;

// ── Variable-length integer (QUIC varint, RFC 9000 §16) ────────────────

const VARINT_MAX_1: u64 = (1 << 6) - 1;
const VARINT_MAX_2: u64 = (1 << 14) - 1;
const VARINT_MAX_4: u64 = (1 << 30) - 1;
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Encode a value (must be <= 2^62-1) as a QUIC variable-length integer,
/// always using the shortest encoding that fits.
pub fn encode_varint(value: u64) -> Result<Vec<u8>, QMuxError> {
    if value > VARINT_MAX {
        return Err(QMuxError::new(
            ErrorCode::InternalError,
            "varint value exceeds the 62-bit QUIC varint range",
        ));
    }
    if value <= VARINT_MAX_1 {
        Ok(vec![value as u8])
    } else if value <= VARINT_MAX_2 {
        let v = (value as u16) | 0x4000;
        Ok(v.to_be_bytes().to_vec())
    } else if value <= VARINT_MAX_4 {
        let v = (value as u32) | 0x8000_0000;
        Ok(v.to_be_bytes().to_vec())
    } else {
        let v = value | 0xc000_0000_0000_0000;
        Ok(v.to_be_bytes().to_vec())
    }
}

/// Decode a QUIC variable-length integer at `data[offset..]`.
/// Returns `(value, bytes_consumed)`.
pub fn decode_varint(data: &[u8], offset: usize) -> Result<(u64, usize), QMuxError> {
    let first = *data
        .get(offset)
        .ok_or_else(|| QMuxError::new(ErrorCode::FrameEncodingError, "varint: no data at offset"))?;
    let len = 1usize << (first >> 6);
    if offset + len > data.len() {
        return Err(QMuxError::new(ErrorCode::FrameEncodingError, "varint: truncated"));
    }
    let value = match len {
        1 => (first & 0x3f) as u64,
        2 => {
            let mut b = [0u8; 2];
            b.copy_from_slice(&data[offset..offset + 2]);
            (u16::from_be_bytes(b) & 0x3fff) as u64
        }
        4 => {
            let mut b = [0u8; 4];
            b.copy_from_slice(&data[offset..offset + 4]);
            (u32::from_be_bytes(b) & 0x3fff_ffff) as u64
        }
        _ => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[offset..offset + 8]);
            u64::from_be_bytes(b) & 0x3fff_ffff_ffff_ffff
        }
    };
    Ok((value, len))
}

/// Number of bytes `encode_varint(value)` would produce.
pub fn varint_length(value: u64) -> usize {
    if value <= VARINT_MAX_1 {
        1
    } else if value <= VARINT_MAX_2 {
        2
    } else if value <= VARINT_MAX_4 {
        4
    } else {
        8
    }
}

// ── QUIC transport error codes (RFC 9000 §20.1, values used by wsh) ───

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    NoError,
    InternalError,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ProtocolViolation,
    ApplicationError,
    Other(u64),
}

impl ErrorCode {
    pub fn code(self) -> u64 {
        match self {
            ErrorCode::NoError => 0x00,
            ErrorCode::InternalError => 0x01,
            ErrorCode::FlowControlError => 0x03,
            ErrorCode::StreamLimitError => 0x04,
            ErrorCode::StreamStateError => 0x05,
            ErrorCode::FinalSizeError => 0x06,
            ErrorCode::FrameEncodingError => 0x07,
            ErrorCode::TransportParameterError => 0x08,
            ErrorCode::ProtocolViolation => 0x0a,
            ErrorCode::ApplicationError => 0x0c,
            ErrorCode::Other(v) => v,
        }
    }

    pub fn from_code(v: u64) -> Self {
        match v {
            0x00 => ErrorCode::NoError,
            0x01 => ErrorCode::InternalError,
            0x03 => ErrorCode::FlowControlError,
            0x04 => ErrorCode::StreamLimitError,
            0x05 => ErrorCode::StreamStateError,
            0x06 => ErrorCode::FinalSizeError,
            0x07 => ErrorCode::FrameEncodingError,
            0x08 => ErrorCode::TransportParameterError,
            0x0a => ErrorCode::ProtocolViolation,
            0x0c => ErrorCode::ApplicationError,
            other => ErrorCode::Other(other),
        }
    }
}

/// A connection-level QMux/QUIC framing violation.
#[derive(Debug, Clone)]
pub struct QMuxError {
    pub error_code: ErrorCode,
    pub message: String,
}

impl QMuxError {
    pub fn new(error_code: ErrorCode, message: impl Into<String>) -> Self {
        Self { error_code, message: message.into() }
    }
}

impl fmt::Display for QMuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (error code 0x{:02x})", self.message, self.error_code.code())
    }
}

impl std::error::Error for QMuxError {}

// ── Frame type constants ────────────────────────────────────────────

pub mod frame_type {
    pub const PADDING: u64 = 0x00;
    pub const RESET_STREAM: u64 = 0x04;
    pub const STOP_SENDING: u64 = 0x05;
    /// STREAM base type; the low 3 bits (FIN=0x01, LEN=0x02, OFF=0x04) vary per frame.
    pub const STREAM: u64 = 0x08;
    pub const MAX_DATA: u64 = 0x10;
    pub const MAX_STREAM_DATA: u64 = 0x11;
    pub const MAX_STREAMS_BIDI: u64 = 0x12;
    pub const MAX_STREAMS_UNI: u64 = 0x13;
    pub const DATA_BLOCKED: u64 = 0x14;
    pub const STREAM_DATA_BLOCKED: u64 = 0x15;
    pub const STREAMS_BLOCKED_BIDI: u64 = 0x16;
    pub const STREAMS_BLOCKED_UNI: u64 = 0x17;
    pub const CONNECTION_CLOSE_TRANSPORT: u64 = 0x1c;
    pub const CONNECTION_CLOSE_APPLICATION: u64 = 0x1d;
    /// RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-09 §3).
    pub const RESET_STREAM_AT: u64 = 0x24;
    /// DATAGRAM base type; low bit is the LEN flag (RFC 9221).
    pub const DATAGRAM: u64 = 0x30;
}

/// QX_TRANSPORT_PARAMETERS frame type -- a 62-bit constant chosen to
/// double as a protocol discriminator (draft-ietf-quic-qmux-02 §4.1).
/// Always the 8-byte varint form on the wire.
pub const QX_TRANSPORT_PARAMETERS_TYPE: u64 = 0x3f51_5330_0d0a_0d0a & 0x3fff_ffff_ffff_ffff;

// ── Transport parameters ────────────────────────────────────────────

/// Transport parameter codepoints QMux permits (draft-ietf-quic-qmux-02
/// §5.1) plus RESET_STREAM_AT's negotiation parameter and DATAGRAM's
/// (RFC 9221 §3).
pub mod transport_param_id {
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    pub const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransportParameters {
    pub max_idle_timeout: Option<u64>,
    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,
    pub max_datagram_frame_size: Option<u64>,
}

fn encode_param(id: u64, value: u64, out: &mut Vec<u8>) -> Result<(), QMuxError> {
    let value_bytes = encode_varint(value)?;
    out.extend(encode_varint(id)?);
    out.extend(encode_varint(value_bytes.len() as u64)?);
    out.extend(value_bytes);
    Ok(())
}

pub fn encode_transport_parameters(params: &TransportParameters) -> Result<Vec<u8>, QMuxError> {
    let mut body = Vec::new();
    if let Some(v) = params.max_idle_timeout {
        encode_param(transport_param_id::MAX_IDLE_TIMEOUT, v, &mut body)?;
    }
    if let Some(v) = params.initial_max_data {
        encode_param(transport_param_id::INITIAL_MAX_DATA, v, &mut body)?;
    }
    if let Some(v) = params.initial_max_stream_data_bidi_local {
        encode_param(transport_param_id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, v, &mut body)?;
    }
    if let Some(v) = params.initial_max_stream_data_bidi_remote {
        encode_param(transport_param_id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, v, &mut body)?;
    }
    if let Some(v) = params.initial_max_stream_data_uni {
        encode_param(transport_param_id::INITIAL_MAX_STREAM_DATA_UNI, v, &mut body)?;
    }
    if let Some(v) = params.initial_max_streams_bidi {
        encode_param(transport_param_id::INITIAL_MAX_STREAMS_BIDI, v, &mut body)?;
    }
    if let Some(v) = params.initial_max_streams_uni {
        encode_param(transport_param_id::INITIAL_MAX_STREAMS_UNI, v, &mut body)?;
    }
    if let Some(v) = params.max_datagram_frame_size {
        encode_param(transport_param_id::MAX_DATAGRAM_FRAME_SIZE, v, &mut body)?;
    }

    let mut out = Vec::new();
    out.extend(encode_varint(QX_TRANSPORT_PARAMETERS_TYPE)?);
    out.extend(encode_varint(body.len() as u64)?);
    out.extend(body);
    Ok(out)
}

fn decode_transport_parameters(data: &[u8]) -> Result<TransportParameters, QMuxError> {
    let mut params = TransportParameters::default();
    let mut offset = 0;
    while offset < data.len() {
        let (id, id_len) = decode_varint(data, offset)?;
        offset += id_len;
        let (len, len_len) = decode_varint(data, offset)?;
        offset += len_len;
        let value_bytes = data
            .get(offset..offset + len as usize)
            .ok_or_else(|| QMuxError::new(ErrorCode::FrameEncodingError, "transport parameter value truncated"))?;
        offset += len as usize;

        let value = if value_bytes.is_empty() { None } else { Some(decode_varint(value_bytes, 0)?.0) };

        match id {
            transport_param_id::MAX_IDLE_TIMEOUT => params.max_idle_timeout = value,
            transport_param_id::INITIAL_MAX_DATA => params.initial_max_data = value,
            transport_param_id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => params.initial_max_stream_data_bidi_local = value,
            transport_param_id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => params.initial_max_stream_data_bidi_remote = value,
            transport_param_id::INITIAL_MAX_STREAM_DATA_UNI => params.initial_max_stream_data_uni = value,
            transport_param_id::INITIAL_MAX_STREAMS_BIDI => params.initial_max_streams_bidi = value,
            transport_param_id::INITIAL_MAX_STREAMS_UNI => params.initial_max_streams_uni = value,
            transport_param_id::MAX_DATAGRAM_FRAME_SIZE => params.max_datagram_frame_size = value,
            _ => {} // unknown parameter codepoints are ignored (forward compatibility)
        }
    }
    Ok(params)
}

// ── QMux Record framing ─────────────────────────────────────────────

/// Wrap already-encoded frame bytes in a QMux Record: `{Size varint, Frames}`.
pub fn encode_record(frames_bytes: &[u8]) -> Result<Vec<u8>, QMuxError> {
    let mut out = encode_varint(frames_bytes.len() as u64)?;
    out.extend_from_slice(frames_bytes);
    Ok(out)
}

/// Incrementally accumulates bytes from the underlying transport and
/// yields complete QMux Records (the raw Frames bytes, not yet parsed
/// into individual frames).
#[derive(Debug, Default)]
pub struct RecordDecoder {
    buffer: Vec<u8>,
}

impl RecordDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, QMuxError> {
        self.buffer.extend_from_slice(chunk);
        let mut records = Vec::new();

        loop {
            let (size, size_len) = match decode_varint(&self.buffer, 0) {
                Ok(v) => v,
                Err(_) => break, // not enough bytes yet for the Size varint
            };
            let total = size_len + size as usize;
            if self.buffer.len() < total {
                break;
            }
            records.push(self.buffer[size_len..total].to_vec());
            self.buffer.drain(..total);
        }
        Ok(records)
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
    }
}

// ── Decoded frame representation ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding,
    ResetStream { stream_id: u64, error_code: u64, final_size: u64 },
    ResetStreamAt { stream_id: u64, error_code: u64, final_size: u64, reliable_size: u64 },
    StopSending { stream_id: u64, error_code: u64 },
    Stream { stream_id: u64, offset: u64, data: Vec<u8>, fin: bool },
    MaxData { max_data: u64 },
    MaxStreamData { stream_id: u64, max_stream_data: u64 },
    MaxStreams { unidirectional: bool, max_streams: u64 },
    DataBlocked { data_limit: u64 },
    StreamDataBlocked { stream_id: u64, stream_data_limit: u64 },
    StreamsBlocked { unidirectional: bool, stream_limit: u64 },
    ConnectionClose { application: bool, error_code: u64, close_frame_type: Option<u64>, reason: String },
    Datagram { data: Vec<u8> },
    QxTransportParameters { params: TransportParameters },
}

// ── Frame encoders ───────────────────────────────────────────────────

pub fn encode_reset_stream(stream_id: u64, error_code: ErrorCode, final_size: u64) -> Result<Vec<u8>, QMuxError> {
    let mut out = encode_varint(frame_type::RESET_STREAM)?;
    out.extend(encode_varint(stream_id)?);
    out.extend(encode_varint(error_code.code())?);
    out.extend(encode_varint(final_size)?);
    Ok(out)
}

pub fn encode_reset_stream_at(stream_id: u64, error_code: ErrorCode, final_size: u64, reliable_size: u64) -> Result<Vec<u8>, QMuxError> {
    let mut out = encode_varint(frame_type::RESET_STREAM_AT)?;
    out.extend(encode_varint(stream_id)?);
    out.extend(encode_varint(error_code.code())?);
    out.extend(encode_varint(final_size)?);
    out.extend(encode_varint(reliable_size)?);
    Ok(out)
}

pub fn encode_stop_sending(stream_id: u64, error_code: ErrorCode) -> Result<Vec<u8>, QMuxError> {
    let mut out = encode_varint(frame_type::STOP_SENDING)?;
    out.extend(encode_varint(stream_id)?);
    out.extend(encode_varint(error_code.code())?);
    Ok(out)
}

/// Offset and Length are always included (OFF=1, LEN=1) -- QMux Records
/// already delimit frame boundaries, so omitting Length saves nothing
/// the way it can in a raw QUIC packet.
pub fn encode_stream(stream_id: u64, offset: u64, data: &[u8], fin: bool) -> Result<Vec<u8>, QMuxError> {
    let flags: u64 = 0x02 /* LEN */ | 0x04 /* OFF */ | if fin { 0x01 } else { 0x00 };
    let mut out = encode_varint(frame_type::STREAM | flags)?;
    out.extend(encode_varint(stream_id)?);
    out.extend(encode_varint(offset)?);
    out.extend(encode_varint(data.len() as u64)?);
    out.extend_from_slice(data);
    Ok(out)
}

pub fn encode_max_data(max_data: u64) -> Result<Vec<u8>, QMuxError> {
    let mut out = encode_varint(frame_type::MAX_DATA)?;
    out.extend(encode_varint(max_data)?);
    Ok(out)
}

pub fn encode_max_stream_data(stream_id: u64, max_stream_data: u64) -> Result<Vec<u8>, QMuxError> {
    let mut out = encode_varint(frame_type::MAX_STREAM_DATA)?;
    out.extend(encode_varint(stream_id)?);
    out.extend(encode_varint(max_stream_data)?);
    Ok(out)
}

pub fn encode_max_streams(unidirectional: bool, max_streams: u64) -> Result<Vec<u8>, QMuxError> {
    let ty = if unidirectional { frame_type::MAX_STREAMS_UNI } else { frame_type::MAX_STREAMS_BIDI };
    let mut out = encode_varint(ty)?;
    out.extend(encode_varint(max_streams)?);
    Ok(out)
}

pub fn encode_data_blocked(data_limit: u64) -> Result<Vec<u8>, QMuxError> {
    let mut out = encode_varint(frame_type::DATA_BLOCKED)?;
    out.extend(encode_varint(data_limit)?);
    Ok(out)
}

pub fn encode_stream_data_blocked(stream_id: u64, stream_data_limit: u64) -> Result<Vec<u8>, QMuxError> {
    let mut out = encode_varint(frame_type::STREAM_DATA_BLOCKED)?;
    out.extend(encode_varint(stream_id)?);
    out.extend(encode_varint(stream_data_limit)?);
    Ok(out)
}

pub fn encode_streams_blocked(unidirectional: bool, stream_limit: u64) -> Result<Vec<u8>, QMuxError> {
    let ty = if unidirectional { frame_type::STREAMS_BLOCKED_UNI } else { frame_type::STREAMS_BLOCKED_BIDI };
    let mut out = encode_varint(ty)?;
    out.extend(encode_varint(stream_limit)?);
    Ok(out)
}

pub fn encode_connection_close(application: bool, error_code: u64, frame_type_val: Option<u64>, reason: &str) -> Result<Vec<u8>, QMuxError> {
    let reason_bytes = reason.as_bytes();
    let mut out = encode_varint(if application { frame_type::CONNECTION_CLOSE_APPLICATION } else { frame_type::CONNECTION_CLOSE_TRANSPORT })?;
    out.extend(encode_varint(error_code)?);
    if !application {
        out.extend(encode_varint(frame_type_val.unwrap_or(0))?);
    }
    out.extend(encode_varint(reason_bytes.len() as u64)?);
    out.extend_from_slice(reason_bytes);
    Ok(out)
}

pub fn encode_datagram(data: &[u8]) -> Result<Vec<u8>, QMuxError> {
    let mut out = encode_varint(frame_type::DATAGRAM | 0x01)?;
    out.extend(encode_varint(data.len() as u64)?);
    out.extend_from_slice(data);
    Ok(out)
}

// ── Frame decoder ─────────────────────────────────────────────────────

/// Decode every frame in a Frames payload (the contents of one QMux
/// Record). Returns the first malformed frame as an error -- per QMux,
/// a malformed frame is a connection-level protocol error, not a
/// recoverable one.
pub fn decode_frames(data: &[u8]) -> Result<Vec<Frame>, QMuxError> {
    let mut frames = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let (raw_type, type_len) = decode_varint(data, offset)?;
        offset += type_len;

        if raw_type == QX_TRANSPORT_PARAMETERS_TYPE {
            let (len, len_len) = decode_varint(data, offset)?;
            offset += len_len;
            let params_bytes = data
                .get(offset..offset + len as usize)
                .ok_or_else(|| QMuxError::new(ErrorCode::FrameEncodingError, "QX_TRANSPORT_PARAMETERS truncated"))?;
            offset += len as usize;
            frames.push(Frame::QxTransportParameters { params: decode_transport_parameters(params_bytes)? });
            continue;
        }

        // STREAM frames occupy the type range 0x08-0x0f (base 0x08 | 3 flag bits).
        if (0x08..=0x0f).contains(&raw_type) {
            let fin = raw_type & 0x01 != 0;
            let has_len = raw_type & 0x02 != 0;
            let has_off = raw_type & 0x04 != 0;

            let (stream_id, sid_len) = decode_varint(data, offset)?;
            offset += sid_len;

            let mut stream_offset = 0u64;
            if has_off {
                let (off, off_len) = decode_varint(data, offset)?;
                offset += off_len;
                stream_offset = off;
            }

            let length = if has_len {
                let (len, len_len) = decode_varint(data, offset)?;
                offset += len_len;
                len as usize
            } else {
                data.len() - offset
            };

            let stream_data = data
                .get(offset..offset + length)
                .ok_or_else(|| QMuxError::new(ErrorCode::FrameEncodingError, "STREAM frame data truncated"))?
                .to_vec();
            offset += length;

            frames.push(Frame::Stream { stream_id, offset: stream_offset, data: stream_data, fin });
            continue;
        }

        // DATAGRAM frames occupy 0x30-0x31 (base 0x30 | 1 LEN flag bit).
        if raw_type == frame_type::DATAGRAM || raw_type == (frame_type::DATAGRAM | 0x01) {
            let has_len = raw_type & 0x01 != 0;
            let length = if has_len {
                let (len, len_len) = decode_varint(data, offset)?;
                offset += len_len;
                len as usize
            } else {
                data.len() - offset
            };
            let payload = data
                .get(offset..offset + length)
                .ok_or_else(|| QMuxError::new(ErrorCode::FrameEncodingError, "DATAGRAM frame data truncated"))?
                .to_vec();
            offset += length;
            frames.push(Frame::Datagram { data: payload });
            continue;
        }

        match raw_type {
            frame_type::PADDING => {
                frames.push(Frame::Padding);
            }
            frame_type::RESET_STREAM => {
                let (stream_id, l1) = decode_varint(data, offset)?; offset += l1;
                let (error_code, l2) = decode_varint(data, offset)?; offset += l2;
                let (final_size, l3) = decode_varint(data, offset)?; offset += l3;
                frames.push(Frame::ResetStream { stream_id, error_code, final_size });
            }
            frame_type::RESET_STREAM_AT => {
                let (stream_id, l1) = decode_varint(data, offset)?; offset += l1;
                let (error_code, l2) = decode_varint(data, offset)?; offset += l2;
                let (final_size, l3) = decode_varint(data, offset)?; offset += l3;
                let (reliable_size, l4) = decode_varint(data, offset)?; offset += l4;
                if reliable_size > final_size {
                    return Err(QMuxError::new(ErrorCode::FrameEncodingError, "RESET_STREAM_AT: reliableSize > finalSize"));
                }
                frames.push(Frame::ResetStreamAt { stream_id, error_code, final_size, reliable_size });
            }
            frame_type::STOP_SENDING => {
                let (stream_id, l1) = decode_varint(data, offset)?; offset += l1;
                let (error_code, l2) = decode_varint(data, offset)?; offset += l2;
                frames.push(Frame::StopSending { stream_id, error_code });
            }
            frame_type::MAX_DATA => {
                let (max_data, l1) = decode_varint(data, offset)?; offset += l1;
                frames.push(Frame::MaxData { max_data });
            }
            frame_type::MAX_STREAM_DATA => {
                let (stream_id, l1) = decode_varint(data, offset)?; offset += l1;
                let (max_stream_data, l2) = decode_varint(data, offset)?; offset += l2;
                frames.push(Frame::MaxStreamData { stream_id, max_stream_data });
            }
            frame_type::MAX_STREAMS_BIDI | frame_type::MAX_STREAMS_UNI => {
                let (max_streams, l1) = decode_varint(data, offset)?; offset += l1;
                frames.push(Frame::MaxStreams { unidirectional: raw_type == frame_type::MAX_STREAMS_UNI, max_streams });
            }
            frame_type::DATA_BLOCKED => {
                let (data_limit, l1) = decode_varint(data, offset)?; offset += l1;
                frames.push(Frame::DataBlocked { data_limit });
            }
            frame_type::STREAM_DATA_BLOCKED => {
                let (stream_id, l1) = decode_varint(data, offset)?; offset += l1;
                let (stream_data_limit, l2) = decode_varint(data, offset)?; offset += l2;
                frames.push(Frame::StreamDataBlocked { stream_id, stream_data_limit });
            }
            frame_type::STREAMS_BLOCKED_BIDI | frame_type::STREAMS_BLOCKED_UNI => {
                let (stream_limit, l1) = decode_varint(data, offset)?; offset += l1;
                frames.push(Frame::StreamsBlocked { unidirectional: raw_type == frame_type::STREAMS_BLOCKED_UNI, stream_limit });
            }
            frame_type::CONNECTION_CLOSE_TRANSPORT | frame_type::CONNECTION_CLOSE_APPLICATION => {
                let application = raw_type == frame_type::CONNECTION_CLOSE_APPLICATION;
                let (error_code, l1) = decode_varint(data, offset)?; offset += l1;
                let mut close_frame_type = None;
                if !application {
                    let (ft, l2) = decode_varint(data, offset)?; offset += l2;
                    close_frame_type = Some(ft);
                }
                let (reason_len, l3) = decode_varint(data, offset)?; offset += l3;
                let reason_bytes = data
                    .get(offset..offset + reason_len as usize)
                    .ok_or_else(|| QMuxError::new(ErrorCode::FrameEncodingError, "CONNECTION_CLOSE reason truncated"))?;
                offset += reason_len as usize;
                frames.push(Frame::ConnectionClose {
                    application,
                    error_code,
                    close_frame_type,
                    reason: String::from_utf8_lossy(reason_bytes).into_owned(),
                });
            }
            other => {
                return Err(QMuxError::new(
                    ErrorCode::FrameEncodingError,
                    format!("unknown/prohibited frame type: 0x{other:x}"),
                ));
            }
        }
    }

    Ok(frames)
}

// ── Stream ID helpers (RFC 9000 §2.1) ───────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamInitiator {
    Client,
    Server,
}

impl StreamInitiator {
    fn bit(self) -> u64 {
        match self {
            StreamInitiator::Client => 0,
            StreamInitiator::Server => 1,
        }
    }
}

pub fn is_client_initiated(stream_id: u64) -> bool {
    stream_id & 0x01 == 0
}

pub fn is_bidirectional(stream_id: u64) -> bool {
    stream_id & 0x02 == 0
}

/// First bidirectional stream ID for the given initiator.
pub fn first_bidi_stream_id(initiator: StreamInitiator) -> u64 {
    initiator.bit()
}

/// Next bidirectional stream ID after `id` for the same initiator (+4).
pub fn next_bidi_stream_id(id: u64) -> u64 {
    id + 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_matches_rfc9000_appendix_a1_worked_examples_byte_for_byte() {
        assert_eq!(encode_varint(37).unwrap(), vec![0x25]);
        assert_eq!(encode_varint(15293).unwrap(), vec![0x7b, 0xbd]);
        assert_eq!(encode_varint(494878333).unwrap(), vec![0x9d, 0x7f, 0x3e, 0x7d]);
    }

    #[test]
    fn varint_round_trips_at_and_around_every_length_class_boundary() {
        for v in [0u64, 1, 63, 64, 65, 16383, 16384, 16385, 1073741823, 1073741824, 1073741825] {
            let enc = encode_varint(v).unwrap();
            let (value, length) = decode_varint(&enc, 0).unwrap();
            assert_eq!(length, enc.len(), "length mismatch for {v}");
            assert_eq!(value, v, "value mismatch for {v}");
        }
    }

    #[test]
    fn varint_round_trips_the_maximum_62_bit_value() {
        let enc = encode_varint(VARINT_MAX).unwrap();
        assert_eq!(enc.len(), 8);
        let (value, _) = decode_varint(&enc, 0).unwrap();
        assert_eq!(value, VARINT_MAX);
    }

    #[test]
    fn varint_rejects_values_above_the_62_bit_range() {
        assert!(encode_varint(VARINT_MAX + 1).is_err());
    }

    #[test]
    fn varint_decode_errors_on_truncated_input_rather_than_panicking() {
        // 0xc0 prefix claims an 8-byte value but only 3 bytes are present.
        assert!(decode_varint(&[0xc0, 0x01, 0x02], 0).is_err());
    }

    #[test]
    fn varint_length_matches_actual_encoded_length_for_boundary_values() {
        for v in [0u64, 63, 64, 16383, 16384, 1073741823, 1073741824] {
            assert_eq!(varint_length(v), encode_varint(v).unwrap().len());
        }
    }

    #[test]
    fn varint_decodes_at_a_nonzero_offset_without_disturbing_preceding_bytes() {
        let mut buf = vec![0xff, 0xff];
        buf.extend(encode_varint(15293).unwrap());
        let (value, length) = decode_varint(&buf, 2).unwrap();
        assert_eq!(value, 15293);
        assert_eq!(length, 2);
    }

    #[test]
    fn record_encode_prefixes_frames_bytes_with_their_varint_length() {
        let frames = vec![1, 2, 3, 4, 5];
        let record = encode_record(&frames).unwrap();
        assert_eq!(record[0], 5); // 1-byte varint for size 5
        assert_eq!(&record[1..], &frames[..]);
    }

    #[test]
    fn record_decoder_yields_nothing_until_a_full_record_has_arrived() {
        let mut decoder = RecordDecoder::new();
        let record = encode_record(&[9, 9, 9]).unwrap();

        assert!(decoder.feed(&record[0..2]).unwrap().is_empty());
        let out = decoder.feed(&record[2..]).unwrap();
        assert_eq!(out, vec![vec![9, 9, 9]]);
    }

    #[test]
    fn record_decoder_yields_multiple_records_fed_in_a_single_chunk_in_order() {
        let mut decoder = RecordDecoder::new();
        let r1 = encode_record(&[1]).unwrap();
        let r2 = encode_record(&[2, 2]).unwrap();
        let r3 = encode_record(&[3, 3, 3]).unwrap();
        let mut combined = Vec::new();
        combined.extend(r1);
        combined.extend(r2);
        combined.extend(r3);

        let out = decoder.feed(&combined).unwrap();
        assert_eq!(out, vec![vec![1], vec![2, 2], vec![3, 3, 3]]);
    }

    #[test]
    fn record_decoder_handles_a_record_split_byte_by_byte_across_many_feeds() {
        let mut decoder = RecordDecoder::new();
        let record = encode_record(&[7, 7, 7, 7]).unwrap();
        let mut out = Vec::new();
        for i in 0..record.len() - 1 {
            out.extend(decoder.feed(&record[i..i + 1]).unwrap());
        }
        assert!(out.is_empty());
        out.extend(decoder.feed(&record[record.len() - 1..]).unwrap());
        assert_eq!(out, vec![vec![7, 7, 7, 7]]);
    }

    #[test]
    fn a_large_frames_payload_uses_a_multi_byte_size_varint_correctly() {
        let mut decoder = RecordDecoder::new();
        let payload = vec![0xabu8; 20000];
        let record = encode_record(&payload).unwrap();
        assert_eq!(record[0] >> 6, 0b10); // 4-byte varint prefix (20000 > 16383)
        let out = decoder.feed(&record).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 20000);
    }

    #[test]
    fn record_decoder_reset_discards_any_partially_buffered_record() {
        let mut decoder = RecordDecoder::new();
        let record = encode_record(&[1, 2, 3]).unwrap();
        decoder.feed(&record[0..2]).unwrap();
        decoder.reset();
        let out = decoder.feed(&record).unwrap();
        assert_eq!(out, vec![vec![1, 2, 3]]);
    }

    #[test]
    fn stream_frame_type_byte_encodes_fin_len_off_flags_correctly() {
        let data = vec![65, 66, 67];
        let encoded = encode_stream(4, 10, &data, true).unwrap();
        let frames = decode_frames(&encoded).unwrap();
        assert_eq!(frames, vec![Frame::Stream { stream_id: 4, offset: 10, data: data.clone(), fin: true }]);
        // First byte: 0x08 (STREAM) | 0x01 (FIN) | 0x02 (LEN) | 0x04 (OFF) = 0x0f
        assert_eq!(encoded[0], 0x0f);
    }

    #[test]
    fn stream_frame_without_fin() {
        let encoded = encode_stream(0, 0, &[1], false).unwrap();
        let frames = decode_frames(&encoded).unwrap();
        assert_eq!(frames, vec![Frame::Stream { stream_id: 0, offset: 0, data: vec![1], fin: false }]);
    }

    #[test]
    fn reset_stream_round_trip() {
        let encoded = encode_reset_stream(4, ErrorCode::InternalError, 100).unwrap();
        let frames = decode_frames(&encoded).unwrap();
        assert_eq!(frames, vec![Frame::ResetStream { stream_id: 4, error_code: 1, final_size: 100 }]);
    }

    #[test]
    fn reset_stream_at_round_trip() {
        let encoded = encode_reset_stream_at(8, ErrorCode::NoError, 1000, 400).unwrap();
        let frames = decode_frames(&encoded).unwrap();
        assert_eq!(frames, vec![Frame::ResetStreamAt { stream_id: 8, error_code: 0, final_size: 1000, reliable_size: 400 }]);
    }

    #[test]
    fn reset_stream_at_with_reliable_size_gt_final_size_is_rejected() {
        let encoded = encode_reset_stream_at(8, ErrorCode::NoError, 10, 20).unwrap();
        let err = decode_frames(&encoded).unwrap_err();
        assert_eq!(err.error_code, ErrorCode::FrameEncodingError);
    }

    #[test]
    fn stop_sending_round_trip() {
        let encoded = encode_stop_sending(12, ErrorCode::ApplicationError).unwrap();
        let frames = decode_frames(&encoded).unwrap();
        assert_eq!(frames, vec![Frame::StopSending { stream_id: 12, error_code: 0x0c }]);
    }

    #[test]
    fn max_data_round_trip() {
        let encoded = encode_max_data(65536).unwrap();
        assert_eq!(decode_frames(&encoded).unwrap(), vec![Frame::MaxData { max_data: 65536 }]);
    }

    #[test]
    fn max_stream_data_round_trip() {
        let encoded = encode_max_stream_data(4, 32768).unwrap();
        assert_eq!(decode_frames(&encoded).unwrap(), vec![Frame::MaxStreamData { stream_id: 4, max_stream_data: 32768 }]);
    }

    #[test]
    fn max_streams_round_trip_bidi_and_uni_use_distinct_type_bytes() {
        let bidi = encode_max_streams(false, 10).unwrap();
        let uni = encode_max_streams(true, 5).unwrap();
        assert_ne!(bidi[0], uni[0]);
        assert_eq!(decode_frames(&bidi).unwrap(), vec![Frame::MaxStreams { unidirectional: false, max_streams: 10 }]);
        assert_eq!(decode_frames(&uni).unwrap(), vec![Frame::MaxStreams { unidirectional: true, max_streams: 5 }]);
    }

    #[test]
    fn data_blocked_round_trip() {
        let encoded = encode_data_blocked(1000).unwrap();
        assert_eq!(decode_frames(&encoded).unwrap(), vec![Frame::DataBlocked { data_limit: 1000 }]);
    }

    #[test]
    fn stream_data_blocked_round_trip() {
        let encoded = encode_stream_data_blocked(4, 500).unwrap();
        assert_eq!(decode_frames(&encoded).unwrap(), vec![Frame::StreamDataBlocked { stream_id: 4, stream_data_limit: 500 }]);
    }

    #[test]
    fn streams_blocked_round_trip_bidi_and_uni_use_distinct_type_bytes() {
        let bidi = encode_streams_blocked(false, 3).unwrap();
        let uni = encode_streams_blocked(true, 2).unwrap();
        assert_ne!(bidi[0], uni[0]);
        assert_eq!(decode_frames(&bidi).unwrap(), vec![Frame::StreamsBlocked { unidirectional: false, stream_limit: 3 }]);
    }

    #[test]
    fn connection_close_transport_round_trip_includes_the_triggering_frame_type() {
        let encoded = encode_connection_close(false, ErrorCode::ProtocolViolation.code(), Some(frame_type::STREAM), "bad stream order").unwrap();
        let frames = decode_frames(&encoded).unwrap();
        assert_eq!(frames, vec![Frame::ConnectionClose {
            application: false,
            error_code: 0x0a,
            close_frame_type: Some(frame_type::STREAM),
            reason: "bad stream order".to_string(),
        }]);
    }

    #[test]
    fn connection_close_application_round_trip_omits_the_frame_type_field() {
        let encoded = encode_connection_close(true, 5, None, "bye").unwrap();
        let frames = decode_frames(&encoded).unwrap();
        match &frames[0] {
            Frame::ConnectionClose { application, close_frame_type, reason, .. } => {
                assert!(*application);
                assert_eq!(*close_frame_type, None);
                assert_eq!(reason, "bye");
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[test]
    fn connection_close_with_empty_reason_round_trips_to_empty_string() {
        let encoded = encode_connection_close(true, 0, None, "").unwrap();
        match &decode_frames(&encoded).unwrap()[0] {
            Frame::ConnectionClose { reason, .. } => assert_eq!(reason, ""),
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[test]
    fn datagram_round_trip() {
        let data = vec![1, 2, 3, 4, 5];
        let encoded = encode_datagram(&data).unwrap();
        assert_eq!(decode_frames(&encoded).unwrap(), vec![Frame::Datagram { data }]);
    }

    #[test]
    fn qx_transport_parameters_round_trip_carries_only_recognized_parameters() {
        let params = TransportParameters {
            initial_max_data: Some(1_000_000),
            initial_max_stream_data_bidi_local: Some(65536),
            initial_max_streams_bidi: Some(100),
            max_datagram_frame_size: Some(1200),
            ..Default::default()
        };
        let encoded = encode_transport_parameters(&params).unwrap();
        let frames = decode_frames(&encoded).unwrap();
        match &frames[0] {
            Frame::QxTransportParameters { params: decoded } => assert_eq!(decoded, &params),
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[test]
    fn qx_transport_parameters_type_varint_is_always_the_full_8_byte_form() {
        let params = TransportParameters { initial_max_data: Some(1), ..Default::default() };
        let encoded = encode_transport_parameters(&params).unwrap();
        assert_eq!(encoded[0] >> 6, 0b11);
        assert!(encoded.len() >= 8);
    }

    #[test]
    fn multiple_frames_concatenated_in_one_frames_payload_decode_in_order() {
        let mut combined = Vec::new();
        combined.extend(encode_max_data(100).unwrap());
        combined.extend(encode_stream(0, 0, &[1, 2], false).unwrap());
        combined.extend(encode_stop_sending(4, ErrorCode::NoError).unwrap());

        let frames = decode_frames(&combined).unwrap();
        assert_eq!(frames.len(), 3);
        assert!(matches!(frames[0], Frame::MaxData { .. }));
        assert!(matches!(frames[1], Frame::Stream { .. }));
        assert!(matches!(frames[2], Frame::StopSending { .. }));
    }

    #[test]
    fn an_unknown_prohibited_frame_type_errors_with_frame_encoding_error() {
        // 0x06 is CRYPTO -- a QMux-prohibited frame type.
        let err = decode_frames(&[0x06]).unwrap_err();
        assert_eq!(err.error_code, ErrorCode::FrameEncodingError);
    }

    #[test]
    fn stream_id_helpers_classify_initiator_and_directionality() {
        assert!(is_client_initiated(0));
        assert!(!is_client_initiated(1));
        assert!(is_bidirectional(0));
        assert!(!is_bidirectional(2));
    }

    #[test]
    fn client_and_server_bidi_streams_start_at_0_and_1_and_increment_by_4() {
        let mut id = first_bidi_stream_id(StreamInitiator::Client);
        assert_eq!(id, 0);
        id = next_bidi_stream_id(id);
        assert_eq!(id, 4);
        id = next_bidi_stream_id(id);
        assert_eq!(id, 8);

        let mut server_id = first_bidi_stream_id(StreamInitiator::Server);
        assert_eq!(server_id, 1);
        server_id = next_bidi_stream_id(server_id);
        assert_eq!(server_id, 5);
    }
}
