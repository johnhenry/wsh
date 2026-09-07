//! Stream-mode chunk framing for wsh's opt-in end-to-end encryption layer
//! (see `session.rs`'s `WshSession::enable_e2e`, which accepts stream-backed
//! sessions -- this module supplies the framing wrapper that makes that
//! possible; the AEAD primitives themselves live in `crate::e2e_frame` and
//! are reused unchanged).
//!
//! This is PR 2 of 3 in the stream-mode E2E rollout (wsh #22, follow-up to
//! the virtual-mode rollout in #19). PR 1 shipped the JS side
//! (`@johnhenry/wsh`'s `src/stream-frame.mjs`, published as 0.16.0), which
//! this module mirrors byte-for-byte -- see that file's doc comment for the
//! full design; the short version is reproduced below.
//!
//! ── Why framing is needed at all ────────────────────────────────────────
//! Stream-mode sessions are raw byte streams with no message boundaries.
//! Virtual-mode reuses the control-message envelope (`EncryptedFrame`) to
//! carry one sealed frame per `SessionData` 1:1, but a byte stream has no
//! such envelope -- a single `read()` may return a partial chunk, multiple
//! chunks, or a chunk split across two reads. [`ChunkAccumulator`] restores
//! chunk boundaries on the read side; [`encode_chunk`] builds them on the
//! write side.
//!
//! ── Wire format ──────────────────────────────────────────────────────────
//!
//!   `[ 4-byte big-endian length prefix N ][ 12-byte nonce ][ N bytes: ciphertext + 16-byte GCM tag ]`
//!
//! - `N` counts only the ciphertext+tag bytes that follow the nonce (the
//!   nonce itself is a fixed 12-byte wire constant, not counted -- avoids an
//!   off-by-12 footgun).
//! - The nonce is 12 bytes, clear (not secret), and uses the same
//!   `[8-byte big-endian counter][4-byte role tag]` layout as virtual-mode
//!   (see `crate::e2e_frame::build_nonce`) -- a stream "chunk index" is
//!   exactly the same thing as virtual-mode's "message counter".
//! - The length field is NOT bound as AEAD additional authenticated data:
//!   there's no tampering scenario it prevents that the GCM tag doesn't
//!   already catch.
//! - Chunk size: soft target ~16 KiB plaintext, hard cap 64 KiB. See
//!   [`resolve_coalesce_options`] for how writes are batched up to (well
//!   below) that cap before sealing.
//!
//! ── Failure modes at stream end ────────────────────────────────────────
//! [`ChunkAccumulator`] distinguishes:
//!  1. Clean EOF -- buffer empty when `finish()` is called.
//!  2. Torn chunk -- partial bytes buffered (not enough for a complete
//!     chunk) when `finish()` is called -- `finish()` returns an error.
//!  3. Failed AEAD authentication on an otherwise-complete chunk -- this is
//!     *not* raised by this module (it has no key); callers use
//!     `crate::e2e_frame::open_frame`'s error (see `session.rs`'s stream
//!     read path) to report it. Mirrors the JS side's distinction between
//!     `StreamTornChunkError` and `StreamAuthenticationError`; this crate
//!     reuses `WshError::Other` for both cases rather than adding new
//!     variants, matching `crate::e2e_frame`'s existing error-handling
//!     convention.
//!
//! No partial-chunk plaintext is ever released in any case.
//!
//! ── Efficiency note ───────────────────────────────────────────────────
//! [`ChunkAccumulator`] uses a cursor-based internal buffer (append via an
//! amortized-doubling growable `Vec<u8>`, consume via advancing a read
//! offset) rather than repeatedly re-slicing the whole buffer on every
//! `feed()` call, which would go quadratic under many small reads. The only
//! per-chunk copies are for the two pieces (`nonce`, `ciphertext`) actually
//! handed back to the caller.

use wsh_core::error::{WshError, WshResult};
use wsh_core::messages::ChannelKind;

const LENGTH_PREFIX_BYTES: usize = 4;
const NONCE_BYTES: usize = crate::e2e_frame::NONCE_LENGTH;
const GCM_TAG_BYTES: usize = 16;

/// Soft target plaintext chunk size (see module doc comment).
pub const CHUNK_SOFT_TARGET_BYTES: usize = 16 * 1024;

/// Hard cap on plaintext chunk size; ciphertext+tag never exceeds this + 16.
pub const CHUNK_HARD_CAP_BYTES: usize = 64 * 1024;

/// Sanity bound on the wire length prefix, used only to fail fast on an
/// obviously-corrupt/malicious length field rather than buffering
/// unboundedly while waiting for a chunk that will never complete.
/// Generous headroom above [`CHUNK_HARD_CAP_BYTES`] so a legitimate sender
/// is never rejected.
const MAX_WIRE_CIPHERTEXT_BYTES: usize = CHUNK_HARD_CAP_BYTES + GCM_TAG_BYTES;

/// Encode one sealed chunk for the wire: `[len][nonce][ciphertext]`.
///
/// `nonce` must be exactly [`crate::e2e_frame::NONCE_LENGTH`] bytes.
pub fn encode_chunk(nonce: &[u8], ciphertext: &[u8]) -> WshResult<Vec<u8>> {
    if nonce.len() != NONCE_BYTES {
        return Err(WshError::Other(format!(
            "stream-frame: nonce must be {NONCE_BYTES} bytes, got {}",
            nonce.len()
        )));
    }
    let mut out = Vec::with_capacity(LENGTH_PREFIX_BYTES + NONCE_BYTES + ciphertext.len());
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

/// Reassembles a raw byte stream into complete `(nonce, ciphertext)` chunks.
/// See the module doc comment for the wire format and the efficiency note
/// on the internal buffer strategy.
#[derive(Default)]
pub struct ChunkAccumulator {
    buf: Vec<u8>,
    /// Read cursor -- bytes before this offset are already consumed.
    start: usize,
    /// Write cursor -- bytes before this offset are valid buffered data.
    end: usize,
}

impl ChunkAccumulator {
    /// Create an empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed newly-read bytes in and pull out every complete chunk now
    /// available, in order. Any trailing partial chunk stays buffered for
    /// the next `feed()` call.
    pub fn feed(&mut self, bytes: &[u8]) -> WshResult<Vec<(Vec<u8>, Vec<u8>)>> {
        if !bytes.is_empty() {
            self.append(bytes);
        }
        let mut chunks = Vec::new();
        while let Some(chunk) = self.try_parse_one()? {
            chunks.push(chunk);
        }
        // Once fully drained, reset cursors so the buffer doesn't retain a
        // large-but-empty backing allocation indefinitely.
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
            self.buf.clear();
        }
        Ok(chunks)
    }

    /// Call at clean stream EOF. Returns an error if partial chunk bytes
    /// are still buffered (a truncated stream); otherwise a no-op.
    pub fn finish(&self) -> WshResult<()> {
        let remaining = self.end - self.start;
        if remaining > 0 {
            return Err(WshError::Other(format!(
                "stream-frame: stream ended with {remaining} torn (incomplete) chunk bytes buffered"
            )));
        }
        Ok(())
    }

    fn append(&mut self, bytes: &[u8]) {
        let live_length = self.end - self.start;
        let needed = live_length + bytes.len();
        if needed > self.buf.len().saturating_sub(self.start) {
            // Grow (and compact away already-consumed prefix bytes) with
            // amortized doubling, so repeated small feed() calls stay
            // linear overall rather than re-copying the whole live region
            // every time.
            let new_capacity = needed.max(self.buf.len() * 2).max(4096);
            let mut new_buf = vec![0_u8; new_capacity];
            new_buf[..live_length].copy_from_slice(&self.buf[self.start..self.end]);
            self.buf = new_buf;
            self.end = live_length;
            self.start = 0;
        }
        self.buf[self.end..self.end + bytes.len()].copy_from_slice(bytes);
        self.end += bytes.len();
    }

    fn try_parse_one(&mut self) -> WshResult<Option<(Vec<u8>, Vec<u8>)>> {
        let available = self.end - self.start;
        if available < LENGTH_PREFIX_BYTES + NONCE_BYTES {
            return Ok(None);
        }
        let n = u32::from_be_bytes([
            self.buf[self.start],
            self.buf[self.start + 1],
            self.buf[self.start + 2],
            self.buf[self.start + 3],
        ]) as usize;
        if n > MAX_WIRE_CIPHERTEXT_BYTES {
            return Err(WshError::Other(format!(
                "stream-frame: chunk length {n} exceeds max {MAX_WIRE_CIPHERTEXT_BYTES} -- corrupt or malicious framing"
            )));
        }
        let total = LENGTH_PREFIX_BYTES + NONCE_BYTES + n;
        if available < total {
            return Ok(None); // wait for more bytes
        }
        let nonce_start = self.start + LENGTH_PREFIX_BYTES;
        let ciphertext_start = nonce_start + NONCE_BYTES;
        let nonce = self.buf[nonce_start..ciphertext_start].to_vec();
        let ciphertext = self.buf[ciphertext_start..self.start + total].to_vec();
        self.start += total;
        Ok(Some((nonce, ciphertext)))
    }
}

// ── Write coalescing ───────────────────────────────────────────────────
//
// Purely local, sender-side batching of small consecutive write() calls
// into one sealed chunk -- NOT a wire protocol change (the receiver has no
// idea how many writes got merged, see wsh #22's design-doc update). Smart
// defaults derive from session `kind`; callers can override via
// `enable_e2e`'s coalesce option or fully disable it.

/// Effective coalescing config: batch writes up to `max_bytes` or
/// `max_delay_ms`, whichever comes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoalesceOptions {
    /// Flush once this many bytes are buffered.
    pub max_bytes: usize,
    /// Flush this many milliseconds after the first buffered byte of the
    /// current batch, if the byte threshold hasn't fired first.
    pub max_delay_ms: u64,
}

/// Caller-supplied override for [`resolve_coalesce_options`]. Mirrors the
/// JS side's `enableE2E(key, { coalesce })` option shape.
#[derive(Debug, Clone, Copy, Default)]
pub enum CoalesceOverride {
    /// No override -- use the default profile derived from session `kind`.
    #[default]
    Default,
    /// Seal every write immediately, no batching.
    Disabled,
    /// Explicit values; any field left `None` falls back to the base
    /// profile's value for that field.
    Custom {
        max_bytes: Option<usize>,
        max_delay_ms: Option<u64>,
    },
}

/// Default coalescing profiles by session kind.
///  - `Pty` (interactive): latency-first -- flush on a short timer or a
///    small byte threshold, whichever fires first. This isn't "batching
///    keystrokes"; it mainly catches writes issued in the same tick
///    (multi-byte UTF-8, escape sequences, paste bursts) -- a single
///    keystroke still goes out almost immediately.
///  - `Exec` (bulk, and the fallback for any other kind): throughput-first
///    -- longer timer and the full 16 KiB soft target from the chunk-size
///    design above.
pub const PTY_COALESCE_PROFILE: CoalesceOptions = CoalesceOptions {
    max_bytes: 4 * 1024,
    max_delay_ms: 6,
};

/// See [`PTY_COALESCE_PROFILE`].
pub const EXEC_COALESCE_PROFILE: CoalesceOptions = CoalesceOptions {
    max_bytes: CHUNK_SOFT_TARGET_BYTES,
    max_delay_ms: 30,
};

fn base_profile_for_kind(kind: &ChannelKind) -> CoalesceOptions {
    match kind {
        ChannelKind::Pty => PTY_COALESCE_PROFILE,
        _ => EXEC_COALESCE_PROFILE,
    }
}

/// Resolve the effective coalescing config for a session. `None` means
/// "coalescing disabled -- seal every write immediately".
#[must_use]
pub fn resolve_coalesce_options(
    kind: &ChannelKind,
    override_: CoalesceOverride,
) -> Option<CoalesceOptions> {
    let base = base_profile_for_kind(kind);
    match override_ {
        CoalesceOverride::Disabled => None,
        CoalesceOverride::Default => Some(base),
        CoalesceOverride::Custom {
            max_bytes,
            max_delay_ms,
        } => Some(CoalesceOptions {
            max_bytes: max_bytes.filter(|b| *b > 0).unwrap_or(base.max_bytes),
            max_delay_ms: max_delay_ms.unwrap_or(base.max_delay_ms),
        }),
    }
}

/// Batches consecutive `write()` calls and flushes them as one chunk once
/// `max_bytes` is buffered or `max_delay_ms` has elapsed since the first
/// buffered byte of the current batch, whichever comes first.
///
/// `write()` resolves once bytes are queued, not once they're actually
/// flushed -- coalescing is local batching, so "queued" is the
/// caller-visible unit of success (matching wsh #22's resolved design).
/// Unlike the JS `WriteCoalescer` (which uses `setTimeout` and a promise
/// chain), this Rust port drives the timer explicitly via `tokio::time`
/// and serializes flushes with an internal `tokio::sync::Mutex` -- same
/// externally-observable behavior (bytes are queued immediately, flush
/// order matches write order, a flush error surfaces to the next caller
/// that awaits a flush), different mechanics for a synchronous-callback-free
/// async runtime.
pub struct WriteCoalescer<F>
where
    F: Fn(Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = WshResult<()>> + Send>>
        + Send
        + Sync,
{
    options: CoalesceOptions,
    on_flush: F,
    state: tokio::sync::Mutex<CoalescerState>,
}

struct CoalescerState {
    pending: Vec<u8>,
    /// Set when the first byte of the current batch is buffered; cleared on
    /// flush. Used to compute whether `max_delay_ms` has elapsed.
    batch_started_at: Option<tokio::time::Instant>,
}

impl<F> WriteCoalescer<F>
where
    F: Fn(Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = WshResult<()>> + Send>>
        + Send
        + Sync,
{
    /// Create a new coalescer with the given options and flush callback.
    pub fn new(options: CoalesceOptions, on_flush: F) -> Self {
        Self {
            options,
            on_flush,
            state: tokio::sync::Mutex::new(CoalescerState {
                pending: Vec::new(),
                batch_started_at: None,
            }),
        }
    }

    /// Buffer bytes for later coalesced sealing, flushing synchronously if
    /// the byte threshold is met. The delay-based flush is driven by
    /// `maybe_flush_on_timeout` (see `session.rs`'s stream write path,
    /// which races a per-write delay timer against subsequent writes)
    /// since this type has no free-running background task of its own.
    pub async fn write(&self, bytes: &[u8]) -> WshResult<()> {
        let should_flush_now = {
            let mut state = self.state.lock().await;
            state.pending.extend_from_slice(bytes);
            if state.batch_started_at.is_none() {
                state.batch_started_at = Some(tokio::time::Instant::now());
            }
            state.pending.len() >= self.options.max_bytes
        };
        if should_flush_now {
            self.flush().await
        } else {
            Ok(())
        }
    }

    /// Force-flush any currently-buffered bytes immediately (used on
    /// session close and once `max_delay_ms` elapses since the first
    /// buffered byte of the current batch).
    pub async fn flush(&self) -> WshResult<()> {
        let merged = {
            let mut state = self.state.lock().await;
            state.batch_started_at = None;
            if state.pending.is_empty() {
                return Ok(());
            }
            std::mem::take(&mut state.pending)
        };
        (self.on_flush)(merged).await
    }

    /// How long until `max_delay_ms` elapses for the current batch, if a
    /// batch is in progress. `None` if nothing is buffered (no timer
    /// needed).
    pub async fn time_until_deadline(&self) -> Option<tokio::time::Duration> {
        let state = self.state.lock().await;
        let started = state.batch_started_at?;
        let deadline = started + tokio::time::Duration::from_millis(self.options.max_delay_ms);
        Some(deadline.saturating_duration_since(tokio::time::Instant::now()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_frame::{seal_frame, RoleTag};

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    #[test]
    fn encode_chunk_matches_documented_wire_layout() {
        let key = test_key();
        let (nonce, ciphertext) =
            seal_frame(&key, "sess-x", RoleTag::Initiator, 0, b"hello").unwrap();
        let encoded = encode_chunk(&nonce, &ciphertext).unwrap();

        assert_eq!(&encoded[0..4], &(ciphertext.len() as u32).to_be_bytes());
        assert_eq!(&encoded[4..16], &nonce[..]);
        assert_eq!(&encoded[16..], &ciphertext[..]);
        assert_eq!(encoded.len(), 4 + 12 + ciphertext.len());
    }

    #[test]
    fn encode_chunk_rejects_wrong_length_nonce() {
        assert!(encode_chunk(&[0u8; 11], b"ct").is_err());
        assert!(encode_chunk(&[0u8; 13], b"ct").is_err());
    }

    #[test]
    fn round_trip_single_chunk() {
        let key = test_key();
        let plaintext = b"round trip me";
        let (nonce, ciphertext) =
            seal_frame(&key, "sess-rt", RoleTag::Initiator, 0, plaintext).unwrap();
        let wire = encode_chunk(&nonce, &ciphertext).unwrap();

        let mut acc = ChunkAccumulator::new();
        let chunks = acc.feed(&wire).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, nonce);
        assert_eq!(chunks[0].1, ciphertext);
        acc.finish().unwrap();
    }

    #[test]
    fn multi_chunk_in_one_read() {
        let key = test_key();
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        for (i, msg) in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()]
            .into_iter()
            .enumerate()
        {
            let (nonce, ciphertext) =
                seal_frame(&key, "sess-multi", RoleTag::Initiator, i as u64, msg).unwrap();
            wire.extend_from_slice(&encode_chunk(&nonce, &ciphertext).unwrap());
            expected.push((nonce, ciphertext));
        }

        let mut acc = ChunkAccumulator::new();
        let chunks = acc.feed(&wire).unwrap();
        assert_eq!(chunks, expected);
        acc.finish().unwrap();
    }

    #[test]
    fn one_chunk_split_across_two_reads() {
        let key = test_key();
        let plaintext = b"this chunk arrives in two pieces over the wire";
        let (nonce, ciphertext) =
            seal_frame(&key, "sess-split", RoleTag::Initiator, 0, plaintext).unwrap();
        let wire = encode_chunk(&nonce, &ciphertext).unwrap();
        let midpoint = wire.len() / 2;

        let mut acc = ChunkAccumulator::new();
        let first = acc.feed(&wire[..midpoint]).unwrap();
        assert!(first.is_empty(), "no complete chunk yet");

        let second = acc.feed(&wire[midpoint..]).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].0, nonce);
        assert_eq!(second[0].1, ciphertext);
        acc.finish().unwrap();
    }

    #[test]
    fn one_chunk_split_byte_by_byte() {
        let key = test_key();
        let (nonce, ciphertext) =
            seal_frame(&key, "sess-bytewise", RoleTag::Initiator, 0, b"tiny").unwrap();
        let wire = encode_chunk(&nonce, &ciphertext).unwrap();

        let mut acc = ChunkAccumulator::new();
        let mut all_chunks = Vec::new();
        for byte in &wire {
            all_chunks.extend(acc.feed(std::slice::from_ref(byte)).unwrap());
        }
        assert_eq!(all_chunks.len(), 1);
        assert_eq!(all_chunks[0].0, nonce);
        assert_eq!(all_chunks[0].1, ciphertext);
        acc.finish().unwrap();
    }

    #[test]
    fn torn_chunk_at_finish_is_an_error() {
        let key = test_key();
        let (nonce, ciphertext) =
            seal_frame(&key, "sess-torn", RoleTag::Initiator, 0, b"truncated?").unwrap();
        let wire = encode_chunk(&nonce, &ciphertext).unwrap();

        let mut acc = ChunkAccumulator::new();
        // Feed everything except the last byte -- the chunk never completes.
        let chunks = acc.feed(&wire[..wire.len() - 1]).unwrap();
        assert!(chunks.is_empty());
        assert!(acc.finish().is_err());
    }

    #[test]
    fn clean_eof_with_empty_buffer_is_not_an_error() {
        let mut acc = ChunkAccumulator::new();
        acc.finish().unwrap();

        let key = test_key();
        let (nonce, ciphertext) =
            seal_frame(&key, "sess-clean", RoleTag::Initiator, 0, b"ok").unwrap();
        let wire = encode_chunk(&nonce, &ciphertext).unwrap();
        acc.feed(&wire).unwrap();
        acc.finish().unwrap(); // fully drained again, still fine
    }

    #[test]
    fn oversized_length_prefix_is_rejected() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&(u32::MAX).to_be_bytes());
        wire.extend_from_slice(&[0u8; 12]); // nonce
        let mut acc = ChunkAccumulator::new();
        assert!(acc.feed(&wire).is_err());
    }

    #[test]
    fn coalesce_profiles_match_documented_values() {
        assert_eq!(PTY_COALESCE_PROFILE.max_bytes, 4 * 1024);
        assert_eq!(PTY_COALESCE_PROFILE.max_delay_ms, 6);
        assert_eq!(EXEC_COALESCE_PROFILE.max_bytes, CHUNK_SOFT_TARGET_BYTES);
        assert_eq!(EXEC_COALESCE_PROFILE.max_delay_ms, 30);
        assert_eq!(CHUNK_SOFT_TARGET_BYTES, 16 * 1024);
    }

    #[test]
    fn resolve_coalesce_options_picks_profile_by_kind() {
        let pty = resolve_coalesce_options(&ChannelKind::Pty, CoalesceOverride::Default).unwrap();
        assert_eq!(pty, PTY_COALESCE_PROFILE);

        let exec =
            resolve_coalesce_options(&ChannelKind::Exec, CoalesceOverride::Default).unwrap();
        assert_eq!(exec, EXEC_COALESCE_PROFILE);

        // Unknown/other kinds fall back to the exec (throughput-first)
        // profile, mirroring the JS side's `|| DEFAULT_COALESCE_PROFILES.exec`.
        let meta =
            resolve_coalesce_options(&ChannelKind::Meta, CoalesceOverride::Default).unwrap();
        assert_eq!(meta, EXEC_COALESCE_PROFILE);
    }

    #[test]
    fn resolve_coalesce_options_disabled_returns_none() {
        assert_eq!(
            resolve_coalesce_options(&ChannelKind::Pty, CoalesceOverride::Disabled),
            None
        );
    }

    #[test]
    fn resolve_coalesce_options_custom_overrides_fields_independently() {
        let custom = resolve_coalesce_options(
            &ChannelKind::Pty,
            CoalesceOverride::Custom {
                max_bytes: Some(999),
                max_delay_ms: None,
            },
        )
        .unwrap();
        assert_eq!(custom.max_bytes, 999);
        // max_delay_ms falls back to the pty base profile's value.
        assert_eq!(custom.max_delay_ms, PTY_COALESCE_PROFILE.max_delay_ms);
    }

    #[tokio::test]
    async fn write_coalescer_flushes_on_byte_threshold() {
        let flushed = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let flushed_clone = flushed.clone();
        let coalescer = WriteCoalescer::new(
            CoalesceOptions {
                max_bytes: 4,
                max_delay_ms: 10_000,
            },
            move |bytes| {
                let flushed = flushed_clone.clone();
                Box::pin(async move {
                    flushed.lock().await.push(bytes);
                    Ok(())
                })
            },
        );

        coalescer.write(b"ab").await.unwrap();
        assert!(flushed.lock().await.is_empty(), "under threshold, no flush yet");
        coalescer.write(b"cd").await.unwrap(); // now 4 bytes total -- hits threshold
        assert_eq!(flushed.lock().await.len(), 1);
        assert_eq!(flushed.lock().await[0], b"abcd");
    }

    #[tokio::test]
    async fn write_coalescer_explicit_flush_merges_pending_writes() {
        let flushed = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let flushed_clone = flushed.clone();
        let coalescer = WriteCoalescer::new(
            CoalesceOptions {
                max_bytes: 1024,
                max_delay_ms: 10_000,
            },
            move |bytes| {
                let flushed = flushed_clone.clone();
                Box::pin(async move {
                    flushed.lock().await.push(bytes);
                    Ok(())
                })
            },
        );

        coalescer.write(b"foo").await.unwrap();
        coalescer.write(b"bar").await.unwrap();
        assert!(flushed.lock().await.is_empty());
        coalescer.flush().await.unwrap();
        assert_eq!(flushed.lock().await[0], b"foobar");

        // A second flush with nothing pending is a no-op (doesn't call
        // on_flush again).
        coalescer.flush().await.unwrap();
        assert_eq!(flushed.lock().await.len(), 1);
    }

    // ── Cross-implementation interop vector (framing layer) ─────────────
    //
    // Captured from a real run of @johnhenry/wsh's src/stream-frame.mjs
    // `encodeChunk` (PR 1, wsh #22) sealing three plaintext messages with
    // `e2e-frame.mjs`'s `sealFrame` under a fixed all-bytes-0..31 raw
    // AES-256 key, session_id "sess-stream-interop-vector-1", role
    // ROLE_TAGS.initiator, and counters 0/1/2, then concatenating the three
    // encoded chunks into one continuous wire byte stream (as a real
    // WebTransport read might deliver them merged). This proves Rust's
    // length-prefix encoding/byte order/accumulator boundaries agree with
    // JS byte-for-byte -- `e2e_frame.rs`'s own interop vector only proves
    // the AEAD primitives agree, not this framing layer built on top of
    // them.
    #[test]
    fn js_interop_vector_wire_bytes_match_and_parse_identically() {
        let key = test_key();
        let session_id = "sess-stream-interop-vector-1";
        let messages: [&[u8]; 3] = [
            b"first chunk from js",
            b"second chunk, a bit longer than the first one",
            b"third",
        ];

        #[rustfmt::skip]
        let expected_wire: [u8; 165] = [
            0, 0, 0, 35, 0, 0, 0, 0, 0, 0, 0, 0, 105, 110, 105, 116, 85, 68, 18, 209, 227, 7, 114,
            6, 185, 143, 157, 171, 122, 217, 217, 68, 106, 57, 50, 247, 162, 95, 89, 66, 97, 99,
            188, 77, 23, 0, 10, 144, 24, 102, 27, 0, 0, 0, 61, 0, 0, 0, 0, 0, 0, 0, 1, 105, 110,
            105, 116, 234, 63, 192, 9, 5, 106, 114, 186, 129, 86, 171, 158, 56, 164, 86, 64, 147,
            144, 17, 230, 250, 44, 2, 214, 189, 20, 74, 80, 214, 28, 191, 234, 220, 158, 2, 180, 6,
            199, 43, 67, 96, 77, 32, 142, 83, 248, 245, 2, 57, 114, 133, 47, 220, 37, 168, 240,
            104, 189, 97, 215, 222, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 2, 105, 110, 105, 116, 212,
            6, 247, 186, 36, 31, 224, 182, 236, 94, 133, 106, 114, 145, 189, 20, 251, 186, 18, 179,
            161,
        ];

        // Rust must reproduce the exact same wire bytes when sealing +
        // encoding the same plaintexts under the same key/session/role/
        // counters.
        let mut wire = Vec::new();
        for (i, msg) in messages.iter().enumerate() {
            let (nonce, ciphertext) =
                seal_frame(&key, session_id, RoleTag::Initiator, i as u64, msg).unwrap();
            wire.extend_from_slice(&encode_chunk(&nonce, &ciphertext).unwrap());
        }
        assert_eq!(
            wire.as_slice(),
            &expected_wire[..],
            "Rust-produced wire bytes must match JS's encodeChunk output byte-for-byte"
        );

        // And Rust's ChunkAccumulator must parse JS's exact captured wire
        // bytes back into the right chunk boundaries -- fed in three
        // uneven pieces (mirroring the JS-side capture script's own split
        // points) to also prove split-across-reads handling agrees.
        let mut acc = ChunkAccumulator::new();
        let mut parsed = Vec::new();
        for piece in [&expected_wire[..7], &expected_wire[7..82], &expected_wire[82..]] {
            parsed.extend(acc.feed(piece).unwrap());
        }
        acc.finish().unwrap();
        assert_eq!(parsed.len(), 3);

        for (i, (nonce, ciphertext)) in parsed.iter().enumerate() {
            let opened =
                crate::e2e_frame::open_frame(&key, session_id, i as u64, nonce, ciphertext)
                    .unwrap();
            assert_eq!(opened, messages[i]);
        }
    }
}
