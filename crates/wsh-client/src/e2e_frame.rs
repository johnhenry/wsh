//! EncryptedFrame sealing/opening for wsh's opt-in end-to-end encryption
//! layer (wsh #19; PR 2 of the E2E rollout -- PR 1 shipped the JS side,
//! `@johnhenry/wsh`'s `src/e2e-frame.mjs`, which this module mirrors
//! byte-for-byte so a Rust `WshClient`/`WshSession` and a JS peer land on
//! the exact same AEAD bytes).
//!
//! This module holds only the AES-256-GCM primitives (`seal_frame`/
//! `open_frame`); `session.rs`'s `WshSession::enable_e2e` wires them into
//! the virtual-mode data plane (stream-mode sessions are explicitly out of
//! scope here, same as the JS side).
//!
//! ── Nonce construction ─────────────────────────────────────────────
//! Nonces are the AES-GCM-mandated 96 bits (12 bytes), built as:
//!
//!   `[ 8-byte big-endian monotonic counter ][ 4-byte sender-role tag ]`
//!
//! The counter starts at 0 and increments by one for every frame a given
//! sender seals (never reused, per `open_frame`'s strict expected-counter
//! check below). The 4-byte role tag is fixed per sender for the lifetime
//! of one E2E-enabled connection and differs between the two peers of a
//! session (see [`RoleTag`]), so the two directions of one session
//! structurally cannot produce a colliding nonce even under fully
//! concurrent bidirectional traffic.
//!
//! ── AAD ────────────────────────────────────────────────────────────
//! The frame's `session_id` (UTF-8 bytes) is bound as AES-GCM "additional
//! authenticated data": authenticated but never encrypted, so a relay that
//! only ever sees ciphertext can't splice a frame from one session onto
//! another -- decryption fails if the `session_id` supplied to
//! `open_frame` doesn't match the one the ciphertext was sealed under.
//!
//! ── Replay/reorder protection ─────────────────────────────────────
//! `open_frame` requires the frame's nonce counter to be *exactly* the
//! caller-supplied `expected_counter` -- not merely "not yet seen" or "not
//! too old". This is intentionally strict for v1, mirroring the JS side:
//! any replayed, duplicated, dropped, or reordered frame is rejected
//! outright.
//!
//! ── Key lifetime ───────────────────────────────────────────────────
//! The `key` passed to `seal_frame`/`open_frame` is connection-scoped, not
//! session-scoped: a session that is detached and later Resumed/Attached
//! on a new connection MUST run a fresh `WshClient::initiate_e2e` and call
//! `WshSession::enable_e2e` again with the new key. Never persist or reuse
//! a `shared_secret` (or its counters) across a resume.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

use wsh_core::error::{WshError, WshResult};

/// AES-GCM-mandated nonce length in bytes.
pub const NONCE_LENGTH: usize = 12;
const COUNTER_LENGTH: usize = 8;
/// Length in bytes of each side's fixed nonce role tag.
pub const ROLE_TAG_LENGTH: usize = 4;

/// Which side of an E2E-enabled connection a `WshSession` is playing, for
/// nonce role-tag purposes. Mirrors `@johnhenry/wsh`'s `ROLE_TAGS` --
/// `initiator` is naturally the side that called `initiate_e2e()` first /
/// sent round-1 `KeyExchange`, `responder` the other side. The exact byte
/// values below MUST match the JS side for wire interop; they are fixed
/// structural tags, not secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleTag {
    /// `b"init"` -- 0x69 0x6e 0x69 0x74.
    Initiator,
    /// `b"resp"` -- 0x72 0x65 0x73 0x70.
    Responder,
}

impl RoleTag {
    /// The fixed 4-byte wire value for this role, matching
    /// `@johnhenry/wsh`'s `ROLE_TAGS` exactly.
    pub const fn bytes(self) -> [u8; ROLE_TAG_LENGTH] {
        match self {
            RoleTag::Initiator => *b"init",
            RoleTag::Responder => *b"resp",
        }
    }

    /// The other side's role tag -- the two peers of one session MUST use
    /// opposite roles, or their nonces can collide.
    pub const fn peer(self) -> RoleTag {
        match self {
            RoleTag::Initiator => RoleTag::Responder,
            RoleTag::Responder => RoleTag::Initiator,
        }
    }
}

/// Build the 12-byte nonce for a given (counter, role tag) pair. Exported
/// mainly for tests -- callers should go through [`seal_frame`]/
/// [`open_frame`].
pub fn build_nonce(counter: u64, role_tag: RoleTag) -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH];
    nonce[..COUNTER_LENGTH].copy_from_slice(&counter.to_be_bytes());
    nonce[COUNTER_LENGTH..].copy_from_slice(&role_tag.bytes());
    nonce
}

fn less_safe_key(key: &[u8; 32]) -> WshResult<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| WshError::Other("e2e-frame: invalid AES-256-GCM key".into()))?;
    Ok(LessSafeKey::new(unbound))
}

/// Seal a plaintext frame under an AES-256-GCM key.
///
/// `session_id` is bound as AAD. `role_tag` is this sender's fixed nonce
/// role tag (distinct between the two peers of a session). `counter` is
/// this sender's next monotonic send counter (0, 1, 2, ...).
///
/// Returns `(nonce, ciphertext)` -- the ciphertext includes the AEAD
/// authentication tag appended, matching `crypto.subtle.encrypt`'s output
/// shape on the JS side.
pub fn seal_frame(
    key: &[u8; 32],
    session_id: &str,
    role_tag: RoleTag,
    counter: u64,
    plaintext: &[u8],
) -> WshResult<(Vec<u8>, Vec<u8>)> {
    let nonce_bytes = build_nonce(counter, role_tag);
    let key = less_safe_key(key)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = Aad::from(session_id.as_bytes());

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, aad, &mut in_out)
        .map_err(|_| WshError::Other("e2e-frame: AES-256-GCM seal failed".into()))?;

    Ok((nonce_bytes.to_vec(), in_out))
}

/// Open (decrypt + authenticate) a sealed frame.
///
/// Fails if:
///  - `nonce` isn't exactly [`NONCE_LENGTH`] bytes,
///  - the frame's nonce counter isn't exactly `expected_counter` (replay,
///    reorder, or drop -- see this module's doc comment), or
///  - the AEAD authentication tag doesn't verify (tampered ciphertext,
///    wrong key, or `session_id` mismatch since it's bound as AAD).
pub fn open_frame(
    key: &[u8; 32],
    session_id: &str,
    expected_counter: u64,
    nonce: &[u8],
    ciphertext: &[u8],
) -> WshResult<Vec<u8>> {
    if nonce.len() != NONCE_LENGTH {
        return Err(WshError::Other(format!(
            "e2e-frame: nonce must be {NONCE_LENGTH} bytes, got {}",
            nonce.len()
        )));
    }
    let actual_counter = u64::from_be_bytes(nonce[..COUNTER_LENGTH].try_into().unwrap());
    if actual_counter != expected_counter {
        return Err(WshError::Other(format!(
            "e2e-frame: replay/reorder detected -- expected counter {expected_counter}, got {actual_counter}"
        )));
    }

    let key = less_safe_key(key)?;
    let nonce_array: [u8; NONCE_LENGTH] = nonce.try_into().unwrap();
    let nonce = Nonce::assume_unique_for_key(nonce_array);
    let aad = Aad::from(session_id.as_bytes());

    let mut in_out = ciphertext.to_vec();
    let plaintext = key.open_in_place(nonce, aad, &mut in_out).map_err(|_| {
        WshError::Other("e2e-frame: authentication failed while opening frame".into())
    })?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    #[test]
    fn round_trip_recovers_plaintext() {
        let key = test_key();
        let plaintext = b"hello from the initiator";

        let (nonce, ciphertext) =
            seal_frame(&key, "session-a", RoleTag::Initiator, 0, plaintext).unwrap();
        assert_eq!(nonce.len(), NONCE_LENGTH);

        let opened = open_frame(&key, "session-a", 0, &nonce, &ciphertext).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn round_trips_multiple_sequential_frames_with_increasing_counters() {
        let key = test_key();
        let messages: Vec<&[u8]> = vec![b"one", b"two", b"three"];

        let frames: Vec<(Vec<u8>, Vec<u8>)> = messages
            .iter()
            .enumerate()
            .map(|(i, msg)| {
                seal_frame(&key, "session-b", RoleTag::Initiator, i as u64, msg).unwrap()
            })
            .collect();

        for (i, (nonce, ciphertext)) in frames.iter().enumerate() {
            let opened = open_frame(&key, "session-b", i as u64, nonce, ciphertext).unwrap();
            assert_eq!(opened, messages[i]);
        }
    }

    #[test]
    fn tamper_detection_flipped_ciphertext_byte_fails_to_open() {
        let key = test_key();
        let plaintext = b"do not tamper with me";
        let (nonce, mut ciphertext) =
            seal_frame(&key, "session-c", RoleTag::Initiator, 0, plaintext).unwrap();

        ciphertext[0] ^= 0xff;

        assert!(open_frame(&key, "session-c", 0, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn tamper_detection_flipped_aad_session_id_fails_to_open() {
        let key = test_key();
        let plaintext = b"bound to session-d only";
        let (nonce, ciphertext) =
            seal_frame(&key, "session-d", RoleTag::Initiator, 0, plaintext).unwrap();

        // Attempting to open under a different session_id (simulating a
        // relay splicing ciphertext from one session onto another) must
        // fail.
        assert!(open_frame(&key, "session-e", 0, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn replay_reorder_rejection() {
        let key = test_key();
        let plaintext = b"sequenced message";

        let frame0 = seal_frame(&key, "session-f", RoleTag::Initiator, 0, plaintext).unwrap();
        let frame1 = seal_frame(&key, "session-f", RoleTag::Initiator, 1, plaintext).unwrap();

        // Replaying frame0 when counter 1 is expected must fail.
        assert!(open_frame(&key, "session-f", 1, &frame0.0, &frame0.1).is_err());
        // Skipping ahead (frame1 when 0 is expected) must also fail.
        assert!(open_frame(&key, "session-f", 0, &frame1.0, &frame1.1).is_err());
        // The correctly-ordered sequence succeeds.
        open_frame(&key, "session-f", 0, &frame0.0, &frame0.1).unwrap();
        open_frame(&key, "session-f", 1, &frame1.0, &frame1.1).unwrap();
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let key = test_key();
        let mut other_key = test_key();
        other_key[0] ^= 0xff;
        let plaintext = b"secret";
        let (nonce, ciphertext) =
            seal_frame(&key, "session-g", RoleTag::Initiator, 0, plaintext).unwrap();

        assert!(open_frame(&other_key, "session-g", 0, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn nonce_uniqueness_across_consecutive_seals_and_across_roles() {
        let key = test_key();
        let plaintext = b"same plaintext every time";

        let (nonce_a0, _) =
            seal_frame(&key, "session-h", RoleTag::Initiator, 0, plaintext).unwrap();
        let (nonce_a1, _) =
            seal_frame(&key, "session-h", RoleTag::Initiator, 1, plaintext).unwrap();
        let (nonce_b0, _) =
            seal_frame(&key, "session-h", RoleTag::Responder, 0, plaintext).unwrap();

        // Consecutive counters on the same role never collide.
        assert_ne!(nonce_a0, nonce_a1);
        // Same counter, different role, never collides either -- this is
        // exactly why the two peers of a session structurally cannot
        // produce a colliding nonce even under concurrent bidirectional
        // traffic at the same counter value.
        assert_ne!(nonce_a0, nonce_b0);
    }

    #[test]
    fn build_nonce_matches_the_documented_byte_layout() {
        // [ 8-byte big-endian counter ][ 4-byte role tag ]
        let nonce = build_nonce(42, RoleTag::Initiator);
        assert_eq!(&nonce[..8], &42u64.to_be_bytes());
        assert_eq!(&nonce[8..], b"init");

        let nonce = build_nonce(42, RoleTag::Responder);
        assert_eq!(&nonce[8..], b"resp");
    }

    #[test]
    fn role_tag_bytes_match_js_role_tags_exactly() {
        // Must byte-for-byte match @johnhenry/wsh's src/e2e-frame.mjs
        // ROLE_TAGS -- these are wire values, not arbitrary constants.
        assert_eq!(RoleTag::Initiator.bytes(), [0x69, 0x6e, 0x69, 0x74]);
        assert_eq!(RoleTag::Responder.bytes(), [0x72, 0x65, 0x73, 0x70]);
    }

    // ── Cross-implementation interop vector ─────────────────────────
    //
    // Captured from a real run of @johnhenry/wsh's src/e2e-frame.mjs
    // `sealFrame` (PR 1, wsh #19) with a fixed all-bytes-0..31 raw AES-256
    // key imported via WebCrypto, session_id "sess-interop-vector-1",
    // ROLE_TAGS.initiator, and counter 42. This is the single most
    // important test in this module: if Rust's nonce byte layout, AAD
    // construction, or AEAD parameters ever silently drift from the JS
    // side, this is what catches it -- everything else in this file only
    // proves Rust agrees with itself.
    #[test]
    fn js_interop_vector_seal_matches_byte_for_byte() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let session_id = "sess-interop-vector-1";
        let counter = 42u64;
        let plaintext = b"hello rust from js, PR2 interop vector";

        let expected_nonce: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 42, 105, 110, 105, 116];
        let expected_ciphertext: [u8; 54] = [
            139, 196, 3, 139, 180, 196, 50, 21, 99, 185, 108, 176, 29, 93, 225, 148, 140, 138, 162,
            0, 170, 225, 39, 159, 204, 224, 253, 83, 228, 159, 74, 217, 49, 35, 55, 101, 234, 235,
            152, 199, 83, 118, 226, 233, 174, 116, 227, 53, 176, 237, 168, 163, 194, 203,
        ];

        let (nonce, ciphertext) =
            seal_frame(&key, session_id, RoleTag::Initiator, counter, plaintext).unwrap();
        assert_eq!(
            nonce, expected_nonce,
            "nonce byte layout must match JS exactly"
        );
        assert_eq!(
            ciphertext, expected_ciphertext,
            "ciphertext (incl. AEAD tag) must match JS's crypto.subtle.encrypt output exactly"
        );

        // And Rust must be able to open the exact bytes JS produced too
        // (not just reproduce them from scratch).
        let opened = open_frame(
            &key,
            session_id,
            counter,
            &expected_nonce,
            &expected_ciphertext,
        )
        .unwrap();
        assert_eq!(opened, plaintext);
    }
}
