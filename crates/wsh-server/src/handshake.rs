//! Authentication handshake flow.
//!
//! Implements the wsh auth protocol:
//! 1. Client sends HELLO
//! 2. Server sends CHALLENGE with random nonce
//! 3. Client sends AUTH (pubkey signature or password)
//! 4. Server sends AUTH_OK (with session token) or AUTH_FAIL

use rand::Rng;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use wsh_core::keys::AuthorizedKey;
use wsh_core::messages::*;
use wsh_core::{self, WshError, WshResult};

/// Result of a successful authentication.
#[derive(Debug)]
pub struct AuthResult {
    /// Authenticated username.
    pub username: String,
    /// Fingerprint of the key used (empty string for password auth).
    pub fingerprint: String,
    /// Session token bytes.
    pub token: Vec<u8>,
    /// Session ID.
    pub session_id: String,
}

/// Result of processing a HELLO message.
pub struct HelloResult {
    /// SERVER_HELLO envelope to send back.
    pub server_hello: Envelope,
    /// CHALLENGE envelope to send back.
    pub challenge: Envelope,
    /// The generated session ID (needed for transcript verification).
    pub session_id: String,
    /// The nonce (needed for transcript verification).
    pub nonce: Vec<u8>,
    /// Server fingerprints to advertise.
    pub fingerprints: Vec<String>,
    /// Every channel binding the client's signature may legitimately carry on this connection
    /// (wsh #119); includes the empty one unless the host requires a binding. A host with no
    /// key offers nothing to bind, so this is just the empty binding.
    pub acceptable_bindings: Vec<Vec<u8>>,
    /// The host requires a bound login: an unbound signature is refused (with a reason that says so).
    pub binding_required: bool,
}

/// Supported protocol versions (in priority order, newest first).
const SUPPORTED_VERSIONS: &[&str] = &["wsh-v1"];

/// Check if a protocol version is supported.
pub fn is_version_supported(version: &str) -> bool {
    SUPPORTED_VERSIONS.contains(&version)
}

/// Negotiate protocol version from client's version string.
///
/// Returns the negotiated version or an error if incompatible.
/// Currently only "wsh-v1" is supported, but the infrastructure
/// supports future version negotiation.
pub fn negotiate_version(client_version: &str) -> WshResult<String> {
    if is_version_supported(client_version) {
        Ok(client_version.to_string())
    } else {
        Err(WshError::InvalidMessage(format!(
            "unsupported protocol version: {} (supported: {})",
            client_version,
            SUPPORTED_VERSIONS.join(", ")
        )))
    }
}

/// Process a HELLO message, returning SERVER_HELLO + CHALLENGE envelopes.
///
/// `enabled_features` allows the caller to pass a dynamically-built list
/// of features based on server configuration (e.g. gateway, relay, recording).
/// If `None`, a default set of `["mcp", "file-transfer"]` is used.
pub fn handle_hello(
    hello: &HelloPayload,
    server_fingerprints: &[String],
    enabled_features: Option<&[String]>,
    identity: Option<&crate::host_key::HostIdentity>,
) -> WshResult<HelloResult> {
    // Validate protocol version with negotiation support
    let _negotiated = negotiate_version(&hello.version)?;

    debug!(username = %hello.username, version = %hello.version, "received HELLO");

    // Generate session ID early — it's part of the auth transcript
    let session_id = generate_session_id();

    // Generate random 32-byte nonce
    let mut nonce = vec![0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill(&mut nonce[..]);

    let mut features = enabled_features
        .map(|f| f.to_vec())
        .unwrap_or_else(|| vec!["mcp".to_string(), "file-transfer".to_string()]);
    let mut host_fingerprint = None;
    let mut acceptable_bindings = vec![Vec::new()];
    let mut binding_required = false;
    if let Some(id) = identity {
        // A bare fingerprint for clients that know nothing of the proof (what the Node host
        // sends too); the proof itself only when the client sent a nonce.
        host_fingerprint = Some(id.fingerprint.clone());
        if let Some(nonce) = wsh_core::host_key::find_client_nonce(&hello.features) {
            features.extend(wsh_core::host_key::advert_features(
                id.signing_key(),
                &session_id,
                &nonce,
                &hello.username,
            ));
        }
        // Channel binding (#119): the one kind this server can bind is its own host key.
        if hello.auth_method != Some(AuthMethod::Password) {
            features.extend(wsh_core::channel_binding::binding_features(
                &["host"],
                id.require_channel_binding,
            ));
            let held = [("host", vec![id.public_key().to_vec()])];
            let required = id.require_channel_binding.then_some(&[][..]);
            acceptable_bindings = wsh_core::channel_binding::acceptable_bindings(&held, required);
            binding_required = id.require_channel_binding;
        }
    }

    let server_hello = Envelope {
        msg_type: MsgType::ServerHello,
        payload: Payload::ServerHello(ServerHelloPayload {
            session_id: session_id.clone(),
            features,
            fingerprints: server_fingerprints.to_vec(),
            host_fingerprint,
        }),
    };

    let challenge = Envelope {
        msg_type: MsgType::Challenge,
        payload: Payload::Challenge(ChallengePayload {
            nonce: nonce.clone(),
            session_id: session_id.clone(),
        }),
    };

    Ok(HelloResult {
        server_hello,
        challenge,
        session_id,
        nonce,
        fingerprints: server_fingerprints.to_vec(),
        acceptable_bindings,
        binding_required,
    })
}

/// Verify an AUTH message against authorized keys or password.
///
/// `session_id` is the one from SERVER_HELLO — it's part of the auth transcript.
/// `username` is the one from the HELLO that preceded this AUTH — also part
/// of the transcript, so a signature can't be replayed under another
/// username.
pub fn verify_auth(
    auth: &AuthPayload,
    nonce: &[u8],
    session_id: &str,
    username: &str,
    authorized_keys: &[AuthorizedKey],
    server_secret: &[u8],
    session_ttl: u64,
    allow_pubkey: bool,
    allow_password: bool,
    acceptable_bindings: &[Vec<u8>],
    binding_required: bool,
) -> WshResult<AuthResult> {
    match auth.method {
        AuthMethod::Pubkey => {
            if !allow_pubkey {
                return Err(WshError::AuthFailed("pubkey auth disabled".into()));
            }
            verify_pubkey_auth(
                auth,
                nonce,
                session_id,
                username,
                authorized_keys,
                server_secret,
                session_ttl,
                acceptable_bindings,
                binding_required,
            )
        }
        AuthMethod::Password => {
            if !allow_password {
                return Err(WshError::AuthFailed("password auth disabled".into()));
            }
            verify_password_auth(auth, session_id, server_secret, session_ttl)
        }
    }
}

/// 4-byte big-endian length prefix, matching @johnhenry/wsh's `lengthPrefixed()`.
fn length_prefixed(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Build the challenge transcript (must match JS and Rust client implementations).
///
/// Format: `SHA-256("wsh-v1\0" || lp(username) || lp(session_id) || nonce)`
/// where `lp()` length-prefixes the two variable-length string fields so
/// they can't collide when concatenated. `username` binds the transcript to
/// a specific identity, so a signature produced for one username can't be
/// replayed/relabeled as another.
#[cfg(test)]
fn build_transcript(username: &str, session_id: &str, nonce: &[u8]) -> Vec<u8> {
    build_transcript_bound(username, session_id, nonce, &[])
}

fn build_transcript_bound(
    username: &str,
    session_id: &str,
    nonce: &[u8],
    channel_binding: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(PROTOCOL_VERSION.as_bytes());
    hasher.update(b"\0");
    hasher.update(length_prefixed(username.as_bytes()));
    hasher.update(length_prefixed(session_id.as_bytes()));
    hasher.update(nonce);
    hasher.update(channel_binding);
    hasher.finalize().to_vec()
}

/// Verify pubkey-based authentication.
fn verify_pubkey_auth(
    auth: &AuthPayload,
    nonce: &[u8],
    session_id: &str,
    username: &str,
    authorized_keys: &[AuthorizedKey],
    server_secret: &[u8],
    session_ttl: u64,
    acceptable_bindings: &[Vec<u8>],
    binding_required: bool,
) -> WshResult<AuthResult> {
    let public_key = auth
        .public_key
        .as_ref()
        .ok_or_else(|| WshError::AuthFailed("missing public_key in pubkey auth".into()))?;
    let signature = auth
        .signature
        .as_ref()
        .ok_or_else(|| WshError::AuthFailed("missing signature in pubkey auth".into()))?;

    // Check if the key is authorized
    if !wsh_core::keys::is_key_authorized(public_key, authorized_keys) {
        let fp = wsh_core::fingerprint(public_key);
        warn!(fingerprint = %fp, "unauthorized key");
        return Err(WshError::AuthFailed("key not authorized".into()));
    }

    // Verify the signature over the transcript. Transcript:
    // SHA-256("wsh-v1\0" || lp(username) || lp(session_id) || nonce || channel_binding)
    // where the binding is any of `acceptable_bindings` (see `HelloResult`).

    // Import the public key and verify Ed25519 signature.
    let vk_bytes: [u8; 32] = public_key
        .as_slice()
        .try_into()
        .map_err(|_| WshError::AuthFailed("invalid public key length".into()))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes)
        .map_err(|e| WshError::AuthFailed(format!("invalid public key: {e}")))?;
    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|e| WshError::AuthFailed(format!("invalid signature: {e}")))?;

    use ed25519_dalek::Verifier;
    let verifies = |binding: &[u8]| {
        verifying_key
            .verify(
                &build_transcript_bound(username, session_id, nonce, binding),
                &sig,
            )
            .is_ok()
    };
    if !acceptable_bindings.iter().any(|b| verifies(b)) {
        if binding_required && verifies(&[]) {
            return Err(WshError::AuthFailed(
                "channel binding required: the signature is not bound to this connection".into(),
            ));
        }
        return Err(WshError::AuthFailed("signature verification failed".into()));
    }

    let fp = wsh_core::fingerprint(public_key);
    let token = wsh_core::create_token(server_secret, session_id, session_ttl);

    info!(fingerprint = %wsh_core::short_fingerprint(&fp, &[], 8), "pubkey auth OK");

    Ok(AuthResult {
        username: String::new(), // Will be filled from HELLO
        fingerprint: fp,
        token,
        session_id: session_id.to_string(),
    })
}

/// Create the result of a password login the caller has already verified.
///
/// The hashes live in `[auth.password_hashes]` and are checked by
/// `WshServer::check_password` (see `auth::password`); this only mints the token.
/// The username is taken from the HELLO message that preceded AUTH.
fn verify_password_auth(
    auth: &AuthPayload,
    session_id: &str,
    server_secret: &[u8],
    session_ttl: u64,
) -> WshResult<AuthResult> {
    let _password = auth
        .password
        .as_ref()
        .ok_or_else(|| WshError::AuthFailed("missing password in password auth".into()))?;

    // Password verification is performed by the caller (server.rs) which has
    // access to the password hash map. Here we just create the auth result.
    // The caller should validate the password before calling this function.
    let token = wsh_core::create_token(server_secret, session_id, session_ttl);

    info!("password auth OK");

    Ok(AuthResult {
        username: String::new(),    // Filled by caller from HELLO
        fingerprint: String::new(), // No fingerprint for password auth
        token,
        session_id: session_id.to_string(),
    })
}

/// `AuthOk.ttl`: seconds this server promises to keep the connection. This
/// server enforces no connection lifetime (`session_ttl` is the lifetime of a
/// DETACHED session, enforced by the session manager), so it promises none: 0
/// means "no limit is promised" (spec, wsh #125). It used to send
/// `session_ttl` here, which nothing enforced.
///
/// `AuthOk.token` stays an HMAC because released clients require a non-empty
/// field, but it is OPAQUE: no message accepts it back (Attach and Resume
/// verify the per-session token from `OpenOk`), and a client must not present
/// it as a credential.
pub const AUTH_OK_TTL: u64 = 0;

/// Build an AUTH_OK envelope.
pub fn build_auth_ok(session_id: &str, token: &[u8], ttl: u64) -> Envelope {
    Envelope {
        msg_type: MsgType::AuthOk,
        payload: Payload::AuthOk(AuthOkPayload {
            session_id: session_id.to_string(),
            token: token.to_vec(),
            ttl,
        }),
    }
}

/// Build an AUTH_FAIL envelope.
pub fn build_auth_fail(reason: &str) -> Envelope {
    Envelope {
        msg_type: MsgType::AuthFail,
        payload: Payload::AuthFail(AuthFailPayload {
            reason: reason.to_string(),
        }),
    }
}

/// Generate a random session ID.
fn generate_session_id() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_key::HostIdentity;
    use ed25519_dalek::{Signer, SigningKey};
    use wsh_core::channel_binding;
    use wsh_core::host_key;

    fn hello(nonce: Option<&str>, method: AuthMethod) -> HelloPayload {
        HelloPayload {
            version: PROTOCOL_VERSION.to_string(),
            username: "alice".into(),
            features: nonce
                .map(|n| vec![format!("{}{n}", host_key::HOST_KEY_NONCE_PREFIX)])
                .unwrap_or_default(),
            auth_method: Some(method),
        }
    }

    fn server_hello(r: &HelloResult) -> ServerHelloPayload {
        match &r.server_hello.payload {
            Payload::ServerHello(sh) => sh.clone(),
            _ => unreachable!(),
        }
    }

    #[test]
    fn no_identity_means_no_host_key_features_and_the_empty_binding_only() {
        let r = handle_hello(
            &hello(Some(&host_key::new_nonce()), AuthMethod::Pubkey),
            &[],
            None,
            None,
        )
        .unwrap();
        let sh = server_hello(&r);
        assert_eq!(sh.host_fingerprint, None);
        assert!(!sh
            .features
            .iter()
            .any(|f| f.starts_with("host-key") || f.starts_with("channel-binding")));
        assert_eq!(r.acceptable_bindings, vec![Vec::<u8>::new()]);
    }

    #[test]
    fn an_identity_proves_the_key_over_the_clients_nonce() {
        let id = HostIdentity::ephemeral(false);
        let nonce = host_key::new_nonce();
        let r = handle_hello(
            &hello(Some(&nonce), AuthMethod::Pubkey),
            &[],
            None,
            Some(&id),
        )
        .unwrap();
        let sh = server_hello(&r);
        assert_eq!(
            sh.host_fingerprint.as_deref(),
            Some(id.fingerprint.as_str())
        );
        let proven = host_key::verify_advert(
            &sh.features,
            sh.host_fingerprint.as_deref(),
            &sh.session_id,
            &nonce,
            "alice",
        )
        .unwrap()
        .unwrap();
        assert_eq!(proven.fingerprint, id.fingerprint);
        assert!(sh.features.contains(&"channel-binding:host".to_string()));
        assert!(!sh
            .features
            .contains(&"channel-binding-required".to_string()));
    }

    #[test]
    fn a_client_that_sent_no_nonce_gets_the_bare_fingerprint_and_no_proof() {
        let id = HostIdentity::ephemeral(false);
        let r = handle_hello(&hello(None, AuthMethod::Pubkey), &[], None, Some(&id)).unwrap();
        let sh = server_hello(&r);
        assert_eq!(
            sh.host_fingerprint.as_deref(),
            Some(id.fingerprint.as_str())
        );
        assert!(!sh
            .features
            .iter()
            .any(|f| f.starts_with("host-key:") || f.starts_with("host-key-sig:")));
    }

    fn login(id: &HostIdentity, binding: Option<Vec<u8>>) -> WshResult<AuthResult> {
        let r = handle_hello(&hello(None, AuthMethod::Pubkey), &[], None, Some(id)).unwrap();
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let sid = server_hello(&r).session_id;
        let transcript =
            build_transcript_bound("alice", &sid, &r.nonce, binding.as_deref().unwrap_or(&[]));
        let auth = AuthPayload {
            method: AuthMethod::Pubkey,
            signature: Some(sk.sign(&transcript).to_bytes().to_vec()),
            public_key: Some(pk.to_vec()),
            password: None,
        };
        let key = AuthorizedKey {
            key_type: "ssh-ed25519".into(),
            key_data: String::new(),
            raw: Vec::new(),
            comment: String::new(),
            fingerprint: wsh_core::fingerprint(&pk),
            options: None,
        };
        verify_auth(
            &auth,
            &r.nonce,
            &sid,
            "alice",
            &[key],
            b"secret",
            3600,
            true,
            false,
            &r.acceptable_bindings,
            r.binding_required,
        )
    }

    #[test]
    fn a_login_bound_to_the_host_key_verifies_and_so_does_an_unbound_one_unless_required() {
        let id = HostIdentity::ephemeral(false);
        let bound = channel_binding::compute(&[("host", &id.public_key())]);
        assert!(login(&id, Some(bound.clone())).is_ok());
        assert!(
            login(&id, None).is_ok(),
            "a released client that cannot bind still logs in"
        );
        let strict = HostIdentity::ephemeral(true);
        let bound = channel_binding::compute(&[("host", &strict.public_key())]);
        assert!(login(&strict, Some(bound)).is_ok());
        let err = login(&strict, None).err().unwrap().to_string();
        assert!(err.contains("channel binding required"), "{err}");
    }

    #[test]
    fn a_login_bound_to_another_hosts_key_is_refused() {
        let id = HostIdentity::ephemeral(false);
        let other = HostIdentity::ephemeral(false);
        let wrong = channel_binding::compute(&[("host", &other.public_key())]);
        assert!(login(&id, Some(wrong)).is_err());
    }
}
