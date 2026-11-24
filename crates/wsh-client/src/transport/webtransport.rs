//! Browser-compatible WebTransport implementation for wsh.
//!
//! Uses the `wtransport` crate to establish a real WebTransport-over-HTTP/3
//! session so browser clients and Rust clients speak the same transport.

use std::future::Future;
use std::pin::Pin;

use wtransport::endpoint::endpoint_side;
use wtransport::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};

use wsh_core::codec::FrameDecoder;
use wsh_core::error::{WshError, WshResult};
use wsh_core::transport::{ByteStream, IdentifiedStream, TransportSession};

/// The frames of the control stream: bytes in, whole frames out one at a time. A single read can complete several frames,
/// so the ones not yet handed on are kept (taking only the first of what a read decoded would drop the rest).
struct ControlFrames {
    decoder: FrameDecoder,
    ready: std::collections::VecDeque<Vec<u8>>,
}

impl ControlFrames {
    fn new() -> Self {
        Self {
            decoder: FrameDecoder::new(),
            ready: std::collections::VecDeque::new(),
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.ready.extend(self.decoder.feed_raw(bytes));
    }

    fn pop(&mut self) -> Option<Vec<u8>> {
        self.ready.pop_front()
    }
}

/// A WebTransport bidirectional stream wrapped as a `ByteStream`.
struct WebTransportStream {
    send: SendStream,
    recv: RecvStream,
}

impl ByteStream for WebTransportStream {
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = WshResult<usize>> + Send + 'a>> {
        Box::pin(async move {
            match self.recv.read(buf).await {
                Ok(Some(n)) => Ok(n),
                Ok(None) => Ok(0),
                Err(e) => Err(WshError::Transport(format!("WebTransport read error: {e}"))),
            }
        })
    }

    fn write_all<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = WshResult<()>> + Send + 'a>> {
        Box::pin(async move {
            self.send
                .write_all(data)
                .await
                .map_err(|e| WshError::Transport(format!("WebTransport write error: {e}")))
        })
    }

    fn close(&mut self) -> Pin<Box<dyn Future<Output = WshResult<()>> + Send + '_>> {
        Box::pin(async move {
            self.send
                .finish()
                .await
                .map_err(|e| WshError::Transport(format!("WebTransport close error: {e}")))?;
            Ok(())
        })
    }
}

/// WebTransport session backed by a browser-compatible HTTP/3 session.
pub struct WebTransportSession {
    _endpoint: Endpoint<endpoint_side::Client>,
    connection: Connection,
    control_send: SendStream,
    control_recv: RecvStream,
    decoder: ControlFrames,
    next_stream_id: u32,
    connected: bool,
}

/// How a WebTransport connection decides whether to trust the server's TLS certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CertPolicy {
    /// The certificate must chain to a root in the platform's trust store and name the host
    /// (what a browser does without `serverCertificateHashes`). The default.
    #[default]
    SystemRoots,
    /// The certificate's SHA-256 must be one of these (the JS client's `serverCertificateHashes`):
    /// no certificate authority is involved, and the certificate must be valid for at most 14 days
    /// with an ECDSA P-256 key, as the WebTransport specification requires of a pinned one. Several
    /// hashes allow a rotation (the current and the next certificate).
    Pinned(Vec<[u8; 32]>),
    /// The certificate is not checked at all: anyone on the path can be the server. For development
    /// against a throwaway server only; every connection prints a warning.
    InsecureSkipVerification,
}

/// Parse a certificate hash as `openssl x509 -fingerprint -sha256` prints it (colon-separated hex,
/// with or without the `SHA256 Fingerprint=` prefix) or as plain hex, upper or lower case.
pub fn parse_cert_hash(text: &str) -> WshResult<[u8; 32]> {
    let trimmed = text.trim();
    let body = match trimmed.split_once('=') {
        Some((label, rest)) if label.to_ascii_lowercase().contains("fingerprint") => rest,
        _ => trimmed,
    };
    let hex: String = body
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
        .filter(|b| b.len() == 32 && hex.len() == 64)
        .ok_or_else(|| {
            WshError::Transport(
                "a certificate hash is the SHA-256 of the certificate: 64 hex digits, optionally \
                 colon-separated (openssl x509 -fingerprint -sha256 -noout -in cert.pem)"
                    .into(),
            )
        })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

static INSECURE_WARNINGS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many connections have printed the unverified-certificate warning in this process.
pub fn insecure_warnings_printed() -> usize {
    INSECURE_WARNINGS.load(std::sync::atomic::Ordering::Relaxed)
}

/// The warning printed on every connection made with [`CertPolicy::InsecureSkipVerification`].
pub fn insecure_warning(url: &str) -> String {
    format!(
        "wsh: WARNING: the server certificate of {url} is not verified (--insecure-skip-cert-verification). \
         Anyone on the network path can impersonate this server. Use it for development only; \
         pin the certificate with --cert-hash instead."
    )
}

impl WebTransportSession {
    /// Connect to a wsh server over WebTransport, validating its certificate against the
    /// system trust store ([`CertPolicy::SystemRoots`]).
    pub async fn connect(url: &str) -> WshResult<Self> {
        Self::connect_with(url, &CertPolicy::default()).await
    }

    /// Connect to a wsh server over WebTransport under `policy`.
    pub async fn connect_with(url: &str, policy: &CertPolicy) -> WshResult<Self> {
        install_rustls_crypto_provider();
        let normalized_url = normalize_webtransport_url(url)?;
        let builder = ClientConfig::builder().with_bind_default();
        let client_config = match policy {
            CertPolicy::SystemRoots => builder.with_native_certs().build(),
            CertPolicy::Pinned(hashes) => {
                if hashes.is_empty() {
                    return Err(WshError::Transport(
                        "no certificate hash given to pin the WebTransport server to".into(),
                    ));
                }
                builder
                    .with_server_certificate_hashes(
                        hashes
                            .iter()
                            .copied()
                            .map(wtransport::tls::Sha256Digest::new),
                    )
                    .build()
            }
            CertPolicy::InsecureSkipVerification => {
                INSECURE_WARNINGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                eprintln!("{}", insecure_warning(&normalized_url));
                builder.with_no_cert_validation().build()
            }
        };
        let endpoint = Endpoint::client(client_config)
            .map_err(|e| WshError::Transport(format!("endpoint error: {e}")))?;
        let connection = endpoint.connect(&normalized_url).await.map_err(|e| {
            let hint = match policy {
                CertPolicy::SystemRoots => {
                    " (the server's certificate is validated against the system trust store; \
                         for a self-signed server pin its certificate with --cert-hash <sha256>)"
                }
                CertPolicy::Pinned(_) => " (the server's certificate does not match --cert-hash)",
                CertPolicy::InsecureSkipVerification => "",
            };
            WshError::Transport(format!("WebTransport connect error: {e}{hint}"))
        })?;

        tracing::info!("WebTransport connected to {}", normalized_url);

        let (control_send, control_recv) = connection
            .open_bi()
            .await
            .map_err(|e| WshError::Transport(format!("control stream open failed: {e}")))?
            .await
            .map_err(|e| {
                WshError::Transport(format!("control stream initialization failed: {e}"))
            })?;

        Ok(Self {
            _endpoint: endpoint,
            connection,
            control_send,
            control_recv,
            decoder: ControlFrames::new(),
            next_stream_id: 1,
            connected: true,
        })
    }
}

impl WebTransportSession {
    /// A handle that opens data streams without the transport lock. The peer sees a WebTransport
    /// stream only once its first byte arrives (there is no empty announce frame here), which a
    /// typed rpc channel's first message provides.
    pub fn stream_opener(&self) -> super::StreamOpener {
        let connection = self.connection.clone();
        let next = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1 << 30));
        super::StreamOpener::new(move || {
            let connection = connection.clone();
            let next = next.clone();
            async move {
                let (send, recv) = connection
                    .open_bi()
                    .await
                    .map_err(|e| WshError::Transport(format!("failed to open stream: {e}")))?
                    .await
                    .map_err(|e| {
                        WshError::Transport(format!("failed to initialize stream: {e}"))
                    })?;
                Ok(IdentifiedStream {
                    id: next.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                    stream: Box::new(WebTransportStream { send, recv }),
                })
            }
        })
    }
}

fn install_rustls_crypto_provider() {
    super::install_crypto_provider();
}

impl TransportSession for WebTransportSession {
    async fn send_control(&mut self, data: &[u8]) -> WshResult<()> {
        let frame = frame_helpers::encode_raw(data);
        self.control_send
            .write_all(&frame)
            .await
            .map_err(|e| WshError::Transport(format!("control send error: {e}")))?;
        Ok(())
    }

    async fn recv_control(&mut self) -> WshResult<Vec<u8>> {
        loop {
            // Frames already read, whole, come first -- also after the stream has ended.
            if let Some(frame) = self.decoder.pop() {
                return Ok(frame);
            }

            let mut buf = vec![0u8; 8192];
            match self.control_recv.read(&mut buf).await {
                Ok(Some(n)) => self.decoder.push(&buf[..n]),
                Ok(None) => {
                    self.connected = false;
                    return Err(WshError::Transport("control stream closed".into()));
                }
                Err(e) => {
                    self.connected = false;
                    return Err(WshError::Transport(format!("control recv error: {e}")));
                }
            }
        }
    }

    async fn open_stream(&mut self) -> WshResult<IdentifiedStream> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| WshError::Transport(format!("failed to open stream: {e}")))?
            .await
            .map_err(|e| WshError::Transport(format!("failed to initialize stream: {e}")))?;

        let id = self.next_stream_id;
        self.next_stream_id += 1;

        Ok(IdentifiedStream {
            id,
            stream: Box::new(WebTransportStream { send, recv }),
        })
    }

    async fn accept_stream(&mut self) -> WshResult<IdentifiedStream> {
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|e| WshError::Transport(format!("failed to accept stream: {e}")))?;

        let id = self.next_stream_id;
        self.next_stream_id += 1;

        Ok(IdentifiedStream {
            id,
            stream: Box::new(WebTransportStream { send, recv }),
        })
    }

    async fn close(&mut self) -> WshResult<()> {
        self.connected = false;
        self.connection.close(0u32.into(), b"client disconnect");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Normalize a WebTransport URL so the Rust client accepts both `https://`
/// and the legacy `wt://` alias.
pub fn normalize_webtransport_url(url: &str) -> WshResult<String> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        Ok(url.to_string())
    } else if lower.starts_with("wt://") {
        Ok(format!("https://{}", &url[5..]))
    } else {
        Err(WshError::Transport(format!(
            "invalid WebTransport URL: {url}"
        )))
    }
}

/// Helper to encode raw bytes into a length-prefixed frame (used for control messages).
mod frame_helpers {
    pub fn encode_raw(data: &[u8]) -> Vec<u8> {
        let len = data.len() as u32;
        let mut frame = Vec::with_capacity(4 + data.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wtransport::tls::Identity;
    use wtransport::ServerConfig;

    /// A WebTransport server with a fresh self-signed certificate (ECDSA P-256, 14 days, the
    /// shape `serverCertificateHashes` accepts). Returns its URL and the certificate's SHA-256.
    async fn self_signed_server() -> (String, [u8; 32], tokio::task::JoinHandle<()>) {
        let identity = Identity::self_signed(["localhost", "127.0.0.1", "::1"]).unwrap();
        let hash = *identity.certificate_chain().as_slice()[0].hash().as_ref();
        let config = ServerConfig::builder()
            .with_bind_address("127.0.0.1:0".parse().unwrap())
            .with_identity(identity)
            .build();
        let endpoint = wtransport::Endpoint::server(config).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            loop {
                let incoming = endpoint.accept().await;
                tokio::spawn(async move {
                    if let Ok(request) = incoming.await {
                        if let Ok(connection) = request.accept().await {
                            tokio::time::sleep(Duration::from_secs(20)).await;
                            drop(connection);
                        }
                    }
                });
            }
        });
        (format!("https://127.0.0.1:{port}/wsh"), hash, task)
    }

    async fn try_connect(url: &str, policy: &CertPolicy) -> WshResult<WebTransportSession> {
        tokio::time::timeout(
            Duration::from_secs(8),
            WebTransportSession::connect_with(url, policy),
        )
        .await
        .unwrap_or_else(|_| Err(WshError::Timeout))
    }

    #[tokio::test]
    async fn a_self_signed_server_is_refused_by_default() {
        let (url, _hash, server) = self_signed_server().await;
        let err = try_connect(&url, &CertPolicy::default()).await.err();
        assert!(
            matches!(err, Some(WshError::Transport(_))),
            "the default policy must validate the certificate against the system roots: {err:?}"
        );
        // The convenience entry point has the same default.
        assert!(WebTransportSession::connect(&url).await.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn a_pinned_certificate_hash_is_accepted_and_a_wrong_one_is_refused() {
        let (url, hash, server) = self_signed_server().await;
        assert!(try_connect(&url, &CertPolicy::Pinned(vec![hash]))
            .await
            .is_ok());

        let mut wrong = hash;
        wrong[0] ^= 0xff;
        assert!(
            try_connect(&url, &CertPolicy::Pinned(vec![wrong]))
                .await
                .is_err(),
            "a hash that is not the server's certificate must be refused"
        );
        // Several pins (a rotation): any one of them may match.
        assert!(try_connect(&url, &CertPolicy::Pinned(vec![wrong, hash]))
            .await
            .is_ok());
        server.abort();
    }

    #[tokio::test]
    async fn an_empty_pin_list_is_an_error_not_no_verification() {
        let (url, _hash, server) = self_signed_server().await;
        let err = try_connect(&url, &CertPolicy::Pinned(Vec::new()))
            .await
            .err();
        assert!(matches!(err, Some(WshError::Transport(m)) if m.contains("no certificate hash")));
        server.abort();
    }

    #[tokio::test]
    async fn the_development_opt_out_connects_and_warns_on_every_connection() {
        let (url, _hash, server) = self_signed_server().await;
        let before = insecure_warnings_printed();
        assert!(try_connect(&url, &CertPolicy::InsecureSkipVerification)
            .await
            .is_ok());
        assert!(try_connect(&url, &CertPolicy::InsecureSkipVerification)
            .await
            .is_ok());
        assert_eq!(
            insecure_warnings_printed() - before,
            2,
            "one warning per connection"
        );
        server.abort();
    }

    #[test]
    fn the_warning_names_the_flag_and_what_is_lost() {
        let text = insecure_warning("https://127.0.0.1:4433/wsh");
        assert!(text.contains("--insecure-skip-cert-verification"));
        assert!(text.contains("not verified"));
        assert!(text.contains("127.0.0.1:4433"));
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    /// One read of the control stream can carry several frames (a ServerHello and the Challenge behind it): every one is
    /// handed on, in order, and none is lost.
    #[test]
    fn several_frames_in_one_read_are_all_delivered_in_order() {
        let mut frames = ControlFrames::new();
        let mut chunk = framed(b"one");
        chunk.extend(framed(b"two"));
        chunk.extend(framed(b"three"));
        frames.push(&chunk);
        assert_eq!(frames.pop().as_deref(), Some(&b"one"[..]));
        assert_eq!(frames.pop().as_deref(), Some(&b"two"[..]));
        assert_eq!(frames.pop().as_deref(), Some(&b"three"[..]));
        assert_eq!(frames.pop(), None);
    }

    #[test]
    fn a_frame_split_across_reads_is_delivered_once_complete_and_frames_after_it_are_kept() {
        let mut frames = ControlFrames::new();
        let whole = framed(b"split-frame");
        frames.push(&whole[..6]);
        assert_eq!(frames.pop(), None);
        let mut rest = whole[6..].to_vec();
        rest.extend(framed(b"next"));
        frames.push(&rest);
        assert_eq!(frames.pop().as_deref(), Some(&b"split-frame"[..]));
        assert_eq!(frames.pop().as_deref(), Some(&b"next"[..]));
        assert_eq!(frames.pop(), None);
    }

    #[test]
    fn a_certificate_hash_is_parsed_from_the_spellings_openssl_prints() {
        let want = [0xab; 32];
        let plain = "ab".repeat(32);
        assert_eq!(parse_cert_hash(&plain).unwrap(), want);
        assert_eq!(parse_cert_hash(&plain.to_uppercase()).unwrap(), want);
        let colons = vec!["AB"; 32].join(":");
        assert_eq!(parse_cert_hash(&colons).unwrap(), want);
        assert_eq!(
            parse_cert_hash(&format!("SHA256 Fingerprint={colons}\n")).unwrap(),
            want
        );
        assert_eq!(
            parse_cert_hash(&format!("sha256 Fingerprint = {colons}")).unwrap(),
            want
        );
    }

    #[test]
    fn a_malformed_certificate_hash_is_refused() {
        for bad in [
            "",
            "abcd",
            &"zz".repeat(32),
            &"ab".repeat(31),
            &"ab".repeat(33),
        ] {
            assert!(parse_cert_hash(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_policy_never_turns_on_by_itself() {
        assert_eq!(CertPolicy::default(), CertPolicy::SystemRoots);
    }

    #[test]
    fn normalize_webtransport_url_preserves_path_and_query() {
        assert_eq!(
            normalize_webtransport_url("wt://example.com:4433/wsh?transport=web").unwrap(),
            "https://example.com:4433/wsh?transport=web"
        );
    }

    #[test]
    fn normalize_webtransport_url_rejects_non_webtransport_schemes() {
        for url in [
            "ws://example.com",
            "wss://example.com",
            "http://example.com",
        ] {
            assert!(
                normalize_webtransport_url(url).is_err(),
                "{url} should be rejected"
            );
        }
    }
}
