//! Transport layer auto-selection for wsh.
//!
//! Selects WebTransport or WebSocket based on the URL scheme:
//! - `wss://` or `ws://` → WebSocket
//! - `https://` or `wt://` → WebTransport

pub mod websocket;
pub mod webtransport;

pub use websocket::WebSocketSession;
pub use webtransport::{CertPolicy, WebTransportSession};

use wsh_core::error::{WshError, WshResult};
use wsh_core::transport::{IdentifiedStream, TransportSession};

/// Transport kind, inferred from the connection URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    WebSocket,
    WebTransport,
}

/// Enum-dispatched transport session.
///
/// Wraps both WebSocket and WebTransport sessions so we can use them
/// without `dyn TransportSession` (which is not object-safe due to async methods).
/// Opens client-initiated data streams WITHOUT the transport lock: the client's dispatch loop holds
/// that lock for as long as it waits for a control message, so a call that needed it (an rpc
/// channel's stream, wsh #127) would stall until something else woke the loop.
#[derive(Clone)]
pub struct StreamOpener(
    std::sync::Arc<
        dyn Fn() -> std::pin::Pin<
                Box<dyn std::future::Future<Output = WshResult<IdentifiedStream>> + Send>,
            > + Send
            + Sync,
    >,
);

impl StreamOpener {
    pub(crate) fn new<F, Fut>(f: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = WshResult<IdentifiedStream>> + Send + 'static,
    {
        Self(std::sync::Arc::new(move || Box::pin(f())))
    }

    pub async fn open(&self) -> WshResult<IdentifiedStream> {
        (self.0)().await
    }
}

pub enum AnyTransport {
    WebSocket(WebSocketSession),
    WebTransport(WebTransportSession),
    #[cfg(test)]
    Test(TestTransport),
}

#[cfg(test)]
pub struct TestTransport;

impl AnyTransport {
    pub async fn send_control(&mut self, data: &[u8]) -> WshResult<()> {
        match self {
            Self::WebSocket(s) => s.send_control(data).await,
            Self::WebTransport(s) => s.send_control(data).await,
            #[cfg(test)]
            Self::Test(_) => Err(WshError::Transport(
                "test transport does not support control sends".into(),
            )),
        }
    }

    pub async fn recv_control(&mut self) -> WshResult<Vec<u8>> {
        match self {
            Self::WebSocket(s) => s.recv_control().await,
            Self::WebTransport(s) => s.recv_control().await,
            #[cfg(test)]
            Self::Test(_) => Err(WshError::Transport(
                "test transport does not support control receives".into(),
            )),
        }
    }

    pub async fn open_stream(&mut self) -> WshResult<IdentifiedStream> {
        match self {
            Self::WebSocket(s) => s.open_stream().await,
            Self::WebTransport(s) => s.open_stream().await,
            #[cfg(test)]
            Self::Test(_) => Err(WshError::Transport(
                "test transport does not support streams".into(),
            )),
        }
    }

    /// A handle that opens data streams without going through this transport's lock.
    pub fn stream_opener(&self) -> Option<StreamOpener> {
        match self {
            Self::WebSocket(s) => Some(s.stream_opener()),
            Self::WebTransport(s) => Some(s.stream_opener()),
            #[cfg(test)]
            Self::Test(_) => None,
        }
    }

    pub async fn accept_stream(&mut self) -> WshResult<IdentifiedStream> {
        match self {
            Self::WebSocket(s) => s.accept_stream().await,
            Self::WebTransport(s) => s.accept_stream().await,
            #[cfg(test)]
            Self::Test(_) => Err(WshError::Transport(
                "test transport does not support streams".into(),
            )),
        }
    }

    pub async fn close(&mut self) -> WshResult<()> {
        match self {
            Self::WebSocket(s) => s.close().await,
            Self::WebTransport(s) => s.close().await,
            #[cfg(test)]
            Self::Test(_) => Ok(()),
        }
    }

    pub fn is_connected(&self) -> bool {
        match self {
            Self::WebSocket(s) => s.is_connected(),
            Self::WebTransport(s) => s.is_connected(),
            #[cfg(test)]
            Self::Test(_) => true,
        }
    }
}

/// Determine the transport kind from a URL string.
pub fn detect_transport(url: &str) -> WshResult<TransportKind> {
    let lower = url.to_lowercase();
    if lower.starts_with("ws://") || lower.starts_with("wss://") {
        Ok(TransportKind::WebSocket)
    } else if lower.starts_with("https://") || lower.starts_with("wt://") {
        Ok(TransportKind::WebTransport)
    } else {
        Err(WshError::Transport(format!(
            "unsupported URL scheme: {url} (expected ws://, wss://, https://, or wt://)"
        )))
    }
}

/// Install the process-wide rustls `CryptoProvider` (ring) if none is set.
///
/// The dependency tree enables both rustls providers (`ring` here, `aws-lc-rs`
/// through another crate), and rustls then refuses to pick one on its own: the
/// first `wss://` handshake that built a `ClientConfig` panicked with "Could not
/// automatically determine the process-level CryptoProvider" (#134). Called
/// before every connection and by `wsh` at start-up; harmless to call again, and
/// it leaves a provider the embedding application installed first alone.
pub fn install_crypto_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            // `Err` means another thread installed one between the check and here.
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}

/// Connect to a wsh server, auto-selecting the transport from the URL scheme. A WebTransport
/// server's certificate is validated against the system trust store ([`CertPolicy::SystemRoots`]).
pub async fn auto_connect(url: &str) -> WshResult<AnyTransport> {
    auto_connect_with(url, &CertPolicy::default()).await
}

/// [`auto_connect`] under a certificate policy. The policy governs WebTransport only: a `ws://` /
/// `wss://` URL with a pin or the opt-out is refused rather than connected with the setting
/// silently ignored (a `wss://` certificate is always checked against the system trust store).
pub async fn auto_connect_with(url: &str, policy: &CertPolicy) -> WshResult<AnyTransport> {
    install_crypto_provider();
    let kind = detect_transport(url)?;

    match kind {
        TransportKind::WebSocket => {
            if *policy != CertPolicy::SystemRoots {
                return Err(WshError::Transport(
                    "a certificate hash or --insecure-skip-cert-verification applies to WebTransport \
                     (https://) only; a wss:// certificate is checked against the system trust store"
                        .into(),
                ));
            }
            let session = WebSocketSession::connect(url).await?;
            Ok(AnyTransport::WebSocket(session))
        }
        TransportKind::WebTransport => {
            let session = WebTransportSession::connect_with(url, policy).await?;
            Ok(AnyTransport::WebTransport(session))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::webtransport::normalize_webtransport_url;

    #[test]
    fn install_crypto_provider_sets_a_process_default() {
        install_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
        // Idempotent: a second call neither panics nor replaces it.
        install_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[test]
    fn detect_websocket() {
        assert_eq!(
            detect_transport("ws://localhost:8080").unwrap(),
            TransportKind::WebSocket
        );
        assert_eq!(
            detect_transport("wss://example.com").unwrap(),
            TransportKind::WebSocket
        );
    }

    #[test]
    fn detect_webtransport() {
        assert_eq!(
            detect_transport("https://example.com:4433").unwrap(),
            TransportKind::WebTransport
        );
        assert_eq!(
            detect_transport("wt://example.com:4433").unwrap(),
            TransportKind::WebTransport
        );
    }

    #[test]
    fn detect_transport_is_case_insensitive() {
        assert_eq!(
            detect_transport("WSS://example.com").unwrap(),
            TransportKind::WebSocket
        );
        assert_eq!(
            detect_transport("WT://example.com/wsh").unwrap(),
            TransportKind::WebTransport
        );
    }

    #[test]
    fn detect_transport_rejects_bare_hosts() {
        assert!(detect_transport("localhost:4422").is_err());
        assert!(detect_transport("example.com").is_err());
    }

    #[test]
    fn detect_webtransport_with_path_and_query() {
        assert_eq!(
            detect_transport("wt://example.com:4433/wsh?transport=web").unwrap(),
            TransportKind::WebTransport
        );
    }

    #[test]
    fn detect_unknown() {
        assert!(detect_transport("http://example.com").is_err());
        assert!(detect_transport("ftp://example.com").is_err());
    }

    #[test]
    fn normalize_wt_url_preserves_https() {
        assert_eq!(
            normalize_webtransport_url("https://example.com:4433/wsh").unwrap(),
            "https://example.com:4433/wsh"
        );
    }

    #[test]
    fn normalize_wt_url_accepts_legacy_alias() {
        assert_eq!(
            normalize_webtransport_url("wt://example.com/wsh").unwrap(),
            "https://example.com/wsh"
        );
    }
}
