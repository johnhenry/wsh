//! Browser-compatible WebTransport listener using `wtransport`.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use wtransport::endpoint::endpoint_side;
use wtransport::{Endpoint, Identity, ServerConfig};
use wsh_core::{WshError, WshResult};

/// A handle to an accepted WebTransport connection.
pub struct WebTransportConnection {
    /// The established WebTransport session connection.
    pub connection: wtransport::Connection,
    /// Remote address.
    pub remote_addr: SocketAddr,
}

/// Shared endpoint handle used to keep the listener alive.
pub type WebTransportEndpoint = Arc<Endpoint<endpoint_side::Server>>;

/// Start the WebTransport listener.
pub async fn start_listener(
    bind_addr: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
) -> WshResult<(WebTransportEndpoint, mpsc::Receiver<WebTransportConnection>)> {
    let identity = Identity::load_pemfiles(cert_path, key_path)
        .await
        .map_err(|e| WshError::Transport(format!("failed to load WebTransport identity: {e}")))?;
    let server_config = ServerConfig::builder()
        .with_bind_address(bind_addr)
        .with_identity(identity)
        .build();
    let endpoint = Arc::new(
        Endpoint::server(server_config)
            .map_err(|e| WshError::Transport(format!("WebTransport bind failed: {e}")))?,
    );

    info!(addr = %bind_addr, "WebTransport listener started");

    let (tx, rx) = mpsc::channel::<WebTransportConnection>(64);
    let listener_endpoint = endpoint.clone();

    tokio::spawn(async move {
        loop {
            let incoming_session = listener_endpoint.accept().await;
            let tx = tx.clone();
            tokio::spawn(async move {
                match incoming_session.await {
                    Ok(session_request) => {
                        let remote = session_request.remote_address();
                        debug!(
                            remote = %remote,
                            authority = %session_request.authority(),
                            path = %session_request.path(),
                            "WebTransport session request accepted"
                        );

                        match session_request.accept().await {
                            Ok(connection) => {
                                let wt_conn = WebTransportConnection {
                                    connection,
                                    remote_addr: remote,
                                };
                                if tx.send(wt_conn).await.is_err() {
                                    warn!("WebTransport connection channel closed");
                                }
                            }
                            Err(e) => {
                                warn!(remote = %remote, error = %e, "WebTransport session accept failed");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "WebTransport handshake failed");
                    }
                }
            });
        }
    });

    Ok((endpoint, rx))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::start_listener;
    use wsh_core::WshError;

    #[tokio::test]
    async fn start_listener_fails_when_identity_files_are_missing() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let cert_path = PathBuf::from(format!("/tmp/wsh-missing-cert-{suffix}.pem"));
        let key_path = PathBuf::from(format!("/tmp/wsh-missing-key-{suffix}.pem"));

        let err = match start_listener(
            "127.0.0.1:0".parse().unwrap(),
            &cert_path,
            &key_path,
        )
        .await
        {
            Ok(_) => panic!("listener startup unexpectedly succeeded"),
            Err(err) => err,
        };

        match err {
            WshError::Transport(message) => {
                assert!(message.contains("failed to load WebTransport identity"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
