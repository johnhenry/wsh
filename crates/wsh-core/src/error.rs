use thiserror::Error;

/// Errors produced by the wsh protocol layer.
#[derive(Debug, Error)]
pub enum WshError {
    #[error("codec error: {0}")]
    Codec(String),

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("unknown key: {0}")]
    UnknownKey(String),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("channel error: {0}")]
    Channel(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("token error: {0}")]
    Token(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The host proved a host key that `known_hosts` has no entry for, and the caller did not
    /// allow first use. Carries what a person needs to decide.
    #[error("host key for {host} is not in known_hosts (fingerprint {fingerprint}); first use must be accepted explicitly")]
    HostKeyUnknown { host: String, fingerprint: String },

    #[error("timeout")]
    Timeout,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl From<ciborium::de::Error<std::io::Error>> for WshError {
    fn from(e: ciborium::de::Error<std::io::Error>) -> Self {
        WshError::Codec(e.to_string())
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for WshError {
    fn from(e: ciborium::ser::Error<std::io::Error>) -> Self {
        WshError::Codec(e.to_string())
    }
}

impl From<crate::qmux::QMuxError> for WshError {
    fn from(e: crate::qmux::QMuxError) -> Self {
        WshError::Transport(e.to_string())
    }
}

pub type WshResult<T> = Result<T, WshError>;
