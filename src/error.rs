use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OsmanthusError {
    #[error("Osmanthus is not initialized. Run `osmanthus init` first")]
    NotInitialized,
    #[error("Osmanthus is already initialized at {0}")]
    AlreadyInitialized(String),
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("event not found: {0}")]
    EventNotFound(String),
    #[error("event is no longer pending: {0}")]
    EventNotPending(String),
    #[error("event expired: {0}")]
    EventExpired(String),
    #[error("authentication temporarily locked; retry in {0} seconds")]
    AuthenticationLocked(i64),
    #[error("invalid authenticator code")]
    InvalidCode,
    #[error("this operation requires root; run it with sudo")]
    RootRequired,
    #[error("system policy is not initialized; run `sudo osmanthus policy init` first")]
    SystemPolicyNotInitialized,
    #[error("command is required after `--`")]
    MissingCommand,
    #[error("unsafe state path: {0}")]
    UnsafePath(String),
    #[error("failed to execute command: {0}")]
    Execution(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    TimeFormat(#[from] time::error::Format),
}

pub type Result<T> = std::result::Result<T, OsmanthusError>;
