use std::fmt;
use std::io;
use url;
use serde_bencode;
use serde_json;
use reqwest;
use serde_urlencoded;

pub type Result<T> = std::result::Result<T, TorrentError>;

#[derive(Debug)]
pub enum TorrentError {
    Io(io::Error),
    Bencode(serde_bencode::Error),
    MissingKey(&'static str),
    UnexpectedType {
        expected: &'static str,
        found: &'static str,
    },
    Reqwest(reqwest::Error),
    UrlEncoding(serde_urlencoded::ser::Error),
    InvalidResponseFormat(String),
    UrlParse(url::ParseError),
    Json(serde_json::Error),
    Tracker(String),
    InvalidInfoHash,
    InvalidPeerResponse,
    PieceVerificationFailed,
    ConnectionFailed(String),
    DecodeError(String),
    NoPeersAvailable,
    UnexpectedMessage,
    UnexpectedBlockData,
    DownloadFailed(String),
}

impl fmt::Display for TorrentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TorrentError::Io(e) => write!(f, "IO Error: {}", e),
            TorrentError::Bencode(e) => write!(f, "Bencode Error: {}", e),
            TorrentError::MissingKey(key) => write!(f, "Missing Key: {}", key),
            TorrentError::UnexpectedType { expected, found } => 
                write!(f, "Unexpected Type: expected {}, found {}", expected, found),
            TorrentError::Reqwest(e) => write!(f, "HTTP Request Error: {}", e),
            TorrentError::UrlEncoding(e) => write!(f, "URL Encoding Error: {}", e),
            TorrentError::InvalidResponseFormat(msg) => write!(f, "Invalid Response Format: {}", msg),
            TorrentError::UrlParse(e) => write!(f, "URL Parse Error: {}", e),
            TorrentError::Json(e) => write!(f, "JSON Error: {}", e),
            TorrentError::Tracker(e) => write!(f, "Tracker Error: {}", e),
            TorrentError::InvalidInfoHash => write!(f, "Invalid Info Hash"),
            TorrentError::InvalidPeerResponse => write!(f, "Invalid Peer Response"),
            TorrentError::PieceVerificationFailed => write!(f, "Piece Verification Failed"),
            TorrentError::ConnectionFailed(msg) => write!(f, "Connection Failed: {}", msg),
            TorrentError::DecodeError(msg) => write!(f, "Decode Error: {}", msg),
            TorrentError::NoPeersAvailable => write!(f, "No Peers Available"),
            TorrentError::UnexpectedMessage => write!(f, "Unexpected Message"),
            TorrentError::UnexpectedBlockData => write!(f, "Unexpected Block Data"),
            TorrentError::DownloadFailed(msg) => write!(f, "Download Failed: {}", msg),
        }
    }
}

impl std::error::Error for TorrentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TorrentError::Io(e) => Some(e),
            TorrentError::Bencode(e) => Some(e),
            TorrentError::Reqwest(e) => Some(e),
            TorrentError::UrlEncoding(e) => Some(e),
            TorrentError::UrlParse(e) => Some(e),
            TorrentError::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for TorrentError {
    fn from(err: io::Error) -> Self {
        TorrentError::Io(err)
    }
}

impl From<serde_bencode::Error> for TorrentError {
    fn from(err: serde_bencode::Error) -> Self {
        TorrentError::Bencode(err)
    }
}

impl From<reqwest::Error> for TorrentError {
    fn from(err: reqwest::Error) -> Self {
        TorrentError::Reqwest(err)
    }
}

impl From<serde_urlencoded::ser::Error> for TorrentError {
    fn from(err: serde_urlencoded::ser::Error) -> Self {
        TorrentError::UrlEncoding(err)
    }
}

impl From<url::ParseError> for TorrentError {
    fn from(err: url::ParseError) -> Self {
        TorrentError::UrlParse(err)
    }
}

impl From<serde_json::Error> for TorrentError {
    fn from(err: serde_json::Error) -> Self {
        TorrentError::Json(err)
    }
}

impl From<std::array::TryFromSliceError> for TorrentError {
    fn from(err: std::array::TryFromSliceError) -> Self {
        TorrentError::DecodeError(err.to_string())
    }
}