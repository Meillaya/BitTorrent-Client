use crate::error::{Result, TorrentError};
use crate::torrent::TorrentInfo;
use serde::{Deserialize, Serialize};
use serde_bencode::de::from_bytes;
use reqwest::blocking::Client;
use std::net::{Ipv4Addr, SocketAddrV4};


pub use peers::Peers;

/// It's recommended to generate a unique PEER_ID for each client instance.
/// For simplicity, we'll use a fixed PEER_ID in this example.
/// In production, consider generating a random 20-byte string.
const PEER_ID: &str = "00112233445566778899";

#[derive(Debug, Clone, Serialize)]
pub struct TrackerRequest {
    /// A unique identifier for your client.
    /// A string of length 20 that you get to pick.
    pub peer_id: String,
    /// The port your client is listening on.
    pub port: u16,
    /// The total amount uploaded so far.
    pub uploaded: usize,
    /// The total amount downloaded so far.
    pub downloaded: usize,
    /// The number of bytes left to download.
    pub left: usize,
    /// Whether the peer list should use the compact representation.
    /// The compact representation is more commonly used in the wild; the non-compact
    /// representation is mostly supported for backward-compatibility.
    pub compact: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrackerResponse {
    /// An integer, indicating how often your client should make a request to the tracker in seconds.
    /// You can ignore this value for the purposes of this challenge.
    #[serde(default)]
    pub interval: Option<usize>,
    /// A string, which contains a list of peers that your client can connect to.
    /// Each peer is represented using 6 bytes. The first 4 bytes are the peer's IP address and the
    /// last 2 bytes are the peer's port number.
    pub peers: Peers,
}

impl TrackerResponse {
pub fn query(t: &TorrentInfo, info_hash: &[u8; 20]) -> Result<Self> {
    let request = TrackerRequest {
        peer_id: PEER_ID.to_string(),
        port: 6881,
        uploaded: 0,
        downloaded: 0,
        left: t.length as usize,
        compact: 1,
    };

    let url_params = serde_urlencoded::to_string(&request)
        .map_err(|e| TorrentError::InvalidResponseFormat(format!("Failed to serialize request: {}", e)))?;

    let tracker_url = format!(
        "{}?{}&info_hash={}",
        t.announce,
        url_params,
        &url_encode(info_hash)
    );

  
    let response = make_tracker_request(&tracker_url)?;

    let tracker_info: TrackerResponse = from_bytes(&response)
        .map_err(|e| TorrentError::InvalidResponseFormat(format!("Failed to deserialize tracker response: {}", e)))?;

    Ok(tracker_info)
}
}


fn url_encode(t: &[u8; 20]) -> String {
    let mut encoded = String::with_capacity(3 * t.len());
    for &byte in t {
        encoded.push('%');
        encoded.push_str(&hex::encode([byte]));
    }
    encoded
}

fn make_tracker_request(url: &str) -> Result<Vec<u8>> {
    let client = Client::new();
    let response = client.get(url).send()
        .map_err(|e| TorrentError::Tracker(format!("Failed to send request to tracker: {}", e)))?;

    if !response.status().is_success() {
        return Err(TorrentError::Tracker(format!("Tracker returned error status: {}", response.status())));
    }

    response.bytes()
        .map(|b| b.to_vec())
        .map_err(|e| TorrentError::Tracker(format!("Failed to read tracker response bytes: {}", e)))
}


mod peers {
    use super::*;
    use serde::de::{self, Visitor};
    use serde::ser::Serializer;
    use std::fmt;

    #[derive(Debug, Clone)]
    pub struct Peers(pub Vec<SocketAddrV4>);

    struct PeersVisitor;

    impl<'de> Visitor<'de> for PeersVisitor {
        type Value = Peers;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a byte string with each peer represented by 6 bytes")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v.len() % 6 != 0 {
                return Err(E::custom(format!("Peers byte string length {} is not a multiple of 6", v.len())));
            }

            let peers = v.chunks_exact(6)
                .map(|chunk| {
                    let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                    let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                    SocketAddrV4::new(ip, port)
                })
                .collect();

            Ok(Peers(peers))
        }
    }

    impl<'de> Deserialize<'de> for Peers {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            deserializer.deserialize_bytes(PeersVisitor)
        }
    }

    impl Serialize for Peers {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = Vec::with_capacity(6 * self.0.len());
            for peer in &self.0 {
                bytes.extend_from_slice(&peer.ip().octets());
                bytes.extend_from_slice(&peer.port().to_be_bytes());
            }
            serializer.serialize_bytes(&bytes)
        }
    }
}
