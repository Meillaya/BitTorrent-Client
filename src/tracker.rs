// tracker.rs

use rand::Rng;
use crate::error::{Result, TorrentError};
use crate::torrent::TorrentInfo;
use serde::{Deserialize, Serialize};
use serde_bencode::de::from_bytes;
use reqwest::Client;
// use std::net::{Ipv4Addr, SocketAddrV4};
// use tokio::time::{sleep, Duration};

pub use peers::Peers;



fn generate_peer_id() -> [u8; 20] {
    let prefix = b"-TR3000-"; // Example prefix indicating the client and version
    let mut peer_id = [0u8; 20];
    peer_id[..8].copy_from_slice(prefix);
    let rand_chars: Vec<u8> = (0..12).map(|_| {
        let chars = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let idx = rand::thread_rng().gen_range(0..chars.len());
        chars[idx]
    }).collect();
    peer_id[8..20].copy_from_slice(&rand_chars);
    peer_id
}
#[derive(Debug, Clone, Serialize)]
pub struct TrackerRequest {
    #[serde(serialize_with = "serialize_peer_id")]
    pub peer_id: [u8; 20],
    pub port: u16,
    pub uploaded: usize,
    pub downloaded: usize,
    pub left: usize,
    pub compact: u8,
}

fn serialize_peer_id<S>(peer_id: &[u8; 20], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let peer_id_str = String::from_utf8_lossy(peer_id).into_owned();
    serializer.serialize_str(&peer_id_str)
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrackerResponse {
    #[serde(default)]
    pub interval: Option<usize>,
    pub peers: Peers,
}

impl TrackerResponse {
    pub async fn query(t: &TorrentInfo, info_hash: &[u8; 20]) -> Result<Self> {
        let client = Client::new();
        let request = TrackerRequest {
            peer_id: generate_peer_id(),
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

        let response = make_tracker_request(&client, &tracker_url).await?;

        let tracker_info: TrackerResponse = from_bytes(&response)
            .map_err(|e| TorrentError::InvalidResponseFormat(format!("Failed to deserialize tracker response: {}", e)))?;

        Ok(tracker_info)
    }

    pub async fn query_with_url(t: &TorrentInfo, info_hash: &[u8; 20]) -> Result<Self> {
        let client = Client::new();
        let request = TrackerRequest {
            peer_id: generate_peer_id(),
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 999, // Placeholder
            compact: 1,
        };

        let url_params = serde_urlencoded::to_string(&request)
        .map_err(|e| TorrentError::InvalidResponseFormat(format!("Failed to serialize request: {}", e)))?;

        let info_hash_encoded = url_encode(info_hash);
        let mut url = t.announce.clone();
        
        // Check if the URL is relative and prepend a default base if necessary
        if !url.starts_with("http://") && !url.starts_with("https://") {
            url = format!("http://{}", url);
        }
        
        let full_url = format!(
            "{}?{}&info_hash={}",
            url,
            url_params,
            info_hash_encoded
        );

        println!("Tracker URL: {}", url);  // Print the URL before sending the request

        let response = make_tracker_request(&client, &full_url).await?;



        let tracker_info: TrackerResponse = from_bytes(&response)
            .map_err(|e| TorrentError::InvalidResponseFormat(format!("Failed to deserialize tracker response: {}", e)))?;

        Ok(tracker_info)

    }}

fn url_encode(t: &[u8; 20]) -> String {
    let mut encoded = String::with_capacity(3 * t.len());
    for &byte in t {
        encoded.push('%');
        encoded.push_str(&hex::encode([byte]));
    }
    encoded
}

async fn make_tracker_request(client: &Client, url: &str) -> Result<Vec<u8>> {

    println!("Tracker URL: {}", url); 
    let response = client.get(url).send().await
        .map_err(|e| TorrentError::Tracker(format!("Failed to send request to tracker: {}", e)))?;

    if !response.status().is_success() {
        return Err(TorrentError::Tracker(format!("Tracker returned error status: {}", response.status())));
    }

    let bytes = response.bytes().await
        .map_err(|e| TorrentError::Tracker(format!("Failed to read tracker response bytes: {}", e)))?;
    Ok(bytes.to_vec())
}

mod peers {
    use serde::de::{self, Visitor};
    use serde::ser::Serializer;
    use std::fmt;
    use std::net::{Ipv4Addr, SocketAddrV4};

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

    impl<'de> serde::Deserialize<'de> for Peers {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_bytes(PeersVisitor)
        }
    }

    impl serde::Serialize for Peers {
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
