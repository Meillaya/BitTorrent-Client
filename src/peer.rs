// src/peer.rs

use std::io::{Read, Write};
use std::net::TcpStream;
use crate::error::{Result, TorrentError};

const PROTOCOL: &str = "BitTorrent protocol";

pub struct Peer {
    stream: TcpStream,
}

impl Peer {
    pub fn new(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .map_err(|e| TorrentError::ConnectionFailed(e.to_string()))?;
        Ok(Self { stream })
    }

    pub fn handshake(&mut self, info_hash: &[u8; 20], peer_id: &[u8; 20]) -> Result<[u8; 20]> {
        let mut handshake = vec![19];
        handshake.extend_from_slice(PROTOCOL.as_bytes());
        handshake.extend_from_slice(&[0; 8]);
        handshake.extend_from_slice(info_hash);
        handshake.extend_from_slice(peer_id);

        self.stream.write_all(&handshake)
            .map_err(|e| TorrentError::ConnectionFailed(format!("Failed to send handshake: {}", e)))?;

        let mut response = [0u8; 68];
        self.stream.read_exact(&mut response)
            .map_err(|e| TorrentError::ConnectionFailed(format!("Failed to receive handshake: {}", e)))?;

        if response[0] != 19 || &response[1..20] != PROTOCOL.as_bytes() {
            return Err(TorrentError::InvalidPeerResponse);
        }

        let mut peer_id = [0u8; 20];
        peer_id.copy_from_slice(&response[48..68]);
        Ok(peer_id)
    }
}
