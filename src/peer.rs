// peer.rs

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use crate::error::{Result, TorrentError};
use rand::Rng;

const PROTOCOL: &str = "BitTorrent protocol";

pub struct Peer {
    stream: TcpStream,
}

pub struct PeerMessage {
    pub payload: Vec<u8>,
    pub id: u8,
}

impl Peer {
    pub fn new(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .map_err(|e| TorrentError::ConnectionFailed(e.to_string()))?;
        
        // Enable TCP_NODELAY to send packets immediately
        stream.set_nodelay(true)
            .map_err(|e| TorrentError::ConnectionFailed(format!("Failed to set TCP_NODELAY: {}", e)))?;
        
        Ok(Self { stream })
    }

    pub fn enable_tcp_nodelay(&mut self) -> Result<()> {
        self.stream.set_nodelay(true)
            .map_err(|e| TorrentError::ConnectionFailed(format!("Failed to set TCP_NODELAY: {}", e)))?;
        Ok(())
    }

    pub fn handshake(&mut self, info_hash: &[u8; 20], peer_id: &[u8; 20]) -> Result<[u8; 20]> {
        const MAX_RETRIES: u32 = 5;
        const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(1);
        const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);

        let mut handshake = vec![19];
        handshake.extend_from_slice(PROTOCOL.as_bytes());
        handshake.extend_from_slice(&[0; 8]); // Reserved bytes
        handshake.extend_from_slice(info_hash);
        handshake.extend_from_slice(peer_id);

        let mut retry_delay = INITIAL_RETRY_DELAY;
        let mut rng = rand::thread_rng();

        for attempt in 1..=MAX_RETRIES { // Inclusive range to include MAX_RETRIES
            match self.try_handshake(&handshake) {
                Ok(peer_id_received) => return Ok(peer_id_received),
                Err(e) if attempt < MAX_RETRIES => {
                    eprintln!("Handshake attempt {} failed: {}. Retrying...", attempt, e);
                    let jitter = Duration::from_millis(rng.gen_range(0..100));
                    std::thread::sleep(retry_delay + jitter);
                    retry_delay = std::cmp::min(retry_delay * 2, MAX_RETRY_DELAY);
                }
                Err(e) => return Err(e),
            }
        }
       
        Err(TorrentError::ConnectionFailed("Max handshake attempts reached".into()))
    }

    fn try_handshake(&mut self, handshake: &[u8]) -> Result<[u8; 20]> {
        assert_eq!(handshake.len(), 68, "Handshake must be 68 bytes long");
    
        self.stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        self.stream.set_write_timeout(Some(Duration::from_secs(10)))?;  
    
        eprintln!("Sending handshake...");
        self.stream.write_all(handshake)
            .map_err(|e| TorrentError::ConnectionFailed(format!("Failed to send handshake: {}", e)))?;
        eprintln!("Handshake sent. Awaiting response...");
    
        let mut response = [0u8; 68];
        self.stream.read_exact(&mut response)
            .map_err(|e| TorrentError::ConnectionFailed(format!("Failed to receive handshake: {}", e)))?;
        eprintln!("Handshake response received.");
    
        if response[0] != 19 || &response[1..20] != PROTOCOL.as_bytes() {
            return Err(TorrentError::InvalidPeerResponse);
        }
    
        if &response[28..48] != &handshake[28..48] {
            return Err(TorrentError::InvalidPeerResponse);
        }
    
        let mut received_peer_id = [0u8; 20];
        received_peer_id.copy_from_slice(&response[48..68]);
        Ok(received_peer_id)
    }
    

    pub fn receive_bitfield(&mut self) -> Result<()> {
        let message = self.receive_message()?;
        if message.id != 5 {
            return Err(TorrentError::UnexpectedMessage);
        }
        Ok(())
    }

    pub fn send_interested(&mut self) -> Result<()> {
        self.send_message(2, &[])?;
        println!("Sent 'interested' message.");
        Ok(())
    }

    pub fn receive_unchoke(&mut self) -> Result<()> {
        let message = self.receive_message()?;
        if message.id != 1 {
            return Err(TorrentError::UnexpectedMessage);
        }
        println!("Received 'unchoke' message.");
        Ok(())
    }

    pub fn request_block(&mut self, index: usize, begin: usize, length: usize) -> Result<()> {
        let payload = [
            (index as u32).to_be_bytes(),
            (begin as u32).to_be_bytes(),
            (length as u32).to_be_bytes(),
        ].concat();

        self.send_message(6, &payload)?;
        println!("Requested block: piece {}, begin {}, length {}", index, begin, length);
        Ok(())
    }

    pub fn receive_block(&mut self, expected_index: usize, expected_begin: usize) -> Result<Vec<u8>> {
        let message = self.receive_message()?;
        if message.id != 7 {
            return Err(TorrentError::UnexpectedMessage);
        }

        if message.payload.len() < 8 {
            return Err(TorrentError::UnexpectedBlockData);
        }

        let index  = u32::from_be_bytes(message.payload[0..4].try_into()?);
        let begin = u32::from_be_bytes(message.payload[4..8].try_into()?);
        if index as usize != expected_index || begin as usize != expected_begin {
            return Err(TorrentError::UnexpectedBlockData);
        }
        println!("Received block: piece {}, begin {}", index, begin);
        Ok(message.payload[8..].to_vec())
    }

    fn send_message(&mut self, id: u8, payload: &[u8]) -> Result<()> {
        let length = (payload.len() + 1) as u32;

        let mut message = length.to_be_bytes().to_vec();
        message.push(id);
        message.extend_from_slice(payload);
        self.stream.write_all(&message)
            .map_err(|e| TorrentError::ConnectionFailed(format!("Failed to send message: {}", e)))?;
        Ok(())
    }

    fn receive_message(&mut self) -> Result<PeerMessage> {
        let mut length_bytes = [0u8; 4];
        self.stream.read_exact(&mut length_bytes)
            .map_err(|e| TorrentError::ConnectionFailed(format!("Failed to read message length: {}", e)))?;
        let length = u32::from_be_bytes(length_bytes) as usize;

        if length == 0 {
            return Err(TorrentError::UnexpectedMessage);
        }

        let mut message = vec![0u8; length];
        self.stream.read_exact(&mut message)
            .map_err(|e| TorrentError::ConnectionFailed(format!("Failed to read message: {}", e)))?;

        Ok(PeerMessage {
            id: message[0],
            payload: message[1..].to_vec(),
        })
    }
}
