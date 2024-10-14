use crate::{torrent::TorrentInfo, tracker::TrackerResponse, magnet, error::{Result, TorrentError}};
use tokio::{net::TcpStream, time::timeout};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rand::Rng;
use std::time::Duration;
use tokio::time::sleep;
use serde_bencode::value as BencodeValue;

const PROTOCOL: &str = "BitTorrent protocol";
const MAX_HANDSHAKE_ATTEMPTS: usize = 5;

pub struct Peer {
    stream: TcpStream,
    supports_extensions: bool,
    extension_handshake: Option<BencodeValue::Value>,

}

pub struct PeerMessage {
    pub payload: Vec<u8>,
    pub id: u8,
}

impl Peer {
    pub async fn new(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).await
            .map_err(|e| TorrentError::ConnectionFailed(e.to_string()))?;
        Ok(Self {
            stream,
            supports_extensions: true,
            extension_handshake: None,
        })
    }

    pub async fn enable_tcp_nodelay(&mut self) -> Result<()> {
        self.stream.set_nodelay(true)
            .map_err(|e| TorrentError::ConnectionFailed(format!("Failed to set TCP_NODELAY: {}", e)))?;
        Ok(())
    }


    pub async fn handshake(&mut self, info_hash: &[u8; 20], peer_id: &[u8; 20]) -> Result<[u8; 20]> {
        let mut handshake = vec![19];
        handshake.extend_from_slice(PROTOCOL.as_bytes());
    
        let mut reserved_bytes = [0u8; 8];
        reserved_bytes[5] = 0x10; // Set the extension protocol bit
        handshake.extend_from_slice(&reserved_bytes);
        handshake.extend_from_slice(info_hash);
        handshake.extend_from_slice(peer_id);
        
        let mut attempts = 0;
        while attempts < MAX_HANDSHAKE_ATTEMPTS {
            match self.try_handshake(&handshake).await {
                Ok(peer_id_received) => {
                    if self.supports_extensions {
                        self.send_extension_handshake().await?;
                        self.receive_extension_handshake().await?;
                    }
                    return Ok(peer_id_received);
                },
                Err(e) => {
                    eprintln!("Handshake attempt {} failed: {}. Retrying...", attempts + 1, e);
                    attempts += 1;
                    let jitter = rand::thread_rng().gen_range(0..100);
                    sleep(Duration::from_secs(2) + Duration::from_millis(jitter)).await;
                }
            }
        }
        Err(TorrentError::ConnectionFailed("Max handshake attempts reached".into()))
    }

    async fn try_handshake(&mut self, handshake: &[u8]) -> Result<[u8; 20]> {
        assert_eq!(handshake.len(), 68, "Handshake must be 68 bytes long");

        eprintln!("Sending handshake...");
        self.stream.write_all(handshake).await
            .map_err(|e| TorrentError::ConnectionFailed(format!("Failed to send handshake: {}", e)))?;
        eprintln!("Handshake sent. Awaiting response...");

        let mut response = [0u8; 68];
        
        self.stream.read_exact(&mut response).await
            .map_err(|e| TorrentError::ConnectionFailed(format!("Failed to receive handshake: {}", e)))?;
        eprintln!("Handshake response received.");

        if response[0] != 19 || &response[1..20] != PROTOCOL.as_bytes() {
            return Err(TorrentError::InvalidPeerResponse);
        }

        if &response[28..48] != &handshake[28..48] {
            return Err(TorrentError::InvalidPeerResponse);
        }

        self.supports_extensions = (response[25] & 0x10) != 0;
        
        let mut received_peer_id = [0u8; 20];
        received_peer_id.copy_from_slice(&response[48..68]);
        Ok(received_peer_id)
    }

    pub async fn receive_bitfield(&mut self) -> Result<()> {
        let message = self.receive_message().await?;
        if message.id != 5 {
            return Err(TorrentError::UnexpectedMessage("Expected bitfield message".to_string()));
        }
        Ok(())
    }

    pub async fn send_interested(&mut self) -> Result<()> {
        self.send_message(2, &[]).await?;
        println!("Sent 'interested' message.");
        Ok(())
    }

    pub async fn receive_unchoke(&mut self) -> Result<()> {
        let message = self.receive_message().await?;
        if message.id != 1 {
            return Err(TorrentError::UnexpectedMessage("Expected unchoke message".to_string()));
        }
        println!("Received 'unchoke' message.");
        Ok(())
    }

    pub async fn request_block(&mut self, index: usize, begin: usize, length: usize) -> Result<()> {
        let payload = [
            (index as u32).to_be_bytes(),
            (begin as u32).to_be_bytes(),
            (length as u32).to_be_bytes(),
        ].concat();

        self.send_message(6, &payload).await?;
        println!("Requested block: piece {}, begin {}, length {}", index, begin, length);
        Ok(())
    }

    pub async fn receive_block(&mut self, expected_index: usize, expected_begin: usize) -> Result<Vec<u8>> {
        let message = self.receive_message().await?;
        if message.id != 7 {
            return Err(TorrentError::UnexpectedMessage("Expected block message".to_string()));
        }

        if message.payload.len() < 8 {
            return Err(TorrentError::UnexpectedBlockData);
        }

        let index = u32::from_be_bytes(message.payload[0..4].try_into()?);
        let begin = u32::from_be_bytes(message.payload[4..8].try_into()?);
        if index as usize != expected_index || begin as usize != expected_begin {
            return Err(TorrentError::UnexpectedBlockData);
        }
        println!("Received block: piece {}, begin {}", index, begin);
        Ok(message.payload[8..].to_vec())
    }

    async fn send_message(&mut self, id: u8, payload: &[u8]) -> Result<()> {
        let length = (payload.len() + 1) as u32;
        let mut message = length.to_be_bytes().to_vec();
        message.push(id);
        message.extend_from_slice(payload);
        self.stream.write_all(&message).await
            .map_err(|e| TorrentError::ConnectionFailed(format!("Failed to send message: {}", e)))?;
        Ok(())
    }

    async fn receive_message(&mut self) -> Result<PeerMessage> {
        const TIMEOUT_DURATION: Duration = Duration::from_secs(30);
    
        // Read the message length (4 bytes)
        let mut length_bytes = [0u8; 4];
        timeout(TIMEOUT_DURATION, self.stream.read_exact(&mut length_bytes)).await
            .map_err(|_| TorrentError::ConnectionTimeout)??;
    
        let length = u32::from_be_bytes(length_bytes) as usize;
        // println!("Received message length: {} bytes", length);
    
        if length == 0 {
            // Keep-alive message with no payload
            return Ok(PeerMessage { id: 0, payload: Vec::new() });
        }
    
        // Read the message body
        let mut buffer = vec![0u8; length];
        let mut total_read = 0;
    
        while total_read < length {
            match timeout(TIMEOUT_DURATION, self.stream.read(&mut buffer[total_read..])).await {
                Ok(Ok(0)) => return Err(TorrentError::ConnectionClosed),
                Ok(Ok(n)) => {
                    total_read += n;
                    // println!("Read {} bytes, total: {}/{}", n, total_read, length);
                },
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(Err(e)) => return Err(TorrentError::ConnectionFailed(format!("Failed to read message: {}", e))),
                Err(_) => return Err(TorrentError::ConnectionTimeout),
            }
        }
    
        // Parse the message
        let id = buffer[0];
        let payload = buffer[1..].to_vec();
    
        // println!("Received message: ID={}, payload length={}", id, payload.len());
        Ok(PeerMessage { id, payload })
    }
    

    pub async fn receive_metadata(&mut self) -> Result<Vec<u8>> {
        let message = self.receive_message().await?;
        if message.id != 20 {
            return Err(TorrentError::UnexpectedMessage("Expected message ID 20".to_string()));
        }
        // println!("Received message: ID={}", message.id);

        let _extension_id = message.payload[0];
        // println!("Received extension ID: {}", extension_id);
        
        let payload = &message.payload[1..];
        let dict: serde_bencode::value::Value = serde_bencode::from_bytes(payload)?;
    
        // println!("Received message: ID={}, payload={:?}", message.id, message.payload);
    
        if let serde_bencode::value::Value::Dict(d) = dict {
            let msg_type = d.get(&b"msg_type".to_vec())
                .and_then(|v| if let serde_bencode::value::Value::Int(i) = v { Some(*i) } else { None })
                .ok_or(TorrentError::InvalidMetadataResponse)?;
            let piece = d.get(&b"piece".to_vec())
                .and_then(|v| if let serde_bencode::value::Value::Int(i) = v { Some(*i) } else { None })
                .ok_or(TorrentError::InvalidMetadataResponse)?;
            
            if msg_type == 1 && piece == 0 {
                let encoded_dict = serde_bencode::to_bytes(&serde_bencode::value::Value::Dict(d.clone()))?;
                let dict_length = encoded_dict.len();
    
                if payload.len() > dict_length {
                    let metadata = &payload[dict_length..];
                    println!("Received metadata: length={}", metadata.len());
                    return Ok(metadata.to_vec());
                }
            }
        }
    
        Err(TorrentError::InvalidMetadataResponse)
    }    
    
    

    pub async fn send_metadata_request(&mut self) -> Result<()> {
        let extension_id = self.get_metadata_extension_id()?;

        // Construct the bencoded dictionary: {'msg_type': 0, 'piece': 0}
        let dict = serde_bencode::value::Value::Dict(vec![
            (b"msg_type".to_vec(), serde_bencode::value::Value::Int(0)),
            (b"piece".to_vec(), serde_bencode::value::Value::Int(0)),
        ].into_iter().collect());
        let bencoded_dict = serde_bencode::to_bytes(&dict)?;

        // Construct the payload: [extension message ID][bencoded dictionary]
        let mut payload = vec![extension_id];
        payload.extend_from_slice(&bencoded_dict);

        // Send the extended message with message ID 20
        self.send_message(20, &payload).await?;

        println!("Sent metadata request");
        Ok(())
    }

    fn get_metadata_extension_id(&self) -> Result<u8> {
        if let Some(serde_bencode::value::Value::Dict(dict)) = &self.extension_handshake {
            if let Some(serde_bencode::value::Value::Dict(m_dict)) = dict.get(&b"m".to_vec()) {
                if let Some(serde_bencode::value::Value::Int(id)) = m_dict.get(&b"ut_metadata".to_vec()) {
                    return Ok(*id as u8);
                }
            }
        }
        Err(TorrentError::MetadataExtensionNotSupported)
    }



    pub async fn receive_extension_handshake(&mut self) -> Result<()> {
        loop {
            let message = self.receive_message().await?;
            match message.id {
                20 => {
                    // Extended message
                    if message.payload.is_empty() {
                        continue; // No extended message ID, ignore
                    }
                    let extended_id = message.payload[0];
                    if extended_id == 0 {
                        // Extension handshake
                        let handshake_data: serde_bencode::value::Value = serde_bencode::from_bytes(&message.payload[1..])?;
                        self.extension_handshake = Some(handshake_data.clone());

                        // println!("Received extension handshake: {:?}", self.extension_handshake);
                        if let Some(serde_bencode::value::Value::Dict(dict)) = &self.extension_handshake {
                            if let Some(serde_bencode::value::Value::Dict(m_dict)) = dict.get(&b"m".to_vec()) {
                                if let Some(serde_bencode::value::Value::Int(id)) = m_dict.get(&b"ut_metadata".to_vec()) {
                                    println!("Peer Metadata Extension ID: {}", id);
                                }
                            }
                        }
                        return Ok(());
                    } else {
                        // Other extended messages can be handled here
                        println!("Received extended message with ID: {}", extended_id);
                    }
                },
                5 => {
                    // Bitfield message
                    println!("Received bitfield message");
                    // You can process the bitfield here if needed
                },
                _ => {
                    // Handle other message types or ignore
                    println!("Received message with ID: {}", message.id);
                }
            }
        }
    }

    pub async fn send_extension_handshake(&mut self) -> Result<()> {
        let extension_handshake = {
            let mut m = std::collections::HashMap::new();
            m.insert("ut_metadata".to_string(), 1u8);
            let dict = serde_json::json!({ "m": m });
            serde_bencode::to_bytes(&dict)?
        };

        self.send_message(20, &[0].iter().chain(extension_handshake.iter()).copied().collect::<Vec<u8>>()).await?;
        println!("Sent extension handshake");
        Ok(())
    }
    pub async fn magnet_handshake(&mut self, magnet_link: &str) -> Result<[u8; 20]> {
        let parsed_magnet = magnet::Magnet::parse(magnet_link)?;
        let info_hash = hex::decode(&parsed_magnet.info_hash)
            .map_err(|_| TorrentError::InvalidInfoHash)?;
        let info_hash: [u8; 20] = info_hash.try_into()
            .map_err(|_| TorrentError::InvalidInfoHash)?;
        let peer_id: [u8; 20] = generate_peer_id();
        let received_peer_id = self.handshake(&info_hash, &peer_id).await?;


        let torrent_info = TorrentInfo::from_magnet(&parsed_magnet)?;
        let tracker_response =
            TrackerResponse::query_with_url(&torrent_info, &info_hash).await?;

        if tracker_response.peers.0.is_empty() {
            return Err(TorrentError::NoPeersAvailable);
        }

  
        Ok(received_peer_id)
    }
}

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