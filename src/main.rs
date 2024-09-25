use bittorrent_starter_rust::{bencode, error::{Result, TorrentError}, torrent, tracker, peer};
use serde_json::Value;
use serde_bencode::value::Value as BencodeValue;
use tracker::TrackerResponse;
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [<args>]", args[0]);
        eprintln!("Commands: decode, info, peers, handshake");
        std::process::exit(1);
    }
    
    let command = &args[1];
    let torrent_file = &args[2];
    
    match command.as_str() {
        "decode" => {
            if args.len() != 3 {
                eprintln!("Usage: {} decode <bencoded_value>", args[0]);
                std::process::exit(1);
            }
            let bencoded_value = args[2].as_bytes();
            let decoded: BencodeValue = bencode::decode(bencoded_value)?;
            let json_value: Value = bencode_to_json(decoded);
            println!("{}", serde_json::to_string(&json_value)?);
        },
        "info" => {
            let info = torrent::get_info(torrent_file)?;
            println!("Tracker URL: {}", info.announce);
            println!("Length: {}", info.length);
            println!("Info Hash: {}", info.info_hash);
            println!("Piece Length: {}", info.piece_length);
            println!("Piece Hashes:");
            for (index, hash) in info.pieces.iter().enumerate() {
                println!("{}: {}", index, hex::encode(hash));
            }
        },
        "peers" => {
            let info = torrent::get_info(torrent_file)?;
            let info_hash = hex::decode(&info.info_hash)
                .map_err(|_| TorrentError::InvalidInfoHash)?;
            let info_hash: [u8; 20] = info_hash.try_into()
                .map_err(|_| TorrentError::InvalidInfoHash)?;
            let tracker_response = TrackerResponse::query(&info, &info_hash)?;
            for peer in tracker_response.peers.0 {
                println!("{}", peer);
            }
        },
        "handshake" => {
            if args.len() != 4 {
                eprintln!("Usage: {} handshake <torrent_file> <peer>", args[0]);
                std::process::exit(1);
            }
            let torrent_file = &args[2];
            let peer_addr = &args[3];

            let info = torrent::get_info(torrent_file)?;
            let info_hash = hex::decode(&info.info_hash)
                .map_err(|_| TorrentError::InvalidInfoHash)?;
            let info_hash: [u8; 20] = info_hash.try_into()
                .map_err(|_| TorrentError::InvalidInfoHash)?;

            let peer_id = *b"00112233445566778899";
            let mut peer = peer::Peer::new(peer_addr)?;
            let received_peer_id = peer.handshake(&info_hash, &peer_id)?;

            println!("Peer ID: {}", hex::encode(received_peer_id));
        },
        "download_piece" => {
            if arg
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            std::process::exit(1);
        }
    }
    
    Ok(())
}

fn bencode_to_json(value: BencodeValue) -> Value {
    match value {
        BencodeValue::Bytes(b) => {
            match String::from_utf8(b.clone()) {
                Ok(s) => Value::String(s),
                Err(_) => Value::String(hex::encode(b)),
            }
        },
        BencodeValue::Int(i) => Value::Number(i.into()),
        BencodeValue::List(l) => Value::Array(l.into_iter().map(bencode_to_json).collect()),
        BencodeValue::Dict(d) => {
            let mut map = serde_json::Map::new();
            for (k, v) in d {
                let key = String::from_utf8_lossy(&k).into_owned();
                map.insert(key, bencode_to_json(v));
            }
            Value::Object(map)
        },
    }
}