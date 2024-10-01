use bittorrent_starter_rust::{
    bencode, error::{Result, TorrentError}, torrent, tracker, peer, download, magnet
};
use serde_json::Value;
use serde_bencode::value::Value as BencodeValue;
use tracker::TrackerResponse;
use torrent::TorrentInfo;
use tokio;



#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [<args>]", args[0]);
        eprintln!("Commands: decode, info, peers, handshake, download_piece, download");
        std::process::exit(1);
    }
    
    let command = &args[1];
    
    match command.as_str() {
        "decode" => {
            if args.len() != 3 {
                eprintln!("Usage: {} decode <bencoded_value>", args[0]);
                std::process::exit(1);
            }
            let bencoded_value = args[2].as_bytes();
            let decoded: BencodeValue = bencode::decode(bencoded_value)?;
            let json_value: Value = bencode_to_json(decoded);
            println!("{}", serde_json::to_string_pretty(&json_value)?);
        },
        "info" => {
            if args.len() != 3 {
                eprintln!("Usage: {} info <torrent_file>", args[0]);
                std::process::exit(1);
            }
            let torrent_file = &args[2];
            let info = torrent::get_info(torrent_file)?;
            println!("Tracker URL: {}", info.announce);
            println!("Length: {}", info.length);
            println!("Info Hash: {}", info.info_hash);
            println!("Piece Length: {}", info.piece_length);
            println!("Number of Pieces: {}", info.pieces.len());
        },
        "peers" => {
            if args.len() != 3 {
                eprintln!("Usage: {} peers <torrent_file>", args[0]);
                std::process::exit(1);
            }
            let torrent_file = &args[2];
            let info = torrent::get_info(torrent_file)?;
            let info_hash = hex::decode(&info.info_hash)
                .map_err(|_| TorrentError::InvalidInfoHash)?;
            let info_hash: [u8; 20] = info_hash.try_into()
                .map_err(|_| TorrentError::InvalidInfoHash)?;
            let tracker_response = TrackerResponse::query(&info, &info_hash).await?;
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

            let peer_id: [u8; 20] = *b"00112233445566778899"; // Consider generating a unique peer ID
            let mut peer = peer::Peer::new(peer_addr).await?;
            let received_peer_id = peer.handshake(&info_hash, &peer_id).await?;

            println!("Peer ID: {}", hex::encode(received_peer_id));
        },
        "download_piece" => {
            if args.len() != 6 {
                eprintln!("Usage: {} download_piece -o <output_file> <torrent_file> <piece_index>", args[0]);
                std::process::exit(1);
            }
            if args[2] != "-o" {
                eprintln!("Usage: {} download_piece -o <output_file> <torrent_file> <piece_index>", args[0]);
                std::process::exit(1);
            }
            let output_file = &args[3];
            let torrent_file = &args[4];
            let piece_index: usize = match args[5].parse() {
                Ok(index) => index,
                Err(_) => {
                    eprintln!("Invalid piece index: {}", args[5]);
                    std::process::exit(1);
                }
            };

            download::download_piece(output_file, torrent_file, piece_index).await?;
        },
        "download" => {
            if args.len() != 5 || args[2] != "-o" {
                eprintln!("Usage: {} download -o <output_file> <torrent_file>", args[0]);
                std::process::exit(1);
            }
            let output_file = &args[3];
            let torrent_file = &args[4];

           
            download::download_file(output_file, torrent_file).await?;
        },
        "magnet_parse" => {
            if args.len() != 3 {
                eprintln!("Usage: {} magnet_parse <magnet-link>", args[0]);
                std::process::exit(1);
            }

            let magnet_link = &args[2];
            let parsed_magnet = magnet::Magnet::parse(&magnet_link)?;
            if let Some(tracker_url) = parsed_magnet.tracker_url {
                println!("Tracker URL: {}", tracker_url);
            }
            println!("Info Hash: {}", parsed_magnet.info_hash);
        },
        "magnet_handshake" => {
            if args.len() != 3 {
                eprintln!("Usage: {} magnet_handshake <magnet-link>", args[0]);
                std::process::exit(1);
            }

            let magnet_link = &args[2];
            magnet_handshake(magnet_link).await?;
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            eprintln!("Commands: decode, info, peers, handshake, download_piece, download");
            std::process::exit(1);
        }
    }
    
    Ok(())
}

async fn magnet_handshake(magnet_link: &str) -> Result<()> {

    let parsed_magnet = magnet::Magnet::parse(magnet_link)?;
    let info_hash = hex::decode(&parsed_magnet.info_hash)
        .map_err(|_| TorrentError::InvalidInfoHash)?;
    let info_hash: [u8; 20] = info_hash.try_into()
        .map_err(|_| TorrentError::InvalidInfoHash)?;
    

    let torrent_info = TorrentInfo::from_magnet(&parsed_magnet)?;
    let tracker_response =
        TrackerResponse::query_with_url(&torrent_info, &info_hash).await?;


    if tracker_response.peers.0.is_empty() {
        return Err(TorrentError::NoPeersAvailable);
    }

    let peer_addr = &tracker_response.peers.0[0].to_string();
    let mut peer = peer::Peer::new(peer_addr).await?;
    
    let received_peer_id = peer.magnet_handshake(magnet_link).await?;

    println!("Peer ID: {}", hex::encode(received_peer_id));

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
