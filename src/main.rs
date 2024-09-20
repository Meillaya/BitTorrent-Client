use hex;
use reqwest;
use serde_json;
use std::{env, fs, fmt};
use serde_bencode::{de, ser, value::Value};
use serde_urlencoded;
use sha1::{Sha1, Digest};
use std::collections::HashMap;
use reqwest::blocking::Client;
use std::net::{Ipv4Addr, SocketAddrV4};


#[derive(Debug)]
enum TorrentError {
    IoError(std::io::Error),
    DecodeError(serde_bencode::Error),
    MissingKey(&'static str),
    UnexpectedType(&'static str),
    ReqwestError(reqwest::Error),
}

impl fmt::Display for TorrentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TorrentError::IoError(e) => write!(f, "IO Error: {}", e),
            TorrentError::DecodeError(e) => write!(f, "Decode Error: {}", e),
            TorrentError::MissingKey(key) => write!(f, "Missing Key: {}", key),
            TorrentError::UnexpectedType(key) => write!(f, "Unexpected Error: {}", key),
            TorrentError::ReqwestError(e) => write!(f, "Reqwest: {}", e),
        }
    }
}

impl From <std::io::Error> for TorrentError {
    fn from(error: std::io::Error) -> Self {
        TorrentError::IoError(error)
    }
}

impl From <serde_bencode::Error> for TorrentError {
    fn from(error: serde_bencode::Error) -> Self {
        TorrentError::DecodeError(error)
    }
}

fn decode_torrent_file(file_path: &str) -> Result<Value, TorrentError> {

    let torrent_content = fs::read(file_path)?;
    Ok(de::from_bytes(&torrent_content)?)
}


fn decode_bencoded_value(encoded_value: &[u8]) -> Result<serde_json::Value, TorrentError> {

    let decoded: serde_bencode::value::Value = de::from_bytes(encoded_value)?;

    Ok(match decoded {
        Value::Int(i) => serde_json::Value::Number(serde_json::Number::from(i)),
        Value::Bytes(b) => {
            let s = String::from_utf8_lossy(&b);
            serde_json::Value::String(s.into_owned())
        },
        Value::List(l) => {
            let json_list: Result<Vec<serde_json::Value>, TorrentError> = l.into_iter()
                .map(|v|{
                    let encoded = ser::to_bytes(&v)?;
                    decode_bencoded_value(&encoded)
                })
                .collect();
            serde_json::Value::Array(json_list?)
        },
        Value::Dict(d) => {
            let json_map: Result<serde_json::Map<String, serde_json::Value>, TorrentError> =  d.into_iter()
            .map(|(k, v)| {
                let key = String::from_utf8_lossy(&k).into_owned();
                let encoded = ser::to_bytes(&v)?;
                let value = decode_bencoded_value(&encoded)?;
                Ok((key,value))
            })
            .collect();
        serde_json::Value::Object(json_map?)
        }
    })
}

fn extract_torrent_info(decoded_value: Value) -> Result<(), TorrentError> {

    if let Value::Dict(torrent_dict) = decoded_value {

        let announce = torrent_dict.get("announce".as_bytes())
            .ok_or(TorrentError::MissingKey("announce"))?;
        if let Value::Bytes(announce_bytes) = announce {
            let tracker_url = String::from_utf8_lossy(announce_bytes);
            println!("Tracker URL: {}", tracker_url);
        }
        else {
            return Err(TorrentError::UnexpectedType("announce"));

        }

        let info = torrent_dict.get("info".as_bytes())
        .ok_or(TorrentError::MissingKey("info"))?;
        if let Value::Dict(info_dict) = info {
            let length = info_dict.get("length".as_bytes())
                .ok_or(TorrentError::MissingKey("length"))?;
            if let Value::Int(length_value) = length {
                println!("Length: {}", length_value);
            } else {
                return Err(TorrentError::UnexpectedType("length"));
            }

            let info_hash = calculate_info_hash(info)?;
            println!("Info Hash: {}", info_hash);

            let piece_length = info_dict.get("piece length".as_bytes())
                .ok_or(TorrentError::MissingKey("piece length"))?;
            if let Value::Int(piece_length_value) = piece_length {
                println!("Piece Length: {}", piece_length_value);
            } else {
                return Err(TorrentError::UnexpectedType("piece length"));
            }


            let pieces = info_dict.get("pieces".as_bytes())
                .ok_or(TorrentError::MissingKey("pieces"))?;
            if let Value::Bytes(pieces_bytes) = pieces {

                println!("Pieces Hashes:");
                for chunk in pieces_bytes.chunks(20) {
                    println!("{}", hex::encode(chunk));
                }
            } else {         
                return Err(TorrentError::UnexpectedType("pieces"));
            }
        } else {
            return Err(TorrentError::UnexpectedType("info"));
        }
    } else {
        return Err(TorrentError::UnexpectedType("torrent"));
    }
    Ok(())

}

fn calculate_info_hash(info: &Value) -> Result<String, TorrentError> {

    let encoded = ser::to_bytes(info)?;
    let mut hasher = Sha1::new();
    hasher.update(&encoded);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}


// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() -> Result<(), TorrentError> {

    let args: Vec<String> = env::args().collect();
    let command = args.get(1).ok_or(TorrentError::MissingKey("command"))?;

    match command.as_str() {

        "decode" => {
            let encoded_value = args.get(2)
            .ok_or(TorrentError::MissingKey("encoded value"))?
            .as_bytes();
            let decoded_value = decode_bencoded_value(encoded_value)?;
            println!("{}", decoded_value.to_string());
        }
        "info" => {

            let torrent_file = args.get(2).ok_or(TorrentError::MissingKey("torrent file"))?;
            let decoded_value = decode_torrent_file(torrent_file)?;
            extract_torrent_info(decoded_value)?;
        }
        _ => println!("Unknown command: {}", command),
    }

    Ok(())

}
