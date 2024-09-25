use reqwest;
use serde_json;
use std::{env, fs, fmt};
use serde_bencode::{de, ser, value::Value};
use serde_urlencoded;
use sha1::{Sha1, Digest};
use reqwest::blocking::Client;
use std::net::Ipv4Addr;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};

#[derive(Debug)]
enum TorrentError {
    IoError(std::io::Error),
    DecodeError(serde_bencode::Error),
    MissingKey(&'static str),
    UnexpectedType(&'static str),
    ReqwestError(reqwest::Error),
    UrlEncodingError(serde_urlencoded::ser::Error),
}

impl fmt::Display for TorrentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TorrentError::IoError(e) => write!(f, "IO Error: {}", e),
            TorrentError::DecodeError(e) => write!(f, "Decode Error: {}", e),
            TorrentError::MissingKey(key) => write!(f, "Missing Key: {}", key),
            TorrentError::UnexpectedType(key) => write!(f, "Unexpected Error: {}", key),
            TorrentError::ReqwestError(e) => write!(f, "Reqwest: {}", e),
            TorrentError::UrlEncodingError(key) => write!(f, "UrlEncodingError: {}", key),
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

impl From<reqwest::Error> for TorrentError {
    fn from(error: reqwest::Error) -> Self {
        TorrentError::ReqwestError(error)
    }
}

impl From<serde_urlencoded::ser::Error> for TorrentError {
    fn from(error: serde_urlencoded::ser::Error) -> Self {
        TorrentError::UrlEncodingError(error)
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


fn get_peers(torrent_file: &str) -> Result<(), TorrentError> {
    let decoded_value = decode_torrent_file(torrent_file)?;
    let (tracker_url, info_hash, length) = extract_torrent_info(decoded_value)?;

    
    let encoded_info_hash = percent_encode(&info_hash, NON_ALPHANUMERIC).to_string();

    let params = [
        ("info_hash", encoded_info_hash),
        ("peer_id", "00112233445566778899".to_string()),
        ("port", "6881".to_string()),
        ("uploaded", "0".to_string()),
        ("downloaded", "0".to_string()),
        ("left", length.to_string()),
        ("compact", "1".to_string()),
    ];

    let client = Client::new();
    let url = format!("{}?{}", tracker_url, serde_urlencoded::to_string(&params)?);
    
    let response = client.get(&url).send()?;
    let response_bytes = response.bytes()?;
    let response_value: Value = de::from_bytes(&response_bytes)?;

    if let Value::Dict(response_dict) = response_value {
        if let Some(Value::Bytes(peers_bytes)) = response_dict.get(b"peers" as &[u8]) {
            for chunk in peers_bytes.chunks(6) {
                if chunk.len() == 6 {
                    let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                    let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                    println!("{}:{}", ip, port);
                }
            }
        } else {
            println!("No peers found in the response");
        }
    } else {
        return Err(TorrentError::UnexpectedType("tracker response"));
    }
    Ok(())
}

fn extract_torrent_info(decoded_value: Value) -> Result<(String, Vec<u8>, i64), TorrentError> {
    if let Value::Dict(torrent_dict) = decoded_value {
        let announce = torrent_dict.get(b"announce" as &[u8])
            .ok_or(TorrentError::MissingKey("announce"))?;
        let tracker_url = if let Value::Bytes(announce_bytes) = announce {
            String::from_utf8_lossy(announce_bytes).to_string()
        } else {
            return Err(TorrentError::UnexpectedType("announce"));
        };

        let info = torrent_dict.get(b"info" as &[u8])
            .ok_or(TorrentError::MissingKey("info"))?;
        let info_hash = if let Value::Dict(info_dict) = info {
            let encoded = ser::to_bytes(info)?;
            let mut hasher = Sha1::new();
            hasher.update(&encoded);
            hasher.finalize().to_vec()
        } else {
            return Err(TorrentError::UnexpectedType("info"));
        };
        
        let length = if let Value::Dict(info_dict) = info {
            if let Some(Value::Int(length)) = info_dict.get(b"length" as &[u8]) {
                *length
            } else {
                return Err(TorrentError::MissingKey("length"));
            }
        } else {
            return Err(TorrentError::UnexpectedType("info"));
        };

        Ok((tracker_url, info_hash, length))
    } else {
        Err(TorrentError::UnexpectedType("torrent"))
    }
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
        },
        "info" => {
            let torrent_file = args.get(2).ok_or(TorrentError::MissingKey("torrent file"))?;
            let decoded_value = decode_torrent_file(torrent_file)?;
            let (tracker_url, info_hash, length) = extract_torrent_info(decoded_value)?;
            println!("Tracker URL: {}", tracker_url);
            println!("Length: {}", length);
            println!("Info Hash: {}", hex::encode(info_hash));
        },
        "peers" => {
            let torrent_file = args.get(2).ok_or(TorrentError::MissingKey("torrent file"))?;
            get_peers(torrent_file)?;
        },
        _ => println!("Unknown command: {}", command),
    }

    Ok(())

}