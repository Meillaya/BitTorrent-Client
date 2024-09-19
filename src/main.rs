use serde_json;
use std::{env, fs, fmt};
use serde_bencode::{de, ser, value::Value};

#[derive(Debug)]
enum TorrentError {
    IoError(std::io::Error),
    DecodeError(serde_bencode::Error),
    MissingKey(&'static str),
    UnexpectedType(&'static str),
}

impl fmt::Display for TorrentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TorrentError::IoError(e) => write!(f, "IO Error: {}", e),
            TorrentError::DecodeError(e) => write!(f, "Decode Error: {}", e),
            TorrentError::MissingKey(key) => write!(f, "Missing Key: {}", key),
            TorrentError::UnexpectedType(key) => write!(f, "Unexpected Error: {}", key),
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

fn decode_torrent_file(file_path: &str) -> Value {

    let torrent_content = fs::read(file_path);
    Okde::from_bytes(&torrent_content)
}


fn decode_bencoded_value(encoded_value: &[u8]) -> serde_json::Value {

    let decoded: serde_bencode::value::Value = de::from_bytes(encoded_value)
        .expect("Failed to decode bencoded value");

    match decoded {
        serde_bencode::value::Value::Int(i) => serde_json::Value::Number(serde_json::Number::from(i)),
        serde_bencode::value::Value::Bytes(b) => {
            let s = String::from_utf8_lossy(&b);
            serde_json::Value::String(s.into_owned())
        },
        serde_bencode::value::Value::List(l) => {
            let json_list: Vec<serde_json::Value> = l.into_iter()
                .map(|v|{
                    let encoded = ser::to_bytes(&v).expect("Failed to encode value");
                    decode_bencoded_value(&encoded)
                })
                .collect();
            serde_json::Value::Array(json_list)
        },
        serde_bencode::value::Value::Dict(d) => {
            let json_map: serde_json::Map<String, serde_json::Value> = d.into_iter()
            .map(|(k, v)| {
                let key = String::from_utf8_lossy(&k).into_owned();
                let encoded = ser::to_bytes(&v).expect("Failed to encode value");
                let value = decode_bencoded_value(&encoded);
                (key,value)
            })
            .collect();
        serde_json::Value::Object(json_map)
        }
    }
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2].as_bytes(); // Convert String to &[u8]
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } 
    else if command == "info" {
        let torrent_file = &args[2];
        let decoded_value = decode_torrent_file(torrent_file);

        if let Value::Dict(torrent_dict) = decoded_value {

            //Extract tracker URL
            if let Some(Value::Bytes(announce)) = torrent_dict.get("announce".as_bytes()) {
                let tracker_url = String::from_utf8_lossy(announce);
                println!("Tracker URL: {}", tracker_url);
            }

            //Extract file length
            if let Some (Value::Dict(info)) = torrent_dict.get("info".as_bytes()) {
                if let Some(Value::Int(length)) = info.get("length".as_bytes()) {
                    println!("Length: {}", length);
                }
            }
        }
    } else {
        println!("unknown command: {}", args[1])
    }
}
