use crate::error::{Result, TorrentError};
use serde_bencode::value::Value;
use std::collections::HashMap;

pub fn decode(data: &[u8]) -> Result<Value> {
    serde_bencode::de::from_bytes(data).map_err(TorrentError::from)
}

pub fn encode(value: &Value) -> Result<Vec<u8>> {
    serde_bencode::ser::to_bytes(value).map_err(TorrentError::from)
}

// Decoding functions for specific types
pub fn decode_bytes(data: &[u8]) -> Result<Vec<u8>> {
    match decode(data)? {
        Value::Bytes(b) => Ok(b),
        _ => Err(TorrentError::UnexpectedType {
            expected: "bytes",
            found: "non-bytes",
        }),
    }
}

pub fn decode_string(data: &[u8]) -> Result<String> {
    let bytes = decode_bytes(data)?;
    String::from_utf8(bytes).map_err(|e| TorrentError::InvalidResponseFormat(e.to_string()))
}

pub fn decode_integer(data: &[u8]) -> Result<i64> {
    match decode(data)? {
        Value::Int(i) => Ok(i),
        _ => Err(TorrentError::UnexpectedType {
            expected: "integer",
            found: "non-integer",
        }),
    }
}

pub fn decode_list(data: &[u8]) -> Result<Vec<Value>> {
    match decode(data)? {
        Value::List(l) => Ok(l),
        _ => Err(TorrentError::UnexpectedType {
            expected: "list",
            found: "non-list",
        }),
    }
}

pub fn decode_dict(data: &[u8]) -> Result<HashMap<Vec<u8>, Value>> {
    match decode(data)? {
        Value::Dict(d) => Ok(d),
        _ => Err(TorrentError::UnexpectedType {
            expected: "dictionary",
            found: "non-dictionary",
        }),
    }
}

// Encoding functions for specific types
pub fn encode_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    encode(&Value::Bytes(bytes.to_vec()))
}

pub fn encode_string(s: &str) -> Result<Vec<u8>> {
    encode_bytes(s.as_bytes())
}

pub fn encode_integer(i: i64) -> Result<Vec<u8>> {
    encode(&Value::Int(i))
}

pub fn encode_list(list: &[Value]) -> Result<Vec<u8>> {
    encode(&Value::List(list.to_vec()))
}

pub fn encode_dict(dict: &HashMap<Vec<u8>, Value>) -> Result<Vec<u8>> {
    encode(&Value::Dict(dict.clone()))
}

// Helper functions for working with dictionaries
// pub fn get_bytes_from_dict(dict: &HashMap<Vec<u8>, Value>, key: &[u8]) -> Result<Vec<u8>> {
//     match dict.get(key) {
//         Some(Value::Bytes(b)) => Ok(b.clone()),
//         Some(_) => Err(TorrentError::UnexpectedType {
//             expected: "bytes",
//             found: "non-bytes",
//         }),
//         None => Err(TorrentError::MissingKey(&String::from_utf8_lossy(key).into_owned())),
//     }
// }

// pub fn get_string_from_dict(dict: &HashMap<Vec<u8>, Value>, key: &[u8]) -> Result<String> {
//     let bytes = get_bytes_from_dict(dict, key)?;
//     String::from_utf8(bytes).map_err(|e| TorrentError::InvalidResponseFormat(e.to_string()))
// }

// pub fn get_integer_from_dict(dict: &HashMap<Vec<u8>, Value>, key: &[u8]) -> Result<i64> {
//     match dict.get(key) {
//         Some(Value::Int(i)) => Ok(*i),
//         Some(_) => Err(TorrentError::UnexpectedType {
//             expected: "integer",
//             found: "non-integer",
//         }),
//         None => Err(TorrentError::MissingKey(String::from_utf8_lossy(key).into_owned())),
//     }
// }

// pub fn get_list_from_dict(dict: &HashMap<Vec<u8>, Value>, key: &[u8]) -> Result<Vec<Value>> {
//     match dict.get(key) {
//         Some(Value::List(l)) => Ok(l.clone()),
//         Some(_) => Err(TorrentError::UnexpectedType {
//             expected: "list",
//             found: "non-list",
//         }),
//         None => Err(TorrentError::MissingKey(String::from_utf8_lossy(key).into_owned())),
//     }
// }

// pub fn get_dict_from_dict(dict: &HashMap<Vec<u8>, Value>, key: &[u8]) -> Result<HashMap<Vec<u8>, Value>> {
//     match dict.get(key) {
//         Some(Value::Dict(d)) => Ok(d.clone()),
//         Some(_) => Err(TorrentError::UnexpectedType {
//             expected: "dictionary",
//             found: "non-dictionary",
//         }),
//         None => Err(TorrentError::MissingKey(String::from_utf8_lossy(key).into_owned())),
//     }
// }
