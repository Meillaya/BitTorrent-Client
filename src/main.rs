use serde_json;
use std::env;
use serde_bencode::de;
use serde_bencode::ser;

//using serde_bencode
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
    } else {
        println!("unknown command: {}", args[1])
    }
}
