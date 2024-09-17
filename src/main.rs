use serde_json;
use std::env;
use serde_bencode::de;

//using serde_bencode
fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {

    let decoded: serde_bencode::value::Value = de::from_bytes(encoded_value.as_bytes())
        .expect("Failed to decode bencoded value");

    match decoded {

        serde_bencode::value::Value::Int(i) => serde_json::Value::Number(serde_json::Number::from(i)),
        serde_bencode::value::Value::Bytes(b) => {
            let s = String::from_utf8_lossy(&b);
            serde_json::Value::String(s.into_owned())
        },
        _ => panic!("Unsopported bencoded type"),
    }

}

//Using standard libraries
// #[allow(dead_code)]
// fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
//     if encoded_value.starts_with('i') && encoded_value.ends_with('e') {


//         let number_str = &encoded_value[1..encoded_value.len() -1];
//         match number_str.parse::<i64>(){
//             Ok(number) => serde_json::Value::Number(serde_json::Number::from(number)),
//             Err(_) => panic!("Invalid bencoded integer: {}", encoded_value),
//         }
//     }
//     else if encoded_value.chars().next().unwrap().is_digit(10) {
//         let colon_index = encoded_value.find(':').unwrap();
//         let number_string = &encoded_value[..colon_index];
//         let number = number_string.parse::<i64>().unwrap();
//         let string = &encoded_value[colon_index + 1..colon_index + 1 + number as usize];
//         return serde_json::Value::String(string.to_string());
//     } else {
//         panic!("Unhandled encoded value: {}", encoded_value)
//     }
// }

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        // println!("Logs from your program will appear here!");

        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } else {
        println!("unknown command: {}", args[1])
    }
}
