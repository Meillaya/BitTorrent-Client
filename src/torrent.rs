// torrent.rs

use crate::error::{Result, TorrentError};
use crate::magnet;
use serde::{Deserialize, Serialize};
use serde_bencode::de::from_bytes;
use sha1::{Digest, Sha1};
use std::fs;
// use std::sync::Arc;

pub use hashes::Hashes;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Torrent {
    pub announce: String,
    pub info: Info,
}

impl Torrent {
    pub fn info_hash(&self) -> [u8; 20] {
        let info_encoded =
            serde_bencode::ser::to_bytes(&self.info).expect("Re-encode info section should be fine");
        let mut hasher = Sha1::new();
        hasher.update(&info_encoded);
        hasher
            .finalize()
            .try_into()
            .expect("Hash output should be 20 bytes")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Info {
    pub name: String,
    #[serde(rename = "piece length")]
    pub piece_length: usize,
    pub pieces: Hashes,
    #[serde(flatten)]
    pub keys: Keys,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Keys {
    SingleFile {
        length: usize,
    },
    MultiFile { files: Vec<File> },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct File {
    pub length: usize,
    pub path: Vec<String>,
}

mod hashes {
    // use serde::{Deserialize, Serialize};
    use serde::de::{self, Visitor};
    use serde::ser::Serializer;
    use std::fmt;

    #[derive(Debug, Clone)]
    pub struct Hashes(pub Vec<[u8; 20]>);

    struct HashesVisitor;

    impl<'de> Visitor<'de> for HashesVisitor {
        type Value = Hashes;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a byte string whose length is a multiple of 20")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v.len() % 20 != 0 {
                return Err(E::custom(format!("length is {}", v.len())));
            }

            Ok(Hashes(
                v.chunks_exact(20)
                    .map(|slice_20| slice_20.try_into().expect("Slice is exactly 20 bytes"))
                    .collect(),
            ))
        }
    }

    impl<'de> serde::Deserialize<'de> for Hashes {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_bytes(HashesVisitor)
        }
    }

    impl serde::Serialize for Hashes {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let single_slice = self.0.concat();
            serializer.serialize_bytes(&single_slice)
        }
    }
}

pub fn decode_file(file_path: &str) -> Result<Torrent> {
    let content = fs::read(file_path)?;
    let torrent = from_bytes::<Torrent>(&content)
        .map_err(|_| TorrentError::DecodeError("Failed to deserialize Torrent".into()))?;
    Ok(torrent)
}
#[derive(Clone)]
pub struct TorrentInfo {
    pub announce: String,
    pub info_hash: String,
    pub length: i64,
    pub name: String,
    pub piece_length: i64,
    pub pieces: Vec<[u8; 20]>,
}

impl TorrentInfo {
    pub fn calculate_length(info: &Info) -> i64 {
        match &info.keys {
            Keys::SingleFile { length } => *length as i64,
            Keys::MultiFile { files } => files.iter().map(|f| f.length as i64).sum(),
        }
    }

    pub fn from_magnet(magnet: &magnet::Magnet) -> Result<Self> {
        Ok(TorrentInfo {
            announce: magnet.tracker_url.clone().unwrap_or_default(),
            info_hash: magnet.info_hash.clone(),
            length: 0, // Length is unknown from magnet link
            name: magnet.display_name.clone().unwrap_or_default(),
            piece_length: 0, // Unknown from magnet link
            pieces: Vec::new(), // Unknown from magnet link
        })
    }
}

pub fn get_info(file_path: &str) -> Result<TorrentInfo> {
    let torrent = decode_file(file_path)?;

    let info_hash = torrent.info_hash();
    let length = TorrentInfo::calculate_length(&torrent.info);

    Ok(TorrentInfo {
        announce: torrent.announce,
        info_hash: hex::encode(info_hash),
        length,
        name: torrent.info.name,
        piece_length: torrent.info.piece_length as i64,
        pieces: torrent.info.pieces.0,
    })
}

pub fn get_piece_hash(info: &TorrentInfo, piece_index: usize) -> Result<[u8; 20]> {
    info.pieces
        .get(piece_index)
        .cloned()
        .ok_or_else(|| TorrentError::InvalidResponseFormat("Invalid piece index".into()))
}

pub fn verify_piece(info: &TorrentInfo, piece_index: usize, piece_data: &[u8]) -> bool {
    if let Ok(expected_hash) = get_piece_hash(info, piece_index) {
        let mut hasher = Sha1::new();
        hasher.update(piece_data);
        let actual_hash = hasher.finalize();
        expected_hash == actual_hash.as_slice()
    } else {
        false
    }
}
