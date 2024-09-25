// src/torrent.rs

use crate::error::{Result, TorrentError};
use serde::{Deserialize, Serialize};
use serde_bencode::de::from_bytes;
use sha1::{Digest, Sha1};
use std::fs;

pub use hashes::Hashes;

/// A Metainfo file (also known as .torrent files).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Torrent {
    /// The URL of the tracker.
    pub announce: String,

    pub info: Info,
}

impl Torrent {
    /// Calculates the SHA1 info hash of the `info` section.
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
    /// The suggested name to save the file (or directory) as. It is purely advisory.
    ///
    /// In the single file case, the name key is the name of a file, in the multiple file case, it's
    /// the name of a directory.
    pub name: String,

    /// The number of bytes in each piece the file is split into.
    ///
    /// For the purposes of transfer, files are split into fixed-size pieces which are all the same
    /// length except for possibly the last one which may be truncated.
    #[serde(rename = "piece length")]
    pub piece_length: usize,

    /// Each entry of `pieces` is the SHA1 hash of the piece at the corresponding index.
    pub pieces: Hashes,

    #[serde(flatten)]
    pub keys: Keys,
}

/// There is a key `length` or a key `files`, but not both or neither.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Keys {
    /// If `length` is present then the download represents a single file.
    SingleFile {
        /// The length of the file in bytes.
        length: usize,
    },
    /// Otherwise it represents a set of files which go in a directory structure.
    ///
    /// For the purposes of the other keys in `Info`, the multi-file case is treated as only having
    /// a single file by concatenating the files in the order they appear in the files list.
    MultiFile { files: Vec<File> },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct File {
    /// The length of the file, in bytes.
    pub length: usize,

    /// Subdirectory names for this file, the last of which is the actual file name
    /// (a zero length list is an error case).
    pub path: Vec<String>,
}

/// Module for handling piece hashes.
mod hashes {
    use serde::{Deserialize, Serialize};
    use serde::de::{self, Deserializer, Visitor};
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

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
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

    impl<'de> Deserialize<'de> for Hashes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(HashesVisitor)
        }
    }

    impl Serialize for Hashes {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let single_slice = self.0.concat();
            serializer.serialize_bytes(&single_slice)
        }
    }
}

/// Decodes a bencoded torrent file into a `Torrent` struct.
pub fn decode_file(file_path: &str) -> Result<Torrent> {
    let content = fs::read(file_path)?;
    let torrent = from_bytes::<Torrent>(&content)
        .map_err(|_| TorrentError::DecodeError("Failed to deserialize Torrent".into()))?;
    Ok(torrent)
}

/// Struct to hold extracted torrent information.
pub struct TorrentInfo {
    pub announce: String,
    pub info_hash: String,
    pub length: i64,
    pub name: String,
    pub piece_length: i64,
    pub pieces: Vec<[u8; 20]>,
}

impl TorrentInfo {
    /// Calculates the total length of the torrent.
    pub fn calculate_length(info: &Info) -> i64 {
        match &info.keys {
            Keys::SingleFile { length } => *length as i64,
            Keys::MultiFile { files } => files.iter().map(|f| f.length as i64).sum(),
        }
    }
}

/// Retrieves torrent information including the info hash.
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

/// Retrieves the SHA1 hash of a specific piece.
pub fn get_piece_hash(info: &TorrentInfo, piece_index: usize) -> Result<[u8; 20]> {
    info.pieces
        .get(piece_index)
        .cloned()
        .ok_or_else(|| TorrentError::InvalidResponseFormat("Invalid piece index".into()))
}

/// Verifies a piece's integrity by comparing its hash.
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