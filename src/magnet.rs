use crate::error::{Result, TorrentError};
use url::Url;

pub struct Magnet {
    pub info_hash: String,
    pub tracker_url: Option<String>,
    pub display_name: Option<String>,
}

impl Magnet {
    pub fn parse(link: &str) -> Result<Self> {
        let url = Url::parse(link)
            .map_err(|_|TorrentError::InvalidMagnetLink)?;

        if url.scheme() != "magnet" {
            return Err(TorrentError::InvalidMagnetLink)
        }

        let mut info_hash = None;
        let mut tracker_url = None;
        let mut display_name = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "xt" => {
                    if value.starts_with("urn:btih:") {
                        info_hash = Some(value[9..].to_string());
                    }
                }
                "tr" => tracker_url = Some(value.to_string()),
                "dn" => display_name = Some(value.to_string()),
                _ => {}
            }
        }

        let info_hash = info_hash.ok_or(TorrentError::InvalidMagnetLink)?;

        Ok(Magnet {
            info_hash,
            tracker_url,
            display_name,
        })

    }
}