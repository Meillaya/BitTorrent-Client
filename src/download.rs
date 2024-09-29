// download.rs

use crate::{
    torrent, tracker, peer, error::{Result, TorrentError}
};
use std::io::Write;
use std::fs;


pub fn download_file(output_file: &str, torrent_file: &str) -> Result<()> {
    let info = torrent::get_info(torrent_file)?;
    let info_hash = hex::decode(&info.info_hash)
        .map_err(|_| TorrentError::InvalidInfoHash)?;
    let info_hash: [u8; 20] = info_hash.try_into()
        .map_err(|_| TorrentError::InvalidInfoHash)?;

    let tracker_response = tracker::TrackerResponse::query(&info, &info_hash)?;
    if tracker_response.peers.0.is_empty() {
        return Err(TorrentError::NoPeersAvailable);
    }

    let total_pieces = info.pieces.len();
    let mut all_pieces = Vec::with_capacity(total_pieces);

    for piece_index in 0..total_pieces {
        let mut piece_downloaded = false;
        for peer_addr in tracker_response.peers.0.iter().take(5) {
            let peer_addr_str = peer_addr.to_string();
            eprintln!("Attempting to download piece {} from peer: {}", piece_index, peer_addr_str);
            match try_download_from_peer(&peer_addr_str, &info, &info_hash, piece_index) {
                Ok(piece_data) => {
                    if torrent::verify_piece(&info, piece_index, &piece_data) {
                        all_pieces.push(piece_data);
                        piece_downloaded = true;
                        println!("Successfully downloaded piece {}", piece_index);
                        break;
                    } else {
                        eprintln!("Piece {} failed verification from peer {}", piece_index, peer_addr_str);
                    }
                }
                Err(e) => eprintln!("Failed to download piece {} from peer {}: {}", piece_index, peer_addr_str, e),
            }
        }
        if !piece_downloaded {
            return Err(TorrentError::DownloadFailed(format!("Failed to download piece {}", piece_index)));
        }
    }

    // Combine all pieces into a single file
    let mut file = fs::File::create(output_file)?;
    for piece in all_pieces {
        file.write_all(&piece)?;
    }

    println!("Successfully downloaded file to {}", output_file);
    Ok(())
}




pub fn download_piece(output_file: &str, torrent_file: &str, piece_index: usize) -> Result<()> {
    let info = torrent::get_info(torrent_file)?;
    let info_hash = hex::decode(&info.info_hash)
        .map_err(|_| TorrentError::InvalidInfoHash)?;
    let info_hash: [u8; 20] = info_hash.try_into()
        .map_err(|_| TorrentError::InvalidInfoHash)?;

    let tracker_response = tracker::TrackerResponse::query(&info, &info_hash)?;
    if tracker_response.peers.0.is_empty() {
        return Err(TorrentError::NoPeersAvailable);
    }

    for peer_addr in tracker_response.peers.0.iter().take(5) {
        // Assuming peers are in "IP:PORT" format
        let peer_addr_str = peer_addr.to_string();
        eprintln!("Attempting to connect to peer: {}", peer_addr_str);
        match try_download_from_peer(&peer_addr_str, &info, &info_hash, piece_index) {
            Ok(piece_data) => {
                if torrent::verify_piece(&info, piece_index, &piece_data) {
                    fs::write(output_file, &piece_data)?;
                    println!("Successfully downloaded piece {} to {}", piece_index, output_file);
                    return Ok(());
                } else {
                    eprintln!("Piece {} failed verification from peer {}", piece_index, peer_addr_str);
                }
            }
            Err(e) => eprintln!("Failed to download from peer {}: {}", peer_addr_str, e),
        }
    }
  
    Err(TorrentError::DownloadFailed("Failed to download from any peer".into()))
}

fn try_download_from_peer(
    peer_addr: &str,
    info: &torrent::TorrentInfo,
    info_hash: &[u8; 20],
    piece_index: usize
) -> Result<Vec<u8>> {
    let peer_id: [u8; 20] = *b"00112233445566778899"; // Ensure it's a [u8; 20]
    let mut peer = peer::Peer::new(peer_addr)?;
    
    // Enable TCP_NODELAY to send packets immediately
    peer.enable_tcp_nodelay()?;

    peer.handshake(info_hash, &peer_id)?;
    
    let piece_data = download_piece_from_peer(&mut peer, info, piece_index)?;
    
    Ok(piece_data)
}

fn download_piece_from_peer(
    peer: &mut peer::Peer,
    info: &torrent::TorrentInfo,
    piece_index: usize
) -> Result<Vec<u8>> {
    peer.receive_bitfield()?;
    peer.send_interested()?;
    peer.receive_unchoke()?;

    let piece_length = if piece_index == info.pieces.len() - 1 {
        // For the last piece, calculate the correct length
        info.length as usize - (info.pieces.len() - 1) * (info.piece_length as usize)
    } else {
        info.piece_length as usize
    };

    let mut piece_data = Vec::with_capacity(piece_length);
    const BLOCK_SIZE: usize = 16 * 1024; // 16 KiB

    let num_blocks = (piece_length + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for block_index in 0..num_blocks {
        let begin = block_index * BLOCK_SIZE;
        let length = if block_index == num_blocks - 1 {
            // Last block
            piece_length - begin
        } else {
            BLOCK_SIZE
        };

        peer.request_block(piece_index, begin, length)?;
        let block = peer.receive_block(piece_index, begin)?;

        if block.len() != length {
            return Err(TorrentError::UnexpectedBlockData);
        }

        piece_data.extend_from_slice(&block);
    }

    if piece_data.len() != piece_length {
        return Err(TorrentError::UnexpectedBlockData);
    }

    Ok(piece_data) 
}
