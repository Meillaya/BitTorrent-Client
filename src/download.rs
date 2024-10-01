// download.rs

use crate::{
    torrent, tracker, peer, error::{Result, TorrentError}
};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use std::collections::VecDeque;
use rand::Rng;
use rand::seq::SliceRandom; // For peer selection
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration};

// Constants for configuration
const MAX_RETRIES: u32 = 5;
const WORKER_COUNT: usize = 10;
const RETRY_DELAY: Duration = Duration::from_secs(2);
// const ENDGAME_THRESHOLD: usize = 5;

/// Downloads the entire file from the torrent.
pub async fn download_file(output_file: &str, torrent_file: &str) -> Result<()> {
    let info = torrent::get_info(torrent_file)?;
    let info_hash = hex::decode(&info.info_hash)
        .map_err(|_| TorrentError::InvalidInfoHash)?;
    let info_hash: [u8; 20] = info_hash.try_into()
        .map_err(|_| TorrentError::InvalidInfoHash)?;

    let tracker_response = tracker::TrackerResponse::query(&info, &info_hash).await?;
    if tracker_response.peers.0.is_empty() {
        return Err(TorrentError::NoPeersAvailable);
    }

    // Initialize piece availability map for "rarest first" strategy
    let mut piece_availability: Vec<usize> = vec![0; info.pieces.len()];
    // TODO: Fetch each peer's bitfield to accurately populate piece_availability
    // For simplicity, we'll assume all peers have all pieces 
    for _peer in &tracker_response.peers.0 {
        for piece in 0..info.pieces.len() {
            piece_availability[piece] += 1;
        }
    }

    // Create a queue of pieces sorted by rarity (rarest first)
    let mut piece_indices: Vec<usize> = (0..info.pieces.len()).collect();
    piece_indices.sort_by_key(|&idx| piece_availability[idx]);

    let piece_queue = Arc::new(Mutex::new(VecDeque::from(piece_indices)));
    let all_pieces = Arc::new(Mutex::new(vec![None; info.pieces.len()]));
    let semaphore = Arc::new(Semaphore::new(WORKER_COUNT));
    let mut join_set = JoinSet::new();

    // Spawn worker tasks
    for _ in 0..WORKER_COUNT {
        let piece_queue = Arc::clone(&piece_queue);
        let all_pieces = Arc::clone(&all_pieces);
        let info = info.clone();
        let info_hash = info_hash.clone();
        let peers = tracker_response.peers.0.clone();
        let semaphore = Arc::clone(&semaphore);

        join_set.spawn(async move {
            loop {
                // Acquire a permit before proceeding
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        // No available permits, retry after a short delay
                        sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                // Fetch the next piece index
                let piece_index_opt = {
                    let mut queue = piece_queue.lock().await;
                    queue.pop_front()
                };

                let piece_index = match piece_index_opt {
                    Some(idx) => idx,
                    None => {
                        // No more pieces to download
                        drop(permit); // Release the permit
                        break;
                    },
                };

                // Download the piece with retry logic
                let mut attempts = 0;
                let mut success = false;
                while attempts < MAX_RETRIES && !success {
                    let peer = select_peer(&peers).await;
                    match try_download_piece(&peer, &info, &info_hash, piece_index).await {
                        Ok(piece_data) => {
                            if torrent::verify_piece(&info, piece_index, &piece_data) {
                                let mut all = all_pieces.lock().await;
                                all[piece_index] = Some(piece_data);
                                println!("Successfully downloaded piece {}", piece_index);
                                success = true;
                            } else {
                                eprintln!("Piece {} failed verification from peer {}", piece_index, peer);
                            }
                        },
                        Err(e) => {
                            eprintln!("Failed to download piece {} from peer {}: {}", piece_index, peer, e);
                        }
                    }
                    attempts += 1;
                    if !success {
                        sleep(RETRY_DELAY).await;
                    }
                }
                if !success {
                    eprintln!("Exceeded maximum retries for piece {}", piece_index);
                }

                drop(permit); // Release the semaphore permit
            }
        });
    }

    // Await all worker tasks
    while let Some(res) = join_set.join_next().await {
        if let Err(e) = res {
            eprintln!("A download task failed: {}", e);
        }
    }

    // Check if all pieces were downloaded
    let all_pieces_guard = all_pieces.lock().await;
    if all_pieces_guard.iter().any(|piece| piece.is_none()) {
        return Err(TorrentError::DownloadFailed("Some pieces failed to download".into()));
    }

    // Write the pieces to the output file in order
    let mut file = File::create(output_file).await?;
    for piece in all_pieces_guard.iter() {
        if let Some(data) = piece {
            file.write_all(data).await?;
        }
    }

    println!("Successfully downloaded file to {}", output_file);
    Ok(())
}

/// Downloads a specific piece from the torrent.
pub async fn download_piece(output_file: &str, torrent_file: &str, piece_index: usize) -> Result<()> {
    let info = torrent::get_info(torrent_file)?;
    let info_hash = hex::decode(&info.info_hash)
        .map_err(|_| TorrentError::InvalidInfoHash)?;
    let info_hash: [u8; 20] = info_hash.try_into()
        .map_err(|_| TorrentError::InvalidInfoHash)?;

    let tracker_response = tracker::TrackerResponse::query(&info, &info_hash).await?;
    if tracker_response.peers.0.is_empty() {
        return Err(TorrentError::NoPeersAvailable);
    }

    let all_pieces = Arc::new(Mutex::new(vec![None; info.pieces.len()]));
    let semaphore = Arc::new(Semaphore::new(1)); // Single worker for single piece
    let mut join_set = JoinSet::new();

    // Spawn a single worker task
    {
        let piece_queue = Arc::new(Mutex::new(VecDeque::from(vec![piece_index])));
        let piece_queue = Arc::clone(&piece_queue);
        let all_pieces = Arc::clone(&all_pieces);
        let info = info.clone();
        let info_hash = info_hash.clone();
        let peers = tracker_response.peers.0.clone();
        let semaphore = Arc::clone(&semaphore);

        join_set.spawn(async move {
            loop {
                // Acquire a permit before proceeding
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        // No available permits, retry after a short delay
                        sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                // Fetch the next piece index
                let piece_index_opt = {
                    let mut queue = piece_queue.lock().await;
                    queue.pop_front()
                };

                let piece_index = match piece_index_opt {
                    Some(idx) => idx,
                    None => {
                        // No more pieces to download
                        drop(permit); // Release the permit
                        break;
                    },
                };

                // Download the piece with retry logic
                let mut attempts = 0;
                let mut success = false;
                while attempts < MAX_RETRIES && !success {
                    let peer = select_peer(&peers).await;
                    match try_download_piece(&peer, &info, &info_hash, piece_index).await {
                        Ok(piece_data) => {
                            if torrent::verify_piece(&info, piece_index, &piece_data) {
                                let mut all = all_pieces.lock().await;
                                all[piece_index] = Some(piece_data);
                                println!("Successfully downloaded piece {}", piece_index);
                                success = true;
                            } else {
                                eprintln!("Piece {} failed verification from peer {}", piece_index, peer);
                            }
                        },
                        Err(e) => {
                            eprintln!("Failed to download piece {} from peer {}: {}", piece_index, peer, e);
                        }
                    }
                    attempts += 1;
                    if !success {
                        sleep(RETRY_DELAY).await;
                    }
                }
                if !success {
                    eprintln!("Exceeded maximum retries for piece {}", piece_index);
                }

                drop(permit); // Release the semaphore permit
            }
        });
    }

    // Await the download task
    while let Some(res) = join_set.join_next().await {
        if let Err(e) = res {
            eprintln!("A download task failed: {}", e);
        }
    }

    // Check if the piece was downloaded
    let all_pieces_guard = all_pieces.lock().await;
    if let Some(Some(piece_data)) = all_pieces_guard.get(piece_index) {
        tokio::fs::write(output_file, piece_data).await?;
        println!("Successfully downloaded piece {} to {}", piece_index, output_file);
        Ok(())
    } else {
        Err(TorrentError::DownloadFailed(format!("Failed to download piece {}", piece_index)))
    }
}

/// Attempts to download a specific piece from a given peer.
/// Returns the piece data if successful.
async fn try_download_piece(peer_addr: &str, info: &torrent::TorrentInfo, info_hash: &[u8; 20], piece_index: usize) -> Result<Vec<u8>> {
    let peer_id: [u8; 20] = generate_peer_id();
    let mut peer = peer::Peer::new(peer_addr).await?;
    
    peer.enable_tcp_nodelay().await?;
    peer.handshake(info_hash, &peer_id).await?;
    
    let piece_data = download_piece_from_peer(&mut peer, info, piece_index).await?;
    
    Ok(piece_data)
}

/// Handles the actual download of a piece from the connected peer.
async fn download_piece_from_peer(peer: &mut peer::Peer, info: &torrent::TorrentInfo, piece_index: usize) -> Result<Vec<u8>> {
    peer.receive_bitfield().await?;
    peer.send_interested().await?;
    peer.receive_unchoke().await?;

    let piece_length = if piece_index == info.pieces.len() - 1 {
        // For the last piece, calculate the correct length
        info.length as usize - (info.pieces.len() - 1) * (info.piece_length as usize)
    } else {
        info.piece_length as usize
    };
    
    let mut piece_data = Vec::with_capacity(piece_length);
    const BLOCK_SIZE: usize = 1 << 14; // 16 KiB

    let num_blocks = (piece_length + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for block_index in 0..num_blocks {
        let begin = block_index * BLOCK_SIZE;
        let length = std::cmp::min(BLOCK_SIZE, piece_length - begin);

        peer.request_block(piece_index, begin, length).await?;
        let block = peer.receive_block(piece_index, begin).await?;

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

/// Selects a random peer from the available peers.
/// Future Improvement: Implement a more sophisticated selection strategy.
async fn select_peer(peers: &Vec<std::net::SocketAddrV4>) -> String {
    let mut rng = rand::thread_rng();
    let peer = peers.choose(&mut rng).unwrap(); // Ensure there's at least one peer
    peer.to_string()
}

// Generates a unique peer ID.
// Example: "-TR3000-" followed by random characters.
fn generate_peer_id() -> [u8; 20] {
    let prefix = b"-TR3000-"; // Example prefix indicating the client and version
    let mut peer_id = [0u8; 20];
    peer_id[..8].copy_from_slice(prefix);
    let rand_chars: Vec<u8> = (0..12).map(|_| {
        let chars = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let idx = rand::thread_rng().gen_range(0..chars.len());
        chars[idx]
    }).collect();
    peer_id[8..20].copy_from_slice(&rand_chars);
    peer_id
}
