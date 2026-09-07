//! Dedicated-stream file transfer for wsh.
//!
//! Uploads and downloads files over a dedicated data stream,
//! using 64KB chunks with progress reporting.

use wsh_core::error::{WshError, WshResult};
use wsh_core::messages::ChannelKind;

use crate::client::WshClient;
use crate::session::SessionOpts;

/// Default chunk size for file transfers: 64 KB.
const CHUNK_SIZE: usize = 64 * 1024;

/// Upload file data to a remote path via a dedicated file stream.
///
/// Opens a file channel, sends a header with the remote path, then streams
/// the data in 64KB chunks. Calls `on_progress` with bytes sent so far.
///
/// Returns the total number of bytes uploaded.
pub async fn upload<F>(
    client: &WshClient,
    data: &[u8],
    remote_path: &str,
    mut on_progress: F,
) -> WshResult<u64>
where
    F: FnMut(u64, u64),
{
    let total = data.len() as u64;

    // Open a file channel
    let session = client
        .open_session(SessionOpts {
            kind: ChannelKind::File,
            command: Some(format!("upload:{remote_path}")),
            cols: None,
            rows: None,
            env: None,
        })
        .await?;

    // Send the file header: [4-byte path_len][path][8-byte total_size]
    let header = build_upload_header(remote_path, total);
    session.write(&header).await?;

    // Stream the data in chunks
    let mut sent: u64 = 0;
    for chunk in data.chunks(CHUNK_SIZE) {
        session.write(chunk).await?;
        sent += chunk.len() as u64;
        on_progress(sent, total);
    }

    // Wait for server acknowledgment (reads a small response)
    let mut ack_buf = [0u8; 64];
    let n = session.read(&mut ack_buf).await?;
    if n == 0 {
        tracing::warn!("no ack received from server after upload");
    }

    // Close the file channel
    session.close().await?;

    tracing::info!("uploaded {} bytes to '{}'", total, remote_path);

    Ok(total)
}

/// Download a file from a remote path via a dedicated file stream.
///
/// Opens a file channel, sends a download request header, then reads
/// data until the stream closes.
///
/// Returns the file contents as bytes.
pub async fn download(client: &WshClient, remote_path: &str) -> WshResult<Vec<u8>> {
    // Open a file channel
    let session = client
        .open_session(SessionOpts {
            kind: ChannelKind::File,
            command: Some(format!("download:{remote_path}")),
            cols: None,
            rows: None,
            env: None,
        })
        .await?;

    // Send the download request header: [4-byte path_len][path]
    let header = build_download_header(remote_path);
    session.write(&header).await?;

    // Read the response: first 8 bytes are the total file size
    let mut size_buf = [0u8; 8];
    let mut size_read = 0;
    while size_read < 8 {
        let n = session.read(&mut size_buf[size_read..]).await?;
        if n == 0 {
            return Err(WshError::Transport(
                "unexpected EOF reading file size".into(),
            ));
        }
        size_read += n;
    }
    let total_size = u64::from_be_bytes(size_buf) as usize;

    // Read the file data
    let mut data = Vec::with_capacity(total_size);
    let mut buf = vec![0u8; CHUNK_SIZE];

    loop {
        let n = session.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);

        // Safety check: don't read more than expected
        if data.len() >= total_size {
            data.truncate(total_size);
            break;
        }
    }

    session.close().await?;

    tracing::info!("downloaded {} bytes from '{}'", data.len(), remote_path);

    Ok(data)
}

// ── Header builders ──────────────────────────────────────────────────

/// Build the upload header: `[4-byte path_len][path_bytes][8-byte total_size]`
fn build_upload_header(path: &str, total_size: u64) -> Vec<u8> {
    let path_bytes = path.as_bytes();
    let mut header = Vec::with_capacity(4 + path_bytes.len() + 8);
    header.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
    header.extend_from_slice(path_bytes);
    header.extend_from_slice(&total_size.to_be_bytes());
    header
}

/// Build the download header: `[4-byte path_len][path_bytes]`
fn build_download_header(path: &str) -> Vec<u8> {
    let path_bytes = path.as_bytes();
    let mut header = Vec::with_capacity(4 + path_bytes.len());
    header.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
    header.extend_from_slice(path_bytes);
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_header_format() {
        let header = build_upload_header("/tmp/test.txt", 1024);
        let path_len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        assert_eq!(path_len, 13); // "/tmp/test.txt".len()
        let path = std::str::from_utf8(&header[4..4 + path_len]).unwrap();
        assert_eq!(path, "/tmp/test.txt");
        let size = u64::from_be_bytes([
            header[17], header[18], header[19], header[20], header[21], header[22], header[23],
            header[24],
        ]);
        assert_eq!(size, 1024);
    }

    #[test]
    fn download_header_format() {
        let header = build_download_header("/tmp/data.bin");
        let path_len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        assert_eq!(path_len, 13);
        let path = std::str::from_utf8(&header[4..4 + path_len]).unwrap();
        assert_eq!(path, "/tmp/data.bin");
    }

    #[test]
    fn chunk_size_is_64kb() {
        assert_eq!(CHUNK_SIZE, 65536);
    }
}
