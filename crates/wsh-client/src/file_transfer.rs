//! File transfer for wsh: upload/download over a dedicated data stream
//! (64KB `FileChunk` chunks with progress reporting), plus `list()` over
//! the structured file channel (`FileOp`/`FileResult`, wsh #59).

use wsh_core::error::{WshError, WshResult};
use wsh_core::messages::{ChannelKind, Envelope, FileEntry, FileOpPayload, MsgType, Payload};

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

/// List a remote directory via the structured file channel (`FileOp`/
/// `FileResult` with `op: "list"`) -- wsh #59.
///
/// Before this, the Rust client had no `list()` at all (only `upload`/
/// `download`, above); the JS SDK's `WshFileTransfer.list()` didn't use
/// this wire path either -- it ran `ls -la` over a plain exec channel and
/// parsed the text output client-side (see `src/file-transfer.mjs`). Both
/// sides now go through the same generated `FileEntry` shape, so a symlink
/// can't be reported as a plain file in one implementation and not the
/// other.
///
/// A refusal (op not implemented by the server, no such directory,
/// permission denied) is returned as `Err`, never coerced into `Ok(vec![])`
/// -- an empty `Ok` only happens for an actually-listable, actually-empty
/// directory (wsh #58's "an unauthorized fs capability must be reported as
/// a named refusal, never rendered as an empty directory").
pub async fn list(client: &WshClient, remote_path: &str) -> WshResult<Vec<FileEntry>> {
    let result = file_op(client, "list", remote_path).await?;
    Ok(result.entries)
}

/// Remove a remote file or (empty) directory via the structured file
/// channel (`FileOp`/`FileResult` with `op: "remove"`) -- used by `wsh
/// sftp`'s `rm` (wsh #58: "where the capability allows it" -- today's
/// `wsh-server` still refuses every op other than "list", so this reaches
/// a clean, named refusal rather than a hang or a silent no-op; a server
/// that later implements "remove" needs no client-side change).
pub async fn remove(client: &WshClient, remote_path: &str) -> WshResult<()> {
    file_op(client, "remove", remote_path).await?;
    Ok(())
}

/// Send a `FileOp` and wait for its `FileResult`, turning `success: false`
/// into `Err` uniformly for every op that goes through this path -- so a
/// refusal always surfaces as an error to the caller, never as a
/// default/empty value that could be mistaken for a real (if boring)
/// result (wsh #58).
async fn file_op(
    client: &WshClient,
    op: &str,
    remote_path: &str,
) -> WshResult<wsh_core::messages::FileResultPayload> {
    let envelope = Envelope {
        msg_type: MsgType::FileOp,
        payload: Payload::FileOp(FileOpPayload {
            channel_id: next_file_op_channel_id(),
            op: op.to_string(),
            path: remote_path.to_string(),
            offset: None,
            length: None,
        }),
    };

    let response = client
        .send_and_wait_public(envelope, MsgType::FileResult)
        .await?;

    let result = match response.payload {
        Payload::FileResult(r) => r,
        _ => {
            return Err(WshError::InvalidMessage(format!(
                "expected FILE_RESULT in response to {op} FileOp"
            )))
        }
    };

    if !result.success {
        return Err(WshError::Channel(
            result
                .error_message
                .unwrap_or_else(|| format!("{op} {remote_path:?} refused")),
        ));
    }

    Ok(result)
}

/// FileOp has no Open/OpenOk step (unlike upload/download's dedicated file
/// channel) -- the server doesn't track or validate this value, only
/// echoes it back in FileResult, so a process-local monotonic counter is
/// sufficient to keep concurrent FileOp calls visually distinguishable in
/// logs. Mirrors `WshClient._nextChannelId()` in `src/client.mjs`.
fn next_file_op_channel_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
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

    #[test]
    fn file_op_channel_ids_are_monotonic_and_nonzero() {
        let a = next_file_op_channel_id();
        let b = next_file_op_channel_id();
        assert_ne!(a, 0);
        assert!(b > a);
    }
}
