//! File transfer for wsh: upload/download over a file channel as `FileChunk`
//! control messages (64KB chunks, offset-addressed, the last `is_final`; the
//! host ends an upload with `Exit` and `Close` -- the framing the JS client,
//! the Node and in-page hosts and `wsh-server` all speak, #140), plus `list()`
//! over the structured file channel (`FileOp`/`FileResult`, wsh #59).

use wsh_core::error::{WshError, WshResult};
use wsh_core::messages::{ChannelKind, Envelope, FileEntry, FileOpPayload, MsgType, Payload};

use crate::client::WshClient;
use crate::session::SessionOpts;

/// Default chunk size for file transfers: 64 KB.
const CHUNK_SIZE: usize = 64 * 1024;
/// How long a host has to confirm an upload (`Exit`, then `Close`) after the last chunk.
const UPLOAD_CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// A download reserves at most this much memory up front, whatever size the host announces.
const MAX_PREALLOCATE: u64 = 64 * 1024 * 1024;

/// Upload file data to a remote path over a file channel.
///
/// Opens a file channel (`upload:<path>`), sends the data as `FileChunk`
/// messages in 64KB chunks, and waits for the host's confirmation. Calls
/// `on_progress` with bytes sent so far.
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
            ..Default::default()
        })
        .await?;

    // The data as `FileChunk` control messages (offset-addressed, the last one `is_final`): the one
    // framing every host and client speaks (#140). An empty file is one empty final chunk.
    let mut sent: u64 = 0;
    let mut chunks = data.chunks(CHUNK_SIZE).peekable();
    if chunks.peek().is_none() {
        session.write_file_chunk(0, &[], true, 0).await?;
    }
    while let Some(chunk) = chunks.next() {
        let is_final = chunks.peek().is_none();
        session
            .write_file_chunk(sent, chunk, is_final, total)
            .await?;
        sent += chunk.len() as u64;
        on_progress(sent, total);
    }

    // The host confirms with Exit (its code) and then Close.
    if !session.wait_closed(UPLOAD_CONFIRM_TIMEOUT).await {
        let _ = session.close().await;
        return Err(WshError::Channel(
            "upload: the host did not confirm the transfer".into(),
        ));
    }
    match session.exit_code().await {
        Some(0) => {}
        Some(code) => {
            return Err(WshError::Channel(format!(
                "upload failed with exit code {code}"
            )));
        }
        None => {
            return Err(WshError::Channel(
                "upload failed: the channel closed without a result".into(),
            ));
        }
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
            ..Default::default()
        })
        .await?;

    // The host answers with `FileChunk` control messages until one is `is_final` (the one framing
    // every host and client speaks, #140). A refusal (no such file) is an `Exit` with a non-zero
    // code and a `Close`, with no chunk. Everything from the host is untrusted: chunks must be
    // in order, stay inside the size the first one announced, and the last must reach it.
    let mut data: Vec<u8> = Vec::new();
    let mut total_size: Option<u64> = None;
    loop {
        let Some(chunk) = session.read_file_chunk().await else {
            let _ = session.close().await;
            return Err(WshError::Channel(match session.exit_code().await {
                Some(code) if code != 0 => {
                    format!("download failed: the host refused or could not read {remote_path:?} (exit code {code})")
                }
                _ => "download failed: connection closed before the transfer completed (truncated)"
                    .into(),
            }));
        };
        let total = *total_size.get_or_insert(chunk.total_size);
        if chunk.total_size != total
            || chunk.offset != data.len() as u64
            || chunk.offset + chunk.data.len() as u64 > total
        {
            let _ = session.close().await;
            return Err(WshError::Channel(
                "download failed: the host sent chunks out of order or past the announced size"
                    .into(),
            ));
        }
        if data.is_empty() {
            data.reserve(total.min(MAX_PREALLOCATE) as usize);
        }
        data.extend_from_slice(&chunk.data);
        if chunk.is_final {
            if data.len() as u64 != total {
                let _ = session.close().await;
                return Err(WshError::Channel(format!(
                    "download failed: truncated transfer (received {} of {total} bytes)",
                    data.len()
                )));
            }
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

#[cfg(test)]
mod tests {
    use super::*;

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
