/**
 * WshFileTransfer — scp-like file transfer over a wsh connection.
 *
 * Uploads and downloads delegate to the underlying client's upload()/
 * download() (FileChunk control messages over a 'file'-kind channel —
 * see client.mjs). list() (wsh #59) delegates to the client's fileList(),
 * which sends a structured FileOp{op:"list"} and reads the typed
 * FileResult.entries -- the same wire path upload/download already use
 * for moving bytes, now extended to directory listings.
 *
 * Before wsh #59, list() ran `ls -la` over a plain exec channel and
 * parsed the text output client-side -- a private, JS-only convention
 * the Rust client had no equivalent of at all (see wsh #58/#59, and the
 * FileEntry nested type in spec/wsh-v1.yaml this now shares with Rust).
 */

/** Default timeout for waiting on control messages (30 seconds). */
const RESPONSE_TIMEOUT_MS = 30_000;

export class WshFileTransfer {
  /**
   * @type {{
   *   upload: function, download: function, fileList: function,
   * }}
   */
  #client;

  /**
   * @param {object} client - A WshClient (or any object exposing the same
   *   methods used below). `upload()`/`download()` are used directly for
   *   file transfer; `list()` uses `fileList()` (the structured
   *   FileOp/FileResult request-response helper already on WshClient).
   *   Each method checks for the members it specifically needs, so a
   *   client exposing only `upload()`/`download()` (and nothing else)
   *   stays valid for those two calls.
   */
  constructor(client) {
    if (!client) throw new Error('WshFileTransfer requires a client');
    this.#client = client;
  }

  /**
   * Upload data to a remote path.
   *
   * Delegates to the underlying client's `upload()`, which sends the data
   * as a sequence of `FileChunk` control messages over a `'file'`-kind
   * channel — the single wire scheme for file transfer (see
   * `WshClient.upload` in `client.mjs`).
   *
   * @param {Uint8Array | ArrayBuffer} data - File content to upload
   * @param {string} remotePath - Destination path on the remote host
   * @param {object} [opts]
   * @param {function} [opts.onProgress] - Called with { sent: number, total: number }
   * @param {number} [opts.timeout] - Timeout in ms for server responses
   * @returns {Promise<{ success: boolean, bytesTransferred: number }>}
   */
  async upload(data, remotePath, { onProgress, timeout = RESPONSE_TIMEOUT_MS } = {}) {
    if (typeof this.#client.upload !== 'function') {
      throw new Error('WshFileTransfer requires a client exposing upload() (e.g. WshClient)');
    }

    await this.#client.upload(data, remotePath, {
      onProgress: (value) => {
        if (typeof value === 'number') {
          onProgress?.({ sent: value, total: data.byteLength ?? data.length ?? 0 });
          return;
        }
        onProgress?.(value);
      },
      timeout,
    });
    const bytes = data instanceof Uint8Array ? data.byteLength : data.byteLength ?? data.length ?? 0;
    return { success: true, bytesTransferred: bytes };
  }

  /**
   * Download a file from a remote path.
   *
   * Delegates to the underlying client's `download()`, which reads the
   * data as a sequence of `FileChunk` control messages over a
   * `'file'`-kind channel — the single wire scheme for file transfer (see
   * `WshClient.download` in `client.mjs`).
   *
   * @param {string} remotePath - File path on the remote host
   * @param {object} [opts]
   * @param {function} [opts.onProgress] - Called with { received: number, total?: number }
   * @param {number} [opts.timeout] - Timeout in ms for server responses
   * @returns {Promise<Uint8Array>} File content
   */
  async download(remotePath, { onProgress, timeout = RESPONSE_TIMEOUT_MS } = {}) {
    if (typeof this.#client.download !== 'function') {
      throw new Error('WshFileTransfer requires a client exposing download() (e.g. WshClient)');
    }
    return await this.#client.download(remotePath, { onProgress, timeout });
  }

  /**
   * List files at a remote path over the structured file channel (wsh #59):
   * sends `FileOp{op:"list"}` via the client's `fileList()` and reads the
   * typed `FileResult.entries` -- the same `FileEntry` shape
   * `crates/wsh-core`'s Rust client is generated from, so a symlink can't
   * be reported as a plain file here and correctly here-and-there.
   *
   * A refusal (unimplemented op, unauthorized fs capability, no such
   * directory) throws -- it is never coerced into an empty array, so a
   * caller can't mistake "refused" for "empty directory" (wsh #58).
   *
   * @param {string} remotePath - Directory path on the remote host
   * @param {object} [opts]
   * @param {number} [opts.timeout] - Timeout in ms for the server response
   * @returns {Promise<Array<{
   *   name: string, size: number, modified: Date,
   *   type: 'file'|'directory'|'symlink'|'device'|'pipe'|'socket',
   *   symlinkTarget?: string,
   * }>>}
   */
  async list(remotePath, { timeout = RESPONSE_TIMEOUT_MS } = {}) {
    if (!remotePath || typeof remotePath !== 'string') {
      throw new Error('remotePath is required');
    }
    if (typeof this.#client.fileList !== 'function') {
      throw new TypeError(
        'WshFileTransfer.list() requires a client exposing fileList() (e.g. WshClient)'
      );
    }

    const result = await this.#client.fileList(remotePath, timeout);

    if (!result.success) {
      throw new Error(result.error_message || `List failed: refused for ${remotePath}`);
    }

    return (result.entries || []).map((entry) => ({
      name: entry.name,
      size: entry.size,
      modified: new Date(entry.modified * 1000),
      type: entry.type,
      ...(entry.symlink_target !== undefined ? { symlinkTarget: entry.symlink_target } : {}),
    }));
  }
}
