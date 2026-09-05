/**
 * WshFileTransfer — scp-like file transfer over a wsh connection.
 *
 * Uploads and downloads delegate to the underlying client's upload()/
 * download() (FileChunk control messages over a 'file'-kind channel —
 * see client.mjs). list() is a separate helper that runs `ls -la` over
 * a plain exec channel.
 */

import { MSG, open, CHANNEL_KIND } from './messages.mjs';
import { waitForControlMessage } from './control-listener.mjs';

/** Default timeout for waiting on control messages (30 seconds). */
const RESPONSE_TIMEOUT_MS = 30_000;

export class WshFileTransfer {
  /**
   * @type {{
   *   upload: function, download: function,
   *   sendControl: function, openStream: function, onControl: function,
   * }}
   */
  #client;

  /**
   * @param {object} client - A WshClient (or any object exposing upload()/
   *   download() with the same signatures — those are used directly for
   *   upload/download). list() additionally needs, for the underlying exec
   *   channel it runs `ls -la` over:
   *   - sendControl(msg): send a control message
   *   - openStream(): open a new bidirectional stream
   *   - onControl: settable callback for incoming control messages
   *     (or a method to add a listener — see _waitForMessage)
   *
   *   Only `list()` needs the control-channel members, so they are checked
   *   there rather than here: uploading and downloading through a client
   *   that has `upload()`/`download()` and nothing else stays valid.
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
   * List files at a remote path by executing `ls -la` via the client.
   *
   * This uses a standard exec channel rather than the file transfer protocol,
   * parsing the output of `ls -la` into structured entries.
   *
   * @param {string} remotePath - Directory path on the remote host
   * @returns {Promise<Array<{ name: string, size: number, modified: string, type: string }>>}
   */
  async list(remotePath) {
    if (!remotePath || typeof remotePath !== 'string') {
      throw new Error('remotePath is required');
    }
    if (typeof this.#client.sendControl !== 'function' || typeof this.#client.openStream !== 'function') {
      throw new TypeError(
        'WshFileTransfer.list() requires a client exposing sendControl() and openStream() (e.g. WshClient)'
      );
    }

    // Use an exec channel to run ls
    const openMsg = open({
      kind: CHANNEL_KIND.EXEC,
      command: `ls -la ${this._shellEscape(remotePath)}`,
    });

    await this.#client.sendControl(openMsg);

    const response = await this._waitForMessage(
      (msg) => msg.type === MSG.OPEN_OK || msg.type === MSG.OPEN_FAIL,
      RESPONSE_TIMEOUT_MS
    );

    if (response.type === MSG.OPEN_FAIL) {
      throw new Error(`List failed: ${response.reason || 'unknown reason'}`);
    }

    // Read the output stream
    const stream = await this.#client.openStream();
    const reader = stream.readable.getReader();
    const chunks = [];

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }

    const output = new TextDecoder().decode(this._concatChunks(chunks));
    return this._parseLsOutput(output);
  }

  // ── Internal helpers ──────────────────────────────────────────────

  /**
   * Wait for a control message matching a predicate.
   *
   * Temporarily hooks into the client's control message flow and resolves
   * when a matching message arrives (or rejects on timeout).
   *
   * @param {function(object): boolean} predicate
   * @param {number} timeoutMs
   * @returns {Promise<object>}
   */
  _waitForMessage(predicate, timeoutMs) {
    return waitForControlMessage(this.#client, predicate, timeoutMs, 'File transfer response');
  }

  /**
   * Concatenate an array of Uint8Arrays into one.
   *
   * @param {Uint8Array[]} chunks
   * @param {number} [totalLength] - Pre-computed total, avoids re-summing
   * @returns {Uint8Array}
   */
  _concatChunks(chunks, totalLength) {
    if (chunks.length === 0) return new Uint8Array(0);
    if (chunks.length === 1) return chunks[0];

    const total = totalLength ?? chunks.reduce((sum, c) => sum + c.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }

  /**
   * Parse the output of `ls -la` into structured entries.
   *
   * Expected format per line:
   *   drwxr-xr-x 2 user group  4096 Jan 15 12:00 dirname
   *   -rw-r--r-- 1 user group 12345 Jan 15 12:00 filename.txt
   *
   * @param {string} output
   * @returns {Array<{ name: string, size: number, modified: string, type: string }>}
   */
  _parseLsOutput(output) {
    const lines = output.split('\n').filter((l) => l.trim());
    const entries = [];

    for (const line of lines) {
      // Skip the "total" header line
      if (line.startsWith('total ')) continue;

      // ls -la columns: perms links owner group size month day time name
      const parts = line.split(/\s+/);
      if (parts.length < 9) continue;

      const perms = parts[0];
      const size = parseInt(parts[4], 10) || 0;
      const month = parts[5];
      const day = parts[6];
      const time = parts[7];
      // Name may contain spaces — rejoin everything from column 8 onward
      const name = parts.slice(8).join(' ');

      // Skip . and .. entries
      if (name === '.' || name === '..') continue;

      // Determine type from permission string first character
      let type = 'file';
      if (perms.startsWith('d')) type = 'directory';
      else if (perms.startsWith('l')) type = 'symlink';
      else if (perms.startsWith('c') || perms.startsWith('b')) type = 'device';
      else if (perms.startsWith('p')) type = 'pipe';
      else if (perms.startsWith('s')) type = 'socket';

      entries.push({
        name,
        size,
        modified: `${month} ${day} ${time}`,
        type,
      });
    }

    return entries;
  }

  /**
   * Basic shell escaping for a path argument.
   * @param {string} str
   * @returns {string}
   */
  _shellEscape(str) {
    // Wrap in single quotes, escaping any embedded single quotes
    return "'" + str.replace(/'/g, "'\\''") + "'";
  }
}
