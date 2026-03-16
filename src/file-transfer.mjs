/**
 * WshFileTransfer — dedicated stream file transfer (scp-like) over a wsh connection.
 *
 * Uploads and downloads files using the wsh channel protocol with 'file' kind
 * channels. Data flows over a dedicated bidirectional stream in 64KB chunks.
 */

import { MSG, open, CHANNEL_KIND } from './messages.mjs';

/** Transfer chunk size: 64KB. */
const CHUNK_SIZE = 65536;

/** Default timeout for waiting on control messages (30 seconds). */
const RESPONSE_TIMEOUT_MS = 30_000;

export class WshFileTransfer {
  /** @type {{ sendControl: function, openStream: function, onControl: function }} */
  #client;

  /**
   * @param {object} client - A WshClient or any transport object exposing:
   *   - sendControl(msg): send a control message
   *   - openStream(): open a new bidirectional stream
   *   - onControl: settable callback for incoming control messages
   *     (or a method to add a listener — see _waitForMessage)
   */
  constructor(client) {
    if (!client) throw new Error('WshFileTransfer requires a client');
    this.#client = client;
  }

  /**
   * Upload data to a remote path.
   *
   * Protocol flow:
   *   1. Send OPEN { kind: 'file', command: 'upload', path }
   *   2. Receive OPEN_OK { channel_id, stream_ids }
   *   3. Write data to dedicated stream in 64KB chunks
   *   4. Close the write side of the stream
   *   5. Wait for EXIT message with status code
   *
   * @param {Uint8Array | ArrayBuffer} data - File content to upload
   * @param {string} remotePath - Destination path on the remote host
   * @param {object} [opts]
   * @param {function} [opts.onProgress] - Called with { sent: number, total: number }
   * @param {number} [opts.timeout] - Timeout in ms for server responses
   * @returns {Promise<{ success: boolean, bytesTransferred: number }>}
   */
  async upload(data, remotePath, { onProgress, timeout = RESPONSE_TIMEOUT_MS } = {}) {
    if (typeof this.#client.upload === 'function') {
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

    const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError('Data must be a Uint8Array or ArrayBuffer');
    }
    if (!remotePath || typeof remotePath !== 'string') {
      throw new Error('remotePath is required');
    }

    // 1. Request a file upload channel
    const openMsg = open({
      kind: CHANNEL_KIND.FILE,
      command: 'upload',
    });
    openMsg.path = remotePath;
    openMsg.size = bytes.length;

    await this.#client.sendControl(openMsg);

    // 2. Wait for OPEN_OK or OPEN_FAIL
    const response = await this._waitForMessage(
      (msg) => msg.type === MSG.OPEN_OK || msg.type === MSG.OPEN_FAIL,
      timeout
    );

    if (response.type === MSG.OPEN_FAIL) {
      throw new Error(`Upload rejected: ${response.reason || 'unknown reason'}`);
    }

    const channelId = response.channel_id;

    // 3. Open a dedicated data stream and write in chunks
    const stream = await this.#client.openStream();
    const writer = stream.writable.getWriter();
    let sent = 0;

    try {
      while (sent < bytes.length) {
        const end = Math.min(sent + CHUNK_SIZE, bytes.length);
        const chunk = bytes.subarray(sent, end);
        await writer.write(chunk);
        sent = end;
        try {
          onProgress?.({ sent, total: bytes.length });
        } catch { /* ignore callback errors */ }
      }
    } finally {
      // 4. Close the write side to signal end of data
      try {
        await writer.close();
      } catch {
        // Stream may already be closed on error
      }
    }

    // 5. Wait for EXIT confirmation
    const exitMsg = await this._waitForMessage(
      (msg) => msg.type === MSG.EXIT && msg.channel_id === channelId,
      timeout
    );

    const success = exitMsg.code === 0;
    if (!success) {
      throw new Error(`Upload failed with exit code ${exitMsg.code}`);
    }

    return { success, bytesTransferred: sent };
  }

  /**
   * Download a file from a remote path.
   *
   * Protocol flow:
   *   1. Send OPEN { kind: 'file', command: 'download', path }
   *   2. Receive OPEN_OK { channel_id, stream_ids }
   *   3. Read from the dedicated stream, accumulating chunks
   *   4. Return complete file content as Uint8Array
   *
   * @param {string} remotePath - File path on the remote host
   * @param {object} [opts]
   * @param {function} [opts.onProgress] - Called with { received: number, total?: number }
   * @param {number} [opts.timeout] - Timeout in ms for server responses
   * @returns {Promise<Uint8Array>} File content
   */
  async download(remotePath, { onProgress, timeout = RESPONSE_TIMEOUT_MS } = {}) {
    if (typeof this.#client.download === 'function') {
      return await this.#client.download(remotePath, { onProgress, timeout });
    }

    if (!remotePath || typeof remotePath !== 'string') {
      throw new Error('remotePath is required');
    }

    // 1. Request a file download channel
    const openMsg = open({
      kind: CHANNEL_KIND.FILE,
      command: 'download',
    });
    openMsg.path = remotePath;

    await this.#client.sendControl(openMsg);

    // 2. Wait for OPEN_OK or OPEN_FAIL
    const response = await this._waitForMessage(
      (msg) => msg.type === MSG.OPEN_OK || msg.type === MSG.OPEN_FAIL,
      timeout
    );

    if (response.type === MSG.OPEN_FAIL) {
      throw new Error(`Download rejected: ${response.reason || 'unknown reason'}`);
    }

    const channelId = response.channel_id;
    const totalSize = response.size; // Server may include total file size

    // 3. Open a dedicated data stream and read chunks
    const stream = await this.#client.openStream();
    const reader = stream.readable.getReader();
    const chunks = [];
    let received = 0;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        chunks.push(value);
        received += value.length;

        try {
          onProgress?.({ received, total: totalSize });
        } catch { /* ignore callback errors */ }
      }
    } finally {
      reader.releaseLock();
    }

    // 4. Wait for EXIT confirmation
    try {
      const exitMsg = await this._waitForMessage(
        (msg) => msg.type === MSG.EXIT && msg.channel_id === channelId,
        timeout
      );
      if (exitMsg.code !== 0) {
        throw new Error(`Download failed with exit code ${exitMsg.code}`);
      }
    } catch (err) {
      // If the stream closed cleanly and we got data, the EXIT may have
      // already been consumed or the server may not send one for downloads.
      // Only rethrow if we have no data.
      if (received === 0) throw err;
    }

    // Concatenate chunks into a single Uint8Array
    return this._concatChunks(chunks, received);
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
    return new Promise((resolve, reject) => {
      let timer = null;
      let settled = false;

      const cleanup = () => {
        settled = true;
        if (timer !== null) clearTimeout(timer);
        // Remove listener
        if (this.#client.removeControlListener) {
          this.#client.removeControlListener(listener);
        } else if (this.#client._controlListeners) {
          const idx = this.#client._controlListeners.indexOf(listener);
          if (idx !== -1) this.#client._controlListeners.splice(idx, 1);
        }
      };

      const listener = (msg) => {
        if (settled) return;
        if (predicate(msg)) {
          cleanup();
          resolve(msg);
        }
      };

      // Register listener on the client
      if (this.#client.addControlListener) {
        this.#client.addControlListener(listener);
      } else if (this.#client._controlListeners) {
        this.#client._controlListeners.push(listener);
      } else {
        // Fallback: wrap existing onControl
        const prev = this.#client.onControl;
        this.#client.onControl = (msg) => {
          prev?.(msg);
          listener(msg);
        };
      }

      timer = setTimeout(() => {
        if (!settled) {
          cleanup();
          reject(new Error(`Timeout waiting for response (${timeoutMs}ms)`));
        }
      }, timeoutMs);
    });
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
