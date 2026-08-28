import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { WshTransport } from '../src/transport.mjs';
import { MSG, open, openOk, openFail, exit, close, fileChunk } from '../src/messages.gen.mjs';

// Note: Web Crypto API (crypto.subtle) with Ed25519 requires Node 20+ or a browser.
let auth;
let clientMod;
let fileTransferMod;
try {
  auth = await import('../src/auth.mjs');
  clientMod = await import('../src/client.mjs');
  fileTransferMod = await import('../src/file-transfer.mjs');
} catch {
  // Module import may fail in environments without Web Crypto Ed25519
}

const hasEd25519 = auth && typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';

/**
 * A minimal in-memory server-side mock covering: the CHALLENGE-first auth
 * handshake (see test/client.test.mjs), and a 'file'-kind channel served
 * entirely as FileChunk control messages (never a real second stream) --
 * matching every real server today, which always returns data_mode:
 * 'virtual' regardless of channel kind.
 */
class MockFileServerTransport extends WshTransport {
  sentMessages = [];
  #sessionId;
  #files;
  #nextChannelId = 1;
  #uploads = new Map(); // channel_id -> { chunks: Map<offset, Uint8Array>, totalSize }
  #truncateDownloadAfterBytes;

  constructor({ sessionId = 'server-session', files = {}, truncateDownloadAfterBytes = Infinity } = {}) {
    super();
    this.#sessionId = sessionId;
    this.#files = files;
    this.#truncateDownloadAfterBytes = truncateDownloadAfterBytes;
  }

  async _doConnect() {}
  async _doClose() {}
  async _doOpenStream() {
    throw new Error('file transfer must never open a real stream -- FileChunk travels as a control message');
  }

  async _doSendControl(msg) {
    this.sentMessages.push(msg);

    if (msg.type === MSG.HELLO) {
      setTimeout(() => {
        this._emitControl({ type: MSG.CHALLENGE, nonce: new Uint8Array(32).fill(7), session_id: this.#sessionId });
      }, 0);
      return;
    }
    if (msg.type === MSG.AUTH) {
      setTimeout(() => {
        this._emitControl({ type: MSG.AUTH_OK });
      }, 0);
      return;
    }

    if (msg.type === MSG.OPEN) {
      const channelId = this.#nextChannelId++;
      const [op, path] = String(msg.command).split(/:(.+)/s);

      if (op === 'download') {
        if (!(path in this.#files)) {
          setTimeout(() => this._emitControl(openFail({ reason: `no such file: ${path}` })), 0);
          return;
        }
        setTimeout(() => {
          this._emitControl(openOk({ channelId, dataMode: 'virtual', capabilities: [] }));
          this.#streamDownload(channelId, this.#files[path]);
        }, 0);
        return;
      }

      if (op === 'upload') {
        this.#uploads.set(channelId, { chunks: new Map(), totalSize: null, path });
        setTimeout(() => this._emitControl(openOk({ channelId, dataMode: 'virtual', capabilities: [] })), 0);
        return;
      }

      setTimeout(() => this._emitControl(openFail({ reason: `unsupported command: ${msg.command}` })), 0);
      return;
    }

    if (msg.type === MSG.FILE_CHUNK) {
      const upload = this.#uploads.get(msg.channel_id);
      if (!upload) return;
      upload.chunks.set(msg.offset, msg.data);
      upload.totalSize = msg.total_size;

      if (msg.is_final) {
        const received = [...upload.chunks.values()].reduce((sum, c) => sum + c.byteLength, 0);
        const ok = received === upload.totalSize;
        this.#files[upload.path] = ok ? this.#assembleUpload(upload) : null;
        setTimeout(() => {
          this._emitControl(exit({ channelId: msg.channel_id, code: ok ? 0 : 1 }));
          this._emitControl(close({ channelId: msg.channel_id }));
        }, 0);
      }
      return;
    }

    if (msg.type === MSG.CLOSE) {
      this.#uploads.delete(msg.channel_id);
    }
  }

  #assembleUpload(upload) {
    const out = new Uint8Array(upload.totalSize);
    for (const [offset, chunk] of upload.chunks) out.set(chunk, offset);
    return out;
  }

  #streamDownload(channelId, data) {
    const CHUNK = 5; // deliberately tiny to force multiple chunks in tests
    let offset = 0;
    let sentBytes = 0;
    const sendNext = () => {
      const end = Math.min(offset + CHUNK, data.byteLength);
      const isFinal = end >= data.byteLength;

      if (sentBytes >= this.#truncateDownloadAfterBytes) {
        // Simulate a connection drop mid-transfer: the channel closes
        // (server-initiated) without ever sending a final chunk.
        this._emitControl(close({ channelId }));
        return;
      }

      this._emitControl(fileChunk({
        channelId, offset, data: data.subarray(offset, end), isFinal, totalSize: data.byteLength,
      }));
      sentBytes += end - offset;
      offset = end;
      if (!isFinal) setTimeout(sendNext, 0);
    };
    sendNext();
  }
}

async function connectedClient(transport) {
  const keyPair = await auth.generateKeyPair(true);
  const client = new clientMod.WshClient({
    transportFactories: { ws: () => transport },
  });
  await client.connect('ws://test.invalid', { username: 'alice', keyPair, transport: 'ws' });
  return client;
}

describe('WshClient file transfer (FileChunk)', { skip: !hasEd25519 && 'Ed25519 not available in this runtime' }, () => {
  it('upload() sends the data as FileChunk messages and resolves on server confirmation', async () => {
    const files = {};
    const transport = new MockFileServerTransport({ files });
    const client = await connectedClient(transport);

    // Bigger than the 64KB chunk size so it's guaranteed to split into
    // multiple FileChunk messages.
    const data = new Uint8Array(150_000).map((_, i) => i % 256);
    await client.upload(data, '/tmp/out.txt');

    const chunkMsgs = transport.sentMessages.filter((m) => m.type === MSG.FILE_CHUNK);
    assert.ok(chunkMsgs.length > 1, 'expected the payload to be split across multiple FileChunk messages');
    assert.equal(chunkMsgs.at(-1).is_final, true);
    assert.ok(chunkMsgs.every((m) => m.total_size === data.byteLength));
    assert.deepEqual(files['/tmp/out.txt'], data);
  });

  it('upload() of an empty file sends exactly one zero-length final chunk', async () => {
    const transport = new MockFileServerTransport({ files: {} });
    const client = await connectedClient(transport);

    await client.upload(new Uint8Array(0), '/tmp/empty.txt');

    const chunkMsgs = transport.sentMessages.filter((m) => m.type === MSG.FILE_CHUNK);
    assert.equal(chunkMsgs.length, 1);
    assert.equal(chunkMsgs[0].is_final, true);
    assert.equal(chunkMsgs[0].total_size, 0);
    assert.equal(chunkMsgs[0].data.byteLength, 0);
  });

  it('upload() throws if the server reports a non-zero exit code', async () => {
    // A minimal transport that always confirms the upload with a failure
    // exit code, to check upload() propagates it rather than treating
    // "the server responded" as success on its own.
    class AlwaysFailTransport extends MockFileServerTransport {
      async _doSendControl(msg) {
        this.sentMessages.push(msg);
        if (msg.type === MSG.HELLO) {
          setTimeout(() => this._emitControl({ type: MSG.CHALLENGE, nonce: new Uint8Array(32).fill(7), session_id: 'x' }), 0);
        } else if (msg.type === MSG.AUTH) {
          setTimeout(() => this._emitControl({ type: MSG.AUTH_OK }), 0);
        } else if (msg.type === MSG.OPEN) {
          setTimeout(() => this._emitControl(openOk({ channelId: 1, dataMode: 'virtual', capabilities: [] })), 0);
        } else if (msg.type === MSG.FILE_CHUNK && msg.is_final) {
          setTimeout(() => {
            this._emitControl(exit({ channelId: msg.channel_id, code: 1 }));
            this._emitControl(close({ channelId: msg.channel_id }));
          }, 0);
        }
      }
    }
    const failTransport = new AlwaysFailTransport({});
    const client = await connectedClient(failTransport);

    await assert.rejects(
      () => client.upload(new TextEncoder().encode('nope'), '/tmp/rejected.txt'),
      /exit code 1/
    );
  });

  // Also a regression test for a dispatch-ordering bug found while writing
  // this suite: the mock's OPEN_OK and the first FileChunk are emitted
  // synchronously back-to-back (#streamDownload sends chunk 0 right after
  // OPEN_OK, in the same synchronous call), reproducing what a fast real
  // server sending both in one write (and thus possibly one TCP read /
  // message batch) would look like. openSession() used to register the
  // session in #sessions only as a later microtask continuation of its
  // OPEN_OK waiter, so the first chunk could be dispatched before the
  // session existed and be silently dropped -- corrupting the start of
  // every download. #handleControl now constructs and registers the
  // session synchronously in the same dispatch step as OPEN_OK itself.
  it('download() reassembles FileChunk messages delivered out of a single read into the original bytes', async () => {
    const original = new TextEncoder().encode('roundtrip file contents, definitely more than one 5-byte chunk');
    const transport = new MockFileServerTransport({ files: { '/tmp/in.txt': original } });
    const client = await connectedClient(transport);

    const result = await client.download('/tmp/in.txt');
    assert.deepEqual(result, original);
  });

  it('upload() then download() round-trips real content end to end', async () => {
    const transport = new MockFileServerTransport({ files: {} });
    const client = await connectedClient(transport);

    const original = new TextEncoder().encode('end-to-end roundtrip through the mock relay server');
    await client.upload(original, '/tmp/roundtrip.txt');
    const result = await client.download('/tmp/roundtrip.txt');

    assert.deepEqual(result, original);
  });

  it('download() rejects a nonexistent path with OPEN_FAIL', async () => {
    const transport = new MockFileServerTransport({ files: {} });
    const client = await connectedClient(transport);

    await assert.rejects(() => client.download('/tmp/missing.txt'), /no such file/);
  });

  it('download() detects a truncated transfer when the channel closes before is_final', async () => {
    const original = new TextEncoder().encode('this file will never fully arrive because the link drops');
    const transport = new MockFileServerTransport({
      files: { '/tmp/flaky.txt': original },
      truncateDownloadAfterBytes: 10,
    });
    const client = await connectedClient(transport);

    await assert.rejects(() => client.download('/tmp/flaky.txt'), /truncated/);
  });

  it('download() reports progress via onProgress with {received, total}', async () => {
    const original = new TextEncoder().encode('progress reporting sanity check payload');
    const transport = new MockFileServerTransport({ files: { '/tmp/progress.txt': original } });
    const client = await connectedClient(transport);

    const calls = [];
    const result = await client.download('/tmp/progress.txt', {
      onProgress: (p) => calls.push({ ...p }),
    });

    assert.deepEqual(result, original);
    assert.ok(calls.length > 1);
    assert.equal(calls.at(-1).received, original.byteLength);
    assert.ok(calls.every((c) => c.total === original.byteLength));
  });
});

describe('WshFileTransfer', { skip: !hasEd25519 && 'Ed25519 not available in this runtime' }, () => {
  it('upload()/download() delegate to the client and round-trip through it', async () => {
    const transport = new MockFileServerTransport({ files: {} });
    const client = await connectedClient(transport);
    const ft = new fileTransferMod.WshFileTransfer(client);

    const original = new TextEncoder().encode('via the WshFileTransfer facade');
    const uploadResult = await ft.upload(original, '/tmp/facade.txt');
    assert.equal(uploadResult.success, true);
    assert.equal(uploadResult.bytesTransferred, original.byteLength);

    const downloaded = await ft.download('/tmp/facade.txt');
    assert.deepEqual(downloaded, original);
  });

  it('upload()/download() throw a clear error against a client without upload()/download()', async () => {
    const bareTransportClient = { sendControl: async () => {}, openStream: async () => ({}) };
    const ft = new fileTransferMod.WshFileTransfer(bareTransportClient);

    await assert.rejects(() => ft.upload(new Uint8Array(1), '/tmp/x'), /requires a client exposing upload/);
    await assert.rejects(() => ft.download('/tmp/x'), /requires a client exposing download/);
  });
});
