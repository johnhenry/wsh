import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  WebTransportTransport,
  parseCertificateHash,
  normalizeWebTransportOptions,
} from '../src/transport.mjs';

// These tests stand in a real `WebTransport` global. That is a mock of
// the *platform*, not of a wsh server: every assertion below is against
// the WebTransport constructor's own contract (what arguments it is
// handed), which no counterparty can answer differently to make the
// client happy. The thing being checked is precisely the thing a mocked
// server could never reveal -- that the options a caller asked for
// actually reach the browser API.

/** A stand-in WebTransport that records exactly how it was constructed. */
class FakeWebTransport {
  static calls = [];

  constructor(url, options) {
    // Record `arguments.length` too: `new WebTransport(url)` and
    // `new WebTransport(url, {})` are equivalent to the platform but not
    // to this test -- the second form is what a naive `{...undefined}`
    // spread would produce, and it would hide a dropped option.
    FakeWebTransport.calls.push({ url, options, argCount: arguments.length });

    this.ready = Promise.resolve();
    this.closed = new Promise(() => {});
  }

  createBidirectionalStream() {
    return Promise.resolve({
      readable: new ReadableStream({ start(c) { c.close(); } }),
      writable: new WritableStream(),
    });
  }

  get incomingBidirectionalStreams() {
    return new ReadableStream({ start(c) { c.close(); } });
  }

  close() {}
}

let savedWebTransport;

beforeEach(() => {
  savedWebTransport = globalThis.WebTransport;
  globalThis.WebTransport = FakeWebTransport;
  FakeWebTransport.calls = [];
});

afterEach(() => {
  if (savedWebTransport === undefined) delete globalThis.WebTransport;
  else globalThis.WebTransport = savedWebTransport;
});

// A real SHA-256 digest of a certificate, in the three shapes a caller
// plausibly has it in.
const HASH_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const HASH_BYTES = Uint8Array.from(
  HASH_HEX.match(/../g).map((h) => Number.parseInt(h, 16))
);
const HASH_B64 = Buffer.from(HASH_BYTES).toString('base64');

describe('parseCertificateHash', () => {
  it('accepts plain hex', () => {
    assert.deepEqual(parseCertificateHash(HASH_HEX), HASH_BYTES);
  });

  it('accepts the colon-separated hex openssl prints', () => {
    const colons = HASH_HEX.match(/../g).join(':').toUpperCase();
    assert.deepEqual(parseCertificateHash(colons), HASH_BYTES);
  });

  it("accepts openssl's full `SHA256 Fingerprint=AB:CD:...` line", () => {
    const line = `SHA256 Fingerprint=${HASH_HEX.match(/../g).join(':').toUpperCase()}`;
    assert.deepEqual(parseCertificateHash(line), HASH_BYTES);
  });

  it('accepts base64 and base64url', () => {
    assert.deepEqual(parseCertificateHash(HASH_B64), HASH_BYTES);
    const b64url = HASH_B64.replace(/\+/g, '-').replace(/\//g, '_');
    assert.deepEqual(parseCertificateHash(b64url), HASH_BYTES);
  });

  it('passes a BufferSource straight through as bytes', () => {
    assert.deepEqual(parseCertificateHash(HASH_BYTES), HASH_BYTES);
    assert.deepEqual(parseCertificateHash(HASH_BYTES.buffer), HASH_BYTES);
  });

  it('rejects a digest of the wrong length rather than letting the connection fail opaquely', () => {
    assert.throws(
      () => parseCertificateHash('0123456789abcdef'),
      (err) => err instanceof RangeError && /32 bytes, got 8/.test(err.message)
    );
  });

  it('rejects a string that is neither hex nor base64', () => {
    assert.throws(() => parseCertificateHash('not a digest!!'), TypeError);
  });

  it('rejects a non-string, non-BufferSource value', () => {
    assert.throws(() => parseCertificateHash(12345), TypeError);
  });
});

describe('normalizeWebTransportOptions', () => {
  it('returns undefined when there is nothing to pass', () => {
    assert.equal(normalizeWebTransportOptions(undefined), undefined);
    assert.equal(normalizeWebTransportOptions({}), undefined);
    assert.equal(normalizeWebTransportOptions({ congestionControl: undefined }), undefined);
  });

  it('normalizes every accepted digest shape to { algorithm, value: Uint8Array }', () => {
    const out = normalizeWebTransportOptions({
      serverCertificateHashes: [
        HASH_HEX,
        HASH_BYTES,
        { value: HASH_B64 },
        { algorithm: 'SHA-256', value: HASH_HEX },
      ],
    });
    assert.equal(out.serverCertificateHashes.length, 4);
    for (const entry of out.serverCertificateHashes) {
      assert.equal(entry.algorithm, 'sha-256');
      assert.ok(entry.value instanceof Uint8Array);
      assert.deepEqual(entry.value, HASH_BYTES);
    }
  });

  it('forwards unknown platform options verbatim', () => {
    const out = normalizeWebTransportOptions({
      congestionControl: 'low-latency',
      requireUnreliable: true,
      somethingTheEngineGainsLater: 42,
    });
    assert.deepEqual(out, {
      congestionControl: 'low-latency',
      requireUnreliable: true,
      somethingTheEngineGainsLater: 42,
    });
  });

  it('rejects an empty or non-array serverCertificateHashes', () => {
    assert.throws(() => normalizeWebTransportOptions({ serverCertificateHashes: [] }), TypeError);
    assert.throws(() => normalizeWebTransportOptions({ serverCertificateHashes: HASH_HEX }), TypeError);
  });
});

describe('WebTransportTransport passes options to the WebTransport constructor', () => {
  it('serverCertificateHashes given to the constructor reaches `new WebTransport(url, options)`', async () => {
    const t = new WebTransportTransport({ serverCertificateHashes: [HASH_HEX] });
    await t.connect('https://192.168.1.20:4433/wsh');

    assert.equal(FakeWebTransport.calls.length, 1);
    const call = FakeWebTransport.calls[0];
    assert.equal(call.url, 'https://192.168.1.20:4433/wsh');
    assert.equal(call.argCount, 2, 'the options dictionary must actually be passed');
    assert.deepEqual(call.options, {
      serverCertificateHashes: [{ algorithm: 'sha-256', value: HASH_BYTES }],
    });
  });

  it('options given to connect() reach the constructor too', async () => {
    const t = new WebTransportTransport();
    await t.connect('https://example.test:4433/wsh', {
      serverCertificateHashes: [{ algorithm: 'sha-256', value: HASH_BYTES }],
    });

    assert.equal(FakeWebTransport.calls[0].argCount, 2);
    assert.deepEqual(FakeWebTransport.calls[0].options.serverCertificateHashes, [
      { algorithm: 'sha-256', value: HASH_BYTES },
    ]);
  });

  it('connect() options override constructor options key by key', async () => {
    const other = new Uint8Array(32).fill(0xaa);
    const t = new WebTransportTransport({
      serverCertificateHashes: [HASH_HEX],
      congestionControl: 'throughput',
    });
    await t.connect('https://example.test:4433/wsh', { serverCertificateHashes: [other] });

    assert.deepEqual(FakeWebTransport.calls[0].options, {
      serverCertificateHashes: [{ algorithm: 'sha-256', value: other }],
      congestionControl: 'throughput',
    });
  });

  it('passes no second argument at all when no options were given', async () => {
    const t = new WebTransportTransport();
    await t.connect('https://example.test:4433/wsh');

    assert.equal(FakeWebTransport.calls[0].argCount, 1);
    assert.equal(FakeWebTransport.calls[0].options, undefined);
  });

  it('a malformed hash fails the connect locally, before any network work', async () => {
    const t = new WebTransportTransport({ serverCertificateHashes: ['deadbeef'] });
    await assert.rejects(
      () => t.connect('https://example.test:4433/wsh'),
      RangeError
    );
    assert.equal(FakeWebTransport.calls.length, 0, 'must not have constructed a WebTransport');
    assert.equal(t.state, 'closed');
  });
});
