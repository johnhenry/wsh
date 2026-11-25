// The GatewayFail code table as data, from one place (#220): the numeric codes a host puts in GatewayFail.code, with their names and
// meaning, exported so that a consumer that decodes them (BrowserMesh's netway keeps a hand-written copy) imports the table instead.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { GATEWAY_FAIL, GATEWAY_FAIL_TABLE, GATEWAY_FAIL_LOCAL, gatewayFailName, GatewayError } from '@johnhenry/wsh';
import { GATEWAY_FAIL as serverTable } from '../src/server/gateway-core.mjs';

// What @johnhenry/browsermesh-netway's `GATEWAY_ERROR` held when this table was first written (packages/browsermesh-netway/src/constants.mjs).
// Every name but TIMEOUT keeps its number. TIMEOUT moved from 5 to 8 (#223): 5 is GATEWAY_DISABLED, what the spec and the Rust server say.
const NETWAY_GATEWAY_ERROR = { CONNECTION_REFUSED: 1, HOST_UNREACHABLE: 2, DNS_FAILED: 3, POLICY_DENIED: 4, CLOSED: 6, QUEUE_FULL: 7 };
const vectors = JSON.parse(readFileSync(new URL('../spec/gateway-fail.vectors.json', import.meta.url), 'utf8'));

describe('GATEWAY_FAIL: the codes of GatewayFail', () => {
  it('is the table the Node gateway sends, one object (not a copy), frozen', () => {
    assert.equal(serverTable, GATEWAY_FAIL);
    assert.ok(Object.isFrozen(GATEWAY_FAIL));
    assert.ok(Object.isFrozen(GATEWAY_FAIL_TABLE));
    assert.throws(() => { 'use strict'; GATEWAY_FAIL.NEW = 9; }, TypeError);
  });

  it('keeps every number netway mirrors, except that TIMEOUT is 8 and 5 is GATEWAY_DISABLED', () => {
    for (const [name, code] of Object.entries(NETWAY_GATEWAY_ERROR)) assert.equal(GATEWAY_FAIL[name], code, name);
    assert.equal(GATEWAY_FAIL.TIMEOUT, 8);
    assert.equal(GATEWAY_FAIL.GATEWAY_DISABLED, 5);
  });

  it('has a row for every code: its number, its name and what it means; numbers and names are unique', () => {
    assert.deepEqual(GATEWAY_FAIL_TABLE.map((r) => r.name), Object.keys(GATEWAY_FAIL));
    for (const row of GATEWAY_FAIL_TABLE) {
      assert.equal(GATEWAY_FAIL[row.name], row.code);
      assert.ok(Number.isInteger(row.code) && row.code >= 1 && row.code <= 0xffff);
      assert.equal(typeof row.meaning, 'string');
      assert.ok(row.meaning.length > 10);
      assert.ok(Object.isFrozen(row));
    }
    assert.equal(new Set(GATEWAY_FAIL_TABLE.map((r) => r.code)).size, GATEWAY_FAIL_TABLE.length);
    assert.equal(new Set(GATEWAY_FAIL_TABLE.map((r) => r.name)).size, GATEWAY_FAIL_TABLE.length);
  });

  it('names the code a client makes up for itself, which never crosses the wire, apart from the wire codes', () => {
    assert.deepEqual({ ...GATEWAY_FAIL_LOCAL }, { UNSUPPORTED: 0 });
    for (const code of Object.values(GATEWAY_FAIL_LOCAL)) assert.ok(!Object.values(GATEWAY_FAIL).includes(code));
    assert.equal(new GatewayError('x', GATEWAY_FAIL_LOCAL.UNSUPPORTED).code, 0);
  });

  it('5 is GATEWAY_DISABLED (the spec and the Rust server) and says it is also what an older Node gateway sent for a timeout; TIMEOUT is 8', () => {
    const five = GATEWAY_FAIL_TABLE.find((r) => r.code === 5);
    assert.equal(five.name, 'GATEWAY_DISABLED');
    assert.deepEqual(five.alsoSentAs, ['TIMEOUT']);
    assert.match(five.meaning, /disabled/);
    assert.match(five.meaning, /timeout/);
    assert.match(five.meaning, /older/);
    const eight = GATEWAY_FAIL_TABLE.find((r) => r.code === 8);
    assert.equal(eight.name, 'TIMEOUT');
    assert.equal(eight.alsoSentAs, undefined);
    assert.equal(gatewayFailName(5), 'GATEWAY_DISABLED');
    assert.equal(gatewayFailName(8), 'TIMEOUT');
  });

  it('a GatewayError that carries 5 says both readings in its message and keeps the host\'s words; other codes are untouched', () => {
    const e = new GatewayError('gateway disabled', 5);
    assert.equal(e.code, 5);
    assert.match(e.message, /^gateway disabled/);
    assert.match(e.message, /disabled/);
    assert.match(e.message, /timeout from an older Node gateway/);
    assert.equal(new GatewayError('connect timed out', 8).message, 'connect timed out');
    assert.equal(new GatewayError('refused', 4).message, 'refused');
    assert.equal(new GatewayError('x', 0).message, 'x');
  });

  it('the Node gateway sends 8 (not 5) when a connect times out', async () => {
    const { socksConnect } = await import('../src/server/gateway.mjs');
    const { createServer } = await import('node:net');
    const held = new Set();
    const srv = createServer((s) => { held.add(s); s.on('error', () => {}); });  // accepts and never answers
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    try {
      await assert.rejects(socksConnect({ host: '127.0.0.1', port: srv.address().port }, 'example.test', 80, { timeoutMs: 50 }), (e) => e.code === 8 && e.code === GATEWAY_FAIL.TIMEOUT);
    } finally { for (const s of held) s.destroy(); await new Promise((r) => srv.close(r)); }
  });

  it('the shared vectors (spec/gateway-fail.vectors.json) match the table, name for name and number for number', () => {
    assert.equal(vectors.version, 1);
    assert.deepEqual(vectors.codes.map((c) => c.code), GATEWAY_FAIL_TABLE.map((r) => r.code));
    for (const v of vectors.codes) {
      const row = GATEWAY_FAIL_TABLE.find((r) => r.code === v.code);
      assert.equal(row.name, v.name);
      assert.deepEqual(row.alsoSentAs ?? [], v.alsoSentAs ?? []);
      assert.equal(GATEWAY_FAIL[v.name], v.code);
      assert.ok(Array.isArray(v.sentBy) && v.sentBy.length > 0);
    }
    assert.equal(vectors.codes.find((c) => c.code === 5).name, 'GATEWAY_DISABLED');
    assert.equal(vectors.codes.find((c) => c.code === 8).name, 'TIMEOUT');
  });

  it('the spec lists 5, 6, 7 and 8 under the numbers the table uses', () => {
    const spec = readFileSync(new URL('../spec/wsh-v1.yaml', import.meta.url), 'utf8');
    const block = spec.slice(spec.indexOf('Machine-readable failure reason'), spec.indexOf('Machine-readable failure reason') + 1600).replace(/\s+/g, ' ');
    for (const row of GATEWAY_FAIL_TABLE) assert.ok(block.includes(`${row.code}=${row.name}`), `${row.code}=${row.name}`);
  });

  it('covers every code the Rust server sends (read from its source)', () => {
    const source = readFileSync(new URL('../crates/wsh-server/src/gateway/session.rs', import.meta.url), 'utf8');
    const sent = [...source.matchAll(/^const FAIL_[A-Z_]+: u32 = (\d+);/gm)].map((m) => Number(m[1]));
    assert.ok(sent.length >= 5, 'the constants were found');
    for (const code of sent) assert.ok(GATEWAY_FAIL_TABLE.some((r) => r.code === code), `the Rust server sends ${code}`);
  });

  it('gatewayFailName(code) is the name, or null for a number not in the table', () => {
    assert.equal(gatewayFailName(4), 'POLICY_DENIED');
    assert.equal(gatewayFailName(7), 'QUEUE_FULL');
    assert.equal(gatewayFailName(0), 'UNSUPPORTED');
    assert.equal(gatewayFailName(99), null);
    assert.equal(gatewayFailName('4'), null);
    assert.equal(gatewayFailName(undefined), null);
  });
});
