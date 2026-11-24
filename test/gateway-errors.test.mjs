// The GatewayFail code table as data, from one place (#220): the numeric codes a host puts in GatewayFail.code, with their names and
// meaning, exported so that a consumer that decodes them (BrowserMesh's netway keeps a hand-written copy) imports the table instead.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { GATEWAY_FAIL, GATEWAY_FAIL_TABLE, GATEWAY_FAIL_LOCAL, gatewayFailName, GatewayError } from '@johnhenry/wsh';
import { GATEWAY_FAIL as serverTable } from '../src/server/gateway-core.mjs';

// What @johnhenry/browsermesh-netway's `GATEWAY_ERROR` held when this table was written (packages/browsermesh-netway/src/constants.mjs):
// the export must stay a superset of it, name for name and number for number.
const NETWAY_GATEWAY_ERROR = { CONNECTION_REFUSED: 1, HOST_UNREACHABLE: 2, DNS_FAILED: 3, POLICY_DENIED: 4, TIMEOUT: 5, CLOSED: 6, QUEUE_FULL: 7 };

describe('GATEWAY_FAIL: the codes of GatewayFail', () => {
  it('is the table the Node gateway sends, one object (not a copy), frozen', () => {
    assert.equal(serverTable, GATEWAY_FAIL);
    assert.ok(Object.isFrozen(GATEWAY_FAIL));
    assert.ok(Object.isFrozen(GATEWAY_FAIL_TABLE));
    assert.throws(() => { 'use strict'; GATEWAY_FAIL.NEW = 9; }, TypeError);
  });

  it('is a superset of what netway mirrors, name for name and number for number', () => {
    for (const [name, code] of Object.entries(NETWAY_GATEWAY_ERROR)) assert.equal(GATEWAY_FAIL[name], code, name);
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

  it('says where the Rust server differs: the code 5 it sends for a disabled gateway', () => {
    const five = GATEWAY_FAIL_TABLE.find((r) => r.code === 5);
    assert.equal(five.name, 'TIMEOUT');
    assert.deepEqual(five.alsoSentAs, ['GATEWAY_DISABLED']);
    assert.match(five.meaning, /disabled/);
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
