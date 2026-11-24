// The notation of key capabilities (spec/capabilities.md, #220): the shared vectors in spec/capabilities.vectors.json, run against the JS
// evaluation (`permits` / `checkCapabilities` of @johnhenry/wsh/capabilities) and against the full key check of key-options.mjs, which
// composes `restrict`/`permit-*`/`expires` with the list. The Rust server runs the same file (crates/wsh-server/src/auth/permissions.rs).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { permits, checkCapabilities, parseCapabilityList, CAPABILITIES_NOTATION_VERSION } from '@johnhenry/wsh/capabilities';
import vectors from '@johnhenry/wsh/spec/capabilities.vectors.json' with { type: 'json' };
import { parseKeyOptions, checkKeyRequest } from '../src/key-options.mjs';

const runsHere = (v) => v.hosts === undefined || v.hosts.includes('node');
const optionsOf = (v) => [v.options, v.capabilities ? `capabilities="${v.capabilities.join(',')}"` : null, v.expires ? `expires="${v.expires}"` : null].filter(Boolean).join(',');

describe('the vectors file', () => {
  it('has a version, and it is the revision of the notation the package implements', () => {
    assert.equal(vectors.version, 1);
    assert.equal(vectors.version, CAPABILITIES_NOTATION_VERSION);
    assert.equal(vectors.spec, 'spec/capabilities.md');
  });

  it('is published as a package file and named in the exports (another implementation runs it from the package)', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    assert.ok(pkg.files.includes('spec/*.json') && pkg.files.includes('spec/*.md'), 'spec files are in `files`');
    assert.equal(pkg.exports['./spec/*.json'], './spec/*.json');
    assert.equal(pkg.exports['./spec/*.md'], './spec/*.md');
    assert.equal(pkg.exports['./capabilities'].import, './src/capabilities.mjs');
  });

  it('every refusal code it uses is one the hosts document, and every case names a known host class', async () => {
    const { KEY_OPTION_ERRORS, KEY_REQUEST_REFUSALS } = await import('../src/key-options.mjs');
    for (const v of vectors.lists) if (v.code) assert.ok(KEY_OPTION_ERRORS.includes(v.code), v.code);
    for (const v of vectors.requests) if (v.code) assert.ok([...KEY_REQUEST_REFUSALS].includes(v.code), v.code);
    for (const v of [...vectors.lists, ...vectors.requests]) for (const h of v.hosts ?? []) assert.ok(h in vectors.hostClasses, `${v.name}: ${h}`);
  });
});

describe('capability lists: shared vectors', () => {
  for (const v of vectors.lists.filter(runsHere)) {
    it(`list: ${v.name}`, () => {
      const r = parseCapabilityList(v.capabilities);
      if (v.result === 'ok') { assert.equal(r.ok, true, JSON.stringify(r)); assert.deepEqual(r.capabilities, v.capabilities); return; }
      assert.equal(r.ok, false);
      assert.equal(r.code, v.code);
      // a list with a bad entry is refused whole, in a key line as well
      const line = parseKeyOptions(`capabilities="${v.capabilities.join(',')}"`);
      assert.equal(line.ok, false);
      assert.equal(line.code, v.code);
    });
  }
});

describe('does a holder of list L permit request R: shared vectors', () => {
  for (const v of vectors.requests.filter(runsHere)) {
    it(`request: ${v.name}`, () => {
      const now = v.now === undefined ? undefined : v.now * 1000;
      if (v.invalidList) {
        assert.equal(permits(v.capabilities, v.request, { now }), false, 'a list with an entry that is not understood permits nothing');
        assert.equal(parseKeyOptions(optionsOf(v)).ok, false);
        return;
      }
      // the whole key: options, expiry, list (what a host runs)
      const parsed = parseKeyOptions(optionsOf(v));
      assert.ok(parsed.ok, `must parse: ${parsed.reason}`);
      const refusal = checkKeyRequest(parsed.permissions, v.request, { activeSessions: v.activeSessions ?? 0, now: v.now });
      if (v.permitted) assert.equal(refusal, null, JSON.stringify(refusal));
      else {
        assert.equal(refusal?.code, v.code ?? 'capability-missing');
        if (v.capability !== undefined) assert.equal(refusal.capability, v.capability, 'the refusal names the capability that was needed');
      }
      // the pure function says the same, for the cases that are about the list and its expiry
      if (v.options === undefined && v.activeSessions === undefined) {
        assert.equal(permits(v.capabilities, v.request, { expires: v.expires, now }), v.permitted, 'permits()');
        const r = checkCapabilities(v.capabilities, v.request, { expires: v.expires, now });
        assert.equal(r === null, v.permitted);
        if (!v.permitted) assert.equal(r.code, v.code ?? 'capability-missing');
      }
    });
  }
});

describe('permits() is a pure function that fails closed', () => {
  it('accepts a comma separated string as capabilities="..." does, a Date or milliseconds for expires and now', () => {
    assert.equal(permits('exec,fs:read', { kind: 'open', channel: 'exec' }), true);
    const expires = new Date(Date.UTC(2030, 0, 1));
    assert.equal(permits(['exec'], { kind: 'open', channel: 'exec' }, { expires, now: new Date(Date.UTC(2029, 11, 31)) }), true);
    assert.equal(permits(['exec'], { kind: 'open', channel: 'exec' }, { expires, now: expires.getTime() }), false);
    assert.equal(permits(['exec'], { kind: 'open', channel: 'exec' }, { expires: '2030-01-01T00:00:00Z', now: expires.getTime() + 1000 }), false);
  });

  it('refuses where it cannot decide: no list, a list that is not strings, no request, a request kind it does not know, a bad expires', () => {
    const exec = { kind: 'open', channel: 'exec' };
    for (const bad of [undefined, null, 5, {}, [1], [null], ['exec', {}]]) assert.equal(permits(bad, exec), false, String(JSON.stringify(bad)));
    assert.equal(permits(['exec'], undefined), false);
    assert.equal(permits(['exec'], null), false);
    assert.equal(permits(['exec'], {}), false);
    assert.equal(permits(['exec'], { kind: 'teleport' }), false);
    assert.equal(permits(['exec', 'relay'], { kind: 'teleport' }), false);
    assert.equal(permits(['*'], exec), false, '* alone is not a capability');
    assert.equal(permits(['exec'], exec, { expires: 'next tuesday' }), false);
    assert.throws(() => permits(['exec'], exec, { now: 'now' }), TypeError);
  });

  it('does not change what it is given', () => {
    const list = Object.freeze(['exec', 'gateway:tcp:*.example.com:443']);
    const req = Object.freeze({ kind: 'tcp', host: 'a.example.com', port: 443 });
    assert.equal(permits(list, req), true);
    assert.deepEqual(list, ['exec', 'gateway:tcp:*.example.com:443']);
    assert.equal(permits(list, req), true);
  });

  it('the login is permitted until the expiry, as in a key line', () => {
    assert.equal(permits(['exec'], { kind: 'login' }), true);
    assert.equal(permits(['exec'], { kind: 'login' }, { expires: '2030-01-01T00:00:00Z', now: Date.UTC(2030, 0, 1) }), false);
  });
});
