// authorized_keys options (wsh #122): the shared vectors in spec/key-options.vectors.json, run against the Node host's parser and
// request check. The Rust server runs the same file (crates/wsh-server/src/auth/permissions.rs), so the two cannot drift.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseAuthorizedKeyLine, parseKeyOptions, checkKeyRequest, fullAccess } from '../src/key-options.mjs';

const vectors = JSON.parse(readFileSync(new URL('../spec/key-options.vectors.json', import.meta.url), 'utf8'));
const withKey = (line) => line.replaceAll(vectors.keyPlaceholder, vectors.key);
const canOf = (p) => vectors.grants.filter((g) => p[g]);

describe('authorized_keys options: shared vectors', () => {
  for (const v of vectors.lines) {
    it(`line: ${v.name}`, () => {
      const r = parseAuthorizedKeyLine(withKey(v.line));
      if (v.result === 'skip') { assert.ok(r.skip, `expected a skipped line, got ${JSON.stringify(r)}`); return; }
      if (v.result === 'refused') {
        assert.ok(r.refused, `expected the key to be refused, got ${JSON.stringify(r)}`);
        assert.equal(r.refused.code, v.code);
        assert.equal(r.permissions, undefined, 'a refused key carries no permissions');
        return;
      }
      assert.ok(r.permissions, `expected a usable key, got ${JSON.stringify(r)}`);
      assert.equal(r.key.byteLength, 32);
      assert.deepEqual(canOf(r.permissions), v.can);
      assert.equal(r.permissions.forcedCommand, v.forcedCommand);
      assert.equal(r.permissions.maxSessions, v.maxSessions);
    });
  }

  for (const v of vectors.requests) {
    it(`request: ${v.name}`, () => {
      const parsed = parseKeyOptions(v.options);
      assert.ok(parsed.ok, `options ${JSON.stringify(v.options)} must parse: ${parsed.reason}`);
      const refusal = checkKeyRequest(parsed.permissions, v.request, { activeSessions: v.activeSessions ?? 0 });
      if (v.allowed) assert.equal(refusal, null, JSON.stringify(refusal));
      else assert.equal(refusal?.code, v.code);
    });
  }

  it('a key with no options has full access and that is what an empty options string means', () => {
    assert.deepEqual(parseKeyOptions('').permissions, fullAccess());
    assert.deepEqual(parseKeyOptions(null).permissions, fullAccess());
  });

  it('the vectors only use refusal codes the hosts document', async () => {
    const { KEY_OPTION_ERRORS, KEY_REQUEST_REFUSALS } = await import('../src/key-options.mjs');
    for (const v of vectors.lines) if (v.code) assert.ok(KEY_OPTION_ERRORS.includes(v.code), v.code);
    for (const v of vectors.requests) if (v.code) assert.ok(KEY_REQUEST_REFUSALS.includes(v.code), v.code);
  });
});
