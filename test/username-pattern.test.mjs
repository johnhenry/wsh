// test/username-pattern.test.mjs -- the host option `usernamePattern`: which login names a host admits. The default is the
// OS-user shape and does not change; a host that does not map names to OS accounts (a page, a mesh peer whose name is a
// base64url identity hash) may admit its own shape, but never control characters, path separators or an unbounded name.
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { createWshServer } from '@johnhenry/wsh/server';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { resolveUsernamePattern, DEFAULT_USERNAME_PATTERN } from '../src/server/username.mjs';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';

const IDENTITY = 'Q2f-9_xK0aZ1b3c4d5e6f7g8h9i0jklmnopqrstuvwx'; // a base64url hash that starts with a letter...
const DIGIT_FIRST = '9Q2f-9_xK0aZ1b3c4d5e6f7g8h9i0jklmnopqrstuvw';
const DASH_FIRST = '-Q2f9_xK0aZ1b3c4d5e6f7g8h9i0jklmnopqrstuvwxy';
const peer = /^[A-Za-z0-9_-]{1,64}$/;

let keyPair;
let authorizedKeys;
before(async () => {
  keyPair = await generateKeyPair(true);
  authorizedKeys = await exportPublicKeySSH(keyPair.publicKey);
});

async function attempt(host, username) {
  const client = new WshClient();
  try {
    await client.connect(host.url, { username, keyPair, timeout: 5000, ...(host.connectOptions ?? {}) });
    const seen = host.seen?.();
    await client.disconnect().catch(() => {});
    return { ok: true, seen };
  } catch (error) {
    return { ok: false, error };
  }
}

async function nodeHost(opts) {
  const seen = [];
  const server = createWshServer({ auth: { authorizedKeys, authorize: (who) => { seen.push(who.username); return true; } }, ...opts });
  const { port } = await server.listen();
  return { url: `ws://127.0.0.1:${port}`, server, seen: () => seen.at(-1), close: () => server.close() };
}

describe('the default pattern is unchanged', () => {
  it('is the OS-user shape and refuses a name that starts with a digit or a dash', async () => {
    assert.equal(DEFAULT_USERNAME_PATTERN.source, '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$');
    const host = await nodeHost({});
    try {
      assert.equal((await attempt(host, 'alice')).ok, true);
      for (const name of [DIGIT_FIRST, DASH_FIRST, 'a b', 'a/b']) {
        const r = await attempt(host, name);
        assert.equal(r.ok, false, JSON.stringify(name));
        assert.match(r.error.message, /bad username/);
      }
    } finally { await host.close(); }
  });
});

describe('usernamePattern on a Node host', () => {
  it('admits what the pattern names, and only that', async () => {
    const host = await nodeHost({ usernamePattern: peer });
    try {
      for (const name of [IDENTITY, DIGIT_FIRST, DASH_FIRST]) {
        const r = await attempt(host, name);
        assert.equal(r.ok, true, name);
        assert.equal(r.seen, name, 'authorize() sees the name unchanged');
      }
      const refused = await attempt(host, 'has.dot');
      assert.equal(refused.ok, false);
      assert.match(refused.error.message, /bad username/);
    } finally { await host.close(); }
  });

  it('accepts the pattern as a source string', async () => {
    const host = await nodeHost({ usernamePattern: '^[A-Za-z0-9_-]{1,64}$' });
    try { assert.equal((await attempt(host, DIGIT_FIRST)).ok, true); } finally { await host.close(); }
  });
});

describe('usernamePattern on a memory host', () => {
  it('admits a name the default refuses', async () => {
    const host = createMemoryHost({ auth: { authorizedKeys }, usernamePattern: peer });
    const client = await host.connect({ username: DIGIT_FIRST, keyPair });
    await client.disconnect();
    const strict = createMemoryHost({ auth: { authorizedKeys } });
    await assert.rejects(strict.connect({ username: DIGIT_FIRST, keyPair }), /bad username/);
  });
});

describe('what no pattern can admit', () => {
  it('refuses control characters, path separators and a long name even under a pattern that matches anything', async () => {
    const host = await nodeHost({ usernamePattern: /^[\s\S]+$/ });
    try {
      for (const name of ['a\nb', 'a\u0000b', 'a\u001bb', 'a\u007fb', 'a/b', 'a\\b', '..', 'x'.repeat(257), ' x']) {
        const r = await attempt(host, name);
        assert.equal(r.ok, false, JSON.stringify(name));
      }
      assert.equal((await attempt(host, 'x'.repeat(256))).ok, true, 'the longest allowed name');
    } finally { await host.close(); }
  });

  it('resolveUsernamePattern rejects what is not a pattern, and a pattern that matches the empty name', () => {
    for (const bad of [42, {}, [], '(', /^$/, /^.*$/, 'a*']) {
      assert.throws(() => resolveUsernamePattern(bad, 'createWshServer'), (e) => e instanceof TypeError && /usernamePattern/.test(e.message), String(bad));
    }
    assert.equal(resolveUsernamePattern(undefined, 'x'), DEFAULT_USERNAME_PATTERN);
    assert.ok(resolveUsernamePattern(peer, 'x') instanceof RegExp);
  });

  it('a global or sticky flag does not make the test stateful', () => {
    const re = resolveUsernamePattern(/^[a-z]+$/g, 'x');
    assert.equal(re.global, false);
    assert.equal(re.test('abc'), true);
    assert.equal(re.test('abc'), true);
  });
});
