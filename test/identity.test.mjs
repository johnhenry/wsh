// @johnhenry/wsh/identity (#220): one browser-safe module for a key's identity in its three spellings -- the raw Ed25519 public key, the
// OpenSSH `ssh-ed25519` line, and the two names derived from the hash of the raw key (the hex fingerprint of wsh, the base64url pod id of
// a mesh) -- and a builder of `authorized_keys` lines that refuses what could grant more than was asked.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PodIdentity } from '@johnhenry/browsermesh-primitives';
import {
  fingerprint, podId, fingerprintToPodId, podIdToFingerprint,
  rawKeyToOpenSsh, openSshToRawKey, parseOpenSshKey, publicKeyToOpenSsh, identityOf, authorizedKeyLine, normalizeIdentity,
} from '@johnhenry/wsh/identity';
import * as identity from '@johnhenry/wsh/identity';
import * as main from '@johnhenry/wsh';
import { generateKeyPair, exportPublicKeyRaw, exportPublicKeySSH } from '@johnhenry/wsh';
import { parseAuthorizedKeyLine } from '../src/key-options.mjs';

const LINE = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFwuwlhewrj73VpJwckueO62uR5tQZacudrGnfSHW89b';
const hex = (u8) => Buffer.from(u8).toString('hex');
const keyBytes = () => Uint8Array.from(Buffer.from(LINE.split(' ')[1], 'base64').subarray(19));

describe('the module is one stable export', () => {
  it('names every conversion, and the main entry still exports the ones it had', () => {
    for (const name of ['fingerprint', 'podId', 'fingerprintToPodId', 'podIdToFingerprint', 'rawKeyToOpenSsh', 'openSshToRawKey', 'parseOpenSshKey', 'publicKeyToOpenSsh', 'identityOf', 'authorizedKeyLine', 'normalizeIdentity']) {
      assert.equal(typeof identity[name], 'function', name);
    }
    for (const name of ['fingerprint', 'podId', 'fingerprintToPodId', 'podIdToFingerprint']) assert.equal(main[name], identity[name], `${name} is one function, not a copy`);
  });
});

describe('fingerprint and pod id', () => {
  it('are the same hash in two spellings, both ways, and agree with a mesh identity', async () => {
    const mesh = await PodIdentity.generate();
    const raw = await exportPublicKeyRaw(mesh.keyPair.publicKey);
    const fp = await fingerprint(raw);
    assert.match(fp, /^[0-9a-f]{64}$/);
    assert.equal(await podId(raw), mesh.podId);
    assert.equal(fingerprintToPodId(fp), mesh.podId);
    assert.equal(podIdToFingerprint(mesh.podId), fp);
    assert.equal(fingerprintToPodId(fp.toUpperCase()), mesh.podId, 'hex is accepted in either case');
    assert.equal(podIdToFingerprint(fingerprintToPodId(fp)), fp);
  });

  it('refuse what is not exactly a 32-byte hash, instead of emitting a name for something else', () => {
    for (const bad of ['', 'ab', 'a'.repeat(63), 'a'.repeat(65), 'g'.repeat(64), ' '.repeat(64), `${'a'.repeat(62)}\n`, null, undefined, 5, {}]) {
      assert.throws(() => fingerprintToPodId(bad), TypeError, JSON.stringify(bad));
    }
    for (const bad of ['', 'A'.repeat(42), 'A'.repeat(44), `${'A'.repeat(42)}=`, `${'A'.repeat(42)}+`, `${'A'.repeat(42)}/`, '!'.repeat(43), `${'A'.repeat(42)} `, null, undefined, 5]) {
      assert.throws(() => podIdToFingerprint(bad), TypeError, JSON.stringify(bad));
    }
    // 43 characters carry 258 bits: the last character may only have its top four bits set, or two names would stand for one key
    assert.throws(() => podIdToFingerprint(`${'A'.repeat(42)}B`), TypeError);
    assert.equal(podIdToFingerprint(`${'A'.repeat(42)}A`), '00'.repeat(32));
    assert.equal(podIdToFingerprint(`${'A'.repeat(42)}g`).length, 64);
  });
});

describe('raw key <-> OpenSSH line', () => {
  it('a known key round-trips, with and without a comment', () => {
    const raw = keyBytes();
    assert.equal(raw.byteLength, 32);
    assert.equal(rawKeyToOpenSsh(raw), LINE);
    assert.equal(rawKeyToOpenSsh(raw, 'alice@laptop'), `${LINE} alice@laptop`);
    assert.deepEqual(openSshToRawKey(LINE), raw);
    assert.deepEqual(openSshToRawKey(`${LINE} alice@laptop`), raw);
    assert.deepEqual(parseOpenSshKey(`${LINE} alice@laptop work key`), { raw, comment: 'alice@laptop work key' });
    assert.deepEqual(parseOpenSshKey(LINE), { raw, comment: '' });
  });

  it('agrees with the line the CryptoKey export makes, and with what a host reads', async () => {
    const { publicKey } = await generateKeyPair(true);
    const raw = await exportPublicKeyRaw(publicKey);
    assert.equal(rawKeyToOpenSsh(raw), await exportPublicKeySSH(publicKey));
    assert.equal(await publicKeyToOpenSsh(publicKey), await exportPublicKeySSH(publicKey));
    assert.equal(await publicKeyToOpenSsh(publicKey, 'me'), `${await exportPublicKeySSH(publicKey)} me`);
    const parsed = parseAuthorizedKeyLine(rawKeyToOpenSsh(raw));
    assert.deepEqual(parsed.key, raw);
  });

  it('refuses a key that is not 32 bytes of Ed25519, and a comment that could start another line', () => {
    for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0), 'abc', null, [1, 2], new Uint16Array(16)]) {
      assert.throws(() => rawKeyToOpenSsh(bad), TypeError, String(bad?.constructor?.name));
    }
    for (const bad of ['a\nb', 'a\rb', 'a\0b', 'a\tb\u007f', 'x y']) {
      assert.throws(() => rawKeyToOpenSsh(new Uint8Array(32), bad), TypeError, JSON.stringify(bad));
    }
  });

  it('reads nothing but a plain ssh-ed25519 line: no options, no other key type, no trailing bytes, no second line', () => {
    const raw = keyBytes();
    const wire = (type, key, extra = new Uint8Array(0)) => {
      const t = new TextEncoder().encode(type);
      const out = new Uint8Array(4 + t.length + 4 + key.length + extra.length);
      const v = new DataView(out.buffer);
      v.setUint32(0, t.length); out.set(t, 4); v.setUint32(4 + t.length, key.length); out.set(key, 8 + t.length); out.set(extra, 8 + t.length + key.length);
      return out;
    };
    const line = (bytes) => `ssh-ed25519 ${Buffer.from(bytes).toString('base64')}`;
    assert.deepEqual(openSshToRawKey(line(wire('ssh-ed25519', raw))), raw);
    const bad = {
      'options before the key': `restrict ${LINE}`,
      'another key type': LINE.replace('ssh-ed25519', 'ssh-rsa'),
      'a second line': `${LINE}\n${LINE}`,
      'a comment with a newline': `${LINE} a\nb`,
      'leading space': ` ${LINE}`,
      'no data': 'ssh-ed25519',
      'not base64': 'ssh-ed25519 ***',
      'a type inside that is not ed25519': line(wire('ssh-rsa', raw)),
      'a 31-byte key': line(wire('ssh-ed25519', raw.subarray(0, 31))),
      'a 33-byte key': line(wire('ssh-ed25519', new Uint8Array(33))),
      'bytes after the key': line(wire('ssh-ed25519', raw, new Uint8Array([1]))),
      'a length that runs past the data': line(wire('ssh-ed25519', raw).subarray(0, 40)),
      'padding that is not canonical': `${LINE}=`,
      'not a string': 5,
    };
    for (const [name, input] of Object.entries(bad)) assert.throws(() => openSshToRawKey(input), TypeError, name);
  });
});

describe('identityOf: one key, every spelling', () => {
  it('from a raw key, a line or a CryptoKey', async () => {
    const raw = keyBytes();
    const fp = await fingerprint(raw);
    const want = { raw, fingerprint: fp, podId: fingerprintToPodId(fp), openssh: LINE };
    assert.deepEqual(await identityOf(raw), want);
    assert.deepEqual(await identityOf(LINE), want);
    assert.deepEqual(await identityOf(`${LINE} someone`), want);
    const { publicKey } = await generateKeyPair(true);
    const viaKey = await identityOf(publicKey);
    assert.equal(viaKey.podId, await podId(await exportPublicKeyRaw(publicKey)));
    await assert.rejects(identityOf('not a key'), TypeError);
    await assert.rejects(identityOf(new Uint8Array(5)), TypeError);
    await assert.rejects(identityOf(undefined), TypeError);
  });
});

describe('normalizeIdentity: who a call is from, whatever carried it', () => {
  it('gives { username, fingerprint, podId } and derives the one that is missing from the other', async () => {
    const raw = keyBytes();
    const fp = await fingerprint(raw);
    const id = fingerprintToPodId(fp);
    assert.deepEqual(normalizeIdentity({ username: 'alice', fingerprint: fp }), { username: 'alice', fingerprint: fp, podId: id });
    assert.deepEqual(normalizeIdentity({ podId: id }), { username: null, fingerprint: fp, podId: id });
    assert.deepEqual(normalizeIdentity({ username: 'x', fingerprint: fp.toUpperCase(), podId: id }), { username: 'x', fingerprint: fp, podId: id }, 'a fingerprint is lower case');
    assert.deepEqual(normalizeIdentity(undefined), { username: null, fingerprint: null, podId: null });
    assert.deepEqual(normalizeIdentity({ username: 'bob' }), { username: 'bob', fingerprint: null, podId: null });
  });

  it('refuses an identity that names two different keys, and one that is not an identity', () => {
    const a = '00'.repeat(32);
    const b = '11'.repeat(32);
    assert.throws(() => normalizeIdentity({ fingerprint: a, podId: fingerprintToPodId(b) }), TypeError);
    assert.throws(() => normalizeIdentity({ podId: 'not a pod id' }), TypeError);
    assert.throws(() => normalizeIdentity({ fingerprint: 'zz' }), TypeError);
    assert.throws(() => normalizeIdentity('alice'), TypeError);
    assert.throws(() => normalizeIdentity({ username: 5 }), TypeError);
  });

  it('keeps a fingerprint that is not a key hash as the host gave it (a host may name callers its own way) and derives no pod id from it', () => {
    assert.deepEqual(normalizeIdentity({ username: 'u', fingerprint: 'peer-7' }, { strict: false }), { username: 'u', fingerprint: 'peer-7', podId: null });
  });
});

describe('authorizedKeyLine: a line for authorized_keys, and nothing it was not asked for', () => {
  const raw = keyBytes();

  it('writes capabilities and expires as options and the key after them, and a host reads exactly that back', () => {
    const line = authorizedKeyLine(raw, { capabilities: ['exec', 'fs:read', 'gateway:tcp:*.example.com:443'], expires: '2030-01-01T00:00:00Z', comment: 'mesh peer' });
    assert.equal(line, `capabilities="exec,fs:read,gateway:tcp:*.example.com:443",expires="2030-01-01T00:00:00Z" ${LINE} mesh peer`);
    const parsed = parseAuthorizedKeyLine(line);
    assert.deepEqual(parsed.key, raw);
    assert.deepEqual(parsed.permissions.capabilities, ['exec', 'fs:read', 'gateway:tcp:*.example.com:443']);
    assert.equal(parsed.permissions.expires, 1893456000);
  });

  it('takes an OpenSSH line for the key, a Date or milliseconds for expires, and a comma separated string of capabilities', async () => {
    assert.equal(authorizedKeyLine(LINE, { capabilities: 'exec,pty' }), `capabilities="exec,pty" ${LINE}`);
    assert.equal(authorizedKeyLine(`${LINE} old comment`, { capabilities: ['exec'] }), `capabilities="exec" ${LINE}`, 'a comment of the input line is not carried over');
    assert.equal(authorizedKeyLine(raw, { capabilities: ['exec'], expires: new Date(Date.UTC(2030, 0, 1, 0, 0, 0, 999)) }), `capabilities="exec",expires="2030-01-01T00:00:00Z" ${LINE}`);
    assert.equal(authorizedKeyLine(raw, { capabilities: ['exec'], expires: Date.UTC(2030, 0, 1) }), `capabilities="exec",expires="2030-01-01T00:00:00Z" ${LINE}`);
    assert.equal(authorizedKeyLine(raw, { capabilities: ['exec'], expires: '2030-01-01T01:00:00+01:00' }), `capabilities="exec",expires="2030-01-01T00:00:00Z" ${LINE}`, 'an offset is written as UTC');
    const { publicKey } = await generateKeyPair(true);
    assert.equal(authorizedKeyLine(await publicKeyToOpenSsh(publicKey), { capabilities: [] }).startsWith('capabilities="" ssh-ed25519 '), true);
    assert.throws(() => authorizedKeyLine(publicKey, { capabilities: [] }), TypeError, 'a CryptoKey is exported first (export is asynchronous): publicKeyToOpenSsh()');
  });

  it('an empty list is a key that may do nothing, and says so', () => {
    const parsed = parseAuthorizedKeyLine(authorizedKeyLine(raw, { capabilities: [] }));
    assert.deepEqual(parsed.permissions.capabilities, []);
  });

  it('refuses to write a key with no limits unless it is asked to, in words', () => {
    assert.throws(() => authorizedKeyLine(raw), /capabilities/);
    assert.throws(() => authorizedKeyLine(raw, {}), /capabilities/);
    assert.throws(() => authorizedKeyLine(raw, { expires: '2030-01-01T00:00:00Z' }), /capabilities/);
    assert.equal(authorizedKeyLine(raw, { allowFullAccess: true }), LINE);
    assert.equal(authorizedKeyLine(raw, { allowFullAccess: true, expires: '2030-01-01T00:00:00Z' }), `expires="2030-01-01T00:00:00Z" ${LINE}`);
    assert.throws(() => authorizedKeyLine(raw, { allowFullAccess: true, capabilities: ['exec'] }), TypeError, 'two answers to one question');
  });

  it('refuses a capability list a host would not load, naming the entry', () => {
    for (const bad of [['exec', 'teleport'], ['gateway:tcp:host'], [''], ['exec pty'], [5], ['objects:window:fly'], 'exec,,pty', ['*']]) {
      assert.throws(() => authorizedKeyLine(raw, { capabilities: bad }), TypeError, JSON.stringify(bad));
    }
    assert.throws(() => authorizedKeyLine(raw, { capabilities: ['exec', 'teleport'] }), /teleport/);
  });

  it('refuses input that would add an option or a line of its own: quotes, commas, newlines, in capabilities, expires or the comment', () => {
    for (const bad of ['exec" ,permit-pty,x="', 'exec"', 'exec\nssh-ed25519 AAAA', 'exec\\', 'a,b']) {
      // a comma splits a string into entries, so only the entries that are not valid on their own are what is refused
      if (bad === 'a,b') { assert.throws(() => authorizedKeyLine(raw, { capabilities: bad }), TypeError); continue; }
      assert.throws(() => authorizedKeyLine(raw, { capabilities: [bad] }), TypeError, JSON.stringify(bad));
    }
    for (const bad of ['2030-01-01T00:00:00Z",permit-pty,x="', 'tomorrow', '2030-01-01', '2030-01-01t00:00:00z', 1e30, NaN, new Date(NaN), true, '1969-12-31T23:59:59Z']) {
      assert.throws(() => authorizedKeyLine(raw, { capabilities: ['exec'], expires: bad }), TypeError, String(bad));
    }
    for (const bad of ['a\nrestrict ssh-ed25519 AAAA', 'a\rb', 'a\0b']) {
      assert.throws(() => authorizedKeyLine(raw, { capabilities: ['exec'], comment: bad }), TypeError, JSON.stringify(bad));
    }
    assert.throws(() => authorizedKeyLine(raw, { capabilities: ['exec'], comment: 5 }), TypeError);
  });

  it('refuses a key that is not an Ed25519 public key, and an option it does not know', () => {
    assert.throws(() => authorizedKeyLine(new Uint8Array(31), { capabilities: ['exec'] }), TypeError);
    assert.throws(() => authorizedKeyLine('ssh-rsa AAAA', { capabilities: ['exec'] }), TypeError);
    assert.throws(() => authorizedKeyLine(`restrict ${LINE}`, { capabilities: ['exec'] }), TypeError, 'options of an input line are not carried over, they are refused');
    assert.throws(() => authorizedKeyLine(raw, { capabilities: ['exec'], command: 'rm -rf /' }), TypeError, 'an option this builder does not write');
    assert.throws(() => authorizedKeyLine(raw, null), TypeError);
  });

  it('what it writes always reads back to the same grant (the builder checks its own output)', () => {
    for (const capabilities of [[], ['exec'], ['relay', 'pty'], ['unix:/srv/*', 'gateway:udp:*:53'], ['objects:window:get', 'mcp:*', 'rpc:wsh-fs']]) {
      const parsed = parseAuthorizedKeyLine(authorizedKeyLine(raw, { capabilities, comment: 'c' }));
      assert.ok(parsed.permissions, JSON.stringify(parsed));
      assert.deepEqual(parsed.permissions.capabilities, capabilities);
      assert.equal(parsed.permissions.forcedCommand, null);
    }
  });
});
