// test/server-password-hash.test.mjs -- `hashPassword` / `verifyPassword` / `passwordVerifier` of
// `@johnhenry/wsh/server`: scrypt (node:crypto) PHC strings with a per-user salt, a constant-time comparison,
// the same decoy work for an unknown user, and what happens to an old unsalted `sha256:` entry.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createWshServer, hashPassword, verifyPassword, passwordVerifier } from '@johnhenry/wsh/server';
import { WshClient } from '@johnhenry/wsh';

// Small cost keeps the suite quick; the default is exercised once below.
const cheap = { ln: 10 };

describe('hashPassword / verifyPassword', () => {
  it('writes a PHC scrypt string with a fresh salt each time and no trace of the password', async () => {
    const a = await hashPassword('correct horse', cheap);
    const b = await hashPassword('correct horse', cheap);
    assert.match(a, /^\$scrypt\$ln=10,r=8,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
    assert.notEqual(a, b, 'a per-user random salt');
    assert.ok(!a.includes('correct'));
  });

  it('the default cost is memory-hard (64 MiB) and verifies', async () => {
    const h = await hashPassword('pw');
    assert.match(h, /^\$scrypt\$ln=16,r=8,p=1\$/);
    assert.equal(await verifyPassword('pw', h), true);
    assert.equal(await verifyPassword('pw2', h), false);
  });

  it('verifies the right password and refuses a wrong one', async () => {
    const h = await hashPassword('s3cret', cheap);
    assert.equal(await verifyPassword('s3cret', h), true);
    assert.equal(await verifyPassword('s3cre', h), false);
    assert.equal(await verifyPassword('', h), false);
    assert.equal(await verifyPassword(123, h), false);
  });

  it('refuses what is not a usable hash instead of throwing', async () => {
    const good = await hashPassword('x', cheap);
    const [, , params, salt, hash] = good.split('$');
    for (const bad of [
      '', 'plain', null, undefined, 42,
      `$argon2id$v=19$m=19456,t=2,p=1$${salt}$${hash}`, // another algorithm: not handled here
      `$scrypt$${params}$${salt}`, // missing the hash
      `$scrypt$${params}$${salt}$${hash.slice(2)}`, // a hash of the wrong length: timingSafeEqual would throw
      `$scrypt$ln=10,r=8$${salt}$${hash}`, // a missing parameter
      `$scrypt$ln=10,r=8,p=1,x=1$${salt}$${hash}`, // an unknown parameter
      `$scrypt$ln=30,r=8,p=1$${salt}$${hash}`, // a cost that would exhaust memory
      `$scrypt$ln=10,r=8,p=1$!!$${hash}`, // not base64
    ]) assert.equal(await verifyPassword('x', bad), false, String(bad));
  });

  it('compares with timingSafeEqual (no early exit on the first differing byte)', async () => {
    const src = await import('node:fs/promises').then((fs) => fs.readFile(new URL('../src/server/password.mjs', import.meta.url), 'utf8'));
    assert.match(src, /timingSafeEqual/);
    assert.doesNotMatch(src, /(derived|key|hash)\s*(===|==)\s*(expected|stored)/);
  });
});

describe('passwordVerifier', () => {
  it('serves a table of users and refuses a wrong password, an unknown user and a prototype key', async () => {
    const hashes = { alice: await hashPassword('alice-pw', cheap), bob: await hashPassword('bob-pw', cheap) };
    const check = passwordVerifier(hashes);
    assert.equal(await check('alice', 'alice-pw'), true);
    assert.equal(await check('bob', 'bob-pw'), true);
    assert.equal(await check('alice', 'bob-pw'), false);
    assert.equal(await check('mallory', 'alice-pw'), false);
    assert.equal(await check('__proto__', 'x'), false);
    assert.equal(await check('constructor', 'x'), false);
    assert.equal(await check('alice', { not: 'a string' }), false);
  });

  it('accepts a Map and a lookup function', async () => {
    const h = await hashPassword('pw', cheap);
    assert.equal(await passwordVerifier(new Map([['u', h]]))('u', 'pw'), true);
    assert.equal(await passwordVerifier((user) => (user === 'u' ? h : undefined))('u', 'pw'), true);
    assert.equal(await passwordVerifier((user) => (user === 'u' ? h : undefined))('v', 'pw'), false);
  });

  it('does the same hashing work for an unknown user as for a wrong password', async () => {
    const h = await hashPassword('pw', cheap);
    const { scrypt: real } = await import('node:crypto');
    let calls = 0;
    const scrypt = (pw, salt, len, opts) => {
      calls++;
      return new Promise((res, rej) => real(pw, salt, len, opts, (e, k) => (e ? rej(e) : res(k))));
    };
    const check = passwordVerifier({ alice: h }, { scrypt });
    await check('alice', 'wrong');
    const afterKnown = calls;
    await check('mallory', 'wrong');
    assert.equal(afterKnown, 1);
    assert.equal(calls - afterKnown, 1, 'one derivation for an unknown user too, so the cost does not say whether the user exists');
  });

  it('refuses an old unsalted sha256 entry by default, naming the user and never the hash', async () => {
    const legacy = `sha256:${createHash('sha256').update('old').digest('hex')}`;
    const warnings = [];
    const check = passwordVerifier({ carol: legacy, dave: await hashPassword('new', cheap) }, { onWarn: (m) => warnings.push(m) });
    assert.equal(await check('carol', 'old'), false, 'refused although the password is right');
    assert.equal(await check('dave', 'new'), true);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /carol/);
    assert.match(warnings[0], /hashPassword/);
    assert.ok(!warnings[0].includes(legacy) && !warnings[0].includes(legacy.slice(7)), 'the hash is not logged');
  });

  it('keeps an unsalted entry working with allowLegacySha256, with a warning that names the user', async () => {
    const legacy = `sha256:${createHash('sha256').update('old').digest('hex')}`;
    const warnings = [];
    const check = passwordVerifier({ carol: legacy }, { allowLegacySha256: true, onWarn: (m) => warnings.push(m) });
    assert.equal(await check('carol', 'old'), true);
    assert.equal(await check('carol', 'older'), false);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /carol/);
    assert.ok(!warnings[0].includes(legacy.slice(7)));
  });

  it('refuses an entry that is neither, and says which user', async () => {
    const warnings = [];
    const check = passwordVerifier({ erin: 'hunter2' }, { onWarn: (m) => warnings.push(m) });
    assert.equal(await check('erin', 'hunter2'), false, 'a plain-text entry never matches');
    assert.match(warnings[0], /erin/);
    assert.ok(!warnings[0].includes('hunter2'));
  });

  it('is the auth.password of a server: a login with the right password works, a wrong one is refused', async () => {
    const check = passwordVerifier({ alice: await hashPassword('right', cheap) });
    const server = createWshServer({ auth: { password: check, rateLimit: { failureDelayMs: 0 } }, exec: true });
    const { port } = await server.listen();
    try {
      const { stdout } = await WshClient.exec(`ws://127.0.0.1:${port}`, 'echo hi', { username: 'alice', password: 'right', timeout: 5000 });
      assert.match(new TextDecoder().decode(stdout), /hi/);
      await assert.rejects(new WshClient().connect(`ws://127.0.0.1:${port}`, { username: 'alice', password: 'wrong', timeout: 5000 }));
    } finally { await server.close(); }
  });
});
