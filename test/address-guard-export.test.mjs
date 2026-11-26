// test/address-guard-export.test.mjs -- `@johnhenry/wsh/address-guard`: the gateway's destination-address guard as a public entry point
// (the classifier, the policy check, the resolve-once-and-check name helper and the checked TCP and UDP dials). The gateway of
// `@johnhenry/wsh/server` calls these same functions; test/gateway-address-policy.test.mjs and test/gateway-udp.test.mjs drive it.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import dgram from 'node:dgram';
import {
  isPublicAddress, classifyAddress, ADDRESS_CLASSES, checkAddress, resolveChecked, dialChecked, dialUdpChecked, AddressGuardError,
} from '@johnhenry/wsh/address-guard';
import * as gatewayModule from '../src/server/gateway.mjs';
import * as entry from '../src/address-guard.mjs';
import { MSG } from '@johnhenry/wsh';
import { fixture, until } from './gateway-fixture.mjs';

/** [address, class]: every class, IPv4 and IPv6, and the IPv6 forms that carry an IPv4 address. */
const TABLE = [
  // public
  ['8.8.8.8', 'public'], ['1.1.1.1', 'public'], ['93.184.216.34', 'public'], ['172.15.0.1', 'public'], ['172.32.0.1', 'public'],
  ['100.63.255.255', 'public'], ['100.128.0.1', 'public'], ['2606:4700:4700::1111', 'public'], ['2a00:1450:4001:81b::200e', 'public'],
  // unspecified
  ['0.0.0.0', 'unspecified'], ['0.1.2.3', 'unspecified'], ['::', 'unspecified'],
  // loopback
  ['127.0.0.1', 'loopback'], ['127.255.255.254', 'loopback'], ['::1', 'loopback'],
  // private (RFC 1918, and the deprecated IPv6 site-local block)
  ['10.1.2.3', 'private'], ['172.16.0.1', 'private'], ['172.31.255.255', 'private'], ['192.168.1.1', 'private'], ['fec0::1', 'private'],
  // unique-local
  ['fc00::1', 'unique-local'], ['fd00::1', 'unique-local'], ['fd12:3456::1', 'unique-local'], ['fdff:ffff::1', 'unique-local'],
  // link-local
  ['169.254.1.1', 'link-local'], ['169.254.0.1', 'link-local'], ['fe80::1', 'link-local'], ['febf::1', 'link-local'],
  // cloud metadata endpoints (a class of their own, so a caller can say why)
  ['169.254.169.254', 'metadata'], ['169.254.170.2', 'metadata'], ['100.100.100.200', 'metadata'], ['192.0.0.192', 'metadata'],
  ['fd00:ec2::254', 'metadata'], ['::ffff:169.254.169.254', 'metadata'], ['168.63.129.16', 'metadata'],
  // carrier-grade NAT
  ['100.64.0.1', 'carrier-nat'], ['100.127.255.255', 'carrier-nat'],
  // documentation and benchmarking
  ['192.0.2.1', 'documentation'], ['198.51.100.7', 'documentation'], ['203.0.113.9', 'documentation'], ['2001:db8::1', 'documentation'], ['3fff::1', 'documentation'],
  ['198.18.0.1', 'benchmarking'], ['198.19.255.255', 'benchmarking'], ['2001:2::1', 'benchmarking'],
  // multicast
  ['224.0.0.1', 'multicast'], ['239.1.1.1', 'multicast'], ['ff02::1', 'multicast'], ['ff0e::1', 'multicast'],
  // reserved (everything else that is not global unicast)
  ['240.0.0.1', 'reserved'], ['255.255.255.255', 'reserved'], ['192.0.0.8', 'reserved'], ['192.88.99.1', 'reserved'], ['100::1', 'reserved'],
  ['5f00::1', 'reserved'], ['1::1', 'reserved'], ['2001:1::1', 'reserved'], ['::2', 'reserved'],
  // IPv4-compatible (deprecated): refused whatever it wraps
  ['::127.0.0.1', 'reserved'], ['::8.8.8.8', 'reserved'],
  // IPv4-mapped IPv6: the class of the IPv4 address inside
  ['::ffff:10.0.0.1', 'private'], ['::ffff:a00:1', 'private'], ['::ffff:127.0.0.1', 'loopback'], ['::ffff:7f00:1', 'loopback'],
  ['0:0:0:0:0:ffff:7f00:1', 'loopback'], ['::ffff:192.168.0.1', 'private'], ['::ffff:100.64.0.1', 'carrier-nat'], ['::ffff:0.0.0.0', 'unspecified'],
  ['::ffff:224.0.0.1', 'multicast'], ['::ffff:8.8.8.8', 'public'],
  // NAT64 64:ff9b::/96: the class of the IPv4 address inside (a translator would dial it); the local-use /48 is reserved
  ['64:ff9b::7f00:1', 'loopback'], ['64:ff9b::127.0.0.1', 'loopback'], ['64:ff9b::a00:1', 'private'], ['64:ff9b::192.168.1.1', 'private'],
  ['64:ff9b::a9fe:a9fe', 'metadata'], ['64:ff9b::808:808', 'public'], ['64:ff9b:1::1', 'reserved'], ['64:ff9b:1::808:808', 'reserved'],
  // 6to4 2002::/16: the class of the IPv4 address inside
  ['2002:7f00:1::', 'loopback'], ['2002:a00:1::1', 'private'], ['2002:c0a8:101::1', 'private'], ['2002:a9fe:a9fe::1', 'metadata'], ['2002:808:808::1', 'public'],
  // Teredo 2001::/32: always refused, whatever its (obfuscated) server and client addresses are
  ['2001::1', 'teredo'], ['2001:0:4136:e378:8000:63bf:3fff:fdd2', 'teredo'], ['2001:0:5ef5:79fd:0:0:0:1', 'teredo'],
];

describe('classifyAddress and isPublicAddress: every class, IPv4 and IPv6', () => {
  for (const [address, cls] of TABLE) {
    it(`${address} is ${cls}`, () => {
      assert.equal(classifyAddress(address), cls);
      assert.equal(isPublicAddress(address), cls === 'public');
    });
  }

  it('every class in the table is in ADDRESS_CLASSES, and every class has an example', () => {
    assert.deepEqual([...ADDRESS_CLASSES].sort(), [...new Set([...TABLE.map(([, c]) => c), 'invalid'])].sort());
    assert.throws(() => { ADDRESS_CLASSES.push('x'); }, TypeError);
  });

  it('what is not an address is "invalid" and never public: names, numbers in other spellings, zone ids, non-strings', () => {
    for (const a of ['', 'localhost', 'example.com', '1.2.3', '1.2.3.4.5', '256.1.1.1', '01.2.3.4', '2130706433', '0x7f.0.0.1', '1.2.3.4/8', 'fe80::1%eth0', ':::', '1::2::3', 'g::1', '12345::1', undefined, null, 5, {}]) {
      assert.equal(classifyAddress(a), 'invalid', String(a));
      assert.equal(isPublicAddress(a), false, String(a));
    }
  });

  it('upper case, surrounding whitespace and the leading-zero group forms are read as the address they are', () => {
    assert.equal(classifyAddress('FD00::1'), 'unique-local');
    assert.equal(classifyAddress('::FFFF:10.0.0.1'), 'private');
    assert.equal(classifyAddress(' 8.8.8.8 '), 'public');
    assert.equal(classifyAddress('0:0:0:0:0:0:0:1'), 'loopback');
    assert.equal(classifyAddress('0000:0000:0000:0000:0000:ffff:0a00:0001'), 'private');
  });

  it('the pure classifier is its own module with no Node import, and the entry re-exports it (one implementation)', async () => {
    const pure = await import('../src/address-class.mjs');
    assert.equal(entry.classifyAddress, pure.classifyAddress);
    assert.equal(entry.isPublicAddress, pure.isPublicAddress);
    const guard = await import('../src/server/address-guard.mjs');
    assert.equal(guard.isPublicAddress, pure.isPublicAddress);
  });
});

// The vectors the Rust wsh-server runs too (crates/wsh-core/src/gateway/address_class.rs): the two implementations agree address by address.
const VECTORS = JSON.parse(readFileSync(new URL('../spec/address-class.vectors.json', import.meta.url), 'utf8'));

describe('spec/address-class.vectors.json: the vectors shared with the Rust server', () => {
  it('has a version, and names exactly the classes this implementation can return', () => {
    assert.equal(VECTORS.version, 1);
    assert.deepEqual([...VECTORS.classes], [...ADDRESS_CLASSES]);
  });

  it('is published as a package file, and every class has at least one vector in it', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    assert.ok(pkg.files.includes('spec/*.json'));
    const seen = new Set(VECTORS.groups.flatMap((g) => g.vectors.map((v) => v.class)));
    assert.deepEqual([...seen].sort(), [...ADDRESS_CLASSES].sort());
  });

  for (const group of VECTORS.groups) {
    for (const v of group.vectors) {
      it(`${group.name}: ${JSON.stringify(v.address)} is ${v.class}`, () => {
        assert.equal(classifyAddress(v.address), v.class);
        assert.equal(isPublicAddress(v.address), v.public);
        assert.equal(v.public, v.class === 'public');
      });
    }
  }
});

describe('checkAddress: the policy (allowPrivate, allow, deny)', () => {
  it('a public address passes, a non-public one is refused with its class, by default', () => {
    assert.deepEqual(checkAddress('8.8.8.8'), { permitted: true, class: 'public' });
    assert.deepEqual(checkAddress('10.0.0.1'), { permitted: false, class: 'private', reason: 'class' });
    assert.deepEqual(checkAddress('not an address'), { permitted: false, class: 'invalid', reason: 'class' });
  });

  it('allowPrivate: true lets the private-network classes through, and nothing else', () => {
    for (const a of ['10.0.0.1', '127.0.0.1', '::1', '169.254.1.1', 'fe80::1', 'fd00::1', '100.64.0.1', '::ffff:10.0.0.1']) {
      assert.equal(checkAddress(a, { allowPrivate: true }).permitted, true, a);
    }
    // unspecified (0.0.0.0 connects to the host itself), multicast, reserved, documentation, Teredo and a bad address stay refused.
    for (const a of ['0.0.0.0', '::', '224.0.0.1', 'ff02::1', '240.0.0.1', '192.0.2.1', '2001::1', 'nope']) {
      assert.equal(checkAddress(a, { allowPrivate: true }).permitted, false, a);
    }
  });

  it('allowPrivate: true does NOT open the cloud-metadata addresses: only an explicit allow entry does', () => {
    for (const a of ['169.254.169.254', 'fd00:ec2::254', '::ffff:169.254.169.254', '100.100.100.200']) {
      assert.deepEqual(checkAddress(a, { allowPrivate: true }), { permitted: false, class: 'metadata', reason: 'class' }, a);
    }
    assert.equal(checkAddress('169.254.169.254', { allowPrivate: true, allow: ['169.254.169.254'] }).permitted, true);
  });

  it('an allow list of CIDRs and addresses permits exactly those, whatever their class; a mapped address is tested as the IPv4 inside', () => {
    const policy = { allow: ['10.0.0.0/8', '127.0.0.1', 'fd00::/8'] };
    assert.equal(checkAddress('10.9.9.9', policy).permitted, true);
    assert.equal(checkAddress('::ffff:10.1.1.1', policy).permitted, true);
    assert.equal(checkAddress('127.0.0.1', policy).permitted, true);
    assert.equal(checkAddress('fd12::1', policy).permitted, true);
    assert.equal(checkAddress('127.0.0.2', policy).permitted, false);
    assert.equal(checkAddress('192.168.0.1', policy).permitted, false);
    assert.equal(checkAddress('fe80::1', policy).permitted, false);
    // an allow entry for an IPv4 block does not open the NAT64 or 6to4 form of the same address
    assert.equal(checkAddress('64:ff9b::a00:1', policy).permitted, false);
    assert.equal(checkAddress('2002:a00:1::1', policy).permitted, false);
  });

  it('a deny list refuses even a public address, and wins over allow and allowPrivate', () => {
    assert.deepEqual(checkAddress('8.8.8.8', { deny: ['8.8.8.0/24'] }), { permitted: false, class: 'public', reason: 'deny' });
    assert.equal(checkAddress('10.0.0.1', { allowPrivate: true, deny: ['10.0.0.0/8'] }).permitted, false);
    assert.equal(checkAddress('10.0.0.1', { allow: ['10.0.0.1'], deny: ['10.0.0.1'] }).permitted, false);
    assert.equal(checkAddress('10.0.0.1', { allowPrivate: true, deny: ['10.0.0.0/8'] }).reason, 'deny');
    assert.equal(checkAddress('9.9.9.9', { deny: ['8.8.8.0/24'] }).permitted, true);
    // the wrapped forms of a denied IPv4 block are denied too
    for (const a of ['::ffff:8.8.8.8', '64:ff9b::808:808', '2002:808:808::1']) {
      assert.deepEqual(checkAddress(a, { deny: ['8.8.8.0/24'] }), { permitted: false, class: 'public', reason: 'deny' }, a);
    }
    assert.equal(checkAddress('2606:4700:4700::1111', { deny: ['2606:4700::/32'] }).permitted, false);
  });

  it('a bad policy is a TypeError, not a silently open check', () => {
    assert.throws(() => checkAddress('8.8.8.8', { allow: ['nope'] }), TypeError);
    assert.throws(() => checkAddress('8.8.8.8', { deny: ['10.0.0.0/33'] }), TypeError);
    assert.throws(() => checkAddress('8.8.8.8', { allow: '10.0.0.0/8' }), TypeError);
    assert.throws(() => checkAddress('8.8.8.8', { allowPrivate: 'yes' }), TypeError);
  });
});

/** A resolver double: answers the first call with `first`, every later call with `later`, and counts the calls. */
function rebinding(first, later) {
  const calls = [];
  const lookup = async (name, o) => { calls.push({ name, ...o }); return (calls.length === 1 ? first : later).map((address) => ({ address, family: address.includes(':') ? 6 : 4 })); };
  return { lookup, calls };
}

describe('resolveChecked: a name is resolved once and only the permitted answers come back', () => {
  it('returns the permitted addresses with their family and class, in resolver order', async () => {
    const r = rebinding(['8.8.8.8', '2606:4700:4700::1111'], []);
    const out = await resolveChecked('dual.test', { lookup: r.lookup });
    assert.deepEqual(out, [{ address: '8.8.8.8', family: 4, class: 'public' }, { address: '2606:4700:4700::1111', family: 6, class: 'public' }]);
    assert.equal(r.calls.length, 1);
  });

  it('a name with mixed public and private answers: the private ones are dropped (default), or the whole name is refused (refuseMixed)', async () => {
    const r = rebinding(['10.0.0.5', '93.184.216.34', '169.254.169.254', '::1'], []);
    assert.deepEqual((await resolveChecked('mixed.test', { lookup: r.lookup })).map((a) => a.address), ['93.184.216.34']);
    const r2 = rebinding(['10.0.0.5', '93.184.216.34'], []);
    await assert.rejects(resolveChecked('mixed.test', { lookup: r2.lookup, refuseMixed: true }), (e) => {
      assert.ok(e instanceof AddressGuardError);
      assert.equal(e.code, 'ADDRESS_REFUSED');
      assert.deepEqual(e.refused, [{ address: '10.0.0.5', class: 'private' }]);
      return true;
    });
  });

  it('every answer refused is ADDRESS_REFUSED, naming each refused address and why', async () => {
    const r = rebinding(['10.0.0.5', '169.254.169.254'], []);
    await assert.rejects(resolveChecked('internal.test', { lookup: r.lookup }), (e) => {
      assert.ok(e instanceof AddressGuardError);
      assert.equal(e.code, 'ADDRESS_REFUSED');
      assert.deepEqual(e.refused, [{ address: '10.0.0.5', class: 'private' }, { address: '169.254.169.254', class: 'metadata' }]);
      assert.deepEqual(e.refusedAddresses, ['10.0.0.5', '169.254.169.254']);
      assert.match(e.message, /private|metadata/);
      return true;
    });
  });

  it('allowPrivate, allow and deny apply to the answers', async () => {
    const answers = ['10.0.0.5', '192.168.1.1', '8.8.8.8'];
    assert.deepEqual((await resolveChecked('x.test', { lookup: rebinding(answers, []).lookup, allowPrivate: true })).map((a) => a.address), answers);
    assert.deepEqual((await resolveChecked('x.test', { lookup: rebinding(answers, []).lookup, allow: ['10.0.0.0/8'] })).map((a) => a.address), ['10.0.0.5', '8.8.8.8']);
    assert.deepEqual((await resolveChecked('x.test', { lookup: rebinding(answers, []).lookup, allowPrivate: true, deny: ['192.168.0.0/16', '8.8.8.8'] })).map((a) => a.address), ['10.0.0.5']);
  });

  it('an IP literal is checked as it is, with no lookup', async () => {
    const r = rebinding([], []);
    await assert.rejects(resolveChecked('10.0.0.1', { lookup: r.lookup }), (e) => e.code === 'ADDRESS_REFUSED');
    assert.deepEqual(await resolveChecked('8.8.8.8', { lookup: r.lookup }), [{ address: '8.8.8.8', family: 4, class: 'public' }]);
    assert.deepEqual(await resolveChecked('::ffff:8.8.8.8', { lookup: r.lookup }), [{ address: '::ffff:8.8.8.8', family: 6, class: 'public' }]);
    assert.equal(r.calls.length, 0);
  });

  it('family 4 or 6 is asked of the resolver, and an answer of the other family is dropped', async () => {
    const r = rebinding(['8.8.8.8', '2606:4700:4700::1111'], []);
    const out = await resolveChecked('dual.test', { lookup: r.lookup, family: 6 });
    assert.equal(r.calls[0].family, 6);
    assert.deepEqual(out.map((a) => a.address), ['2606:4700:4700::1111']);
    await assert.rejects(resolveChecked('dual.test', { lookup: rebinding(['8.8.8.8'], []).lookup, family: 6 }), (e) => e.code === 'NAME_NOT_FOUND');
    await assert.rejects(resolveChecked('x', { family: 5 }), TypeError);
  });

  it('a resolver that finds nothing is NAME_NOT_FOUND; one that never answers is TIMEOUT; an aborted signal is ABORTED', async () => {
    await assert.rejects(resolveChecked('gone.test', { lookup: async () => [] }), (e) => e.code === 'NAME_NOT_FOUND');
    await assert.rejects(resolveChecked('gone.test', { lookup: async () => { const e = new Error('x'); e.code = 'ENOTFOUND'; throw e; } }), (e) => e.code === 'NAME_NOT_FOUND');
    await assert.rejects(resolveChecked('slow.test', { lookup: () => new Promise(() => {}), timeoutMs: 30 }), (e) => e.code === 'TIMEOUT');
    const ac = new AbortController();
    const p = resolveChecked('slow.test', { lookup: () => new Promise(() => {}), signal: ac.signal });
    ac.abort();
    await assert.rejects(p, (e) => e.code === 'ABORTED');
    await assert.rejects(resolveChecked('slow.test', { lookup: async () => ['8.8.8.8'], signal: AbortSignal.abort() }), (e) => e.code === 'ABORTED');
  });
});

describe('dialChecked: connect to the address that was checked, never to the name', () => {
  const servers = [];
  afterEach(async () => { for (const s of servers.splice(0)) s.close(); });
  const echo = () => new Promise((resolve) => {
    const s = net.createServer((c) => { c.on('data', (d) => c.write(Buffer.concat([Buffer.from('echo:'), d]))); c.on('error', () => {}); });
    s.listen(0, '127.0.0.1', () => { servers.push(s); resolve(s.address().port); });
  });
  const reply = (socket) => new Promise((resolve, reject) => { socket.once('data', (d) => resolve(String(d))); socket.once('error', reject); socket.write('hi'); });

  it('rebinding: a resolver that answers a public address and then a private one is asked once, and the dial goes to the address it checked', async () => {
    const port = await echo();
    // The first (and only) answer is the address the guard checks; the second, which a second lookup would get, is private.
    const r = rebinding(['127.0.0.1'], ['10.0.0.1']);
    const { socket, address, family, class: cls } = await dialChecked('rebind.test', port, { lookup: r.lookup, allow: ['127.0.0.1'] });
    assert.equal(r.calls.length, 1, 'the name was resolved once');
    assert.equal(address, '127.0.0.1');
    assert.equal(family, 4);
    assert.equal(cls, 'loopback');
    assert.equal(socket.remoteAddress, '127.0.0.1', 'the socket is connected to the checked address');
    assert.equal(await reply(socket), 'echo:hi');
    socket.destroy();
  });

  it('a name that resolves to a private address is refused, and nothing is dialled', async () => {
    const port = await echo();
    let dialled = 0;
    servers[0].on('connection', () => { dialled++; });
    const r = rebinding(['127.0.0.1'], ['127.0.0.1']);
    await assert.rejects(dialChecked('loop.test', port, { lookup: r.lookup }), (e) => e instanceof AddressGuardError && e.code === 'ADDRESS_REFUSED' && e.refused[0].class === 'loopback');
    await assert.rejects(dialChecked('127.0.0.1', port), (e) => e.code === 'ADDRESS_REFUSED');
    await assert.rejects(dialChecked('localhost', port), (e) => e.code === 'ADDRESS_REFUSED');
    assert.equal(dialled, 0);
  });

  it('a name with mixed answers dials the permitted one only', async () => {
    const port = await echo();
    const r = rebinding(['10.255.255.1', '169.254.169.254', '127.0.0.1'], []);
    const { socket, address } = await dialChecked('mixed.test', port, { lookup: r.lookup, allow: ['127.0.0.1'] });
    assert.equal(address, '127.0.0.1');
    socket.destroy();
  });

  it('allowPrivate: true dials loopback; the deny list refuses it again', async () => {
    const port = await echo();
    const { socket } = await dialChecked('127.0.0.1', port, { allowPrivate: true });
    assert.equal(await reply(socket), 'echo:hi');
    socket.destroy();
    await assert.rejects(dialChecked('127.0.0.1', port, { allowPrivate: true, deny: ['127.0.0.0/8'] }), (e) => e.code === 'ADDRESS_REFUSED');
  });

  it('tries the next permitted address when one refuses the connection', async () => {
    const port = await echo();
    // 127.0.0.1:<port> has the listener; ::1 has none on this port (or is absent): the connect to ::1 fails, then 127.0.0.1 answers.
    const r = rebinding(['::1', '127.0.0.1'], []);
    const { socket, address } = await dialChecked('two.test', port, { lookup: r.lookup, allowPrivate: true });
    assert.equal(address, '127.0.0.1');
    socket.destroy();
  });

  it('a refused connection is CONNECTION_REFUSED, naming nothing but the code', async () => {
    const port = await echo();
    servers.pop().close();
    await assert.rejects(dialChecked('127.0.0.1', port, { allowPrivate: true }), (e) => e instanceof AddressGuardError && e.code === 'CONNECTION_REFUSED');
  });

  it('a connect that does not complete is TIMEOUT; an abort is ABORTED and leaves no socket open', async () => {
    // 192.0.2.1 is documentation space: allow it explicitly so the guard passes and the connect itself is what is bounded.
    await assert.rejects(dialChecked('192.0.2.1', 9, { allow: ['192.0.2.1'], timeoutMs: 50 }), (e) => e instanceof AddressGuardError && (e.code === 'TIMEOUT' || e.code === 'UNREACHABLE'));
    const ac = new AbortController();
    const p = dialChecked('192.0.2.1', 9, { allow: ['192.0.2.1'], signal: ac.signal });
    ac.abort();
    await assert.rejects(p, (e) => e.code === 'ABORTED');
  });

  it('a bad port is a TypeError', async () => {
    await assert.rejects(dialChecked('8.8.8.8', 0), TypeError);
    await assert.rejects(dialChecked('8.8.8.8', 70000), TypeError);
    await assert.rejects(dialChecked('', 80), TypeError);
  });
});

describe('dialUdpChecked: a datagram socket connected to the checked address', () => {
  const sockets = [];
  afterEach(() => { for (const s of sockets.splice(0)) try { s.close(); } catch { /* closed */ } });
  const bound = (type = 'udp4', host = '127.0.0.1') => new Promise((resolve) => { const s = dgram.createSocket(type); sockets.push(s); s.bind(0, host, () => resolve(s)); });
  const nextMessage = (s, ms = 300) => new Promise((resolve) => { const t = setTimeout(() => { s.off('message', on); resolve(null); }, ms); const on = (d, rinfo) => { clearTimeout(t); resolve({ data: String(d), rinfo }); }; s.once('message', on); });

  it('refuses a private, loopback or metadata destination, and a name that resolves to one', async () => {
    await assert.rejects(dialUdpChecked('127.0.0.1', 5353), (e) => e instanceof AddressGuardError && e.code === 'ADDRESS_REFUSED');
    await assert.rejects(dialUdpChecked('169.254.169.254', 53), (e) => e.code === 'ADDRESS_REFUSED' && e.refused[0].class === 'metadata');
    const r = rebinding(['10.0.0.1'], ['8.8.8.8']);
    await assert.rejects(dialUdpChecked('dns.test', 53, { lookup: r.lookup }), (e) => e.code === 'ADDRESS_REFUSED');
  });

  it('resolves once and connects the socket to the checked address; reports the address dialled', async () => {
    const server = await bound();
    const r = rebinding(['127.0.0.1'], ['10.0.0.1']);
    const { socket, address, family, class: cls } = await dialUdpChecked('udp.test', server.address().port, { lookup: r.lookup, allow: ['127.0.0.1'] });
    sockets.push(socket);
    assert.equal(r.calls.length, 1);
    assert.equal(address, '127.0.0.1');
    assert.equal(family, 4);
    assert.equal(cls, 'loopback');
    assert.equal(socket.remoteAddress().address, '127.0.0.1');
    assert.equal(socket.remoteAddress().port, server.address().port);
    const got = nextMessage(server);
    socket.send('ping');
    const m = await got;
    assert.equal(m.data, 'ping');
    const back = nextMessage(socket);
    server.send('pong', m.rinfo.port, m.rinfo.address);
    assert.equal((await back).data, 'pong');
  });

  it('a reply from any other address or port than the one dialled is dropped, not delivered', async () => {
    const server = await bound();
    const stranger = await bound();
    const { socket } = await dialUdpChecked('127.0.0.1', server.address().port, { allowPrivate: true });
    sockets.push(socket);
    const got = nextMessage(server);
    socket.send('ping');
    const m = await got;
    const heard = [];
    socket.on('message', (d) => heard.push(String(d)));
    stranger.send('from a stranger', m.rinfo.port, m.rinfo.address); // another port: the socket is connect()ed, the kernel drops it
    server.send('from the server', m.rinfo.port, m.rinfo.address);
    await new Promise((resolve) => { const t = setTimeout(resolve, 200); socket.once('message', () => { clearTimeout(t); setTimeout(resolve, 100); }); });
    assert.deepEqual(heard, ['from the server']);
  });

  it('an IPv6 destination gets an IPv6 socket', async (t) => {
    const server = await bound('udp6', '::1').catch(() => null);
    if (!server) { t.skip('no IPv6 loopback'); return; }
    const { socket, family } = await dialUdpChecked('::1', server.address().port, { allowPrivate: true });
    sockets.push(socket);
    assert.equal(family, 6);
    const got = nextMessage(server);
    socket.send('v6');
    assert.equal((await got).data, 'v6');
  });

  it('an aborted signal and a bad port are refused', async () => {
    await assert.rejects(dialUdpChecked('8.8.8.8', 53, { signal: AbortSignal.abort() }), (e) => e.code === 'ABORTED');
    await assert.rejects(dialUdpChecked('8.8.8.8', 0), TypeError);
  });
});

describe('the gateway calls the exported functions (one implementation)', () => {
  it('@johnhenry/wsh/server\'s gateway module re-uses the guard rather than a copy', () => {
    assert.equal(gatewayModule.resolveChecked, undefined, 'the gateway keeps no resolver of its own');
    assert.equal(typeof gatewayModule.gatewayPolicy, 'function');
    // The gateway's policy for a name and an explicit literal is the guard's own check.
    const cfg = { allowPrivate: [{ v: 4, bytes: Uint8Array.of(10, 0, 0, 0), bits: 8 }] };
    assert.equal(gatewayModule.addressPermitted(cfg, '10.1.1.1'), true);
    assert.equal(gatewayModule.addressPermitted(cfg, '127.0.0.1'), false);
    assert.equal(gatewayModule.addressPermitted(cfg, '127.0.0.1', { explicitLiteral: '127.0.0.1' }), true);
    assert.equal(gatewayModule.addressPermitted(cfg, '169.254.169.254'), false);
  });

  it('through a real gateway with allow ["*"]: the metadata endpoint of a platform, a Teredo address and the wrapped private forms are refused (POLICY_DENIED), a documented table row each', async () => {
    const fx = fixture();
    try {
      const { client, inbox } = await fx.setup({ allow: ['*'] });
      const hosts = ['168.63.129.16', '169.254.169.254', '100.100.100.200', '2001:0:4136:e378:8000:63bf:3fff:fdd2', '64:ff9b::a00:1', '2002:a00:1::1', '::ffff:10.0.0.1'];
      for (const [i, host] of hosts.entries()) {
        await client.sendControl({ type: MSG.OPEN_TCP, gateway_id: i + 1, host, port: 80 });
        const f = await until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === i + 1), `GatewayFail for ${host}`);
        assert.equal(f.code, 4, `${host} -> POLICY_DENIED`);
      }
    } finally { await fx.teardown(); }
  });
});
