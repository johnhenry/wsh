// test/gateway-address-policy.test.mjs -- the gateway's destination policy is applied to the
// address a name resolves to (resolved once, connected to as checked), not only to the name the client sent.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import dnsPromises from 'node:dns/promises';
import { createWshServer } from '@johnhenry/wsh/server';
import { MSG } from '@johnhenry/wsh';
import { fixture, until, sleep, listen } from './gateway-fixture.mjs';

describe('gateway: the resolved address is checked', () => {
  const fx = fixture();
  const realLookup = dnsPromises.lookup;
  afterEach(async () => { dnsPromises.lookup = realLookup; await fx.teardown(); });

  /** Make `name` resolve to the given answers (one list per call; the last repeats), counting the calls. */
  function stubDns(table) {
    const calls = [];
    dnsPromises.lookup = async (name, opts) => {
      if (!Object.hasOwn(table, name)) return realLookup(name, opts);
      calls.push(name);
      const list = table[name];
      const answers = Array.isArray(list[0]) ? list[Math.min(calls.filter((c) => c === name).length - 1, list.length - 1)] : list;
      return answers.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
    };
    return calls;
  }
  const failOf = (inbox, id) => until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === id), `GatewayFail ${id}`);
  const open = (client, id, host, port) => client.sendControl({ type: MSG.OPEN_TCP, gateway_id: id, host, port });

  it('refuses an allowed name that resolves to a loopback, private, link-local or wrapped address, after ONE lookup', async () => {
    const echoPort = await fx.echoServer();
    const answers = {
      'loop.test': ['127.0.0.1'], 'priv.test': ['10.1.2.3'], 'meta.test': ['169.254.169.254'], 'ula.test': ['fd00::1'],
      'mapped.test': ['::ffff:127.0.0.1'], 'nat64.test': ['64:ff9b::7f00:1'], 'sixtofour.test': ['2002:7f00:1::'], 'mixed.test': ['10.0.0.1', '192.168.0.1', '::1'],
    };
    const calls = stubDns(answers);
    const { client, inbox } = await fx.setup({ allow: ['*'] });
    let id = 1;
    for (const name of Object.keys(answers)) {
      await open(client, id, name, echoPort);
      const f = await failOf(inbox, id);
      assert.equal(f.code, 4, `${name} -> POLICY_DENIED`);
      id++;
    }
    assert.equal(inbox.some((m) => m.type === MSG.GATEWAY_OK), false);
    assert.equal(calls.length, Object.keys(answers).length, 'each name is looked up exactly once');
  });

  it('connects to the address it checked: a name whose second answer would be private never gets a second lookup', async () => {
    const echoPort = await fx.echoServer();
    // First answer: loopback (explicitly permitted below). A second lookup would say 10.0.0.9 -- the connect must not use it.
    const calls = stubDns({ 'flip.test': [['127.0.0.1'], ['10.0.0.9']] });
    const { client, inbox } = await fx.setup({ allow: ['flip.test'], allowPrivate: ['127.0.0.1'] });
    await open(client, 1, 'flip.test', echoPort);
    const ok = await until(() => inbox.find((m) => m.type === MSG.GATEWAY_OK), 'GatewayOk');
    assert.equal(ok.resolved_addr, '127.0.0.1');
    await client.sendControl({ type: MSG.GATEWAY_DATA, gateway_id: 1, data: new TextEncoder().encode('x') });
    const d = await until(() => inbox.find((m) => m.type === MSG.GATEWAY_DATA), 'echo');
    assert.equal(new TextDecoder().decode(d.data), 'echo:x');
    assert.equal(calls.length, 1);
  });

  it('a name that rebinds from public to private between requests is checked afresh each time', async () => {
    const echoPort = await fx.echoServer();
    stubDns({ 'rebind.test': [['127.0.0.1']] });
    const { client, inbox } = await fx.setup({ allow: ['rebind.test'] });
    await open(client, 1, 'rebind.test', echoPort);
    assert.equal((await failOf(inbox, 1)).code, 4);
    await open(client, 2, 'rebind.test', echoPort);
    assert.equal((await failOf(inbox, 2)).code, 4);
  });

  it('an IP literal under "*" is subject to the same guard, including the odd spellings getaddrinfo accepts', async () => {
    const echoPort = await fx.echoServer();
    const { client, inbox } = await fx.setup({ allow: ['*'] });
    let id = 1;
    for (const host of ['127.0.0.1', '127.1', '2130706433', '0x7f.0.0.1', '017700000001', '0.0.0.0', '10.0.0.1', '169.254.169.254', '::1', '::ffff:127.0.0.1', 'localhost']) {
      await open(client, id, host, echoPort);
      const f = await failOf(inbox, id);
      assert.ok(f.code === 4 || f.code === 3, `${host} was refused (code ${f.code}: ${f.message})`);
      id++;
    }
    assert.equal(inbox.some((m) => m.type === MSG.GATEWAY_OK), false);
  });

  it('private destinations only by explicit rule: allowPrivate, or an allow entry that is itself the IP literal', async () => {
    const echoPort = await fx.echoServer();
    // 1. allowPrivate covers loopback for a "*" gateway.
    let t = await fx.setup({ allow: ['*'], allowPrivate: ['127.0.0.0/8'] });
    await open(t.client, 1, '127.0.0.1', echoPort);
    await until(() => t.inbox.find((m) => m.type === MSG.GATEWAY_OK), 'ok via allowPrivate');
    // ...but not other private space.
    await open(t.client, 2, '10.0.0.1', 80);
    assert.equal((await failOf(t.inbox, 2)).code, 4);
    // 2. an explicit IP-literal entry permits exactly that address.
    t = await fx.setup({ allow: [`127.0.0.1:${echoPort}`] });
    await open(t.client, 1, '127.0.0.1', echoPort);
    await until(() => t.inbox.find((m) => m.type === MSG.GATEWAY_OK), 'ok via literal entry');
    await open(t.client, 2, '127.0.0.1', echoPort + 1);
    assert.equal((await failOf(t.inbox, 2)).code, 4, 'another port is not listed');
  });

  it('an explicit literal entry does not make a NAME that resolves to that address reachable', async () => {
    const echoPort = await fx.echoServer();
    stubDns({ 'evil.test': ['127.0.0.1'] });
    const { client, inbox } = await fx.setup({ allow: [`127.0.0.1:${echoPort}`, 'evil.test'] });
    await open(client, 1, 'evil.test', echoPort);
    assert.equal((await failOf(inbox, 1)).code, 4);
  });

  it('ResolveDns answers are filtered by the same guard, and a later OpenTcp to a private answer is refused', async () => {
    stubDns({ 'split.test': ['10.0.0.1', '8.8.8.8'], 'allprivate.test': ['10.0.0.1', '192.168.1.1'] });
    const { client, inbox } = await fx.setup({ allow: ['*'] });
    await client.sendControl({ type: MSG.RESOLVE_DNS, gateway_id: 1, name: 'split.test', record_type: 'A' });
    const r = await until(() => inbox.find((m) => m.type === MSG.DNS_RESULT && m.gateway_id === 1), 'DnsResult');
    assert.deepEqual(r.addresses, ['8.8.8.8'], 'the private answer is not handed out');
    await client.sendControl({ type: MSG.RESOLVE_DNS, gateway_id: 2, name: 'allprivate.test', record_type: 'A' });
    assert.equal((await failOf(inbox, 2)).code, 4);
    await open(client, 3, '10.0.0.1', 80);
    assert.equal((await failOf(inbox, 3)).code, 4);
  });

  it('ResolveDns hands out a private answer when a rule permits it', async () => {
    stubDns({ 'lan.test': ['10.0.0.1', '8.8.4.4'] });
    const { client, inbox } = await fx.setup({ allow: ['lan.test'], allowPrivate: ['10.0.0.0/8'] });
    await client.sendControl({ type: MSG.RESOLVE_DNS, gateway_id: 1, name: 'lan.test', record_type: 'A' });
    const r = await until(() => inbox.find((m) => m.type === MSG.DNS_RESULT), 'DnsResult');
    assert.deepEqual(r.addresses, ['10.0.0.1', '8.8.4.4']);
  });

  it('through a SOCKS proxy the name goes unresolved, but an IP literal is still checked', async () => {
    let proxyHits = 0;
    const proxy = net.createServer((c) => { proxyHits++; c.on('error', () => {}); c.destroy(); });
    const proxyPort = await listen(proxy); fx.nets.push(proxy);
    const { client, inbox } = await fx.setup({ allow: ['*'], socks: `127.0.0.1:${proxyPort}` });
    await open(client, 1, '127.0.0.1', 80);
    assert.equal((await failOf(inbox, 1)).code, 4);
    await open(client, 2, '10.0.0.1', 80);
    assert.equal((await failOf(inbox, 2)).code, 4);
    await sleep(50);
    assert.equal(proxyHits, 0, 'a refused literal never reaches the proxy');
  });

  it('rejects a malformed allowPrivate entry and a non-array', () => {
    assert.throws(() => createWshServer({ gateway: { allow: ['*'], allowPrivate: ['not-an-address'] } }), /allowPrivate/);
    assert.throws(() => createWshServer({ gateway: { allow: ['*'], allowPrivate: ['10.0.0.0/33'] } }), /allowPrivate/);
    assert.throws(() => createWshServer({ gateway: { allow: ['*'], allowPrivate: '10.0.0.0/8' } }), /allowPrivate/);
  });
});
