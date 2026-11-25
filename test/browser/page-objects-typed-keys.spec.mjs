// What the Node tests could not show (#219, the "not verified" list), against a REAL Chromium page host behind a byte pipe:
//  1. typed remotes: `rootDescription` from a real page host, `describeRootTypes` on it, and the generated `.d.ts` compiled by the TypeScript of this repo against
//     usage that must pass and usage that must be refused, for the full key and for a key that may only read;
//  2. two different keys on one real host, one after the other (a page host serves one operator at a time): handles, callbacks and refusals stay with the
//     channel and the key that made them.
import { test, expect } from './fixtures.mjs';
import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { set, on, use, release, rootDescription, RemoteHandle } from '@johnhenry/wsh/objects';
import { describeRootTypes } from '@johnhenry/wsh/objects-types';

const repo = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const tsc = path.join(repo, 'node_modules', 'typescript', 'bin', 'tsc');

/** Compile `files` (name -> text) in a scratch directory with the repo's TypeScript and the package's own `.d.ts` files; resolves `{ code, out }`. */
async function compile(files) {
  const dir = await mkdtemp(path.join(tmpdir(), 'wsh-typed-'));
  try {
    for (const [name, text] of Object.entries(files)) await writeFile(path.join(dir, name), text);
    await writeFile(path.join(dir, 'tsconfig.json'), JSON.stringify({
      compilerOptions: {
        target: 'ES2022', lib: ['ES2022', 'DOM'], module: 'ESNext', moduleResolution: 'Bundler', strict: true, noEmit: true, skipLibCheck: true, types: [],
        paths: { '@johnhenry/wsh': [path.join(repo, 'src', 'index.d.ts')], '@johnhenry/wsh/*': [path.join(repo, 'src', '*.d.ts')] },
      },
      files: Object.keys(files).filter((n) => n.endsWith('.ts')).map((n) => path.join(dir, n)),
    }));
    return await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [tsc, '--pretty', 'false', '-p', path.join(dir, 'tsconfig.json')], { cwd: dir, env: { ...process.env, HOME: dir } });
      let out = '';
      child.stdout.on('data', (d) => { out += d; });
      child.stderr.on('data', (d) => { out += d; });
      child.on('error', reject);
      child.on('close', (code) => resolve({ code, out }));
    });
  } finally { await rm(dir, { recursive: true, force: true }); }
}

test.describe('a real page host: typed remotes, and two keys one after the other', () => {
  let pipe; let alice; let aliceLine; let bob; let bobLine; let bobReadOnly;
  test.beforeAll(async () => {
    alice = await generateKeyPair(true); aliceLine = await exportPublicKeySSH(alice.publicKey);
    bob = await generateKeyPair(true); bobLine = await exportPublicKeySSH(bob.publicKey);
    bobReadOnly = `capabilities="objects:window:get" ${bobLine}`;
  });
  // The repo's own pipe relay, not the byte-copying helper of the other specs: a second operator arrives while the page is dialling the relay again after the first,
  // and a relay has to hold what that operator sends until the page is there (`earlyBytes`), as every real one does.
  test.beforeEach(async () => {
    const relay = createPipeRelay();
    const { port } = await relay.listen();
    const base = `ws://127.0.0.1:${port}`;
    const id = newRendezvousId();
    pipe = { hostUrl: { url: base, id }, operatorUrl: pipeUrl(base, id), close: () => relay.close() };
  });
  test.afterEach(async () => { await pipe.close(); });

  const connect = async (keyPair, username, expectHostKey) => {
    const wsh = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
    await wsh.connect(pipe.operatorUrl, { username, keyPair, transport: 'ws', sealSession: true, expectHostKey });
    return wsh;
  };

  test('the generated .d.ts of a real host compiles, types real values, and says less for a key that may only read', async ({ page }) => {
    const expose = { window: {
      allow: {
        get: ['document.title', 'app.cart.items', 'app.state.user'], call: ['app.cart.add'], set: ['app.state.user'], on: ['@hashchange'],
      },
      eventFields: { hashchange: ['newURL', 'oldURL'] },
      types: {
        'document.title': { value: 'string' },
        'app.cart.items': { value: '{ sku: string; qty: number }[]' },
        'app.cart.add': { args: '[item: { sku: string; qty?: number }]', result: '{ count: number }' },
        'app.state.user': { value: 'string' },
        '@hashchange': { data: '{ type: "hashchange"; newURL: string }' },
      },
    } };
    await page.evaluate(() => window.h.pageApp());
    const host = await page.evaluate((o) => window.h.startPageHost(o), { relay: pipe.hostUrl, authorizedKeys: [aliceLine, bobReadOnly], expose });

    // The full key: read, call, assign, listen.
    const wsh = await connect(alice, 'alice', host.fingerprint);
    let fullText;
    try {
      const remote = await wsh.openObjects();
      const description = await rootDescription(remote.window);
      fullText = describeRootTypes(description, { name: 'WindowRemote' });
      expect(fullText).toMatch(/readonly title: RemoteValue<string>/);
      expect(fullText).toMatch(/RemoteCall<\[item: \{ sku: string; qty\?: number \}\], \{ count: number \}/);
      expect(fullText).not.toMatch(/secret|localStorage|cookie/);
      // What the file says is what the real page does.
      expect(typeof (await remote.window.document.title)).toBe('string');
      expect(await remote.window.app.cart.add({ sku: 'B2', qty: 3 })).toEqual({ count: 2 });
      expect((await remote.window.app.cart.items).every((i) => typeof i.sku === 'string' && typeof i.qty === 'number')).toBe(true);
    } finally { await wsh.disconnect(); }

    const positive = `
import type { WshClient } from '@johnhenry/wsh';
import { set, on } from '@johnhenry/wsh/objects';
import type { WindowRemote } from './window-remote.js';
declare const client: WshClient;
export async function usage(): Promise<void> {
  const { window } = await client.openObjects<{ window: WindowRemote }>();
  const title: string = await window.document.title;
  const result: { count: number } = await window.app.cart.add({ sku: 'A', qty: 1 });
  const items: { sku: string; qty: number }[] = await window.app.cart.items;
  await set(window.app.state, 'user', 'bob');
  const stop = await on(window, 'hashchange', (data) => { const url: string = data.newURL; void url; }, { fields: ['newURL', 'oldURL'] });
  await stop();
  // @ts-expect-error a path the host does not allow is not in the file
  void window.app.secret;
  // @ts-expect-error the argument is { sku: string; qty?: number }
  void window.app.cart.add({ sku: 5 });
  // @ts-expect-error title is a string
  const wrong: number = await window.document.title;
  // @ts-expect-error assigning needs the type the host gave
  await set(window.app.state, 'user', 5);
  // @ts-expect-error the host offers hashchange here, not click
  await on(window, 'click', () => {});
  void [title, result, items, wrong];
}
`;
    const full = await compile({ 'window-remote.d.ts': fullText, 'usage.ts': positive });
    expect(full.out).toBe('');
    expect(full.code).toBe(0);

    // A key that may only read: the same host, another key, a smaller file (an operation the key lacks is not in it at all).
    const readOnlyWsh = await connect(bob, 'bob', host.fingerprint);
    let readText;
    try {
      const remote = await readOnlyWsh.openObjects();
      readText = describeRootTypes(await rootDescription(remote.window), { name: 'WindowRemote' });
      expect(readText).toMatch(/readonly title: RemoteValue<string>/);
      expect(readText.replace(/^import .*$/m, '')).not.toMatch(/RemoteCall|WithSet|WithEvents/);
      expect(await remote.window.document.title).toBe('Planted Shop Title');
      await expect(Promise.resolve(remote.window.app.cart.add({ sku: 'x' }))).rejects.toMatchObject({ reason: 'not-permitted' });
      await expect(set(remote.window.app.state, 'user', 'x')).rejects.toMatchObject({ reason: 'not-permitted' });
      await expect(on(remote.window, 'hashchange', () => {})).rejects.toMatchObject({ reason: 'not-permitted' });
      expect(await page.evaluate(() => window.app.state.user)).toBe('alice');
    } finally { await readOnlyWsh.disconnect(); }
    const narrow = `
import type { WshClient } from '@johnhenry/wsh';
import { set, on } from '@johnhenry/wsh/objects';
import type { WindowRemote } from './window-remote.js';
declare const client: WshClient;
export async function usage(): Promise<void> {
  const { window } = await client.openObjects<{ window: WindowRemote }>();
  const title: string = await window.document.title;
  // @ts-expect-error this key holds no call capability: add is not in its file
  void window.app.cart.add({ sku: 'A' });
  // set and on are NOT refused by the compiler for this key: a reference that has no WithSet or WithEvents in its file stays permissive (types are advisory);
  // the host refuses them when they run (see below).
  await set(window.app.state, 'user', 'x');
  await on(window, 'hashchange', () => {});
  void title;
}
`;
    const narrowed = await compile({ 'window-remote.d.ts': readText, 'usage.ts': narrow });
    expect(narrowed.out).toBe('');
    expect(narrowed.code).toBe(0);

    // The control: the same compiler rejects usage that is wrong (so a pass above is not a compiler that checks nothing).
    const broken = await compile({ 'window-remote.d.ts': fullText, 'usage.ts': positive.replace(/\/\/ @ts-expect-error[^\n]*\n/g, '') });
    expect(broken.code).not.toBe(0);
    expect(broken.out).toMatch(/error TS/);
  });

  test('two different keys, one after the other, on one real host: handles and callbacks stay with the channel and the key that made them', async ({ page }) => {
    const expose = { window: { mode: 'handles', allow: { get: ['app.account', 'app.account.balance'], call: ['app.account.deposit', 'app.watch(callback)', 'app.tick'] } } };
    await page.evaluate(() => window.h.pageApp());
    const host = await page.evaluate((o) => window.h.startPageHost(o), { relay: pipe.hostUrl, authorizedKeys: [aliceLine, bobReadOnly], expose });

    // Alice may do everything on the root: a handle used across calls, a callback the page keeps.
    const aliceGot = [];
    let aliceRawId;
    const aliceWsh = await connect(alice, 'alice', host.fingerprint);
    try {
      const remote = (await aliceWsh.openObjects()).window;
      const account = await remote.app.account;
      expect(account).toBeInstanceOf(RemoteHandle);
      expect(await use(account).deposit(5)).toBe(15);
      expect(await remote.app.watch((v) => aliceGot.push(v))).toBe('watching');
      expect(await remote.app.tick(1)).toBe(1);
      await expect.poll(() => aliceGot.length).toBe(1);
      // Her handle's id as the wire carries it, on a channel of her own: it names nothing on any other channel.
      const raw = await aliceWsh.openRpc('wsh-objects');
      aliceRawId = (await raw.request('resolve', { root: 'window', ops: [{ get: 'app' }, { get: 'account' }] })).h;
      expect(typeof aliceRawId).toBe('string');
    } finally { await aliceWsh.disconnect(); }

    // Bob may only read. He gets a handle (a read), he cannot use it to call, he cannot pass the page a callback, and Alice's handle id is nothing to him.
    const bobWsh = await connect(bob, 'bob', host.fingerprint);
    try {
      const channel = await bobWsh.openRpc('wsh-objects');
      await expect(channel.request('resolve', { handle: aliceRawId, ops: [{ get: 'balance' }] })).rejects.toThrow(/no such handle/);
      const remote = (await bobWsh.openObjects()).window;
      const account = await remote.app.account;
      expect(account).toBeInstanceOf(RemoteHandle);
      expect(await use(account).balance).toBe(15);
      await expect(Promise.resolve(use(account).deposit(1))).rejects.toMatchObject({ reason: 'not-permitted' });
      await expect(Promise.resolve(remote.app.watch(() => {}))).rejects.toMatchObject({ reason: 'not-permitted' });
      expect(await page.evaluate(() => window.app.account.balance)).toBe(15);
      // The page ticks: Alice's stub is dead (her channel ended), Bob registered none: nothing reaches either, and nothing throws.
      expect(await page.evaluate(() => { try { return window.app.tick(2); } catch (e) { return String(e); } })).toBe(1);
      await new Promise((r) => setTimeout(r, 150));
      expect(aliceGot.length).toBe(1);
      await release(account);
    } finally { await bobWsh.disconnect(); }

    // Alice again: a new session, a new table. Her old handle is gone with her old channel; a new callback gets only what is called after it.
    const again = await connect(alice, 'alice', host.fingerprint);
    try {
      const remote = (await again.openObjects()).window;
      const fresh = [];
      expect(await remote.app.watch((v) => fresh.push(v))).toBe('watching');
      expect(await page.evaluate(() => window.app.tick(3))).toBe(2);
      await expect.poll(() => fresh.length).toBe(1);
      expect(fresh[0]).toEqual({ n: 3, at: 'page' });
      expect(aliceGot.length, 'the dead stub of the first session was not called').toBe(1);
      const account = await remote.app.account;
      expect(await use(account).deposit(1)).toBe(16);
    } finally { await again.disconnect(); }
  });
});
