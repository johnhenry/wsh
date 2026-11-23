// test/server-key-options.test.mjs -- authorized_keys options on the Node host (wsh #122, step one): the same key file
// gives the same answer as the Rust server. Each option is enforced at its own entry (Open, FileOp, upload/download, MCP, rpc,
// relay), and a line with an option this host does not understand never lets the key in. The parsing and the allow/refuse
// table are in test/key-options.test.mjs (shared vectors); this drives a real server.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createWshServer, parseAuthorizedKeys } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint } from '@johnhenry/wsh';
import { parseAuthorizedKeyEntries } from '../src/server/auth.mjs';

const dec = new TextDecoder();
const until = async (fn, what, ms = 3000) => {
  const t = Date.now();
  while (!(await fn())) { if (Date.now() - t > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 10)); }
};

/** Each key has its own options; a server with every one of them in one file. */
const LINES = {
  full: '',
  execOnly: 'restrict,permit-exec',
  ptyOnly: 'restrict,permit-pty',
  noPty: 'no-pty',
  files: 'restrict,permit-file-transfer',
  mcpOnly: 'restrict,permit-mcp',
  relayOnly: 'restrict,permit-relay',
  nothing: 'restrict',
  forced: 'restrict,command="echo forced"',
  forcedSpaced: 'command="echo \\"two words\\" here"',
  capped: 'max-sessions=2',
  future: 'restrict,permit-exec,permit-teleport',
  noAgent: 'no-agent-forwarding,restrict,permit-exec',
};

describe('authorized_keys options on the Node host (#122)', () => {
  const keys = {};
  let server; let url; let root; const logs = []; const spawned = []; const execCalls = [];
  const clients = [];

  before(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'wsh-keyopts-'));
    await writeFile(path.join(root, 'hello.txt'), 'hello');
    const lines = [];
    for (const [name, options] of Object.entries(LINES)) {
      const keyPair = await generateKeyPair(true);
      keys[name] = { keyPair, fp: await fingerprint(await exportPublicKeyRaw(keyPair.publicKey)) };
      lines.push(`${options ? `${options} ` : ''}${await exportPublicKeySSH(keyPair.publicKey)} ${name}@test`);
    }
    const spawn = (_f, _a, o) => {
      spawned.push(o);
      return { onData() {}, onExit() {}, write() {}, resize() {}, kill() {} };
    };
    server = createWshServer({
      auth: { authorizedKeys: `${lines.join('\n')}\n` },
      exec: async (command, io) => {
        execCalls.push(command);
        if (command === 'hang') { await new Promise((resolve) => io.signal.addEventListener('abort', resolve, { once: true })); return 0; }
        await io.write(`ran:${command}\n`);
        return 0;
      },
      pty: { spawn, shell: '/bin/sh' },
      fs: { root },
      rpc: { 'wsh-host': true, 'wsh-fs': true },
      mcp: { tools: [{ name: 'echo', description: 'echo', call: async () => 'pong' }] },
      relay: { canRegister: () => true, canConnect: () => true },
      onLog: (l) => logs.push(l),
    });
    ({ port: server.port } = await server.listen());
    url = `ws://127.0.0.1:${server.port}`;
  });
  after(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    await server.close();
    await rm(root, { recursive: true, force: true });
  });

  async function login(name) {
    const c = new WshClient();
    await c.connect(url, { username: 'alice', keyPair: keys[name].keyPair });
    clients.push(c);
    return c;
  }
  const output = (session) => new Promise((resolve) => { const out = []; session.onData = (d) => out.push(dec.decode(d)); session.onClose = () => resolve(out.join('')); });
  const run = async (client, command) => output(await client.openSession({ type: 'exec', command }));
  /** The request is refused with a reason matching `re`: as a rejection (an Open) or as a failed FileResult (a FileOp). */
  const refusedWith = async (promise, re) => {
    let r;
    try { r = await promise; } catch (e) { assert.match(e.message, re); return; }
    assert.equal(r?.success, false, `the request was served: ${JSON.stringify(r)}`);
    assert.match(String(r.error_message ?? r.errorMessage), re);
  };

  it('a line with options now parses: the key is on the allowlist with its permissions', () => {
    const { entries, refused } = parseAuthorizedKeyEntries('restrict,permit-exec ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFwuwlhewrj73VpJwckueO62uR5tQZacudrGnfSHW89b bob\n');
    assert.equal(refused.length, 0);
    assert.equal(entries.length, 1);
    assert.equal(entries[0].permissions.exec, true);
    assert.equal(entries[0].permissions.pty, false);
  });

  it('parseAuthorizedKeys still returns bare keys only: a line with options is never handed out without them', () => {
    assert.equal(parseAuthorizedKeys('restrict,permit-exec ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFwuwlhewrj73VpJwckueO62uR5tQZacudrGnfSHW89b bob\n').length, 0);
  });

  it('a key with no options is served everywhere, as before', async () => {
    const c = await login('full');
    assert.equal(await run(c, 'x'), 'ran:x\n');
    assert.ok(await c.openSession({ type: 'pty' }));
    assert.ok((await c.fileOperation('list', '/')).entries.some((e) => e.name === 'hello.txt'));
    assert.deepEqual((await c.discoverTools()).map((t) => t.name), ['echo']);
  });

  it('restrict,permit-exec: exec is served, pty, files and MCP are refused', async () => {
    const c = await login('execOnly');
    assert.equal(await run(c, 'y'), 'ran:y\n');
    await refusedWith(c.openSession({ type: 'pty' }), /PTY not permitted/);
    await refusedWith(c.fileOperation('list', '/'), /file transfer not permitted/);
    await refusedWith(c.download('/hello.txt'), /file transfer not permitted/);
    await refusedWith(c.upload(new Blob(['x']), '/up.txt'), /file transfer not permitted/);
    assert.deepEqual(await c.discoverTools(), []);
    const called = await c.callTool('echo', {});
    assert.equal(called.success, false);
    assert.match(called.error, /MCP not permitted/);
  });

  it('restrict,permit-pty: a shell is served, and so are commands (a shell can run them)', async () => {
    const c = await login('ptyOnly');
    const before = spawned.length;
    assert.ok(await c.openSession({ type: 'pty' }));
    assert.equal(spawned.length, before + 1);
    assert.equal(await run(c, 'z'), 'ran:z\n');
    await refusedWith(c.fileOperation('list', '/'), /file transfer not permitted/);
  });

  it('no-pty: commands, files and MCP stay, the pty goes', async () => {
    const c = await login('noPty');
    await refusedWith(c.openSession({ type: 'pty' }), /PTY not permitted/);
    assert.equal(await run(c, 'n'), 'ran:n\n');
    assert.ok((await c.fileOperation('list', '/')).entries.length);
  });

  it('restrict,permit-file-transfer: list, download, upload and the wsh-fs channel are served; exec is not', async () => {
    const c = await login('files');
    assert.ok((await c.fileOperation('list', '/')).entries.some((e) => e.name === 'hello.txt'));
    assert.equal(dec.decode(await c.download('/hello.txt')), 'hello');
    await c.upload(new Blob(['up']), '/up.txt');
    assert.equal(dec.decode(await c.download('/up.txt')), 'up');
    await refusedWith(c.openSession({ type: 'exec', command: 'x' }), /exec access not permitted/);
    await refusedWith(c.openSession({ type: 'pty' }), /PTY not permitted/);
  });

  it('restrict alone: nothing is served, and the refusal names what is missing', async () => {
    const c = await login('nothing');
    await refusedWith(c.openSession({ type: 'exec', command: 'x' }), /exec access not permitted/);
    await refusedWith(c.openSession({ type: 'pty' }), /PTY not permitted/);
    await refusedWith(c.fileOperation('list', '/'), /file transfer not permitted/);
    await refusedWith(c.openSession({ type: 'rpc', protocol: 'wsh-fs' }), /file transfer not permitted/);
    assert.deepEqual(await c.discoverTools(), []);
  });

  it('rpc channels follow the key: wsh-fs needs file transfer, wsh-host is open', async () => {
    const files = await login('files');
    assert.ok(await files.openSession({ type: 'rpc', protocol: 'wsh-fs' }));
    const exec = await login('execOnly');
    assert.ok(await exec.openSession({ type: 'rpc', protocol: 'wsh-host' }));
    await refusedWith(exec.openSession({ type: 'rpc', protocol: 'wsh-fs' }), /file transfer not permitted/);
  });

  it('restrict,permit-mcp: discovery and calls are served; exec is not', async () => {
    const c = await login('mcpOnly');
    assert.deepEqual((await c.discoverTools()).map((t) => t.name), ['echo']);
    assert.ok(await c.callTool('echo', {}));
    await refusedWith(c.openSession({ type: 'exec', command: 'x' }), /exec access not permitted/);
  });

  it('a forced command replaces whatever the client asks to run, and is all the key can do', async () => {
    const c = await login('forced');
    assert.equal(await run(c, 'rm -rf /'), 'ran:echo forced\n');
    assert.ok(!execCalls.includes('rm -rf /'));
    await refusedWith(c.openSession({ type: 'pty' }), /forced exec command/);
    await refusedWith(c.fileOperation('list', '/'), /forced exec command/);
    await refusedWith(c.openSession({ type: 'rpc', protocol: 'wsh-host' }), /forced exec command/);
    assert.deepEqual(await c.discoverTools(), []);
  });

  it('a forced command with quotes and spaces is the unescaped text', async () => {
    const c = await login('forcedSpaced');
    assert.equal(await run(c, 'ignored'), 'ran:echo "two words" here\n');
  });

  it('max-sessions=2: a third live session is refused, and a slot frees when one ends', async () => {
    const c = await login('capped');
    const a = await c.openSession({ type: 'exec', command: 'hang' });
    const b = await c.openSession({ type: 'exec', command: 'hang' });
    await refusedWith(c.openSession({ type: 'exec', command: 'hang' }), /max sessions for this key reached \(2\)/);
    // the count is per key, not per connection
    const other = await login('capped');
    await refusedWith(other.openSession({ type: 'exec', command: 'hang' }), /max sessions/);
    const gone = new Promise((resolve) => { a.onClose = resolve; });
    a.close?.();
    await gone;
    await until(async () => { try { (await c.openSession({ type: 'exec', command: 'hang' })); return true; } catch { return false; } }, 'a slot to free');
    void b;
  });

  it('a key whose line has an option this host does not understand cannot log in, and the reason is logged', async () => {
    const c = new WshClient();
    await assert.rejects(c.connect(url, { username: 'alice', keyPair: keys.future.keyPair }), /not authorized/);
    assert.ok(logs.some((l) => /refused/.test(l) && /unknown-option/.test(l) && /permit-teleport/.test(l)), logs.join('\n'));
  });

  it('ssh options that only ask for less (no-agent-forwarding) are accepted', async () => {
    const c = await login('noAgent');
    assert.equal(await run(c, 'k'), 'ran:k\n');
  });

  it('relay: a key without permit-relay cannot register or list; one with it can', async () => {
    const allowed = new WshClient();
    await allowed.connectReverse(url, { username: 'alice', keyPair: keys.relayOnly.keyPair, expose: { exec: true } });
    clients.push(allowed);
    await until(() => server.peerFingerprints().includes(keys.relayOnly.fp), 'the permitted peer to register');
    assert.ok(Array.isArray(await allowed.listPeers()), 'a key with permit-relay can list');

    const denied = new WshClient();
    await denied.connectReverse(url, { username: 'alice', keyPair: keys.execOnly.keyPair, expose: { exec: true } }).catch(() => {});
    clients.push(denied);
    await new Promise((r) => setTimeout(r, 150));
    assert.ok(!server.peerFingerprints().includes(keys.execOnly.fp), 'a key without permit-relay never registers');
    assert.ok(logs.some((l) => /key options refused relay/.test(l) && /relay-not-permitted/.test(l)), logs.join('\n'));

    // ... and cannot list or connect either
    const mute = await login('execOnly');
    await assert.rejects(mute.listPeers(150), /./);
    const rejected = await mute.reverseConnect(keys.relayOnly.fp, 500).then((r) => r, (e) => e);
    assert.match(String(rejected instanceof Error ? rejected.message : rejected.reason), /relay not permitted/);  });
});
