#!/usr/bin/env node
// wsh-objects-types (#219): connect to a wsh host that serves `wsh-objects` (a page host behind a relay, any host with `exposeObjects`), ask what THIS key may do on one
// root, and write the TypeScript declarations for it. JavaScript only: the Rust CLI has no `wsh-objects` client. Nothing is evaluated: the host's type texts are checked and
// copied, and the file is written only when --out is given.

import { parseArgs } from 'node:util';
import { createRequire } from 'node:module';
import { userInfo } from 'node:os';
import { writeFile } from 'node:fs/promises';
import { loadIdentity, defaultIdentityPath, McpBridgeError } from '../src/mcp-stdio.mjs';
import { WshClient } from '../src/index.mjs';
import { openObjects, rootDescription } from '../src/objects.mjs';
import { describeRootTypes } from '../src/objects-types.mjs';

const { version } = createRequire(import.meta.url)('../package.json');

const HELP = `wsh-objects-types ${version} -- the TypeScript types of a root of wsh-objects, for what this key may do

Usage: wsh-objects-types [options] [user@]<url>

  <url>                   ws://, wss:// or https:// URL of the wsh host (a host serving the rpc channel "wsh-objects"; a page host: its operator URL)
  -l, --user NAME         login name (default: the user@ part of the URL, else $WSH_USER, $USER, or the OS user)
  -i, --identity FILE     Ed25519 private key (default: ~/.wsh/keys/default.pem, the key \`wsh keygen\` makes)
      --root NAME         the root to describe (default: the only one the key may use; required when there are several)
      --name TYPE         the name of the exported type (default: the root's name, capitalised, plus Remote)
  -o, --out FILE          write the declarations to FILE (default: standard output). An existing file is not overwritten without --force
      --force             overwrite --out
      --sealed            seal the whole session end to end and refuse a host that cannot (a host behind a relay, a page); key login only
      --host-key KEY      pin the host: a hex fingerprint, or an ssh-ed25519 line (default: not pinned, with a warning)
      --timeout MS        to log in and to open the channel (default: 15000)
  -h, --help              this text
  -V, --version

The declarations say only what the key that connected may do (the host's allow-lists narrowed by that key's capabilities); values are \`unknown\` unless the host
supplied a type, which is checked and copied as text, never evaluated. Use it as: client.openObjects<{ window: WindowRemote }>().
Exit status: 0 written, 2 it could not be done.
`;

const fail = (message) => { process.stderr.write(`wsh-objects-types: ${message}\n`); process.exit(2); };

let parsed;
try {
  parsed = parseArgs({
    allowPositionals: true,
    options: {
      user: { type: 'string', short: 'l' },
      identity: { type: 'string', short: 'i' },
      root: { type: 'string' },
      name: { type: 'string' },
      out: { type: 'string', short: 'o' },
      force: { type: 'boolean' },
      sealed: { type: 'boolean' },
      'host-key': { type: 'string' },
      timeout: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'V' },
    },
  });
} catch (e) { fail(`${e.message}\nTry \`wsh-objects-types --help\`.`); }
const { values, positionals } = parsed;
if (values.help) { process.stdout.write(HELP); process.exit(0); }
if (values.version) { process.stdout.write(`${version}\n`); process.exit(0); }
if (positionals.length !== 1) fail('exactly one host URL is required. Try `wsh-objects-types --help`.');

let url = positionals[0];
let userFromUrl;
const at = url.indexOf('@');
if (at > 0 && !url.slice(0, at).includes('/') && !url.slice(0, at).includes(':')) { userFromUrl = url.slice(0, at); url = url.slice(at + 1); }
if (!/^(wss?|https?):\/\//.test(url)) fail(`${url}: expected a ws://, wss:// or https:// URL`);
const timeout = values.timeout === undefined ? 15_000 : Number(values.timeout);
if (!Number.isInteger(timeout) || timeout < 1) fail('--timeout must be a whole number of at least 1');
const username = values.user ?? userFromUrl ?? process.env.WSH_USER ?? process.env.USER ?? userInfo().username;

const client = new WshClient();
let code = 0;
try {
  let signer;
  try { signer = await loadIdentity(values.identity ?? defaultIdentityPath()); } catch (e) { throw e instanceof McpBridgeError ? e : new Error(e?.message ?? String(e)); }
  await client.connect(url, { username, signer, timeout, ...(values['host-key'] ? { expectHostKey: values['host-key'] } : {}), ...(values.sealed ? { sealSession: true } : {}) });
  const page = await openObjects(client);
  const roots = Object.keys(page);
  if (roots.length === 0) throw new Error('this key may use no root of the host');
  const root = values.root ?? (roots.length === 1 ? roots[0] : undefined);
  if (root === undefined) throw new Error(`the host has several roots the key may use (${roots.join(', ')}): choose one with --root`);
  if (!roots.includes(root)) throw new Error(`no root ${JSON.stringify(root)} that this key may use (${roots.join(', ')})`);
  const text = describeRootTypes(await rootDescription(page[root]), values.name === undefined ? {} : { name: values.name });
  if (values.out === undefined) process.stdout.write(text);
  else {
    await writeFile(values.out, text, { flag: values.force ? 'w' : 'wx', mode: 0o644 });
    process.stderr.write(`wsh-objects-types: wrote ${values.out}\n`);
  }
} catch (e) {
  process.stderr.write(`wsh-objects-types: ${e?.code === 'EEXIST' ? `${values.out} exists (--force overwrites it)` : (e?.message ?? e)}\n`);
  code = 2;
} finally {
  await client.disconnect().catch(() => {});
}
process.exit(code);
