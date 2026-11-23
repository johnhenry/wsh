#!/usr/bin/env node
// wsh-mcp (wsh #127): a stdio bridge so an MCP client can reach an MCP server behind a wsh host. See src/mcp-stdio.mjs and the README.

import { parseArgs } from 'node:util';
import { createRequire } from 'node:module';
import { userInfo } from 'node:os';
import { runMcpStdioBridge, loadIdentity, defaultIdentityPath, McpBridgeError } from '../src/mcp-stdio.mjs';

const { version } = createRequire(import.meta.url)('../package.json');

const HELP = `wsh-mcp ${version} -- reach an MCP server behind a wsh host from an MCP client that launches a command

Usage: wsh-mcp [options] [user@]<url>

  <url>                   ws://, wss:// or https:// URL of the wsh host (a host serving an rpc channel "mcp")
  -l, --user NAME         login name (default: the user@ part of the URL, else $WSH_USER, $USER, or the OS user)
  -i, --identity FILE     Ed25519 private key (default: ~/.wsh/keys/default.pem, the key \`wsh keygen\` makes)
      --channel NAME      the rpc channel to open (default: mcp)
      --host-key KEY      pin the host: a hex fingerprint, or an ssh-ed25519 line (default: not pinned, with a warning)
      --no-reconnect      exit when the connection is lost instead of reconnecting
      --reconnect-attempts N   attempts before giving up (default: 5, from 500 ms, doubling)
      --timeout MS        to log in and to open the channel (default: 15000)
  -h, --help              this text
  -V, --version

stdout carries MCP messages only (one JSON-RPC message per line); everything else goes to stderr.
Exit status: 0 the client closed the connection, 1 the host was lost for good, 2 it could not start.

An MCP client configuration (Claude Desktop, Cursor, ...):

  { "mcpServers": { "remote": { "command": "wsh-mcp", "args": ["--identity", "/home/me/.wsh/keys/default.pem", "wss://host.example:4422"] } } }
`;

function usage(message) {
  process.stderr.write(`wsh-mcp: ${message}\nTry \`wsh-mcp --help\`.\n`);
  process.exit(2);
}

let parsed;
try {
  parsed = parseArgs({
    allowPositionals: true,
    options: {
      user: { type: 'string', short: 'l' },
      identity: { type: 'string', short: 'i' },
      channel: { type: 'string' },
      'host-key': { type: 'string' },
      'no-reconnect': { type: 'boolean' },
      'reconnect-attempts': { type: 'string' },
      timeout: { type: 'string' },
      target: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'V' },
    },
  });
} catch (e) { usage(e.message); }
const { values, positionals } = parsed;
if (values.help) { process.stdout.write(HELP); process.exit(0); }
if (values.version) { process.stdout.write(`${version}\n`); process.exit(0); }
if (values.target !== undefined) usage('--target: rpc channels are not per target (#121), so there is nothing to select; the host serves one "mcp" channel');
if (positionals.length !== 1) usage('exactly one host URL is required');

let url = positionals[0];
let userFromUrl;
const at = url.indexOf('@');
if (at > 0 && !url.slice(0, at).includes('/') && !url.slice(0, at).includes(':')) { userFromUrl = url.slice(0, at); url = url.slice(at + 1); }
if (!/^(wss?|https?):\/\//.test(url)) usage(`${url}: expected a ws://, wss:// or https:// URL`);
const number = (name, v, min) => {
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min) usage(`--${name} must be a whole number of at least ${min}`);
  return n;
};
const attempts = number('reconnect-attempts', values['reconnect-attempts'], 0);
const timeoutMs = number('timeout', values.timeout, 1);
const username = values.user ?? userFromUrl ?? process.env.WSH_USER ?? process.env.USER ?? userInfo().username;

const handle = { close: null };
let exitCode;
try {
  const signer = await loadIdentity(values.identity ?? defaultIdentityPath());
  for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => { void handle.close?.(); });
  exitCode = await runMcpStdioBridge({
    url, username, signer, channel: values.channel, expectHostKey: values['host-key'], timeoutMs,
    reconnect: values['no-reconnect'] ? false : (attempts === undefined ? undefined : { attempts }),
    signalHandle: handle,
  });
} catch (e) {
  process.stderr.write(`wsh-mcp: ${e?.message ?? e}\n`);
  exitCode = e instanceof McpBridgeError ? e.exitCode : 2;
}
process.exit(exitCode);
