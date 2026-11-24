// scripts/message-matrix.mjs -- which wire messages each implementation actually names (#129).
//   node scripts/message-matrix.mjs           rewrite spec/message-matrix.md          (npm run matrix)
//   node scripts/message-matrix.mjs --check   exit 1 if that file is stale            (npm run matrix:check; also a test)
//
// The matrix is DERIVED, not kept by hand: the message list (name, code, section) comes from spec/wsh-v1.yaml, and every
// cell comes from the source of the implementation it is in. An implementation "names" a message when code that is not
// generated and not a test sends it or acts on it:
//   - JS:   `MSG.X`, or a call of the message's builder function (`open(...)`, as imported from messages.mjs), in a
//           source file of that implementation, comments removed;
//   - Rust: `Payload::X`, `MsgType::X` or the `XPayload` struct in a source file of that implementation, comments and
//           `#[cfg(test)]` code removed.
// Naming a message is not the same as handling every field of it correctly (the conformance and interop tests are for
// that); it is the difference between "a handler exists" and "nothing in this implementation has heard of it".
// A source file that is not classified below fails the check: add a file to the list of the implementation it belongs
// to (HOST, CLIENT, SHARED) and the matrix follows.
import { readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const OUT = path.join(ROOT, 'spec', 'message-matrix.md');

export const COLUMNS = [
  { key: 'jsHost', label: 'JS host' },
  { key: 'jsClient', label: 'JS client' },
  { key: 'rustHost', label: 'Rust host' },
  { key: 'rustClient', label: 'Rust client' },
];

/**
 * Which source files belong to which implementation. A path is a file, or a directory when it ends in `/`.
 * SHARED files count for both the host and the client column of their language (the key exchange, the sealed frame and
 * the like are one code path that both ends run). IGNORED files cannot name a message (generated code, barrels, codecs).
 */
export const FILES = {
  js: {
    host: ['src/server/', 'src/host.mjs', 'src/host-backends.mjs', 'src/memory-host.mjs', 'src/reverse-host.mjs', 'src/session-registry.mjs', 'src/shares.mjs', 'src/recording.mjs', 'src/refusal.mjs'],
    client: [
      'src/client.mjs', 'src/session.mjs', 'src/file-transfer.mjs', 'src/forward-node.mjs', 'src/gateway-channel.mjs', 'src/gateway-client.mjs',
      'src/gateway-datagram.mjs', 'src/mcp-bridge.mjs', 'src/mcp-stdio.mjs', 'src/keystore.mjs', 'src/known-hosts.mjs', 'src/control-listener.mjs',
      'src/transport.mjs', 'src/transport-ws.mjs',
    ],
    shared: [
      'src/auth.mjs', 'src/bridge-seal.mjs', 'src/channel-binding.mjs', 'src/e2e-exchange.mjs', 'src/e2e-frame.mjs', 'src/features.mjs', 'src/host-key.mjs',
      'src/key-options.mjs', 'src/operator-proof.mjs', 'src/rpc.mjs', 'src/rpc-virtual.mjs', 'src/rpc-mcp.mjs', 'src/stream-frame.mjs', 'src/virtual-session.mjs',
    ],
    ignored: ['src/index.mjs', 'src/messages.mjs', 'src/messages.gen.mjs', 'src/cbor.mjs', 'src/mlkem.mjs', 'src/pipe-relay.mjs', 'src/pipe-url.mjs', 'src/page-host.mjs', 'src/webmcp.mjs', 'src/qmux.mjs', 'src/qmux-connection.mjs'],
  },
  rust: {
    host: ['crates/wsh-server/src/'],
    client: ['crates/wsh-client/src/', 'crates/wsh-cli/src/'],
    shared: ['crates/wsh-core/src/'],
    ignored: ['crates/wsh-core/src/messages.gen.rs', 'crates/wsh-core/src/messages.rs'],
  },
};

const walk = async (dir, ext) => {
  const out = [];
  for (const e of await readdir(path.join(ROOT, dir), { withFileTypes: true })) {
    const rel = `${dir}/${e.name}`;
    if (e.isDirectory()) out.push(...await walk(rel, ext));
    else if (e.name.endsWith(ext)) out.push(rel);
  }
  return out;
};
const under = (file, list) => list.some((p) => (p.endsWith('/') ? file.startsWith(p) : file === p));
const isTestFile = (f) => /(^|\/)(tests?|tests\.rs)(\/|$)/.test(f) || f.endsWith('/tests.rs');

/** Spec messages in file order: `{ name, code, section }`. Reads only the `messages:` block of the YAML. */
export function parseSpecMessages(yaml) {
  const out = [];
  let inMessages = false;
  let section = null;
  let current = null;
  for (const line of yaml.split('\n')) {
    if (/^\S/.test(line)) { inMessages = /^messages:\s*$/.test(line); section = null; current = null; continue; }
    if (!inMessages) continue;
    let m = line.match(/^ {2}([a-z_0-9]+):\s*$/);
    if (m) { section = m[1]; current = null; continue; }
    m = line.match(/^ {4}([A-Z][A-Za-z0-9]*):\s*$/);
    if (m) { current = { name: m[1], code: null, section }; out.push(current); continue; }
    m = line.match(/^ {6}code:\s*(0x[0-9a-fA-F]+|\d+)/);
    if (m && current && current.code === null) current.code = Number(m[1]);
  }
  return out;
}

/** The generated JS: message code -> `MSG` key, and `MSG` key -> builder function name. */
export function parseGeneratedJs(text) {
  const keyByCode = new Map();
  const msgBlock = text.match(/export const MSG = Object\.freeze\(\{([\s\S]*?)\}\);/);
  for (const m of (msgBlock?.[1] ?? '').matchAll(/([A-Z0-9_]+):\s*(0x[0-9a-fA-F]+|\d+)/g)) keyByCode.set(Number(m[2]), m[1]);
  const builderByKey = new Map();
  for (const chunk of text.split(/^export function /m).slice(1)) {
    const name = chunk.match(/^(\w+)\(/)?.[1];
    const key = chunk.match(/type:\s*MSG\.([A-Z0-9_]+)/)?.[1];
    if (name && key && !builderByKey.has(key)) builderByKey.set(key, name);
  }
  return { keyByCode, builderByKey };
}

const cache = new Map();
/** A file is stripped once, however many messages are looked for in it. */
const memo = (fn, source) => {
  const k = `${fn.name}:${source}`;
  if (!cache.has(k)) cache.set(k, fn(source));
  return cache.get(k);
};

export const stripJsComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`\\])\/\/.*$/gm, '$1');
/** Rust source without comments and without the items marked `#[cfg(test)]` (a test module, helper or import). */
export function stripRust(source) {
  // Strings, char literals and comments are blanked (keeping line structure) in ONE pass, leftmost first, so that a brace,
  // a quote or `//` inside one of them cannot be mistaken for code (`'"'` is a char, not the start of a string).
  const blank = (m) => m.replace(/[^\n]/g, ' ');
  const literals = /r(#*)"[\s\S]*?"\1|"(?:\\[\s\S]|[^"\\])*"|'(?:\\.|[^'\\\n])'|\/\*[\s\S]*?\*\/|\/\/.*$/gm;
  const s = source.replace(literals, blank);
  const real = source.split('');
  let from = 0;
  for (;;) {
    const at = s.indexOf('#[cfg(test)]', from);
    if (at < 0) break;
    let i = at + '#[cfg(test)]'.length;
    while (i < s.length && s[i] !== '{' && s[i] !== ';') i++;
    let end = i + 1;
    if (s[i] === '{') {
      for (let depth = 1; end < s.length && depth > 0; end++) depth += s[end] === '{' ? 1 : s[end] === '}' ? -1 : 0;
    }
    for (let j = at; j < end && j < real.length; j++) if (real[j] !== '\n') real[j] = ' ';
    from = end;
  }
  return real.join('').replace(literals, blank);
}

/** Does this JS source name the message (`MSG.key`, or a call of its builder as imported from a messages module)? */
export function jsNames(source, key, builder) {
  const text = memo(stripJsComments, source);
  if (new RegExp(`\\bMSG\\.${key}\\b`).test(text)) return true;
  if (!builder) return false;
  for (const imp of text.matchAll(/import\s*\{([^}]*)\}\s*from\s*['"][^'"]*\bmessages(?:\.gen)?\.mjs['"]/g)) {
    for (const part of imp[1].split(',')) {
      const [orig, alias] = part.trim().split(/\s+as\s+/);
      if (orig !== builder) continue;
      if (new RegExp(`(?<![\\w.])${alias ?? orig}\\s*\\(`).test(text.replace(imp[0], ''))) return true;
    }
  }
  return false;
}

/** Does this Rust source name the message? */
export function rustNames(source, name) {
  return new RegExp(`\\b(?:Payload|MsgType)::${name}\\b|\\b${name}Payload\\b`).test(memo(stripRust, source));
}

async function sources(lang, ext, role) {
  const all = await walk(lang === 'js' ? 'src' : 'crates', ext);
  const files = lang === 'js' ? all.filter((f) => !f.endsWith('.d.ts')) : all.filter((f) => f.includes('/src/'));
  const f = FILES[lang];
  const unclassified = [];
  const picked = [];
  for (const file of files) {
    if (isTestFile(file) || under(file, f.ignored)) continue;
    const mine = under(file, f.shared) || under(file, f[role]);
    const other = under(file, f.host) || under(file, f.client);
    if (!mine && !other) unclassified.push(file);
    if (mine) picked.push(file);
  }
  return { picked, unclassified };
}

/** @returns {Promise<{ messages: object[], unclassified: string[] }>} */
export async function buildMatrix() {
  const spec = parseSpecMessages(await readFile(path.join(ROOT, 'spec/wsh-v1.yaml'), 'utf8'));
  const gen = parseGeneratedJs(await readFile(path.join(ROOT, 'src/messages.gen.mjs'), 'utf8'));
  const read = async (files) => Promise.all(files.map((f) => readFile(path.join(ROOT, f), 'utf8')));
  const sets = {};
  const unclassified = new Set();
  for (const [col, lang, ext, role] of [['jsHost', 'js', '.mjs', 'host'], ['jsClient', 'js', '.mjs', 'client'], ['rustHost', 'rust', '.rs', 'host'], ['rustClient', 'rust', '.rs', 'client']]) {
    const { picked, unclassified: u } = await sources(lang, ext, role);
    u.forEach((f) => unclassified.add(f));
    sets[col] = await read(picked);
  }
  const messages = spec.map((m) => {
    const key = gen.keyByCode.get(m.code);
    const builder = key ? gen.builderByKey.get(key) : undefined;
    const cells = {
      jsHost: !!key && sets.jsHost.some((s) => jsNames(s, key, builder)),
      jsClient: !!key && sets.jsClient.some((s) => jsNames(s, key, builder)),
      rustHost: sets.rustHost.some((s) => rustNames(s, m.name)),
      rustClient: sets.rustClient.some((s) => rustNames(s, m.name)),
    };
    return { ...m, key, ...cells };
  });
  return { messages, unclassified: [...unclassified].sort() };
}

const hex = (n) => `0x${n.toString(16).padStart(2, '0')}`;
const mark = (b) => (b ? 'yes' : '-');

export function render({ messages }) {
  const lines = [];
  lines.push('<!-- GENERATED by `npm run matrix` (scripts/message-matrix.mjs) from spec/wsh-v1.yaml and the source of each implementation. Do not edit; `npm run matrix:check` (CI, and test/message-matrix.test.mjs) fails when this file is stale. -->');
  lines.push('', '# Message matrix: spec versus implementations', '');
  lines.push('Every message of [`wsh-v1.yaml`](wsh-v1.yaml) and whether each implementation **names** it: sends it or acts on it in code that is');
  lines.push('neither generated nor a test. `yes` means a handler or a sender exists; `-` means nothing in that implementation has heard of the message');
  lines.push('(the Rust types still decode it, since every message is generated into both languages; the JS decoder passes it through).');
  lines.push('It does not say that every field is honoured: [`test/spec-conformance.test.mjs`](../test/spec-conformance.test.mjs) and the interop tests do that.');
  lines.push('How it is derived, and which files count for which column, is in the header of [`scripts/message-matrix.mjs`](../scripts/message-matrix.mjs).');
  lines.push('A column is the whole implementation of that role: **JS host** = `createWshServer`, `createMemoryHost`, `createReverseHost`, the relay;');
  lines.push('**JS client** = `WshClient` and its helpers; **Rust host** = `wsh-server`; **Rust client** = `wsh-client` and the `wsh` CLI.');
  lines.push('Which messages a peer may RECEIVE without negotiating, and what to do about a message a peer does not know, is in [COMPATIBILITY.md](../COMPATIBILITY.md).');
  lines.push('');
  const total = messages.length;
  lines.push('## Summary', '');
  lines.push('| | messages named | of |', '| --- | ---: | ---: |');
  for (const c of COLUMNS) lines.push(`| ${c.label} | ${messages.filter((m) => m[c.key]).length} | ${total} |`);
  const none = messages.filter((m) => !COLUMNS.some((c) => m[c.key]));
  const both = messages.filter((m) => COLUMNS.every((c) => m[c.key]));
  lines.push('', `${both.length} messages are named by all four; ${none.length} by none of them (defined in the spec, implemented nowhere yet).`, '');
  const sections = [...new Set(messages.map((m) => m.section))];
  lines.push('## Per message', '');
  for (const section of sections) {
    lines.push(`### ${section}`, '', `| message | code | ${COLUMNS.map((c) => c.label).join(' | ')} |`, `| --- | --- | ${COLUMNS.map(() => ':---:').join(' | ')} |`);
    for (const m of messages.filter((x) => x.section === section)) lines.push(`| ${m.name} | ${hex(m.code)} | ${COLUMNS.map((c) => mark(m[c.key])).join(' | ')} |`);
    lines.push('');
  }
  lines.push('## Defined but named by no implementation', '');
  lines.push(none.length ? none.map((m) => `${m.name} (${hex(m.code)}, ${m.section})`).join(', ') + '.' : 'None.', '');
  return `${lines.join('\n')}`;
}

export async function check() {
  const matrix = await buildMatrix();
  const problems = [];
  if (matrix.unclassified.length) problems.push(`source files not classified in scripts/message-matrix.mjs (FILES): ${matrix.unclassified.join(', ')}`);
  const missing = matrix.messages.filter((m) => m.code === null || m.key === undefined);
  if (missing.length) problems.push(`spec messages without a code or a generated MSG key: ${missing.map((m) => m.name).join(', ')} (run \`npm run codegen\`)`);
  const want = render(matrix);
  const have = await readFile(OUT, 'utf8').catch(() => '');
  if (have !== want) problems.push('spec/message-matrix.md is stale: run `npm run matrix` and commit the result');
  return problems;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.includes('--check')) {
    const problems = await check();
    if (problems.length) { console.error(problems.join('\n')); process.exitCode = 1; } else console.log('message matrix: up to date');
  } else {
    const matrix = await buildMatrix();
    if (matrix.unclassified.length) { console.error(`source files not classified in scripts/message-matrix.mjs (FILES): ${matrix.unclassified.join(', ')}`); process.exitCode = 1; }
    else { await writeFile(OUT, render(matrix)); console.log(`wrote ${path.relative(ROOT, OUT)} (${matrix.messages.length} messages)`); }
  }
}
