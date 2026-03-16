#!/usr/bin/env node
/**
 * wsh protocol codegen — reads wsh-v1.yaml, emits JS + Rust + Markdown.
 *
 * Usage: node web/packages/wsh/spec/codegen.mjs
 *
 * Zero npm dependencies — uses only node:fs and node:path, plus a minimal
 * inline YAML parser sufficient for the schema subset we use.
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../../..');

// ── Minimal YAML parser ─────────────────────────────────────────────
// Handles: scalars, quoted strings, inline arrays [a, b], nested maps.
// Sufficient for our schema. Not a general-purpose YAML parser.

function parseYaml(text) {
  const lines = text.split('\n');
  return parseBlock(lines, 0, -1).value;
}

function parseBlock(lines, start, parentIndent) {
  const obj = {};
  let i = start;
  while (i < lines.length) {
    const line = lines[i];
    // Skip blank lines and comments
    if (/^\s*(#|$)/.test(line)) { i++; continue; }

    const indent = line.search(/\S/);
    if (indent <= parentIndent) break;

    // Key: value
    const m = line.match(/^(\s*)([A-Za-z_][\w]*)\s*:\s*(.*)/);
    if (!m) { i++; continue; }

    const key = m[2];
    const rest = m[3].trim();

    if (rest === '' || rest.startsWith('#')) {
      // Block value — recurse
      const child = parseBlock(lines, i + 1, indent);
      obj[key] = child.value;
      i = child.next;
    } else {
      // Inline value
      obj[key] = parseScalar(rest);
      i++;
    }
  }
  return { value: obj, next: i };
}

function parseScalar(s) {
  // Remove trailing comment
  // Be careful with strings containing # inside quotes
  if (s.startsWith('"') || s.startsWith("'")) {
    // Quoted string
    const quote = s[0];
    const end = s.indexOf(quote, 1);
    if (end > 0) return s.slice(1, end).replace(/\\0/g, '\0').replace(/\\n/g, '\n').replace(/\\"/g, '"');
    return s.slice(1);
  }

  // Inline empty object {}
  if (s === '{}') return {};

  // Inline array [a, b, c]
  if (s.startsWith('[')) {
    const inner = s.slice(1, s.lastIndexOf(']')).trim();
    if (inner === '') return [];
    return inner.split(',').map(v => parseScalar(v.trim()));
  }

  // Boolean / null
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (s === 'null') return null;

  // Hex number
  if (/^0x[0-9a-fA-F]+$/.test(s)) return parseInt(s, 16);

  // Decimal number
  if (/^-?\d+(\.\d+)?$/.test(s)) return parseFloat(s);

  // Remove trailing comment from unquoted string
  const commentIdx = s.indexOf(' #');
  if (commentIdx > 0) s = s.slice(0, commentIdx).trim();

  return s;
}

// ── Load schema ──────────────────────────────────────────────────────

const yamlPath = join(__dirname, 'wsh-v1.yaml');
const schema = parseYaml(readFileSync(yamlPath, 'utf8'));

// Flatten all messages from categories into a single ordered list
function flattenMessages(schema) {
  const msgs = [];
  for (const [category, catMsgs] of Object.entries(schema.messages)) {
    for (const [name, def] of Object.entries(catMsgs)) {
      msgs.push({ name, category, ...def });
    }
  }
  msgs.sort((a, b) => a.code - b.code);
  return msgs;
}

const allMessages = flattenMessages(schema);

// ── Naming helpers ───────────────────────────────────────────────────

/** PascalCase → SCREAMING_SNAKE_CASE */
function toScreamingSnake(name) {
  return name.replace(/([a-z])([A-Z])/g, '$1_$2')
             .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
             .toUpperCase();
}

/** PascalCase → camelCase */
function toCamelCase(name) {
  return name[0].toLowerCase() + name.slice(1);
}

/** snake_case → camelCase */
function snakeToCamel(s) {
  return s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
}

// ── JS Emitter ───────────────────────────────────────────────────────

function emitJS(schema) {
  const out = [];
  const NL = '\n';

  out.push('/**');
  out.push(' * wsh protocol control message types and constructors.');
  out.push(' * AUTO-GENERATED from wsh-v1.yaml — do not edit.');
  out.push(' * Run: node web/packages/wsh/spec/codegen.mjs');
  out.push(' */');
  out.push('');

  // MSG constants
  out.push('// ── Message type constants ────────────────────────────────────────────');
  out.push('');
  out.push('export const MSG = Object.freeze({');

  let lastCategory = null;
  for (const msg of allMessages) {
    if (msg.category !== lastCategory) {
      if (lastCategory !== null) out.push('');
      out.push(`  // ${msg.category[0].toUpperCase() + msg.category.slice(1)}`);
      lastCategory = msg.category;
    }
    const constName = toScreamingSnake(msg.name);
    const hex = '0x' + msg.code.toString(16).padStart(2, '0');
    out.push(`  ${(constName + ':').padEnd(18)} ${hex},`);
  }
  out.push('});');
  out.push('');

  // MSG_NAMES reverse lookup
  out.push('// Reverse lookup: number → name');
  out.push('export const MSG_NAMES = Object.freeze(');
  out.push('  Object.fromEntries(Object.entries(MSG).map(([k, v]) => [v, k]))');
  out.push(');');
  out.push('');

  // Channel kind enum
  out.push('// ── Channel kinds ─────────────────────────────────────────────────────');
  out.push('');
  out.push('export const CHANNEL_KIND = Object.freeze({');
  for (const v of schema.enums.ChannelKind.values) {
    out.push(`  ${(v.toUpperCase() + ':').padEnd(6)} '${v}',`);
  }
  out.push('});');
  out.push('');

  // Auth method enum
  out.push('// ── Auth methods ──────────────────────────────────────────────────────');
  out.push('');
  out.push('export const AUTH_METHOD = Object.freeze({');
  for (const v of schema.enums.AuthMethod.values) {
    out.push(`  ${(v.toUpperCase() + ':').padEnd(10)} '${v}',`);
  }
  out.push('});');
  out.push('');

  // Protocol version
  out.push('// ── Protocol version ──────────────────────────────────────────────────');
  out.push('');
  out.push(`export const PROTOCOL_VERSION = '${schema.protocol.version}';`);
  out.push('');

  // Message constructors
  out.push('// ── Message constructors ──────────────────────────────────────────────');
  out.push('');

  for (const msg of allMessages) {
    // Skip WsData — it's a framing marker, not a CBOR message
    if (msg.name === 'WsData') continue;

    const fnName = toCamelCase(msg.name);
    const constName = toScreamingSnake(msg.name);
    const fields = msg.fields || {};
    const fieldEntries = Object.entries(fields);

    if (fieldEntries.length === 0) {
      // No-arg constructor
      out.push(`export function ${fnName}() {`);
      out.push(`  return { type: MSG.${constName} };`);
      out.push('}');
      out.push('');
      continue;
    }

    // ── Special case: Auth (conditional fields based on method) ───────
    if (msg.name === 'Auth') {
      out.push('export function auth({ method, signature, publicKey, password } = {}) {');
      out.push('  const msg = { type: MSG.AUTH, method };');
      out.push('  if (method === AUTH_METHOD.PUBKEY) {');
      out.push('    msg.signature = signature;');
      out.push('    msg.public_key = publicKey;');
      out.push('  } else if (method === AUTH_METHOD.PASSWORD) {');
      out.push('    msg.password = password;');
      out.push('  }');
      out.push('  return msg;');
      out.push('}');
      out.push('');
      continue;
    }

    // ── Special case: Hello (version auto-filled, authMethod always set) ──
    if (msg.name === 'Hello') {
      out.push('export function hello({ username, features = [], authMethod = AUTH_METHOD.PUBKEY } = {}) {');
      out.push('  return {');
      out.push('    type: MSG.HELLO,');
      out.push('    version: PROTOCOL_VERSION,');
      out.push('    username,');
      out.push('    features,');
      out.push('    auth_method: authMethod,');
      out.push('  };');
      out.push('}');
      out.push('');
      continue;
    }

    // ── Special case: McpCall (arguments is a reserved word) ─────────
    if (msg.name === 'McpCall') {
      out.push('export function mcpCall({ tool, arguments: args } = {}) {');
      out.push('  return { type: MSG.MCP_CALL, tool, arguments: args };');
      out.push('}');
      out.push('');
      continue;
    }

    // ── Special case: AuthMethods (custom default) ───────────────────
    if (msg.name === 'AuthMethods') {
      out.push('export function authMethods({ methods = [AUTH_METHOD.PUBKEY] } = {}) {');
      out.push('  return {');
      out.push('    type: MSG.AUTH_METHODS,');
      out.push('    methods,');
      out.push('  };');
      out.push('}');
      out.push('');
      continue;
    }

    // ── General case ─────────────────────────────────────────────────

    // Classify fields
    const optionalNoDefault = []; // fields with required:false and no default → conditional
    const allParams = [];

    for (const [fieldName, fieldDef] of fieldEntries) {
      const camelName = snakeToCamel(fieldName);
      const isRequired = fieldDef.required === true;
      const hasDefault = 'default' in fieldDef;

      if (hasDefault) {
        const def = fieldDef.default;
        if (def === '[]') allParams.push(`${camelName} = []`);
        else if (def === '{}') allParams.push(`${camelName} = {}`);
        else if (typeof def === 'string' && def.startsWith('"')) {
          allParams.push(`${camelName} = ${def}`);
        } else {
          allParams.push(`${camelName} = ${def}`);
        }
      } else {
        allParams.push(camelName);
      }

      if (!isRequired && !hasDefault) {
        optionalNoDefault.push({ fieldName, camelName });
      }
    }

    out.push(`export function ${fnName}({ ${allParams.join(', ')} } = {}) {`);

    if (optionalNoDefault.length > 0) {
      // Build initial msg with required/default fields, then conditional adds
      const initFields = fieldEntries.filter(([, fd]) =>
        fd.required === true || 'default' in fd
      );

      out.push(`  const msg = { type: MSG.${constName}, ${initFields.map(([fn]) => {
        const cn = snakeToCamel(fn);
        return fn === cn ? fn : `${fn}: ${cn}`;
      }).join(', ')} };`);

      for (const { fieldName, camelName } of optionalNoDefault) {
        out.push(`  if (${camelName} !== undefined) msg.${fieldName} = ${camelName};`);
      }
      out.push('  return msg;');
    } else {
      // Simple object literal return
      out.push('  return {');
      out.push(`    type: MSG.${constName},`);
      for (const [fn] of fieldEntries) {
        const cn = snakeToCamel(fn);
        if (fn === cn) {
          out.push(`    ${fn},`);
        } else {
          out.push(`    ${fn}: ${cn},`);
        }
      }
      out.push('  };');
    }

    out.push('}');
    out.push('');
  }

  // Utility functions
  out.push('// ── Utility ───────────────────────────────────────────────────────────');
  out.push('');
  out.push('/**');
  out.push(' * Get the human-readable name for a message type number.');
  out.push(' * @param {number} typeNum');
  out.push(' * @returns {string}');
  out.push(' */');
  out.push('export function msgName(typeNum) {');
  out.push("  return MSG_NAMES[typeNum] || `UNKNOWN(0x${typeNum.toString(16)})`;");
  out.push('}');
  out.push('');
  out.push('/**');
  out.push(' * Validate that a message has a recognized type field.');
  out.push(' * @param {object} msg');
  out.push(' * @returns {boolean}');
  out.push(' */');
  out.push('export function isValidMessage(msg) {');
  out.push("  return msg != null && typeof msg === 'object' && typeof msg.type === 'number' && msg.type in MSG_NAMES;");
  out.push('}');
  out.push('');

  return out.join(NL);
}

// ── Rust default-value helpers ────────────────────────────────────────

/** PascalCase → snake_case */
function toSnakeCase(name) {
  return name.replace(/([a-z])([A-Z])/g, '$1_$2')
             .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
             .toLowerCase();
}

/**
 * Check if a YAML default differs from the Rust type's Default trait.
 * Trivial defaults: "" for String, 0 for numbers, [] for Vec, {} for json.
 */
function isNonTrivialDefault(yamlType, defaultVal) {
  // String type: trivial default is ""
  if (yamlType === 'string' || yamlType === 'ChannelKind' || yamlType === 'AuthMethod') {
    return typeof defaultVal === 'string' && defaultVal !== '' && defaultVal !== '""';
  }
  // Numeric types: trivial default is 0
  if (['u8', 'u16', 'u32', 'u64', 'i32', 'f64'].includes(yamlType)) {
    return defaultVal !== 0;
  }
  // Array types: trivial default is []
  if (yamlType.endsWith('[]')) {
    if (typeof defaultVal === 'string' && (defaultVal === '[]' || defaultVal === '"[]"')) return false;
    if (Array.isArray(defaultVal) && defaultVal.length === 0) return false;
    // String-encoded non-empty arrays like '["read"]' are non-trivial
    if (typeof defaultVal === 'string' && defaultVal.startsWith('[') && defaultVal !== '[]') return true;
    return Array.isArray(defaultVal) && defaultVal.length > 0;
  }
  // JSON: trivial default is {}
  if (yamlType === 'json') {
    if (typeof defaultVal === 'object' && Object.keys(defaultVal).length === 0) return false;
    if (defaultVal === '{}') return false;
    return true;
  }
  return false;
}

/**
 * Emit a Rust default function body for a non-trivial YAML default.
 */
function emitDefaultFn(fnName, rustTypeName, yamlType, defaultVal) {
  // String defaults
  if (yamlType === 'string') {
    const strVal = typeof defaultVal === 'string' ? defaultVal.replace(/^"|"$/g, '') : String(defaultVal);
    return `fn ${fnName}() -> ${rustTypeName} {\n    "${strVal}".to_string()\n}`;
  }
  // Numeric defaults
  if (['u8', 'u16', 'u32', 'u64', 'i32', 'f64'].includes(yamlType)) {
    return `fn ${fnName}() -> ${rustTypeName} {\n    ${defaultVal}\n}`;
  }
  // String array with values (may be parsed as actual array or as string '["read"]')
  if (yamlType === 'string[]') {
    let items;
    if (Array.isArray(defaultVal)) {
      items = defaultVal;
    } else if (typeof defaultVal === 'string' && defaultVal.startsWith('[')) {
      // Parse string-encoded array like '["read"]'
      try { items = JSON.parse(defaultVal); } catch { items = []; }
    }
    if (items && items.length > 0) {
      const rustItems = items.map(v => {
        const s = typeof v === 'string' ? v.replace(/^"|"$/g, '') : String(v);
        return `"${s}".to_string()`;
      }).join(', ');
      return `fn ${fnName}() -> ${rustTypeName} {\n    vec![${rustItems}]\n}`;
    }
  }
  // AuthMethod array
  if (yamlType === 'AuthMethod[]') {
    let items;
    if (Array.isArray(defaultVal)) {
      items = defaultVal;
    } else if (typeof defaultVal === 'string' && defaultVal.startsWith('[')) {
      try { items = JSON.parse(defaultVal); } catch { items = []; }
    }
    if (items && items.length > 0) {
      const rustItems = items.map(v => {
        const s = typeof v === 'string' ? v.replace(/^"|"$/g, '') : String(v);
        return `AuthMethod::${s[0].toUpperCase() + s.slice(1)}`;
      }).join(', ');
      return `fn ${fnName}() -> ${rustTypeName} {\n    vec![${rustItems}]\n}`;
    }
  }
  // Fallback: bare default
  return `fn ${fnName}() -> ${rustTypeName} {\n    Default::default()\n}`;
}

// ── Rust Emitter ─────────────────────────────────────────────────────

function rustType(yamlType, required, hasDefault) {
  const inner = rustInnerType(yamlType);
  // Optional (no default) → Option<T>
  // Has default → T (with #[serde(default)])
  // Required → T
  if (required === false && !hasDefault && !yamlType.endsWith('[]') && yamlType !== 'json') {
    return `Option<${inner}>`;
  }
  return inner;
}

function rustInnerType(yamlType) {
  if (yamlType === 'string') return 'String';
  if (yamlType === 'bytes') return 'Vec<u8>';
  if (yamlType === 'bool') return 'bool';
  if (yamlType === 'u8') return 'u8';
  if (yamlType === 'u16') return 'u16';
  if (yamlType === 'u32') return 'u32';
  if (yamlType === 'u64') return 'u64';
  if (yamlType === 'i32') return 'i32';
  if (yamlType === 'f64') return 'f64';
  if (yamlType === 'json') return 'serde_json::Value';
  if (yamlType === 'ChannelKind') return 'ChannelKind';
  if (yamlType === 'AuthMethod') return 'AuthMethod';
  if (yamlType === 'string[]') return 'Vec<String>';
  if (yamlType === 'u32[]') return 'Vec<u32>';
  if (yamlType === 'AuthMethod[]') return 'Vec<AuthMethod>';
  if (yamlType === 'AttachmentInfo[]') return 'Vec<AttachmentInfo>';
  if (yamlType === 'SessionSummary[]') return 'Vec<SessionSummary>';
  if (yamlType === 'PeerInfo[]') return 'Vec<PeerInfo>';
  if (yamlType === 'McpToolSpec[]') return 'Vec<McpToolSpec>';
  if (yamlType === 'map<string,string>') return 'std::collections::HashMap<String, String>';
  return yamlType; // nested type reference
}

function isBytesField(yamlType) {
  return yamlType === 'bytes';
}

function emitRust(schema) {
  const out = [];

  out.push('// wsh protocol control message types.');
  out.push('// AUTO-GENERATED from wsh-v1.yaml — do not edit.');
  out.push('// Run: node web/packages/wsh/spec/codegen.mjs');
  out.push('');
  out.push('use serde::{Deserialize, Serialize};');
  out.push('');

  // Rust messages exclude WsData (it's a JS-only framing marker)
  const rustMessages = allMessages.filter(m => m.category !== 'framing');

  // MsgType enum
  out.push('/// Numeric message type tags — must match JS `MSG` constants.');
  out.push('#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]');
  out.push('#[serde(into = "u8", try_from = "u8")]');
  out.push('#[repr(u8)]');
  out.push('pub enum MsgType {');
  let lastCat = null;
  for (const msg of rustMessages) {
    if (msg.category !== lastCat) {
      if (lastCat !== null) out.push('');
      lastCat = msg.category;
    }
    const hex = '0x' + msg.code.toString(16).padStart(2, '0');
    out.push(`    ${msg.name} = ${hex},`);
  }
  out.push('}');
  out.push('');

  // From<MsgType> for u8
  out.push('impl From<MsgType> for u8 {');
  out.push('    fn from(m: MsgType) -> u8 {');
  out.push('        m as u8');
  out.push('    }');
  out.push('}');
  out.push('');

  // TryFrom<u8> for MsgType
  out.push('impl TryFrom<u8> for MsgType {');
  out.push('    type Error = String;');
  out.push('    fn try_from(v: u8) -> Result<Self, String> {');
  out.push('        match v {');
  for (const msg of rustMessages) {
    const hex = '0x' + msg.code.toString(16).padStart(2, '0');
    out.push(`            ${hex} => Ok(Self::${msg.name}),`);
  }
  out.push('            _ => Err(format!("unknown message type: 0x{v:02x}")),');
  out.push('        }');
  out.push('    }');
  out.push('}');
  out.push('');

  // Enums
  for (const [enumName, enumDef] of Object.entries(schema.enums)) {
    out.push(`/// ${enumName} enum.`);
    out.push('#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]');
    out.push('#[serde(rename_all = "lowercase")]');
    out.push(`pub enum ${enumName} {`);
    for (const [index, v] of enumDef.values.entries()) {
      if (index === 0) {
        out.push('    #[default]');
      }
      out.push(`    ${v[0].toUpperCase() + v.slice(1)},`);
    }
    out.push('}');
    out.push('');
  }

  // Protocol version
  out.push('/// Protocol version string.');
  out.push(`pub const PROTOCOL_VERSION: &str = "${schema.protocol.version}";`);
  out.push('');

  // Envelope
  out.push('// ── Message payloads ──────────────────────────────────────────────────');
  out.push('');
  out.push('/// Envelope: every control message has a `type` plus a payload.');
  out.push('#[derive(Debug, Clone, Serialize, Deserialize)]');
  out.push('pub struct Envelope {');
  out.push('    #[serde(rename = "type")]');
  out.push('    pub msg_type: MsgType,');
  out.push('');
  out.push('    #[serde(flatten)]');
  out.push('    pub payload: Payload,');
  out.push('}');
  out.push('');

  // Payload enum
  // Determine which messages share a payload struct (Ping/Pong share PingPong)
  const payloadVariants = [];
  const seenPingPong = { added: false };

  for (const msg of rustMessages) {
    // Ping and Pong share PingPongPayload
    if (msg.name === 'Ping' || msg.name === 'Pong') {
      if (!seenPingPong.added) {
        payloadVariants.push({ variantName: 'PingPong', payloadName: 'PingPongPayload' });
        seenPingPong.added = true;
      }
      continue;
    }

    const fields = msg.fields || {};
    if (Object.keys(fields).length === 0) {
      // Empty payload messages get a shared Empty variant
      // Actually from the Rust code, McpDiscover, ReverseList each get their own payload struct
      payloadVariants.push({ variantName: msg.name, payloadName: `${msg.name}Payload` });
      continue;
    }

    payloadVariants.push({ variantName: msg.name, payloadName: `${msg.name}Payload` });
  }

  out.push('/// All possible message payloads (untagged for CBOR compatibility).');
  out.push('#[derive(Debug, Clone, Serialize, Deserialize)]');
  out.push('#[serde(untagged)]');
  out.push('pub enum Payload {');
  for (const { variantName, payloadName } of payloadVariants) {
    out.push(`    ${variantName}(${payloadName}),`);
  }
  out.push('    Empty(EmptyPayload),');
  out.push('}');
  out.push('');

  out.push('impl Payload {');
  out.push('    pub fn decode_for_msg_type(');
  out.push('        msg_type: MsgType,');
  out.push('        data: &[u8],');
  out.push('    ) -> Result<Self, ciborium::de::Error<std::io::Error>> {');
  out.push('        let cursor = std::io::Cursor::new(data);');
  out.push('        match msg_type {');
  out.push('            MsgType::Ping | MsgType::Pong => Ok(Self::PingPong(ciborium::from_reader(cursor)?)),');
  for (const msg of rustMessages) {
    if (msg.name === 'Ping' || msg.name === 'Pong') continue;
    out.push(`            MsgType::${msg.name} => Ok(Self::${msg.name}(ciborium::from_reader(cursor)?)),`);
  }
  out.push('        }');
  out.push('    }');
  out.push('}');
  out.push('');

  // Payload structs
  out.push('// ── Individual payload structs ────────────────────────────────────────');
  out.push('');

  // EmptyPayload
  out.push('#[derive(Debug, Clone, Serialize, Deserialize)]');
  out.push('#[serde(deny_unknown_fields)]');
  out.push('pub struct EmptyPayload {}');
  out.push('');

  // PingPongPayload (shared)
  out.push('#[derive(Debug, Clone, Serialize, Deserialize)]');
  out.push('#[serde(deny_unknown_fields)]');
  out.push('pub struct PingPongPayload {');
  out.push('    pub id: u64,');
  out.push('}');
  out.push('');

  // Track custom default functions to emit after each struct
  for (const msg of rustMessages) {
    if (msg.name === 'Ping' || msg.name === 'Pong') continue;

    const fields = msg.fields || {};
    const fieldEntries = Object.entries(fields);
    const defaultFns = []; // collect {fnName, rustCode} for after the struct

    out.push('#[derive(Debug, Clone, Serialize, Deserialize)]');
    out.push('#[serde(deny_unknown_fields)]');
    out.push(`pub struct ${msg.name}Payload {`);

    if (fieldEntries.length === 0) {
      // empty struct body
    } else {
      for (const [fieldName, fieldDef] of fieldEntries) {
        const isRequired = fieldDef.required === true;
        const hasDefault = 'default' in fieldDef;
        const rType = rustType(fieldDef.type, isRequired, hasDefault);
        const isBytes = isBytesField(fieldDef.type);

        // serde attributes
        const attrs = [];

        if (hasDefault && !isBytes) {
          // Check if the default is non-trivial (differs from Rust's Default trait)
          const needsCustomDefault = isNonTrivialDefault(fieldDef.type, fieldDef.default);
          if (needsCustomDefault) {
            const fnName = `default_${toSnakeCase(msg.name)}_${fieldName}`;
            attrs.push(`default = "${fnName}"`);
            defaultFns.push({
              fnName,
              rustCode: emitDefaultFn(fnName, rType, fieldDef.type, fieldDef.default),
            });
          } else {
            attrs.push('default');
          }
        }

        if (!isRequired && !hasDefault) {
          attrs.push('default');
          attrs.push('skip_serializing_if = "Option::is_none"');
        }

        // Bytes handling
        if (isBytes && isRequired) {
          attrs.push('with = "serde_bytes"');
        } else if (isBytes && !isRequired) {
          attrs.length = 0; // rebuild
          attrs.push('default');
          attrs.push('skip_serializing_if = "Option::is_none"');
          attrs.push('with = "option_bytes"');
        }

        if (attrs.length > 0) {
          out.push(`    #[serde(${attrs.join(', ')})]`);
        }

        out.push(`    pub ${fieldName}: ${rType},`);
      }
    }

    out.push('}');
    out.push('');

    // Emit any custom default functions after the struct
    for (const { rustCode } of defaultFns) {
      out.push(rustCode);
      out.push('');
    }
  }

  // Nested types
  for (const [typeName, typeDef] of Object.entries(schema.nested_types)) {
    out.push('#[derive(Debug, Clone, Serialize, Deserialize)]');
    out.push(`pub struct ${typeName} {`);

    for (const [fieldName, fieldDef] of Object.entries(typeDef.fields)) {
      const isRequired = fieldDef.required === true;
      const hasDefault = 'default' in fieldDef;
      const rType = rustType(fieldDef.type, isRequired, hasDefault);

      const attrs = [];
      if (hasDefault) {
        attrs.push('default');
      }
      if (!isRequired && !hasDefault) {
        attrs.push('default');
        attrs.push('skip_serializing_if = "Option::is_none"');
      }

      if (attrs.length > 0) {
        out.push(`    #[serde(${attrs.join(', ')})]`);
      }
      out.push(`    pub ${fieldName}: ${rType},`);
    }

    out.push('}');
    out.push('');
  }

  // option_bytes module
  out.push('// ── Helper for optional bytes serde ──────────────────────────────────');
  out.push('');
  out.push('mod option_bytes {');
  out.push('    use serde::{self, Deserialize, Deserializer, Serializer};');
  out.push('');
  out.push('    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>');
  out.push('    where');
  out.push('        S: Serializer,');
  out.push('    {');
  out.push('        match value {');
  out.push('            Some(bytes) => super::serde_bytes::serialize(bytes, serializer),');
  out.push('            None => serializer.serialize_none(),');
  out.push('        }');
  out.push('    }');
  out.push('');
  out.push("    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>");
  out.push('    where');
  out.push("        D: Deserializer<'de>,");
  out.push('    {');
  out.push("        let opt: Option<super::serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;");
  out.push('        Ok(opt.map(|b: super::serde_bytes::ByteBuf| b.into_vec()))');
  out.push('    }');
  out.push('}');
  out.push('');

  // serde_bytes module
  out.push('// serde_json::Value is used in McpToolSpec / McpCallPayload / McpResultPayload.');
  out.push('');
  out.push('mod serde_bytes {');
  out.push('    use serde::{self, Deserialize, Deserializer, Serializer};');
  out.push('');
  out.push('    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>');
  out.push('    where');
  out.push('        S: Serializer,');
  out.push('    {');
  out.push('        serializer.serialize_bytes(bytes)');
  out.push('    }');
  out.push('');
  out.push("    #[allow(dead_code)]");
  out.push("    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>");
  out.push('    where');
  out.push("        D: Deserializer<'de>,");
  out.push('    {');
  out.push('        let buf: ByteBuf = Deserialize::deserialize(deserializer)?;');
  out.push('        Ok(buf.into_vec())');
  out.push('    }');
  out.push('');
  out.push('    #[derive(Debug)]');
  out.push('    pub struct ByteBuf(Vec<u8>);');
  out.push('');
  out.push('    impl ByteBuf {');
  out.push('        pub fn into_vec(self) -> Vec<u8> {');
  out.push('            self.0');
  out.push('        }');
  out.push('    }');
  out.push('');
  out.push("    impl<'de> Deserialize<'de> for ByteBuf {");
  out.push('        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>');
  out.push('        where');
  out.push("            D: Deserializer<'de>,");
  out.push('        {');
  out.push('            struct ByteBufVisitor;');
  out.push('');
  out.push("            impl<'de> serde::de::Visitor<'de> for ByteBufVisitor {");
  out.push('                type Value = ByteBuf;');
  out.push('');
  out.push("                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {");
  out.push('                    formatter.write_str("bytes")');
  out.push('                }');
  out.push('');
  out.push('                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> {');
  out.push('                    Ok(ByteBuf(v.to_vec()))');
  out.push('                }');
  out.push('');
  out.push('                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E> {');
  out.push('                    Ok(ByteBuf(v))');
  out.push('                }');
  out.push('');
  out.push("                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>");
  out.push('                where');
  out.push("                    A: serde::de::SeqAccess<'de>,");
  out.push('                {');
  out.push('                    let mut bytes = Vec::new();');
  out.push('                    while let Some(b) = seq.next_element::<u8>()? {');
  out.push('                        bytes.push(b);');
  out.push('                    }');
  out.push('                    Ok(ByteBuf(bytes))');
  out.push('                }');
  out.push('            }');
  out.push('');
  out.push('            deserializer.deserialize_any(ByteBufVisitor)');
  out.push('        }');
  out.push('    }');
  out.push('}');
  out.push('');

  return out.join('\n');
}

// ── Markdown Emitter ─────────────────────────────────────────────────

function emitMarkdown(schema) {
  const out = [];
  const ver = schema.protocol.version;

  out.push(`# ${schema.protocol.name} Protocol Specification — ${ver}`);
  out.push('');
  out.push('> Auto-generated from `wsh-v1.yaml`. Do not edit.');
  out.push('> Run: `node web/packages/wsh/spec/codegen.mjs`');
  out.push('');

  // TOC
  out.push('## Table of Contents');
  out.push('');
  out.push('1. [Overview](#overview)');
  out.push('2. [Enums](#enums)');
  out.push('3. [Message Types](#message-types)');
  out.push('4. [Message Details](#message-details)');
  out.push('5. [Nested Types](#nested-types)');
  out.push('6. [Crypto Primitives](#crypto-primitives)');
  out.push('7. [Transport Bindings](#transport-bindings)');
  out.push('');

  // Overview
  out.push('## Overview');
  out.push('');
  out.push(`- **Protocol**: ${schema.protocol.name}`);
  out.push(`- **Version**: \`${ver}\``);
  out.push(`- **Wire format**: ${schema.protocol.wire_format.toUpperCase()}`);
  out.push(`- **Framing**: ${schema.protocol.framing.replace(/_/g, ' ')}`);
  out.push(`- **Total message types**: ${allMessages.length} (including WS_DATA framing marker)`);
  out.push('');

  // Enums
  out.push('## Enums');
  out.push('');
  for (const [name, def] of Object.entries(schema.enums)) {
    out.push(`### ${name}`);
    out.push('');
    out.push(`Type: \`${def.type}\``);
    out.push('');
    out.push('| Value |');
    out.push('|-------|');
    for (const v of def.values) {
      out.push(`| \`${v}\` |`);
    }
    out.push('');
  }

  // Message types table
  out.push('## Message Types');
  out.push('');
  out.push('| Code | Name | Category |');
  out.push('|------|------|----------|');
  for (const msg of allMessages) {
    const hex = '0x' + msg.code.toString(16).padStart(2, '0');
    out.push(`| \`${hex}\` | ${msg.name} | ${msg.category} |`);
  }
  out.push('');

  // Message details
  out.push('## Message Details');
  out.push('');

  for (const msg of allMessages) {
    const hex = '0x' + msg.code.toString(16).padStart(2, '0');
    out.push(`### ${msg.name} (\`${hex}\`)`);
    out.push('');
    out.push(`Category: **${msg.category}**`);
    if (msg.description) {
      out.push('');
      out.push(`> ${msg.description}`);
    }
    out.push('');

    const fields = msg.fields || {};
    const fieldEntries = Object.entries(fields);

    if (fieldEntries.length === 0) {
      out.push('*No fields.*');
    } else {
      out.push('| Field | Type | Required | Default |');
      out.push('|-------|------|----------|---------|');
      for (const [fn, fd] of fieldEntries) {
        const req = fd.required === true ? 'yes' : 'no';
        const def = 'default' in fd ? `\`${fd.default}\`` : '—';
        out.push(`| \`${fn}\` | \`${fd.type}\` | ${req} | ${def} |`);
      }
    }
    out.push('');
  }

  // Nested types
  out.push('## Nested Types');
  out.push('');

  for (const [name, def] of Object.entries(schema.nested_types)) {
    out.push(`### ${name}`);
    out.push('');
    out.push('| Field | Type | Required | Default |');
    out.push('|-------|------|----------|---------|');
    for (const [fn, fd] of Object.entries(def.fields)) {
      const req = fd.required === true ? 'yes' : 'no';
      const def2 = 'default' in fd ? `\`${fd.default}\`` : '—';
      out.push(`| \`${fn}\` | \`${fd.type}\` | ${req} | ${def2} |`);
    }
    out.push('');
  }

  // Crypto
  out.push('## Crypto Primitives');
  out.push('');

  const crypto = schema.crypto;
  out.push('### Auth Transcript');
  out.push('');
  out.push(`- **Algorithm**: ${crypto.auth_transcript.algorithm}`);
  out.push(`- **Formula**: \`${crypto.auth_transcript.formula}\``);
  if (crypto.auth_transcript.note) {
    out.push(`- **Note**: ${crypto.auth_transcript.note}`);
  }
  out.push('');

  out.push('### Fingerprint');
  out.push('');
  out.push(`- **Algorithm**: ${crypto.fingerprint.algorithm}`);
  out.push(`- **Input**: ${crypto.fingerprint.input}`);
  out.push(`- **Output**: ${crypto.fingerprint.output}`);
  out.push('');

  out.push('### Session Token');
  out.push('');
  out.push(`- **Format**: \`${crypto.session_token.format}\``);
  out.push(`- **Total bytes**: ${crypto.session_token.total_bytes}`);
  out.push('');

  out.push(`### Key Type: ${crypto.key_type}`);
  out.push('');
  out.push(`- **SSH wire format**: \`${crypto.ssh_wire_format}\``);
  out.push('');

  // Transport
  out.push('## Transport Bindings');
  out.push('');

  out.push('### WebTransport');
  out.push('');
  out.push(schema.transport.webtransport.description);
  out.push('');

  out.push('### WebSocket');
  out.push('');
  out.push(`- **Framing**: \`${schema.transport.websocket.framing}\``);
  out.push(`- **WS_DATA type**: \`0x${schema.transport.websocket.ws_data_type.toString(16).padStart(2, '0')}\``);
  out.push('');

  return out.join('\n');
}

// ── Main ─────────────────────────────────────────────────────────────

const jsOutput = emitJS(schema);
const rustOutput = emitRust(schema);
const mdOutput = emitMarkdown(schema);

// Write outputs
const jsPath = join(ROOT, 'web/packages/wsh/src/messages.gen.mjs');
const rsPath = join(ROOT, 'crates/wsh-core/src/messages.gen.rs');
const mdPath = join(__dirname, 'wsh-v1.md');

mkdirSync(dirname(jsPath), { recursive: true });
mkdirSync(dirname(rsPath), { recursive: true });

writeFileSync(jsPath, jsOutput);
writeFileSync(rsPath, rustOutput);
writeFileSync(mdPath, mdOutput);

console.log(`✓ JS  → ${jsPath}`);
console.log(`✓ Rust → ${rsPath}`);
console.log(`✓ Spec → ${mdPath}`);
console.log(`  ${allMessages.length} message types generated.`);
