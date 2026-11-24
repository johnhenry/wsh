// test/message-matrix.test.mjs -- #129: spec/message-matrix.md is generated from the spec and from what each implementation
// names (scripts/message-matrix.mjs), and this test fails when it is stale. CI runs it as part of `npm test` and again as
// `npm run matrix:check`.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { MSG } from '../src/messages.gen.mjs';
import {
  OUT, buildMatrix, render, check, parseSpecMessages, parseGeneratedJs, jsNames, rustNames, stripRust, COLUMNS,
} from '../scripts/message-matrix.mjs';

describe('message matrix: the check', () => {
  it('spec/message-matrix.md is current, and every source file is classified (run `npm run matrix` if this fails)', async () => {
    assert.deepEqual(await check(), []);
  });

  it('a stale file is caught: flipping any one cell changes the rendering', async () => {
    const matrix = await buildMatrix();
    const have = await readFile(OUT, 'utf8');
    assert.equal(render(matrix), have);
    for (const col of COLUMNS) {
      const flipped = { messages: matrix.messages.map((m, i) => (i === 3 ? { ...m, [col.key]: !m[col.key] } : m)) };
      assert.notEqual(render(flipped), have, `${col.key} flipped`);
    }
  });

  it('has a row for every message of the spec and of the generated tables, with the same codes', async () => {
    const { messages } = await buildMatrix();
    assert.equal(messages.length, Object.keys(MSG).length);
    for (const m of messages) {
      assert.ok(Number.isInteger(m.code), `${m.name} has a code`);
      assert.equal(MSG[m.key], m.code, `${m.name}: spec code and MSG.${m.key} agree`);
    }
    assert.equal(new Set(messages.map((m) => m.code)).size, messages.length, 'codes are unique');
  });

  it('what every implementation must name is named: the handshake and the first channel messages', async () => {
    const { messages } = await buildMatrix();
    const by = Object.fromEntries(messages.map((m) => [m.name, m]));
    for (const name of ['Hello', 'ServerHello', 'Auth', 'Open', 'OpenOk', 'SessionData', 'Exit']) {
      for (const c of COLUMNS) assert.ok(by[name][c.key], `${name} is named by ${c.label}`);
    }
  });
});

describe('message matrix: what counts as naming a message', () => {
  it('JS: MSG.X, or a call of the builder imported from a messages module; not a comment, a string, another function of that name', () => {
    assert.ok(jsNames("switch (m.type) { case MSG.OPEN: return 1; }", 'OPEN', 'open'));
    assert.ok(jsNames("import { open as openMsg } from './messages.mjs';\nsend(openMsg({ kind }));", 'OPEN', 'open'));
    assert.ok(jsNames("import { MSG, open } from '../messages.gen.mjs';\nsend(open({ kind }));", 'OPEN', 'open'));
    assert.ok(!jsNames("// MSG.OPEN is handled elsewhere\n/* MSG.OPEN */", 'OPEN', 'open'), 'comments do not count');
    assert.ok(!jsNames("import { open } from 'node:fs/promises';\nawait open(file);", 'OPEN', 'open'), 'a function of the same name from elsewhere');
    assert.ok(!jsNames("import { open } from './messages.mjs';\n// open(x)", 'OPEN', 'open'), 'imported but never called');
    assert.ok(!jsNames('const x = MSG.OPEN_OK;', 'OPEN', 'open'), 'a longer key is another message');
  });

  it('Rust: Payload::X, MsgType::X or the XPayload struct; not a comment, a string, a test module, or another message', () => {
    assert.ok(rustNames('match p { Payload::Open(o) => 1 }', 'Open'));
    assert.ok(rustNames('let m = MsgType::Open;', 'Open'));
    assert.ok(rustNames('fn f(p: &OpenPayload) {}', 'Open'));
    assert.ok(!rustNames('// Payload::Open\nlet s = "Payload::Open";', 'Open'));
    assert.ok(!rustNames('Payload::OpenOk(x)', 'Open'), 'OpenOk is not Open');
    assert.ok(!rustNames('fn real() {}\n#[cfg(test)]\nmod tests {\n  fn t() { let _ = Payload::Open(x); }\n}\n', 'Open'), 'test code does not count');
    assert.ok(rustNames('#[cfg(test)]\nuse std::io;\nfn real() { let _ = Payload::Open(x); }\n', 'Open'), 'a cfg(test) import does not hide the code after it');
    assert.ok(rustNames('#[cfg(test)]\nmod tests { fn t() { let s = "}"; } }\nfn real() { let _ = Payload::Open(x); }\n', 'Open'), 'a brace in a string does not end a test module early');
  });

  it('stripRust keeps line structure and removes only what it should', () => {
    const src = 'a // c\nb /* x\ny */ c\n#[cfg(test)]\nmod t { fn f() {} }\nd';
    const out = stripRust(src);
    assert.equal(out.split('\n').length, src.split('\n').length);
    assert.ok(/\ba\b/.test(out) && /\bb\b/.test(out) && /\bc\b/.test(out) && /\bd\b/.test(out));
    assert.ok(!out.includes('fn f'));
  });

  it('the parsers read the spec and the generated JS', () => {
    const yaml = 'protocol:\n  name: x\nmessages:\n  one:\n    Hello:\n      code: 0x01\n      fields:\n        code:\n          type: string\n  two:\n    Open:\n      code: 16\nnested_types:\n  Thing:\n    code: 5\n';
    assert.deepEqual(parseSpecMessages(yaml), [{ name: 'Hello', code: 1, section: 'one' }, { name: 'Open', code: 16, section: 'two' }]);
    const gen = parseGeneratedJs('export const MSG = Object.freeze({\n  HELLO: 0x01,\n  OPEN: 0x10,\n});\nexport function hello({ a } = {}) {\n  return { type: MSG.HELLO };\n}\nexport function open() {\n  const msg = { type: MSG.OPEN };\n}\n');
    assert.equal(gen.keyByCode.get(16), 'OPEN');
    assert.equal(gen.builderByKey.get('HELLO'), 'hello');
  });
});
