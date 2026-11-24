/**
 * The text of a TypeScript type that a host supplies for a path (`exposeObjects({ types })`) and a client writes into a `.d.ts` file. It is HOST-AUTHORED text
 * that travels to the far side, so the far side treats it as untrusted: it is never evaluated, only checked here and, if it passes, written out by an explicit
 * call. The check is a small tokenizer, not a parser: it accepts a conservative subset of type syntax (identifiers, string and number literals, and the
 * punctuation of object, tuple, function, union, intersection, generic, conditional and indexed types) and refuses everything that could change what the
 * surrounding declaration means or reach outside it.
 *
 * What it refuses, and why:
 * - any character outside printable ASCII on one line (no newline, so nothing can start a new declaration or a `///` directive);
 * - `/`, `\`, a backtick, `@`, `#`, `%`, `^`, `~`, `!` and `*`: no comment, no escape sequence, no template literal, no decorator;
 * - the words `import`, `export`, `require`, `declare`, `module`, `namespace`, `global`, `typeof`, `class`, `function`, `enum`, `interface`, `eval`: nothing
 *   that reads a file, a value or the global scope by name, or declares anything;
 * - unbalanced or mismatched brackets, a `;` outside braces and a `,` outside any bracket: a text cannot close the declaration it sits in or add a member to it;
 * - a text, a string literal, a nesting depth or a total that is over its bound.
 *
 * It does not make the text TRUE: a host can name a type that is wrong, and a type that is too wide or too narrow is a tooling problem, not a hole (a type
 * is erased before anything runs). It makes the text safe to write into a declaration file.
 */

export const TYPE_TEXT_LIMITS = Object.freeze({
  /** Characters of one type text. */
  maxTextChars: 1024,
  /** Characters of one string literal inside a type text. */
  maxStringChars: 200,
  /** Nesting of brackets in one type text. */
  maxNesting: 16,
  /** Entries of a type map. */
  maxEntries: 256,
  /** Characters of all the type texts of one root together. */
  maxTotalChars: 32 * 1024,
});

const FORBIDDEN_WORDS = new Set(['import', 'export', 'require', 'declare', 'module', 'namespace', 'global', 'typeof', 'class', 'function', 'enum', 'interface', 'eval']);
const PUNCTUATION = new Set(['{', '}', '[', ']', '(', ')', '<', '>', '|', '&', ':', ';', ',', '?', '=', '.', '-', '+']);
const OPEN = { '{': '}', '[': ']', '(': ')', '<': '>' };
const CLOSE = new Set(Object.values(OPEN));

/**
 * Check one type text; returns it unchanged, or throws a `TypeError` that names the rule.
 * @param {unknown} text
 * @param {string} [what] - what the text is for, for the message
 * @returns {string}
 */
export function checkTypeText(text, what = 'a type text') {
  const fail = (why) => new TypeError(`${what}: ${why}`);
  if (typeof text !== 'string' || text.trim() === '') throw fail('must be a non-empty string');
  if (text.length > TYPE_TEXT_LIMITS.maxTextChars) throw fail(`is over ${TYPE_TEXT_LIMITS.maxTextChars} characters`);
  const stack = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    const code = text.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) throw fail('may hold printable ASCII on one line only');
    if (c === ' ') { i++; continue; }
    if (c === '"' || c === "'") {
      const end = text.indexOf(c, i + 1);
      if (end < 0) throw fail('has a string literal that does not end');
      const body = text.slice(i + 1, end);
      if (body.includes('\\')) throw fail('has a string literal with an escape sequence');
      if (body.length > TYPE_TEXT_LIMITS.maxStringChars) throw fail(`has a string literal over ${TYPE_TEXT_LIMITS.maxStringChars} characters`);
      i = end + 1;
      continue;
    }
    if (/[A-Za-z_$]/.test(c)) {
      let j = i + 1;
      while (j < text.length && /[A-Za-z0-9_$]/.test(text[j])) j++;
      const word = text.slice(i, j);
      if (FORBIDDEN_WORDS.has(word)) throw fail(`may not use the word "${word}"`);
      i = j;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i + 1;
      while (j < text.length && /[0-9._]/.test(text[j])) j++;
      i = j;
      continue;
    }
    if (!PUNCTUATION.has(c)) throw fail(`may not contain "${c}"`);
    // `=>` is an arrow, not a closing angle bracket.
    if (c === '=' && text[i + 1] === '>') { i += 2; continue; }
    if (c in OPEN) {
      stack.push(OPEN[c]);
      if (stack.length > TYPE_TEXT_LIMITS.maxNesting) throw fail(`nests deeper than ${TYPE_TEXT_LIMITS.maxNesting}`);
    } else if (CLOSE.has(c)) {
      if (stack.pop() !== c) throw fail(`has a "${c}" that closes nothing`);
    } else if (c === ';') {
      if (stack[stack.length - 1] !== '}') throw fail('has a ";" outside braces');
    } else if (c === ',') {
      if (stack.length === 0) throw fail('has a "," outside any bracket');
    }
    i++;
  }
  if (stack.length) throw fail('has a bracket that is not closed');
  return text;
}
