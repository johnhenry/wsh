// scripts/bundle-size.mjs -- `npm run size`: bundle each browser entry point and print raw / gzip bytes against the budget.
//   node scripts/bundle-size.mjs            print the table (and append it to $GITHUB_STEP_SUMMARY); exit 1 over budget
//   node scripts/bundle-size.mjs --update   rewrite scripts/bundle-budget.json from the current sizes
import { readFile, writeFile, appendFile } from 'node:fs/promises';
import path from 'node:path';
import { ENTRY_POINTS, ROOT, bundle } from './browser-bundles.mjs';

const BUDGET_FILE = path.join(ROOT, 'scripts', 'bundle-budget.json');
/** A bundle may grow by this much over its budget before it counts as a regression. */
export const TOLERANCE = 0.1;

export async function measure() {
  const out = [];
  for (const point of ENTRY_POINTS) out.push({ name: point.name, ...(await bundle(point)) });
  return out;
}

export async function readBudget() {
  return JSON.parse(await readFile(BUDGET_FILE, 'utf8'));
}

/** @returns {string[]} one line per entry point over its budget (or missing from it) */
export function overBudget(sizes, budget) {
  const bad = [];
  for (const s of sizes) {
    const b = budget.entries?.[s.name];
    if (!b) bad.push(`${s.name}: no budget (run \`npm run size -- --update\`)`);
    else if (s.gzip > Math.ceil(b.gzip * (1 + TOLERANCE))) bad.push(`${s.name}: ${s.gzip} B gzip is over its budget of ${b.gzip} B (+${Math.round(TOLERANCE * 100)}% allowed)`);
  }
  return bad;
}

const kb = (n) => (n / 1024).toFixed(1);

function table(sizes, budget) {
  const rows = sizes.map((s) => {
    const b = budget?.entries?.[s.name];
    return `| ${s.name} | ${kb(s.raw)} kB | ${kb(s.gzip)} kB | ${b ? `${kb(b.gzip)} kB` : '-'} |`;
  });
  return ['| entry point | minified | gzip | gzip budget |', '| --- | ---: | ---: | ---: |', ...rows].join('\n');
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('bundle-size.mjs')) {
  const sizes = await measure();
  if (process.argv.includes('--update')) {
    const entries = Object.fromEntries(sizes.map((s) => [s.name, { raw: s.raw, gzip: s.gzip }]));
    await writeFile(BUDGET_FILE, `${JSON.stringify({ note: 'Browser bundle budget: `npm run size -- --update` rewrites it. A bundle may exceed its gzip figure by 10% before the test fails.', entries }, null, 2)}\n`);
    console.log(table(sizes, { entries }));
    console.log(`\nwrote ${path.relative(ROOT, BUDGET_FILE)}`);
  } else {
    const budget = await readBudget();
    const md = table(sizes, budget);
    console.log(md);
    if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, `### Browser bundle size\n\n${md}\n`);
    const bad = overBudget(sizes, budget);
    if (bad.length) { console.error(`\n${bad.join('\n')}`); process.exitCode = 1; }
  }
}
