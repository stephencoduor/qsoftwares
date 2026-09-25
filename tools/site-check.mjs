#!/usr/bin/env node
// Static checks for qsoftwares.org — no server, no dependencies.
//
//   node tools/site-check.mjs
//
// For every *.html page in the repo root (and tools/playbook/template.html):
//   1. every local <img src>, <script src>, <link href> and <a href> file exists;
//   2. every link to an anchor (page.html#id or #id) lands on an element with that id;
//   3. the retired product name "Msacco" is shown nowhere — HTML comments are allowed to record it.
// Exits non-zero with one line per problem.
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
// Theme leftovers no page links to; their links point at demo pages that were never added.
const LEGACY = new Set(['home-3-light.html', 'test.html']);
const pages = readdirSync(root).filter((f) => f.endsWith('.html') && !LEGACY.has(f)).concat(['tools/playbook/template.html']);
// The playbook's #part-N ids exist only once the encrypted body is decrypted in the browser.
const RUNTIME_ANCHOR = /^part-\d+$/;
// The template is built into the repo root as carbon-playbook.html, so its links resolve from there.
const baseOf = (page) => (page.startsWith('tools/playbook/') ? '.' : dirname(page));
const idsOf = new Map();
const problems = [];

const read = (p) => readFileSync(join(root, p), 'utf8');
const ids = (html) => new Set([...html.matchAll(/\sid=["']([^"']+)["']/g)].map((m) => m[1]));
for (const p of pages) idsOf.set(p, ids(read(p)));

for (const page of pages) {
  const html = read(page);
  const base = baseOf(page);
  const refs = [...html.matchAll(/<(?:img|script|link|a|source)\b[^>]*?\s(?:src|href)=["']([^"']+)["']/gi)].map((m) => m[1]);
  for (const ref of refs) {
    if (/^(https?:|mailto:|tel:|data:|javascript:|\/\/)/i.test(ref) || ref === '#' || ref.startsWith('{')) continue;
    const [pathPart, anchor] = ref.split('#');
    const target = pathPart ? join(base, pathPart.split('?')[0]) : (page.startsWith('tools/playbook/') ? 'carbon-playbook.html' : page);
    if (pathPart && !existsSync(join(root, target))) { problems.push(`${page}: missing file ${ref}`); continue; }
    if (anchor && target.endsWith('.html') && !RUNTIME_ANCHOR.test(anchor)) {
      const known = idsOf.get(target) ?? ids(read(target));
      if (!known.has(anchor)) problems.push(`${page}: ${ref} lands on no id="${anchor}"`);
    }
  }
  const visible = html.replace(/<!--[\s\S]*?-->/g, '');
  const hits = [...visible.matchAll(/[^\n]{0,40}\bmsacco\b[^\n]{0,40}/gi)].filter((m) => !/id=["']msacco["']/i.test(m[0]));
  for (const h of hits) problems.push(`${page}: shows the retired name — …${h[0].trim()}…`);
}

if (problems.length) {
  console.error(problems.join('\n'));
  console.error(`\nsite-check: ${problems.length} problem(s) in ${pages.length} pages`);
  process.exit(1);
}
console.log(`site-check: ${pages.length} pages, every local link, image and anchor resolves; "Msacco" shown nowhere`);
