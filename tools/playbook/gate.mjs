#!/usr/bin/env node
/**
 * Partner gate for carbon-playbook.html.
 *
 * qsoftwares.org is static hosting from a PUBLIC repository, so there is no server that could
 * check a login and nothing in the page source can be trusted to stay hidden. The playbook is
 * therefore published ENCRYPTED. Each registered partner gets a personal access code; the code
 * unwraps the content key in the partner's own browser (WebCrypto), and nothing readable is ever
 * sent to or stored on the site.
 *
 *   content   AES-256-GCM under a content key (CK). A fresh CK is generated on EVERY build.
 *   partner   access code (80 random bits) --PBKDF2-SHA256--> key-encryption key (KEK)
 *             the page carries one entry per partner: { id, salt, iv, wk = AES-GCM(KEK, CK) }
 *   revoke    drop the partner's entry and rebuild: the new CK is never wrapped for them, so a
 *             saved copy of their old code cannot open the new page.
 *   decoys    the entry list is padded to a fixed length so the page does not reveal how many
 *             partners there are.
 *
 * Private inputs live in ./private (git-ignored, NEVER commit):
 *   private/playbook-source.html   the playbook body, plaintext
 *   private/partners.json          the registry (names, emails, each partner's KEK)
 *
 * Usage (from the repo root):
 *   node tools/playbook/gate.mjs add --name "Jane Doe" --org "Acme" --email jane@acme.org [--type funding]
 *   node tools/playbook/gate.mjs revoke --email jane@acme.org
 *   node tools/playbook/gate.mjs list
 *   node tools/playbook/gate.mjs build
 *   node tools/playbook/gate.mjs verify --code CF-XXXX-XXXX-XXXX-XXXX
 *
 * Options for tests: --private <dir>  --out <file>
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomInt, webcrypto } from 'node:crypto';

const { subtle } = webcrypto;
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..');

export const KDF_ITERATIONS = 310_000;
export const ENTRY_SLOTS = 40;
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32: no I, L, O, U
const ID_DOMAIN = 'cf-playbook:id:';

const b64 = (buf) => Buffer.from(buf).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const utf8 = (s) => new TextEncoder().encode(s);
const rand = (n) => webcrypto.getRandomValues(new Uint8Array(n));

/** The same normalisation the page applies: forgiving about case, spacing, dashes and O/I/L. */
export function normaliseCode(input) {
  let s = String(input).toUpperCase().replace(/[^0-9A-Z]/g, '');
  if (s.length === 18 && s.startsWith('CF')) s = s.slice(2);
  return s.replace(/O/g, '0').replace(/[IL]/g, '1');
}

export function newAccessCode() {
  let raw = '';
  for (let i = 0; i < 16; i++) raw += ALPHABET[randomInt(ALPHABET.length)];
  return { raw, display: `CF-${raw.match(/.{4}/g).join('-')}` };
}

export async function codeId(norm) {
  const digest = await subtle.digest('SHA-256', utf8(ID_DOMAIN + norm));
  return Buffer.from(digest).toString('hex').slice(0, 24);
}

export async function deriveKekRaw(norm, salt) {
  const base = await subtle.importKey('raw', utf8(norm), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: KDF_ITERATIONS }, base, 256);
  return new Uint8Array(bits);
}

const aesKey = (raw, usages) => subtle.importKey('raw', raw, 'AES-GCM', false, usages);

async function seal(keyRaw, plain) {
  const iv = rand(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(keyRaw, ['encrypt']), plain);
  return { iv: b64(iv), ct: b64(ct) };
}

async function open(keyRaw, iv, ct) {
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, await aesKey(keyRaw, ['decrypt']), unb64(ct)));
}

/** What the browser does with a code, reproduced here so a build can be checked before it ships. */
export async function unlock(manifest, code) {
  const norm = normaliseCode(code);
  const id = await codeId(norm);
  const entry = manifest.partners.find((p) => p.id === id);
  if (!entry) return null;
  try {
    const kek = await deriveKekRaw(norm, unb64(entry.salt));
    const ck = await open(kek, entry.iv, entry.wk);
    return new TextDecoder().decode(await open(ck, manifest.content.iv, manifest.content.ct));
  } catch {
    return null;
  }
}

export async function buildManifest(sourceHtml, partners) {
  const ck = rand(32);
  const content = await seal(ck, utf8(sourceHtml));
  const entries = [];
  for (const p of partners.filter((x) => x.status === 'active')) {
    const w = await seal(unb64(p.kek), ck);
    entries.push({ id: p.id, salt: p.salt, iv: w.iv, wk: w.ct });
  }
  if (entries.length > ENTRY_SLOTS) throw new Error(`more than ${ENTRY_SLOTS} active partners: raise ENTRY_SLOTS`);
  while (entries.length < ENTRY_SLOTS) {
    // A decoy has the same shape and sizes as a real entry (48-byte wk = 32-byte key + 16-byte tag).
    entries.push({ id: Buffer.from(rand(12)).toString('hex'), salt: b64(rand(16)), iv: b64(rand(12)), wk: b64(rand(48)) });
  }
  for (let i = entries.length - 1; i > 0; i--) { const j = randomInt(i + 1); [entries[i], entries[j]] = [entries[j], entries[i]]; }
  return { v: 1, kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: KDF_ITERATIONS }, builtAt: new Date().toISOString(), content: { iv: content.iv, ct: content.ct }, partners: entries };
}

// ------------------------------------------------------------------------------------ CLI
function args(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) { out[argv[i].slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true; } else out._.push(argv[i]);
  }
  return out;
}

function paths(a) {
  const priv = resolve(a.private || join(ROOT, 'private'));
  return { priv, registry: join(priv, 'partners.json'), source: join(priv, 'playbook-source.html'), template: join(HERE, 'template.html'), out: resolve(a.out || join(ROOT, 'carbon-playbook.html')) };
}

const loadRegistry = (p) => (existsSync(p.registry) ? JSON.parse(readFileSync(p.registry, 'utf8')) : []);
const saveRegistry = (p, r) => { mkdirSync(p.priv, { recursive: true }); writeFileSync(p.registry, JSON.stringify(r, null, 2) + '\n', { mode: 0o600 }); };

async function build(p) {
  if (!existsSync(p.source)) throw new Error(`missing ${p.source} (the plaintext playbook body; it is git-ignored on purpose)`);
  const manifest = await buildManifest(readFileSync(p.source, 'utf8'), loadRegistry(p));
  const template = readFileSync(p.template, 'utf8');
  if (!template.includes('/*PB:MANIFEST*/')) throw new Error('template.html has no /*PB:MANIFEST*/ marker');
  const page = template.replace('/*PB:MANIFEST*/', JSON.stringify(manifest).replace(/</g, '\\u003c'));
  if (/id="part-1"|class="pb-stage"|class="pb-check"/.test(page)) throw new Error('refusing to write: plaintext playbook body found in the output');
  writeFileSync(p.out, page);
  const active = loadRegistry(p).filter((x) => x.status === 'active').length;
  console.log(`built ${p.out}\n  ${active} active partner(s), ${ENTRY_SLOTS - active} decoy entries, fresh content key`);
  return manifest;
}

async function main() {
  const a = args(process.argv.slice(2));
  const cmd = a._[0];
  const p = paths(a);
  if (cmd === 'build') return void (await build(p));
  if (cmd === 'list') {
    const r = loadRegistry(p);
    if (!r.length) return console.log('no partners registered yet');
    for (const x of r) console.log(`${x.status.padEnd(8)} ${x.email.padEnd(34)} ${(x.type || '-').padEnd(12)} ${x.name} · ${x.org} · since ${x.createdAt.slice(0, 10)}`);
    return;
  }
  if (cmd === 'add') {
    for (const k of ['name', 'org', 'email']) if (!a[k] || a[k] === true) throw new Error(`--${k} is required`);
    const r = loadRegistry(p);
    if (r.some((x) => x.email.toLowerCase() === a.email.toLowerCase() && x.status === 'active')) throw new Error(`${a.email} is already an active partner (revoke first to re-issue)`);
    const code = newAccessCode();
    const salt = rand(16);
    const kek = await deriveKekRaw(code.raw, salt);
    r.push({ name: a.name, org: a.org, email: a.email, type: a.type === true ? '' : a.type || '', id: await codeId(code.raw), salt: b64(salt), kek: b64(kek), status: 'active', createdAt: new Date().toISOString() });
    saveRegistry(p, r);
    const manifest = await build(p);
    if ((await unlock(manifest, code.display)) === null) throw new Error('self-check failed: the new code does not open the build');
    console.log(`\nregistered ${a.name} <${a.email}>\n\n  ACCESS CODE (shown once, not stored):  ${code.display}\n\nSend it to the partner, then commit and publish carbon-playbook.html.`);
    return;
  }
  if (cmd === 'revoke') {
    if (!a.email || a.email === true) throw new Error('--email is required');
    const r = loadRegistry(p);
    const hit = r.filter((x) => x.email.toLowerCase() === a.email.toLowerCase() && x.status === 'active');
    if (!hit.length) throw new Error(`no active partner with email ${a.email}`);
    for (const x of hit) { x.status = 'revoked'; x.revokedAt = new Date().toISOString(); }
    saveRegistry(p, r);
    await build(p);
    console.log(`revoked ${a.email}. Commit and publish carbon-playbook.html: until then the old page is still live.`);
    return;
  }
  if (cmd === 'verify') {
    if (!a.code || a.code === true) throw new Error('--code is required');
    const page = readFileSync(p.out, 'utf8');
    const m = JSON.parse(page.slice(page.indexOf('id="pb-manifest">') + 17, page.indexOf('</script>', page.indexOf('id="pb-manifest">'))));
    const html = await unlock(m, a.code);
    console.log(html === null ? 'NO: this code does not open the published page' : `YES: opens it (${html.length} characters of playbook)`);
    process.exitCode = html === null ? 1 : 0;
    return;
  }
  console.log('usage: gate.mjs add|revoke|list|build|verify   (see the header of this file)');
  process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { console.error('error:', e.message); process.exit(1); });
}
