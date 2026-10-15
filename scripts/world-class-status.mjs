import { readFile, writeFile } from 'node:fs/promises';
import { lstatSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, resolve, relative, isAbsolute, sep } from 'node:path';
import { isMain } from "./lib/is-main.mjs";

// Status ledger for docs/WORLD-CLASS-PLAN.md. "Verified" is not a feeling: it needs linked evidence of the
// right kind, and anything that needs an outside party can only be verified by one (named, https, dated).
const STATUSES = ['planned', 'in-progress', 'implemented', 'verified'];
const VERIFIERS = ['CI', 'XREV', 'XIMP', 'XUSE'];
const STREAMS = ['WS1', 'WS2', 'WS3', 'WS4', 'WS5', 'WS6', 'WS7', 'WS8', 'WS9', 'WS10'];
const root = fileURLToPath(new URL('../', import.meta.url));
const need = (c, m) => { if (!c) throw Error(m); };
const exact = (o, keys, what) => { need(o && typeof o === 'object' && !Array.isArray(o), `${what} must be an object`); const extra = Object.keys(o).filter(k => !keys.includes(k)); need(!extra.length, `${what}: unexpected members ${extra.join(', ')}`); };

const withinDir = (parent, child) => { const r = relative(parent, child); return r === '' || (r !== '..' && !r.startsWith('..' + sep) && !isAbsolute(r)); };
function repoFile(rootDir, ref, what) {
  need(typeof ref === 'string' && ref && !isAbsolute(ref) && !ref.split('/').includes('..'), `${what}: path must be a relative repository path`);
  const full = resolve(rootDir, ref); const rel = relative(rootDir, full);
  need(rel !== '..' && !rel.startsWith('..' + sep) && !isAbsolute(rel), `${what}: path escapes the repository`);
  let st; try { st = lstatSync(full); } catch { throw Error(`${what}: missing file ${ref}`); }
  need(st.isFile() && !st.isSymbolicLink(), `${what}: ${ref} must be a regular file`);
  need(withinDir(realpathSync(rootDir), realpathSync(full)), `${what}: ${ref} resolves outside the repository`);
}

export function validateStatus(status, { registry, root: rootDir = root }) {
  exact(status, ['schema', 'updated', 'rule', 'streams'], 'Status');
  need(status.schema === 'kya.world-class-status/v1', 'Unsupported status schema');
  need(/^\d{4}-\d{2}-\d{2}$/.test(status.updated), 'updated must be a YYYY-MM-DD date');
  need(typeof status.rule === 'string' && status.rule.length > 20, 'rule must state how verified is earned');
  need(Array.isArray(status.streams) && status.streams.length === STREAMS.length && STREAMS.every((id, i) => status.streams[i]?.id === id), `streams must be exactly ${STREAMS.join(', ')} in order (stream missing or reordered)`);
  const ids = new Set(), reqIds = new Set(registry.requirements.map(r => r.id));
  for (const stream of status.streams) {
    exact(stream, ['id', 'title', 'items'], `Stream ${stream.id}`);
    need(typeof stream.title === 'string' && stream.title && Array.isArray(stream.items) && stream.items.length, `Stream ${stream.id} needs a title and items`);
    for (const it of stream.items) {
      exact(it, ['id', 'title', 'status', 'verifiedBy', 'evidence', 'needsOutside', 'notes'], `Item ${it.id}`);
      need(new RegExp(`^${stream.id}-\\d{2}$`).test(it.id), `Item id ${it.id} must look like ${stream.id}-01`);
      need(!ids.has(it.id), `Duplicate item id ${it.id}`); ids.add(it.id);
      need(typeof it.title === 'string' && it.title, `${it.id}: title required`);
      need(STATUSES.includes(it.status), `${it.id}: unknown status ${it.status}`);
      need(it.needsOutside === undefined || typeof it.needsOutside === 'boolean', `${it.id}: needsOutside must be boolean`);
      need(it.notes === undefined || typeof it.notes === 'string', `${it.id}: notes must be a string`);
      const evidence = it.evidence ?? [];
      need(Array.isArray(evidence), `${it.id}: evidence must be an array`);
      if (['implemented', 'verified'].includes(it.status)) need(evidence.length > 0, `${it.id}: ${it.status} needs linked evidence`);
      for (const e of evidence) {
        need(e && typeof e === 'object', `${it.id}: evidence entries must be objects`);
        if (e.type === 'requirement') { exact(e, ['type', 'ref'], `${it.id} evidence`); need(reqIds.has(e.ref), `${it.id}: unknown requirement ${e.ref}`); }
        else if (['test', 'file'].includes(e.type)) { exact(e, ['type', 'ref'], `${it.id} evidence`); repoFile(rootDir, e.ref, `${it.id} evidence`); if (e.type === 'test') need(e.ref.startsWith('test/') && e.ref.endsWith('.test.mjs'), `${it.id}: a test reference must be a test/*.test.mjs file`); }
        else if (e.type === 'external') {
          exact(e, ['type', 'party', 'url', 'date'], `${it.id} evidence`);
          need(typeof e.party === 'string' && e.party.trim(), `${it.id}: external evidence needs a named party`);
          need(typeof e.url === 'string' && /^https:\/\/[^\s]+$/.test(e.url), `${it.id}: external evidence needs an https link`);
          need(typeof e.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(e.date) && !Number.isNaN(Date.parse(e.date)), `${it.id}: external evidence needs an ISO date`);
        } else throw Error(`${it.id}: unknown evidence type ${e.type}`);
      }
      if (it.status === 'verified') {
        need(VERIFIERS.includes(it.verifiedBy), `${it.id}: verified needs a verifier (${VERIFIERS.join(', ')})`);
        if (it.verifiedBy === 'CI') { need(!it.needsOutside, `${it.id}: work that needs an outside party cannot be verified by CI alone`); need(evidence.some(e => ['requirement', 'test', 'file'].includes(e.type)), `${it.id}: CI verification needs a requirement, test or file as evidence`); }
        else need(evidence.some(e => e.type === 'external'), `${it.id}: ${it.verifiedBy} verification needs external evidence (named party, https link, date)`);
      } else need(it.verifiedBy === undefined, `${it.id}: only verified items carry a verifier`);
    }
  }
  return true;
}

export function renderStatus(status) {
  const icon = { planned: 'planned', 'in-progress': 'in progress', implemented: 'implemented', verified: 'VERIFIED' };
  const lines = ['# World-class plan status', '', `Generated from [evidence/world-class-status.json](../evidence/world-class-status.json) by \`node scripts/world-class-status.mjs --write\`. Last updated ${status.updated}.`, '', status.rule, ''];
  const all = status.streams.flatMap(s => s.items), count = k => all.filter(i => i.status === k).length;
  lines.push(`Totals: ${all.length} items; ${count('planned')} planned, ${count('in-progress')} in progress, ${count('implemented')} implemented, ${count('verified')} verified. Items that need an outside party: ${all.filter(i => i.needsOutside).length}; verified by an outside party: ${all.filter(i => i.status === 'verified' && i.verifiedBy !== 'CI').length}.`, '');
  for (const s of status.streams) {
    lines.push(`## ${s.id} ${s.title}`, '', '| Item | Status | Verifier | Evidence | Needs outsiders |', '| :--- | :--- | :--- | :--- | :--- |');
    for (const i of s.items) lines.push(`| ${i.id} ${i.title}${i.notes ? ` (${i.notes})` : ''} | ${icon[i.status]} | ${i.verifiedBy ?? ''} | ${(i.evidence ?? []).map(e => e.type === 'external' ? `${e.party} ${e.url}` : `\`${e.ref}\``).join(', ')} | ${i.needsOutside ? 'yes' : ''} |`);
    lines.push('');
  }
  return lines.join('\n');
}

if (isMain(import.meta.url)) {
  const status = JSON.parse(await readFile(join(root, 'evidence/world-class-status.json'), 'utf8')), registry = JSON.parse(await readFile(join(root, 'evidence/requirements.json'), 'utf8'));
  validateStatus(status, { registry, root });
  const out = join(root, 'docs/WORLD-CLASS-STATUS.md'), text = renderStatus(status);
  if (process.argv.includes('--write')) await writeFile(out, text);
  else if ((await readFile(out, 'utf8').catch(() => '')) !== text) throw Error('docs/WORLD-CLASS-STATUS.md drift; run node scripts/world-class-status.mjs --write');
  const all = status.streams.flatMap(s => s.items);
  console.log(JSON.stringify({ items: all.length, verified: all.filter(i => i.status === 'verified').length, verifiedByOutsider: all.filter(i => i.status === 'verified' && i.verifiedBy !== 'CI').length, needsOutside: all.filter(i => i.needsOutside).length }));
}
