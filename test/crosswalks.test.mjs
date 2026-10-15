import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const dir = join(root, 'docs/crosswalks');
const DISCLAIMER = 'Draft input for practitioner and legal review. Not legal advice. Not a compliance claim.';
const STATUSES = new Set(['`supports as input`', '`partial`', '`not addressed`']);
const FRAMEWORKS = ['eu-ai-act.md', 'nist-ai-rmf.md', 'iso-iec-42001.md', 'soc-2.md'];

async function load() {
  const names = (await readdir(dir)).filter(n => n.endsWith('.md')).sort();
  const files = {};
  for (const n of names) files[n] = await readFile(join(dir, n), 'utf8');
  return files;
}
function rowsOf(text) {
  return text.split('\n').filter(l => l.startsWith('| ') && !l.startsWith('| :') && !l.startsWith('| Framework clause'))
    .map(l => l.slice(1, -1).split(' | ').map(c => c.trim()));
}

test('every requirement ID cited by a crosswalk exists in the registry', async () => {
  const reg = JSON.parse(await readFile(join(root, 'evidence/requirements.json'), 'utf8'));
  const ids = new Set(reg.requirements.map(r => r.id));
  const files = await load();
  let cited = 0;
  for (const [name, text] of Object.entries(files)) {
    if (name === 'INTEGRATION.md') continue;
    for (const id of text.match(/KYA-[A-Z]+-\d{3}/g) || []) { cited++; assert(ids.has(id), `${name} cites unknown ${id}`); }
  }
  assert(cited > 40);
});

test('every crosswalk file opens with the disclaimer', async () => {
  const files = await load();
  for (const f of FRAMEWORKS) assert(f in files, `missing ${f}`);
  for (const [name, text] of Object.entries(files)) {
    assert.equal(text.split('\n').find(l => l.trim()), DISCLAIMER, name);
  }
});

test('every crosswalk row has an allowed status and a flag when its basis is secondary', async () => {
  const files = await load();
  for (const f of FRAMEWORKS) {
    const rows = rowsOf(files[f]);
    assert(rows.length >= 10, f);
    for (const r of rows) {
      assert.equal(r.length, 5, `${f}: ${r[0]}`);
      assert(STATUSES.has(r[4]), `${f}: bad status in ${r[0]}`);
      assert(r.every(c => c.length > 0), `${f}: empty cell in ${r[0]}`);
      assert(/^(primary text read|primary page, condensed fetch|secondary; needs primary re-check)$/.test(r[1]), `${f}: bad basis ${r[1]}`);
      if (r[1].startsWith('secondary')) assert(r[1].includes('needs primary re-check'));
    }
  }
  for (const f of ['iso-iec-42001.md', 'soc-2.md']) for (const r of rowsOf(files[f])) assert(r[1].startsWith('secondary'), f);
});

test('no crosswalk claims compliance or certification outside a negation', async () => {
  const files = await load();
  for (const [name, text] of Object.entries(files)) {
    for (const line of text.split('\n')) {
      const re = /\b(compliant|certified|guarantees)\b/gi;
      let m;
      while ((m = re.exec(line))) {
        const before = line.slice(Math.max(0, m.index - 60), m.index);
        assert(/\b(not|no|never|nor|cannot|without)\b|n't/i.test(before), `${name}: ${line}`);
      }
    }
  }
});

test('the crosswalk index lists every framework file', async () => {
  const files = await load();
  for (const f of FRAMEWORKS) assert(files['README.md'].includes(f), f);
});
