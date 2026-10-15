import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, mkdir, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateStatus } from '../scripts/world-class-status.mjs';

const registry = JSON.parse(await readFile(new URL('../evidence/requirements.json', import.meta.url), 'utf8'));
const current = JSON.parse(await readFile(new URL('../evidence/world-class-status.json', import.meta.url), 'utf8'));

function withEvidence(ref) {
  const s = structuredClone(current), target = s.streams[0].items[0];
  for (const it of s.streams.flatMap(x => x.items)) { it.status = 'planned'; delete it.verifiedBy; it.evidence = []; it.needsOutside = false; }
  target.status = 'verified'; target.verifiedBy = 'CI'; target.evidence = [{ type: 'file', ref }];
  return s;
}

test('a repository file whose name starts with two dots is accepted as inside the repository', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'kya-wcs-'));
  try {
    await writeFile(join(dir, '..notes.md'), 'x');
    assert.doesNotThrow(() => validateStatus(withEvidence('..notes.md'), { registry, root: dir }));
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('a file under a linked directory that resolves to a sibling with the same prefix is refused', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'kya-wcs-')), repo = join(parent, 'repo'), evil = join(parent, 'repo-evil');
  try {
    await mkdir(repo); await mkdir(evil);
    await writeFile(join(evil, 'f.md'), 'x');
    await symlink(evil, join(repo, 'linked'));
    assert.throws(() => validateStatus(withEvidence('linked/f.md'), { registry, root: repo }), /outside|regular|resolves/i);
  } finally { await rm(parent, { recursive: true, force: true }); }
});
