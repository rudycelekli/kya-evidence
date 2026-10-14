import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';

// Structural checks for the governance layer. These tests read the markdown; they do not judge legal content.
const ROOT = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, ROOT), 'utf8');

const NOTICE = 'Draft for review by qualified legal counsel. Not legal advice. Not yet adopted by any body.';
const NOTICE_LINE = '> **' + NOTICE + '**';

const GOVERNANCE_DOCS = [
  'CHARTER.md',
  'IPR-POLICY.md',
  'TRADEMARK-AND-CLAIMS.md',
  'VERSIONING.md',
  'EXTENSION-REGISTRY.md',
  'DECISION-PROCESS.md',
];
const LEGAL_DOCS = [...GOVERNANCE_DOCS.map((name) => 'docs/governance/' + name), 'CODE_OF_CONDUCT.md'];
const REQUIRED_ADR_SECTIONS = ['## Context', '## Decision', '## Alternatives', '## Consequences', '## Validation'];

test('every legal document opens with the draft-counsel notice', async () => {
  for (const path of LEGAL_DOCS) {
    const lines = (await read(path)).split('\n').filter((line) => line.trim() !== '');
    const first = lines[0];
    assert.equal(first, NOTICE_LINE, path + ' must open with the draft-counsel notice');
  }
});

test('the draft-counsel notice appears exactly once in each governance document', async () => {
  for (const path of LEGAL_DOCS) {
    const text = await read(path);
    const occurrences = text.split(NOTICE).length - 1;
    assert.equal(occurrences, 1, path + ' must contain the notice exactly once');
  }
});

test('CONTRIBUTING mentions the Developer Certificate of Origin sign-off', async () => {
  const text = await read('CONTRIBUTING.md');
  assert.match(text, /Developer Certificate of Origin/);
  assert.match(text, /Signed-off-by:/);
});

test('CONTRIBUTING links every governance document and the code of conduct', async () => {
  const text = await read('CONTRIBUTING.md');
  for (const name of GOVERNANCE_DOCS) {
    assert.ok(text.includes('docs/governance/' + name), 'CONTRIBUTING must link ' + name);
  }
  assert.ok(text.includes('CODE_OF_CONDUCT.md'), 'CONTRIBUTING must link the code of conduct');
});

test('CONTRIBUTING requires an ADR before code under src/conformance changes', async () => {
  const text = await read('CONTRIBUTING.md');
  assert.match(text, /Code under `src\/conformance\/` must not change without an ADR/);
});

test('CONTRIBUTING states the test-first expectation', async () => {
  const text = await read('CONTRIBUTING.md');
  assert.match(text, /Write the failing test before the change/);
});

test('every ADR has the five required sections and a Status line', async () => {
  const names = (await readdir(new URL('docs/adr/', ROOT))).filter((name) => /^\d{4}-.+\.md$/.test(name));
  assert.ok(names.length >= 24, 'expected at least 24 ADR files');
  for (const name of names) {
    const text = await read('docs/adr/' + name);
    assert.match(text, /^\*\*Status\*\*: \S/m, name + ' must have a Status line');
    for (const section of REQUIRED_ADR_SECTIONS) {
      assert.ok(text.split('\n').includes(section), name + ' is missing ' + section);
    }
  }
});

test('ADR-0024 is Proposed and dated 2026-10-15', async () => {
  const text = await read('docs/adr/0024-governance-charter-and-change-process.md');
  assert.match(text, /^# ADR-0024: /m);
  assert.match(text, /^\*\*Status\*\*: Proposed$/m);
  assert.match(text, /^\*\*Date\*\*: 2026-10-15$/m);
});

test('GOVERNANCE keeps its existing sections and links the governance layer', async () => {
  const text = await read('docs/GOVERNANCE.md');
  for (const heading of [
    '## Separation of roles',
    '## Appeals and correction lineage',
    '## Requirement identifiers',
    '## Conformance claims',
    '## Before any adoption claim',
  ]) {
    assert.ok(text.includes(heading), 'GOVERNANCE must keep ' + heading);
  }
  for (const name of GOVERNANCE_DOCS) {
    assert.ok(text.includes('governance/' + name), 'GOVERNANCE must link ' + name);
  }
});

test('governance documents do not attach registered mark symbols to the name', async () => {
  for (const path of LEGAL_DOCS) {
    const text = await read(path);
    assert.equal(/(KYA Evidence|Know Your Agent)\s*[®™]/.test(text), false, path + ' must not claim a registered mark');
  }
});

test('IPR policy prohibits customer data credentials private code and operational logs', async () => {
  const text = await read('docs/governance/IPR-POLICY.md');
  for (const phrase of ['customer data', 'credentials', 'private product code', 'operational logs']) {
    assert.ok(text.includes(phrase), 'IPR policy must prohibit ' + phrase);
  }
});

test('code of conduct has an enforcement placeholder and no email address', async () => {
  const text = await read('CODE_OF_CONDUCT.md');
  assert.ok(text.includes('[ENFORCEMENT CONTACT'), 'enforcement contact placeholder is required');
  assert.equal(/[\w.+-]+@[\w-]+\.[\w.-]+/.test(text), false, 'no email address may be invented');
});

test('extension registry reserves the kya prefix and forbids weakening a MUST', async () => {
  const text = await read('docs/governance/EXTENSION-REGISTRY.md');
  assert.ok(text.includes('`kya.`'), 'kya prefix must be reserved');
  assert.match(text, /weaken a MUST/);
});

test('versioning lists all five stability levels', async () => {
  const text = await read('docs/governance/VERSIONING.md');
  for (const level of ['Experimental', 'Candidate', 'Stable', 'Deprecated', 'Retired']) {
    assert.ok(text.includes('| ' + level + ' |'), 'missing stability level ' + level);
  }
});

test('versioning treats an evaluator digest change as breaking with an ADR and migration note', async () => {
  const text = await read('docs/governance/VERSIONING.md');
  const section = text.slice(text.indexOf('## 6.'), text.indexOf('## 7.'));
  assert.ok(section.length > 0, 'evaluator section is missing');
  assert.match(section, /breaking change/);
  assert.match(section, /ADR/);
  assert.match(section, /migration note/);
});
