import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

// Structural checks only. These tests read markdown; they do not judge statistical content.
const ROOT = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, ROOT), 'utf8');

const STUDY = 'docs/CALIBRATION-STUDY.md';
const TEMPLATE = 'docs/CALIBRATION-PREREGISTRATION-TEMPLATE.md';
const ALL = [STUDY, TEMPLATE];

const DISCLAIMER = 'No data exists yet, and nothing in';
const STUDY_HEADINGS = [
  'Hypotheses', 'Outcome definitions', 'Unit of analysis', 'Eligible population and exclusions',
  'Follow-up windows and censoring', 'Baselines', 'Sample size reasoning', 'Handling configuration change',
  'Missing data', 'Multiplicity', 'Decision rules fixed before seeing data', 'Threats to validity',
  'Data governance and privacy', 'What is not established',
];
const TEMPLATE_HEADINGS = [
  'Study identity', 'Hypotheses', 'Outcome definition', 'Unit and population', 'Follow-up and censoring',
  'Baselines', 'Sample size', 'Analysis plan', 'Decision rules', 'Integrity gates', 'Data governance',
  'Deviations log', 'Freeze and hash procedure',
];

function headings(text) {
  return text.split('\n').filter((l) => l.startsWith('## ')).map((l) => l.slice(3).trim());
}

test('calibration docs contain every required section heading', async () => {
  const study = headings(await read(STUDY));
  for (const h of STUDY_HEADINGS) assert.ok(study.includes(h), STUDY + ' lacks section ' + h);
  const template = headings(await read(TEMPLATE));
  for (const h of TEMPLATE_HEADINGS) assert.ok(template.includes(h), TEMPLATE + ' lacks section ' + h);
});

test('calibration docs state that no data exists', async () => {
  for (const path of [STUDY, TEMPLATE]) {
    const text = await read(path);
    assert.ok(text.includes(DISCLAIMER + ' '), path + ' lacks the no-data disclaimer');
    assert.match(text, /No data exists yet, and nothing in [a-z ]+ is evidence of predictive validity\./);
  }
});

test('calibration docs define ACCEPT REJECT and INCONCLUSIVE', async () => {
  const study = await read(STUDY);
  const template = await read(TEMPLATE);
  for (const word of ['ACCEPT', 'REJECT', 'INCONCLUSIVE']) {
    assert.match(study, new RegExp('^' + word + ': ', 'm'), STUDY + ' lacks a definition of ' + word);
    assert.match(template, new RegExp('^' + word + ': ', 'm'), TEMPLATE + ' lacks a field for ' + word);
  }
});

test('calibration docs never claim predictive validity outside a negation', async () => {
  const claim = /predictive validity|is predictive|are predictive|predicts incidents|validated predictor|proven predictor/i;
  const negation = /\b(no|not|nothing|never|cannot|without|neither|nor)\b|n't/i;
  for (const path of ALL) {
    const text = await read(path);
    for (const line of text.split('\n')) {
      if (claim.test(line)) assert.match(line, negation, path + ' has an unnegated claim: ' + line.slice(0, 80));
    }
  }
});

test('preregistration template freezes through the existing campaign ledger', async () => {
  const text = await read(TEMPLATE);
  for (const term of ['SHA-256', 'kya.campaign-plan/v1', 'capture-issuer', 'openLedger', 'campaign-closed', 'headDigest']) {
    assert.ok(text.includes(term), TEMPLATE + ' lacks ' + term);
  }
  assert.match(text, /adds no new ledger kind/);
});

test('calibration docs are plain ASCII', async () => {
  for (const path of ALL) {
    const text = await read(path);
    assert.ok(/^[\x09\x0a\x20-\x7e]*$/.test(text), path + ' contains non-ASCII characters');
  }
});
