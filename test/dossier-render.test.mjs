import test from 'node:test';
import assert from 'node:assert/strict';
import { createDossier } from '../src/reporting/application/dossier.mjs';
import { renderDossierHtml, renderDossierMarkdown } from '../src/reporting/infrastructure/render.mjs';
import { CORE_PROFILE, EVALUATOR_DIGEST, createReferenceAdapter, runConformance } from '../src/conformance/index.mjs';
import { digest, signEvidence } from '../src/index.mjs';
import { NOW, inputs, manifest, profile, policy, bundle, keys, clone } from './helpers.mjs';

function supplied(patch = {}) {
  const m = manifest(), p = profile();
  if (patch.name) m.agent.name = patch.name;
  if (patch.title) p.checks[0].title = patch.title;
  return { manifest: m, profile: p, policy: policy(p), evidence: bundle(m, p), evaluatorDigest: inputs().evaluatorDigest, now: NOW };
}

async function originalFixture(mode = 'careful') {
  const m = manifest(), run = await runConformance({ adapter: createReferenceAdapter({ mode }), manifest: m, now: NOW });
  for (const [index, observation] of run.observations.entries()) {
    observation.transportLatencyMs = 0;
    if (observation.response !== null) observation.response.usage.costUsd = 0;
    observation.reasons.push('PRIVATE-ORIGINAL-CANARY-MUST-NOT-EXPORT');
    run.evidence[index].artifactDigest = digest(observation);
  }
  return { inputs: { manifest: m, profile: CORE_PROFILE, policy: policy(CORE_PROFILE), evidence: run.evidence.map(item => signEvidence(item, keys.privateKey)), evaluatorDigest: EVALUATOR_DIGEST, now: NOW }, observations: run.observations };
}

test('standalone views show actual policy result and missing originals without invented strengths', () => {
  const dossier = createDossier({ inputs: supplied() });
  assert.equal(dossier.assessment.decision, 'qualified');
  assert.equal(dossier.strengths.length, 0);
  for (const view of [renderDossierHtml(dossier), renderDossierMarkdown(dossier)]) {
    assert.match(view, /Standalone unauthenticated report/);
    assert.match(view, /evidence replay required/);
    assert.match(view, /qualified/);
    assert.match(view, /fixture/);
    assert.match(view, /No structured-response-replayed strengths are available/);
    assert.match(view, /not a commercial quality badge/);
    assert.match(view, /Unknown checks are unmeasured, not weaknesses/);
    assert.match(view, /not verified billing/);
    assert.ok(view.includes(dossier.dossierDigest));
    assert.ok(view.includes(dossier.assessment.acceptedEvidenceDigests[0]));
  }
});

test('HTML treats agent, check and limitation strings as inert data', () => {
  const attack = '</h1><script>fetch("https://attacker.example")</script><img src=x onerror=alert(1)>', dossier = createDossier({ inputs: supplied({ name: attack, title: attack }) });
  dossier.limitations.push(attack);
  const { dossierDigest: old, ...body } = dossier;
  dossier.dossierDigest = digest(body);
  const html = renderDossierHtml(dossier);
  assert.doesNotMatch(html, /<script|<img\b|<iframe\b|<link\b|<svg\b/);
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(html.includes('&quot;https://attacker.example&quot;'));
  assert.ok(!html.includes(attack));
  assert.ok(old !== dossier.dossierDigest);
});

test('Markdown escapes HTML, table delimiters, headings, code fences and line breaks in data', () => {
  const attack = '<script>x</script>\n# injected | [link](https://attacker.example) ```', dossier = createDossier({ inputs: supplied({ name: attack, title: attack }) });
  const markdown = renderDossierMarkdown(dossier);
  assert.doesNotMatch(markdown, /<script|\n# injected|\n\| injected|```/);
  assert.ok(markdown.includes('&lt;script&gt;'));
  assert.ok(markdown.includes('\\|'));
  assert.ok(markdown.includes('\\['));
  assert.ok(markdown.includes('\\`'));
});

test('verified structured originals produce scoped strengths, preserve zero telemetry and omit raw originals', async () => {
  const dossier = createDossier(await originalFixture());
  assert.equal(dossier.strengths.length, CORE_PROFILE.checks.length);
  assert.equal(dossier.measurements.cost.reportedTotalUsd, 0);
  assert.equal(dossier.measurements.latency.reportedTotalMs, 0);
  for (const view of [renderDossierHtml(dossier), renderDossierMarkdown(dossier)]) {
    assert.match(view, /\$0\.00/);
    assert.match(view, /0 ms/);
    assert.match(view, /structured.response.replay/);
    assert.doesNotMatch(view, /PRIVATE-ORIGINAL-CANARY-MUST-NOT-EXPORT|"actions"|"response"/);
  }
  assert.match(renderDossierHtml(dossier), /Actual execution, effects and complete monitoring remain unverified/);
});

test('missing original with zero known measurements leaves complete total unavailable', async () => {
  const options = await originalFixture();
  options.observations.pop();
  const dossier = createDossier(options), html = renderDossierHtml(dossier);
  assert.equal(dossier.coverage.verifiedStructuredPasses, CORE_PROFILE.checks.length - 1);
  assert.equal(dossier.measurements.cost.reportedSubtotalUsd, 0);
  assert.equal(dossier.measurements.cost.reportedTotalUsd, null);
  assert.match(html, /\$0\.00/);
  assert.match(html, /Unavailable/);
  assert.match(html, /Passed assertions lack structured-response support/);
});

test('failure details keep root cause unestablished and unknowns stay outside failure observations', async () => {
  const failing = createDossier(await originalFixture('reckless'));
  assert.equal(failing.assessment.decision, 'blocked');
  assert.ok(failing.failureModes.length > 0);
  assert.match(renderDossierHtml(failing), /<b>Root cause:<\/b> not established/);
  assert.match(renderDossierMarkdown(failing), /Root cause: not established/);
  const frozen = supplied();
  frozen.evidence = [];
  const unknown = createDossier({ inputs: frozen });
  assert.equal(unknown.failureModes.length, 0);
  const html = renderDossierHtml(unknown);
  assert.match(html, /Unmeasured\. This check is not an observed weakness or a pass/);
  assert.match(html, /insufficient-evidence/);
  assert.equal((html.match(/class="detail checks"/g) ?? []).length, unknown.assessment.checks.length);
});

test('rejected observations retain original indices, digests and stable reason codes', async () => {
  const options = await originalFixture();
  options.observations.push(clone(options.observations[0]));
  const dossier = createDossier(options);
  assert.equal(dossier.observations.rejected.length, 2);
  for (const view of [renderDossierHtml(dossier), renderDossierMarkdown(dossier)]) {
    for (const item of dossier.observations.rejected) {
      assert.ok(view.includes(item.digest));
      assert.ok(view.includes(String(item.index)));
    }
    assert.ok(view.includes('duplicate-observation') || view.includes('duplicate\\-observation'));
  }
});

test('all evidence modes remain explicit and never upgrade a report to authenticated execution', () => {
  for (const mode of ['fixture', 'runtime', 'mixed', 'none']) {
    const frozen = supplied();
    frozen.policy.allowedSources = ['fixture', 'runtime'];
    frozen.evidence = mode === 'none' ? [] : frozen.evidence.map((envelope, index) => signEvidence({ ...envelope.payload, source: mode === 'mixed' ? index % 2 ? 'runtime' : 'fixture' : mode }, keys.privateKey));
    const dossier = createDossier({ inputs: frozen }), html = renderDossierHtml(dossier);
    assert.equal(dossier.assessment.evidenceMode, mode);
    assert.ok(html.includes(`<span class="value">${mode}</span>`));
    assert.match(html, /Actual effects verified: no\. Capture complete: no/);
    assert.match(html, /Issuer independence: relying-policy assignment/);
  }
});

test('offline HTML is semantic, script-free, printable and provides detail for every check and blind spot', () => {
  const dossier = createDossier({ inputs: supplied() }), html = renderDossierHtml(dossier);
  assert.match(html, /<!doctype html><html lang="en">/);
  assert.match(html, /default-src 'none'/);
  assert.match(html, /@media print/);
  assert.match(html, /display:block!important/);
  assert.match(html, /<caption>/);
  assert.doesNotMatch(html, /<script|<link\b|<iframe\b|<form\b|<img\b|https?:\/\/|@import|url\(/);
  assert.equal((html.match(/class="detail checks"/g) ?? []).length, dossier.assessment.checks.length);
  for (const spot of dossier.blindSpots) assert.ok(html.includes(`<summary>${spot.title}`));
  assert.ok(html.endsWith('</main></body></html>'));
});

test('both renderers reject altered checksum and accessor input before producing a view', () => {
  const dossier = createDossier({ inputs: supplied() }), altered = clone(dossier);
  altered.coverage.reportedPasses++;
  for (const render of [renderDossierHtml, renderDossierMarkdown]) assert.throws(() => render(altered));
  let touched = false;
  const accessor = clone(dossier);
  Object.defineProperty(accessor, 'assessment', { get() { touched = true; return dossier.assessment; }, enumerable: true });
  for (const render of [renderDossierHtml, renderDossierMarkdown]) assert.throws(() => render(accessor));
  assert.equal(touched, false);
});
