import { validateDossier } from '../application/dossier.mjs';

const UNAUTHENTICATED = 'Standalone unauthenticated report · evidence replay required';
const REPLAYED = 'structured-response-replayed';
const h = value => String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
const md = value => String(value).replace(/\r/g, '\\r').replace(/\n/g, '\\n').replace(/[&<>]/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[character])).replace(/[\\`*{}\[\]()#+.!_|>~\-]/g, '\\$&');
const percentage = value => `${Math.round(value * 10_000) / 100}%`;
const measured = (value, unit) => value === null ? 'Unavailable' : unit === 'USD' ? value === 0 ? '$0.00' : `$${value}` : `${value} ms`;

function captured(value) {
  const dossier = validateDossier(value);
  if (dossier.strengths.some(item => item.verificationReach !== REPLAYED)) throw new Error('Dossier strength requires a structured response replay');
  return dossier;
}

function sourceNotice(mode) {
  return ({ fixture: 'Fixture evidence. No commercial runtime quality was measured.', runtime: 'Runtime-labelled receipts. Actual execution and effects are not authenticated by this report.', mixed: 'Mixed fixture and runtime-labelled receipts. The sources do not establish commercial runtime quality.', none: 'No admissible scored evidence. Unknown checks remain unmeasured.' })[mode];
}

function bindings(dossier) {
  const assessment = dossier.assessment;
  return [
    ['Dossier', dossier.dossierDigest], ['Assessor source', dossier.assessorSourceDigest],
    ['Frozen inputs', dossier.inputsDigest], ['Observations', dossier.observationsDigest],
    ['Assessment', assessment.reportDigest], ['Manifest', assessment.subjectDigest],
    ['Scope', assessment.scopeDigest], ['Profile', assessment.profileDigest],
    ['Evaluator', assessment.evaluatorDigest], ['Relying policy', assessment.policyDigest],
    ['Evidence bundle', assessment.evidenceBundleDigest],
    ...assessment.acceptedEvidenceDigests.map((value, index) => [`Accepted receipt ${index + 1}`, value]),
    ...dossier.benchmarks.map((value, index) => [`Benchmark catalog ${index + 1}`, value.catalogDigest]),
    ...dossier.benchmarkRunDigests.map((value, index) => [`Benchmark run ${index + 1}`, value]),
  ];
}

function rows(dossier) {
  return ['cost', 'latency'].map(kind => {
    const data = dossier.measurements[kind], unit = kind === 'cost' ? 'USD' : 'ms';
    return [kind === 'cost' ? 'Reported evaluator cost' : 'Reported evaluator latency', measured(data[kind === 'cost' ? 'reportedSubtotalUsd' : 'reportedSubtotalMs'], unit), measured(data[kind === 'cost' ? 'reportedTotalUsd' : 'reportedTotalMs'], unit), `${data.known} / ${data.planned} (${percentage(data.coverage)})`, data.aggregation];
  });
}

function recordsByCheck(dossier) {
  return new Map([...dossier.reportedPasses, ...dossier.failureModes].map(item => [item.checkId, item]));
}

function itemFacts(item, escape) {
  return [
    ['Check', item.checkId], ['Dimension', item.dimension], ['Critical', item.critical ? 'yes' : 'no'],
    ['Evidence ID', item.evidenceId ?? 'unavailable'], ['Source', item.source ?? 'unavailable'],
    ['Verification reach', item.verificationReach],
  ].map(([label, value]) => [label, escape(value)]);
}

/** Render only the validator's captured dossier; this view never regrades evidence. */
export function renderDossierMarkdown(value) {
  const dossier = captured(value), assessment = dossier.assessment, records = recordsByCheck(dossier);
  const out = [
    '# KYA Evidence dossier', '', `## ${md(assessment.agentName)}`, '',
    `**${UNAUTHENTICATED}**`, '',
    `Policy decision: **${md(assessment.decision)}**. Evidence source: **${md(assessment.evidenceMode)}**.`, '',
    sourceNotice(assessment.evidenceMode), '',
    'This is a scoped relying-policy result. It grants no authorization, verifies no actual effects, and does not establish complete capture or independent issuer identity. It is not a commercial quality badge or a credit score for a person.', '',
    `Scope: ${md(assessment.scopeId)}. Assessed: ${md(assessment.assessedAt)}. Valid until: ${md(assessment.validUntil)}.`, '',
    `Policy score: ${md(assessment.score.earned)} / ${md(assessment.score.possible)}; possible upper bound: ${md(assessment.score.upperBound)}. Structured coverage: ${md(percentage(assessment.coverage))}; policy-assigned independent coverage: ${md(percentage(assessment.independentCoverage))}.`, '',
    '## Coverage and verification', '',
    '| Planned checks | Reported passes | Structured response replays | Verified original observations |',
    '| --- | --- | --- | --- |',
    `| ${dossier.coverage.plannedChecks} | ${dossier.coverage.reportedPasses} | ${dossier.coverage.verifiedStructuredPasses} | ${dossier.coverage.verifiedOriginals} |`, '',
    `Observations provided: ${dossier.observations.provided}; structured replays: ${dossier.observations.structuredReplays}; verified originals: ${dossier.observations.verifiedOriginals}.`, '',
    'Unknown checks are unmeasured, not weaknesses. Reported passes without a verified original structured response are not demonstrated strengths.', '',
    '## Scoped strengths', '',
    ...dossier.strengths.map(item => `- ${md(item.title)} — ${md(item.checkId)}; ${md(item.source)}; ${md(item.verificationReach)}; evidence ${md(item.evidenceId)}.`),
    ...(dossier.strengths.length ? [] : ['No structured-response-replayed strengths are available.']), '',
    '## Failure observations', '',
    ...dossier.failureModes.flatMap(item => [`### ${md(item.title)}`, '', ...itemFacts(item, md).map(([label, value]) => `- ${label}: ${value}`), `- Reasons: ${item.reasonCodes.map(md).join(', ') || 'none reported'}`, '- Root cause: not established.', '']),
    ...(dossier.failureModes.length ? [] : ['No failure observations supplied. This is not proof of absence of failure.', '']),
    '## Every frozen check', '',
    '| Check | Dimension | Status | Critical | Evidence ID | Verification reach |', '| --- | --- | --- | --- | --- | --- |',
    ...assessment.checks.map(check => `| ${md(check.title)} (${md(check.id)}) | ${md(check.dimension)} | ${md(check.status)} | ${check.critical ? 'yes' : 'no'} | ${md(check.evidenceId ?? 'unavailable')} | ${md(records.get(check.id)?.verificationReach ?? 'not established')} |`), '',
    '## Blind spots and next evidence', '',
    ...dossier.blindSpots.flatMap(item => [`### ${md(item.title)}`, '', `Category: ${md(item.category)}. Checks: ${item.checkIds.map(md).join(', ') || 'none specified'}.`, '', md(item.detail), '', `Next evidence: ${md(item.nextEvidence)}`, '']),
    ...(dossier.blindSpots.length ? [] : ['No blind spots supplied; this does not establish complete assurance.', '']),
    '## Reported measurements', '', md(dossier.measurements.label), '',
    '| Measurement | Observed subtotal | Complete reported total | Coverage | Aggregation |', '| --- | --- | --- | --- | --- |',
    ...rows(dossier).map(row => `| ${row.map(md).join(' | ')} |`), '',
    'Missing measurements are not zero. Totals describe receipt-bound evaluator reports, not verified billing, wall-clock performance, retries or total human effort.', '',
    '## Embedded offline control benchmarks', '',
    ...dossier.benchmarks.flatMap((benchmark, index) => [`### Control benchmark ${index + 1}`, '', `Catalog digest: ${md(benchmark.catalogDigest)}. Run digest: ${md(benchmark.runDigest)}.`, '', `Total: ${md(benchmark.summary.total)}; passed: ${md(benchmark.summary.passed)}; failed: ${md(benchmark.summary.failed)}; errors: ${md(benchmark.summary.errors)}; possible: ${md(benchmark.summary.possible)}.`, '', 'Fixture only. Commercial runtimes measured: no. Execution authenticated: no.', '']),
    ...(dossier.benchmarks.length ? [] : ['No embedded benchmark runs provided.', '']),
    '## Policy blockers and rejected evidence', '',
    ...assessment.blockers.map(code => `- Policy blocker: ${md(code)}`),
    ...assessment.rejectedEvidence.map(item => `- Rejected receipt ${md(item.index)} (${md(item.id ?? 'unavailable')}): ${md(item.reason)}`),
    ...dossier.observations.rejected.map(item => `- Rejected observation ${md(item.index)} (${md(item.digest ?? 'unavailable')}): ${md(item.code)}`),
    ...(assessment.blockers.length || assessment.rejectedEvidence.length || dossier.observations.rejected.length ? [] : ['None reported.']), '',
    '## Bound evidence digests', '', '| Binding | SHA-256 |', '| --- | --- |',
    ...bindings(dossier).map(([label, digest]) => `| ${label} | ${md(digest)} |`), '',
    'These are unsigned content commitments. Reconstruct the dossier from trusted original inputs and replay its evidence before relying on the decision. A matching checksum or valid signature does not establish truthful execution.', '',
    '## Limitations', '', ...dossier.limitations.map(item => `- ${md(item)}`), '',
    'Raw responses and private source code are not included in this presentation.', '',
  ];
  return out.join('\n');
}

const style = `:root{color-scheme:light;--ink:#182b29;--muted:#536961;--paper:#f4f2eb;--line:#cbd3c9;--green:#234f41;--accent:#e8eedf}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1100px;margin:auto;padding:48px 40px 80px}header{padding:0 0 30px;border-bottom:2px solid var(--ink)}.eyebrow{font-size:11px;letter-spacing:.18em;text-transform:uppercase;font-weight:700;color:var(--muted)}h1{font:clamp(38px,6vw,64px)/1.06 Georgia,serif;margin:18px 0}h2{font:28px/1.2 Georgia,serif;margin:0 0 16px}h3{font-size:17px;margin:0 0 8px}p{margin:10px 0}.lead{max-width:78ch;color:var(--muted)}.warning{padding:16px 20px;margin:24px 0;border:1px solid #a88e54;border-left:4px solid #826629;background:#faf2dc}.warning strong{display:block}.policy{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:24px}.policy>div{border-top:1px solid var(--line);padding-top:14px}.value{display:block;font:30px/1.3 Georgia,serif;overflow-wrap:anywhere}.label{display:block;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}section{padding-top:32px;margin-top:24px;border-top:1px solid var(--line)}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}.metric{background:#fff;border:1px solid var(--line);padding:16px}.metric .value{font-size:32px}.note{font-size:14px;color:var(--muted)}.empty{padding:16px;background:#eaece5}.detail{border:1px solid var(--line);margin:10px 0;background:#fff;break-inside:avoid}.detail summary{padding:15px 18px;cursor:pointer;font-weight:600}.detail summary::marker{color:var(--green)}.detail-body{border-top:1px solid var(--line);padding:16px 18px}.detail .status{font-size:12px;font-weight:500;margin-left:12px;color:var(--muted)}dl{display:grid;grid-template-columns:minmax(130px,1fr) minmax(0,3fr);margin:0}dt,dd{padding:7px 0;border-bottom:1px solid #e7ebe5;margin:0}dt{font-size:13px;color:var(--muted)}dd{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;font-size:14px}caption{text-align:left;color:var(--muted);margin-bottom:10px}th,td{text-align:left;vertical-align:top;padding:12px 10px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}th{font-size:11px;letter-spacing:.06em;text-transform:uppercase;background:var(--accent)}.table-scroll{overflow:auto}code{font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere;word-break:break-word}.checks small{display:block;font-weight:400;color:var(--muted)}ul{padding-left:22px}li{margin:6px 0}.bindings{font-size:13px}.bindings td:first-child{width:180px}footer{margin-top:40px;border-top:2px solid var(--ink);padding-top:20px;font-size:12px;color:var(--muted)}@media(max-width:700px){main{padding:28px 20px 50px}.metrics{grid-template-columns:repeat(2,1fr)}.policy{grid-template-columns:1fr}dl{grid-template-columns:1fr}dd{padding-top:0}}@media print{@page{size:A4;margin:15mm}body{background:#fff;font-size:10pt}main{max-width:none;padding:0}h1{font-size:32pt}h2{font-size:20pt}section{padding-top:16px;margin-top:16px}.metrics{grid-template-columns:repeat(4,1fr)}.detail summary{padding:9px 12px;cursor:default}.detail>div{display:block!important}details::details-content{display:block!important;content-visibility:visible!important}.detail-body{padding:10px 12px}details:not([open])>.detail-body{content-visibility:visible!important}summary::marker{content:""}table{font-size:9pt}.table-scroll{overflow:visible}.warning,.metric,th{background:#fff}.bindings code{font-size:8pt}footer{margin-top:20px}.policy .value{font-size:20pt}}`;

function factsHtml(item) {
  return `<dl>${itemFacts(item, h).map(([label, value]) => `<dt>${label}</dt><dd>${value}</dd>`).join('')}</dl>`;
}

function checkHtml(check, item) {
  const reason = item?.reasonCodes?.length ? `<p><b>Reasons:</b> ${item.reasonCodes.map(h).join(', ')}</p>` : '';
  return `<details open class="detail checks"><summary>${h(check.title)} <span class="status">${h(check.status)}${check.critical ? ' · critical' : ''}</span><small>${h(check.id)} · ${h(check.dimension)}</small></summary><div class="detail-body"><dl><dt>Status</dt><dd>${h(check.status)}</dd><dt>Critical gate</dt><dd>${check.critical ? 'yes' : 'no'}</dd><dt>Frozen weight</dt><dd>${h(check.weight)}</dd><dt>Evidence ID</dt><dd>${h(check.evidenceId ?? 'unavailable')}</dd><dt>Signing key ID</dt><dd><code>${h(check.keyId ?? 'unavailable')}</code></dd><dt>Issuer role</dt><dd>${h(check.independence ?? 'not established')} · relying-policy assignment</dd><dt>Source</dt><dd>${h(item?.source ?? 'not established')}</dd><dt>Verification reach</dt><dd>${h(item?.verificationReach ?? 'not established')}</dd></dl>${reason}${check.status === 'unknown' ? '<p class="note">Unmeasured. This check is not an observed weakness or a pass.</p>' : ''}<p class="note">Root cause: not established. A reported outcome alone does not establish actual execution or effects.</p></div></details>`;
}

/** Standalone offline HTML; all dossier strings are escaped, with no active scripts. */
export function renderDossierHtml(value) {
  const dossier = captured(value), assessment = dossier.assessment, records = recordsByCheck(dossier);
  const coverage = [['Planned checks', dossier.coverage.plannedChecks], ['Reported passes', dossier.coverage.reportedPasses], ['Structured replays', dossier.coverage.verifiedStructuredPasses], ['Verified originals', dossier.coverage.verifiedOriginals]];
  const strengths = dossier.strengths.map(item => `<details open class="detail"><summary>${h(item.title)} <span class="status">structured response replay</span></summary><div class="detail-body">${factsHtml(item)}<p class="note">Scoped evaluator result over the verified original structured response. Actual execution, effects and complete monitoring remain unverified.</p></div></details>`).join('') || '<p class="empty">No structured-response-replayed strengths are available.</p>';
  const failures = dossier.failureModes.map(item => `<details open class="detail"><summary>${h(item.title)} <span class="status">${h(item.dimension)}${item.critical ? ' · critical' : ''}</span></summary><div class="detail-body">${factsHtml(item)}<p><b>Reasons:</b> ${item.reasonCodes.map(h).join(', ') || 'none reported'}</p><p><b>Root cause:</b> not established.</p></div></details>`).join('') || '<p class="empty">No failure observations supplied. This is not proof of absence of failure.</p>';
  const blindSpots = dossier.blindSpots.map(item => `<details open class="detail"><summary>${h(item.title)} <span class="status">${h(item.category)}</span></summary><div class="detail-body"><p>${h(item.detail)}</p><dl><dt>Blind spot ID</dt><dd>${h(item.id)}</dd><dt>Related checks</dt><dd>${item.checkIds.map(h).join(', ') || 'none specified'}</dd><dt>Next evidence</dt><dd>${h(item.nextEvidence)}</dd></dl></div></details>`).join('') || '<p class="empty">No blind spots supplied; this does not establish complete assurance.</p>';
  const benchmarks = dossier.benchmarks.map((benchmark, index) => `<details open class="detail"><summary>Control benchmark ${index + 1} <span class="status">fixture only</span></summary><div class="detail-body"><dl><dt>Catalog digest</dt><dd><code>${h(benchmark.catalogDigest)}</code></dd><dt>Run digest</dt><dd><code>${h(benchmark.runDigest)}</code></dd><dt>Total / possible</dt><dd>${h(benchmark.summary.total)} / ${h(benchmark.summary.possible)}</dd><dt>Passed / failed / errors</dt><dd>${h(benchmark.summary.passed)} / ${h(benchmark.summary.failed)} / ${h(benchmark.summary.errors)}</dd><dt>Commercial runtimes measured</dt><dd>no</dd><dt>Execution authenticated</dt><dd>no</dd></dl></div></details>`).join('') || '<p class="empty">No embedded benchmark runs provided.</p>';
  const blockers = assessment.blockers.map(code => `<li>Policy blocker: ${h(code)}</li>`).join('');
  const rejected = [...assessment.rejectedEvidence.map(item => `<li>Rejected receipt ${h(item.index)} (${h(item.id ?? 'unavailable')}): ${h(item.reason)}</li>`), ...dossier.observations.rejected.map(item => `<li>Rejected observation ${h(item.index)} (<code>${h(item.digest ?? 'unavailable')}</code>): ${h(item.code)}</li>`)].join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"><title>KYA Evidence dossier · ${h(assessment.agentName)}</title><style>${style}</style></head><body><main><header><div class="eyebrow">KYA Evidence / experimental reference implementation</div><h1>${h(assessment.agentName)}</h1><p class="lead">A scoped account of reported checks, verified structured observations, failure patterns and the evidence still needed.</p><div class="warning"><strong>${h(UNAUTHENTICATED)}</strong><span>Checksums identify bytes. Signature validity does not establish truthful execution, identity or independent review.</span></div><div class="policy"><div><span class="label">Reported relying-policy decision</span><span class="value">${h(assessment.decision)}</span></div><div><span class="label">Evidence source</span><span class="value">${h(assessment.evidenceMode)}</span></div></div><p>${h(sourceNotice(assessment.evidenceMode))}</p><p class="note">This report is not a commercial quality badge or a credit score for a person. Authorization granted: no. Actual effects verified: no. Capture complete: no. Issuer independence: relying-policy assignment.</p><p class="note">Scope: ${h(assessment.scopeId)} · assessed ${h(assessment.assessedAt)} · valid until ${h(assessment.validUntil)}</p></header><section><h2>Coverage before conclusions</h2><div class="metrics">${coverage.map(([label, value]) => `<div class="metric"><span class="label">${label}</span><span class="value">${h(value)}</span></div>`).join('')}</div><p>Policy score: <b>${h(assessment.score.earned)} / ${h(assessment.score.possible)}</b> · possible upper bound ${h(assessment.score.upperBound)}. Structured coverage ${h(percentage(assessment.coverage))}; policy-assigned independent coverage ${h(percentage(assessment.independentCoverage))}.</p><p class="note">Observations provided: ${h(dossier.observations.provided)} · structured replays: ${h(dossier.observations.structuredReplays)} · verified originals: ${h(dossier.observations.verifiedOriginals)}.</p><p class="note">Unknown checks are unmeasured, not weaknesses. Reported passes without a verified original structured response are not demonstrated strengths.</p></section><section><h2>Scoped strengths</h2>${strengths}</section><section><h2>Failure observations</h2>${failures}<p class="note">Patterns describe supplied evidence. Causal explanations require separate reviewed intervention evidence.</p></section><section><h2>Every frozen check</h2>${assessment.checks.map(check => checkHtml(check, records.get(check.id))).join('')}</section><section><h2>Blind spots and next evidence</h2>${blindSpots}</section><section><h2>Reported measurements</h2><p class="note">${h(dossier.measurements.label)}</p><div class="table-scroll"><table><caption>Coverage and aggregation over the declared receipt population</caption><thead><tr><th>Measurement</th><th>Observed subtotal</th><th>Complete reported total</th><th>Coverage</th><th>Aggregation</th></tr></thead><tbody>${rows(dossier).map(row => `<tr>${row.map(cell => `<td>${h(cell)}</td>`).join('')}</tr>`).join('')}</tbody></table></div><p class="note">Missing measurements are not zero. These reports do not verify billing, wall-clock performance, retries or total human effort.</p></section><section><h2>Embedded offline control benchmarks</h2>${benchmarks}<p class="note">Fixture controls exercise selected protocol and evaluator behavior. They are not commercial runtime measurements.</p></section><section><h2>Policy blockers and rejected evidence</h2>${blockers || rejected ? `<ul>${blockers}${rejected}</ul>` : '<p class="empty">None reported.</p>'}</section><section><h2>Bound evidence digests</h2><table class="bindings"><thead><tr><th>Binding</th><th>SHA-256</th></tr></thead><tbody>${bindings(dossier).map(([label, digest]) => `<tr><td>${label}</td><td><code>${h(digest)}</code></td></tr>`).join('')}</tbody></table><p class="note">These are unsigned content commitments. Reconstruct the dossier from trusted original inputs and replay its evidence before relying on the decision. Matching checksums do not authenticate the producer or execution.</p></section><section><h2>Limitations</h2><ul>${dossier.limitations.map(item => `<li>${h(item)}</li>`).join('')}</ul></section><footer>Standalone offline dossier · raw responses and private source code are not included · open each detail for evidence reach and limitations. All detail content is included when printed.</footer></main></body></html>`;
}
