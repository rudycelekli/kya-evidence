import { canonical, insist } from '../shared/canonical.mjs';
import { verifyAssessment } from '../assessment/application/assess.mjs';
import { CURRENCY_CODES } from '../assessment/application/codes.mjs';
import { timestamp } from '../identity/domain/services/validation.mjs';
import { gate, checkUrl, checkReportTimes, ownOptions, GATE_FLAGS } from './gate.mjs';
import { checkReportFields } from '../assessment/application/report-shape.mjs';
import { buildStatement } from './intoto.mjs';
import { buildAttributes, currencyFromAttributes } from './otel.mjs';
import { buildOAuthClaims, buildSpiffeBinding, checkSpiffeId } from './oauth.mjs';
import { buildA2aExtension, buildMcpMeta, MCP_META_KEY } from './discovery.mjs';

export const BRIDGE_KINDS = Object.freeze(['intoto', 'otel', 'oauth', 'spiffe', 'a2a', 'mcp']);
const BASE = { authenticated: false, warning: 'This cross-check rebuilds the export from the supplied report and compares it. It proves the export is consistent with that report, not that the report is truthful, authentic or authorized.' };

// Each kind: read the currency block and any export-time extras out of the output, and rebuild the whole export from a report.
const camelCurrency = c => ({ checked: c.checked, current: c.current, reliable: c.reliable ?? null, checkedAt: c.checkedAt, triggerCodes: c.triggerCodes, digest: c.digest, overrides: c.overrides });
const KINDS = {
  intoto: { read: o => ({ currency: camelCurrency(o.predicate.currency) }), build: (r, c) => buildStatement(r, c) },
  otel: { read: o => ({ currency: currencyFromAttributes(o) }), build: (r, c) => buildAttributes(r, c) },
  oauth: {
    read: o => { const k = o.kya.currency; return { currency: { checked: k.checked, current: k.current, reliable: k.current === null ? null : k.current && o.kya.decision === 'qualified', checkedAt: k.checked_at, triggerCodes: k.trigger_codes, digest: k.digest, overrides: k.overrides } }; },
    build: (r, c) => buildOAuthClaims(r, c)
  },
  spiffe: {
    read: o => ({ ...KINDS.oauth.read({ kya: o.claims }), spiffeId: checkSpiffeId(o.spiffeId) }),
    build: (r, c, x) => buildSpiffeBinding(r, c, x.spiffeId)
  },
  a2a: { read: o => ({ currency: pointerCurrency(o.params), url: o.params.assessmentUrl }), build: (r, c, x) => buildA2aExtension(r, c, x.url) },
  mcp: { read: o => ({ currency: pointerCurrency(o._meta[MCP_META_KEY]), url: o._meta[MCP_META_KEY].assessmentUrl }), build: (r, c, x) => buildMcpMeta(r, c, x.url) }
};
function pointerCurrency(p) {
  const a = p.currencyCheck.asOfExport;
  return { checked: a.checked, current: a.current, reliable: a.current === null ? null : a.current && p.decision === 'qualified', checkedAt: a.checkedAt, triggerCodes: a.triggerCodes, digest: a.digest, overrides: a.overrides };
}

// Invariants of a currency block taken from the export itself (used only when currency is not rechecked). A block that contradicts
// itself, for example not checked yet current, cannot have come from the exporter.
const HEX64 = /^[a-f0-9]{64}$/;
const sortedUnique = a => a.every((x, i) => i === 0 || a[i - 1] < x);
export function checkCurrencyBlock(c) {
  insist(c && typeof c === 'object', 'Currency block must be an object');
  insist(typeof c.checked === 'boolean', 'Currency block checked must be a boolean');
  insist(Array.isArray(c.triggerCodes) && c.triggerCodes.every(x => typeof x === 'string' && Object.values(CURRENCY_CODES).includes(x)) && sortedUnique(c.triggerCodes), 'Currency block trigger codes must be sorted unique known codes');
  insist(Array.isArray(c.overrides) && c.overrides.every(x => GATE_FLAGS.includes(x)) && sortedUnique(c.overrides), 'Currency block overrides must be sorted unique known flags');
  if (!c.checked) {
    insist(c.current === null && c.digest === null && c.checkedAt === null && c.reliable === null && c.triggerCodes.length === 0, 'An unchecked currency block must carry no result');
    insist(c.overrides.includes('allowNotCurrent'), 'An unchecked currency block must record the allowNotCurrent override');
  } else {
    insist(typeof c.current === 'boolean' && c.current === (c.triggerCodes.length === 0), 'Currency block current contradicts its trigger codes');
    insist(typeof c.reliable === 'boolean', 'Currency block reliable must be a boolean');
    insist(typeof c.digest === 'string' && HEX64.test(c.digest), 'Currency block digest must be 64 hex characters');
    timestamp(c.checkedAt, 'Currency block checked time');
    insist(c.current || c.overrides.includes('allowNotCurrent'), 'A not-current block must record the allowNotCurrent override');
  }
}

const form = v => v === undefined ? 'undefined' : canonical(v);
function diff(actual, expected) {
  const names = [];
  for (const k of new Set([...Object.keys(expected), ...Object.keys(actual)])) {
    if (form(actual[k]) === form(expected[k])) continue;
    const a = actual[k], e = expected[k];
    if (a && e && typeof a === 'object' && typeof e === 'object' && !Array.isArray(a) && !Array.isArray(e)) {
      const sub = [...new Set([...Object.keys(a), ...Object.keys(e)])].filter(s => form(a[s]) !== form(e[s]));
      names.push(`${k} (${sub.join(', ')})`);
    } else names.push(k);
  }
  return names;
}

/**
 * Report-style cross-check, like the VC bridge. Never throws for bad input: returns { valid, errors, reportChecked, currencyRechecked }.
 * Given the source kya.assessment/v1 report, the export is rebuilt with the exporter own construction and compared whole in canonical
 * form; any difference is REPORT_MISMATCH naming the member. Without manifest, policy and now, the currency block is taken from the
 * export itself, so only the report-derived members are bound and currencyRechecked is false: a forged currency block then passes.
 * With manifest, policy and now (and incidents when used) the currency check is run again and compared too. The export-time overrides
 * recorded in the output are honoured only if the recomputation also needed them.
 */
export function verifyBridgeExport(kind, output, rawOptions = {}) {
  const { report, manifest, policy, now, incidents, assessmentUrl } = ownOptions(rawOptions);
  const errors = [];
  const finish = extra => ({ ...BASE, valid: errors.length === 0, errors, reportChecked: false, currencyRechecked: false, ...extra });
  const spec = typeof kind === 'string' && Object.hasOwn(KINDS, kind) ? KINDS[kind] : null;
  if (!spec) { errors.push({ code: 'UNKNOWN_KIND', message: `kind must be one of ${BRIDGE_KINDS.join(', ')}` }); return finish(); }
  if (!output || typeof output !== 'object' || Array.isArray(output)) { errors.push({ code: 'MALFORMED', message: 'Export must be an object' }); return finish(); }
  try { canonical(output); } catch (e) { errors.push({ code: 'MALFORMED', message: `Export is not plain canonical JSON data: ${e.message}` }); return finish(); }
  if (report === undefined) { errors.push({ code: 'REPORT_REQUIRED', message: 'The cross-check needs the source report' }); return finish(); }
  let r;
  try { verifyAssessment(report); r = JSON.parse(canonical(report)); checkReportTimes(r); checkReportFields(r); } catch (e) { errors.push({ code: 'REPORT_INVALID', message: e.message }); return finish(); }
  let read;
  try { read = spec.read(output); if (read.url !== undefined) checkUrl(read.url, 'assessmentUrl'); } catch (e) { errors.push({ code: 'MALFORMED', message: `Export does not have the ${kind} shape: ${e.message}` }); return finish(); }
  if (assessmentUrl !== undefined) {
    if (!('url' in read)) { errors.push({ code: 'OPTION_NOT_APPLICABLE', message: `assessmentUrl applies only to a2a and mcp, not ${kind}` }); return finish(); }
    try { checkUrl(assessmentUrl, 'assessmentUrl'); } catch (e) { errors.push({ code: 'MALFORMED', message: e.message }); return finish(); }
    if (read.url !== assessmentUrl) errors.push({ code: 'REPORT_MISMATCH', message: 'Export differs from the supplied report in: assessmentUrl' });
  }
  const recheck = manifest !== undefined || policy !== undefined || now !== undefined || incidents !== undefined;
  let currency = read.currency;
  if (recheck) {
    try { currency = gate(r, { manifest, policy, now, incidents, allowNonQualified: true, allowNotCurrent: true }).currency; }
    catch (e) { errors.push({ code: e.code === 'CURRENCY_INPUTS_INCOMPLETE' ? e.code : 'CURRENCY_RECHECK_FAILED', message: e.message }); return finish({ reportChecked: false }); }
  } else {
    try { checkCurrencyBlock(currency); } catch (e) { errors.push({ code: 'MALFORMED', message: `Currency block is malformed: ${e.message}` }); return finish(); }
  }
  let expected;
  try { expected = spec.build(r, currency, read); } catch (e) { errors.push({ code: 'MALFORMED', message: e.message }); return finish(); }
  let d;
  try { d = diff(output, expected); } catch (e) { errors.push({ code: 'MALFORMED', message: `Export could not be compared: ${e.message}` }); return finish(); }
  if (d.length) errors.push({ code: 'REPORT_MISMATCH', message: `Export differs from the supplied report in: ${d.join(', ')}` });
  return finish({ reportChecked: true, currencyRechecked: recheck });
}
