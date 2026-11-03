import test from 'node:test';
import assert from 'node:assert/strict';
import { assess } from '../src/index.mjs';
import { inputs } from './helpers.mjs';
import {
  exportInTotoStatement, exportOtelAttributes, exportOAuthClaims, exportSpiffeBinding,
  exportA2aExtension, exportMcpMeta, verifyBridgeExport, MCP_META_KEY
} from '../src/interop-bridges/index.mjs';

const source = inputs();
const qualified = assess(source), nonqualified = assess({ ...source, evidence: [] });
const checked = { manifest: source.manifest, policy: source.policy, now: '2026-10-13T12:10:00.000Z', allowNonQualified: true };
const unchecked = { allowNonQualified: true, allowNotCurrent: true };
const exporters = {
  intoto: exportInTotoStatement,
  otel: exportOtelAttributes,
  oauth: exportOAuthClaims,
  spiffe: (r, o) => exportSpiffeBinding(r, 'spiffe://example.test/agent/one', o),
  a2a: exportA2aExtension,
  mcp: exportMcpMeta
};
const overrides = {
  intoto: o => o.predicate.currency.overrides,
  otel: o => o['kya.gate.overrides'],
  oauth: o => o.kya.currency.overrides,
  spiffe: o => o.claims.currency.overrides,
  a2a: o => o.params.currencyCheck.asOfExport.overrides,
  mcp: o => o._meta[MCP_META_KEY].currencyCheck.asOfExport.overrides
};

test('legitimate nonqualified checked and unchecked exports retain report-only compatibility', () => {
  assert.notEqual(nonqualified.decision, 'qualified');
  for (const [kind, build] of Object.entries(exporters)) {
    for (const options of [checked, unchecked]) {
      const output = build(nonqualified, options);
      assert.ok(overrides[kind](output).includes('allowNonQualified'), kind);
      const result = verifyBridgeExport(kind, output, { report: nonqualified });
      assert.equal(result.valid, true, kind);
      assert.equal(result.reportChecked, true, kind);
      assert.equal(result.currencyRechecked, false, kind);
      assert.equal(result.authenticated, false, kind);
    }
  }
});

test('report-only verification refuses checked reliability inconsistent with report decision or currency', () => {
  const cases = [
    [qualified, checked, false],
    [nonqualified, checked, true],
    [qualified, { ...checked, now: '2026-10-14T12:00:00.000Z', allowNotCurrent: true }, true]
  ];
  for (const kind of ['intoto', 'otel']) {
    for (const [report, options, forgedReliability] of cases) {
      const output = exporters[kind](report, options);
      if (kind === 'intoto') output.predicate.currency.reliable = forgedReliability;
      else output['kya.currency.reliable'] = forgedReliability;
      const result = verifyBridgeExport(kind, output, { report });
      assert.equal(result.valid, false, `${kind}: ${report.decision}`);
      assert.equal(result.errors[0].code, 'MALFORMED', kind);
      assert.equal(result.currencyRechecked, false, kind);
    }
  }
});

test('report-only verification requires the nonqualified override on every checked and unchecked bridge', () => {
  for (const [kind, build] of Object.entries(exporters)) {
    for (const options of [checked, unchecked]) {
      const output = build(nonqualified, options), flags = overrides[kind](output);
      flags.splice(flags.indexOf('allowNonQualified'), 1);
      const result = verifyBridgeExport(kind, output, { report: nonqualified });
      assert.equal(result.valid, false, kind);
      assert.equal(result.errors[0].code, 'MALFORMED', kind);
      assert.equal(result.currencyRechecked, false, kind);
    }
  }
});
