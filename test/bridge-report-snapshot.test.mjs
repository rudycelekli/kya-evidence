import test from 'node:test';
import assert from 'node:assert/strict';
import { assess, canonical } from '../src/index.mjs';
import { inputs } from './helpers.mjs';
import {
  exportInTotoStatement, exportOtelAttributes, exportOAuthClaims, exportSpiffeBinding,
  exportA2aExtension, exportMcpMeta, verifyBridgeExport, MCP_META_KEY
} from '../src/interop-bridges/index.mjs';

const source = inputs(), report = assess(source);
const currency = { manifest: source.manifest, policy: source.policy, now: '2026-10-13T12:10:00.000Z' };
const exporters = {
  intoto: () => exportInTotoStatement(report, { allowNotCurrent: true }),
  otel: () => exportOtelAttributes(report, { allowNotCurrent: true }),
  oauth: () => exportOAuthClaims(report, { allowNotCurrent: true }),
  spiffe: () => exportSpiffeBinding(report, 'spiffe://example.test/agent/one', { allowNotCurrent: true }),
  a2a: () => exportA2aExtension(report, { allowNotCurrent: true }),
  mcp: () => exportMcpMeta(report, { allowNotCurrent: true })
};
const runtimeMode = {
  intoto: o => { o.predicate.evidenceMode = 'runtime'; },
  otel: o => { o['kya.evidence.mode'] = 'runtime'; },
  oauth: o => { o.kya.evidence_mode = 'runtime'; },
  spiffe: o => { o.claims.evidence_mode = 'runtime'; },
  a2a: o => { o.params.evidenceMode = 'runtime'; },
  mcp: o => { o._meta[MCP_META_KEY].evidenceMode = 'runtime'; }
};
function changingReport(firstMode, laterMode) {
  let captures = 0;
  const live = new Proxy(report, {
    ownKeys(target) { captures++; return Reflect.ownKeys(target); },
    getOwnPropertyDescriptor(target, key) {
      const descriptor = Reflect.getOwnPropertyDescriptor(target, key);
      return key === 'evidenceMode' ? { ...descriptor, value: captures === 1 ? firstMode : laterMode } : descriptor;
    }
  });
  return { live, captures: () => captures };
}

test('plain report verification and report-derived mismatch compatibility remain intact', () => {
  assert.equal(report.evidenceMode, 'fixture');
  for (const [kind, build] of Object.entries(exporters)) {
    const output = build(), before = canonical(report);
    const valid = verifyBridgeExport(kind, output, { report });
    assert.equal(valid.valid, true, kind);
    assert.equal(valid.reportChecked, true, kind);
    assert.equal(valid.authenticated, false, kind);
    runtimeMode[kind](output);
    const mismatch = verifyBridgeExport(kind, output, { report });
    assert.equal(mismatch.valid, false, kind);
    assert.ok(mismatch.errors.some(e => e.code === 'REPORT_MISMATCH'), kind);
    assert.equal(canonical(report), before);
  }
});

test('a changing native report cannot launder a stale-digest runtime mode into any bridge', () => {
  for (const [kind, build] of Object.entries(exporters)) {
    const output = build(); runtimeMode[kind](output);
    const changing = changingReport('fixture', 'runtime');
    const result = verifyBridgeExport(kind, output, { report: changing.live });
    assert.equal(result.valid, false, kind);
    assert.ok(result.errors.some(e => e.code === 'REPORT_MISMATCH'), kind);
    assert.equal(result.currencyRechecked, false, kind);
  }
});

test('a benign native report is captured once and the checked snapshot supplies the comparison', () => {
  for (const [kind, build] of Object.entries(exporters)) {
    const output = build(), changing = changingReport('fixture', 'fixture');
    const result = verifyBridgeExport(kind, output, { report: changing.live });
    assert.equal(result.valid, true, kind);
    assert.equal(result.reportChecked, true, kind);
    assert.equal(result.currencyRechecked, false, kind);
    assert.equal(result.authenticated, false, kind);
    assert.equal(changing.captures(), 1, kind);
  }
  const changing = changingReport('fixture', 'fixture');
  const checked = exportOtelAttributes(report, currency);
  const result = verifyBridgeExport('otel', checked, { report: changing.live, ...currency });
  assert.equal(result.valid, true);
  assert.equal(result.currencyRechecked, true);
  assert.equal(changing.captures(), 1);
});

test('the captured report checksum is checked even when a later native view would be valid', () => {
  for (const [kind, build] of Object.entries(exporters)) {
    const output = build(); runtimeMode[kind](output);
    const stale = { ...report, evidenceMode: 'runtime' };
    const changing = changingReport('runtime', 'fixture');
    for (const input of [stale, changing.live]) {
      const result = verifyBridgeExport(kind, output, { report: input });
      assert.equal(result.valid, false, kind);
      assert.equal(result.errors[0].code, 'REPORT_INVALID', kind);
      assert.equal(result.reportChecked, false, kind);
    }
  }
});
