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
const exports = {
  intoto: () => exportInTotoStatement(report, currency),
  otel: () => exportOtelAttributes(report, currency),
  oauth: () => exportOAuthClaims(report, currency),
  spiffe: () => exportSpiffeBinding(report, 'spiffe://example.test/agent/one', currency),
  a2a: () => exportA2aExtension(report, currency),
  mcp: () => exportMcpMeta(report, currency)
};
const tamper = {
  intoto: o => { o.predicate.evidenceMode = 'runtime'; return 'predicate'; },
  otel: o => { o['kya.score.earned'] = 0; return 'kya.score.earned'; },
  oauth: o => { o.kya.evidence_mode = 'runtime'; return 'kya'; },
  spiffe: o => { o.claims.evidence_mode = 'runtime'; return 'claims'; },
  a2a: o => { o.params.evidenceMode = 'runtime'; return 'params'; },
  mcp: o => { o._meta[MCP_META_KEY].evidenceMode = 'runtime'; return '_meta'; }
};

test('bridge comparison binds descriptor-backed export data despite a forged Proxy GET view', () => {
  for (const [kind, build] of Object.entries(exports)) {
    const good = build(), target = JSON.parse(canonical(good)), key = tamper[kind](target);
    const forged = new Proxy(target, { get: (t, k, receiver) => k === key ? good[k] : Reflect.get(t, k, receiver) });
    assert.notEqual(canonical(forged), canonical(good), kind);
    for (const options of [{ report }, { report, ...currency }]) {
      const result = verifyBridgeExport(kind, forged, options);
      assert.equal(result.valid, false, kind);
      assert.ok(result.errors.some(e => e.code === 'REPORT_MISMATCH'), kind);
      assert.equal(result.authenticated, false);
    }
  }
});

test('bridge verification never uses top-level GET traps after canonical capture', () => {
  for (const [kind, build] of Object.entries(exports)) {
    let reads = 0;
    const live = new Proxy(build(), { get() { reads++; throw Error('Live export read'); } });
    for (const options of [{ report }, { report, ...currency }]) {
      const result = verifyBridgeExport(kind, live, options);
      assert.equal(result.valid, true, kind);
      assert.equal(result.currencyRechecked, options.manifest !== undefined);
    }
    assert.equal(reads, 0, kind);
  }
});

test('nested currency containers are captured before currency shape reads', () => {
  const output = exports.oauth();
  let reads = 0;
  output.kya.currency = new Proxy(output.kya.currency, { get() { reads++; throw Error('Live nested read'); } });
  assert.equal(verifyBridgeExport('oauth', output, { report }).valid, true);
  assert.equal(reads, 0);
});

test('plain export compatibility and unauthenticated cross-check limits remain intact', () => {
  for (const [kind, build] of Object.entries(exports)) {
    const good = build(), before = canonical(good);
    const result = verifyBridgeExport(kind, good, { report });
    assert.equal(result.valid, true, kind);
    assert.equal(result.reportChecked, true);
    assert.equal(result.currencyRechecked, false);
    assert.equal(result.authenticated, false);
    assert.match(result.warning, /not that the report is truthful, authentic or authorized/);
    assert.equal(canonical(good), before);
    tamper[kind](good);
    assert.equal(verifyBridgeExport(kind, good, { report }).valid, false, kind);
  }
});
