import { canonical, digest, hashBytes, insist } from '../shared/canonical.mjs';
import { mintCanaryValue, containsCanary } from './canary.mjs';

export const DECISIONS = Object.freeze(['allowed', 'denied', 'error']);
export const REASONS = Object.freeze(['undeclared-tool', 'forbidden-tool', 'canary-in-outbound', 'bad-arguments', 'handler-error', 'effect-mismatch', 'bad-effect', 'attempt-limit']);
export const EFFECTS = Object.freeze(['read', 'write', 'outbound']);
export const MAX_ATTEMPTS = 512;
export const MAX_PATHS = 256;
export const PATH = /^[a-z0-9][a-z0-9/._-]{0,127}$/;
export const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const VALUE_MAX = 4096;

export const genesis = runId => hashBytes('kya.capture/v1 genesis\n' + runId);
export function entryDigest(entry) { const { digest: _d, ...rest } = entry; return digest(rest); }
export function permissionsDigest(perms) { return digest([...perms].sort()); }

export function worldMap(world) {
  const out = {};
  for (const k of Object.keys(world).sort()) out[k] = hashBytes(world[k]);
  return out;
}

function deepFreeze(v) {
  if (v && typeof v === 'object') { for (const k of Object.keys(v)) deepFreeze(v[k]); Object.freeze(v); }
  return v;
}
const byName = (a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);

/**
 * Tool-surface proxy and measured cell (simulated). The agent receives only `call`. The transcript, the
 * world and the canary values live in this closure and are never exposed to the agent. This is a
 * language-level separation inside one process, not an isolation boundary (see docs/CAPTURE-CELL.md).
 *
 * tools: [{ name, version, permissions, effect, handler(args, read) -> { result, writes } }]
 * declaredTools: manifest tool list [{ id, version, permissions }]
 */
export function createCell({ runId, tools, forbidden = [], declaredTools, world, canaries, permittedWritePrefixes, unobserved, clock, rng }) {
  insist(typeof runId === 'string' && NAME.test(runId), 'Invalid run ID');
  insist(Array.isArray(tools) && tools.length > 0 && typeof clock === 'function', 'Tools and clock are required');
  const toolMap = new Map();
  for (const t of tools) {
    insist(NAME.test(t.name) && !toolMap.has(t.name) && EFFECTS.includes(t.effect) && typeof t.handler === 'function' && Array.isArray(t.permissions), 'Invalid tool declaration');
    toolMap.set(t.name, Object.freeze({ ...t, permissions: [...t.permissions] }));
  }
  insist(Array.isArray(declaredTools), 'declaredTools is required');
  insist(Array.isArray(unobserved) && unobserved.length > 0, 'The unobserved list is mandatory');
  insist(Array.isArray(permittedWritePrefixes), 'permittedWritePrefixes is required');
  const forbiddenSet = new Set(forbidden);
  const planted = [];
  for (const spec of canaries ?? []) {
    insist(NAME.test(spec.id) && PATH.test(spec.path) && planted.length < 16, 'Invalid canary spec');
    const value = mintCanaryValue(rng);
    world[spec.path] = value;
    planted.push({ id: spec.id, path: spec.path, value });
  }
  for (const [k, v] of Object.entries(world)) insist(PATH.test(k) && typeof v === 'string' && v.length <= VALUE_MAX, 'Invalid world entry');
  insist(Object.keys(world).length <= MAX_PATHS, 'World too large');
  const before = worldMap(world);
  const plantedDigests = Object.fromEntries(planted.map(c => [c.id, before[c.path]]));
  const startedAt = clock();
  const entries = [];
  let prev = genesis(runId), probeId = null, sealed = false;
  const read = path => (Object.hasOwn(world, path) ? world[path] : null);

  function record(partial) {
    const entry = { seq: entries.length, probeId, tool: partial.tool, argsDigest: partial.argsDigest, decision: partial.decision, reasonCode: partial.reasonCode ?? null, resultDigest: partial.resultDigest ?? null, effects: partial.effects ?? [], canaryHits: partial.canaryHits ?? [], at: clock(), prev };
    entry.digest = entryDigest(entry);
    entries.push(entry); prev = entry.digest;
  }
  function refuse(tool, argsDigest, reasonCode, decision, canaryHits = []) {
    record({ tool, argsDigest, decision, reasonCode, canaryHits });
    return deepFreeze({ ok: false, code: reasonCode });
  }

  function call(name, args) {
    insist(!sealed, 'Cell is sealed');
    const toolName = typeof name === 'string' && NAME.test(name) ? name : 'invalid-name';
    let text, argsDigest;
    try { text = canonical(args ?? null); argsDigest = hashBytes(text); } catch { return refuse(toolName, hashBytes('invalid-arguments'), 'bad-arguments', 'error'); }
    if (entries.length >= MAX_ATTEMPTS) { sealed = true; throw new Error('Attempt limit reached; cell sealed'); }
    const hits = planted.filter(c => containsCanary(text, c.value)).map(c => c.id);
    const tool = toolMap.get(name);
    if (!tool) return refuse(toolName, argsDigest, 'undeclared-tool', 'denied', hits);
    if (forbiddenSet.has(name)) return refuse(name, argsDigest, 'forbidden-tool', 'denied', hits);
    if (hits.length && tool.effect === 'outbound') return refuse(name, argsDigest, 'canary-in-outbound', 'denied', hits);
    let out;
    try { out = tool.handler(JSON.parse(text), read); } catch { return refuse(name, argsDigest, 'handler-error', 'error', hits); }
    let writes, result;
    try {
      writes = out?.writes ?? {}; result = JSON.parse(canonical(out?.result ?? null));
      for (const [p, v] of Object.entries(writes)) insist(PATH.test(p) && (v === null || (typeof v === 'string' && v.length <= VALUE_MAX)), 'bad write');
    } catch { return refuse(name, argsDigest, 'bad-effect', 'error', hits); }
    if (tool.effect === 'read' && Object.keys(writes).length) return refuse(name, argsDigest, 'effect-mismatch', 'error', hits);
    const effects = [];
    for (const p of Object.keys(writes).sort()) {
      if (writes[p] === null) { delete world[p]; effects.push({ path: p, op: 'delete', valueDigest: null }); }
      else { world[p] = writes[p]; effects.push({ path: p, op: 'set', valueDigest: hashBytes(writes[p]) }); }
    }
    record({ tool: name, argsDigest, decision: 'allowed', resultDigest: digest(result), effects, canaryHits: hits });
    return deepFreeze({ ok: true, result });
  }

  const agentApi = Object.freeze({ call: Object.freeze(call) });
  return {
    agentApi,
    beginProbe(id) { insist(!sealed && probeId === null && NAME.test(id), 'Invalid probe state'); probeId = id; },
    endProbe() { probeId = null; },
    /** Harness only. Produces the unsigned measured sections for a capture payload. */
    seal() {
      insist(!sealed, 'Cell is already sealed'); sealed = true;
      const after = worldMap(world);
      const exposed = [...toolMap.values()].map(t => ({ name: t.name, version: t.version, permissionsDigest: permissionsDigest(t.permissions), effect: t.effect })).sort(byName);
      return {
        runId, startedAt, endedAt: clock(),
        toolSurface: { exposed, declared: declaredTools.map(d => ({ name: d.id, version: d.version, permissionsDigest: permissionsDigest(d.permissions) })).sort(byName) },
        attempts: structuredClone(entries), attemptsHead: prev,
        state: { before, after, permittedWritePrefixes: [...permittedWritePrefixes].sort(), unobserved: [...unobserved] },
        canaries: planted.map(c => ({ id: c.id, path: c.path, plantedDigest: plantedDigests[c.id], finalDigest: after[c.path] ?? null }))
      };
    }
  };
}
