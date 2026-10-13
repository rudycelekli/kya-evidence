# Branchable research universes

A KYA universe is a reproducible local research snapshot. It freezes the exact assessment inputs, assessment time, current assessor source digest, output report, question, source references and branch/correction metadata under a canonical SHA-256 digest. A fork preserves its parent's digest and requires a written hypothesis. This makes competing experiments inspectable and replayable; it does not prove truthful runtime observations or causal improvement.

The snapshot is **content-addressed, not write-protected**. Ordinary JavaScript objects and JSON files can be edited. An edit invalidates the recorded digest; verification detects it. Forking clones inputs and preserves parent bytes without shared mutable descendants. Preserve original universe files in an authorized private store rather than overwriting them. A new hypothesis, policy, evaluator, configuration or evidence bundle should produce a new universe with its own digest.

## Freeze and replay

`createUniverse({inputs,question,sourceArtifacts?,parentDigest?,hypothesis?,invalidates?})` accepts exactly six frozen input fields:

```js
const inputs = { manifest, profile, policy, evidence, evaluatorDigest,
  now: '2026-10-13T12:00:00.000Z' };
const baseline = createUniverse({ inputs,
  question: 'Does this exact synthetic configuration meet this frozen policy?',
  sourceArtifacts: [{ id: 'source:owned-fixture', digest: sourceDigest,
    kind: 'original', rights: 'private' }] });
verifyUniverse(baseline);
```

`evidence` contains signed evidence envelopes. `now` is explicit canonical UTC time and remains frozen during replay; omitting it is invalid. Replay uses the same snapshot time, not the current wall clock. The same full inputs, metadata and implementation produce byte-identical canonical universes and digests. Real runs need genuinely collected evidence first; creating a universe never runs an agent or renews expired authority.

`verifyUniverse` checks strict shape, outer digest, matching assessor implementation and a recomputed assessment plus reconstructed universe digest. Its successful result explicitly says `authenticated:false`. A caller can create another internally consistent snapshot and compute its checksum; this does not establish who issued it, when it existed externally, or which process actually ran. A metadata revision with a newly computed digest can replay without becoming an authenticated statement.

`ASSESSOR_SOURCE_DIGEST` hashes all bundled `.mjs`/`.js` files under `src/` plus `package.json`, including import barrels and package routing. The inventory refuses source symlinks. Source changes require the archived implementation for exact historical replay, or an honestly new universe under the new implementation. Updating an outer checksum or substituting a new source digest around an old assessment does not make stale results replay. Retain the exact release/source artifact as well as JSON snapshots. The digest does not independently attest an operating system, Node binary, loaded model, wrapper, or commercial product runtime. Evidence's evaluator digest and the complete frozen input profile remain separate bindings.

## Fork, compare and correct

```js
const candidate = forkUniverse(baseline, {
  hypothesis: 'A fresh complete run should preserve safety gates under this change.',
  manifest: candidateManifest,
  evidence: candidateRunEvidence
});
const comparison = compareUniverses(baseline, candidate);
const graph = verifyUniverseGraph([baseline, candidate]);
```

Fork patch fields are hypothesis, question, sourceArtifacts, invalidates and the six input fields. Unknown fields fail. Hypothesis is required and nonempty. A root universe has no parent or fork hypothesis. A changed manifest requires evidence bound to that exact manifest; retained receipts for the old configuration become rejected evidence and cannot qualify the candidate.

Comparisons first verify both universes and then require matching scope, profile, evaluator, relying policy, evidence mode, ordered cases and weights. Every case must have pass/fail coverage; unknown, abstain and error cases refuse comparison. A comparison returns score difference and parent relationship with `causalClaim:false`. It cannot establish that a code change caused improvement: independently controlled runs, fixed evaluators, identical cases, protected holdouts and external outcome measurements still matter. Changing a relying policy creates a different decision contract, not a comparable score gain.

Corrections are append-only new snapshots: `invalidates:[priorUniverseDigest]` names a universe whose assumptions or results were corrected. This preserves the original evidence and provides an inspectable correction reference. It does not erase the prior artifact or automatically revoke its signed receipts. Update relying-policy evidence/key/subject revocations explicitly when warranted. Recompute dependent analyses under corrected assumptions and preserve those new universes too.

`verifyUniverseGraph` replays each supplied node, rejects duplicate nodes and missing parent/correction references, and checks parent-chain cycles. Graph order does not matter. It reports declaredInvalidations and affectedDescendants along parent lineages so dependent analyses can be identified for correction. Those references are declarations, not an adjudication or revocation grant. The graph validates at most 256 supplied nodes; it does not discover missing files, fetch referenced artifacts or maintain a global registry. A successful graph remains unauthenticated and local.

## Command-line use

Prepare a strict JSON file containing the six input fields above and use supported commands from the checkout:

```sh
node bin/kya.mjs universe --inputs frozen-inputs.json --question "Frozen baseline" --out baseline.json
node bin/kya.mjs replay baseline.json
node bin/kya.mjs fork --parent baseline.json --patch candidate-patch.json --out candidate.json
node bin/kya.mjs compare --left baseline.json --right candidate.json
```

The patch JSON contains a required `hypothesis` and any explicit input overrides. CLI universe creation currently accepts frozen inputs and a question; source references and correction metadata can be supplied through the SDK or fork patch. CLI replay prints integrity/replay verification, not an authentication or capability claim. Keep evidence containing private data in private files; publishing a snapshot requires separate authorized sanitization and changes the affected digests.

## Original evidence and rights

Each source reference has `{id,digest,kind,rights}`. IDs are unique; kind is original, derived or hypothesis; rights is private or redistributable. A hash is a reference to expected bytes, not proof that those original bytes were possessed, retained, licensed or correctly interpreted. Verify original artifacts separately and preserve corrections rather than silently replacing them. Redistribution rights are a caller declaration; replay does not perform legal verification. Do not embed credentials, private client data or unauthorized upstream code in distributable universes.

The regression suite checks every binding, exact replay, deterministic bytes, incomplete/comparison refusals, branch immutability, correction references, strict resource bounds and mutation of actual assessor source in an isolated private test copy. It also checks that rehashing an outer universe cannot launder stale assessment output. These are implementation guarantees of a local research record, not proof of external task success.
