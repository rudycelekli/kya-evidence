# Lane J integration notes

Edits needed in shared files that Lane J did not touch. Nothing below is applied.

## package.json

Add exports (types alongside imports, like existing entries):

```json
"./suites": { "types": "./src/suites/index.d.ts", "import": "./src/suites/index.mjs" },
"./holdout": { "types": "./src/holdout/index.d.ts", "import": "./src/holdout/index.mjs" }
```

`files` already includes `src/`, `docs/`, `test/`; add `"suites/"` so `suites/reconstructions-v1/*.json` ship (the loaders read them relative to `src/suites/`). No new script is required (`npm test` globs `test/*.test.mjs`).

## src/index.mjs and src/index.d.ts

Optionally re-export from `./suites/index.mjs` (`evaluateSuiteScenario`, `validateSuite`, `loadReconstructionsV1`, `SUITE_EVALUATOR_DIGEST`) and `./holdout/index.mjs` (`commitHoldout`, `revealCase`, `verifyReveal`, `verifyFullReveal`, `generateSalt`), and mirror `src/suites/index.d.ts` and `src/holdout/index.d.ts`. Check for name collisions first.

## schemas and scripts/generate-schemas.mjs

Add JSON schemas for `kya.scenario-suite/v1` (fields in `docs/SCENARIO-SUITES.md`; `scenario.disclaimer` required when `provenance` is `incident-reconstruction`) and `kya.holdout-commitment/v1` (`schema`, `suiteId`, `caseCount` integer 1..65536, `merkleRoot` and `saltCommitment` as 64 hex, `createdAt` UTC ISO-8601, `additionalProperties:false`). Regenerate with `node scripts/generate-schemas.mjs` and keep `--check` green.

## evidence/requirements.json

Merge the `requirements` array from `docs/lane-j-requirements-proposal.json` (KYA-SUI-001..005, KYA-HLD-001..004; section "Records and bindings", which exists in `docs/SPECIFICATION.md`). Every trace title appears exactly once; verified against the traceability loader on a scratch copy.

## evidence/adr-index.json

Regenerate with `npm run adr:index` after this branch merges so ADR-0023 is indexed (not staged by this lane).

## Other

`docs/EVALUATOR.md` and `docs/BENCHMARKS.md` may link to `docs/SCENARIO-SUITES.md`. A relying policy that wants suite results must pin `suiteDigest` and `SUITE_EVALUATOR_DIGEST`; the assessment pipeline does not consume them yet. A CLI verb (`kya suite run`, `kya holdout commit|reveal|verify`) is not implemented.
