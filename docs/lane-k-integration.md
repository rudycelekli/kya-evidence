# Lane K integration notes

Shared files this lane did not edit. Apply them in the integration change.

## package.json scripts

```json
"vectors:assessment": "node scripts/assessment-vectors.mjs",
"vectors:assessment:check": "node scripts/assessment-vectors.mjs --check",
"vectors:run": "node scripts/run-vectors.mjs"
```

`files` already includes `scripts/`, `interop/`, `evidence/` and `docs/`; no change is needed there.

## CI

Add after `npm test`:

```yaml
- run: node scripts/assessment-vectors.mjs --check
- run: node scripts/run-vectors.mjs --impl "node interop/impl-contract/js-reference.mjs" --name kya-js-reference --language javascript --out vectors-report.json
```

The second step exits non-zero unless the reference passes every vector. `test/assessment-vectors.test.mjs` already runs both inside `npm test`, so these steps are redundant but give a readable CI summary. The test file takes about 40 seconds.

## Requirement registry

Merge `docs/lane-k-requirements-proposal.json` (`KYA-VEC-001` to `KYA-VEC-008`, area `vectors`, section `Interoperability and versioning`) into `evidence/requirements.json`, then run `npm run requirements` to regenerate `docs/REQUIREMENTS.md`. Every trace title appears exactly once in `test/assessment-vectors.test.mjs`. Merging changes the registry digest, so any signed conformance report must be regenerated; the vector file does not embed the registry digest on purpose, so it does not drift when other lanes add requirements.

## Docs to link

- `docs/CONFORMANCE.md`: link `docs/IMPLEMENTERS-GUIDE.md` and `interop/impl-contract/README.md` as the way to produce `portable-vector` evidence.
- `docs/INTEROPERABILITY.md`: add the assessment vectors beside the byte and signature vectors.
- `docs/WORLD-CLASS-PLAN.md`: WS3 deliverables "golden assessment vectors", "implementers guide" and "language-neutral conformance harness" now exist; "two independent implementations" is still open and EXT.
- `docs/SPECIFICATION.md`: consider stating the run tie-break and a reason code vocabulary (see the spec gaps in the implementers guide).
- `docs/adr/README.md` and `evidence/adr-index.json` (regenerate with `npm run adr:index`; deliberately not staged by this lane).

## Dependency on shared code

The harness imports `src/conformance-report` (`buildReport`, `validateReport`), `src/shared/canonical.mjs` (`parseJson`) and `scripts/requirements.mjs` (`loadRequirements`). The generator and the reference adapter use `src/index.mjs`. If those APIs change, the vectors file regenerates and the drift check shows what moved.

## Not done here

Nothing was published, pushed or wired into CI. `evidence/evaluator-identity.json` and `src/**` are untouched.
