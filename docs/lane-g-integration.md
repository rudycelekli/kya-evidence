# Lane G integration note

Scope: campaign harness, planned-attempt ledger and `capture-issuer` role (ADR-0021). Edits needed in shared files that Lane G may not touch.

## Required shared edits

1. `src/assessment/application/assess.mjs` (important). After `insist(k,'Signer is not a relying-party trust anchor');` add `insist(k.role !== 'capture-issuer','A capture-issuer key cannot issue scoring evidence');`. Until then a capture-issuer key listed in a policy and used to sign evidence is scored like a non-independent signer. It never counts as independent (tested), but it is not rejected inside the scorer. Suggested test in an assessment test file: sign all checks with a capture-issuer key, expect every receipt in `rejectedEvidence`. Mutation anchor: find `insist(k.role !== 'capture-issuer'`, replace `insist(true`.
2. `src/index.d.ts`: widen `Policy.trustedKeys[].role` to `'self'|'independent'|'capture-issuer'`. Optionally add types for `src/campaign/index.mjs` (`createPlan`, `openLedger`, `appendEntry`, `verifyLedger`, `summarizeCampaign`, `runCampaign`, `conformanceDigests`, `verifyCaptureIssuerPolicy`).
3. `package.json`: add script `"campaign": "node scripts/kya-campaign.mjs"` and, if the library should be public, export `"./campaign": { "import": "./src/campaign/index.mjs" }` (plus a `types` entry once types exist). `files` already covers `src/`, `scripts/`, `test/`, `docs/`.
4. `evidence/requirements.json`: append the `requirements` array of `docs/lane-g-requirements-proposal.json` (KYA-CMP-001 to 013, area `campaign`), then `npm run requirements` to regenerate `docs/REQUIREMENTS.md`. Traceability was checked against a scratch copy of the registry: all 13 resolve, each title exactly once, no skips.
5. `evidence/adr-index.json`: regenerate with `npm run adr:index` (ADR-0021 added, ADR-0017 header changed). Not staged by this lane.
6. `docs/SPECIFICATION.md` (optional): mention `capture-issuer` under Trust and eligibility.
7. `bin/kya.mjs` (optional): none required; the CLI is standalone at `scripts/kya-campaign.mjs`.

No schema changes beyond the policy role enum already edited in `scripts/generate-schemas.mjs` and `schemas/policy.schema.json`. A schema for `kya.campaign-plan/v1` and `kya.campaign-ledger/v1` is not generated; validation is in code (`src/campaign/domain/records.mjs`).

## Proposed mutation anchors for `scripts/mutation-check.mjs`

Format `[name, find, replace, file]`. Each was applied by hand and the two campaign test files then failed (detected):

| Name | Find | Replace | File |
| :--- | :--- | :--- | :--- |
| ledger chain commitment removal | `e.prevDigest !== previous` | `false` | `src/campaign/domain/ledger.mjs` |
| ledger transition gate removal | `if (!allowed.includes(state.status))` | `if (false)` | `src/campaign/domain/ledger.mjs` |
| capture-issuer role requirement removal | `anchor.role !== 'capture-issuer'` | `false` | `src/campaign/domain/ledger.mjs` |
| unaccounted attempts leave denominator | `planned: attempts.size` | `planned: attempts.size - open.length` | `src/campaign/domain/ledger.mjs` |
| retry of non-errored attempt allowed | `original.status !== 'errored' \|\|` | `false \|\|` | `src/campaign/domain/ledger.mjs` |
| runner adapter source check removal | `origin.source === declared.adapter.source &&` | `true &&` | `src/campaign/application/runner.mjs` |
| runner adapter mode check removal | `origin.mode === declared.adapter.mode` | `true` | `src/campaign/application/runner.mjs` |
| private directory permission check removal | `(stat.mode & 0o077) === 0` | `true` | `src/campaign/application/runner.mjs` |
| bundle overwrite allowed | `flag: 'wx'` | `flag: 'w'` | `src/campaign/application/runner.mjs` |
| capture-issuer evidence-signer check removal | `insist(!evidenceKeyIds.includes(id)` | `insist(true \|\| !evidenceKeyIds.includes(id)` | `src/campaign/domain/roles.mjs` |

Not proposed: replacing `if (at < Date.parse(plan.createdAt))` with `if (false)` is an equivalent mutant, because the time-regression check right after it still rejects the same entry.

## Notes

- `src/conformance/**` is untouched; `evaluator-identity.test.mjs` passes. The runner imports `adapterOrigin` from `src/conformance/application/origins.mjs` (read-only deep import); consider re-exporting it from `src/conformance/index.mjs` in a lane allowed to change the evaluator digest, since that file is bound into it.
- `currency.mjs` counts incident reports from any trusted role, so a capture-issuer key can raise a report. That is consistent with ADR-0014 (a hostile trusted key can force reassessment) and unchanged.
- Native adapters (`createClaudeCodeAdapter`, `createCodexExecAdapter`) can be passed to `runCampaign` by library callers; the plan must declare their origin, and their existing opt-in gates are untouched. The CLI deliberately wires only the owned reference and command fixtures, and no test launches a vendor-shaped child.
- Ledger files are bounded by the strict JSON parser (1 MiB): at most 128 planned and 256 total attempts.
