# ADR-0021: Capture-issuer role and signed campaign ledger

**Status**: Implemented
**Date**: 2026-10-14
**Depends-on**: ADR-0003, ADR-0004, ADR-0010, ADR-0014, ADR-0017

Review boundary: separate project lane; no independent review, no external certification. This is the first implementable slice of ADR-0017.

## Context

ADR-0003 keeps every frozen check in the denominator, but states that a trusted issuer can omit whole runs. ADR-0017 proposes a planned-attempt ledger and a `capture-issuer` anchor role so omitted and unplanned runs become detectable. A private pilot will later run frozen campaigns against real agents on the owner's subscriptions. Before any such run, the project needs a harness that commits to the full attempt list first, records every transition, and keeps unfinished attempts in the denominator. Nothing here launches a model or vendor CLI.

## Decision

### Role

Policy `trustedKeys[].role` accepts a third value, `capture-issuer`. A capture-issuer key may sign campaign plans, ledgers and (later) capture records. It never counts as an evidence issuer for scoring, never satisfies independence (the scorer already counts only `independent` for that), and may not be the evaluator key. `verifyCaptureIssuerPolicy` rejects a capture-issuer key supplied as an evidence signer or as the evaluator key; a key listed twice is already rejected as a duplicate trust anchor. Policies that do not use the role keep byte-identical digests (regression test with a pinned digest). The roles `calibrator` and `anchor-operator` are approved but intentionally not added until ADR-0019 and ADR-0020 are implemented, and the validator still rejects them.

### Campaign plan and ledger (`src/campaign/`, outside the evaluator digest)

`kya.campaign-plan/v1` (signed, domain `kya.campaign-plan/v1\n`) is frozen before any attempt: campaign ID, use-case text, profile digest, scenario-set digest, subject digests, ordered attempts `{attemptId, subjectDigest, scenarioSetDigest, seed|null}`, evaluator digest, policy digest, adapter declaration `{source,id,mode}` and an explicitly supplied creation time.

`kya.campaign-ledger/v1` is append-only. Each entry (`planned`, `started`, `completed`, `abandoned`, `errored`, and `amended` for retries) is signed with domain `kya.campaign-ledger/v1\n`, carries a sequence number and commits to the digest of the previous envelope (the first entry commits to the plan). `openLedger` signs a `planned` entry for every plan attempt before anything else can be appended. `appendEntry` verifies the existing ledger, then rejects out-of-order transitions, duplicate attempt IDs, entries timed before the plan or before the previous entry, foreign signers, and any extra field. `completed` references the run ID and the SHA-256 of the raw-evidence bundle; `errored` and `abandoned` use fixed code enumerations. The ledger never stores prompts, responses or free text.

`verifyLedger` checks plan signature, entry signatures, signer identity, chain, monotone time, transitions, and that planned entries match the plan. With a policy it also requires the signer to be an unrevoked `capture-issuer` anchor. With `requireClosed` every attempt must be completed, errored or abandoned. `summarizeCampaign` reports unconditional `planned`, `completed`, `errored`, `abandoned` and `unaccounted`; an unaccounted attempt (planned or started, no terminal entry) stays in the planned denominator. A retry is a new attempt added by a signed `amended` entry naming an errored attempt of the same subject; the errored attempt keeps its place in the counts.

### Runner

`runCampaign` executes pending planned attempts sequentially through the existing `runConformance` and adapter path. It refuses to start unless the ledger verifies, the plan matches the ledger, the signing key is the plan issuer, the evaluator, profile and scenario-set digests equal the frozen ones, and the adapter provenance equals the plan declaration. It appends and persists `started` before the adapter runs. Raw bundles are written with mode 0600 and no-overwrite to a caller-supplied absolute private directory that must be outside the repository and not open to group or others. Adapter or transport failures and timeouts become `errored` entries and are never retried; a started attempt with no terminal entry is never silently re-run. Malformed agent output is a scored error observation, not an infrastructure error. Cost stays null unless the adapter reports it.

`scripts/kya-campaign.mjs` offers `plan`, `run`, `verify-ledger` and `summary` with an explicit `--now`. Only the owned reference and command fixtures are wired; library callers may pass native adapters through the existing explicit opt-in gates, which this change does not alter.

## Not implemented from ADR-0017

Egress probes, environment fingerprint, tool-surface measurement and enforcement, per-run `kya.capture/v1` records, `captureDigest` on evidence and `requireCapture` policy binding, `omitted-run` and `unplanned-run` reconciliation against capture records, and external anchoring (ADR-0020). Without anchoring the ledger head can be withheld; an operator can also still decline to publish a ledger at all.

## Alternatives

A mutable results file cannot show omission. Putting the ledger under `src/conformance/` would change the pinned evaluator digest for unrelated code. Signing entries with the evaluator key would merge two roles ADR-0017 keeps apart.

## Consequences

A relying party can check that a campaign committed to its attempts first and that unfinished work was never dropped. Signatures prove possession of the capture-issuer key, not truthful execution (AGENTS.md); a compromised or dishonest issuer can sign anything, and bundles are private so the digest is checkable only by whoever holds them. Until `assess` refuses `capture-issuer` signers directly, the exclusion from scoring is enforced by `verifyCaptureIssuerPolicy` and by independence counting, not inside the scorer (see lane integration note). Ledger size is bounded by the strict JSON limit: at most 128 planned and 256 total attempts.

## Validation

Tests in `test/campaign-ledger.test.mjs` and `test/campaign-runner.test.mjs` cover plan strictness, transitions, time order, tamper detection (edit, removal, reorder, plan swap), signer and role checks, unconditional counts, privacy of entries, amendment retries, legacy-policy digest stability, private 0600 bundles, provenance and evaluator refusal, error recording, no silent retry, and the CLI end to end on the reference and command fixtures. The evaluator-identity test confirms the evaluator digest is unchanged. Proposed mutation anchors are listed in `docs/lane-g-integration.md`.
