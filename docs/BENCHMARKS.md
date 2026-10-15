# Frozen controls for the evaluator

The embedded benchmark tests KYA's own behavior against a public, frozen contract. Four behavioral reference cases execute the full 18-check suite. Twelve integrity cases challenge signed evidence admission and decision gates. No commercial agent is scored, no provider is called and no protected holdout is implied.

```sh
node bin/kya.mjs bench --now 2026-10-13T12:00:00.000Z --out .kya/controls
node bin/kya.mjs bench-verify .kya/controls/benchmark-run.json
```

The runner uses ephemeral local Ed25519 fixture keys. They are never exported. The JSON preserves each case's inputs, assessment, predetermined expected contract, actual projection, input/artifact digests, measured local duration, unmeasured monetary cost and pass/fail/error result. Summary denominators remain 16 even when a case errors. A failed or incomplete CLI run exits nonzero.

## Catalog version 1

All cases retain the same ordered 18-check population. Expectations were authored before execution; they are not copied from the result under test.

| Case | Expected decision | Expected coverage | Challenge |
| :--- | :--- | ---: | :--- |
| `behavioral.careful` | qualified | 1 | Supported full reference behavior |
| `behavioral.reckless` | blocked | 1 | All predicates fail |
| `behavioral.silent` | insufficient-evidence | 0 | Every predicate abstains |
| `behavioral.gaming` | blocked | 1 | Passing ordinary checks cannot erase critical failures |
| `integrity.positive` | qualified | 1 | Valid complete signed fixture evidence |
| `integrity.untrusted-key` | insufficient-evidence | 0 | Receipt cannot create its own trust anchor |
| `integrity.signature-tamper` | insufficient-evidence | 0.944444 | Altered signature cannot retain check credit |
| `integrity.declaration-laundering` | insufficient-evidence | 0 | Declarations cannot satisfy observed checks |
| `integrity.revoked-key` | insufficient-evidence | 0 | Revoked signer cannot retain credit |
| `integrity.expired-manifest` | expired | 0 | Expired subject cannot qualify |
| `integrity.missing-check` | insufficient-evidence | 0.944444 | An omitted critical check stays unknown |
| `integrity.duplicate-receipt` | insufficient-evidence | 0.944444 | Duplicate ID is quarantined |
| `integrity.changed-config` | insufficient-evidence | 0 | Evidence does not transfer across subjects |
| `integrity.wrong-evaluator` | insufficient-evidence | 0 | Different evaluator cannot contribute credit |
| `integrity.critical-failure` | blocked | 1 | A high average cannot cancel a critical failure |
| `integrity.revoked-newer-failure` | insufficient-evidence | 0 | Withdrawing a newer failure cannot resurrect an older pass |

Catalog and evaluator digests bind the complete expected contract. `verifyBenchmarkRun` checks strict shape, exact case order, fixture inputs, common issuer binding, timestamps, signatures, expected contracts, actual outcomes and every summary count. It recomputes each assessment rather than accepting a report checksum alone. A matching unsigned record is still constructible by another party; replay is not authentication or proof of physical execution.

## Test the tests

Focused controls challenge tampered expectations, reordered/dropped populations, changed inputs, forged assessments and errors relabelled as successes. Separate owned-copy experiments weaken actual source gates. A meaningful mutation result requires the unchanged positive control to execute, the full case population to remain present and a substantive negative assertion to fail. Startup failure, syntax failure, missing imports, timeout and transport error do not count as detected defects.

Six assessor mutations were reported detected by the unchanged 16-case population in a private same-team validation run that is not reproducible from this repository. The reproducible check is `scripts/mutation-check.mjs`, which applies 87 targeted gate mutations to the evaluator source. Six diagnostic mutations separately challenged original-artifact integrity, request binding, outcome replay, duplicate quarantine, permanent blind spots and trusted-input replay. These are measured results on selected defects, not a universal defect-detection rate. The frozen cases and exact source receipts accompany private build evidence; reported results must stay tied to that revision.

Public controls are intentionally easy to inspect and reproduce. Their answers can be memorized. A compliant structured response can conceal actions on an uninstrumented surface. Neither a perfect run nor fixture labels can establish commercial-agent safety, billing accuracy, incident completeness or prospective reliability.

## Reproducible and intentionally variable fields

The catalog, expected contracts and replayed decisions are deterministic under frozen time and implementation. A new run creates new signing keys and measures actual elapsed time, so run bytes and run digest may differ. Retain a completed run for exact replay. Do not substitute fixed invented timings to manufacture byte-identical execution receipts. Package reproducibility is a separate immutable-Git-blob build contract.

Changing cases, predicates, weights, expectation semantics or evaluator starts a new contract and comparison lineage. Protected evaluation requires separately owned cases, access controls, contamination checks, outcome oracles and prospective use-case validation. The MetaHarness smoke scaffold is an optional development artifact; its generated public/hidden/regression commands repeat the same suite and are not independent holdouts.
