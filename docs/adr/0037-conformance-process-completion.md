# ADR-0037: Require successful process completion for conformance pass credit

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0015, ADR-0036

## Context

The TAP mapper previously preserved a passing trace on a nonzero exit when any sibling test failed. That exception also admitted null, missing or string exit codes when a failing sibling was present. Unknown or missing trace status could likewise fall through to pass. The CLI discarded process signal metadata.

A real subprocess fixture exposed a deeper problem: Node's default test wrapper can emit a passing trace and a failing assertion, then lose a worker to SIGKILL and still return only exit 1 with those earlier TAP results. A failing sibling therefore cannot establish successful completion. Retaining passes from that process would claim more than the runner observed reliably.

## Decision

For `executed-test` conformance mapping, an entry earns pass only when its matched status is exactly `pass`, the process exit code is exactly numeric zero, and no signal or runner error is present. Every traced test must still have one unambiguous matching verdict. An observed failing trace stays fail even when other execution information is incomplete. Other results from unsuccessful processes become not-run, with null evidence and no executed IDs, and remain in the denominator.

Preserve the native signal metadata in the CLI and describe the optional signal and error fields in the TypeScript interface. Keep Node's existing process isolation model and flags; no experimental isolation option is required.

Clarify KYA-CNF-005 and add the five frozen adversarial tests as requirement traces. The registry digest changes intentionally; old reports remain bound to the old registry. No assessment schema, core evaluator identity, public assessment vector input or expected value changes. ADR-0015 is amended to reference this strengthening.

## Alternatives

- Preserve passing siblings when another test fails: rejected because a worker crash can be hidden behind the same normal wrapper exit 1.
- Require a normal integer exit but retain the sibling exception: insufficient for the real-process case, though it closes malformed metadata cases.
- Disable Node's internal test isolation: deferred. It would introduce version-sensitive experimental/stable flags and change test execution semantics. The CLI already launches a separate process per file, but this change does not need a new execution model.
- Add a separate structured completion channel: deferred. It could support more precise partial results, but needs its own trust, lifecycle and version contract; TAP alone is not that channel.

## Consequences

This strengthens partial-report behavior: even an ordinary assertion failure with exit 1 now withholds passes for sibling traces in that file. Explicit failures remain visible; unknowns never shrink the denominator. Callers needing per-test pass credit must rerun the relevant file successfully. CLI exit zero still means the report artifact was built, not that its requirements passed.

The existing CLI fixture's one expected summary changes from one pass and one fail to one not-run and one fail under the new producer contract. Its inputs are unchanged. The new adversarial cases and expectations were frozen and run against the previous source before implementation; none were weakened to fit the candidate. The 799 assessment vectors are unchanged.

## Validation

`test/conformance-execution-gates.test.mjs` covers malformed process metadata, signals and runner errors with failed siblings, unknown statuses, normal mixed runs, and a real worker SIGKILL after visible good/bad TAP results. The previous mapper fails all five frozen tests; the candidate must pass all five. `scripts/conformance-execution-mutations.mjs` exercises the identical population on four syntactically valid weakened mappers, including restoration of the sibling exception. Existing report tests, mutation redundancy tests, traceability and full regression are checked separately. Same-team review is not external validation; hosted results are recorded only when observed.
