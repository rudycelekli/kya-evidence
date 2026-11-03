# ADR-0051: Admit mutation results only from complete process and count aggregates

**Status**: Implemented locally; pending owner and independent review
**Date**: 2026-11-03
**Related**: ADR-0036, ADR-0037

## Context

The 87-control mutation runner parsed only the first matching tests, pass, fail, cancelled and skipped lines. It did not read TODO counts or reconcile tests with pass and fail totals. A real Node test marked TODO can fail its assertion while the process exits zero and reports that case under TODO rather than fail. The old baseline gate accepted that unfinished execution. A mutant with one normal failure and one TODO also met the old same-population and kill checks. Duplicate or inconsistent aggregate lines could likewise evade complete-run admission. Separate synthetic predicate probes show that nonnumeric statuses were not explicitly refused; real `spawnSync` statuses are normally numeric or null, and no real process producing a string status is claimed.

These are weaknesses in the test-result grader, not changes to the protocol evaluator. A killed mutation is evidence that selected tests detected that weakening; an incomplete process cannot establish that result.

## Decision

Extract a pure aggregate admission module at `scripts/lib/mutation-result.mjs`. Require one terminal aggregate footer in the Node TAP reporter's order: tests, suites, pass, fail, cancelled, skipped, TODO and duration. Count values must have one unambiguous nonnegative safe-integer spelling; missing, duplicate, malformed and unsafe counters are refused. Reject incomplete or nonterminal aggregate blocks. Preserve CRLF compatibility and permit ordinary preceding reporter output. Do not compare the top-level TAP plan with the leaf-test count; nested suites need not make those values equal. Standard error warnings are not assertion failures and are not used as pass credit.

Require a nonempty test population, zero cancelled/skipped/TODO cases and tests equal to pass plus fail. Reject process errors, signals, missing or nonnumeric statuses, and disagreement between zero/nonzero status and the observed fail aggregate. A baseline must exit zero with all tests passing. A mutant uses the same admitted test and suite totals as its baseline; it is killed only by a positive integer exit with an observed positive fail count. A complete all-pass mutant remains a survivor and the existing runner refuses it.

Keep every one of the existing 87 mutations, the exact 22-file test population, per-control baseline execution, isolation copies and syntax preflight. Do not reuse or cache baselines and do not select fewer tests. This change hardens result admission; it does not optimize execution or claim a latency/cost saving.

## Alternatives

- Add only a TODO check: insufficient because malformed counts and process/count disagreements remain.
- Treat any nonzero exit as a detected mutation: rejected; crashes and incomplete execution do not establish an assertion failure.
- Treat the Node top-level TAP plan as the leaf-test count: rejected because nested suites can have a different plan size.
- Implement a complete generic TAP parser: deferred; this module narrowly validates Node aggregate completion and cannot prove the truthfulness of arbitrary emitted text or enumerate test identities.

## Consequences

Previously accepted incomplete or inconsistent mutation results now fail closed. Ordinary complete Node reporter results preserve the existing mutation report shape. The aggregate comparison checks test and suite totals, not exhaustive identity equivalence or arbitrary TAP semantics. Protocol schemas, core evaluator identity, assessment expectations and all public vectors remain unchanged. Evidence remains local and same-team; it is not independent assessment or exhaustive security validation.

## Validation

Eight initially frozen adversarial groups cover valid baseline/kill/survivor behavior; missing/duplicate/malformed/unsafe counts; count arithmetic; TODO/skip/cancel cases; process errors, signals and invalid statuses; process/count disagreement; terminal footer structure and CRLF; and changed aggregate populations. An exact compatibility shim over the previous runner's count parser and admission conditions passes one and fails seven; the candidate passes all eight on those unchanged cases.

Same-team review then found a compatibility error in the first candidate: an ordinary diagnostic comment beginning with the word tests was mistaken for a malformed aggregate line. A ninth case now generates that diagnostic through a real Node process; the original eight-case source and receipts are retained privately. The augmented frozen population passes two of nine cases against the old admission logic and all nine against the corrected candidate. The parser reads the terminal block first and treats earlier fully formed numeric count lines as duplicate ambiguity; ordinary preceding diagnostic prose remains allowed.

Three syntactically valid weakened graders admit TODO populations, nonnumeric statuses or changed populations. The same nine tests must detect each weakening, and a tenth ordinary-suite test executes those controls so grader regressions are exercised by the normal full suite. The control runner itself requires complete fixed-population execution with no cancellation, skip or TODO cases. The first combined ordinary-suite run had nine passes and one failure because its owned child test processes inherited Node's test-context marker and recursively skipped their files. The runner now copies the child environment and removes only that marker; the global process environment and other workers remain unchanged. The failing output is retained privately, and the corrected combined run passes all ten tests. Actual Node TODO output is replayed separately. A representative real control uses the unchanged complete 22-file population for one baseline and its trust-anchor-bypass mutant; this is a sample, not a claim that all 87 controls or the whole repository suite ran for this candidate. Full exact-head hosted verification remains a promotion gate.
