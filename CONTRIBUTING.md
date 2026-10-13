# Contributing

Bring a replayable boundary failure, a sharper evaluator or a working adapter. This Apache-2.0 project is clean-room: no private product code, client records, credentials, internal paths or unapproved traces.

Use Node.js 22 or later:

```sh
node --test test/*.test.mjs
node scripts/check.mjs
node bin/kya.mjs benchmark --out ./artifacts/benchmark
```

A fix includes minimal sanitized input, exact expected behavior, relevant tests and remaining limits. An adapter documents official invocation, isolation responsibility, response contract, evidence origin, version probes and real-versus-fixture verification. No fixture can become a commercial product score.

Scoring, eligibility, schema or evaluator changes need a substantive ADR, adversarial regression and mutation test that fails when the gate is weakened. Freeze baseline/candidate cases and expected outcomes. Do not replace failing cases with easier ones or remove unknowns from the denominator.

Use identity, evidence, assessment and conformance bounded contexts. Public exports expose domain/application; filesystem/process infrastructure stays explicit. Runtime dependencies need measured justification and an ADR. A child process is not an OS sandbox.

README SVGs are self-contained and readable with motion disabled. The offline viewer uses no remote fonts/CDNs, works by keyboard, renders text safely and labels imported reports unverified. Fixtures are explanatory and distinct from signed assessments.

Contributions are proposals until reviewed. Maintainers retain merge and publication authority. Read [GOVERNANCE.md](docs/GOVERNANCE.md) for correction and appeal rules; report sensitive defects through [SECURITY.md](SECURITY.md).
