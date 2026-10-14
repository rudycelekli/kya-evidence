# From reference implementation to adoptable standard

Status: strategy note, not a specification. Date: 2026-10-14. It records what a credible standard needs, where this project stands, and the order of work. Nothing here claims adoption, certification or external review; none exists yet.

## What lasting standards share

| Trait | Where KYA stands today |
| :--- | :--- |
| Narrow, precisely scoped problem | Met: evidence-bound, policy-relative assessment of an exact agent configuration |
| Core plus profiles for use cases | Partial: one core profile; use-case policy templates are in development |
| Normative text, conformance suite, **two independent implementations** | Text, traced requirements and vectors exist; the Python checker is team-built and covers a restricted byte subset |
| **Neutral governance**, IPR policy, versioning, extension registry | Missing: Apache-2.0 only; no foundation, contributor policy or trademark policy |
| Public threat model and **external security review** | Threat model yes; external review none |
| **Interop with incumbents** (W3C VC, in-toto/SLSA predicates, OpenTelemetry, OAuth/SPIFFE, A2A/MCP) | VC export bridge in development; the rest not started |
| Regulator, auditor and insurer mapping (EU AI Act, ISO 42001, NIST AI RMF) | Missing |
| Assessor accreditation, conflict-of-interest rules, appeals | Appeals and incident records begun; accreditation missing |
| Privacy by design (data minimisation, selective disclosure) | Partial: digest-only records, no personal data fields |
| Real usage data and a feedback loop | None |

The central risk is **compliance theatre**: a badge that outlives its evidence. Mitigations already designed in: expiry, exact-scope binding, no universal score, named blocker codes, and honest limits on every artifact.

## Capture tiers (strength of a claim about what an agent did)

| Tier | Meaning | Status |
| :--- | :--- | :--- |
| C0 declared | The agent or operator says what happened | Implemented (declarations never score) |
| C1 configured | A control was requested of a backend | Implemented as declaration |
| C2 measured | A harness-run probe or measurement confirmed the posture and is signed | Proposed (ADR-0017) |
| C3 independently observed | A host-side tap records what the guest did, outside the agent's trust domain | Proposed |
| C4 hardware-attested | A runtime attestation from confidential-computing hardware | Not designed; feasibility unverified |

Design principles taken from measured-sandbox practice: measure rather than configure; probe at the application layer to an IP literal and in both directions so the probe can fail either way; re-assert on every boot and restore; refuse rules a backend cannot enforce instead of normalising them; keep control-plane operations off any channel the agent can reach; make worlds a pure function of (specification, seed) so others can replay them; record the attempt, not only the survivor; invert trust on actions with a harness-owned tool proxy, a before/after world-state digest and canary tokens, so actions are observed rather than self-reported.

Reconciling denominators: infrastructure failures stay visible in unconditional coverage, and are separated from agent-attributable failures in any conditional quality rate. Both are reported.

## Adoption by persona

- **Individuals:** one-command local use, delegation presets, plain summaries, no account.
- **Builders and open source:** CI action, manifest generated from the repository, conformance report per release.
- **Enterprises:** policy templates, an internal agent registry with currency monitoring, SIEM and OpenTelemetry export, IAM bindings, procurement-questionnaire mappings, on-premises verification.
- **Platforms, payment networks, insurers:** verifier API, status lists, per-transaction binding, underwriting signals.
- **Assessors and labs:** accreditation, methodology packs, campaign tooling, dispute process.

## Order of work

1. Now: campaign harness with planned-attempt ledger, CI action and policy templates, VC export bridge, expanded scenarios with commit-reveal holdouts.
2. Next: capture cell (tool proxy, bidirectional probes, world-digest diff, canaries, capture tiers); an in-toto predicate type; governance charter and contributor policy; a standards-venue plan.
3. Requires outsiders: external security and evaluator review; a second independent implementation passing the published vectors; relying-party pilots; a private campaign on several agents with vendor right of reply before any publication.

## Success measures (not vanity metrics)

At least two independent implementations pass the shared vectors; one external security review completed with findings repaired; real campaign data on at least three agent configurations; at least three relying-party pilots using policy templates; a neutral governance home chosen; no unresolved critical bypass. Until these hold, describe the project as an experimental reference implementation.
