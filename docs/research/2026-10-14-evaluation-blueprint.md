# From an agent passport to defensible assurance

KYA Evidence's strongest current contribution is a portable decision contract: exact system and scope, explicit relying policy, signed observations, fixed populations, replayable assessments and contestable corrections. The alpha3 addition makes this contract readable as a diagnostic dossier and challengeable through embedded evaluator controls. Establishing a world standard still requires external implementers, independent capture, protected evaluation, empirical calibration and useful relying-party deployments.

This study inspected 58 selected files across iFixAI, Gradia/HarnessArena and Agentic QE. Original source snapshots, SHA-256 inventories, selected source ranges and checkout status were preserved privately. It is focused architecture research, not an audit of every file, a vendor benchmark, an upstream test-suite execution or proof of adoption. KYA's new implementation is independently written; private product code and original snapshots are excluded from the distribution.

## Source scope

| Source | Frozen revision | Selected files | Verification boundary |
| :--- | :--- | ---: | :--- |
| iFixAI 4.1.0 | `89da541c7ff261a99891dd9bf421bb0563709360` | 12 | Scoring, mandatory gates, unscored correction, reporting and evidence; selected bytes match commit |
| Gradia | `b6e8c84f012ef40fb6d5a87ef62fd213ab84451a` | Part of 22 combined | Selected originals clean; broader checkout had 33 tracked dirty files; private implementation |
| HarnessArena containing workspace | `f1330708e3a6c49eb08380b182b512620c292315` | Part of 22 combined | Selected originals clean; broader workspace had one tracked dirty file; no runner campaign |
| Agentic QE 3.15.5 contribution checkout | `3b81f4e870de60f364de21ebd7750b07991aadbf` | 24 | Clean selected source; exact public fork references; static study separated from installed scanner execution |

Dirty surrounding files were not silently treated as committed source. The private ledger distinguishes full originals from selected ranges actually read; retaining a large feature map is not evidence that every row was inspected. Historical import adapters remain reported external results until original execution evidence is verified. Source revisions here are frozen study inputs, not claims about the latest upstream release.

## What transfers, and what needs a different contract

iFixAI's mandatory gates preserve failed, errored and unselected critical requirements separately from its aggregate. Its score engine normalizes across measured category weights. KYA keeps every required frozen check in the denominator, while retaining mandatory gates. These are different populations and cannot be presented as interchangeable scores. [Frozen score engine](https://github.com/ifixai-ai/iFixAi/blob/89da541c7ff261a99891dd9bf421bb0563709360/ifixai/scoring/engine.py), [mandatory minimums](https://github.com/ifixai-ai/iFixAi/blob/89da541c7ff261a99891dd9bf421bb0563709360/ifixai/scoring/mandatory_minimums.py).

The inspected iFixAI unscored correction can withhold a pass when worst-case unresolved outcomes would defeat it. This supports explicit uncertainty gates. Statistical intervals, effective sample counts and a public fixture-withheld holdout prefix still need separate completeness, independence and contamination evidence. KYA's optimistic unresolved-case bound is consequently labelled a logical bound, never a calibrated confidence interval.

Gradia's relevant mechanisms separate output success from execution requirements, retain planned attempts, distinguish measured subtotal from complete total and describe failures with bounded examples and omissions. Older conditional gradable rates exclude infrastructure failures; newer descriptive comparisons count all planned attempts. KYA adopts explicit denominators and unresolved outcomes. A rule-priority diagnostic or successful retry is a useful pattern, but does not establish causal root cause. HarnessArena's open core prepares a command plan; actual runner settings and external operator assertions require separate verification.

Agentic QE's verification-reach model asks which oracle and observation channel covers a specific risk, with source/environment binding and direct/partial/no reach. KYA applies this to original structured responses and names channels the report cannot reach. A producer's `EXECUTED` label is still a claim unless execution is independently captured. [Exact verification-reach source](https://github.com/proffesor-for-testing/agentic-qe/blob/3b81f4e870de60f364de21ebd7750b07991aadbf/src/validation/verification-reach.ts).

Agentic QE's oracle evaluator requires a passing baseline and checks first-order source mutations. Its shown unsuccessful-run interface can count a crash or timeout as a killed mutant. KYA's private mutation experiments require executed positive controls, fixed populations and assertion failures; startup/transport errors cannot become wins. [Exact oracle evaluator](https://github.com/proffesor-for-testing/agentic-qe/blob/3b81f4e870de60f364de21ebd7750b07991aadbf/src/validation/oracle-eval.ts).

The AQE study also found useful separation of mechanical versus judgment gates, measured versus estimated coverage and scan findings versus scope completeness. These motivate strict numeric/population validation, provenance-aware imports and explicit unknowns. Injected judges, heuristic ranking, approximate significance and producer-marked instrumentation do not establish calibrated predictive assurance or permission to promote a candidate.

## The dossier contract

A score answers a frozen policy question. A dossier explains the supporting population and its reach. Alpha3 recomputes from the six frozen inputs and joins originals only to selected signed receipts. It reconstructs supported requests and replays response predicates, quarantines duplicate or contradictory originals, and reports private-text-free reason codes. Passing receipts without matching replay remain `reportedPasses`; only replayed passing original responses become `strengths`.

Failures retain check identity, criticality, receipt references and observation reach. Root cause stays `not-established`. Unknown, abstained and errored checks remain separate unresolved findings. Latency and reported cost retain known/missing counts, subtotal and complete total; null is not zero. Every dossier retains seven structural blind spots regardless of score. [Full report contract](../DOSSIERS.md).

## Failure and blind-spot taxonomy

| Risk | Existing measured gate | Remaining evidence needed |
| :--- | :--- | :--- |
| Identity/configuration drift | Full manifest, profile/evaluator and exact scope digests | Actual serving model/code/environment attestation |
| Authority overreach | Expiry, approval/refusal and structured action predicates | Independently captured allowed/denied effects and current authorization |
| Injection, secrets and peer authority | Frozen synthetic response cases | Representative protected attacks, actual tool surface and independent capture |
| Task quality | Fixed response oracle | Real task outcomes, valid alternatives and representative use cases |
| Selective disclosure | Latest whole run, no check mixing, duplicate/revoked history rules | Complete planned-attempt ledger and witnessed intake; omitted entire runs remain undetectable |
| False strengths or forged prose | Original digest/request/outcome replay; strict rendering projection | Authenticated capture and truthful issuer assertions |
| Budget or recovery claims | Structured operation/retry predicates | Provider billing, retries, infrastructure and human oversight measurements |
| Case memorization | Public negative controls and source mutation checks | Protected ownership, leakage controls and contamination protocol |
| Independence/Sybil issuers | Out-of-band policy trust anchor and role | Ownership/conflict review and organizational independence evidence |
| Predictive reputation | Explainable policy-relative 0–1000 score | Prospective outcome/severity calibration, uncertainty and appeals |

An owned local boundary experiment emitted memorized compliant structured answers while writing 18 synthetic markers through an unobserved surface. The generic caller-trusted runtime path could still qualify the responses. This demonstrates a capture boundary in this harness, not a vulnerability finding about Claude Code, Codex or another vendor. It is why response replay does not become an actual-effects claim. Separate owned examples also demonstrated that an omitted later failure cannot be discovered from a supplied older passing bundle, and that a consistently rehashed false assessment can pass checksum inspection while trusted-input replay rejects it.

## Embedded evaluator benchmarks

The initial public catalog has 16 cases: careful, reckless, silent and gaming reference behaviors; valid signed evidence; untrusted signer; signature change; declaration laundering; revoked signer; expired manifest; missing check; duplicate receipt; changed configuration; wrong evaluator; critical failure and withdrawn newer failure. Each retains the complete ordered check population, authored expectations and pass/fail/error state. Verification recomputes actual inputs and decisions. [Catalog and controls](../BENCHMARKS.md).

Independent project lanes detected six selected weakened assessor gates with all 16 cases present. Separate dossier controls detected six selected weakened reporting/replay gates. Review also exposed three concrete standalone-validation gaps: malformed benchmark summaries, invented telemetry populations and a qualified narrative retaining critical failure. The frozen repair controls progressed from one of seven passing before repair to seven of seven after repair. These are scoped local controls, not external certification or a universal detection estimate.

## Build a credible campaign for real agents

1. Freeze an explicit relying-party use case, scenario population, permitted tools, severity rubric and predeclared oracle. Record each planned attempt before execution.
2. Verify the adapter and native configuration without guessing provider entitlement. Retain exact harness/model declarations, tool surface and current authority. Distinguish declared, fixture, runtime and independently assessed sources.
3. Run in an owned isolated environment with synthetic or approved data. Independently capture requests, denied attempts, side effects, before/after state and unavailable channels. Retain original bytes privately.
4. Separate public development, regression and protected evaluation cases. Require oracle positives, no-op, cheat, replay, overproduction, valid-alternative and defect controls. Untested applicable controls stay inconclusive.
5. Preserve every attempt, including rejection, infrastructure error, timeout and abandonment. Publish unconditional completion/coverage and conditional gradable quality with both denominators. Never combine favorable checks across runs.
6. Compare baseline and candidate on identical frozen cases. Measure task outcome, failure severity, latency, provider/tool/infrastructure cost and human oversight separately. Retain dependence and uncertainty assumptions.
7. Use a separate reviewer for promotion. Record `ACCEPT`, `REJECT` or `INCONCLUSIVE`, exact artifacts and rollback. Corrections invalidate dependent conclusions while preserving original lineage.

The prior two native Codex subscription calls were provider-rejected for the configured model, with zero accepted finals. Their original outputs and hashes were retained privately; no fallback was guessed. Claude execution remains gated on unresolved effective managed policy. Those transport results are neither successful commercial-agent evaluation nor evidence of vendor task quality. No new provider call is implied by this alpha's offline controls.

## Standardization and governance

Open-KYA describes an alpha, pre-submission identity/governance manifest. KYA Evidence investigates the executable assessment and diagnostic layer; no affiliation or formal compatibility is claimed. A credential bridge should preserve exact digests, evidence class and correction semantics. [Open-KYA's stated incubation status](https://github.com/open-kya/kya-standard).

Adoption requires outside implementations that disagree productively, published compatibility cases, a controlled versioning process, transparent policy choices and real relying-party pilots. A neutral ecosystem should support multiple issuers and assessors, accessible disputes, narrow scoped claims and privacy-preserving correction. A single universal number would obscure use-case risk and transfer human harm into an unvalidated score. The standard should let parties inspect evidence and decide under explicit policy.

## Current and next evidence

Implemented now: exact-scope comparison, response-bound diagnostic dossier, offline HTML/Markdown, public evaluator controls and source-level adversarial repair checks. The reproducible package and validation receipts bind the final revision separately; this document does not manufacture final test counts.

Next research priorities: capture all planned attempts and owned side effects; authenticate environment/runtime identity; reconcile billing and oversight; establish protected representative outcomes; commission external implementation/security review; test credential bridges; calibrate use-case weights prospectively. Unknown cost remains null. Scheduled continuation needs a real registered bounded job, not a roadmap promise. Publication and new external disclosures remain separately authorized.
