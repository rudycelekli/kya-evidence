# Normative requirements

Generated from [`evidence/requirements.json`](../evidence/requirements.json) by `npm run requirements`. MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119/8174. Requirements describe this reference implementation; they are not an adopted standard.

Each requirement is traced to at least one test that must exist exactly once; the gate fails on stale traces. A passing trace shows the reference implementation enforces the requirement, not that it is complete or independently reviewed. A second implementation claims conformance only by passing the same vectors and tests.

| ID | Level | Requirement | Verified by |
| :--- | :--- | :--- | :--- |
| KYA-INT-001 | MUST | Canonicalization MUST be deterministic regardless of member insertion order, and MUST reject accessors, cycles, symbols, non-enumerable data and resource-exhausting input without invoking untrusted code. | `canonical.test.mjs` |
| KYA-INT-002 | MUST | Strict parsing MUST reject duplicate object members and out-of-bound input, and MUST preserve string escapes and supported numbers exactly. | `canonical.test.mjs`, `interop.test.mjs` (host-conditional) |
| KYA-INT-003 | MUST | Published golden vectors MUST reproduce the exact canonical bytes, SHA-256 digests and domain-separated Ed25519 signing input. | `vectors.test.mjs`, `canonical.test.mjs` |
| KYA-INT-004 | MUST | A second implementation MUST reconstruct every published vector and MUST refuse, not approximate, inputs outside its supported subset. | `interop.test.mjs` (host-conditional) |
| KYA-BND-001 | MUST | The subject digest MUST bind the complete manifest; changing a tool, model, configuration, principal or artifact field MUST invalidate prior receipts. | `assessment.test.mjs` |
| KYA-BND-002 | MUST | Manifests MUST reject semantically conflicting permissions, duplicate identifiers and temporal inconsistency. | `assessment.test.mjs` |
| KYA-BND-003 | MUST | Comparison MUST require identical policy, profile, evaluator, full-scope digest and complete check populations; equal scope names with different purpose or permissions MUST NOT compare. | `assessment.test.mjs`, `dossier.test.mjs` |
| KYA-TRU-001 | MUST | Signature validity MUST be checked separately from trust; a receipt MUST NOT make its own key trusted or assign itself independence. | `assessment.test.mjs` |
| KYA-TRU-002 | MUST | Signature tampering, key substitution and non-canonical proof encoding MUST fail; only public Ed25519 SPKI keys are admissible trust anchors. | `assessment.test.mjs` |
| KYA-TRU-003 | MUST | A declaration MUST NOT satisfy a scored check, and a response MUST NOT elevate fixture origin to runtime origin. | `assessment.test.mjs`, `conformance.test.mjs` |
| KYA-TRU-004 | MUST | Revoked keys, expired manifests, future-issued and over-age evidence MUST be rejected with the reason retained in the report. | `assessment.test.mjs` |
| KYA-TRU-005 | MUST | Eligible duplicate evidence IDs MUST be quarantined without boosting score, and untrusted duplicates MUST NOT remove a trusted result. | `assessment.test.mjs` |
| KYA-TRU-006 | MUST | Validators MUST return captured plain data; a Proxy MUST NOT substitute outcomes or trust roles after signature verification or canonical capture. | `assessment.test.mjs` |
| KYA-RUN-001 | MUST | Exactly one latest whole run MUST be selected; checks from several runs MUST NOT be composed. | `assessment.test.mjs` |
| KYA-RUN-002 | MUST | Tied latest runs MUST be reported ambiguous and MUST NOT qualify, and a selected critical failure MUST still block. | `assessment.test.mjs` |
| KYA-RUN-003 | MUST | Invalidating, revoking or expiring a newer failure MUST NOT revive an older pass, and a later self-signed pass MUST NOT erase a critical failure. | `assessment.test.mjs` |
| KYA-RUN-004 | MUST | A repeated frozen check MUST NOT refresh validity or repair a failure; recovery MUST use a fresh complete run ID. | `assessment.test.mjs` |
| KYA-SCO-001 | MUST | Every frozen check MUST remain in the denominator; removing a failed check MUST NOT improve score, and empty evidence MUST remain unknown within a fixed 0..1000 range. | `assessment.test.mjs` |
| KYA-SCO-002 | MUST | A critical failure MUST block qualification even under zero thresholds, and zero thresholds MUST still require one scored observation. | `assessment.test.mjs` |
| KYA-RPT-001 | MUST | The report checksum MUST be treated as unauthenticated; verification MUST NOT establish issuer authenticity, and a rehashed false report MUST fail trusted-input replay. | `assessment.test.mjs`, `benchmarks.test.mjs` |
| KYA-RPT-002 | MUST | Dossier strengths MUST be supported only by replayed originals; signed assertions without matching originals MUST remain reported claims. | `dossier.test.mjs` |
| KYA-RPT-003 | MUST | Unmeasured telemetry MUST remain null or unknown, and unexecuted checks MUST be blind spots rather than invented agent failures. | `dossier.test.mjs` |
| KYA-RPT-004 | MUST | A standalone dossier MUST NOT be resealable into a qualified decision while critical checks are failed or unproven. | `dossier.test.mjs` |
| KYA-UNI-001 | MUST | Identical frozen inputs MUST yield byte-identical universes, and modified assessor source MUST be rejected even when bindings are rehashed. | `universe.test.mjs` |
| KYA-UNI-002 | MUST | Forks MUST name a parent and hypothesis; graphs MUST refuse missing or duplicate references; comparisons MUST refuse incomplete or incompatible populations and MUST NOT claim causal improvement. | `universe.test.mjs` |
| KYA-BEN-001 | MUST | The frozen control catalog MUST keep its complete ordered population; tampered, reordered, resealed or laundered results MUST be rejected, and errors MUST NOT pass. | `benchmarks.test.mjs` |
| KYA-BEN-002 | MUST | Controls MUST detect weakened assessor gates with identical complete populations, and MUST NOT measure commercial-agent competence. | `benchmarks.test.mjs` |
| KYA-CON-001 | MUST | The core suite MUST be complete and immutable; reducing, reweighting or redirecting it MUST be refused, and gaming or silence MUST NOT yield passes. | `conformance.test.mjs` |
| KYA-REL-001 | SHOULD | Release archives SHOULD be verified against a frozen regular-file subset, rejecting duplicate paths, checksum changes, padding and path traversal. | `release.test.mjs` |
| KYA-PRN-001 | MUST | A declared accountable party MUST be a pseudonymous natural-person or legal-entity reference with no extra fields, and an agent MUST NOT be its own accountable party under case variation. | `assessment.test.mjs` |
| KYA-PRN-002 | MUST | When policy requires principal binding, a manifest without a declared accountable party MUST NOT qualify; the declaration MUST be part of the subject digest, and absence of the policy flag MUST preserve prior behavior. | `assessment.test.mjs` |
| KYA-MON-001 | MUST | A currency check MUST report each fired monitoring trigger (subject change, policy change, revocation, expiry, age limit, clock regression) and MUST direct reassessment when any fires. | `assessment.test.mjs` |
| KYA-MON-002 | MUST | A currency check MUST reject a forged or malformed assessment, missing or invalid time, and invalid inputs, and MUST NOT report a non-qualified decision as reliable. | `assessment.test.mjs` |
| KYA-INC-001 | MUST | Incident records MUST be strict, signed under a domain-separated Ed25519 context and MUST carry only a details digest, never narrative text. | `incidents.test.mjs` |
| KYA-INC-002 | MUST | A trusted unresolved high or critical incident MUST trigger reassessment, a future-dated trusted blocking report MUST stay open, and untrusted, revoked, misdirected or malformed records MUST NOT trigger and MUST be listed as ignored. | `incidents.test.mjs` |
| KYA-INC-003 | MUST | Only an independent trusted key MAY resolve an incident, never its own report, and only with a resolution dated strictly after the incident; an appeal MUST be recorded without clearing the trigger. | `incidents.test.mjs` |
| KYA-INC-004 | MUST | Every distinct trusted report record MUST be retained; duplicate or conflicting IDs MUST fail closed (reports stay open, a resolution targets only an unambiguous reference), no key MUST be able to hide, downgrade or clear another record by reusing its ID, input order MUST NOT change the outcome, and an identical envelope delivered twice MUST NOT quarantine itself. | `incidents.test.mjs` |
| KYA-MON-003 | MUST | A currency check MUST reject an assessment whose validity, scope, subject, policy or decision fields are missing or malformed, or whose validity precedes its assessment time, rather than treating it as current. | `assessment.test.mjs` |
| KYA-REQ-001 | MUST | The traceability gate MUST treat dynamic titles, option variables, obfuscated or unconditional skip/todo as untraceable, MUST require an explicit hostConditional flag for host-conditional skips, and CI MUST fail on any skipped or todo test. | `requirements.test.mjs` |
| KYA-CNF-001 | MUST | A conformance report MUST contain exactly one entry for every requirement in the registry it names by digest, and MUST be rejected when it has unknown, missing or duplicate requirement IDs or a registry digest that differs from the registry it is checked against. | `conformance-report.test.mjs` |
| KYA-CNF-002 | MUST NOT | A conformance report MUST NOT record pass for a requirement on declaration evidence or without at least one executed test or vector ID. | `conformance-report.test.mjs` |
| KYA-CNF-003 | MUST | Conformance summary counts MUST keep not-run requirements in the denominator and MUST be recomputed on validation; a requirement MAY be not-applicable only when the implementation's declared subset excludes it. | `conformance-report.test.mjs` |
| KYA-CNF-004 | MUST | A signed conformance report MUST use the Ed25519 domain-separated input prefix kya.conformance-report/v1 followed by a newline, and a signature MUST NOT verify under another record domain or after any payload change. | `conformance-report.test.mjs` |
| KYA-CNF-005 | MUST | The reference report builder MUST mark a requirement pass only when every traced test passed and none was skipped, MUST mark a failing trace fail, and MUST treat skipped, absent or ambiguous traces as not-run. | `conformance-report.test.mjs` |

Registry digest: `f754f7f4ecd39c86a441d0e471ac010c06b838ea8f4d8c27b69a6e134186496a`
