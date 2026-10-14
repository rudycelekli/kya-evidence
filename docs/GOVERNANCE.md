# Neutral infrastructure, contestable decisions

KYA Evidence is currently a maintainer-led experimental project. Its vision is an open protocol that many implementations and independent assessors can use. No standards-body approval, ecosystem adoption or independent certification is claimed. A single score provider should not silently control the meaning of agent reputation.

## Separation of roles

Subjects describe exact systems. Issuers collect and sign observations. Independent assessors challenge execution and evaluator quality. Relying parties supply their own policies and trust anchors. Implementers reproduce protocol behavior. Maintainers steward reference contracts and corrections. These roles are separable; signatures do not establish organizational independence or honest observation.

Contributors propose cases, adapters and fixes. Independent reviewers compare candidate and baseline against identical frozen cases without changing expected outputs. Maintainers review protocol meaning. The repository owner retains merge, publication and deployment authority. Automated generation cannot approve its own promotion.

A schema, scoring, critical-gate, eligibility or evaluator change requires an ADR, adversarial regression, mutation test and same-case comparison. ADR `Implemented` means reference code exists; independent acceptance is separate and must carry evidence. No commercial leaderboard is legitimate without actual authorized runs, capture methods, uncertainty and correction rights.

## Appeals and correction lineage

A challenge supplies assessment digest, exact frozen inputs, assessment time and a sanitized reproduction. Challenges may concern authenticity, configuration binding, scope, role independence, freshness, scenario validity, fairness, scoring or privacy. Policy owners resolve trust assignments. Protocol maintainers resolve reference behavior. Issuers remain accountable for their observations.

Accepted corrections create new evidence and assessments linked by an explicit correction record. Previously authorized evidence is preserved; results are not silently rewritten to improve rankings. Updated policy snapshots revoke affected keys, receipts or subjects. Sensitive traces remain private. Public correction notes contain the minimum authorized reproduction and impact.

A future appeal specification needs time-bound acknowledgement, independent adjudication, conflict-of-interest disclosure and machine-readable correction/revocation lineage. These are proposed governance milestones, not currently implemented services or promised SLAs.

## Interpretation and standardization

Scores attach to exact systems under specific policies. Never infer a person's creditworthiness or worth. Publish check-level limits, weighting rationale, uncertainty and source class. Avoid hidden demographic proxies and universal rankings. An assessment does not override tenant authorization or grant authority to an agent.

Adoption must be earned through at least two independent implementations, interoperable test vectors, independently operated assessments, protected evaluation and prospective use-case validation. Bridges to other projects need executable mappings and explicit collaboration, not name-dropping or presumed affiliation.

## Continuing development

A bounded cycle records owner, inputs, source/evaluator revisions, candidate, tests, failures, cost (null when unmeasured), independent review and `ACCEPT`, `REJECT` or `INCONCLUSIVE`. Promotion keeps rollback. A roadmap alone is not a running scheduler. Spending, public disclosures, deployments and production actions require explicit authorization.

## Requirement identifiers

The registry is `evidence/requirements.json`. IDs have the form `KYA-<AREA>-<NNN>`. The generated [requirements document](REQUIREMENTS.md) lists 39 requirements at this revision, and its registry digest changes whenever the registry changes.

- IDs are never reused. A new obligation takes the next free number in its area.
- A requirement is retired only by a new ADR that names the removed obligation and the reason. The retired ID stays allocated.
- The generator has no retired status today. Retiring a requirement therefore also needs a change to the traceability gate in the same ADR.
- A new requirement enters the registry only with a test that fails without the behavior and a trace that the gate can find.

## Conformance claims

A conformance claim names requirement IDs, not the whole protocol. It records the registry digest, the implementation version and the exact tests or golden vectors that passed. The reference implementation's own traces show that it enforces its registry; they are not an independent claim.

- A second implementation may claim KYA-INT-004 only by reconstructing every published golden vector and refusing inputs outside its supported subset.
- Host-conditional traces (KYA-INT-002, KYA-INT-004) cannot count for a host that lacks the dependency.
- No claim of "KYA conformant" as a whole is made or accepted until the gates below are met.

## Independent roles are policy

Relying parties assign the `self` or `independent` role in `trustedKeys`. A receipt, proof or incident cannot assign its own role (KYA-TRU-001), and a resolution counts only from an `independent` anchor other than the reporter's key (KYA-INC-003). The software checks key roles only. It does not check organizational independence, common ownership or employment, and a relying party that marks two keys as independent when one operator controls both gets the result it configured.

## Disputes and appeals, current limits

- An appeal is a signed record that is listed under `appealed`. It does not clear a trigger, reopen a resolution or change a decision (KYA-INC-003).
- No adjudicator, acknowledgement deadline or conflict-of-interest disclosure exists in code. The proposed milestones in the section above remain proposals.
- A correction takes the form of a new signed resolution from an `independent` anchor, or a policy update that revokes keys or subjects. Policy owners make the policy update.
- Disputes about reference behavior go to maintainers through [SECURITY.md](../SECURITY.md) or the issue tracker. No response time is promised.

## Before any adoption claim

No adoption, standard or compliance claim is made until each item below exists with evidence:

1. External security and evaluator review of the whole reference implementation, with reproduced defects and repaired gates (ROADMAP stage 1).
2. At least one second implementation written by people outside the maintainers, passing the published vectors and traces (stage 5). The team-built Python checker covers a restricted subset and does not count.
3. Protected holdouts, if any scoring claim is made (stage 4).
4. Recorded disagreements between implementations, with their resolution.

Until then, documents say "reference implementation", and an ADR marked `Implemented` means that code exists, not that anyone independent accepted it.
