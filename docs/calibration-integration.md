# Calibration study: integration proposals (WS10-04)

Proposals only, for the integration owner. No shared file was edited by this lane. No data exists yet, and nothing here is evidence of predictive validity.

## Proposed requirements for evidence/requirements.json

Each row names an exact test title in `test/calibration-docs.test.mjs` and a SPECIFICATION section that already exists as a `## <section>` heading in `docs/SPECIFICATION.md`.

| Proposed ID | Level | Requirement | Spec section | Exact test title |
| :--- | :--- | :--- | :--- | :--- |
| KYA-CAL-001 | MUST | The calibration study design and the pre-registration template MUST each contain every required section heading. | Governance documents | `calibration docs contain every required section heading` |
| KYA-CAL-002 | MUST | Both documents MUST state that no data exists and that nothing in them is evidence of predictive validity. | Governance documents | `calibration docs state that no data exists` |
| KYA-CAL-003 | MUST | The design MUST define ACCEPT, REJECT and INCONCLUSIVE before data. | Governance documents | `calibration docs define ACCEPT REJECT and INCONCLUSIVE` |
| KYA-CAL-004 | MUST | No calibration document may claim predictive validity outside a negation. | Governance documents | `calibration docs never claim predictive validity outside a negation` |
| KYA-CAL-005 | MUST | The template MUST describe the freeze-and-hash step using existing campaign plan and ledger concepts and no new ledger kind. | Records and bindings | `preregistration template freezes through the existing campaign ledger` |
| KYA-CAL-006 | MUST | The calibration documents MUST be plain ASCII. | Governance documents | `calibration docs are plain ASCII` |

## Other integration items

1. docs/SPECIFICATION.md, section "Governance documents": add one sentence linking `CALIBRATION-STUDY.md` and `CALIBRATION-PREREGISTRATION-TEMPLATE.md` and repeating that predictive validity is not claimed.
2. docs/WORLD-CLASS-STATUS.md, WS10: record the design and template as drafted, unreviewed, with no data.
3. README: optional link under documentation. Do not describe the study as running.
4. ADR-0021 states that the roles `calibrator` and `anchor-operator` are not yet accepted by the policy validator. This design uses only `capture-issuer` and `independent`; no new role is needed for the registration.
5. Open question for the integration owner: whether the convention of carrying the registration digest in a plan attempt's `scenarioSetDigest` is acceptable, or whether a documented dedicated record type should be considered later through the ADR process. This lane did not add one.
6. Open question: the study uses the outcome record kind from ADR-0014 as is. A resolution there does not distinguish unfounded from remediated reports; see the design, Outcome definitions.
7. Needs the owner: a statistician review of the power section, a privacy review and a DPIA, counsel on publication and right of reply, and a decision whether a relying-party cohort of the required size is reachable at all.
