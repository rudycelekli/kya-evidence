# KYC controls and their stronger agent equivalents

Date: 2026-10-14. Status: research input, not a specification. Two deep-research runs (about 40 sources, 156 claims extracted, 50 sent to three-vote adversarial verification, 8 killed). Several verifier votes in the second run state they relied on recollection or a secondary page rather than a fetched primary text; treat every row marked *needs primary re-check* accordingly. Jurisdiction is named for each rule; nothing here is universal law.

## Verified regulatory mechanics

| Control | Source and jurisdiction | Finding | Confidence |
| :--- | :--- | :--- | :--- |
| Reliance does not transfer liability | UK MLR 2017 reg 39 (legislation.gov.uk, HMRC ECSH33550) | A relevant person relying on a third party for CDD remains liable for failures. It must immediately obtain the CDD information and be able to obtain copies of identification data on request. | High (primary text fetched) |
| Reliance limited to supervised parties | UK MLR 2017 reg 39 | The relied-on person must be supervised under MLR or equivalent. The high-risk-country carve-out detail was not fully verified. | Medium; *needs primary re-check* |
| Reliance in US | 31 CFR 1010.230(j) | Reasonable reliance, an AML-program-regulated counterparty, and an annual contractual certification. | Medium; *needs primary re-check* |
| Ongoing monitoring | MAS Notice 626 (run 1); UK JMLSG 5.7.1 and 5.7.3 | Reliance is allowed for initial CDD but not for ongoing monitoring (MAS). A monitoring system must flag, be reviewed promptly by the right persons, and drive appropriate action (JMLSG, fetched). | High |
| Beneficial ownership is for natural persons | 31 CFR 1010.230(d) | Ownership (25 percent or more) and control prongs name individuals. An agent cannot be a beneficial owner. | Medium; *needs primary re-check* |
| Event-driven re-verification | FinCEN order FIN-2026-R001, 13 Feb 2026 | Relief from re-identification at every new account. Verification is retained at first account, when prior information is doubted, and under risk-based ongoing due diligence. A recorded customer confirmation can suffice. | High (order text read) |
| Corporate Transparency Act | FinCEN interim final rule, March 2025 | Domestic reporting companies exempt; foreign entities remain. Law-firm summaries only. | Medium |
| Digital identity | FATF Guidance on Digital Identity, 6 Mar 2020 (updated since; update not checked) | Non-binding. Non-face-to-face onboarding on reliable independent digital ID may be standard or lower risk. | Medium; *needs primary re-check* |
| EU remote onboarding | AMLA final draft CDD RTS, 30 Sep 2026 (secondary vendor source) | Submitted to the Commission, not adopted. Binding only after Official Journal publication. | Medium |
| Agent identity prior art | DIF KYA-OS (primary DIF blog, March 2026) | Vouched donated its agentic identity framework to DIF; governed by a task force in the Trusted AI Agents Working Group. | High |

Killed by verifiers: a two-step beneficial-owner determination attributed to a source that did not contain it; a claim that US CDD allows owner self-certification (1-2); a claim that only foreign companies must report under the interim rule (1-2).

## Not established by either run
FATF R.10/11/15/20/24 primary text (fetch failures), EU AMLR/eIDAS 2.0 article text (EUR-Lex fetch failed), Mastercard, Stripe and Coinbase mechanics, sanctions screening, SAR/STR specifics and the quantified KYC failure rates. Do not cite them from this note.

## Mapping: KYC control to stronger agent equivalent

| KYC control | KYA today | Stronger equivalent | Status |
| :--- | :--- | :--- | :--- |
| Identify and verify the customer | Manifest binds the full agent configuration; `principal.id` is a pseudonym | Operator KYB plus a named accountable natural person, bound by signed credential to the manifest digest | **Gap: not in protocol** |
| Beneficial owner = natural person | Not modelled | Require an accountable-human reference; an agent can never be its own principal | **Gap** |
| Risk-based approach | Policy-relative thresholds and scope | Authority tiers: higher permissions require stronger source classes and independence | Partly implemented |
| Reliance on third-party vetting | Out-of-band trust anchors; roles by policy | State that reliance never transfers accountability (UK reg 39) and that a relying party's own monitoring cannot be outsourced (MAS 626) | **Spec text missing** |
| Ongoing monitoring | Freshness and expiry only | Re-assessment triggers (manifest change, model change, incident, revocation); flag, review, act (JMLSG 5.7.3) | **Gap** |
| Event-driven re-verification | Changing any manifest field invalidates evidence (KYA-BND-001) | Already stronger than KYC for configuration change | Implemented |
| Sanctions and watchlists | Revocation snapshots (key, subject, evidence) | Status-list-style revocation with freshness proof (W3C Bitstring Status List) | Partly implemented |
| Suspicious activity reporting | None | Signed incident and appeal records; correction lineage (universes already preserve lineage) | **Gap** |
| Record retention | Raw evidence kept privately; hashes public | Retention periods, redaction before hashing, access rules | Partly specified |
| Self-attested information | Declarations never satisfy scored checks (KYA-TRU-003) | Already avoids KYC checkbox self-certification | Implemented |
| Assessment mistaken for authorization | Stated limit only | Keep: assessment is not an authorization grant | Implemented |

## Proposed next requirements (each needs an ADR, adversarial regression and a detecting test before entering the registry)
1. Principal binding: a manifest or credential MUST reference an accountable natural-person or legal-entity principal; a bare agent identifier MUST NOT qualify for authority tiers above a policy-set level.
2. Non-transferable accountability: an assessment MUST state that relying on an issuer's evidence does not transfer the relying party's accountability.
3. Monitoring triggers: a policy MUST define re-assessment triggers; evidence past a trigger MUST NOT remain current.
4. Incident and appeal records: signed, scoped to the subject digest, preserving the original lineage.
5. Authority tiers: permission classes tied to minimum evidence class and independence.

Do not add these to `evidence/requirements.json` until each has a failing-then-passing test, as ADR-0011 requires.
