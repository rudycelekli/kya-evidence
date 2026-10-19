> **Draft for review by qualified legal counsel. Not legal advice. Not yet adopted by any body.**

# Intellectual property policy (draft)

Status: draft, version 0.1 (drafted 2026-10-15). Not adopted. Every clause below needs counsel's review before use. Nothing here is a licence grant beyond what Apache-2.0 already provides.

## 1. Licence of contributions

1. The project is licensed under the Apache License, Version 2.0 (`LICENSE`), with the notices in `NOTICE`.
2. A contribution is licensed to the project and to recipients under Apache-2.0 by the contributor, as stated in the Apache-2.0 terms for contributions.
3. Documentation contributions are offered under the same licence unless a separate written statement says otherwise. Counsel should confirm whether a separate documentation licence is wanted.

## 2. Patent grant

Apache-2.0 section 3 already provides that each contributor grants a patent licence for the patent claims that the contributor's contribution necessarily infringes on its own. This policy adds no further grant and does not expand it. It also ends for a party that starts patent litigation alleging that the project infringes, as the Apache-2.0 terms provide.

## 3. Developer Certificate of Origin

1. Every commit that proposes a change must carry a `Signed-off-by:` line, matching the contributor's real name and a working email address, which certifies the Developer Certificate of Origin (developercertificate.org). A pull request without the sign-off is not merged.
2. A contributor may sign off only for work they have the right to submit under this policy.
3. A `Co-Authored-By` trailer for an AI tool does not replace the sign-off. A human contributor must still take responsibility for the sign-off.
4. Counsel should confirm whether the DCO alone is sufficient for the expected contributors, or whether a contributor licence agreement is also needed.

## 4. Royalty-free commitment for essential claims (DRAFT for counsel)

The following is a draft of an optional commitment for a future standardisation track. It is not in force and no contributor has given it.

> Draft text, not in force: a contributor who holds a patent claim that is essential to implementing a published normative requirement of the KYA Evidence specification intends to license that claim to any implementer on royalty-free terms, on reasonable and non-discriminatory conditions, for the purpose of implementing that requirement, subject to the scope and exceptions that counsel defines.

Points counsel must decide:

- whether the commitment applies only to the normative requirements in the registry, or also to profiles and extensions;
- the treatment of defensive termination, reciprocity and assignment;
- whether the commitment binds successors and transferees;
- how "essential" is determined, and whether an essentiality opinion is needed;
- whether the commitment must be given before any neutral home accepts the project.

## 5. Disclosure of known essential patents

1. A contributor who knows that a patent or pending application they own or control contains a claim that may be essential to a normative requirement must disclose it to the maintainers in writing, as soon as they become aware of it.
2. The disclosure names the patent or application, the requirement IDs it may touch and the contributor's stated licensing position.
3. A disclosure is recorded in the decision record for the affected requirement. A disclosure is not an admission that the claim is valid or essential.
4. Failure to disclose does not by itself breach Apache-2.0. Counsel should decide whether a stronger duty applies.

## 6. Employer contributions

1. A contributor who writes code or text in the course of employment, or with an employer's resources, must have the employer's permission to contribute it. The contributor must sign off only if that permission exists.
2. Employer ownership of IP may apply in some jurisdictions even without a contract. Counsel should advise on the template language for an employer waiver and whether a corporate sign-off register is needed.
3. No corporate contribution agreement exists in this repository today.

## 7. Third-party code and data

1. Third-party code may be included only when its licence is compatible with Apache-2.0, its notice is kept, and the source of the code is named in `NOTICE` or the file header.
2. Third-party datasets, vectors and text must be sanitised and licensed for redistribution. A contributor must name the source and the licence.
3. Each dependency is reviewed before inclusion. The project has zero npm runtime dependencies today; any new dependency needs an ADR (see `CONTRIBUTING.md`).
4. Standards text from other bodies is quoted only to the extent the owning body permits, and is cited, not reproduced.

## 8. Prohibited contributions

The project was written independently: ideas from the owner's private product informed the design and no code or data was copied. Contributors must not submit any of the following, as stated in `AGENTS.md`:

- customer data or records of any person or organisation;
- credentials, API keys, tokens, passwords or signing keys, including test keys that were issued as live keys;
- private product code, including code from a private repository, or code copied from a product the contributor is not licensed to publish;
- operational logs, raw traces, internal paths or infrastructure details.

Sensitive defects are reported through `SECURITY.md`, not through public issues. A maintainer who finds a prohibited item removes it from the repository history where practical, rotates any exposed secret and records the incident.

## 9. Patent and trademark assertions

Neither this policy nor any contribution asserts that the project or its name is patented or registered. See `TRADEMARK-AND-CLAIMS.md`.

## 10. Open questions for counsel

- The exact form of the royalty-free commitment (section 4) and when it would be offered.
- Whether the DCO is sufficient for employers and for AI-assisted contributions.
- The rules for disclosure timing and for patents acquired after a contribution.
- The treatment of contributions that span the Apache-2.0 notice and a future documentation licence.

See also: `CHARTER.md`, `TRADEMARK-AND-CLAIMS.md`, `../../CONTRIBUTING.md`, `../../CODE_OF_CONDUCT.md`.
