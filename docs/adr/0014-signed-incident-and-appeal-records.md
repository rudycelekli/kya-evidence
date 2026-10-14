# ADR-0014: Signed incident, resolution and appeal records

**Status**: Implemented
**Date**: 2026-10-14
**Updated**: 2026-10-14 after independent review (see Review amendments)
**Depends-on**: ADR-0004, ADR-0011, ADR-0013

Review boundary: separate project lane; no external certification.

## Context

KYC separates detecting suspicious activity from reporting it, and regulated parties need contestable, accountable records. A monitoring trigger that only sees manifest, policy and clock cannot represent a problem observed in operation, and a correction or appeal path is needed so a false report cannot permanently harm an agent. Narrative text in public records would leak private detail.

## Decision

Add `kya.incident/v1`: `report`, `resolution` and `appeal` records with severity, subject digest, optional referenced incident, time and a digest of privately held details. Records are signed Ed25519 under their own domain-separation prefix. `checkCurrency` accepts them. Only records signed by a key in the supplied policy trust anchors count. Revoked, misdirected and malformed records are ignored and listed with a reason. Records are namespaced by signing key, so one key cannot erase or rewrite another key's record by reusing its ID; an identical envelope delivered twice collapses, and conflicting records from one key fail closed (most severe report kept, resolutions not honoured). An unresolved high or critical report fires `incident-open`. A resolution clears it only when signed by an `independent`-role anchor other than the reporter and dated strictly after the report. A future-dated trusted blocking report stays open (clock skew fails closed) and is listed. An appeal is recorded in the result and never clears a trigger.

## Alternatives

Free-text incident descriptions would put private data in public records. Letting the reporter resolve its own report removes contestability. Letting appeals suppress a trigger would let an operator mute any report. Counting records from untrusted keys would let anyone force reassessment. A central incident registry needs governance the project does not have.

## Consequences

Relying parties get offline, auditable incident handling with explicit ignored-record reasons and a path to correction. The mechanism cannot find incidents nobody signed or supplied, cannot prove an incident is true, and depends on the policy's roles being assigned honestly. Appeal adjudication and registry governance remain open.

## Validation

Tests cover strict schema and signature failure, each trigger, every ignored-record class, independent-only resolution, self-resolution, early resolution, dangling references, appeals and invalid input. Mutation controls remove the independence requirement and the trust-anchor check and must be detected.

## Review amendments

An independent adversarial review found that quarantining every record with a shared ID let the same envelope delivered twice, or any trusted self key reusing an independent report's ID, erase that report; that a resealed assessment with missing validity fields read as current; that a reporter could resolve its own report and an equal-timestamp resolution counted; and that high severity was untested. All were reproduced and fixed with failing-first tests. Known limits kept open: an appeal records dispute but does not reopen or contest a resolution, a hostile trusted key can still force reassessment by posting a real report, and clock-skew tolerance is fail-closed rather than tuned.
