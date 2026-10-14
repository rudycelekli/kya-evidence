# ADR-0020: External anchoring of evidence bundles and capture digests

**Status**: Proposed
**Date**: 2026-10-14
**Depends-on**: ADR-0003, ADR-0013, ADR-0014, ADR-0017

Review boundary: design only; nothing implemented, no independent review, no external certification.

## Context

Signatures prove key possession, not when a record existed or whether a history was rewritten. ADR-0003 says a trusted issuer can omit whole runs; ADR-0013 notes revocation freshness is limited to a supplied snapshot; ADR-0017 needs planned attempts recorded before execution. A bundle can be backdated, quietly replaced, or an unfavourable run dropped, and the verifier has no external reference.

## Decision

Define an **anchor record** `kya.anchor/v1`: a digest-only commitment of a batch, placed in an external append-only or time-attesting system, plus the proof returned. Anchoring is optional per policy (`requireAnchor`, with `maxAnchorLagSeconds`).

### What is anchored

A batch root: a Merkle root (domain-separated, binary tree over sorted leaf digests) of leaf digests of evidence-bundle digests, `kya.capture/v1` digests, planned-attempt ledger heads (ADR-0017), and optionally revocation-snapshot digests. Only 32-byte digests leave the machine. No subject names, scope text, tool names, traces or manifests. Leaves of different record types are domain-tagged. A per-campaign hash chain head is anchored before the first run (commits the plan) and after the last (commits completeness claim).

### Anchor backends compared

| Backend | Gives | Trust required | Limits |
| :--- | :--- | :--- | :--- |
| RFC 3161 timestamp authority | Signed token that a hash existed at genTime. Per RFC 3161 the token is a proof of existence but the standard does not itself establish TSA trustworthiness; clients judge TSA policy (fetched, https://www.rfc-editor.org/rfc/rfc3161, 2026-10-14) | The TSA key and policy; one authority | No append-only property; a TSA can issue conflicting times undetected; stale/revoked TSA certificates need handling |
| Public transparency log (Merkle log in the style of RFC 9162, or Sigstore Rekor) | Inclusion proof against a signed tree head; consistency proofs show a later head extends an earlier one, so the log is append-only by verifiable construction (RFC 9162 sections 2.1.3, 2.1.4, 4.10, fetched 2026-10-14, https://www.rfc-editor.org/rfc/rfc9162) | Log operator not to equivocate, mitigated by gossip or monitors | Public by nature (digests visible, timing visible); availability depends on a third party; Rekor details not fetched, unverified |
| Signed witness cosigning | Independent witnesses cosign a tree head, so no single operator can present different histories without colluding with a quorum | Witness set and quorum policy | Witness ecosystem and protocols not fetched or assessed here; unverified |

Decision: define the anchor record with a `backend` discriminator and verify two initially, RFC 3161 token and a Merkle inclusion plus consistency proof against a signed tree head. Policy states acceptable backends and a minimum count (for example one transparency log AND one TSA, or a witness quorum). Using two unlike backends reduces single-operator trust. The project does not operate a log.

### Verification

Verifier recomputes the leaf, the Merkle path to the batch root, checks the backend proof, checks the proof's key against policy-listed `anchor-operator` keys (a role distinct from evaluator, capture issuer and independent assessor) and checks anchored time. Outputs: `anchoredAt` (an upper bound: the evidence existed no later than this time), and a lag = anchoredAt minus evidence timestamps; if lag exceeds `maxAnchorLagSeconds` the check is `unanchored-late`. A time **lower bound** is not provided.

Rewrite detection: the verifier given two anchored heads of one campaign chain or log checks consistency (log) or hash-chain extension (campaign). An evidence set that contradicts an earlier anchored commitment yields `history-rewrite-detected`; a ledger entry anchored before execution but missing from later bundles yields `omitted-run` (ADR-0017). An unanchored suffix is reported as such, never silently trusted.

### Privacy and failure behaviour

Digest-only; batching hides individual record count from observers; no salting is needed for high-entropy signed records, but low-entropy leaves (small enumerations) must be salted with a private random value to resist guessing. Anchoring is permanent, so a digest of material later ruled to need deletion remains visible, which carries no content. Anchoring failure never blocks local evaluation; the result is `unanchored`, and a policy that requires anchors treats it as unresolved rather than as pass.

## Alternatives

Rely on signed local timestamps: self-asserted. Blockchain anchoring: strong append-only property but cost, privacy exposure of transactions and governance weight; not excluded as another backend. A project-run central log: needs governance and funding the project lacks (ADR-0014 rejected a central registry for the same reason). Anchoring whole bundles: leaks content. Per-record anchoring only: expensive and reveals counts and timing.

## Consequences

Relying parties gain an upper bound on when evidence existed and detectability of silent rewrites and, with pre-execution anchoring, of omitted runs. Cost: external dependency, batching delay (lag), proof storage, and operator-trust decisions. Claim ceiling: proves a digest was committed by a given time and that the log history is consistent as observed by the verifier. It does not prove the content is true, that capture was honest, that every run was anchored (completeness only holds for what was planned and anchored in advance), that a log operator did not equivocate to this verifier alone without monitors or witnesses, or the identity of the party who submitted. Timestamp is an upper bound only. Ideas adapted from private Gradia Guard evidence-ingestion work were not retrievable in a form used here and none were relied on; the design above is original.

## Validation

Test-first with an in-process fake log and fake TSA (no network): inclusion proof accept and each-bit tamper reject; consistency proof accept and fork reject (`history-rewrite-detected`); wrong domain tag leaf rejected; leaf for unknown record type rejected; late anchor yields `unanchored-late`; unanchored policy-required evidence is unresolved not pass; anchor key not in policy rejected; anchor-operator equal to evaluator key rejected; plan anchored before run versus after run distinguishes `omitted-run` detection; low-entropy leaf without salt rejected by builder; privacy test asserts only digests appear in the anchor payload. Mutation controls drop consistency checking, domain separation and role separation and must be detected. Real-network anchoring is a separate authorized exercise, not part of CI.
