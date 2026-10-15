# Fix lane 2 integration notes

Proposals only; shared files (`evidence/requirements.json`) were not edited.

New tests that could be traced (existing traced titles were not renamed; their bodies were updated for the `masterSalt` API and the `refDigest` withdrawal field):

- KYA-PRV-001 (scanner never leaks): `privacy scan keeps two different files with the same base name outside cwd`, `privacy scan reports unreadable files without echoing the path and strips control characters`, `privacy scan exits 2 when nothing was scanned and normalizes extensions`.
- KYA-PRV-002 (structural rules): `privacy scan applies the coded-field rule to any key ending in Id`, `privacy scan uses the strict parser, strips a BOM and checks nested narrative fields`.
- KYA-PRV-005 (commitments): `field commitment derives a distinct salt per field and an opened field does not leak the master`, `field commitment refuses constant salts, short salts, a public salt parameter and null input`.
- KYA-ASR-00x (standing): `an adverse newer disclosure cannot be laundered by letting it expire`, `withdrawing an adverse newer disclosure does not revive an older none disclosure`, `withdrawal time must not precede its target or lie in the future`, `a withdrawal binds to the target envelope digest and not to the record id alone`, `a declarer can withdraw its own declaration but not another key`.

Format change: `kya.assessor-disclosure/v1` gained the exact key `refDigest` (alpha, documented in ADR-0028). Any external fixture or Python/second-implementation vector for this record must add it; none exists in the repository today.
