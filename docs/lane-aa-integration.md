# Lane AA integration notes

Proposals only; `evidence/requirements.json` is not edited by this lane.

## Proposed requirements

| Id | Level | Statement | Test file | Exact test titles | Spec section |
|---|---|---|---|---|---|
| KYA-ENV-003 | MUST | A second implementation of the proof byte layer MUST refuse every non-canonical PEM or DER spelling of a public key that the core refuses, and MUST accept the canonical spelling. | `second-impl-strictness.test.mjs` | `canonical key is accepted by the core, the second implementation and python`; `crlf line endings in the key PEM are refused by all three`; `re-wrapped key PEM lines are refused by all three`; `missing trailing newline in the key PEM is refused by all three`; `blank line inside the base64 body is refused by all three`; `non-canonical trailing base64 bits are refused by all three`; `long-form DER length is refused by all three`; `trailing zero bytes after the SPKI are refused by all three` | `## Trust and eligibility` |
| KYA-ENV-004 | MUST | A second implementation MUST refuse small-order, off-curve and non-canonical Ed25519 public keys, including the identity key with signature 01 followed by zeros. | `second-impl-strictness.test.mjs` | `identity point key with signature 01 followed by zeros is refused by all three`; `every small-order Ed25519 point is refused by all three`; `non-canonical y encodings are refused by all three` | `## Trust and eligibility` |
| KYA-ENV-005 | SHOULD | The core, the second implementation and the Python checker SHOULD agree accept or reject on a shared set of at least 60 mutated envelopes. | `second-impl-strictness.test.mjs` | `differential run over at least 60 mutated envelopes agrees across core, second implementation and python` | `## Interoperability and versioning` |
| KYA-ENV-006 | MUST | The second implementation MUST still match all 111 assessment vectors after the strictness change. | `second-impl-strictness.test.mjs` | `second implementation still matches all 111 assessment vectors` | `## Interoperability and versioning` |

Python checks live in `interop/python/test_portability.py`, class `PublicKeyStrictness` (run with `python3 -I`); they are not named by a JavaScript requirement.

## Notes

- Messages differ between implementations by design; only the accept or reject decision is compared.
- Python is a proof byte-layer checker: payload schema mutations are outside the three-way comparison.
- Core `validatePublicPem` also applies to second-impl trust anchors now (`validPolicy`), matching the core.
