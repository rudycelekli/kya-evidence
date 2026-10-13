# Secondary Python byte implementation

`interop/python/kya_portability.py` independently reconstructs canonical JSON and SHA-256 bytes for a declared subset of the JavaScript protocol. The implementation was written by another lane of this project team. It is a secondary implementation, not external independent adoption, a standards certification, or a second assessment engine.

The standard-library checker reconstructs every canonical case in `evidence/golden-vectors.json`, hashes the reconstructed bytes, reconstructs the domain-separated signing input from the receipt payload, and checks the envelope digest and public-key fingerprint. It never returns the vector's expected canonical text as its calculation. Existing Ed25519 support is optional.

## Run from a checkout

Python 3.9 or newer is sufficient for the byte checker. There is no required Python dependency installation.

```sh
python3 interop/python/kya_portability.py check-vectors evidence/golden-vectors.json --no-crypto
python3 interop/python/kya_portability.py check-vectors evidence/golden-vectors.json
python3 interop/python/test_portability.py -v
node --test test/interop.test.mjs test/vectors.test.mjs
```

The first command returns `status: "partial"` with all six canonical cases checked and `signature.verified: false`. The second uses `cryptography` only if already available; it returns `status: "passed"` only when Ed25519 verification succeeds. Inspect these fields: exit code zero also covers a successful byte check with an unavailable cryptographic backend. A missing backend never becomes a signature pass. A cryptographic failure returns exit code one. A valid but unsupported double returns exit code two and `status: "unsupported"`, without a canonical result.

To canonicalize bounded JSON from standard input:

```sh
printf '%s' '{"b":2,"a":1}' | python3 interop/python/kya_portability.py canonical
```

## Supported bytes and explicit limits

| Area | Implemented behavior |
| :--- | :--- |
| JSON structures | Exact Python built-in dictionaries, lists, strings, booleans, numbers and null; custom mappings and other types refused |
| Object ordering | UTF-16 code-unit ordering, including astral characters and lone surrogates; no Unicode normalization |
| Strings | JavaScript JSON spelling of controls, quotes, backslashes, valid surrogate pairs and escaped lone surrogates |
| Numbers | Safe integers; signed zero becomes `0`; exact dyadic fractions of magnitude at most one with binary denominator at most 256; signed powers of ten from `10^-1` through `10^-15` |
| Unsupported doubles | Other finite noninteger doubles are refused, including `0.3`, general decimal fractions and subnormal values; this is not a complete ECMAScript number formatter |
| Strict parser | Duplicate and escaped duplicate members, prototype member names, nonfinite constants, trailing input and excessive structures refused |
| Resources | One MiB input/output, depth 32 and 100,000 value nodes; reads are bounded before parsing |
| Signature format | Domain `kya.evidence/v1` plus newline and independently canonicalized payload; Ed25519 SPKI key digest and canonical base64url signature encoding |
| Cryptography | Optional preinstalled `cryptography`; no OpenSSL subprocess, model, network or installation calls |

The proof checker verifies the signature byte layer. It does **not** reproduce full evidence schema semantics, relying-party trust, revocation, timestamps, run selection, scores or qualifications. Its output says `semanticReceiptValidation: false` and `authenticatedIssuer: false`. Signed bytes do not establish truthful execution or authorization. The public vector's toy key is never a production trust anchor.

The Node interoperability tests launch a fixed Python checker with argument arrays, `shell: false`, a restricted environment, five-second timeout and one-MiB output cap. Python availability is probed first; hosts without Python record explicit skipped optional cross-language checks. Subprocess execution is not an OS sandbox for arbitrary hostile programs. Callers choose and trust their Python runtime and any installed cryptographic backend.

## Verification evidence and remaining work

The implementation lane ran Python 3.9.6 with existing `cryptography` 46.0.6. Every public canonical/hash vector matched, signing input was reconstructed, and the public Ed25519 fixture signature verified. Standard-library mode explicitly remained partial. Adversarial checks corrupted expected canonical text, expected hashes, signing input, envelope bytes and signature bytes; corrupted signatures failed even after recomputing their unsigned envelope checksum. A bounded batch compares all 513 signed fractions `n/256` for `-256 <= n <= 256` and 30 signed decimal powers against JavaScript.

Additional checks cover UTF-16 versus scalar ordering, lone surrogates, controls, signed zero, integer bounds, unsupported doubles, duplicate members, cyclic/custom Python values and resource abuse. This evidence establishes agreement for these cases and the declared subset. Full number formatting, independent implementers, full semantic assessment parity and real-runtime validation remain open. Do not label unsupported numeric inputs as agreement or silently replace them with vector expectations.

The lane also weakened four checks separately in disposable copies: expected canonical comparison, expected hash comparison, signing-input comparison and Ed25519 verification. The unchanged Python test suite detected each mutant with its targeted assertion; no production source was mutated. [Captured validation receipt](../interop/python/verification-20261013.json) records the tested source/vector hashes, commands, runtime versions and outcomes. It is a same-team local receipt, not an external attestation.
