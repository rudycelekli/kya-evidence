# ADR-0008: Verify portable protocol bytes in a secondary Python implementation

**Status**: Implemented
**Date**: 2026-10-13
**Depends-on**: ADR-0002, ADR-0006
**Review**: Same-project team implementation and executable comparison; external independent implementation and standards-body adoption remain open.

## Context

JavaScript alone reproducing its own golden vectors does not demonstrate that another language can reconstruct the signing and hashing bytes. Python Unicode ordering and floating-point spelling differ from JavaScript defaults. Reusing expected vector strings, a JavaScript subprocess, or a generic Python JSON serializer would hide those disagreements. A complete ECMAScript double formatter is a separate correctness problem.

## Decision

Implement standard-library canonicalization and hashes independently in Python for an explicit numeric subset that covers every current public vector. Order keys by UTF-16 code units; encode strings with JavaScript-compatible surrogate and control handling; reject duplicate/prototype members and resource abuse. Compute canonical bytes and hashes from input values before comparing expected values. Reconstruct the signing input from the payload and bind envelope/key hashes. Use only an already installed cryptographic backend for optional Ed25519 verification; unavailable verification remains visibly partial.

Safe integers, signed zero, small exact dyadic fractions and bounded signed decimal powers are supported. Other noninteger doubles return unsupported rather than claiming a general translation. Keep the byte verifier distinct from full receipt semantics, relying-party policy and assessment. Describe this as a secondary same-project implementation, not external independence or adoption.

## Alternatives

Using Python's default Unicode key sort violates UTF-16 ordering for astral characters. Default float serialization changes exponent notation and has no general ECMAScript equivalence guarantee. Calling JavaScript would test a wrapper rather than a second calculation. Forwarding expected canonical vector text would make corrupted expectations pass. Implementing a complete shortest-double formatter in this lane would increase the verification surface without a qualified exhaustive numeric corpus.

## Consequences

All existing public vectors can be independently reconstructed without dependencies, while some otherwise valid JavaScript inputs remain deliberately unsupported. Cryptography remains optional and cannot grant issuer trust. Subprocess tests are bounded argument-array executions, not isolation from arbitrary hostile code. The module does not assert full evidence schema validation, semantic assessment parity, standards compliance or external adoption.

## Validation

Run the Python adversarial suite and Node cross-language/vector checks. Require exact agreement for every published canonical byte/hash case, reconstructed signing input, key fingerprint and envelope digest. Test UTF-16 ordering, surrogate handling, controls, zero and safe integer limits, all signed `n/256` values in the supported range, and signed decimal powers. Independently corrupt expected canonical strings, hashes, signing input and signature bytes; recomputing a corrupt signature's checksum must not make it verify. Standard-library-only and absent-backend paths must report partial, unsupported numbers must not return canonical results, and resource/duplicate-member controls must fail closed.

At the implementation snapshot, Python passed 14 tests and the combined Node canonical/vector/interoperability checks passed 39 tests, with no skips. Four isolated mutants weakened the canonical, hash, signing-input or Ed25519 check; the unchanged Python tests detected each. The validation receipt binds tested source and public vector hashes. These measurements apply to this snapshot and these fixtures.
