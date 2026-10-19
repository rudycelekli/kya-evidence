# Fix lane 19: a Python implementation of four contract operations

## What changed

`interop/python-impl/adapter.py` implements `canonicalize`, `digest`, `verify-envelope` and `compare` of contract version 2 in Python 3 with the standard library only, including Ed25519 verification written from RFC 8032. It answers `unsupported` for `assess`, `currency`, `verify-credential`, `verify-score-card` and `compare-score-cards`. Nothing under `src/` changed. The vectors, their expected values and the requirement registry did not change.

It is a same-team implementation in a different language, not outside review. The independence it has and lacks is stated in `docs/IMPLEMENTERS-GUIDE.md`, section "Python implementation of four operations", which also holds the complete disagreement log.

Specification text added (each rule is behaviour the reference already had; no vector result changed): the members of a manifest, profile, policy and evidence payload, the title member of a profile check and the six dimension names, the definition of a control character (U+0000 to U+001F and U+007F), text length counted in UTF-16 code units, uniqueness of `mandatoryMinimums` check IDs, the pointer from the comparison rules to the blocker code vocabulary and cross-checks of `docs/SCORING.md`, and the cofactorless Ed25519 equation.

## Result

Interpreter: `python3` 3.13.5 (`/opt/anaconda3/bin/python3`, first on the PATH) and `/usr/bin/python3` 3.9.6, identical results.

| Operation | Vectors | First run of the first draft | After the specification fixes |
| :--- | :--- | :--- | :--- |
| `canonicalize` | 72 | 72 pass | 72 pass |
| `digest` | 38 | 37 pass, 1 fail | 38 pass |
| `verify-envelope` | 68 | 68 pass | 68 pass |
| `compare` | 35 | 35 pass | 35 pass |
| Other five operations | 586 | `unsupported` or refused at the parser | same |

Whole file: first run 251 pass, 77 fail, 471 unsupported; final 252 pass, 76 fail, 471 unsupported. The 76 fails are the refusal vectors of `assess` (65) and `currency` (11), which the contract records as `fail` for an `unsupported` reply. Registry effect: 2 of 284 requirements `pass`, 16 `fail` (only through those vectors), 266 `not-run`. The reference and `interop/second-impl/` still pass 799 of 799 after the specification edits.

Three disagreements were found after the vectors passed, by running about 300 hand built inputs, a 3000 number fuzz, 140 signature bit flips and one crafted signature through the Python code and the reference adapter used as a black box: control characters, a repeated mandatory minimum check and the blocker code rules of a compared report. No vector pins any of them for the four operations. Each is pinned now by `test/python-impl.test.mjs`, which compares the two adapters on those inputs.

## What is not verified

- Same team, different language. The author of the Python code is the project team. No outside party reviewed it or ran it.
- The vectors cover only what they cover. The only real vector miss was a specification silence, and three more silences were found by comparing against the reference, not by a vector. Other silences may remain.
- The probes used the reference as an oracle, so the three later corrections make Python agree with the reference; they are not independent evidence that the reference is right.
- Number formatting and string escaping were compared on the vectors and on a bounded fuzz, not exhaustively. The Python code was not compared on input of 1 MiB or on the 100000 value bound.
- Linux and Windows were not run. Only macOS with two Python interpreters was.
- The Ed25519 code is not constant time and is for verifying public data.
- `docs/SCORING.md` was read after the first run for the blocker code table, which was outside the list of allowed reading for a clean-room draft.

## Requirement proposals

Not added to `evidence/requirements.json`. Each id is three letters then three digits, each test title is exact and exists once in `test/python-impl.test.mjs`, and the section is an existing `## ` heading of `docs/SPECIFICATION.md`.

| Proposed ID | Level | Area | Section | Statement | Test titles |
| :--- | :--- | :--- | :--- | :--- | :--- |
| KYA-PYI-001 | SHOULD | interoperability | Interoperability and versioning | A second-language implementation of the four version 2 operations canonicalize, digest, verify-envelope and compare SHOULD reproduce every published vector of those operations, and an operation it does not implement MUST be answered with the exact unsupported reply so that the harness records not-run. | `python passes every canonicalize vector through the harness`; `python passes every digest vector through the harness`; `python passes every verify-envelope vector through the harness`; `python passes every compare vector through the harness`; `python answers unsupported for the five operations it does not implement so the harness records not-run`; `the unsupported reply is exactly the three member object of the contract` |
| KYA-PYI-002 | MUST | interoperability | Records and bindings | A verifier that reads untrusted input MUST refuse input the strict parser refuses before it looks at the operation, and a standard library only implementation MUST NOT import a package outside the standard library or make a network, subprocess, file or dynamic code call. | `python refuses input that the strict parser refuses before it looks at the operation`; `the python source imports only standard library modules`; `the python source makes no network subprocess file or dynamic code calls`; `the python adapter is one file that does not read src or the vectors` |
| KYA-PYI-003 | MUST | interoperability | Trust and eligibility | Two implementations MUST agree on the rules the specification states for control characters, repeated mandatory minimums, profile check members, blocker code cross-checks of a compared report, number formatting, member order outside the Basic Multilingual Plane, and the cofactorless Ed25519 equation. | `the rules the disagreement log says were written into the specification agree between python and the reference`; `python and the reference agree on the blocker code rules of a compared report`; `python and the reference agree on number formatting for a spread of doubles`; `python and the reference agree on member order and escapes outside the basic multilingual plane`; `python and the reference refuse a signature that satisfies only the cofactored equation and accept the honest one` |
