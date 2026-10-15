# Lane Q integration proposals (WS6-02)

Lane Q did not edit shared files. These are proposals for the integrating owner. Sections named below exist as `## ` headings in docs/SPECIFICATION.md ("Records and bindings", "Interoperability and versioning", "Reports and viewers"). Titles are copied exactly from `test/interop-bridges.test.mjs`.

## package.json

Add scripts:

```json
"bridge": "node scripts/kya-bridge.mjs"
```

Add to `exports`: `"./interop-bridges": { "import": "./src/interop-bridges/index.mjs" }`. `files` already covers `src/`, `scripts/`, `docs/` and `test/`.

## evidence/requirements.json entries (area `ibr`)

```json
[
  {
    "id": "KYA-IBR-001", "level": "MUST", "area": "ibr", "section": "Interoperability and versioning",
    "statement": "An interop bridge export of an assessment MUST fail closed on a non-qualified decision or a failed, missing or incomplete currency check unless the caller passes an explicit override flag, and any override used MUST be recorded in the output; the export MUST report qualified only when the decision is qualified and a currency check ran and passed.",
    "tests": [
      { "file": "test/interop-bridges.test.mjs", "title": "exports fail closed on a non qualified assessment unless allowNonQualified is passed" },
      { "file": "test/interop-bridges.test.mjs", "title": "exports fail closed on an expired assessment and an aged assessment" },
      { "file": "test/interop-bridges.test.mjs", "title": "exports fail closed when the manifest or the policy changed or the subject is revoked" },
      { "file": "test/interop-bridges.test.mjs", "title": "exports fail closed when no currency inputs are given or only some are given" },
      { "file": "test/interop-bridges.test.mjs", "title": "allowNotCurrent records the override and the export never claims qualified without a passing currency check" }
    ]
  },
  {
    "id": "KYA-IBR-002", "level": "MUST", "area": "ibr", "section": "Interoperability and versioning",
    "statement": "Every interop bridge export MUST be reproducible byte for byte from the same report and options, MUST NOT read a system clock, perform network access or sign, and MUST carry the limit list stating that it is not an authorization grant, that the report checksum is unauthenticated and that no third-party tool has consumed the format.",
    "tests": [
      { "file": "test/interop-bridges.test.mjs", "title": "every export is reproducible byte for byte regardless of input key order" },
      { "file": "test/interop-bridges.test.mjs", "title": "every export states the limits and leaks no principal agent name or signature" },
      { "file": "test/interop-bridges.test.mjs", "title": "the module is offline and unsigned and imports no network or crypto signing api" }
    ]
  },
  {
    "id": "KYA-IBR-003", "level": "MUST", "area": "ibr", "section": "Records and bindings",
    "statement": "The in-toto export MUST be a Statement v1 whose subject digest is the manifest digest and whose predicate carries the decision, score summary, blocker codes, exact input digests, currency block and limits of the source report.",
    "tests": [
      { "file": "test/interop-bridges.test.mjs", "title": "intoto statement is v1 shaped and its subject is the manifest digest" },
      { "file": "test/interop-bridges.test.mjs", "title": "intoto predicate carries decision scores blocker codes input digests and limits" }
    ]
  },
  {
    "id": "KYA-IBR-004", "level": "MUST", "area": "ibr", "section": "Records and bindings",
    "statement": "The OpenTelemetry-style export MUST use only attribute names documented in docs/INTEROP-BRIDGES.md with primitive or string array values, and MUST emit constant false for authorization granted and assessment authenticated.",
    "tests": [
      { "file": "test/interop-bridges.test.mjs", "title": "otel attribute map uses exactly the documented names with primitive or string array values" },
      { "file": "test/interop-bridges.test.mjs", "title": "otel attributes for a blocked assessment carry blocker codes and omit unchecked currency members" },
      { "file": "test/interop-bridges.test.mjs", "title": "otel attribute table in the docs lists every attribute name and no other kya name" }
    ]
  },
  {
    "id": "KYA-IBR-005", "level": "MUST", "area": "ibr", "section": "Records and bindings",
    "statement": "The OAuth claims export MUST NOT set token members (iss, sub, aud, exp, iat, nbf, jti, cnf) and the SPIFFE binding MUST validate the SPIFFE ID and state that the association between identity and assessment is asserted and not proven.",
    "tests": [
      { "file": "test/interop-bridges.test.mjs", "title": "oauth claims carry the assessment digest and decision under one private claim and set no token members" },
      { "file": "test/interop-bridges.test.mjs", "title": "spiffe binding ties one spiffe id to the assessment and says the association is not proven" },
      { "file": "test/interop-bridges.test.mjs", "title": "spiffe binding rejects malformed spiffe ids" }
    ]
  },
  {
    "id": "KYA-IBR-006", "level": "MUST", "area": "ibr", "section": "Interoperability and versioning",
    "statement": "The A2A and MCP exports MUST bind by assessment and subject digest, MUST point at the currency check without claiming it as proof, MUST mark the A2A extension not required and MUST accept only https URL hints that are never fetched.",
    "tests": [
      { "file": "test/interop-bridges.test.mjs", "title": "a2a extension and mcp meta point at the assessment digest and carry the currency check" },
      { "file": "test/interop-bridges.test.mjs", "title": "a2a and mcp urls must be https and are never fetched" }
    ]
  },
  {
    "id": "KYA-IBR-007", "level": "MUST", "area": "ibr", "section": "Reports and viewers",
    "statement": "The bridge cross-check MUST rebuild an export from the source report, report any difference as REPORT_MISMATCH naming the member, never throw on malformed input, and state when the currency block was not re-derived.",
    "tests": [
      { "file": "test/interop-bridges.test.mjs", "title": "cross check accepts every export built from the same report and recomputes currency when inputs are given" },
      { "file": "test/interop-bridges.test.mjs", "title": "cross check names forged members for every kind including an edit that needs no resign" },
      { "file": "test/interop-bridges.test.mjs", "title": "cross check detects injected members dropped members and swapped digests" },
      { "file": "test/interop-bridges.test.mjs", "title": "cross check without currency inputs cannot see a forged currency block but a recheck does" },
      { "file": "test/interop-bridges.test.mjs", "title": "cross check refuses a report that fails its checksum and missing or partial inputs without throwing" }
    ]
  },
  {
    "id": "KYA-IBR-008", "level": "SHOULD", "area": "ibr", "section": "Interoperability and versioning",
    "statement": "The kya-bridge CLI SHOULD export and cross-check every kind offline and refuse unsafe exports with exit code 2 and no output on stdout.",
    "tests": [
      { "file": "test/interop-bridges.test.mjs", "title": "cli exports each kind reproducibly verifies it against the report and refuses unsafe exports with exit 2" }
    ]
  }
]
```

Not mapped to a requirement but covered: `exports reject unknown options and non boolean flags and tampered reports`, `incidents supplied to the gate can make an export refuse`.

## Specification text (optional)

One sentence for "Interoperability and versioning": interop bridge exports are unsigned, fail closed on non-qualified or non-current input, are reproducible, and make no conformance claim; see docs/INTEROP-BRIDGES.md.

## Other

- ADR index: run `npm run adr:index` after merge (it rewrites `evidence/adr-index.json`; not run here to avoid touching a shared file).
- Status ledger (`scripts/world-class-status.mjs`): WS6 row may mention in-toto, OpenTelemetry, OAuth and SPIFFE, A2A and MCP bindings as implemented offline and unconsumed; the XUSE gate stays open.
- Open items: SD-JWT, JSON-LD context and DIF KYA-OS crosswalk (also WS6) are not part of this lane.
