# KYA pilot participation

KYA Passport gives a relying party a stable agent record, signed key history and exact authorization evidence for an MCP call. The pilot evaluates whether an outside operator can reproduce those checks in a scoped environment and report where the workflow breaks.

## Roles and evidence

| Participants | Pilot task | Evidence to return |
| --- | --- | --- |
| Two independent witness operators | Onboard separate keys and state, validate a registry snapshot from independently retained registration receipts, and rehearse one lost-key recovery | Roster and checkpoint digests, proof results, recovery duration, any disputed or missing records |
| Relying party and MCP operator | Enroll an approved test identity, register one test agent, execute one permitted tool request, and exercise denial cases and the controlled interruption | Operation IDs and receipt digests, verified effect count, failures, and operator effort |
| Independent implementer | Implement and run the signed history and proof formats without importing the reference verifier | Pinned source revision, exact vectors and all pass, fail, or unsupported outcomes |
| Security and privacy reviewers | Review key custody, freshness, disclosure and failure behavior, then verify fixes | Scope, findings, residual risks and retest results |

Use synthetic or expressly approved test data. Share commitment hashes, published test cases and redacted failure details. Keep credentials, raw logs and identity attributes under operator control. A participant can flag a failure or withdraw participation. Publish participant names, case results or endorsements only with their permission.

## Invitation draft

We’re looking for independent operators and implementers to test KYA Passport on a scoped agent workflow. A witness operator would run a separate key and database and rehearse recovery. A relying party would verify one agent and a permitted MCP tool call, then test whether rotation, revocation and an interrupted call behave as expected. An implementer would reproduce the proof checks from the wire rules and share any differences.

If you’re interested, tell us which role fits and what test environment you can use. We’ll agree on a scope and evidence format before connecting anything. The goal is to find and document failures, including any workflow you cannot reproduce.

Independent implementers can use the [Passport conformance kit](../interop/passport-conformance/README.md) before connecting to a pilot. Include the frozen corpus digest and your exact implementation revision with the report.
