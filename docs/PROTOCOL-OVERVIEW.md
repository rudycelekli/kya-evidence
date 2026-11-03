# Know Your Agent: evidence for an exact delegation

Status: non-normative overview, 2026-11-03. Describes the experimental KYA Evidence reference implementation and its proposed adoption path. It is not an adopted standard or a claim of independent review.

A relying party needs to answer a concrete question: **does this exact agent configuration meet this party's policy, for this scope, on the evidence supplied?** A name or credential cannot answer that question alone. A signature can protect a statement without making the statement true. A result for one model, toolset or permission scope may not apply after that configuration changes.

KYA makes the evidence and the decision portable. An issuer records check outcomes, a verifier checks bindings and trust, and each relying party supplies its own policy. The intended shared contract is the record format and decision semantics; relying parties retain their decisions.

## What travels between parties

| Object | What it binds or records |
| :--- | :--- |
| Manifest | Exact agent, controller reference, harness, model, tools, configuration and scope. These remain declarations unless separately evidenced. |
| Profile and evaluator | Frozen checks and the exact evaluator identity used to interpret outcomes. |
| Signed receipts | Check outcomes, source class, run, observation time and exact subject, profile and evaluator bindings. |
| Relying policy | Trusted keys and roles, allowed evidence sources, freshness, revocation, coverage and qualification thresholds. |
| Assessment and currency result | Per-check results, failures, unknowns, policy-relative decision and whether later changes or incidents require reassessment. |

The verifier checks exact bindings and signatures, admits evidence under the relying policy, selects a whole run, keeps missing checks in the population and applies critical gates. A high average cannot erase a critical failure. Currency checks make configuration changes, expiry and applicable incidents visible.

For example, consider a hypothetical code agent assessed for reading a repository and preparing a patch. Evidence for that scope cannot silently become evidence for deploying the patch. Changing its model, tools or manifest changes the bound subject. The assessment itself grants no runtime permission.

## What implementers can do today

The repository provides a dependency-free Node.js reference, a written specification, traced requirements, signed receipts, policy templates and a language-neutral implementation contract. Its 799 public assessment vectors cover nine operations. The included JavaScript and Python implementations are same-team work; they are not independent adoption.

From a checkout, run the reference against the public vectors:

```sh
node scripts/run-vectors.mjs --impl "node interop/impl-contract/js-reference.mjs"
```

This tests protocol behavior on synthetic public inputs, without a provider account or model call. It does not evaluate a commercial agent. A new implementer can follow `docs/IMPLEMENTERS-GUIDE.md`, implement the stdin/stdout contract in another language and publish the exact source revision and conformance report, including unsupported requirements and failures.

## What the protocol still needs to earn

Independent implementation and review; real relying-party pilots; protected evaluation and calibration; independently measured capture; and governance accepted by parties beyond this project. A digest is not a data-rights determination, and a signed assertion is not proof of truthful execution, identity, authority, general safety or legal compliance. Adoption should be measured by reproducible use and contested evidence, not badges.

Read the [specification](SPECIFICATION.md), [conformance report contract](CONFORMANCE.md), [implementer guide](IMPLEMENTERS-GUIDE.md), [scoring rules](SCORING.md), [threat model](THREAT-MODEL.md) and [partial declaration imports](DECLARATION-IMPORTS.md) for the precise contracts and limits.
