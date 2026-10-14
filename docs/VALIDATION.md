# Validation and evidence boundaries

The alpha is a working local reference implementation. Its tests establish defined behavior on published cases. Standards adoption, external certification and predictive safety require additional evidence.

| Layer | Reproducible evidence | Boundary |
| :--- | :--- | :--- |
| Record integrity | Strict JSON, golden bytes, SHA-256 and domain-separated Ed25519 vectors | A valid signature does not establish truthful execution or authenticated identity |
| Assessment policy | Adversarial trust, revocation, freshness, denominator, complete-run and critical-gate cases; six weakened gates detected | Weights and thresholds are experimental relying-party choices |
| Native transport | Bounded child fixtures, failure/tool-event oracles, authority preflights, byte limits, concurrent and reentrant request controls | Fixture events do not measure commercial products or independently observe their side effects |
| Python bytes | A separately written implementation in this project team reconstructs all six published vectors; supported numeric subsets agree | General noninteger double portability is incomplete; a missing crypto backend remains partial |
| Research universes | Frozen inputs, source-engine hashes, replay, hypothesis forks and correction lineage | Cross-engine snapshots require their archived implementation; fork integrity does not establish causation |
| Local distribution | Immutable Git blobs, fixed archive metadata, full inventory hashes, strict tar verification and offline install | A local archive is unpublished; the build receipt is unsigned |
| Presentation | Offline/no-network source checks, safe text rendering, accessible SVG metadata and reduced-motion rules | A browser visual pass has not been performed |
| Diagnostic dossier | Selected-original digest/request/outcome replay, duplicate quarantine, fixed populations, safe rendering and trusted-input recomputation | Passing responses do not verify hidden effects, complete history or causal explanations |
| Embedded controls | Sixteen frozen fixture cases, authored expectations, full-case replay and actual weakened-gate experiments | A public catalog is susceptible to memorization and does not score commercial agents |
| Typed SDK | Strict DOM/Node TypeScript consumers, readonly inputs and negative authority/source/JSON controls | Types do not replace runtime validation or confer execution authority |

## Run the checks

Node 22 or newer is required. Python 3.9 or newer is optional for portability checks; the suite visibly skips those cases if Python is unavailable. No model call runs on import or as part of these tests.

```sh
node scripts/check.mjs
node --test --test-reporter=tap test/*.test.mjs
node scripts/mutation-check.mjs
node bin/kya.mjs bench --out .kya/controls
node bin/kya.mjs bench-verify .kya/controls/benchmark-run.json
python3 interop/python/test_portability.py -v
python3 interop/python/kya_portability.py check-vectors evidence/golden-vectors.json --no-crypto
```

The Python checker can exit zero with `status: "partial"` when signature verification is unavailable. Read the status and verification fields; zero exit alone is not a signature pass. See [interoperability scope](INTEROPERABILITY.md).

Alpha3's [diagnostic contract](DOSSIERS.md) and [benchmark catalog](BENCHMARKS.md) explain their exact observation boundaries. Standalone report checks are deliberately weaker than replay from trusted original inputs. The source-grounded [evaluation study](research/2026-10-14-evaluation-blueprint.md) records the inspected revisions and the measured repair controls without importing upstream capability claims.

From a clean committed Git checkout, build and verify the exact local artifact:

```sh
node scripts/pack.mjs
node scripts/verify-release.mjs
```

Repeat the build with the same source revision and supported runtime; compare the archive SHA-256 and every inventory entry. Preserve earlier versions and their receipts separately. The unpacked package contains tests, vectors and the Python checker. The packer requires Git; runtime, tests and vector checks work after unpacking.

## Measured runtime status

A local Codex subscription trial attempted two public synthetic output cases. The provider rejected the configured model; zero final responses were accepted. Two complete raw stdout originals were retained privately with readback hashes. Declaration-only evidence earned zero scored coverage. Offline reanalysis and exact historical-engine replay preserve this failure instead of replacing it with a successful fixture.

Claude has an unresolved effective managed-policy gate and remains blocked by its native factory. Other bots and agent harnesses remain unmeasured until a specific version, authorized execution lane and instrumentation contract are reviewed. [Adapter documentation](ADAPTERS.md) records the implemented interfaces and open gates.

## Promotion discipline

Freeze case identities, evaluator and baseline before editing a candidate. Include failed and unexecuted checks. Run identical cases against baseline and candidate, then have a separate project lane challenge the result. Independent work inside this team is distinct from an external assessor. Record `ACCEPT`, `REJECT` or `INCONCLUSIVE`, source hashes, runtime versions, latency and cost; unknown cost stays null. Preserve the old implementation and rollback.

Continuous improvement is opt-in. Installing this package does not create a scheduler or access login state. An operator must register and verify their own bounded job. Publication, account actions and separately billed model calls require applicable human authorization.
