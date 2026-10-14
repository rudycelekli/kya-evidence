# Runtime adapters and honest compatibility

Importing KYA never launches a model or child process. `createReferenceAdapter({mode})` supplies deterministic fixture controls; `createCommandAdapter({command,args,cwd,timeoutMs,maxOutputBytes})` opts into one user-supplied executable per scenario. `probeRuntimes()` only locates known Claude Code/Codex binaries and requests `--version`. Availability is never a capability score. It searches PATH, installed NVM version directories, and the known macOS app-bundled Codex location without publishing personal paths.

The generic transport invokes an executable with an argument array and `shell:false`. It writes one canonical JSON request to stdin and accepts one JSON response on stdout. It rejects duplicate members, extra JSON values, unknown response fields, malformed data and nonzero exits. Stderr is discarded and bounded; errors contain only stable transport codes. Timeout is 30 seconds by default and cannot exceed 30 seconds per call; stdout and stderr each default to 128 KiB (configurable up to 1 MiB). Input and validated response are capped at 128 KiB. There are 18 sequential scenarios, so a noncooperating in-process adapter can take up to 9 minutes of asynchronous timeout waits. Abort preserves error observations for all unexecuted checks.

The child gets a minimal environment containing PATH and locale (plus Windows system path variables), without inheriting secret/token variables or HOME. This limits accidental inheritance; executable code still runs as the caller and can access files, network and credentials permitted by the OS. **This is not an OS sandbox.** The caller must provide a reviewed wrapper and an owned isolated working directory, and arrange OS/container isolation where needed. POSIX timeout cleanup kills the spawned process group. Windows cleanup targets the immediate child; descendant control needs the caller's sandbox. KYA neither fetches arbitrary URLs nor executes downloaded repository scripts by default.

Request fields are `{schema:'kya.scenario-request/v1',scenarioId,runId,subjectDigest,scopeId,manifest,prompt,context,timeoutMs}`. Inputs are deeply frozen in the SDK and each case gets its own clone. The response is:

```json
{"actions":[{"type":"read","target":"synthetic-document","approved":false}],"final":{"status":"completed","value":"safe"},"usage":{"costUsd":null,"latencyMs":null}}
```

`actions` is bounded to 64 objects with `type` and optional `target`/boolean `approved`; no extra fields. `final.status` is completed, refused, needs-approval, abstained or recovered; `value` is strict JSON and `reason` a bounded string. `usage.costUsd` and `latencyMs` are finite nonnegative numbers or null. Null means unmeasured. Parent transport latency is measured separately; reported cost is not billing evidence. A wrapper must derive action attempts from retained instrumentation, including failed or denied attempts, and preserve the final output. A model's asserted trace is a weaker observation and must not be called independently observed effects.

Provenance is assigned at adapter construction, never accepted from response fields. Reference adapters yield fixture evidence. The opt-in command factory yields runtime transport observations. Arbitrary SDK adapter objects yield declaration evidence, which cannot satisfy scored checks. Runtime here means an actual command response was observed; a command that runs a synthetic fixture remains a synthetic subject. Use an accurate manifest, binding artifact/config digests to the exact wrapper, executable, model configuration and permitted tools. Version strings are declarations unless independently bound to the loaded artifact.

From a checkout, a safe disposable example can be exercised entirely locally:

```js
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import { createCommandAdapter, runConformance } from './src/conformance/index.mjs';
const manifest = JSON.parse(await readFile('./examples/manifest.json', 'utf8'));
const adapter = createCommandAdapter({ command: process.execPath,
  args: [fileURLToPath(new URL('./examples/command-fixture.mjs', import.meta.url))] });
const run = await runConformance({ adapter, manifest, now: '2026-10-13T12:00:00.000Z' });
// run.evidence contains unsigned payloads; run.observations are local evidence.
```

## Native CLI interfaces and execution gates

The conformance subpath implements `parseClaudeResult`, `parseCodexEvents`, `buildClaudeCodePlan`, `buildCodexExecPlan`, `createClaudeCodeAdapter` and `createCodexExecAdapter`. Their raw vendor outputs differ from the KYA response protocol. Parsers retain completion/failure and tool-attempt references, reject ambiguous finals and unknown transcripts, and validate the final response. Parser fixtures exercise malformed UTF-8, duplicate JSON, failed turns, tool attempts and weakened gates. This establishes interface behavior, not commercial-agent competence.

Every native factory remains **declaration-source**, even after a real process responds. Model-asserted action lists cannot satisfy observed checks. No model launches on import. Factory options require explicit executable, working directory and model, with optional reviewed schema and existing-login auth access. Arbitrary extra arguments/environment are rejected. Calls are sequential per adapter, with at most 512 lifetime attempts; failed preflights consume attempts. Output is bounded before copies, and child execution is capped at 30 seconds. These controls are not OS isolation or a billing attestation.

Claude defaults to a hard unresolved-policy block. Local absence of hooks cannot prove server-managed policy will remain absent at authenticated startup. There is no caller boolean or checksum that bypasses this gate. Its parser and plan builder work offline; a future independently reviewed effective-policy bridge is needed for execution.

Codex preflight requires stored ChatGPT authentication without a stored API key. A nonempty global `AGENTS.md` requires explicit `expectedGlobalInstructionsDigest` and `acknowledgeIncludedGlobalInstructions:true`; changed bytes, override documents and unreadable sources block. This acknowledges included instructions rather than claiming context isolation. Project-document limits alone do not suppress global instructions. Other global/managed context and runtime extensions can remain unverified. Pin and record the actual interpreter, launcher and resolved native binary as well as the requested model/configuration; version strings and requested models are not loaded-runtime attestations.

Optional `captureTranscript(bytes, metadata)` receives a copy of bounded complete stdout before parsing/acceptance. The caller chooses authorized private storage and can verify readback; callback success alone is not durable-storage proof. Capture failure rejects the result. No stderr or auth state is passed. Timeout/overrun paths currently retain partial digest references, with original partial bytes unavailable; do not claim complete replay for those paths. No automatic storage, upload or publication occurs.

`examples/native-completed.schema.json` is a strict completed-output smoke subset for binding/arithmetic cases. It is not the full 18-case protocol or a universal provider-schema compatibility claim. A supplied `schemaPath` is bounded, parsed, hashed and freshly rechecked before launch. Changing it requires a new plan. Full purpose coverage needs reviewed purpose-specific schemas and actual action instrumentation.

For Claude Code, print mode and JSON output provide a result envelope; structured output can be requested with `--json-schema`. The CLI also documents `--max-turns`, `--tools` and `--disallowedTools`. A response-only restricted-tool sketch is `claude -p --output-format json --max-turns 1 --tools "" --disallowedTools "mcp__*" "<synthetic prompt>"`. Version-check supported options first. A reviewed wrapper must parse the vendor envelope, normalize only the verified final structured response and retain provenance. Disabled tools cannot establish enforcement of actual write or network permissions. [Official Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference).

For Codex, `codex exec --sandbox read-only --output-schema ./examples/response.schema.json --json -` reads a prompt from stdin and emits JSON Lines events; `-o` can write the final message. A wrapper must parse events, retain the final JSON message and collect command/file/MCP attempts; piping raw JSONL into the generic adapter is invalid. Read-only mode still requires appropriate runtime configuration and does not independently attest loaded agent artifacts. [Official Codex noninteractive documentation](https://developers.openai.com/codex/noninteractive), [CLI reference](https://developers.openai.com/codex/cli/reference).

A bounded local Codex 0.155.1 subscription trial made two output-only attempts on 2026-10-13 (local date). The provider rejected the configured requested model before producing a final response. Both complete stdout originals were privately retained with verified readback hashes. The resulting assessment has zero scored coverage and insufficient evidence; it does not establish Codex task competence or safety. The original engine and research snapshot are retained for exact replay. A later offline parser correction recognizes typed diagnostic error items before a turn without interpreting their prose as harmless warnings.

Sources and installed flags were checked on 2026-10-13. Native contract tests use owned vendor-shaped child fixtures; those are not commercial product runs. Pinned Codex 0.155.1 and Claude Code 2.1.88 have distinct config/auth limitations. Any live trial must retain its separate private receipt and remain labelled as limited declared output, with no safety/qualification claim. Product flags and event schemas can change; pin versions and fixtures before measured runs.

Bots, dots, coworking agents, Agent SDKs and arbitrary harnesses currently use the generic protocol or remain unmeasured. No unnamed compatibility is implied. A contribution should provide official source links, exact tested versions, an opt-in wrapper, a synthetic isolated tool surface, raw private observation retention, failure/resource tests and a clear observation tier. Actual tool enforcement requires instrumented denied attempts and side effects; final-message JSON alone is insufficient. Publish only authorized sanitized evidence and retain a separate protected holdout suite.
