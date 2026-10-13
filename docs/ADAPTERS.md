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

## Official product recipe status

Claude Code and Codex have documented noninteractive interfaces, but their raw outputs are **not** the KYA response protocol. Recipes below are documentation-verified starting points, not implemented product integrations or measured capability runs. Model calls require the user's execution, authentication and budget authority; none run automatically. Existing account configuration may load hooks/plugins; inspect those in an isolated owned lane before authorizing a run.

For Claude Code, print mode and JSON output provide a result envelope; structured output can be requested with `--json-schema`. The CLI also documents `--max-turns`, `--tools` and `--disallowedTools`. A response-only restricted-tool sketch is `claude -p --output-format json --max-turns 1 --tools "" --disallowedTools "mcp__*" "<synthetic prompt>"`. Version-check supported options first. A reviewed wrapper must parse the vendor envelope, normalize only the verified final structured response and retain provenance. Disabled tools cannot establish enforcement of actual write or network permissions. [Official Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference).

For Codex, `codex exec --sandbox read-only --output-schema ./examples/response.schema.json --json -` reads a prompt from stdin and emits JSON Lines events; `-o` can write the final message. A wrapper must parse events, retain the final JSON message and collect command/file/MCP attempts; piping raw JSONL into the generic adapter is invalid. Read-only mode still requires appropriate runtime configuration and does not independently attest loaded agent artifacts. [Official Codex noninteractive documentation](https://developers.openai.com/codex/noninteractive), [CLI reference](https://developers.openai.com/codex/cli/reference).

Sources were checked on 2026-10-13. Product flags and event schemas can change; pin versions and fixtures before measured runs. No product recipe was exercised as a model run in this build. Version-only installed-runtime observations are stored privately by the build, never turned into quality scores.

Bots, dots, coworking agents, Agent SDKs and arbitrary harnesses currently use the generic protocol or remain unmeasured. No unnamed compatibility is implied. A contribution should provide official source links, exact tested versions, an opt-in wrapper, a synthetic isolated tool surface, raw private observation retention, failure/resource tests and a clear observation tier. Actual tool enforcement requires instrumented denied attempts and side effects; final-message JSON alone is insufficient. Publish only authorized sanitized evidence and retain a separate protected holdout suite.
