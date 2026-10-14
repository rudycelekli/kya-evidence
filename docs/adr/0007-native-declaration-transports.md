# ADR-0007: Native CLI output remains declaration evidence

**Status**: Implemented; independent review pending
**Date**: 2026-10-13
**Related**: ADR-0002, ADR-0003, ADR-0004, ADR-0006

## Context

Claude Code and Codex CLI expose structured headless outputs, but an agent's asserted action list is not independent observation of tool effects. Vendor completion/error events can contradict a final message. Native tools, hooks, managed policy and global instruction files can also alter effective runtime configuration. A launch plan that disables project configuration does not establish OS or credential isolation.

## Decision

Add explicit opt-in command-plan builders, strict vendor parsers and native factories under the conformance subpath. Parse Claude single-result JSON or bounded event arrays and Codex exec JSONL. Preserve completed/failed events and byte-digest references without putting raw provider text in errors. Reject multiple final outputs, unsupported events, duplicate JSON, invalid UTF-8, resource overruns, failed turns and observed native tool attempts. Failed turns dominate polished final messages.

Native factories assign declaration provenance, including when a real process was observed. Their asserted actions cannot qualify the core assessment. Local parsed observations expose runtime status, sanitized event/tool references and raw-output hashes for authorized private retention; a hash does not prove original transcript possession or truthful execution. Nonzero process exit never qualifies.

An optional captureTranscript callback receives a copy of bounded original stdout bytes plus sanitized digest metadata before parsing/acceptance, including malformed complete output. It performs no default storage or upload, receives no stderr or authentication state, and must complete successfully before acceptance. CAPTURE_FAILED rejects the result. Timeout/overrun partial digests are labelled separately; complete original retention is unknown on those paths. Callback success is a caller-storage declaration, not independent proof of durable possession.

Codex provider schemas are caller-selected local artifacts, validated as bounded strict JSON, hashed in the immutable plan and freshly rechecked before launch. No default schema or compatibility across all 18 purposes is claimed. The requested model string is a configuration pin, not attestation of the resolved serving model. Neither schemas nor prompts forward evaluator expected answers.

Plans require exact executable, working directory and model. Unknown options, arbitrary extra arguments/environment and CLI-option injection are rejected. Transport uses shell=false, minimal environment, capped output and ≤30-second timeout with POSIX process-group cleanup. Auth is an explicit HOME/CODEX_HOME grant for existing login state; no provider API tokens are inherited. This is not OS isolation, subscription/billing verification, or proof that on-disk credentials use a particular payment route.

Claude uses tool/MCP/skills/session/chrome controls and fixed hook/traffic/update environment settings. Managed hooks can override CLI disableAllHooks. Local files, MDM policy and cached server settings do not prove effective startup policy: the current Claude factory remains blocked when server-managed policy is unresolved. There is no caller boolean/hash override. Its offline plan/parser are usable; operational native integration requires a separately reviewed isolated executor or effective-policy bridge.

Codex uses read-only, ignore-user-config/rules, ephemeral output, disabled project documents/shell/web search and disabled hooks/apps/multi-agent/memory/shell-snapshot features. A nonempty global instruction file under authorized CODEX_HOME is a preflight failure because project_doc_max_bytes=0 does not suppress that source. Deliberate inclusion requires both expectedGlobalInstructionsDigest and acknowledgeIncludedGlobalInstructions=true, verified against fresh exact file bytes and bound in the plan; additional active global documents still fail. This tests a known actual configuration rather than claiming an empty context. Stored auth metadata must indicate ChatGPT mode without a provider API key, but this local snapshot does not attest live entitlement or billing. Managed influences and startup races remain limitations. No credential-copy or temporary HOME workaround is performed.

## Alternatives

Treating every vendor JSON response as runtime-assured behavioral evidence would launder self-reports. Blindly accepting the final JSON after a failed turn or tool event would suppress contradictory observations. Bypassing permissions, inheriting all environment variables, using shell strings or an unverified "policy resolved" flag would widen execution authority without evidence. All were rejected.

## Consequences

Compatibility is version-specific and conservative. Unsupported transcripts and policy uncertainty produce retained failures/unproven evidence, not product quality scores. Importing factories never starts a process. Explicit execution still needs the caller's authorized isolated lane and account/budget authority. Windows immediate-child cleanup does not control descendants without a caller-provided sandbox.

## Validation

Synthetic transcript tests cover success/failure, failed-event dominance, hidden tool attempts, multiple finals, strict JSON/UTF-8, limits and source/type forgery. Independent controls detect actual parser-source mutations that disable failure/tool gates. Disposable Node children test bounded transport and nonzero failed-transcript preservation without invoking models. Plans are tested against authority-override injection and secret-environment inheritance. Global instruction/auth/schema preflights are tested with private disposable files. No live model/provider calls were performed by this implementation lane.

Flag formats were checked against locally installed CLI help and the [Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference) and [Codex CLI reference](https://developers.openai.com/codex/cli/reference). Current live capability remains subject to separate authorized measured runs and independent review.
