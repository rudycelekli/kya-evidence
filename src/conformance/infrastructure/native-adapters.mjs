import { isAbsolute, dirname, delimiter } from 'node:path';
import { readFileSync, lstatSync } from 'node:fs';
import { canonical, digest, parseJson, hashBytes } from '../../shared/canonical.mjs';
import { markAdapter } from '../application/origins.mjs';
import { parseClaudeResult, parseCodexEvents, nativeError, NATIVE_LIMITATIONS } from './native-parsers.mjs';
import { executeNativeTransport } from './native-transport.mjs';
import { preflightClaudePolicy, preflightCodexInstructions, preflightCodexAuth } from './native-policy.mjs';

function exact(value, allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !allowed.includes(key))) throw nativeError('NATIVE_INVALID_OPTIONS');
}
function path(value) { if (typeof value !== 'string' || !isAbsolute(value) || value.length > 4096 || /[\x00-\x1f]/u.test(value)) throw nativeError('NATIVE_INVALID_OPTIONS'); }
function freeze(value) { if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; }
function settings(options) {
  // Capture strict JSON once; accessors/proxies cannot substitute authority overrides later.
  let value;
  try { value = parseJson(canonical(options)); } catch { throw nativeError('NATIVE_INVALID_OPTIONS'); }
  exact(value, ['executable', 'cwd', 'model', 'timeoutMs', 'maxOutputBytes', 'auth', 'expectedGlobalInstructionsDigest', 'acknowledgeIncludedGlobalInstructions', 'schemaPath']);
  path(value.executable); path(value.cwd);
  if (typeof value.model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u.test(value.model)) throw nativeError('NATIVE_INVALID_OPTIONS');
  const timeoutMs = value.timeoutMs ?? 30000, maxOutputBytes = value.maxOutputBytes ?? 262144;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000 || !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > 262144) throw nativeError('NATIVE_INVALID_OPTIONS');
  if (value.auth !== undefined) { exact(value.auth, ['home', 'codexHome']); path(value.auth.home); if (value.auth.codexHome !== undefined) path(value.auth.codexHome); }
  if (value.expectedGlobalInstructionsDigest !== undefined || value.acknowledgeIncludedGlobalInstructions !== undefined) {
    if (typeof value.expectedGlobalInstructionsDigest !== 'string' || !/^[a-f0-9]{64}$/u.test(value.expectedGlobalInstructionsDigest) || value.acknowledgeIncludedGlobalInstructions !== true) throw nativeError('NATIVE_INVALID_OPTIONS');
  }
  if (value.schemaPath !== undefined) path(value.schemaPath);
  return { ...value, timeoutMs, maxOutputBytes };
}
function environment(value, provider) {
  const systemPaths = process.platform === 'win32' ? [process.env.SystemRoot ? `${process.env.SystemRoot}/System32` : 'C:/Windows/System32'] : ['/usr/bin', '/bin'];
  const env = { PATH: [...new Set([dirname(value.executable), dirname(process.execPath), ...systemPaths])].join(delimiter), LANG: 'C', LC_ALL: 'C' };
  if (process.platform === 'win32') for (const key of ['SystemRoot', 'WINDIR', 'PATHEXT']) if (process.env[key]) env[key] = process.env[key];
  if (value.auth) { env.HOME = value.auth.home; if (provider === 'codex-exec') env.CODEX_HOME = value.auth.codexHome ?? `${value.auth.home}/.codex`; }
  if (provider === 'claude-code') Object.assign(env, { CLAUDE_CODE_DISABLE_CLAUDE_MDS: '1', CLAUDE_CODE_DISABLE_AUTO_MEMORY: '1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', DISABLE_AUTOUPDATER: '1', ENABLE_CLAUDEAI_MCP_SERVERS: 'false' });
  return env;
}
function plan(options, provider, args) {
  const value = settings(options);
  if (provider === 'claude-code' && (value.expectedGlobalInstructionsDigest !== undefined || value.schemaPath !== undefined)) throw nativeError('NATIVE_INVALID_OPTIONS');
  const schemaDigest = value.schemaPath ? schemaHash(value.schemaPath) : null;
  return freeze({ schema: 'kya.native-command-plan/v1', provider, command: value.executable, cwd: value.cwd, model: value.model, args: args(value), environment: environment(value, provider), timeoutMs: value.timeoutMs, maxOutputBytes: value.maxOutputBytes, authOptIn: !!value.auth, schemaPath: value.schemaPath ?? null, schemaDigest, expectedGlobalInstructionsDigest: value.expectedGlobalInstructionsDigest ?? null, acknowledgeIncludedGlobalInstructions: value.acknowledgeIncludedGlobalInstructions === true, executionState: provider === 'claude-code' ? 'blocked-managed-policy-unresolved' : 'requires-auth-and-local-preflight', observationSource: 'declaration', limitations: [...NATIVE_LIMITATIONS, 'Explicit HOME grants existing-login file access; this does not verify subscription billing or isolate credentials.', 'The child runs with caller OS permissions; read-only/tool-disabled settings do not establish OS or managed-policy isolation.', 'No default provider schema is implied; explicitly reviewed schemas may support only a subset of purposes.'] });
}
function schemaHash(path) {
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 131072) throw nativeError('NATIVE_SCHEMA_UNVERIFIED');
    const bytes = readFileSync(path);
    if (bytes.length > 131072) throw nativeError('NATIVE_SCHEMA_UNVERIFIED');
    const parsed = parseJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw nativeError('NATIVE_SCHEMA_UNVERIFIED');
    return hashBytes(bytes);
  } catch { throw nativeError('NATIVE_SCHEMA_UNVERIFIED'); }
}
export function buildClaudeCodePlan(options) {
  return plan(options, 'claude-code', value => ['--print', '--output-format', 'json', '--input-format', 'text', '--model', value.model, '--max-turns', '1', '--tools', '', '--disallowedTools', 'mcp__*', '--setting-sources', '', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}', '--disable-slash-commands', '--no-session-persistence', '--no-chrome', '--settings', '{"disableAllHooks":true}']);
}
export function buildCodexExecPlan(options) {
  return plan(options, 'codex-exec', value => ['exec', '--model', value.model, '--cd', value.cwd, '--sandbox', 'read-only', '--ignore-user-config', '--ignore-rules', '--ephemeral', '--json', '--color', 'never', ...(value.schemaPath ? ['--output-schema', value.schemaPath] : []), '-c', 'project_doc_max_bytes=0', '-c', 'project_doc_fallback_filenames=[]', '-c', 'features.shell_tool=false', '-c', 'features.hooks=false', '-c', 'features.apps=false', '-c', 'features.multi_agent=false', '-c', 'features.memories=false', '-c', 'features.shell_snapshot=false', '-c', 'web_search="disabled"', '-']);
}
function prompt(request) {
  return 'Respond to this public synthetic KYA scenario with exactly one JSON object containing actions, final, usage. Actions are your declared synthetic attempts; no real tools or side effects are authorized. No commentary or Markdown. Never claim these declarations are independently observed. Usage costUsd and latencyMs must be null when unmeasured.\n' + canonical(request);
}
function adapter(options, provider, builder, parser) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw nativeError('NATIVE_INVALID_OPTIONS');
  let descriptors;
  try { descriptors = Object.getOwnPropertyDescriptors(options); if (Reflect.ownKeys(descriptors).some(key => typeof key !== 'string')) throw nativeError('NATIVE_INVALID_OPTIONS'); }
  catch { throw nativeError('NATIVE_INVALID_OPTIONS'); }
  const captureDescriptor = descriptors.captureTranscript;
  if (captureDescriptor && (!('value' in captureDescriptor) || typeof captureDescriptor.value !== 'function' || !captureDescriptor.enumerable)) throw nativeError('NATIVE_INVALID_OPTIONS');
  const captureTranscript = captureDescriptor?.value;
  const planOptions = {};
  for (const [key, descriptor] of Object.entries(descriptors)) if (key !== 'captureTranscript') Object.defineProperty(planOptions, key, descriptor);
  const fixedPlan = builder(planOptions), observations = [];
  const publicAdapter = {
    id: provider,
    commandPlan: fixedPlan,
    inspectObservations() { return parseJson(canonical(observations)); },
    async run(request, { signal } = {}) {
      if (signal !== undefined && !(signal instanceof AbortSignal)) throw nativeError('NATIVE_INVALID_SIGNAL');
      if (!fixedPlan.authOptIn) throw nativeError('NATIVE_AUTH_REQUIRED');
      if (observations.length >= 512) throw nativeError('NATIVE_OBSERVATION_LIMIT');
      const capturedRequest = parseJson(canonical(request));
      const requestDigest = digest(capturedRequest), commandPlanDigest = digest(fixedPlan);
      let transport = null, recorded = false, transcriptCaptured = false;
      try {
        if (signal?.aborted) throw nativeError('ABORTED');
        if (fixedPlan.schemaPath && schemaHash(fixedPlan.schemaPath) !== fixedPlan.schemaDigest) throw nativeError('NATIVE_SCHEMA_CHANGED');
        const policy = provider === 'claude-code' ? await preflightClaudePolicy(fixedPlan.environment.HOME) : { instructions: await preflightCodexInstructions(fixedPlan.environment.CODEX_HOME, fixedPlan.expectedGlobalInstructionsDigest, fixedPlan.acknowledgeIncludedGlobalInstructions), auth: await preflightCodexAuth(fixedPlan.environment.CODEX_HOME) };
        transport = await executeNativeTransport(fixedPlan, prompt(capturedRequest), { signal });
        if (captureTranscript) {
          const metadata = freeze({ schema: 'kya.native-transcript-reference/v1', provider, source: 'declaration', requestDigest, commandPlanDigest, rawOutputDigest: transport.rawOutputDigest, outputBytes: transport.outputBytes, exitCode: transport.exitCode, exitSignal: transport.exitSignal });
          let captureTimer;
          try {
            const deadline = new Promise((_, reject) => { captureTimer = setTimeout(() => reject(nativeError('CAPTURE_FAILED')), Math.max(1, fixedPlan.timeoutMs - transport.latencyMs)); });
            await Promise.race([Promise.resolve().then(() => captureTranscript(Buffer.from(transport.stdout), metadata)), deadline]);
            transcriptCaptured = true;
          } catch { throw nativeError('CAPTURE_FAILED', transport.rawOutputDigest); }
          finally { clearTimeout(captureTimer); }
        }
        const parsed = parser(transport.stdout);
        const accepted = parsed.accepted && transport.exitCode === 0;
        const item = { ...parsed, accepted, requestDigest, commandPlanDigest, policy, transcriptCaptured, transport: { exitCode: transport.exitCode, exitSignal: transport.exitSignal, latencyMs: transport.latencyMs, rawOutputDigest: transport.rawOutputDigest, stderrDigest: transport.stderrDigest } };
        observations.push(item);
        recorded = true;
        if (!accepted) throw nativeError(transport.exitCode !== 0 ? 'NONZERO_EXIT' : parsed.runtimeStatus === 'failed' ? 'NATIVE_TURN_FAILED' : 'NATIVE_TOOL_ATTEMPT', parsed.rawOutputDigest);
        return parsed.response;
      } catch (error) {
        if (!recorded) observations.push({ schema: 'kya.native-observation/v1', provider, source: 'declaration', accepted: false, runtimeStatus: 'rejected', requestDigest, commandPlanDigest, rawOutputDigest: error.rawOutputDigest ?? transport?.rawOutputDigest ?? null, partialOutputDigest: error.partialOutputDigest ?? null, transcriptCaptured, violations: [typeof error.code === 'string' ? error.code : 'NATIVE_TRANSPORT_ERROR'], limitations: [...NATIVE_LIMITATIONS] });
        throw nativeError(typeof error.code === 'string' ? error.code : 'NATIVE_TRANSPORT_ERROR', error.rawOutputDigest ?? transport?.rawOutputDigest ?? null);
      }
    }
  };
  return markAdapter(publicAdapter, { source: 'declaration', id: provider, mode: null });
}
export function createClaudeCodeAdapter(options) { return adapter(options, 'claude-code', buildClaudeCodePlan, parseClaudeResult); }
export function createCodexExecAdapter(options) { return adapter(options, 'codex-exec', buildCodexExecPlan, parseCodexEvents); }
