import { canonical, hashBytes, parseJson, digest } from '../../shared/canonical.mjs';
import { validateResponse } from '../domain/protocol.mjs';

const LIMIT = 262144;
const MAX_EVENTS = 512;
const MAX_LINE = 131072;
const TOOL_TYPES = new Set(['command_execution', 'file_change', 'mcp_tool_call', 'web_search', 'tool_use', 'server_tool_use', 'tool_result']);
export const NATIVE_LIMITATIONS = Object.freeze([
  'Agent-reported actions are declarations, not independently observed tool effects.',
  'Vendor events and completion markers are runtime reports; they do not establish truthful execution.',
  'Version-specific parser contract; unsupported or ambiguous transcripts are rejected.',
  'Raw output hashes refer to private transcript bytes; original bytes must be retained separately.'
]);

export function nativeError(code, rawOutputDigest = null) {
  return Object.assign(new Error(`Native adapter rejected output: ${code}`), { code, rawOutputDigest });
}
function decode(input) {
  if (typeof input !== 'string' && (!(input instanceof Uint8Array) || !ArrayBuffer.isView(input))) throw nativeError('NATIVE_INVALID_INPUT');
  let bytes;
  if (typeof input === 'string') {
    if (input.length > LIMIT || Buffer.byteLength(input,'utf8') > LIMIT) throw nativeError('OUTPUT_LIMIT');
    if (!input.isWellFormed()) throw nativeError('NATIVE_INVALID_UTF8');
    bytes=Buffer.from(input);
  } else {
    const proto=Object.getPrototypeOf(Uint8Array.prototype);
    const property=name=>Object.getOwnPropertyDescriptor(proto,name).get.call(input);
    const length=property('byteLength');
    if (length > LIMIT) throw nativeError('OUTPUT_LIMIT');
    bytes=Buffer.from(new Uint8Array(property('buffer'),property('byteOffset'),length));
  }
  const rawOutputDigest = hashBytes(bytes);
  if (bytes.length > LIMIT) throw nativeError('OUTPUT_LIMIT', rawOutputDigest);
  try { return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes), rawOutputDigest }; }
  catch { throw nativeError('NATIVE_INVALID_UTF8', rawOutputDigest); }
}
function json(text, rawOutputDigest) {
  try { return parseJson(text); } catch { throw nativeError('NATIVE_MALFORMED_JSON', rawOutputDigest); }
}
function object(value, rawOutputDigest) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw nativeError('NATIVE_INVALID_EVENT', rawOutputDigest);
  return value;
}
function assertedResponse(value, rawOutputDigest) {
  try { return validateResponse(value); } catch { throw nativeError('NATIVE_INVALID_RESPONSE', rawOutputDigest); }
}
function scanTools(value, attempts) {
  if (!value || typeof value !== 'object') return;
  if (TOOL_TYPES.has(value.type)) attempts.push({ kind: value.type, artifactDigest: digest(value) });
  if (Array.isArray(value)) for (const child of value) scanTools(child, attempts);
  else for (const child of Object.values(value)) scanTools(child, attempts);
}
function observation(provider, rawOutputDigest, status, events, attempts, response, violations) {
  const accepted = status === 'completed' && violations.length === 0;
  return {
    schema: 'kya.native-observation/v1', provider, source: 'declaration', accepted,
    runtimeStatus: status, rawOutputDigest, events, toolAttempts: attempts,
    response: accepted ? response : null,
    responseDigest: response ? digest(response) : null,
    violations, limitations: [...NATIVE_LIMITATIONS]
  };
}

/** Parse single-result Claude JSON, or a bounded JSON array carrying one result. */
export function parseClaudeResult(input) {
  const { text, rawOutputDigest } = decode(input);
  const parsed = json(text, rawOutputDigest);
  const items = Array.isArray(parsed) ? parsed : [parsed];
  if (items.length === 0 || items.length > MAX_EVENTS) throw nativeError('NATIVE_EVENT_LIMIT', rawOutputDigest);
  const events = [], attempts = [];
  let terminal = null;
  for (const raw of items) {
    const event = object(raw, rawOutputDigest);
    if (terminal) throw nativeError('NATIVE_AMBIGUOUS_COMPLETION', rawOutputDigest);
    if (!['system', 'assistant', 'user', 'result'].includes(event.type)) throw nativeError('NATIVE_UNKNOWN_EVENT', rawOutputDigest);
    events.push({ type: event.type, artifactDigest: digest(event) });
    scanTools(event, attempts);
    if (event.type === 'result') terminal = event;
  }
  if (!terminal) throw nativeError('NATIVE_MISSING_COMPLETION', rawOutputDigest);
  if (typeof terminal.is_error !== 'boolean' || typeof terminal.subtype !== 'string') throw nativeError('NATIVE_INVALID_COMPLETION', rawOutputDigest);
  if ((terminal.subtype === 'success') === terminal.is_error) throw nativeError('NATIVE_INVALID_COMPLETION', rawOutputDigest);
  if (terminal.permission_denials !== undefined) {
    if (!Array.isArray(terminal.permission_denials) || terminal.permission_denials.length > 64) throw nativeError('NATIVE_INVALID_EVENT', rawOutputDigest);
    for (const denied of terminal.permission_denials) attempts.push({ kind: 'permission-denial', artifactDigest: digest(denied) });
  }
  if (terminal.is_error) return observation('claude-code', rawOutputDigest, 'failed', events, attempts, null, ['runtime-failed', ...(attempts.length ? ['native-tool-attempt'] : [])]);
  const hasStructured = Object.hasOwn(terminal, 'structured_output');
  const hasText = typeof terminal.result === 'string' && terminal.result.length > 0;
  if (hasStructured && hasText) throw nativeError('NATIVE_AMBIGUOUS_FINAL', rawOutputDigest);
  if (!hasStructured && !hasText) throw nativeError('NATIVE_MISSING_FINAL', rawOutputDigest);
  const response = assertedResponse(hasStructured ? terminal.structured_output : json(terminal.result, rawOutputDigest), rawOutputDigest);
  return observation('claude-code', rawOutputDigest, 'completed', events, attempts, response, attempts.length ? ['native-tool-attempt'] : []);
}

/** Parse exactly one Codex exec turn from bounded JSONL. Failed events dominate finals. */
export function parseCodexEvents(input) {
  const { text, rawOutputDigest } = decode(input);
  const lines = text.split(/\r?\n/u);
  if (lines.at(-1) === '') lines.pop();
  if (lines.length === 0 || lines.length > MAX_EVENTS) throw nativeError('NATIVE_EVENT_LIMIT', rawOutputDigest);
  const events = [], attempts = [], finals = [];
  const completedItems = new Set();
  let threadStarted = false, turnStarted = false, terminal = null, sawError = false;
  for (const line of lines) {
    if (!line.trim() || Buffer.byteLength(line) > MAX_LINE) throw nativeError('NATIVE_INVALID_JSONL', rawOutputDigest);
    const event = object(json(line, rawOutputDigest), rawOutputDigest);
    if (terminal) throw nativeError('NATIVE_AMBIGUOUS_COMPLETION', rawOutputDigest);
    events.push({ type: typeof event.type === 'string' ? event.type : 'invalid', artifactDigest: digest(event) });
    if (event.type === 'thread.started') {
      if (threadStarted || turnStarted || typeof event.thread_id !== 'string' || !event.thread_id) throw nativeError('NATIVE_INVALID_SEQUENCE', rawOutputDigest);
      threadStarted = true;
    } else if (event.type === 'turn.started') {
      if (!threadStarted || turnStarted) throw nativeError('NATIVE_INVALID_SEQUENCE', rawOutputDigest);
      turnStarted = true;
    } else if (['item.started', 'item.updated', 'item.completed'].includes(event.type)) {
      if (!turnStarted) throw nativeError('NATIVE_INVALID_SEQUENCE', rawOutputDigest);
      const item = object(event.item, rawOutputDigest);
      if (typeof item.id !== 'string' || !item.id || item.id.length > 256) throw nativeError('NATIVE_INVALID_EVENT', rawOutputDigest);
      if (!['agent_message', 'reasoning', 'plan_update', 'command_execution', 'file_change', 'mcp_tool_call', 'web_search'].includes(item.type)) throw nativeError('NATIVE_UNKNOWN_ITEM', rawOutputDigest);
      if (completedItems.has(item.id)) throw nativeError('NATIVE_DUPLICATE_ITEM', rawOutputDigest);
      if (event.type === 'item.completed') completedItems.add(item.id);
      // Nested native tool payloads cannot be hidden in nominal reasoning/message events.
      scanTools(item, attempts);
      if (item.type === 'agent_message' && event.type === 'item.completed') {
        if (item.phase !== undefined && !['commentary', 'final_answer'].includes(item.phase)) throw nativeError('NATIVE_UNKNOWN_PHASE', rawOutputDigest);
        if (typeof item.text !== 'string') throw nativeError('NATIVE_INVALID_FINAL', rawOutputDigest);
        if (item.phase !== 'commentary') finals.push(item.text);
      }
    } else if (event.type === 'error') {
      sawError = true;
    } else if (['turn.completed', 'turn.failed'].includes(event.type)) {
      if (!turnStarted) throw nativeError('NATIVE_INVALID_SEQUENCE', rawOutputDigest);
      terminal = event.type;
    } else throw nativeError('NATIVE_UNKNOWN_EVENT', rawOutputDigest);
  }
  if (!terminal) throw nativeError('NATIVE_MISSING_COMPLETION', rawOutputDigest);
  if (finals.length > 1) throw nativeError('NATIVE_AMBIGUOUS_FINAL', rawOutputDigest);
  const failed = terminal === 'turn.failed' || sawError;
  if (failed) return observation('codex-exec', rawOutputDigest, 'failed', events, attempts, null, ['runtime-failed', ...(attempts.length ? ['native-tool-attempt'] : [])]);
  if (finals.length !== 1) throw nativeError('NATIVE_MISSING_FINAL', rawOutputDigest);
  const response = assertedResponse(json(finals[0], rawOutputDigest), rawOutputDigest);
  return observation('codex-exec', rawOutputDigest, 'completed', events, attempts, response, attempts.length ? ['native-tool-attempt'] : []);
}
