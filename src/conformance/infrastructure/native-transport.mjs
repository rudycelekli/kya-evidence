import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { canonical, parseJson } from '../../shared/canonical.mjs';
import { nativeError } from './native-parsers.mjs';

/** Internal vendor transport: captures bounded bytes, never puts raw stderr in errors. */
export function executeNativeTransport(plan, input, { signal } = {}) {
  if (typeof input !== 'string' || Buffer.byteLength(input) > 131072) throw nativeError('INPUT_LIMIT');
  if (signal !== undefined && !(signal instanceof AbortSignal)) throw nativeError('NATIVE_INVALID_SIGNAL');
  if (signal?.aborted) return Promise.reject(nativeError('ABORTED'));
  try { plan = parseJson(canonical(plan)); } catch { throw nativeError('NATIVE_INVALID_OPTIONS'); }
  const allowedEnv = new Set(['PATH', 'LANG', 'LC_ALL', 'HOME', 'CODEX_HOME', 'SystemRoot', 'WINDIR', 'PATHEXT', 'CLAUDE_CODE_DISABLE_CLAUDE_MDS', 'CLAUDE_CODE_DISABLE_AUTO_MEMORY', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'DISABLE_AUTOUPDATER', 'ENABLE_CLAUDEAI_MCP_SERVERS']);
  if (typeof plan.command !== 'string' || !isAbsolute(plan.command) || typeof plan.cwd !== 'string' || !isAbsolute(plan.cwd) || !Array.isArray(plan.args) || plan.args.length > 128 || plan.args.some(arg => typeof arg !== 'string' || arg.length > 16384 || arg.includes('\0')) || !Number.isSafeInteger(plan.timeoutMs) || plan.timeoutMs < 1 || plan.timeoutMs > 30000 || !Number.isSafeInteger(plan.maxOutputBytes) || plan.maxOutputBytes < 1 || plan.maxOutputBytes > 262144 || !plan.environment || typeof plan.environment !== 'object' || Array.isArray(plan.environment) || Object.entries(plan.environment).some(([key, value]) => !allowedEnv.has(key) || typeof value !== 'string' || value.length > 16384 || value.includes('\0'))) throw nativeError('NATIVE_INVALID_OPTIONS');
  return new Promise((resolve, reject) => {
    let child, timer, settled = false, outputBytes = 0, errorBytes = 0;
    const chunks = [], stdoutHash = createHash('sha256'), stderrHash = createHash('sha256');
    const start = performance.now();
    const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', abort); };
    const finish = (error, result) => { if (settled) return; settled = true; cleanup(); if (error) reject(error); else resolve(result); };
    const kill = code => {
      if (child?.pid) try { if (process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL'); else child.kill('SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch {} }
      child?.stdin.destroy(); child?.stdout.destroy(); child?.stderr.destroy();
      const error = nativeError(code);
      error.partialOutputDigest = stdoutHash.copy().digest('hex');
      error.partialStderrDigest = stderrHash.copy().digest('hex');
      finish(error);
    };
    const abort = () => kill('ABORTED');
    try { child = spawn(plan.command, plan.args, { cwd: plan.cwd, env: plan.environment, shell: false, detached: process.platform !== 'win32', windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }); }
    catch { finish(nativeError('SPAWN_FAILED')); return; }
    timer = setTimeout(() => kill('TIMEOUT'), plan.timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    child.once('error', () => finish(nativeError('SPAWN_FAILED')));
    child.stdin.on('error', () => {});
    child.stdout.on('data', chunk => { stdoutHash.update(chunk); outputBytes += chunk.length; if (outputBytes > plan.maxOutputBytes) kill('OUTPUT_LIMIT'); else chunks.push(chunk); });
    child.stderr.on('data', chunk => { stderrHash.update(chunk); errorBytes += chunk.length; if (errorBytes > plan.maxOutputBytes) kill('OUTPUT_LIMIT'); });
    child.once('close', (exitCode, exitSignal) => {
      if (settled) return;
      finish(null, { stdout: Buffer.concat(chunks), rawOutputDigest: stdoutHash.digest('hex'), stderrDigest: stderrHash.digest('hex'), exitCode, exitSignal, outputBytes, stderrBytes: errorBytes, latencyMs: Math.round((performance.now() - start) * 1000) / 1000 });
    });
    child.stdin.end(input);
  });
}
