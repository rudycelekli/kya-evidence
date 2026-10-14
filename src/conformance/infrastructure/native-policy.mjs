import { readFile, readdir, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { userInfo } from 'node:os';
import { hashBytes, parseJson } from '../../shared/canonical.mjs';
import { nativeError } from './native-parsers.mjs';

/** Local policy inventory cannot establish future server policy or OS isolation. */
export async function preflightClaudePolicy(home) {
  if (process.platform !== 'darwin' && process.platform !== 'linux') throw nativeError('NATIVE_MANAGED_POLICY_UNSUPPORTED');
  const base = process.platform === 'darwin' ? '/Library/Application Support/ClaudeCode' : '/etc/claude-code';
  const paths = [join(base, 'managed-settings.json'), join(base, 'managed-mcp.json'), join(home, '.claude', 'remote-settings.json')];
  if (process.platform === 'darwin') {
    paths.push('/Library/Managed Preferences/com.anthropic.claudecode.plist');
    paths.push(join('/Library/Managed Preferences', userInfo().username, 'com.anthropic.claudecode.plist'));
  }
  const records = [];
  try {
    for (const entry of await readdir(join(base, 'managed-settings.d'), { withFileTypes: true })) {
      if (entry.isSymbolicLink()) throw nativeError('NATIVE_MANAGED_POLICY_UNRESOLVED');
      if (entry.isFile() && entry.name.endsWith('.json')) paths.push(join(base, 'managed-settings.d', entry.name));
    }
  } catch (error) { if (error.code !== 'ENOENT') throw nativeError('NATIVE_MANAGED_POLICY_UNRESOLVED'); }
  for (const path of paths.sort()) {
    try {
      const stat = await lstat(path);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 131072) throw nativeError('NATIVE_MANAGED_POLICY_UNRESOLVED');
      const bytes = await readFile(path);
      if (bytes.length > 131072) throw nativeError('NATIVE_MANAGED_POLICY_UNRESOLVED');
      // MDM plists require a trusted policy bridge; never treat them as JSON or absence.
      if (path.endsWith('.plist')) throw nativeError('NATIVE_MANAGED_POLICY_UNRESOLVED');
      let data;
      try { data = parseJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw nativeError('NATIVE_MANAGED_POLICY_UNRESOLVED'); }
      // Conservative initial contract: any nonempty policy requires independent interpretation.
      if (!data || typeof data !== 'object' || Array.isArray(data) || Object.keys(data).length) throw nativeError('NATIVE_MANAGED_POLICY_UNRESOLVED');
      records.push({ source: 'local-managed-policy', artifactDigest: hashBytes(bytes), status: 'empty' });
    } catch (error) {
      if (error.code === 'ENOENT') records.push({ source: 'local-managed-policy', status: 'absent' });
      else throw nativeError('NATIVE_MANAGED_POLICY_UNRESOLVED');
    }
  }
  // Even an empty local snapshot cannot prove what managed policy arrives at startup.
  // A caller-supplied hash or boolean is not a policy-isolation attestation.
  throw nativeError('NATIVE_SERVER_POLICY_UNRESOLVED');
}

export async function preflightCodexInstructions(codeHome, expectedDigest = null, acknowledge = false) {
  const included = [];
  for (const name of ['AGENTS.md', 'AGENTS.override.md']) {
    try {
      const stat = await lstat(join(codeHome, name));
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 131072) throw nativeError('NATIVE_GLOBAL_INSTRUCTIONS_UNRESOLVED');
      if (stat.size > 0) {
        const bytes = await readFile(join(codeHome, name));
        if (bytes.length > 131072 || acknowledge !== true || hashBytes(bytes) !== expectedDigest) throw nativeError('NATIVE_GLOBAL_INSTRUCTIONS_UNRESOLVED');
        included.push({ name, artifactDigest: hashBytes(bytes), status: 'included-user-instructions' });
      }
    } catch (error) { if (error.code !== 'ENOENT') throw nativeError('NATIVE_GLOBAL_INSTRUCTIONS_UNRESOLVED'); }
  }
  if (included.length > 1) throw nativeError('NATIVE_GLOBAL_INSTRUCTIONS_UNRESOLVED');
  return { status: included.length ? 'included-user-instructions' : 'no-active-global-instruction-file', included, limitation: 'Deliberately included instructions or local file absence do not establish policy/OS isolation; startup races remain.' };
}

export async function preflightCodexAuth(codeHome) {
  try {
    const path = join(codeHome, 'auth.json'), stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 131072) throw nativeError('NATIVE_AUTH_MODE_UNVERIFIED');
    const bytes = await readFile(path);
    if (bytes.length > 131072) throw nativeError('NATIVE_AUTH_MODE_UNVERIFIED');
    const data = parseJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (data?.auth_mode !== 'chatgpt' || data.OPENAI_API_KEY || !data.tokens || typeof data.tokens !== 'object' || Array.isArray(data.tokens)) throw nativeError('NATIVE_AUTH_MODE_UNVERIFIED');
    return { mode: 'chatgpt', artifactDigest: hashBytes(bytes), limitation: 'Stored auth metadata is a local snapshot, not billing or live entitlement verification.' };
  } catch { throw nativeError('NATIVE_AUTH_MODE_UNVERIFIED'); }
}
