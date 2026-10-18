// Adapter for the kya.impl-input/v1 contract (interop/impl-contract/README.md). Reads one JSON object on stdin,
// writes one JSON object on stdout, exits non-zero on refusal or crash.
import { parseStrict, assessResult } from './kya2.mjs';
import { currencyResult } from './currency.mjs';
import { OPERATIONS } from './ops.mjs';

const chunks = [];
for await (const c of process.stdin) chunks.push(c);
try {
  const bytes = Buffer.concat(chunks);
  if (bytes.length > 1048576) throw new Error('input longer than 1048576 bytes');
  // ill-formed UTF-8 is a refusal; a byte order mark is kept (ignoreBOM) so that the parser refuses it
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  const input = parseStrict(text);
  if (input === null || typeof input !== 'object' || Array.isArray(input) || input.schema !== 'kya.impl-input/v1') throw new Error('bad input envelope');
  let out;
  if (input.operation === 'assess') out = assessResult(input.inputs);
  else if (input.operation === 'currency') out = currencyResult(input.inputs);
  else if (typeof input.operation === 'string' && Object.hasOwn(OPERATIONS, input.operation)) out = OPERATIONS[input.operation](input.inputs);
  else out = { schema: 'kya.impl-result/v1', operation: String(input.operation), unsupported: true };
  process.stdout.write(JSON.stringify(out));
} catch (e) {
  process.stderr.write(String(e && e.message ? e.message : e).split('\n')[0] + '\n');
  process.exit(1);
}
