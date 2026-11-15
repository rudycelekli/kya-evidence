import { readFile } from 'node:fs/promises';
import { hashBytes, parseJson } from 'kya-evidence';
import { verifyPairedAction } from 'kya-evidence/pairing';

const { proof, context, requestUtf8 } = parseJson(
  await readFile(new URL('./pairing-vector.json', import.meta.url), 'utf8'),
);

// A gateway loads this context from its own identity, policy and challenge stores.
const accepted = verifyPairedAction(proof, { ...context, requestDigest: hashBytes(requestUtf8) });
console.log(JSON.stringify(accepted, null, 2));
