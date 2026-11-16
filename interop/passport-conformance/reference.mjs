import { readFileSync } from 'node:fs';
import { exactKeys, parseJson } from '../../src/shared/canonical.mjs';
import { verifyPassport } from '../../src/passport/index.mjs';
import { verifyWitnessedLookup } from '../../src/passport/registry-checkpoint.mjs';
import { verifyDownstreamReceipt } from '../pairing-gateway/downstream-receipts.mjs';

import { verifyPairedAction } from '../../src/pairing/index.mjs';
import { verifyWitnessRoster } from '../../src/passport/witness-roster.mjs';

const operations = {
  'paired-action': inputs => verifyPairedAction(inputs.proof, inputs.context),
  'witness-roster-chain': ({ chain, trust }) => {
    if (!Array.isArray(chain) || chain.length === 0 || chain.length > 128) throw new Error('Invalid roster chain');
    return chain.reduce((prior, signed) => verifyWitnessRoster(signed, trust, prior), null);
  },
  'passport-history': inputs => verifyPassport(inputs.history, inputs.registry),
  'witnessed-lookup': inputs => verifyWitnessedLookup(inputs.query, inputs.proof, inputs.signed, inputs.endorsements, inputs.trust, inputs.now),
  'downstream-receipt': inputs => verifyDownstreamReceipt(inputs.envelope, inputs.delivery, inputs.publicKey),
};

const request = parseJson(new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(0)));
exactKeys(request, ['schema', 'operation', 'inputs'], 'Conformance request');
if (request.schema !== 'kya.passport-conformance-input/v1') throw new Error('Unsupported request schema');
const response = { schema: 'kya.passport-conformance-result/v1', operation: request.operation };
if (!Object.hasOwn(operations, request.operation)) {
  response.status = 'unsupported';
} else {
  try {
    response.value = operations[request.operation](request.inputs);
    response.status = 'accept';
  } catch {
    response.status = 'reject';
  }
}
process.stdout.write(JSON.stringify(response) + '\n');
