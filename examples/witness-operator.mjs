import { readFile } from 'node:fs/promises';
import { parseJson } from 'kya-evidence';
import { passportPublicKey } from 'kya-evidence/passport';
import { signRegistryStatement, verifyWitnessedLookup } from 'kya-evidence/passport/registry-checkpoint';
import { openPassportWitness } from 'kya-evidence/passport/witness';
import { verifyWitnessRoster, witnessEnrollmentBytes, witnessLookupTrust, witnessRosterBytes } from 'kya-evidence/passport/witness-roster';

const [command, ...args] = process.argv.slice(2);
const json = async file => parseJson(await readFile(file, 'utf8'));
let result;
if (command === 'approve') {
  const [rosterFile, authorityKeyFile] = args;
  result = signRegistryStatement(witnessRosterBytes(await json(rosterFile)), await readFile(authorityKeyFile));
} else if (command === 'enroll') {
  const [rosterFile, operatorId, witnessKeyFile] = args;
  const roster = await json(rosterFile);
  const privateKey = await readFile(witnessKeyFile);
  if (roster.operators.find(operator => operator.id === operatorId)?.publicKey !== passportPublicKey(privateKey)) {
    throw new Error('Operator key mismatch');
  }
  result = { operatorId, signature: signRegistryStatement(witnessEnrollmentBytes(roster, operatorId), privateKey) };
} else {
  if (!['verify', 'endorse', 'restore'].includes(command)) throw new Error('Unknown witness operator command');
  const [configFile, bundleFile, first, second, keyFile] = args;
  const config = await json(configFile);
  const accepted = [];
  for (const signed of config.rosters) accepted.push(verifyWitnessRoster(signed, config, accepted.at(-1)));
  const roster = accepted.at(-1);
  if (!roster || roster.rosterDigest !== config.pinnedRosterDigest) throw new Error('Roster pin mismatch');
  const bundle = await json(bundleFile);
  const trust = witnessLookupTrust(roster, config.originPublicKey, config.checkpointPin);
  if (command === 'verify') {
    result = verifyWitnessedLookup({ kind: first, digest: second }, bundle.proof, bundle.signed,
      bundle.endorsements, trust, new Date().toISOString());
  } else {
    const privateKey = await readFile(keyFile);
    if (roster.operators.find(operator => operator.id === first)?.publicKey !== passportPublicKey(privateKey)) {
      throw new Error('Operator key mismatch');
    }
    const witness = openPassportWitness(second, {
      registry: roster.registry, originPublicKey: config.originPublicKey, witnessPrivateKey: privateKey,
    });
    try {
      if (command === 'endorse') {
        if (bundle.signed.checkpoint.epoch < (trust.minimumEpoch ?? 1)) throw new Error('Checkpoint predates witness roster');
        result = witness.endorse(bundle.signed, bundle.histories);
      } else {
        const anchor = config.checkpointPin;
        if (!anchor || (roster.handoff && anchor.epoch < roster.handoff.epoch)) throw new Error('Latest checkpoint pin required');
        const effective = accepted.findLast(entry => (entry.handoff?.epoch ?? 0) < anchor.epoch);
        if (!effective) throw new Error('Recovery roster unavailable');
        const keys = witnessLookupTrust(effective, config.originPublicKey).witnessPublicKeys;
        result = witness.restore(bundle.signed, bundle.histories, bundle.endorsements, keys, anchor);
      }
    } finally {
      witness.close();
    }
  }
}
console.log(JSON.stringify(result));
