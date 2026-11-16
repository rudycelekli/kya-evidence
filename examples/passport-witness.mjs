import { readFile } from 'node:fs/promises';
import { digest, parseJson } from 'kya-evidence';
import { openPassportRegistry } from 'kya-evidence/passport/registry';
import { buildPassportRegistryIndex } from 'kya-evidence/passport/registry-proof';
import { registryCheckpointBytes, signRegistryStatement, verifyWitnessedLookup } from 'kya-evidence/passport/registry-checkpoint';
import { openPassportWitness } from 'kya-evidence/passport/witness';

const [command, registry, ...args] = process.argv.slice(2);
const json = async file => parseJson(await readFile(file, 'utf8'));
let output;
if (command === 'snapshot') {
  const [database, privateKeyFile, priorFile] = args;
  const prior = priorFile ? (await json(priorFile)).signed.checkpoint : null;
  const store = openPassportRegistry(database, registry);
  try {
    const histories = store.snapshotHistories();
    const index = buildPassportRegistryIndex(histories, registry);
    const time = Date.now();
    const checkpoint = {
      schema: 'kya.registry-checkpoint/v1', registry, epoch: (prior?.epoch ?? 0) + 1,
      previous: prior ? digest(prior) : null, root: index.root, count: index.count,
      issuedAt: new Date(time).toISOString(), expiresAt: new Date(time + 300_000).toISOString(),
    };
    const signature = signRegistryStatement(registryCheckpointBytes(checkpoint), await readFile(privateKeyFile));
    output = { signed: { checkpoint, signature }, histories };
  } finally {
    store.close();
  }
} else if (command === 'endorse') {
  const [bundleFile, database, originPublicKeyFile, witnessPrivateKeyFile] = args;
  const { signed, histories } = await json(bundleFile);
  const witness = openPassportWitness(database, {
    registry, originPublicKey: await readFile(originPublicKeyFile, 'utf8'), witnessPrivateKey: await readFile(witnessPrivateKeyFile),
  });
  try {
    output = witness.endorse(signed, histories);
  } finally {
    witness.close();
  }
} else if (command === 'prove') {
  const [bundleFile, kind, lookupDigest, ...endorsementFiles] = args;
  const { signed, histories } = await json(bundleFile);
  const proof = buildPassportRegistryIndex(histories, registry).prove({ kind, digest: lookupDigest });
  output = { signed, proof, endorsements: await Promise.all(endorsementFiles.map(json)) };
} else if (command === 'verify') {
  const [proofFile, kind, lookupDigest, originPublicKeyFile, ...witnessKeyFiles] = args;
  const { signed, proof, endorsements } = await json(proofFile);
  output = verifyWitnessedLookup({ kind, digest: lookupDigest }, proof, signed, endorsements, {
    registry, originPublicKey: await readFile(originPublicKeyFile, 'utf8'),
    witnessPublicKeys: await Promise.all(witnessKeyFiles.map(file => readFile(file, 'utf8'))),
  }, new Date().toISOString());
} else {
  throw new Error('Expected snapshot, endorse, prove, or verify');
}
console.log(JSON.stringify(output));
