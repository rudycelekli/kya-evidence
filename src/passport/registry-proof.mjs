import { canonical, digest, exactKeys, insist } from '../shared/canonical.mjs';
import { hash, text } from '../identity/domain/services/validation.mjs';
import { verifyPassport } from './index.mjs';

const maxEntries = 1_000_000;
const emptyRoot = digest(['kya.registry-empty/v1']);
const leafHash = leaf => digest(['kya.registry-leaf/v1', leaf]);
const nodeHash = (left, right) => digest(['kya.registry-node/v1', left, right]);

function queryKey(query) {
  exactKeys(query, ['kind', 'digest'], 'Registry query');
  insist(query.kind === 'passport' || query.kind === 'fingerprint', 'Invalid registry query');
  hash(query.digest, 'Lookup digest');
  return query.kind + ':' + query.digest;
}

function lowerBound(entries, key) {
  let low = 0;
  let high = entries.length;
  while (low < high) {
    const mid = Math.floor((low + high) / 2);
    if (entries[mid].key < key) low = mid + 1;
    else high = mid;
  }
  return low;
}

export function buildPassportRegistryIndex(input, registry) {
  text(registry, 'Registry');
  insist(Array.isArray(input) && input.length <= maxEntries, 'Invalid registry snapshot');
  const passports = new Map();
  const indexes = new Map();
  for (const candidate of input) {
    const history = JSON.parse(canonical(candidate));
    const passport = verifyPassport(history, registry);
    const id = passport.passportId;
    insist(!passports.has(id), 'Duplicate passport');
    passports.set(id, { id, head: passport.head, sequence: history.length, history });
    const fingerprints = new Set(passport.fingerprints);
    for (const { event } of history) {
      fingerprints.add(event.manifestDigest);
    }
    for (const fingerprint of fingerprints) {
      if (!indexes.has(fingerprint)) indexes.set(fingerprint, []);
      indexes.get(fingerprint).push(id);
    }
  }
  const entries = [
    ...Array.from(passports.values(), ({ id, head, sequence }) => ({ key: 'passport:' + id, value: { head, sequence } })),
    ...Array.from(indexes, ([fp, ids]) => ({ key: 'fingerprint:' + fp, value: ids.sort() })),
  ].sort((a, b) => (a.key < b.key ? -1 : 1));
  insist(entries.length <= maxEntries, 'Registry index too large');
  const levels = [entries.map(leafHash)];
  while (levels.at(-1).length > 1) {
    const level = levels.at(-1);
    const upper = [];
    for (let i = 0; i < level.length; i += 2) upper.push(nodeHash(level[i], level[i + 1] ?? level[i]));
    levels.push(upper);
  }
  function member(index) {
    if (index < 0 || index >= entries.length) return null;
    const siblings = [];
    let position = index;
    for (const level of levels.slice(0, -1)) {
      siblings.push(level[position ^ 1] ?? level[position]);
      position = Math.floor(position / 2);
    }
    return { index, leaf: entries[index], siblings };
  }
  return {
    root: levels.at(-1)[0] ?? emptyRoot,
    count: entries.length,
    passports,
    prove(query) {
      const key = queryKey(query);
      const i = lowerBound(entries, key);
      const match = entries[i]?.key === key;
      return JSON.parse(canonical(match ? { member: member(i) } : { left: member(i - 1), right: member(i) }));
    },
  };
}

function checkMember(witness, root, count) {
  exactKeys(witness, ['index', 'leaf', 'siblings'], 'Registry membership');
  const { index, leaf, siblings } = witness;
  insist(Number.isInteger(index) && index >= 0 && index < count && Array.isArray(siblings), 'Invalid membership position');
  exactKeys(leaf, ['key', 'value'], 'Registry leaf');
  insist(typeof leaf.key === 'string' && /^(passport|fingerprint):[a-f0-9]{64}$/.test(leaf.key), 'Invalid registry leaf key');
  let width = count;
  let indexAtLevel = index;
  let current = leafHash(leaf);
  let depth = 0;
  while (width > 1) {
    const sibling = siblings[depth++];
    hash(sibling, 'Registry sibling');
    if ((indexAtLevel ^ 1) >= width) insist(sibling === current, 'Invalid registry padding');
    current = indexAtLevel % 2 ? nodeHash(sibling, current) : nodeHash(current, sibling);
    indexAtLevel = Math.floor(indexAtLevel / 2);
    width = Math.ceil(width / 2);
  }
  insist(depth === siblings.length && current === root, 'Registry proof mismatch');
  return leaf;
}

export function verifyPassportRegistryLookup(query, input, root, count) {
  const key = queryKey(query);
  const proof = JSON.parse(canonical(input));
  hash(root, 'Registry root');
  insist(Number.isInteger(count) && count >= 0 && count <= maxEntries, 'Invalid registry count');
  if (Object.hasOwn(proof, 'member')) {
    exactKeys(proof, ['member'], 'Registry lookup');
    const leaf = checkMember(proof.member, root, count);
    insist(leaf.key === key, 'Registry lookup key mismatch');
    return leaf.value;
  }
  exactKeys(proof, ['left', 'right'], 'Registry absence');
  const { left, right } = proof;
  if (count === 0) {
    insist(left === null && right === null && root === emptyRoot, 'Invalid empty registry proof');
    return null;
  }
  if (left !== null) insist(checkMember(left, root, count).key < key, 'Invalid absence boundary');
  if (right !== null) insist(checkMember(right, root, count).key > key, 'Invalid absence boundary');
  insist((left?.index ?? -1) + 1 === (right?.index ?? count), 'Registry absence is not adjacent');
  return null;
}
