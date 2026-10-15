import { canonical, digest, exactKeys, insist } from '../shared/canonical.mjs';
import { identifier, text, hash, validateProfile } from '../identity/domain/services/validation.mjs';

// Profile metadata and registry validator (docs/PROFILES.md, ADR-0030). Fail closed: every rule throws.
// The profile itself is validated by validateProfile() in src/identity/domain/services/validation.mjs;
// this module validates the metadata that describes a profile and the registry that lists them.

export const STATUSES = Object.freeze(['draft', 'reference', 'deprecated', 'retired']);
export const REGISTRY_SCHEMA = 'kya.profile-registry/v1';
export const METADATA_SCHEMA = 'kya.profile-metadata/v1';
export const OWNER_KINDS = Object.freeze(['project', 'third-party']);
export const RESERVED_NAME_PREFIXES = Object.freeze(['kya.', 'kya-', 'core-', 'reference-', 'fixture-', 'local.']);
export const OWNER_CONTACT_PLACEHOLDER = '<owner-contact-placeholder>';

const DNS = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const NAME = /^[a-z0-9][a-z0-9.-]{0,63}$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const SIGNOFF_CLAIM = /(sign(ed)?[- ]?off|expert[- ]reviewed|reviewed by (a |an )?(domain )?expert|domain[- ]expert (approved|accepted)|independently (validated|certified)|certified|accepted by)/i;

function date(v, label) {
  insist(typeof v === 'string' && DATE.test(v) && !Number.isNaN(Date.parse(v)) && new Date(v).toISOString().slice(0, 10) === v, `${label}: invalid date`);
}
function textList(v, label, min) {
  insist(Array.isArray(v) && v.length >= min && v.length <= 64, `${label}: needs ${min} to 64 entries`);
  v.forEach(x => text(x, label, 1024));
}

// A project-owned id is exactly kya-core or core-<name>. A third-party id is <dns-namespace>:<name>.
export function validateProfileId(id, ownerKind) {
  identifier(id, 'Profile ID');
  insist(id === id.toLowerCase(), 'Profile ID must be lowercase');
  if (ownerKind === 'project') {
    insist(id === 'kya-core' || /^core-[a-z0-9][a-z0-9.-]{0,58}$/.test(id), 'Project profile ID must be kya-core or core-<name>');
    return;
  }
  const i = id.indexOf(':');
  insist(i > 0 && id.indexOf(':', i + 1) === -1, 'Third-party profile ID must be <namespace>:<name>');
  const ns = id.slice(0, i), name = id.slice(i + 1);
  insist(DNS.test(ns) && ns.length <= 63, 'Profile namespace must be a lowercase DNS name');
  insist(NAME.test(name), 'Profile name must be lowercase kebab-case, at most 64 characters');
  for (const p of RESERVED_NAME_PREFIXES) insist(!ns.startsWith(p) && !name.startsWith(p), `Profile ID uses reserved prefix ${p}`);
}

export function profileStats(profile) {
  return { checkCount: profile.checks.length, criticalCount: profile.checks.filter(c => c.critical).length, totalWeight: profile.checks.reduce((n, c) => n + c.weight, 0) };
}

// Validate one metadata document. When `profile` is given, the binding to it is checked as well.
export function validateProfileMetadata(doc, { profile } = {}) {
  insist(doc && typeof doc === 'object' && !Array.isArray(doc), 'Metadata must be an object');
  const v = JSON.parse(canonical(doc));
  const deprecated = Object.hasOwn(v, 'deprecation');
  exactKeys(v, ['schema', 'profileId', 'profileVersion', 'profileDigest', 'file', 'checkCount', 'criticalCount', 'totalWeight', 'status', 'purpose', 'intendedScope', 'knownGaps', 'changeLog', 'owner', 'signOff', ...(deprecated ? ['deprecation'] : [])], 'Profile metadata');
  insist(v.schema === METADATA_SCHEMA, 'Unsupported profile metadata schema');
  insist(typeof v.status === 'string' && STATUSES.includes(v.status), 'Unknown profile status');
  exactKeys(v.owner, ['kind', 'contact'], 'Profile owner');
  insist(OWNER_KINDS.includes(v.owner.kind), 'Unknown owner kind');
  text(v.owner.contact, 'Owner contact', 256);
  insist(v.owner.contact === OWNER_CONTACT_PLACEHOLDER || /^https:\/\/[^\s@]+$/.test(v.owner.contact), 'Owner contact must be the placeholder or an https URL without an address');
  validateProfileId(v.profileId, v.owner.kind);
  text(v.profileVersion, 'Profile version', 64);
  hash(v.profileDigest, 'Profile digest');
  text(v.file, 'Profile file', 256);
  insist(/^profiles\/[A-Za-z0-9._-]+\.json$/.test(v.file), 'Profile file must be profiles/<name>.json');
  for (const k of ['checkCount', 'criticalCount', 'totalWeight']) insist(Number.isSafeInteger(v[k]) && v[k] >= 0, `${k} must be a non-negative integer`);
  insist(v.checkCount > 0 && v.criticalCount <= v.checkCount && v.totalWeight >= v.checkCount, 'Inconsistent profile counts');
  text(v.purpose, 'Purpose', 2048); text(v.intendedScope, 'Intended scope', 2048);
  textList(v.knownGaps, 'Known gaps', 1);
  insist(Array.isArray(v.changeLog) && v.changeLog.length >= 1 && v.changeLog.length <= 256, 'Change log needs at least one entry');
  const seen = new Set();
  for (const c of v.changeLog) {
    exactKeys(c, ['version', 'date', 'summary'], 'Change log entry'); text(c.version, 'Change log version', 64); date(c.date, 'Change log date'); text(c.summary, 'Change log summary', 1024);
    insist(!seen.has(c.version), 'Duplicate change log version'); seen.add(c.version);
    insist(!SIGNOFF_CLAIM.test(c.summary) || v.signOff !== null, 'Change log claims sign-off without evidence');
  }
  insist(seen.has(v.profileVersion), 'Change log has no entry for the profile version');
  // A sign-off needs a named reviewer, a role, a date and an evidence digest. Absent, none may be implied.
  if (v.signOff === null) {
    for (const [k, t] of [['purpose', v.purpose], ['intendedScope', v.intendedScope]]) insist(!SIGNOFF_CLAIM.test(t), `${k} claims review or sign-off without evidence`);
  } else {
    exactKeys(v.signOff, ['reviewer', 'role', 'date', 'evidenceDigest'], 'Sign-off');
    text(v.signOff.reviewer, 'Sign-off reviewer', 256); text(v.signOff.role, 'Sign-off role', 256); date(v.signOff.date, 'Sign-off date'); hash(v.signOff.evidenceDigest, 'Sign-off evidence digest');
    insist(v.status !== 'draft', 'A draft profile cannot carry a sign-off; set the status through review');
  }
  insist(v.status !== 'reference' || v.owner.kind === 'project', 'Only a project profile can have reference status');
  if (deprecated) {
    insist(v.status === 'deprecated' || v.status === 'retired', 'Deprecation record requires deprecated or retired status');
    exactKeys(v.deprecation, ['date', 'reason', 'supersededBy'], 'Deprecation'); date(v.deprecation.date, 'Deprecation date'); text(v.deprecation.reason, 'Deprecation reason', 1024);
    if (v.deprecation.supersededBy !== null) identifier(v.deprecation.supersededBy, 'Superseding profile ID');
  } else insist(v.status !== 'deprecated' && v.status !== 'retired', 'Deprecated or retired status requires a deprecation record');
  if (profile !== undefined) {
    const p = validateProfile(profile);
    insist(p.id === v.profileId, 'Metadata profile ID differs from the profile');
    insist(p.version === v.profileVersion, 'Metadata profile version differs from the profile');
    insist(digest(p) === v.profileDigest, 'Profile digest mismatch');
    const s = profileStats(p);
    for (const k of Object.keys(s)) insist(v[k] === s[k], `Metadata ${k} differs from the profile`);
  }
  return v;
}

// Validate the registry document. `profiles` maps a metadata `file` to the parsed profile; a listed file that is
// missing from the map is refused, so a registry cannot name a profile that was never checked.
export function validateProfileRegistry(registry, { profiles } = {}) {
  insist(registry && typeof registry === 'object' && !Array.isArray(registry), 'Registry must be an object');
  const r = JSON.parse(canonical(registry));
  exactKeys(r, ['schema', 'warning', 'profiles'], 'Profile registry');
  insist(r.schema === REGISTRY_SCHEMA, 'Unsupported profile registry schema'); text(r.warning, 'Registry warning', 2048);
  insist(Array.isArray(r.profiles) && r.profiles.length <= 1024, 'Invalid registry profiles');
  insist(profiles === undefined || profiles instanceof Map, 'profiles must be a Map');
  const pairs = new Set(), digests = new Map();
  let prev = '';
  for (const entry of r.profiles) {
    let opts = {};
    if (profiles) {
      insist(entry && typeof entry.file === 'string' && profiles.has(entry.file), 'Registry names a profile file that was not supplied');
      opts = { profile: profiles.get(entry.file) };
    }
    const e = validateProfileMetadata(entry, opts);
    const key = `${e.profileId.toLowerCase()}@${e.profileVersion}`;
    insist(!pairs.has(key), 'Duplicate profile ID and version in registry'); pairs.add(key);
    insist(!digests.has(e.profileDigest) || digests.get(e.profileDigest) === e.profileId.toLowerCase(), 'Profile digest already registered under another ID');
    digests.set(e.profileDigest, e.profileId.toLowerCase());
    insist(key > prev, 'Registry entries must be sorted by ID and version'); prev = key;
  }
  return r;
}
