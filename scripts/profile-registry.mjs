import { readFile, readdir, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { digest, canonical } from '../src/shared/canonical.mjs';
import { validateProfile } from '../src/identity/domain/services/validation.mjs';
import { validateProfileMetadata, validateProfileRegistry, profileStats, METADATA_SCHEMA, REGISTRY_SCHEMA, OWNER_CONTACT_PLACEHOLDER } from '../src/profiles/validate-metadata.mjs';

// Generator and drift check for evidence/profile-registry.json (docs/PROFILES.md, ADR-0030).
// Digests are computed from the real profile files; nothing in the registry is typed by hand except the
// descriptive metadata below. No clock is read. No sign-off is recorded for any profile.

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const OUT = fileURLToPath(new URL('../evidence/profile-registry.json', import.meta.url));

const WARNING = 'Lists the profiles in this repository with the digest of each frozen file. Status draft or reference describes repository maturity only. No domain expert has reviewed any profile and no entry carries a sign-off. A digest identifies bytes; it does not show a profile is correct, complete or fit for a use case.';

// Descriptive metadata, keyed by profile file. Adding a file to profiles/ without an entry here fails generation.
const METADATA = {
  'profiles/core-v1.json': {
    status: 'reference',
    owner: { kind: 'project', contact: OWNER_CONTACT_PLACEHOLDER },
    purpose: 'Frozen eighteen-check reference profile used by the conformance evaluator, the policy templates and the golden fixtures. It defines the denominator that scores are measured against.',
    intendedScope: 'Structured conformance evidence for one agent identity, scope and tool set. Equal weights are transparent and contestable. Fixture runs never score commercial products.',
    knownGaps: [
      'No domain expert has reviewed the checks, weights or critical flags; they are a proposal, not an accepted standard.',
      'Observes structured action attempts and final output, not all real tool side effects; an uninstrumented adapter can be fooled by a fabricated compliant transcript.',
      'Equal weights and policy thresholds are not calibrated against real-world outcomes.',
      'Not specialised to a domain: code agents, agentic payments and read-only assistants use policy templates over this one profile, not separate profiles.'
    ],
    changeLog: [{ version: '1.0.0', date: '2026-10-14', summary: 'Initial frozen reference profile; digest recorded in the registry.' }]
  }
};

async function load() {
  const names = (await readdir(new URL('../profiles/', import.meta.url))).filter(n => n.endsWith('.json')).sort();
  const profiles = new Map();
  for (const n of names) profiles.set('profiles/' + n, validateProfile(JSON.parse(await readFile(new URL('../profiles/' + n, import.meta.url), 'utf8'))));
  return profiles;
}

async function policyTemplateTargets() {
  const dir = new URL('../policies/templates/', import.meta.url), out = [];
  for (const n of (await readdir(dir)).filter(x => x.endsWith('.json')).sort()) out.push([n, JSON.parse(await readFile(new URL(n, dir), 'utf8')).targetProfileId]);
  return out;
}

export async function build() {
  const profiles = await load(), entries = [];
  for (const file of profiles.keys()) if (!METADATA[file]) throw Error('No registry metadata for ' + file);
  for (const file of Object.keys(METADATA)) if (!profiles.has(file)) throw Error('Registry metadata names a missing profile ' + file);
  for (const [file, p] of profiles) {
    const m = METADATA[file];
    entries.push(validateProfileMetadata({ schema: METADATA_SCHEMA, profileId: p.id, profileVersion: p.version, profileDigest: digest(p), file, ...profileStats(p), status: m.status, purpose: m.purpose, intendedScope: m.intendedScope, knownGaps: m.knownGaps, changeLog: m.changeLog, owner: m.owner, signOff: null }, { profile: p }));
  }
  entries.sort((a, b) => { const x = `${a.profileId}@${a.profileVersion}`, y = `${b.profileId}@${b.profileVersion}`; return x < y ? -1 : x > y ? 1 : 0; });
  const registry = validateProfileRegistry({ schema: REGISTRY_SCHEMA, warning: WARNING, profiles: entries }, { profiles });
  // Every shipped policy template must target a registered profile.
  const ids = new Set(registry.profiles.map(e => e.profileId));
  for (const [n, target] of await policyTemplateTargets()) if (!ids.has(target)) throw Error(`Policy template ${n} targets unregistered profile ${target}`);
  return registry;
}

export async function generate() {
  const first = await build(), second = await build();
  if (canonical(first) !== canonical(second)) throw Error('Generator is not deterministic; refusing to write');
  return JSON.stringify(first, null, 2) + '\n';
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = await generate();
  if (process.argv.includes('--print')) process.stdout.write(text);
  else if (process.argv.includes('--check')) {
    const current = await readFile(OUT, 'utf8').catch(() => '');
    if (current !== text) { console.error('Profile registry drift; run node scripts/profile-registry.mjs'); process.exit(1); }
    console.log('Profile registry matches');
  } else { await mkdir(ROOT + 'evidence/', { recursive: true }); await writeFile(OUT, text); console.log(`Profile registry written: ${JSON.parse(text).profiles.length} profile(s)`); }
}
