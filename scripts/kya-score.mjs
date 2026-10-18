#!/usr/bin/env node
// KYA Score card CLI (ADR-0033, Proposed). Offline and deterministic: reads two JSON files, writes one. No network, no model call.
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseJson } from '../src/shared/canonical.mjs';
import { buildScoreCard, verifyScoreCard, ScoreCardRefusal } from '../src/kya-score/index.mjs';
import { isMain } from './lib/is-main.mjs';

const HELP = `kya-score: experimental score card with intervals, repeat variance and an evidence floor

  kya-score build --manifest FILE --runs FILE --out FILE
  kya-score verify FILE

build exits 2 and writes nothing when the evidence floor is not met. verify recomputes the card and exits 1 when it is invalid.
The headline number is unvalidated and carries fixed non-claim codes; see ADR-0033.
`;
function parse(argv) {
  const flags = {}, positional = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const k = argv[i].slice(2), v = argv[++i];
      if (!v || v.startsWith('--') || Object.hasOwn(flags, k)) throw Error('Bad flag ' + k);
      flags[k] = v;
    } else positional.push(argv[i]);
  }
  return { flags, positional };
}
const readJson = async path => parseJson(await readFile(resolve(path), 'utf8'));

export async function main(argv = process.argv.slice(2)) {
  if (!argv.length || argv[0] === '--help' || argv[0] === 'help') { console.log(HELP); return; }
  try {
    const { flags, positional } = parse(argv.slice(1));
    if (argv[0] === 'build') {
      if (positional.length || !flags.manifest || !flags.runs || !flags.out || Object.keys(flags).length !== 3) throw Error('build requires --manifest, --runs and --out only');
      const card = buildScoreCard({ manifest: await readJson(flags.manifest), runs: await readJson(flags.runs) });
      await writeFile(resolve(flags.out), JSON.stringify(card, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
      console.log(JSON.stringify({ out: resolve(flags.out), score: card.results.headline.score, ci95: card.results.headline.ci95, cardDigest: card.cardDigest }));
    } else if (argv[0] === 'verify') {
      if (positional.length !== 1 || Object.keys(flags).length) throw Error('verify requires one FILE');
      const result = verifyScoreCard(await readJson(positional[0]));
      console.log(JSON.stringify(result));
      if (!result.valid) process.exitCode = 1;
    } else throw Error('Unknown command');
  } catch (error) {
    console.error(error instanceof ScoreCardRefusal ? `${error.code}: ${error.refusals.join(',')}` : 'Error: ' + error.message);
    process.exitCode = error instanceof ScoreCardRefusal ? 2 : 1;
  }
}
if (isMain(import.meta.url)) await main();
