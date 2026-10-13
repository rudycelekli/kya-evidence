import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseJson } from '../src/index.mjs';
import { verifyReleaseReceipt } from './lib/ustar.mjs';

const out=fileURLToPath(new URL('../dist/',import.meta.url));
const r=parseJson(await readFile(join(out,'release-receipt.json'),'utf8'));
if(typeof r.archive!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.tgz$/.test(r.archive))throw Error('Unsafe archive filename');
console.log(JSON.stringify(verifyReleaseReceipt(r,await readFile(join(out,r.archive)))));
