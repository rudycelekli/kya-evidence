import { readBounded } from './lib/bounded-read.mjs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseJson } from '../src/index.mjs';
import { verifyReleaseReceipt } from './lib/ustar.mjs';

// Usage: node scripts/verify-release.mjs [--expect-commit SHA]
// With --expect-commit the receipt sourceCommit must equal SHA (the publish job passes GITHUB_SHA), so the artifact
// is tied to the commit the workflow run was started on. The receipt package and version must always match the
// package.json inside the tarball. The receipt is unsigned: this ties the bytes to a commit claim, it does not
// authenticate who built them.
const argv=process.argv.slice(2);let expectCommit;
for(let i=0;i<argv.length;i++){
  if(argv[i]==='--expect-commit'&&expectCommit===undefined&&argv[i+1]&&!argv[i+1].startsWith('--')){expectCommit=argv[++i];}
  else{process.stderr.write('verify-release: usage: node scripts/verify-release.mjs [--expect-commit SHA]\n');process.exit(1);}
}
const out=fileURLToPath(new URL('../dist/',import.meta.url));
const r=parseJson(await readBounded(join(out,'release-receipt.json'),'utf8'));
if(typeof r.archive!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.tgz$/.test(r.archive))throw Error('Unsafe archive filename');
console.log(JSON.stringify(verifyReleaseReceipt(r,await readBounded(join(out,r.archive),undefined,20_000_000),{expectCommit,bindPackage:true})));
