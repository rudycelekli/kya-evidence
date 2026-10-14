import { readdir, readFile, lstat } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
async function walk(dir){const out=[];for(const e of await readdir(dir,{withFileTypes:true})){if(e.name.startsWith('.')||['node_modules','dist','__pycache__'].includes(e.name))continue;const path=join(dir,e.name);if(e.isDirectory())out.push(...await walk(path));else if(e.isFile())out.push(path);else throw Error('Unexpected symlink/special file '+path);}return out;}
const files=await walk(root);
for(const path of files.filter(x=>/\.m?js$/.test(x))){const p=spawnSync(process.execPath,['--check',path],{encoding:'utf8',timeout:5000,maxBuffer:65536});if(p.status!==0)throw Error(p.stderr||'Syntax check failed');}
for(const path of files.filter(x=>/\.json$/.test(x)))JSON.parse(await readFile(path,'utf8'));
for(const required of ['README.md','LICENSE','NOTICE','AGENTS.md','docs/SPECIFICATION.md','docs/SCORING.md','docs/THREAT-MODEL.md','docs/GOVERNANCE.md','dashboard/index.html','assets/kya-hero.svg'])await lstat(join(root,required));
const p=spawnSync(process.execPath,[join(root,'scripts/generate-schemas.mjs'),'--check'],{encoding:'utf8',timeout:5000});if(p.status!==0)throw Error(p.stderr);
const r=spawnSync(process.execPath,[join(root,'scripts/requirements.mjs'),'--check'],{encoding:'utf8',timeout:10000});if(r.status!==0)throw Error(r.stderr||'Requirement traceability failed');
const ws=spawnSync(process.execPath,[join(root,'scripts/world-class-status.mjs')],{encoding:'utf8',timeout:10000});if(ws.status!==0)throw Error(ws.stderr||'World-class status ledger invalid or out of date');
console.log(JSON.stringify({syntax:'passed',json:'passed',schemas:'matched',requirementTraceability:'passed',statusLedger:'passed',requiredArtifacts:'present',files:files.length,notEstablished:['external adoption','live commercial-agent qualification','independent security certification']}));
