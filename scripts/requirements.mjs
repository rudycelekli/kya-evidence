import { readFile,writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { digest } from '../src/index.mjs';

// Traceability gate: every normative requirement must name tests that still exist.
const root=fileURLToPath(new URL('../',import.meta.url));
export async function loadRequirements(base=root){
  const reg=JSON.parse(await readFile(join(base,'evidence/requirements.json'),'utf8'));
  if(reg.schema!=='kya.requirements/v1'||!Array.isArray(reg.requirements)||!reg.requirements.length)throw Error('Requirement registry malformed');
  const titles=new Map(),ids=new Set(),areas={};
  // Textual gate: comments are stripped and tests declared with an unconditional skip/todo option are not listed (host-conditional skips such as `skip: !hasPython` remain listed).
  // A passing trace shows a live, non-skipped declaration exists; CI's `npm test` proves it passes.
  const listed=async file=>{if(!titles.has(file)){const src=(await readFile(join(base,file),'utf8')).replace(/\/\*[\s\S]*?\*\//g,'').replace(/^[ \t]*\/\/.*$/gm,'');titles.set(file,[...src.matchAll(/^test\((['"`])(.*?)\1\s*,\s*(\{[^}]*\})?/gm)].filter(m=>!/\b(skip|todo)\s*:\s*(true|1|['"`])/.test(m[3]??'')).map(m=>m[2]));}return titles.get(file);};
  for(const r of reg.requirements){
    if(!/^KYA-[A-Z]{3}-\d{3}$/.test(r.id)||ids.has(r.id))throw Error('Bad or duplicate requirement ID '+r.id);ids.add(r.id);
    if(!['MUST','MUST NOT','SHOULD','MAY'].includes(r.level))throw Error('Bad level '+r.id);
    if(!r.statement||!r.section||!r.area)throw Error('Incomplete requirement '+r.id);
    if(r.level.startsWith('MUST')&&!r.statement.includes(r.level))throw Error('Statement must state its level: '+r.id);
    if(!Array.isArray(r.tests)||!r.tests.length)throw Error('Requirement without verifying test '+r.id);
    for(const t of r.tests){const found=(await listed(t.file)).filter(x=>x===t.title);if(found.length!==1)throw Error(`Requirement ${r.id} trace ${found.length?'ambiguous':'missing'} (exact title required): ${t.file} :: ${t.title}`);}
    areas[r.area]=(areas[r.area]??0)+1;
  }
  const spec=await readFile(join(base,reg.specification),'utf8');
  for(const r of reg.requirements)if(!spec.includes('## '+r.section))throw Error('Requirement '+r.id+' cites missing section '+r.section);
  return {reg,areas};
}
export function render(reg){
  const lines=['# Normative requirements','','Generated from [`evidence/requirements.json`](../evidence/requirements.json) by `npm run requirements`. '+reg.keywords,'','Each requirement is traced to at least one test that must exist exactly once; the gate fails on stale traces. A passing trace shows the reference implementation enforces the requirement, not that it is complete or independently reviewed. A second implementation claims conformance only by passing the same vectors and tests.','','| ID | Level | Requirement | Verified by |','| :--- | :--- | :--- | :--- |'];
  for(const r of reg.requirements)lines.push(`| ${r.id} | ${r.level} | ${r.statement} | ${r.tests.map(t=>`\`${t.file.replace('test/','')}\``).filter((x,i,a)=>a.indexOf(x)===i).join(', ')} |`);
  lines.push('',`Registry digest: \`${digest(reg)}\``,'');return lines.join('\n');
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
  const {reg,areas}=await loadRequirements(),out=join(root,'docs/REQUIREMENTS.md'),text=render(reg);
  if(process.argv.includes('--check')){if(await readFile(out,'utf8')!==text)throw Error('docs/REQUIREMENTS.md drift; run npm run requirements');}
  else await writeFile(out,text);
  console.log(JSON.stringify({requirements:reg.requirements.length,areas,traceable:true,registryDigest:digest(reg)}));
}
