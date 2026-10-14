import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,cp,readFile,writeFile,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRequirements,render } from '../scripts/requirements.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
async function sandbox(edit){
  const dir=await mkdtemp(join(tmpdir(),'kya-req-'));
  for(const p of ['evidence','docs','test'])await cp(join(root,p),join(dir,p),{recursive:true});
  const file=join(dir,'evidence/requirements.json'),reg=JSON.parse(await readFile(file,'utf8'));await edit(reg,dir);await writeFile(file,JSON.stringify(reg));return dir;
}
async function rejects(edit,pattern){const dir=await sandbox(edit);try{await assert.rejects(loadRequirements(dir),pattern);}finally{await rm(dir,{recursive:true,force:true});}}

test('every normative requirement traces to existing tests, covers all areas, and the generated document is current',async()=>{
  const {reg,areas}=await loadRequirements();
  assert(reg.requirements.length>=29);
  for(const area of ['integrity','binding','trust','run-selection','scoring','reporting','research','benchmarks','conformance','release'])assert(areas[area]>0,area);
  assert.equal(await readFile(join(root,'docs/REQUIREMENTS.md'),'utf8'),render(reg));
});
test('a requirement tracing to a deleted or renamed test is detected',async()=>{
  await rejects(reg=>{reg.requirements[0].tests[0].title='no such test exists';},/trace missing/);
  await rejects(reg=>{reg.requirements[0].tests[0].file='test/missing.test.mjs';},/ENOENT/);
});
test('an untested, duplicated, misleveled or unanchored requirement is detected',async()=>{
  await rejects(reg=>{reg.requirements[1].tests=[];},/without verifying test/);
  await rejects(reg=>{reg.requirements[1].id=reg.requirements[0].id;},/duplicate requirement/i);
  await rejects(reg=>{reg.requirements[0].level='MAYBE';},/Bad level/);
  await rejects(reg=>{reg.requirements[0].level='SHOULD';reg.requirements[0].section='Nonexistent section';},/missing section/);
  await rejects(reg=>{reg.requirements[0].statement=reg.requirements[0].statement.replaceAll('MUST','will');},/must state its level/);
});
test('a title matching several tests is ambiguous rather than silently accepted',async()=>{
  await rejects(reg=>{reg.requirements[0].tests[0].file='test/assessment.test.mjs';reg.requirements[0].tests[0].title='proof';},/ambiguous/);
});
