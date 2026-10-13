import { readdir,readFile,mkdir,writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { digest } from '../src/index.mjs';

// Portable local index. Build evidence separately records the real Ruflo plugin importer.
const root=fileURLToPath(new URL('../',import.meta.url)),dir=join(root,'docs/adr');
const records=[];
for(const file of (await readdir(dir)).filter(x=>x.endsWith('.md')&&x!=='README.md').sort()){
  const text=await readFile(join(dir,file),'utf8'),id=/^# (ADR-\d+):/m.exec(text)?.[1],title=/^# ADR-\d+: (.+)$/m.exec(text)?.[1],status=/\*\*Status\*\*: (.+)/.exec(text)?.[1]??/^status:\s*(.+)$/m.exec(text)?.[1];
  if(!id||!title||!status)throw Error('ADR metadata missing: '+file);
  for(const section of ['Context','Decision','Alternatives','Consequences','Validation'])if(!text.includes('## '+section))throw Error('ADR section missing '+section+': '+file);
  records.push({id,title,status,file:'docs/adr/'+file,contentDigest:digest(text),related:[...new Set([...text.matchAll(/ADR-\d+/g)].map(m=>m[0]))].filter(x=>x!==id)});
}
const ids=new Set(records.map(x=>x.id));if(ids.size!==records.length)throw Error('Duplicate ADR IDs');for(const r of records)for(const ref of r.related)if(!ids.has(ref))throw Error('Dangling ADR reference: '+ref);
await mkdir(join(root,'evidence'),{recursive:true});await writeFile(join(root,'evidence/adr-index.json'),JSON.stringify({schema:'kya.adr-index/v1',records,digest:digest(records),store:'portable local file; not a claim of AgentDB graph persistence'},null,2)+'\n');console.log(JSON.stringify({records:records.length,danglingRefs:0,storage:'evidence/adr-index.json'}));
