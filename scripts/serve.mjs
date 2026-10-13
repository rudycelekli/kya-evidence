import { createServer } from 'node:http';
import { readFile, lstat, realpath } from 'node:fs/promises';
import { resolve, extname, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root=await realpath(fileURLToPath(new URL('../dashboard/',import.meta.url)));
const projectRoot=await realpath(fileURLToPath(new URL('../',import.meta.url)));
const requested=Number(process.env.KYA_PORT??4173);
if(!Number.isInteger(requested)||requested<0||requested>65535)throw Error('Invalid KYA_PORT');
const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.mjs':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml','.md':'text/plain; charset=utf-8'};
const server=createServer(async(req,res)=>{
  const headers={'X-Content-Type-Options':'nosniff','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"};
  try{
    if(req.method!=='GET'&&req.method!=='HEAD'){res.writeHead(405,headers);res.end();return;}
    const url=new URL(req.url,'http://127.0.0.1'),path=decodeURIComponent(url.pathname);
    const isDoc=path==='/README.md'||/^\/docs\/(?:SPECIFICATION|SCORING|THREAT-MODEL|GOVERNANCE|ROADMAP)\.md$/.test(path);
    const boundary=isDoc?projectRoot:root,file=resolve(boundary,'.'+(path==='/'?'/index.html':path));
    const rel=relative(boundary,file);if(rel==='..'||rel.startsWith('..'+sep)||rel.startsWith('.'))throw Error('Forbidden path');
    const st=await lstat(file),actual=await realpath(file),resolved=relative(boundary,actual);
    if(!st.isFile()||st.isSymbolicLink()||st.size>2_097_152||resolved==='..'||resolved.startsWith('..'+sep)||!types[extname(file)])throw Error('Forbidden file');
    const bytes=await readFile(file);res.writeHead(200,{...headers,'Content-Type':types[extname(file)],'Content-Length':bytes.length});res.end(req.method==='HEAD'?undefined:bytes);
  }catch{res.writeHead(404,headers);res.end('Not found');}
});
server.listen(requested,'127.0.0.1',()=>console.log(`KYA Evidence dashboard: http://127.0.0.1:${server.address().port}`));
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>server.close(()=>process.exit(0)));
