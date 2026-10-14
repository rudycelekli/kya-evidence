import test from 'node:test';import assert from 'node:assert/strict';import {readFile,stat} from 'node:fs/promises';import {resolve,relative,sep} from 'node:path';import {fileURLToPath} from 'node:url';import {fixture,PRESETS,parseReport,validateReport,breakdown} from '../dashboard/model.mjs';
const realShape=()=>({...fixture('careful'),schema:'kya.assessment/v1',subjectDigest:'a'.repeat(64),profileDigest:'b'.repeat(64),evaluatorDigest:'c'.repeat(64),policyDigest:'d'.repeat(64),evidenceBundleDigest:'e'.repeat(64),reportDigest:'f'.repeat(64)});
test('presets preserve fixed population and source provenance',()=>{for(const p of PRESETS){const r=fixture(p.id);assert.equal(r.schema,'kya.viewer-fixture/v1');assert.equal(r.evidenceMode,'fixture');assert.equal(r.checks.length,18);assert.equal(breakdown(r).total,18);assert.equal(r.dimensions.length,6);assert.equal(r.independentCoverage,0);}});
test('critical failures block despite other passes',()=>{const r=fixture('unsafe');assert.equal(r.decision,'blocked');assert.ok(r.score.earned>500);assert.ok(r.checks.some(c=>c.critical&&c.status==='fail'));});
test('unknown and revoked cases cannot earn points',()=>{for(const id of ['unknown','revoked']){const r=fixture(id);assert.equal(r.score.earned,0);assert.equal(r.coverage,0);assert.equal(breakdown(r).unresolved,18);}});
test('tampered illustration retains rejection reasons and denominator',()=>{const r=fixture('tampered');assert.equal(r.rejectedEvidence.length,3);assert.equal(breakdown(r).total,18);assert.equal(r.score.earned,833);});
test('viewer accepts actual report shape but never treats fixtures as assessments',()=>{assert.equal(validateReport(realShape()).schema,'kya.assessment/v1');assert.throws(()=>parseReport(JSON.stringify(fixture())),/requires/);});
test('malformed report import is rejected before rendering',()=>{for(const mutate of [r=>r.score.earned=1001,r=>r.coverage=2,r=>r.dimensions.push(r.dimensions[0]),r=>r.checks.push(r.checks[0]),r=>r.checks[0].weight=-1,r=>r.reportDigest='fake',r=>r.checks[0].status='certified',r=>r.decision='approved']){const r=realShape();mutate(r);assert.throws(()=>validateReport(r));}assert.throws(()=>parseReport('{broken'));assert.throws(()=>parseReport(' '.repeat(4*1024*1024+1)),/limit/);});
test('malicious strings remain data, dynamic DOM never uses HTML interpretation',async()=>{const r=realShape();r.agentName='<img src=x onerror=alert(1)>';assert.equal(parseReport(JSON.stringify(r)).agentName,r.agentName);const app=await readFile(new URL('../dashboard/app.mjs',import.meta.url),'utf8');assert.doesNotMatch(app,/innerHTML|outerHTML|insertAdjacentHTML|eval\(/);assert.match(app,/textContent/);assert.match(app,/UNVERIFIED IMPORT/);});
test('offline view contains no remote script, stylesheet, font or network API',async()=>{for(const f of ['index.html','app.mjs','style.css','model.mjs']){const s=await readFile(new URL(`../dashboard/${f}`,import.meta.url),'utf8');assert.doesNotMatch(s,/https?:\/\/|fetch\(|XMLHttpRequest|WebSocket|@import/);}const html=await readFile(new URL('../dashboard/index.html',import.meta.url),'utf8');assert.match(html,/aria-live="polite"/);assert.match(html,/type="file"/);assert.match(html,/class="skip"/);});
// Structural validation of the intentionally small SVG XML subset shipped by
// this package. This is not a browser renderer or a full W3C XML validator.
function svgTree(source){
  const allowed=new Set(['svg','title','desc','style','rect','text','path','g','circle','defs','linearGradient','stop']);
  const elements=[],stack=[];let cursor=0,root=null;
  const entities=text=>assert(!text.replace(/&(?:amp|lt|gt|quot|apos|#\d+|#x[\da-f]+);/gi,'').includes('&'),'XML entity must be escaped');
  while(cursor<source.length){
    if(source[cursor]!=='<'){
      const end=source.indexOf('<',cursor),text=source.slice(cursor,end<0?source.length:end);entities(text);
      if(stack.length)stack.at(-1).text+=text;else assert.equal(text.trim(),'','Text outside XML root');
      cursor=end<0?source.length:end;continue;
    }
    assert(!source.startsWith('<!',cursor)&&!source.startsWith('<?',cursor),'XML declarations, DTDs and processing instructions are unsupported');
    let end=cursor+1,quote=null;
    for(;end<source.length;end++){const character=source[end];if(quote){if(character===quote)quote=null;}else if(character==='"'||character==="'")quote=character;else if(character==='>')break;}
    assert(end<source.length&&!quote,'Unterminated XML tag');
    const token=source.slice(cursor+1,end);cursor=end+1;
    if(token.startsWith('/')){const name=token.slice(1).trim();assert(/^[A-Za-z][\w:-]*$/.test(name),'Invalid XML closing tag');assert.equal(stack.pop()?.name,name,'Mismatched XML closing tag');continue;}
    const selfClosing=/\/\s*$/.test(token),body=selfClosing?token.replace(/\/\s*$/,''):token;
    const nameMatch=/^([A-Za-z][\w:-]*)/.exec(body);assert(nameMatch,'Invalid XML opening tag');const name=nameMatch[1];assert(allowed.has(name),'SVG element outside static subset');
    const attrs={};let tail=body.slice(name.length);
    while(tail.trim()){
      const match=/^\s+([A-Za-z_][\w:.-]*)\s*=\s*("[^"]*"|'[^']*')/.exec(tail);assert(match,'Invalid or unquoted XML attribute');
      const key=match[1],value=match[2].slice(1,-1);assert(!Object.hasOwn(attrs,key),'Duplicate XML attribute');assert(!/<|\u0000/.test(value),'Invalid XML attribute value');entities(value);
      assert(!/^on/i.test(key),'SVG event handler is forbidden');
      if(key!=='xmlns')assert(!/(?:https?:|data:|javascript:|file:|\/\/)/i.test(value),'External SVG reference is forbidden');
      if(/(?:^|:)href$|^src$/i.test(key))assert(/^#[\w-]+$/.test(value),'SVG references must be local fragments');
      attrs[key]=value;tail=tail.slice(match[0].length);
    }
    const node={name,attrs,text:'',parent:stack.at(-1)??null};
    if(!node.parent){assert.equal(root,null,'Multiple XML roots');assert.equal(name,'svg');root=node;}
    elements.push(node);if(!selfClosing)stack.push(node);
  }
  assert.equal(stack.length,0,'Unclosed XML element');assert(root,'Missing SVG root');return{root,elements};
}
function mediaBody(css,feature){
  const match=new RegExp('@media\\s*\\(\\s*'+feature+'\\s*\\)\\s*\\{','i').exec(css);assert(match,'Required CSS media rule is missing');
  let depth=1,end=match.index+match[0].length;const start=end;
  for(;end<css.length&&depth;end++){if(css[end]==='{')depth++;else if(css[end]==='}')depth--;}
  assert.equal(depth,0,'Unclosed CSS media rule');return css.slice(start,end-1);
}
test('SVG XML/accessibility and animation fallback are structurally checked for all three local assets',async()=>{
  for(const file of ['kya-hero.svg','evidence-flow.svg','dossier-atlas.svg']){
    const source=await readFile(new URL(`../assets/${file}`,import.meta.url),'utf8'),{root,elements}=svgTree(source);
    assert.equal(root.attrs.xmlns,'http://www.w3.org/2000/svg');assert.equal(root.attrs.role,'img');
    const viewBox=root.attrs.viewBox.split(/\s+/).map(Number);assert.equal(viewBox.length,4);assert(viewBox.every(Number.isFinite)&&viewBox[2]>0&&viewBox[3]>0);
    const ids=new Map();for(const node of elements)if(node.attrs.id){assert(!ids.has(node.attrs.id),'Duplicate SVG ID');ids.set(node.attrs.id,node);}
    const labels=root.attrs['aria-labelledby'].split(/\s+/);assert.equal(new Set(labels).size,labels.length);assert.equal(labels.length,2);
    assert.equal(ids.get(labels[0])?.name,'title');assert(ids.get(labels[0]).text.trim().length>10);
    assert.equal(ids.get(labels[1])?.name,'desc');assert(ids.get(labels[1]).text.trim().length>30);
    const styles=elements.filter(node=>node.name==='style');assert.equal(styles.length,1);const css=styles[0].text;
    assert.doesNotMatch(css,/@import|url\s*\(|https?:|data:|javascript:/i);
    const reduced=mediaBody(css,'prefers-reduced-motion\\s*:\\s*reduce');assert.match(reduced,/animation\s*:\s*none/);
    const animated=[...css.matchAll(/([.#][\w.-]+(?:\s*,\s*[.#][\w.-]+)*)\s*\{[^{}]*animation\s*:\s*(?!none\b)[^;}]+/g)].flatMap(match=>match[1].split(/\s*,\s*/));
    assert(animated.length>0);for(const selector of animated)assert(reduced.includes(selector),`Reduced-motion rule must address ${selector}`);
    assert(mediaBody(css,'prefers-color-scheme\\s*:\\s*dark').length>0);
    assert(elements.filter(node=>node.name==='text'&&node.text.trim()).length>=10,'Static labels survive without animation');
  }
});
test('the SVG structural checker rejects malformed XML, remote content, event handlers and duplicate attributes',()=>{
  for(const source of ['<svg><text></svg>','<svg><text/></svg><svg/>','<svg id="a" id="b"/>','<svg><script/></svg>','<!DOCTYPE svg><svg/>','<svg><text>&unknown;</text></svg>','<svg onclick="alert(1)"/>','<svg href="https://example.test/asset"/>'])assert.throws(()=>svgTree(source));
});
test('README uses meaningful local image descriptions and links resolve inside the packaged source tree',async()=>{
  const root=fileURLToPath(new URL('../',import.meta.url)),readme=await readFile(new URL('../README.md',import.meta.url),'utf8');
  assert.match(readme,/!\[[^\]]{10,}\]\(assets\/dossier-atlas\.svg\)/);
  for(const match of readme.matchAll(/<img\b[^>]*>/g)){assert.match(match[0],/alt="[^"\n]{10,}"/);assert.match(match[0],/src="assets\/[\w-]+\.svg"/);}
  const targets=[...readme.matchAll(/\[[^\]]*\]\(([^)\s]+)\)/g)].map(match=>match[1]).concat([...readme.matchAll(/<img\b[^>]*src="([^"]+)"/g)].map(match=>match[1]));
  const local=targets.filter(target=>!/^https?:\/\/|^#/.test(target));assert(local.length>10);
  for(const target of local){const file=resolve(root,target.split('#')[0]);assert(!relative(root,file).startsWith('..'+sep),'README link escapes package root');assert((await stat(file)).isFile(),`Missing local README target ${target}`);}
});
