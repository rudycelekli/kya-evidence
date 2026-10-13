import { canonical, digest, insist } from '../../shared/canonical.mjs';

/** Lossy, non-executing declaration import. No proof/TEE/authorization validation. */
export function importDeclarations(format, value) {
  const input=JSON.parse(canonical(value));
  insist(input && typeof input==='object' && !Array.isArray(input),'Declaration must be an object');
  const pickString=(v,max=512)=>typeof v==='string' && v.length<=max ? v : null;
  const pickStrings=v=>Array.isArray(v) ? v.filter(x=>typeof x==='string' && x.length<=256).slice(0,128) : [];
  let identity,declared,recognized;
  if(format==='open-kya-alpha') {
    const required=['@context','id','type','kyaVersion','agentId','verificationMethod','authentication','assertionMethod','capabilityInvocation','proof'];
    insist(required.every(k=>Object.hasOwn(input,k)),'Missing Open-KYA alpha declaration fields');
    const types=Array.isArray(input.type)?input.type:[input.type];
    const contexts=Array.isArray(input['@context'])?input['@context']:[input['@context']];
    insist(types.includes('VerifiablePresentation') && types.includes('KyaManifest') && contexts.includes('https://w3id.org/kya/v1'),'Not a recognized Open-KYA alpha declaration');
    identity={externalAgentId:pickString(input.agentId),displayName:pickString(input.name??input.label),controllerRef:pickString(input.governingAuthority)};
    declared={version:pickString(input.kyaVersion),permissionMode:pickString(input.permissionMode),domains:pickStrings(input.permittedDomains),permittedRegions:pickStrings(input.permittedRegions),forbiddenRegions:pickStrings(input.forbiddenRegions),maxTransactionValue:Number.isSafeInteger(input.maxTransactionValue)?input.maxTransactionValue:null,currency:pickString(input.currency),operatingLimitsDigest:input.operatingLimits?digest(input.operatingLimits):null};
    recognized=new Set([...required,'name','label','governingAuthority','permissionMode','permittedDomains','permittedRegions','forbiddenRegions','maxTransactionValue','currency','operatingLimits']);
  } else if(format==='a2a-1') {
    insist(typeof input.name==='string' && Array.isArray(input.skills),'Not a recognized A2A declaration shape');
    identity={externalAgentId:null,displayName:pickString(input.name),controllerRef:null};
    declared={version:pickString(input.version),skillIds:input.skills.map(x=>pickString(x?.id,128)).filter(Boolean).slice(0,128),capabilitiesDigest:input.capabilities?digest(input.capabilities):null,securitySchemeNames:input.securitySchemes && typeof input.securitySchemes==='object'?Object.keys(input.securitySchemes).slice(0,128):[]};
    recognized=new Set(['name','version','skills','capabilities','securitySchemes']);
  } else throw new Error('Unsupported declaration format; use open-kya-alpha or a2a-1');
  return {schema:'kya.declaration-import/v1',format,sourceDigest:digest(input),identity,declared,unsupportedFields:Object.keys(input).filter(k=>!recognized.has(k)).sort(),unverified:['external identity','controller consent and legal authority','cryptographic proofs and credentials','hardware attestation','runtime enforcement','behavior and quality'],limitations:['Partial declaration mapping only; no standards conformance asserted','No score or permission grant is produced','Transaction units are retained without currency conversion','No source scripts, URLs or credentials are executed or resolved']};
}
