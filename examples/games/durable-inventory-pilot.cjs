/* Runnable integration reference, not a production inventory service.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
'use strict';
const {createAdmission}=require('../../runtime/games-admission-v1.cjs');
const {create}=require('../../runtime/games-authority-sqlite-v1.cjs');
const label=v=>typeof v==='string' && /^[A-Za-z0-9_.:-]{1,96}$/.test(v) && !/[\r\n]/.test(v);
const refuse=reason=>Object.freeze({ok:false,code:'PILOT_INPUT',reason});
function createInventoryPilot({filename,policyBytes,trustedEntry,initialResourcesJson,fuel=64,maxReceipts=4096}) {
  if(!Number.isSafeInteger(fuel)||fuel<0||fuel>64)throw TypeError('fuel bound');
  if(!trustedEntry || trustedEntry.schema!=='inventory.facts.v1' || trustedEntry.version!==1)throw TypeError('pilot schema');
  trustedEntry=Object.freeze({...trustedEntry});
  // Entry MUST be provided by trusted deployment, never a client or artifact itself.
  const loader=createAdmission([trustedEntry]), handle=loader.admit(trustedEntry.id,policyBytes);
  if(!handle)throw Error('Policy admission refused');
  let revoked=false;
  const authority=create({filename,worldId:'inventory-pilot',policyDigest:trustedEntry.digest,schemaVersion:1,
    resourcesJson:initialResourcesJson,maxReceipts,
    decide:({command,resource})=>{
      if(revoked)return {allow:false,reason:'policy-revoked'};
      // Facts reconstructed from the resource inside the SQLite transaction.
      const facts={authenticated:true,exists:true,owns:resource.state.owner===command.actorId,
        unreserved:resource.state.reserved===false};
      const result=loader.evaluate(handle,Buffer.from(JSON.stringify(facts)),{fuel});
      if(!result.ok)throw Error('Axial trap/refusal');
      return {allow:result.allowed,reason:result.allowed?'allowed':result.decision?.reason || 'policy-denied'};
    },
    reduce:({command,resource})=>{
      if(revoked)throw Error('Revoked policy cannot commit');
      if(command.action==='reserve')return {...resource.state,reserved:true};
      if(command.action==='transfer')return {...resource.state,owner:command.payload.target};
      throw Error('Unknown action');
    }});
  function submit(session,requestJson){
    // Session is authenticated infrastructure input, not supplied by the player.
    if(!session||session.authenticated!==true||!label(session.actorId))return refuse('identity');
    if(typeof requestJson!=='string'||Buffer.byteLength(requestJson)>1024)return refuse('bytes');
    let q;try{q=JSON.parse(requestJson);}catch{return refuse('json');}
    const keys=['commandId','resourceId','expectedRevision','action','target'];
    if(!q||typeof q!=='object'||Array.isArray(q)||Object.keys(q).length!==keys.length||keys.some(k=>!Object.hasOwn(q,k))||
      !label(q.commandId)||!label(q.resourceId)||!Number.isSafeInteger(q.expectedRevision)||q.expectedRevision<0||Object.is(q.expectedRevision,-0)||
      !['reserve','transfer'].includes(q.action)||
      (q.action==='reserve'?q.target!==null:!label(q.target)))return refuse('shape');
    return authority.execute(JSON.stringify({worldId:'inventory-pilot',commandId:q.commandId,
      actorId:session.actorId,resourceId:q.resourceId,expectedRevision:q.expectedRevision,action:q.action,
      policyDigest:trustedEntry.digest,schemaVersion:1,payload:q.action==='reserve'?{}:{target:q.target}}));
  }
  function observe(id){return authority.inspect(id);}
  function revoke(){revoked=true;return loader.revoke(trustedEntry.id);}
  return Object.freeze({submit,observe,revoke,close:()=>authority.close()});
}
module.exports={createInventoryPilot};
if(require.main===module){
  const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
  const compiler=require('../../tools/portable-decision-build.cjs'),{hash}=require('../../runtime/games-admission-v1.cjs');
  compiler.build();const policyBytes=Buffer.from(compiler.exportPolicy(path.join(__dirname,'inventory.axi')));
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'axial-inventory-pilot-'));
  const pilot=createInventoryPilot({filename:path.join(directory,'pilot.sqlite'),policyBytes,
    trustedEntry:{id:'inventory',schema:'inventory.facts.v1',version:1,digest:hash(policyBytes)},
    initialResourcesJson:JSON.stringify([{id:'car',revision:0,state:{owner:'alice',reserved:false}}])});
  try{
    const request=JSON.stringify({commandId:'reserve-1',resourceId:'car',expectedRevision:0,action:'reserve',target:null});
    console.log(JSON.stringify({first:pilot.submit({authenticated:true,actorId:'alice'},request),
      replay:pilot.submit({authenticated:true,actorId:'alice'},request),resource:pilot.observe('car')},null,2));
  }finally{pilot.close();fs.rmSync(directory,{recursive:true,force:true});}
}
