'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
let available=true;try{require('node:sqlite');}catch{available=false;}
const {createInventoryPilot}=require('../examples/games/durable-inventory-pilot.cjs');
const {hash}=require('../runtime/games-admission-v1.cjs');
let bytes,entry;
if(available){bytes=Buffer.from(require('../tools/portable-decision-build.cjs').exportPolicy(path.resolve(__dirname,'../examples/games/inventory.axi')));entry={id:'inventory',schema:'inventory.facts.v1',version:1,digest:hash(bytes)};}
const alice={authenticated:true,actorId:'alice'},bob={authenticated:true,actorId:'bob'};
const request=o=>JSON.stringify({commandId:'reserve',resourceId:'car',expectedRevision:0,action:'reserve',target:null,...o});
function setup(t,extra={}){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'axi-pilot-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const config={filename:path.join(dir,'pilot.sqlite'),policyBytes:bytes,trustedEntry:entry,initialResourcesJson:JSON.stringify([{id:'car',revision:0,state:{owner:'alice',reserved:false}}]),...extra};const p=createInventoryPilot(config);t.after(()=>p.close());return {p,config};}
test('admitted C policy drives real durable reserve and replay after restart',{skip:!available},t=>{
 const {p,config}=setup(t),r=p.submit(alice,request());assert.equal(r.code,'COMMITTED');assert.equal(r.resource.state.reserved,true);p.close();
 const restored=createInventoryPilot(config);t.after(()=>restored.close());assert.deepEqual(restored.submit(alice,request()),JSON.parse(JSON.stringify(r)));assert.equal(restored.observe('car').revision,1);
});
test('stale observation after ownership transfer cannot authorize old owner',{skip:!available},t=>{
 const {p}=setup(t),observation=p.observe('car');assert.equal(observation.state.owner,'alice');
 assert.equal(p.submit(alice,request({commandId:'transfer',action:'transfer',target:'bob'})).code,'COMMITTED');
 assert.equal(p.submit(alice,request({expectedRevision:observation.revision})).code,'STALE');
 const denied=p.submit(alice,request({commandId:'reserve-again',expectedRevision:1}));assert.equal(denied.code,'DENY');assert.equal(denied.reason,'NotOwner');
 assert.equal(p.submit(bob,request({commandId:'bob-reserve',expectedRevision:1})).code,'COMMITTED');
});
test('policy revoked after observation but before commit refuses',{skip:!available},t=>{
 const {p}=setup(t);p.observe('car');p.revoke();const result=p.submit(alice,request());assert.equal(result.code,'DENY');assert.equal(result.reason,'policy-revoked');assert.equal(p.observe('car').revision,0);
});
test('revocation never reverses an already committed receipt',{skip:!available},t=>{
 const {p}=setup(t),r=p.submit(alice,request());p.revoke();assert.deepEqual(p.submit(alice,request()),JSON.parse(JSON.stringify(r)));assert.equal(p.observe('car').revision,1);
});
test('forged actor/facts and unauthenticated session cannot affect state',{skip:!available},t=>{
 const {p}=setup(t);assert.equal(p.submit({authenticated:false,actorId:'alice'},request()).code,'PILOT_INPUT');
 assert.equal(p.submit(bob,request({actorId:'alice',owns:true})).code,'PILOT_INPUT');assert.equal(p.submit(bob,request()).reason,'NotOwner');assert.equal(p.observe('car').revision,0);
});
test('tampered artifact and wrong schema fail before authority opens',{skip:!available},t=>{
 assert.throws(()=>setup(t,{policyBytes:Buffer.from('{}')}),/admission/);assert.throws(()=>setup(t,{trustedEntry:{...entry,schema:'wrong'}}),/schema/);
});
test('bounded input and fuel trap fail closed',{skip:!available},t=>{
 const {p}=setup(t,{fuel:0});assert.equal(p.submit(alice,' '.repeat(1025)).code,'PILOT_INPUT');assert.equal(p.submit(alice,request()).code,'TRAP');assert.equal(p.observe('car').revision,0);
});
test('receipt capacity preserves exact replay instead of evicting',{skip:!available},t=>{
 const {p}=setup(t,{maxReceipts:1}),r=p.submit(alice,request());assert.equal(p.submit(alice,request({commandId:'two',expectedRevision:1})).code,'RECEIPT_CAPACITY');assert.deepEqual(p.submit(alice,request()),JSON.parse(JSON.stringify(r)));
});
test('opt-in pilot revocation survives restart and denies fresh effects',{skip:!available},t=>{
 const {p,config}=setup(t,{persistedRevocation:true});assert.equal(p.revoke().code,'REVOKED');p.close();
 const reopened=createInventoryPilot(config);t.after(()=>reopened.close());const r=reopened.submit(alice,request());assert.equal(r.code,'DENY');assert.equal(r.reason,'policy-revoked');assert.equal(reopened.observe('car').revision,0);
});
