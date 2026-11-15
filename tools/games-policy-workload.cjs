#!/usr/bin/env node
/* Copyright (c) 2026 Fermi Hart <contact@fermihart.com>
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
'use strict';
// Reproducible synthetic policy workload, NOT a deployed game benchmark.
const assert=require('node:assert/strict');
const path=require('node:path');
const {performance}=require('node:perf_hooks');
const build=require('./portable-decision-build.cjs');
const admission=require('../runtime/games-admission-v1.cjs');
const budget=require('../runtime/games-budget-v1.cjs');
const ACTORS=1000,TICKS=100,ADMISSIONS=100;
const source=path.join(__dirname,'../examples/games/inventory.axi');
const setupStart=performance.now();
build.build();
const artifact=Buffer.from(build.exportPolicy(source),'utf8');
const program=JSON.parse(artifact.toString('utf8'));
const setupMs=performance.now()-setupStart;
// Trusted manifest comes from this local compiled fixture, never the workload packet.
const digest=admission.hash(artifact);
const loader=admission.createAdmission([{id:'inventory-fixture',schema:'inventory-facts-v1',version:1,digest}]);
const samples={admission:[],enqueue:[],batch:[],evaluation:[],tickIncludingHarness:[]};
let handle;
for(let i=0;i<ADMISSIONS;i++) {
 const start=performance.now();handle=loader.admit('inventory-fixture',artifact);
 samples.admission.push((performance.now()-start)*1000);assert.ok(handle);
}
const tampered=Buffer.from(artifact);tampered[0]^=1;
assert.equal(loader.admit('inventory-fixture',tampered),null);
const q=budget.create({queueItems:2048,queueBytes:524288,itemBytes:256,tickUnits:4096,actorUnits:8});
const counts={evaluations:0,allow:0,deny:0,fuelTrap:0},seenMasks=new Set();
let peakQueued=0,peakBytes=0;
const heapSamples=[];
const sampleHeap=()=>heapSamples.push(process.memoryUsage().heapUsed);
sampleHeap();
for(let tick=0;tick<TICKS;tick++) {
 const tickStart=performance.now();assert.equal(q.beginTick(tick).ok,true);
 for(let actor=0;actor<ACTORS;actor++) {
  const ordinal=tick*ACTORS+actor,mask=ordinal%16,fuel=ordinal%17===0?0:64;
  // These are synthetic authoritative host facts, not facts accepted from players.
  const facts=Object.fromEntries(program.params.map((name,i)=>[name,!!(mask&(1<<i))]));
  const payload=JSON.stringify({mask,fuel,facts});
  const start=performance.now(),result=q.enqueue('npc:'+actor,payload,2);
  samples.enqueue.push((performance.now()-start)*1000);assert.equal(result.ok,true);
 }
 const pending=q.snapshot();peakQueued=Math.max(peakQueued,pending.queued);peakBytes=Math.max(peakBytes,pending.queuedBytes);
 assert.ok(pending.queued<=pending.limits.queueItems && pending.queuedBytes<=pending.limits.queueBytes);
 const batchStart=performance.now(),batch=q.takeBatch();samples.batch.push((performance.now()-batchStart)*1000);
 assert.equal(batch.ok,true);assert.equal(batch.items.length,ACTORS);assert.equal(batch.units,ACTORS*2);
 for(const item of batch.items) {
  const message=JSON.parse(item.payload),factsBytes=Buffer.from(JSON.stringify(message.facts));
  const start=performance.now(),result=loader.evaluate(handle,factsBytes,{fuel:message.fuel});
  samples.evaluation.push((performance.now()-start)*1000);counts.evaluations++;seenMasks.add(message.mask);
  assert.equal(result.policy.digest,digest);
  if(message.fuel===0) {
   assert.equal(result.ok,false);assert.equal(result.allowed,false);assert.equal(result.code,'AXI-R008');
   assert.equal(result.decision,null);counts.fuelTrap++;
  } else if(message.mask===15) {
   assert.equal(result.ok,true);assert.equal(result.allowed,true);
   assert.deepEqual(result.decision,{kind:'allow'});counts.allow++;
  } else {
   const reasons=['IdentityUnknown','NotFound','NotOwner','Reserved'];
   const first=program.params.findIndex(name=>!message.facts[name]);
   assert.equal(result.ok,true);assert.equal(result.allowed,false);
   assert.deepEqual(result.decision,{kind:'deny',reason:reasons[first]});counts.deny++;
  }
 }
 assert.equal(q.snapshot().queued,0);assert.equal(q.snapshot().queuedBytes,0);
 samples.tickIncludingHarness.push((performance.now()-tickStart)*1000);sampleHeap();
}
assert.equal(counts.evaluations,ACTORS*TICKS);assert.equal(seenMasks.size,16);
assert.ok(counts.allow>0 && counts.deny>0 && counts.fuelTrap>0);
function stats(values) {
 const sorted=values.slice().sort((a,b)=>a-b),at=p=>sorted[Math.ceil(sorted.length*p)-1];
 return {samples:values.length,p50:at(.5),p95:at(.95),p99:at(.99),max:sorted.at(-1)};
}
const timing=Object.fromEntries(Object.entries(samples).map(([k,v])=>[k,stats(v)]));
sampleHeap();
console.log(JSON.stringify({workload:'1000 actors x 100 ticks; queue + admitted native-compiled inventory policy',
 node:process.version,platform:process.platform,arch:process.arch,actors:ACTORS,ticks:TICKS,
 policy:{profile:program.format,sourceSha256:program.sourceSha256,compilerSourceDigest:program.compilerSourceDigest,
  artifactDigest:digest,artifactBytes:artifact.length},buildAndExportMilliseconds:setupMs,
 counts,microseconds:timing,
 heap:{samples:heapSamples.length,startBytes:heapSamples[0],endBytes:heapSamples.at(-1),sampledPeakBytes:Math.max(...heapSamples),
  note:'Process heap includes benchmark timing arrays and assertions; GC uncontrolled, no heap cap proven.'},
 queue:{peakItems:peakQueued,peakPayloadBytes:peakBytes,limits:q.snapshot().limits},
 caveat:'Synthetic Node CPU test only. No RustRoots world, mobile/browser, network, renderer, server transaction or concurrent workers. No production capacity claim.'},null,2));
