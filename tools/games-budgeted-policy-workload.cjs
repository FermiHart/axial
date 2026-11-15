#!/usr/bin/env node
/* Copyright (c) 2026 Fermi Hart <contact@fermihart.com>
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
'use strict';
// Deliberately trades decision frequency for bounded work per logical tick.
const assert=require('node:assert/strict'),path=require('node:path');
const {performance}=require('node:perf_hooks');
const build=require('./portable-decision-build.cjs');
const admission=require('../runtime/games-admission-v1.cjs');
const budget=require('../runtime/games-budget-v1.cjs');
const ACTORS=1000,COHORTS=100,BATCHES=[64,128,256,1000];
build.build();
const bytes=Buffer.from(build.exportPolicy(path.join(__dirname,'../examples/games/inventory.axi')));
const program=JSON.parse(bytes.toString('utf8')),digest=admission.hash(bytes);
const loader=admission.createAdmission([{id:'inventory',schema:'inventory-v1',version:1,digest}]);
const handle=loader.admit('inventory',bytes);assert.ok(handle);
function statistics(values){const s=values.slice().sort((a,b)=>a-b),at=p=>s[Math.ceil(s.length*p)-1];
 return {samples:s.length,p50:at(.5),p95:at(.95),p99:at(.99),max:s.at(-1)};}
const results=[];
let expected;
for(const maxPerTick of BATCHES){
 const q=budget.create({queueItems:2048,queueBytes:524288,itemBytes:256,tickUnits:4096,actorUnits:8});
 const counts={allow:0,deny:0,fuelTrap:0,evaluations:0}, completed=new Uint8Array(ACTORS*COHORTS);
 const tickUs=[],serviceUs=[],evaluationUs=[],waitTicks=[];
 let tick=0,peakBacklog=0,peakBytes=0,peakHeap=process.memoryUsage().heapUsed;
 const started=performance.now();
 for(let cohort=0;cohort<COHORTS;cohort++){
  assert.equal(q.snapshot().queued,0);
  const submittedAt=tick;
  // Rotate each cohort's first actor. These HOST scheduling identities/ordinals
  // are not accepted from client claims and do not prove general fairness.
  for(let index=0;index<ACTORS;index++){
   const actor=(index+cohort)%ACTORS,ordinal=cohort*ACTORS+actor;
   const mask=ordinal%16,fuel=ordinal%17===0?0:64;
   const facts=Object.fromEntries(program.params.map((name,i)=>[name,!!(mask&(1<<i))]));
   assert.equal(q.enqueue('npc:'+actor,JSON.stringify({ordinal,mask,fuel,facts}),2).ok,true);
  }
  peakBacklog=Math.max(peakBacklog,q.snapshot().queued);peakBytes=Math.max(peakBytes,q.snapshot().queuedBytes);
  do{
   const tickStart=performance.now();assert.equal(q.beginTick(tick).ok,true);
   const serviceStart=performance.now(),batch=q.takeBatch(maxPerTick);
   assert.equal(batch.ok,true);assert.ok(batch.items.length>0&&batch.items.length<=maxPerTick);
   for(const item of batch.items){
    const message=JSON.parse(item.payload),factsBytes=Buffer.from(JSON.stringify(message.facts));
    assert.ok(Number.isSafeInteger(message.ordinal)&&message.ordinal>=0&&message.ordinal<completed.length);
    assert.equal(completed[message.ordinal],0);completed[message.ordinal]=1;
    const evaluationStart=performance.now(),result=loader.evaluate(handle,factsBytes,{fuel:message.fuel});
    evaluationUs.push((performance.now()-evaluationStart)*1000);counts.evaluations++;
    if(message.fuel===0){assert.equal(result.code,'AXI-R008');assert.equal(result.allowed,false);counts.fuelTrap++;}
    else if(message.mask===15){assert.equal(result.allowed,true);assert.deepEqual(result.decision,{kind:'allow'});counts.allow++;}
    else{assert.equal(result.allowed,false);const first=program.params.findIndex(name=>!message.facts[name]);
     assert.deepEqual(result.decision,{kind:'deny',reason:['IdentityUnknown','NotFound','NotOwner','Reserved'][first]});counts.deny++;}
    waitTicks.push(tick-submittedAt);
   }
   serviceUs.push((performance.now()-serviceStart)*1000);
   assert.ok(q.snapshot().queued<=q.snapshot().limits.queueItems);
   assert.ok(q.snapshot().queuedBytes<=q.snapshot().limits.queueBytes);
   tickUs.push((performance.now()-tickStart)*1000);tick++;
   peakHeap=Math.max(peakHeap,process.memoryUsage().heapUsed);
  }while(q.snapshot().queued>0);
  assert.equal(q.snapshot().queuedBytes,0);
 }
 assert.equal(counts.evaluations,ACTORS*COHORTS);assert.ok(completed.every(x=>x===1));
 assert.equal(tick,COHORTS*Math.ceil(ACTORS/maxPerTick));
 if(expected)assert.deepEqual(counts,expected);else expected={...counts};
 results.push({maxEvaluationsPerTick:maxPerTick,logicalTicks:tick,cohorts:COHORTS,counts,
  observedTotalMilliseconds:performance.now()-started,
  microseconds:{evaluation:statistics(evaluationUs),serviceAndAssertions:statistics(serviceUs),tickWithoutCohortIngress:statistics(tickUs)},
  queueWaitLogicalTicks:statistics(waitTicks),peakBacklog,peakPayloadBytes:peakBytes,
  sampledPeakHeapBytes:peakHeap});
}
console.log(JSON.stringify({node:process.version,platform:process.platform,arch:process.arch,
 artifactDigest:digest,compilerSourceDigest:program.compilerSourceDigest,sourceSha256:program.sourceSha256,
 actors:ACTORS,decisionsPerCase:ACTORS*COHORTS,results,
 caveat:'Same 100000 decisions but different logical duration/frequency. Next cohort waits for backlog to drain: finite closed-loop workload, not a sustained open-loop arrival test. Tick timing excludes cohort ingress; total timing includes it. No dropping. No speedup, fairness, 60Hz or production claim. Heap includes timing arrays and previous cases until GC.'},null,2));
