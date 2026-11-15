#!/usr/bin/env node
/* Copyright (c) 2026 Fermi Hart <contact@fermihart.com>
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
'use strict';
// Synthetic server scheduler workload, not RustRoots, network, rendering or mobile.
const assert=require('node:assert/strict');
const {performance}=require('node:perf_hooks');
const B=require('../runtime/games-budget-v1.cjs');
const ACTORS=1000, TICKS=100;
const q=B.create({queueItems:2048,queueBytes:262144,itemBytes:128,tickUnits:4096,actorUnits:8});
const payload=JSON.stringify({intent:'npc-policy',resourceId:'fixture',version:1});
const enqueueUs=[],batchUs=[],tickUs=[];
let peakQueued=0,peakBytes=0,peakHeap=process.memoryUsage().heapUsed,completed=0;
const startHeap=process.memoryUsage().heapUsed;
for(let tick=0;tick<TICKS;tick++) {
 const t0=performance.now(); assert.equal(q.beginTick(tick).ok,true);
 for(let actor=0;actor<ACTORS;actor++) {
  const before=performance.now();
  const result=q.enqueue('npc:'+actor,payload,2);
  enqueueUs.push((performance.now()-before)*1000);
  assert.equal(result.ok,true);
 }
 const pending=q.snapshot(); peakQueued=Math.max(peakQueued,pending.queued); peakBytes=Math.max(peakBytes,pending.queuedBytes);
 assert.ok(pending.queued<=pending.limits.queueItems && pending.queuedBytes<=pending.limits.queueBytes);
 const before=performance.now(),batch=q.takeBatch(); batchUs.push((performance.now()-before)*1000);
 assert.equal(batch.ok,true); assert.equal(batch.items.length,ACTORS); completed+=batch.items.length;
 assert.equal(q.snapshot().queued,0);assert.equal(q.snapshot().queuedBytes,0);
 tickUs.push((performance.now()-t0)*1000); peakHeap=Math.max(peakHeap,process.memoryUsage().heapUsed);
}
function stats(values) {
 const sorted=values.slice().sort((a,b)=>a-b), at=p=>sorted[Math.ceil(sorted.length*p)-1];
 return {samples:values.length,p50:at(.5),p95:at(.95),p99:at(.99),max:sorted.at(-1)};
}
console.log(JSON.stringify({profile:B.PROFILE,workload:'synthetic 1000 NPC actors, 100 ticks; queue only; no policy VM or world',
 node:process.version,platform:process.platform,arch:process.arch,actors:ACTORS,ticks:TICKS,completed,
 microseconds:{enqueue:stats(enqueueUs),batch:stats(batchUs),tickIncludingHarness:stats(tickUs)},
 memory:{startHeapBytes:startHeap,endHeapBytes:process.memoryUsage().heapUsed,observedPeakHeapBytes:peakHeap,
 note:'Process heap includes harness/timing arrays; GC uncontrolled; not maximum resident memory.'},
 queue:{peakItems:peakQueued,peakPayloadBytes:peakBytes,limits:q.snapshot().limits},
 caveat:'Not a production, browser, phone, networking, Axial policy execution or RustRoots performance claim.'},null,2));
