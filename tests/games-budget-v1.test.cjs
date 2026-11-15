'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const B=require('../runtime/games-budget-v1.cjs');
const make=()=>B.create({queueItems:8,queueBytes:64,itemBytes:16,tickUnits:6,actorUnits:3});
test('explicit ticks are monotonic and cannot refill the same tick',()=>{
 const q=make(); assert.equal(q.takeBatch().code,'AXB-NO-TICK');
 assert.equal(q.beginTick(1).ok,true); q.enqueue('a','{}',3); q.takeBatch();
 for(const t of [1,0,-1,NaN,Infinity,-0]) assert.equal(q.beginTick(t).ok,false);
 assert.equal(q.snapshot().usedUnits,3); assert.equal(q.beginTick(2).ok,true);
 assert.equal(q.snapshot().usedUnits,0);
});
test('per actor and total quotas persist over repeated batches',()=>{
 const q=make(); q.beginTick(1);
 for(const a of ['a','a','b','c']) q.enqueue(a,a,3);
 assert.deepEqual(q.takeBatch(1).items.map(x=>x.actorId),['a']);
 assert.deepEqual(q.takeBatch().items.map(x=>x.actorId),['b']);
 assert.equal(q.takeBatch().items.length,0); assert.equal(q.snapshot().queued,2);
 q.beginTick(2); assert.deepEqual(q.takeBatch().items.map(x=>x.actorId),['a','c']);
});
test('UTF8 byte bounds and queue bounds fail without mutation',()=>{
 const q=make(); assert.equal(q.enqueue('a','😀'.repeat(5)).code,'AXB-ITEM-BYTES');
 for(let i=0;i<4;i++) assert.equal(q.enqueue('a','x'.repeat(16)).ok,true);
 assert.equal(q.enqueue('b','x').code,'AXB-QUEUE-BYTES'); assert.equal(q.snapshot().queuedBytes,64);
 const c=make(); for(let i=0;i<8;i++) c.enqueue('a','');
 assert.equal(c.enqueue('b','').code,'AXB-QUEUE-COUNT');
});
test('invalid identities, payloads and costs do not execute or enter queue',()=>{
 const q=make(); let called=false; const p={toString(){called=true;return '{}'}};
 assert.equal(q.enqueue('a',p).ok,false); assert.equal(called,false);
 for(const a of ['', 'a\n', 'a b', 'x'.repeat(129)]) assert.equal(q.enqueue(a,'{}').ok,false);
 for(const cost of [0,-1,4,NaN,Infinity,1.5]) assert.equal(q.enqueue('a','{}',cost).ok,false);
 assert.equal(q.snapshot().queued,0);
});
test('same input sequence gives identical batches regardless of wallclock',()=>{
 const run=()=>{const q=make(),out=[]; for(let t=0;t<10;t++){
 q.beginTick(t);q.enqueue('a','{}',2);q.enqueue('b','[]',2);out.push(q.takeBatch());}return out};
 assert.deepEqual(run(),run());
});
test('snapshots and item records are frozen, capacity returns after draining',()=>{
 const q=make(); q.beginTick(0); q.enqueue('a','{}',2); const b=q.takeBatch();
 assert.throws(()=>{b.items.push({})},TypeError); assert.throws(()=>{b.items[0].workUnits=0},TypeError);
 assert.equal(q.snapshot().queuedBytes,0); assert.equal(Object.isFrozen(q.snapshot().limits),true);
});
test('configuration and batch sizes cannot bypass hard bounds',()=>{
 for(const opt of [{queueItems:0},{queueItems:5000},{actorUnits:9999},{tickUnits:Infinity},{extra:1}])
 assert.throws(()=>B.create(opt),TypeError);
 const q=make();q.beginTick(0); for(const n of [0,-1,9,NaN]) assert.equal(q.takeBatch(n).ok,false);
});
test('prototype names are not configuration limits',()=>{
 for(const key of ['toString','constructor','__proto__']) assert.throws(()=>B.create(JSON.parse('{"'+key+'":1}')));
});

test('pending actor caps protect queue capacity and release after selection',()=>{
 const q=B.create({queueItems:8,queueBytes:64,itemBytes:16,tickUnits:6,actorUnits:3,
  actorQueueItems:2,actorQueueBytes:20});
 assert.equal(q.enqueue('a','x'.repeat(16)).ok,true);
 assert.equal(q.enqueue('a','x'.repeat(5)).code,'AXB-ACTOR-QUEUE-BYTES');
 assert.equal(q.enqueue('a','x'.repeat(4)).ok,true);
 assert.equal(q.enqueue('a','').code,'AXB-ACTOR-QUEUE-COUNT');
 assert.equal(q.enqueue('b','{}').ok,true);
 q.beginTick(0);assert.equal(q.takeBatch().items.length,3);
 assert.equal(q.snapshot().queuedActors,0);
 assert.equal(q.enqueue('a','x'.repeat(16)).ok,true);
});
test('pending actor limits survive tick reset and reject invalid configuration',()=>{
 const q=B.create({actorQueueItems:1});q.enqueue('a','{}');q.beginTick(0);q.beginTick(1);
 assert.equal(q.enqueue('a','{}').code,'AXB-ACTOR-QUEUE-COUNT');
 for(const options of [{actorQueueItems:0},{actorQueueBytes:0},{queueItems:2,actorQueueItems:3},
  {queueBytes:20,itemBytes:10,actorQueueBytes:21}]) assert.throws(()=>B.create(options),TypeError);
});
