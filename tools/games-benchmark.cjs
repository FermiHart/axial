'use strict';
// Host microbenchmark only. Not a production throughput claim.
const {performance}=require('node:perf_hooks');
const path=require('node:path');
const tool=require('./portable-decision-build.cjs');
const A=require('../runtime/games-admission-v1.cjs');
const B=require('../runtime/games-budget-v1.cjs');
const bytes=Buffer.from(tool.exportPolicy(path.resolve(__dirname,'../tests/portable-decision/access.axi')));
const loader=A.createAdmission([{id:'access',schema:'v1',version:1,digest:A.hash(bytes)}]);
const handle=loader.admit('access',bytes);
const facts=Buffer.from(JSON.stringify({identityKnown:true,resourceAllowed:true,available:true}));
const times=[]; let count=0;
for(let batch=0;batch<100;batch++) {const start=performance.now();for(let i=0;i<100;i++) {if(!loader.evaluate(handle,facts).allowed)throw Error('unexpected deny');count++;} times.push((performance.now()-start)/100);}
times.sort((a,b)=>a-b);
const queue=B.create({queueItems:1000,queueBytes:262144,itemBytes:4096,tickUnits:1000,actorUnits:10});
for(let i=0;i<1000;i++)queue.enqueue('actor'+(i%100),'{}',1);
queue.beginTick(1);const batch=queue.takeBatch();if(batch.items.length!==1000)throw Error('budget regression');
console.log(JSON.stringify({node:process.version,platform:process.platform,arch:process.arch,evaluations:count,
 measure:'milliseconds per evaluation averaged over 100-call batches, includes parse/snapshot',
 batchMeanP50:times[50],batchMeanP95:times[95],batchMeanP99:times[99],heapUsed:process.memoryUsage().heapUsed,
 schedulerItems:batch.items.length,productionBenchmark:false},null,2));
