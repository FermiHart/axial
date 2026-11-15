#!/usr/bin/env node
'use strict';
// Alternating local microbenchmark. No native build and no production claim.
const assert=require('node:assert/strict'),path=require('node:path'),{performance}=require('node:perf_hooks');
const tool=require('./portable-decision-build.cjs'),vm=require('../runtime/portable-decision-v2.js');
const program=JSON.parse(tool.exportPolicy(path.join(__dirname,'../examples/games/inventory.axi')));
const prepared=vm.prepare(program), n=20000, runs=[];
const input=Array.from({length:16},(_,mask)=>Object.fromEntries(program.params.map((k,i)=>[k,!!(mask&(1<<i))])));
const opts=[{fuel:0},{fuel:64}];
function execute(mode,record){
 const samples=[],counts={allow:0,deny:0,trap:0};let fuelUsed=0;
 for(let i=0;i<n;i++){
  const f=input[i%16],o=opts[i%17===0?0:1],t=performance.now();
  const r=mode==='public'?vm.evaluate(program,f,o):prepared.evaluate(f,o);
  if(record)samples.push((performance.now()-t)*1000);
  counts[r.allowed?'allow':r.ok?'deny':'trap']++;fuelUsed+=r.fuelUsed;
 }
 samples.sort((a,b)=>a-b);
 return {mode,iterations:n,counts,fuelUsed,microseconds:record?{median:samples[n/2],p99:samples[Math.ceil(n*.99)-1]}:null};
}
execute('public',false);execute('prepared',false);
for(let pair=0;pair<3;pair++){
 const order=pair%2?['prepared','public']:['public','prepared'];
 const results=order.map(mode=>execute(mode,true));
 assert.deepEqual(results[0].counts,results[1].counts);assert.equal(results[0].fuelUsed,results[1].fuelUsed);
 runs.push({pair,order,results});
}
console.log(JSON.stringify({node:process.version,platform:process.platform,arch:process.arch,
 sourceSha256:program.sourceSha256,compilerSourceDigest:program.compilerSourceDigest,
 runs,caveat:'Shared host Node CPU microbenchmark; warmup plus alternating order, no admission parsing, no FPS/capacity guarantee.'},null,2));
