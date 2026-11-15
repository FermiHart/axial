'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const path=require('node:path');
const tool=require('../tools/portable-decision-build.cjs');
const runtime=require('../runtime/portable-decision-v2.js');
const facts=require('../examples/games/server-facts.cjs');
tool.build();
const programs={};
for(const name of ['door','inventory','race']) {
 const source=path.resolve(__dirname,'../examples/games',name+'.axi');
 const program=programs[name]=JSON.parse(tool.exportPolicy(source));
 test(name+' compiled policy matches C oracle for all facts and fuel prefixes',()=>{
  const rows=tool.run(tool.binary,['oracle',source]).trim().split('\n');
  const masks=new Set(); let allowed=0,denied=0,trapped=0;
  for(const row of rows) {
   const oracle=JSON.parse(row); masks.add(oracle.mask);
   const input=Object.fromEntries(program.params.map((p,i)=>[p,!!(oracle.mask & (1<<i))]));
   const got=runtime.evaluate(program,input,{fuel:oracle.fuel});
   assert.deepEqual({ok:got.ok,allowed:got.allowed,decision:got.decision,
    fuelUsed:got.fuelUsed,fuelLimit:got.fuelLimit,fuelExhausted:got.code==='AXI-R008'},
    {ok:oracle.ok,allowed:oracle.allowed,decision:oracle.decision,fuelUsed:oracle.fuelUsed,
    fuelLimit:oracle.fuelLimit,fuelExhausted:oracle.fuelExhausted});
   if(got.allowed)allowed++; else if(got.ok)denied++; else trapped++;
  }
  assert.equal(masks.size,16);assert.ok(allowed>0&&denied>0&&trapped>0);
  console.log(JSON.stringify({pilot:name,sourceSha256:program.sourceSha256,comparisons:rows.length,allowed,denied,trapped}));
 });
}
const session={authenticated:true,actorId:'alice'};
const state={doors:{door:{allowedActors:['bob'],locked:false}},
 items:{car:{owner:'bob',reservation:null}},races:{oval:{entrants:['bob'],phase:'racing'}}};
const definitions=[['door','doorFacts','door','AccessDenied'],['inventory','inventoryFacts','car','NotOwner'],['race','raceFacts','oval','NotEntered']];
for(const [name,derive,resourceId,reason] of definitions) {
 test(name+' server facts refuse forged claims through compiled Axial decision',()=>{
  const command={resourceId,actorId:'bob',authorized:true,owns:true,entered:true};
  const input=facts[derive](session,state,command);
  assert.deepEqual(runtime.evaluate(programs[name],input,{fuel:64}).decision,{kind:'deny',reason});
  assert.equal(runtime.evaluate(programs[name],input,{fuel:0}).allowed,false);
 });
 test(name+' authorized state allows without applying a world effect',()=>{
  const before=JSON.stringify(state);
  const input=facts[derive]({authenticated:true,actorId:'bob'},state,{resourceId});
  assert.deepEqual(runtime.evaluate(programs[name],input,{fuel:64}).decision,{kind:'allow'});
  assert.equal(JSON.stringify(state),before);
 });
}
