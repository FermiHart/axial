'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const path=require('node:path');
const tool=require('../tools/portable-decision-build.cjs');
const vm=require('../runtime/portable-decision-v2.js');
const admission=require('../runtime/games-admission-v1.cjs');
tool.build();
const program=JSON.parse(tool.exportPolicy(path.join(__dirname,'../examples/games/inventory.axi')));
const copy=x=>JSON.parse(JSON.stringify(x));
const facts=mask=>Object.fromEntries(program.params.map((k,i)=>[k,!!(mask&(1<<i))]));
test('prepared evaluation preserves every result field across masks and fuel',()=>{
 const p=vm.prepare(program);
 for(let m=0;m<16;m++) for(let fuel=0;fuel<=4096;fuel+=fuel<64?1:257)
  assert.deepEqual(p.evaluate(facts(m),{fuel}),vm.evaluate(program,facts(m),{fuel}));
 assert.deepEqual(p.evaluate(facts(15),{fuel:4096}),vm.evaluate(program,facts(15),{fuel:4096}));
});
test('prepared owns snapshot and exposes no mutable program or bypass',()=>{
 const input=copy(program), p=vm.prepare(input), expected=vm.evaluate(program,facts(15),{fuel:64});
 input.code.fill(255);input.params[0]='altered';input.constants.forEach(k=>k.atom='Other');
 input.returnType.errors.push('Other');input.fuelMax=1;input.bodyHash='0'.repeat(64);
 assert.deepEqual(Object.keys(p),['evaluate']);assert.ok(Object.isFrozen(p));assert.ok(Object.isFrozen(p.evaluate));
 assert.throws(()=>{p.evaluate=()=>({allowed:true});},TypeError);
 assert.deepEqual(p.evaluate(facts(15),{fuel:64}),expected);
 assert.equal(vm.evaluate(input,facts(15),{fuel:64}).ok,false);
});
test('invalid preparation refuses without getters and leaves public validation intact',()=>{
 const accessor=copy(program);let invoked=0;
 Object.defineProperty(accessor,'code',{get(){invoked++;throw Error();},enumerable:true});
 for(const p of [null,{},accessor,{...program,code:[255]}, {...program,format:'wrong'},
  {...program,params:['duplicate','duplicate']},new Proxy({}, {ownKeys(){throw Error();}})]) {
  assert.equal(vm.prepare(p),null);assert.equal(vm.validate(p),false);
 }
 assert.equal(invoked,0);
});
test('prepared still checks facts/options descriptors and types on each call',()=>{
 const p=vm.prepare(program);
 const accessor=facts(15);let reads=0;
 Object.defineProperty(accessor,program.params[0],{get(){reads++;return true;},enumerable:true});
 for(const f of [null,{},[],accessor,{...facts(15),extra:true},{...facts(15),[program.params[0]]:1}])
  assert.deepEqual(p.evaluate(f,{fuel:64}),vm.evaluate(program,f,{fuel:64}));
 for(const opt of [null,{}, {fuel:-0},{fuel:-1},{fuel:4097},{fuel:1.5},{fuel:'64'},{fuel:64,extra:true}])
  assert.deepEqual(p.evaluate(facts(15),opt),vm.evaluate(program,facts(15),opt));
 const f=facts(15);assert.equal(p.evaluate(f,{fuel:64}).allowed,true);f[program.params[0]]=false;
 assert.equal(p.evaluate(f,{fuel:64}).allowed,false);assert.equal(reads,0);
});
test('prepared host admission keeps revocation, isolation, bytes and digest guards',()=>{
 const bytes=Buffer.from(JSON.stringify(program)), digest=admission.hash(bytes);
 const manifest=[{id:'policy',schema:'facts',version:1,digest}];
 const loader=admission.createAdmission(manifest), other=admission.createAdmission(manifest);
 const h=loader.admit('policy',bytes);assert.ok(h);bytes.fill(0);
 const f=Buffer.from(JSON.stringify(facts(15)));
 assert.equal(loader.evaluate(h,f,{fuel:64}).allowed,true);
 assert.equal(other.evaluate(h,f,{fuel:64}).code,'AXG-ADMISSION');
 assert.equal(loader.admit('policy',bytes),null);
 for(const bad of [Buffer.from('{'),Buffer.alloc(4097),new Uint8Array(f)])
  assert.equal(loader.evaluate(h,bad,{fuel:64}).code,'AXG-ADMISSION');
 assert.equal(loader.evaluate(h,Buffer.from('{}'),{fuel:64}).code,'AXP-A001');
 assert.equal(loader.evaluate(h,f,{fuel:0}).code,'AXI-R008');
 assert.equal(loader.revoke('policy'),true);
 assert.equal(loader.evaluate(h,f,{fuel:64}).code,'AXG-ADMISSION');
 assert.equal(loader.admit('policy',Buffer.from(JSON.stringify(program))),null);
});
test('structurally valid trap programs and bounded adversarial mutations stay equivalent',()=>{
 const word=(op,a=0,b=0,c=0)=>(op|(a<<8)|(b<<16)|(c<<24))>>>0;
 const codes=[[word(22)],[word(0)],[word(15,0)],[word(8,0,31),word(15,0)],
  [word(9,0,30,31),word(15,0)],[word(13,31,0,1),word(15,31)]];
 let comparisons=0;
 for(const code of codes) {
  const candidate={...copy(program),registers:32,code};
  const p=vm.prepare(candidate);assert.ok(p);
  for(const fuel of [0,1,2,3,64,4096])for(const mask of [0,15]) {
   assert.deepEqual(p.evaluate(facts(mask),{fuel}),vm.evaluate(candidate,facts(mask),{fuel}));comparisons++;
  }
 }
 let seed=0x7ea5beef;
 for(let i=0;i<256;i++){
  seed=(Math.imul(seed,1664525)+1013904223)>>>0;
  const candidate=copy(program);candidate.code[i%candidate.code.length]=seed;
  const p=vm.prepare(candidate);
  if(p)for(const mask of [0,15])assert.deepEqual(p.evaluate(facts(mask),{fuel:64}),vm.evaluate(candidate,facts(mask),{fuel:64}));
  else assert.equal(vm.validate(candidate),false);
 }
 assert.equal(comparisons,72);
});
test('admission rejects cross-realm shared backing for both policy and facts',()=>{
 const realm=require('node:vm'), bytes=Buffer.from(JSON.stringify(program));
 const shared=Buffer.from(realm.runInNewContext('new SharedArrayBuffer('+bytes.length+')'));bytes.copy(shared);
 const loader=admission.createAdmission([{id:'p',schema:'f',version:1,digest:admission.hash(bytes)}]);
 assert.equal(loader.admit('p',shared),null);
 const h=loader.admit('p',bytes), factsBytes=Buffer.from(JSON.stringify(facts(15)));
 const sharedFacts=Buffer.from(realm.runInNewContext('new SharedArrayBuffer('+factsBytes.length+')'));factsBytes.copy(sharedFacts);
 assert.equal(loader.evaluate(h,sharedFacts,{fuel:64}).code,'AXG-ADMISSION');
 assert.equal(loader.evaluate(h,factsBytes,{fuel:64}).allowed,true);
});
