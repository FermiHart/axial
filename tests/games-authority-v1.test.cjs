'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {create} = require('../runtime/games-authority-v1.cjs');
const digest = 'a'.repeat(64);
const cmd = overrides => JSON.stringify({worldId:'game',commandId:'one',actorId:'alice',resourceId:'last-car',
 action:'buy',expectedRevision:0,policyDigest:digest,schemaVersion:1,payload:{},...overrides});
const setup = overrides => create({worldId:'game',policyDigest:digest,schemaVersion:1,
 resourcesJson:JSON.stringify([{id:'last-car',revision:0,state:{owner:'market',stock:1}}]),
 decide:({resource}) => ({allow:resource.state.stock > 0,reason:'stock'}),
 reduce:({command,resource}) => ({...resource.state,owner:command.actorId,stock:resource.state.stock-1}),...overrides});
test('commit and exact replay return same receipt without duplicate effect',()=>{
 const a=setup(); const r=a.execute(cmd()); assert.equal(r.code,'COMMITTED');
 assert.equal(a.execute(cmd()),r); assert.equal(a.inspect('last-car').revision,1); assert.equal(a.inspect('last-car').state.stock,0);
});
test('same command id with other actor/payload is refused',()=>{
 const a=setup(); a.execute(cmd()); assert.equal(a.execute(cmd({actorId:'bob'})).code,'COMMAND_CONFLICT');
});
test('two buyers cannot both buy last unit with same revision',()=>{
 const a=setup(); assert.equal(a.execute(cmd()).ok,true);
 assert.equal(a.execute(cmd({commandId:'two',actorId:'bob'})).code,'STALE');
 assert.equal(a.inspect('last-car').state.owner,'alice');
 assert.equal(a.execute(cmd({commandId:'three',actorId:'bob',expectedRevision:1})).code,'DENY');
});
test('binding rejects world/policy/schema mismatch without mutation',()=>{
 for(const v of [{worldId:'other'},{policyDigest:'b'.repeat(64)},{schemaVersion:2}]){
 const a=setup();assert.equal(a.execute(cmd(v)).code,'BINDING');assert.equal(a.inspect('last-car').revision,0);}
});
test('denial and trap do not run reducer or change state',()=>{
 let runs=0;for(const decide of [()=>({allow:false,reason:'owner'}),()=>{throw Error('trap')},()=>Promise.resolve(true)]){
 const a=setup({decide,reduce:()=>{runs++;return {}}});assert.equal(a.execute(cmd()).ok,false);assert.equal(a.inspect('last-car').revision,0);}
 assert.equal(runs,0);
});
test('reducer failure cannot partially commit; failure receipt replays',()=>{
 const a=setup({reduce:()=>{throw Error('fail')}}),r=a.execute(cmd());assert.equal(r.code,'TRAP');assert.equal(a.execute(cmd()),r);assert.equal(a.inspect('last-car').revision,0);
});
test('callback snapshots are immutable and reducer output is copied',()=>{
 let output={stock:0};const a=setup({decide:f=>{assert.ok(Object.isFrozen(f.resource.state));assert.ok(Object.isFrozen(f.command.payload));return {allow:true,reason:'ok'}},reduce:()=>output});
 a.execute(cmd()); output.stock=100;assert.equal(a.inspect('last-car').state.stock,0);
});
test('reentrancy is refused before a second command can mutate',()=>{
 let a;a=setup({decide:()=>{assert.equal(a.execute(cmd({commandId:'nested'})).code,'BUSY');return {allow:true,reason:'ok'}}});
 assert.equal(a.execute(cmd()).ok,true);assert.equal(a.stats().receipts,1);
});
test('bounded receipts fail closed, retain accepted command replay',()=>{
 const a=setup({maxReceipts:1}),r=a.execute(cmd());assert.equal(a.execute(cmd({commandId:'new',expectedRevision:1})).code,'RECEIPT_CAPACITY');assert.equal(a.execute(cmd()),r);
});
test('malformed oversized and nested data are rejected',()=>{
 const a=setup({maxCommandBytes:512});for(const c of ['{',{},' '.repeat(513),cmd({payload:{nested:{}}}),cmd({expectedRevision:-1}),cmd({extra:1})])assert.equal(a.execute(c).code,'INPUT');
});
test('semantic payload order produces same replay identity',()=>{
 const a=setup();const r=a.execute(cmd({payload:{b:2,a:1}}));assert.equal(a.execute(cmd({payload:{a:1,b:2}})),r);
});
test('safe revision limit fails closed',()=>{
 const a=setup({resourcesJson:JSON.stringify([{id:'last-car',revision:Number.MAX_SAFE_INTEGER,state:{stock:1}}])});
 assert.equal(a.execute(cmd({expectedRevision:Number.MAX_SAFE_INTEGER})).code,'REVISION_EXHAUSTED');
});
test('async reducer and non-record state refuse without commit',()=>{
 for(const reduce of [()=>Promise.resolve({stock:0}),()=>new Date(),()=>({[Symbol('hidden')]:true})]){
 const a=setup({reduce});assert.equal(a.execute(cmd()).code,'TRAP');assert.equal(a.inspect('last-car').revision,0);}
});
test('async callbacks are refused at creation before invocation',()=>{
 let called=false;const asyncCallback=async()=>{called=true;throw Error('must not run')};
 assert.throws(()=>setup({decide:asyncCallback}),TypeError);
 assert.throws(()=>setup({reduce:asyncCallback}),TypeError);
 assert.equal(called,false);
});
test('rejected native promises are observed without commit or process failure',()=>{
 const {spawnSync}=require('node:child_process');
 const script=`const assert=require('node:assert/strict');
 const {create}=require(${JSON.stringify(require.resolve('../runtime/games-authority-v1.cjs'))});
 const digest='a'.repeat(64);
 for(const role of ['decide','reduce']) {
 const opts={worldId:'game',policyDigest:digest,schemaVersion:1,
 resourcesJson:JSON.stringify([{id:'car',revision:0,state:{stock:1}}]),
 decide:()=>({allow:true,reason:'ok'}),reduce:()=>({stock:0})};
 opts[role]=()=>Promise.reject(Error('rejected '+role));
 const a=create(opts), c=JSON.stringify({worldId:'game',commandId:'one',actorId:'alice',resourceId:'car',action:'buy',expectedRevision:0,policyDigest:digest,schemaVersion:1,payload:{}});
 assert.equal(a.execute(c).code,'TRAP');assert.equal(a.inspect('car').revision,0);
 }
 setImmediate(()=>console.log('survived'));`;
 const result=spawnSync(process.execPath,['--unhandled-rejections=strict','-e',script],{encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/survived/);
});
test('arbitrary thenable is never assimilated',()=>{
 let calls=0;const value={then(){calls++;throw Error('must not call')}};
 for(const role of ['decide','reduce']){
 const a=setup({[role]:()=>value});assert.equal(a.execute(cmd()).code,'TRAP');assert.equal(a.inspect('last-car').revision,0);}
 assert.equal(calls,0);
});
