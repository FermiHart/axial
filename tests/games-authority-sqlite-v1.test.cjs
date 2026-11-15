'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawn,spawnSync}=require('node:child_process');
let available=true;try{require('node:sqlite');}catch{available=false;}
const {create}=require('../runtime/games-authority-sqlite-v1.cjs');
const child=path.join(__dirname,'fixtures/games-authority-sqlite-child.cjs'),digest='a'.repeat(64);
const opts=filename=>({filename,worldId:'game',policyDigest:digest,schemaVersion:1,
 resourcesJson:JSON.stringify([{id:'car',revision:0,state:{owner:'market',stock:1}}]),
 decide:({resource})=>({allow:resource.state.stock>0,reason:'stock'}),
 reduce:({resource,command})=>({...resource.state,owner:command.actorId,stock:resource.state.stock-1})});
const cmd=overrides=>JSON.stringify({worldId:'game',commandId:'one',actorId:'alice',resourceId:'car',action:'buy',expectedRevision:0,policyDigest:digest,schemaVersion:1,payload:{},...overrides});
function fixture(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'axial-sqlite-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));return path.join(dir,'authority.sqlite');}
const run=(db,id,actor,mode='')=>spawnSync(process.execPath,[child,db,id,actor,mode],{encoding:'utf8'});
test('SQLite optional runtime available',{skip:!available && 'node:sqlite unavailable; requires Node >=22.13 without flags'},()=>{assert.ok(available);});
test('restart preserves resource and receipt; no repeat mutation',{skip:!available},t=>{
 const db=fixture(t);let a=create(opts(db));const r=a.execute(cmd());a.close();
 a=create(opts(db));assert.deepEqual(a.execute(cmd()),JSON.parse(JSON.stringify(r)));assert.equal(a.inspect('car').revision,1);assert.equal(a.inspect('car').state.stock,0);a.close();
});
test('process exits after COMMIT without response; retry returns durable receipt',{skip:!available},t=>{
 const db=fixture(t),first=run(db,'one','alice','lost-response');assert.equal(first.status,0,first.stderr);assert.equal(first.stdout,'');
 const second=run(db,'one','alice');assert.equal(second.status,0,second.stderr);const r=JSON.parse(second.stdout);assert.equal(r.code,'COMMITTED');assert.equal(r.revision,1);
 const a=create(opts(db));assert.equal(a.inspect('car').revision,1);a.close();
});
test('two processes contend on last resource and only one commits',{skip:!available},async t=>{
 const db=fixture(t);create(opts(db)).close();
 function purchase(id){return new Promise((resolve,reject)=>{const p=spawn(process.execPath,[child,db,id,id]);let out='',err='';p.stdout.on('data',v=>out+=v);p.stderr.on('data',v=>err+=v);p.on('error',reject);p.on('close',code=>{if(code!==0)reject(Error(err));else resolve(JSON.parse(out));});});}
 const results=await Promise.all([purchase('alice'),purchase('bob')]);assert.deepEqual(results.map(r=>r.code).sort(),['COMMITTED','STALE']);
 const a=create(opts(db));assert.equal(a.inspect('car').revision,1);assert.equal(a.inspect('car').state.stock,0);a.close();
});
test('binding persisted and existing DB never reseeded',{skip:!available},t=>{
 const db=fixture(t);const a=create(opts(db));a.execute(cmd());a.close();
 assert.throws(()=>create({...opts(db),policyDigest:'b'.repeat(64)}),/binding/);
 const b=create({...opts(db),resourcesJson:'[]'});assert.equal(b.inspect('car').state.owner,'alice');b.close();
});
test('trap, denial and invalid output cannot mutate; receipts survive reopen',{skip:!available},t=>{
 const db=fixture(t);let a=create({...opts(db),reduce:()=>{throw Error('fail')}});assert.equal(a.execute(cmd()).code,'TRAP');assert.equal(a.inspect('car').revision,0);a.close();
 a=create(opts(db));assert.equal(a.execute(cmd()).code,'TRAP');assert.equal(a.inspect('car').revision,0);a.close();
});
test('durable bounded receipts never evict or reapply commands',{skip:!available},t=>{
 const db=fixture(t);const a=create({...opts(db),maxReceipts:1});const r=a.execute(cmd());assert.equal(a.execute(cmd({commandId:'two'})).code,'RECEIPT_CAPACITY');assert.equal(a.execute(cmd({actorId:'bob'})).code,'COMMAND_CONFLICT');assert.deepEqual(JSON.parse(JSON.stringify(a.execute(cmd()))),JSON.parse(JSON.stringify(r)));a.close();
});
test('lock contention fails closed and succeeds after rollback',{skip:!available},t=>{
 const db=fixture(t);const a=create({...opts(db),busyTimeoutMs:1});const {DatabaseSync}=require('node:sqlite');const locked=new DatabaseSync(db);locked.exec('BEGIN IMMEDIATE');
 assert.equal(a.execute(cmd()).code,'BUSY');assert.equal(a.inspect('car').revision,0);locked.exec('ROLLBACK');locked.close();assert.equal(a.execute(cmd()).code,'COMMITTED');a.close();
});
test('rollback atomicity on SQL receipt failure',{skip:!available},t=>{
 const db=fixture(t);const a=create(opts(db));const {DatabaseSync}=require('node:sqlite');const d=new DatabaseSync(db);
 d.exec("CREATE TRIGGER reject_receipt BEFORE INSERT ON axial_receipts BEGIN SELECT RAISE(ABORT,'forced receipt failure'); END;");
 assert.equal(a.execute(cmd()).code,'STORAGE');assert.equal(a.inspect('car').revision,0);assert.equal(d.prepare('SELECT count(*) n FROM axial_receipts').get().n,0);
 d.exec('DROP TRIGGER reject_receipt');d.close();assert.equal(a.execute(cmd()).code,'COMMITTED');a.close();
});
test('reentrancy and closed handle refuse without mutation',{skip:!available},t=>{
 const db=fixture(t);let a;a=create({...opts(db),decide:()=>{assert.equal(a.execute(cmd({commandId:'nested'})).code,'BUSY');assert.equal(a.close(),false);return {allow:true,reason:'ok'}}});assert.equal(a.execute(cmd()).ok,true);a.close();assert.equal(a.execute(cmd()).code,'CLOSED');
});
test('opt-in revocation persists across reopen; committed receipts remain replayable',{skip:!available},t=>{
 const db=fixture(t);let a=create({...opts(db),persistedRevocation:true});const r=a.execute(cmd());assert.equal(a.revokePolicy().code,'REVOKED');a.close();
 a=create({...opts(db),persistedRevocation:true});assert.deepEqual(a.execute(cmd()),JSON.parse(JSON.stringify(r)));
 const denied=a.execute(cmd({commandId:'after-revoke',expectedRevision:1}));assert.equal(denied.code,'DENY');assert.equal(denied.reason,'policy-revoked');assert.equal(a.inspect('car').revision,1);a.close();
 assert.throws(()=>create(opts(db)),/binding/);
});
test('revocation is observed by already-open second instance without callbacks',{skip:!available},t=>{
 const db=fixture(t);const a=create({...opts(db),persistedRevocation:true});let calls=0;
 const b=create({...opts(db),persistedRevocation:true,decide:()=>{calls++;return {allow:true,reason:'ok'}}});
 assert.equal(a.revokePolicy().ok,true);assert.equal(b.execute(cmd()).reason,'policy-revoked');assert.equal(calls,0);assert.equal(b.inspect('car').revision,0);b.close();a.close();
});
test('revocation lock contention refuses, rollback preserves policy until successful retry',{skip:!available},t=>{
 const db=fixture(t);const a=create({...opts(db),persistedRevocation:true,busyTimeoutMs:1});const {DatabaseSync}=require('node:sqlite');const d=new DatabaseSync(db);
 d.exec('BEGIN IMMEDIATE');assert.equal(a.revokePolicy().code,'BUSY');d.exec('ROLLBACK');
 d.exec("CREATE TRIGGER fail_revoke BEFORE UPDATE ON axial_policy_state BEGIN SELECT RAISE(ABORT,'forced revocation failure'); END;");
 assert.equal(a.revokePolicy().code,'STORAGE');assert.equal(d.prepare('SELECT revoked FROM axial_policy_state WHERE id=1').get().revoked,0);
 d.exec('DROP TRIGGER fail_revoke');assert.equal(a.revokePolicy().code,'REVOKED');assert.equal(a.execute(cmd()).reason,'policy-revoked');d.close();a.close();
});
test('old databases require explicit migration rather than silently enabling mode',{skip:!available},t=>{
 const db=fixture(t);const a=create(opts(db));assert.equal(a.revokePolicy().code,'REVOCATION_DISABLED');a.close();
 assert.throws(()=>create({...opts(db),persistedRevocation:true}),/binding/);create(opts(db)).close();
});
test('player command cannot toggle persisted policy state',{skip:!available},t=>{
 const db=fixture(t);const a=create({...opts(db),persistedRevocation:true});a.revokePolicy();
 assert.equal(a.execute(cmd({revoked:false})).code,'INPUT');assert.equal(a.execute(cmd()).reason,'policy-revoked');a.close();
});
test('persisted revocation refuses in fresh Node process after administrator exits',{skip:!available},t=>{
 const db=fixture(t),a=create({...opts(db),persistedRevocation:true});assert.equal(a.revokePolicy().ok,true);a.close();
 const script=`const {create}=require(${JSON.stringify(require.resolve('../runtime/games-authority-sqlite-v1.cjs'))});
 const a=create({filename:process.argv[1],worldId:'game',policyDigest:'a'.repeat(64),schemaVersion:1,resourcesJson:'[]',persistedRevocation:true,
 decide:()=>{throw Error('must not evaluate revoked')},reduce:()=>{throw Error('must not reduce')}});
 console.log(JSON.stringify({result:a.execute(process.argv[2]),resource:a.inspect('car')}));a.close();`;
 const child=spawnSync(process.execPath,['-e',script,db,cmd()],{encoding:'utf8'});assert.equal(child.status,0,child.stderr);
 const output=JSON.parse(child.stdout);assert.equal(output.result.reason,'policy-revoked');assert.equal(output.resource.revision,0);
});
