'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const tool=require('../tools/portable-decision-build.cjs');
const {createAdmission,hash}=require('../runtime/games-admission-v1.cjs');
const bytes=Buffer.from(tool.exportPolicy(require('node:path').resolve(__dirname,'portable-decision/access.axi')));
const entry={id:'access',schema:'facts.v1',version:1,digest:hash(bytes)};
const facts=Buffer.from(JSON.stringify({identityKnown:true,resourceAllowed:true,available:true}));
function setup(){const a=createAdmission([entry]);return [a,a.admit('access',bytes)];}
test('pinned compiler program admits and allows, with trusted binding',()=>{const [a,h]=setup();assert.ok(h);const r=a.evaluate(h,facts);assert.equal(r.allowed,true);assert.equal(r.policy.digest,hash(bytes));});
test('mutated code cannot authenticate itself with declared hashes',()=>{const a=createAdmission([entry]),p=JSON.parse(bytes);p.code=[15];assert.equal(a.admit('access',Buffer.from(JSON.stringify(p))),null);});
test('manifest is copied and old versions are not admitted by a new loader',()=>{const m={...entry};const a=createAdmission([m]);m.digest='0'.repeat(64);assert.ok(a.admit('access',bytes));const b=createAdmission([{...entry,version:2,digest:'0'.repeat(64)}]);assert.equal(b.admit('access',bytes),null);});
test('opaque handles cannot be forged, copied, or used on another loader',()=>{const [a,h]=setup(),[b]=setup();for(const x of [{},JSON.parse(JSON.stringify(h)),null])assert.equal(a.evaluate(x,facts).allowed,false);assert.equal(b.evaluate(h,facts).allowed,false);});
test('revocation blocks both new and existing handles',()=>{const [a,h]=setup();assert.equal(a.revoke('access'),true);assert.equal(a.evaluate(h,facts).allowed,false);assert.equal(a.admit('access',bytes),null);});
test('raw byte sizes and UTF8 are bounded before parse',()=>{const[a,h]=setup();for(const f of [Buffer.alloc(4097),Buffer.from([255]),Buffer.from('{'),{},Buffer.from('null')])assert.equal(a.evaluate(h,f).allowed,false);assert.equal(a.admit('access',Buffer.alloc(65537)),null);});
test('input mutation after admission cannot change policy',()=>{const a=createAdmission([entry]),b=Buffer.from(bytes),h=a.admit('access',b);b.fill(0);assert.equal(a.evaluate(h,facts).allowed,true);});
test('unknown, duplicate, and malformed trust entries fail closed',()=>{assert.throws(()=>createAdmission([entry,entry]));assert.throws(()=>createAdmission([{...entry,version:0}]));const[a]=setup();assert.equal(a.admit('unknown',bytes),null);});
test('fuel exhaustion remains a trap, never permission',()=>{const[a,h]=setup();assert.equal(a.evaluate(h,facts,{fuel:0}).allowed,false);});
test('bit mutation corpus cannot pass digest admission',()=>{const[a]=setup();for(let i=0;i<bytes.length;i++){const b=Buffer.from(bytes);b[i]^=1;assert.equal(a.admit('access',b),null);}});
