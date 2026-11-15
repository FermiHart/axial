'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const tool=require('../tools/portable-numeric-build.cjs');
const A=require('../runtime/games-admission-v1.cjs');
tool.build();
const bytes=Buffer.from(tool.exportPolicy(path.resolve(__dirname,'portable-numeric/add.axi')));
const manifest=[{id:'add',schema:'i64.v1',version:1,digest:A.hash(bytes)}];
test('numeric profile uses its own trusted loader and exact decimal facts',()=>{
 const a=A.createNumericAdmission(manifest),h=a.admit('add',bytes);
 assert.ok(h);assert.equal(A.createAdmission(manifest).admit('add',bytes),null);
 const result=a.evaluate(h,Buffer.from('{"a":"9007199254740993","b":"2"}'));
 assert.equal(result.ok,true);assert.equal(result.value,'9007199254740995');
 assert.equal(a.evaluate(h,Buffer.from('{"a":9007199254740993,"b":2}')).ok,false);
 a.revoke('add');assert.equal(a.evaluate(h,Buffer.from('{"a":"1","b":"2"}')).ok,false);
});
