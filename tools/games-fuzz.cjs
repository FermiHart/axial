'use strict';
// Seeded rejection corpus; not coverage-guided fuzzing or a sandbox proof.
const A=require('../runtime/games-admission-v1.cjs');
const path=require('node:path'), tool=require('./portable-decision-build.cjs');
const bytes=Buffer.from(tool.exportPolicy(path.resolve(__dirname,'../tests/portable-decision/access.axi')));
const a=A.createAdmission([{id:'p',schema:'v1',version:1,digest:A.hash(bytes)}]);
const h=a.admit('p',bytes);if(!h)throw Error('fixture rejected');
let seed=0x57415645;function rng(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;}
for(let i=0;i<10000;i++){
 const copy=Buffer.from(bytes);copy[rng()%copy.length]^=1<<(rng()%8);
 if(a.admit('p',copy)!==null)throw Error('mutant admitted');
 const garbage=Buffer.alloc(rng()%256);for(let j=0;j<garbage.length;j++)garbage[j]=rng()&255;
 if(a.evaluate(h,garbage).allowed)throw Error('garbage allowed');
}
console.log(JSON.stringify({seed:'0x57415645',mutatedArtifacts:10000,garbageFacts:10000,failures:0,coverageGuided:false}));
