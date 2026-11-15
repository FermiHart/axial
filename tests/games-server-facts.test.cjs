'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const f=require('../examples/games/server-facts.cjs');
const session={authenticated:true,actorId:'alice'};
const world={doors:{door:{allowedActors:['bob'],locked:false}},
 items:{car:{owner:'bob',reservation:null}},races:{oval:{entrants:['bob'],phase:'racing'}}};
test('door fixture ignores claimed client permission',()=>{
 const result=f.doorFacts(session,world,{resourceId:'door',authorized:true,actorId:'bob'});
 assert.equal(result.authorized,false);assert.equal(Object.isFrozen(result),true);
});
test('inventory fixture derives owner from authoritative state',()=>{
 assert.equal(f.inventoryFacts(session,world,{resourceId:'car',owns:true}).owns,false);
 assert.equal(f.inventoryFacts(session,world,{resourceId:'missing'}).exists,false);
});
test('race fixture does not grant entry or rewards from client assertion',()=>{
 assert.equal(f.raceFacts(session,world,{resourceId:'oval',entered:true}).entered,false);
 assert.equal(world.races.oval.phase,'racing');
});

test('inherited resource names do not resolve server assets',()=>{
 for(const key of ['__proto__','constructor','toString']) {
 assert.equal(f.doorFacts(session,world,{resourceId:key}).exists,false);
 assert.equal(f.inventoryFacts(session,world,{resourceId:key}).exists,false);
 assert.equal(f.raceFacts(session,world,{resourceId:key}).exists,false);
 }
});
