'use strict';
const {create}=require('../../runtime/games-authority-sqlite-v1.cjs');
const [filename,commandId,actorId,mode]=process.argv.slice(2),digest='a'.repeat(64);
const a=create({filename,worldId:'game',policyDigest:digest,schemaVersion:1,
 resourcesJson:JSON.stringify([{id:'car',revision:0,state:{owner:'market',stock:1}}]),
 decide:({resource})=>({allow:resource.state.stock>0,reason:'stock'}),
 reduce:({resource,command})=>({...resource.state,owner:command.actorId,stock:resource.state.stock-1})});
const result=a.execute(JSON.stringify({worldId:'game',commandId,actorId,resourceId:'car',action:'buy',expectedRevision:0,policyDigest:digest,schemaVersion:1,payload:{}}));
if(mode==='lost-response') process.exit(0);
console.log(JSON.stringify(result));a.close();
