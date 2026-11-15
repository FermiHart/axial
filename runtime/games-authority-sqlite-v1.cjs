/* Optional durable single-resource reference adapter. Node >=22.13.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
'use strict';
const {createHash} = require('node:crypto');
const memory = require('./games-authority-v1.cjs');
const profile = 'axial.games-authority-sqlite.v1';
const fail = code => Object.freeze({ok:false,code});
function create(options) {
  const {filename, busyTimeoutMs = 2000, persistedRevocation = false, ...config} = options;
  if (typeof persistedRevocation !== 'boolean' || typeof filename !== 'string' || !filename.length || filename === ':memory:' || filename.includes('\0') ||
      !Number.isSafeInteger(busyTimeoutMs) || busyTimeoutMs < 0 || busyTimeoutMs > 30000)
    throw new TypeError('invalid SQLite configuration');
  // Validate the exact memory adapter contract before touching a database file.
  const validated = memory.create(config);
  const {DatabaseSync} = require('node:sqlite');
  const db = new DatabaseSync(filename);
  const binding = JSON.stringify({profile,worldId:config.worldId,policyDigest:config.policyDigest,schemaVersion:config.schemaVersion,...(persistedRevocation?{persistedRevocation:true}:{})});
  let busy = false, closed = false, poisoned = false;
  try {
    db.exec(`PRAGMA busy_timeout=${busyTimeoutMs}; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; BEGIN IMMEDIATE;`);
    db.exec('CREATE TABLE IF NOT EXISTS axial_meta (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL); CREATE TABLE IF NOT EXISTS axial_resources (id TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK(revision>=0), state TEXT NOT NULL); CREATE TABLE IF NOT EXISTS axial_receipts (command_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, result TEXT NOT NULL);');
    const prior=db.prepare('SELECT binding FROM axial_meta WHERE id=1').get();
    if (prior && prior.binding !== binding) throw new Error('SQLite authority binding mismatch');
    if(persistedRevocation) db.exec('CREATE TABLE IF NOT EXISTS axial_policy_state (id INTEGER PRIMARY KEY CHECK(id=1), revoked INTEGER NOT NULL CHECK(revoked IN (0,1)));');
    if (!prior) {
      if (db.prepare('SELECT count(*) n FROM axial_resources').get().n || db.prepare('SELECT count(*) n FROM axial_receipts').get().n)
        throw new Error('Unbound nonempty authority');
      db.prepare('INSERT INTO axial_meta(id,binding) VALUES(1,?)').run(binding);
      if(persistedRevocation) db.exec('INSERT INTO axial_policy_state(id,revoked) VALUES(1,0)');
      const insert=db.prepare('INSERT INTO axial_resources(id,revision,state) VALUES(?,?,?)');
      for (const r of JSON.parse(config.resourcesJson)) {
        const copy=validated.inspect(r.id);
        insert.run(copy.id,copy.revision,JSON.stringify(copy.state));
      }
    }
    if(persistedRevocation && !db.prepare('SELECT revoked FROM axial_policy_state WHERE id=1').get())
      throw new Error('Missing policy revocation state');
    db.exec('COMMIT');
  } catch (error) { try { db.exec('ROLLBACK'); } catch {} db.close(); throw error; }
  const maxReceipts = config.maxReceipts === undefined ? 4096 : config.maxReceipts;
  const getReceipt=db.prepare('SELECT fingerprint,result FROM axial_receipts WHERE command_id=?');
  const receiptCount=db.prepare('SELECT count(*) n FROM axial_receipts');
  const getResource=db.prepare('SELECT id,revision,state FROM axial_resources WHERE id=?');
  const updateResource=db.prepare('UPDATE axial_resources SET revision=?,state=? WHERE id=? AND revision=?');
  const putReceipt=db.prepare('INSERT INTO axial_receipts(command_id,fingerprint,result) VALUES(?,?,?)');
  const getPolicy=persistedRevocation?db.prepare('SELECT revoked FROM axial_policy_state WHERE id=1'):null;
  function execute(bytes) {
    if(closed) return fail('CLOSED');
    if(poisoned) return fail('STORAGE_QUARANTINED');
    if(busy) return fail('BUSY');
    // Validate bytes without running the real host callbacks or consulting state.
    const probe=memory.create({...config,resourcesJson:'[]',decide:()=>({allow:false,reason:'probe'}),reduce:()=>({})});
    const admission=probe.execute(bytes);
    if(admission.code !== 'NOT_FOUND') return admission;
    const parsed=JSON.parse(bytes);
    const payload=Object.fromEntries(Object.keys(parsed.payload).sort().map(k=>[k,parsed.payload[k]]));
    const c={worldId:parsed.worldId,commandId:parsed.commandId,actorId:parsed.actorId,resourceId:parsed.resourceId,
      action:parsed.action,expectedRevision:parsed.expectedRevision,policyDigest:parsed.policyDigest,schemaVersion:parsed.schemaVersion,payload};
    const fingerprint=createHash('sha256').update(JSON.stringify(c)).digest('hex');
    busy=true;let transaction=false;
    try {
      db.exec('BEGIN IMMEDIATE');transaction=true;
      const prior=getReceipt.get(c.commandId);
      if(prior) {
        db.exec('ROLLBACK');transaction=false;
        return prior.fingerprint===fingerprint ? JSON.parse(prior.result) : fail('COMMAND_CONFLICT');
      }
      if(receiptCount.get().n>=maxReceipts) {db.exec('ROLLBACK');transaction=false;return fail('RECEIPT_CAPACITY');}
      if(persistedRevocation) {
        const policy=getPolicy.get();
        if(!policy) throw new Error('Missing policy state');
        if(policy.revoked) {
          const result=Object.freeze({ok:false,code:'DENY',reason:'policy-revoked'});
          putReceipt.run(c.commandId,fingerprint,JSON.stringify(result));
          db.exec('COMMIT');transaction=false;return result;
        }
      }
      const row=getResource.get(c.resourceId);
      const resource=row ? {id:row.id,revision:row.revision,state:JSON.parse(row.state)} : null;
      const runner=memory.create({...config,resourcesJson:JSON.stringify(resource?[resource]:[]),maxReceipts:1});
      const result=runner.execute(bytes);
      if(result.ok) {
        const next=runner.inspect(c.resourceId);
        const changed=updateResource.run(next.revision,JSON.stringify(next.state),next.id,c.expectedRevision);
        if(changed.changes!==1) throw new Error('CAS invariant');
      }
      putReceipt.run(c.commandId,fingerprint,JSON.stringify(result));
      db.exec('COMMIT');transaction=false;
      return result;
    } catch(error) {
      if(transaction) try{db.exec('ROLLBACK');}catch{poisoned=true;}
      return fail(error.errcode===5 || error.errcode===6 ? 'BUSY' : 'STORAGE');
    } finally {busy=false;}
  }
  // Trusted administration capability. Never expose this method as a player command.
  function revokePolicy() {
    if(!persistedRevocation) return fail('REVOCATION_DISABLED');
    if(closed) return fail('CLOSED');
    if(poisoned) return fail('STORAGE_QUARANTINED');
    if(busy) return fail('BUSY');
    busy=true;let transaction=false;
    try {
      db.exec('BEGIN IMMEDIATE');transaction=true;
      if(!getPolicy.get()) throw new Error('Missing policy state');
      db.prepare('UPDATE axial_policy_state SET revoked=1 WHERE id=1').run();
      db.exec('COMMIT');transaction=false;
      return Object.freeze({ok:true,code:'REVOKED',policyDigest:config.policyDigest});
    } catch(error) {
      if(transaction)try{db.exec('ROLLBACK');}catch{poisoned=true;}
      return fail(error.errcode===5||error.errcode===6?'BUSY':'STORAGE');
    } finally {busy=false;}
  }
  function inspect(id) {
    if(closed || poisoned) throw new Error('Authority unavailable');
    const r=getResource.get(id);return r?{id:r.id,revision:r.revision,state:JSON.parse(r.state)}:null;
  }
  function close(){if(busy) return false;if(!closed){db.close();closed=true;}return true;}
  return Object.freeze({profile,execute,inspect,revokePolicy,close});
}
module.exports=Object.freeze({profile,create});
