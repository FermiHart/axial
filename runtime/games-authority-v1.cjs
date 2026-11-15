/* Axial games in-memory authority reference. Not a database or network service.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
'use strict';
const {createHash} = require('node:crypto');
const {isAsyncFunction, isPromise} = require('node:util').types;
const promiseThen = Promise.prototype.then;
function rejectAsyncResult(value) {
  if (!isPromise(value)) return false;
  // Observe native Promise rejections without reading/calling arbitrary thenables.
  promiseThen.call(value, undefined, () => undefined);
  return true;
}
const profile = 'axial.games-authority.v1';
const LABEL = /^[A-Za-z0-9_.:-]{1,128}$/;
const HASH = /^[a-f0-9]{64}$/;
const exact = (r, keys) => r && typeof r === 'object' && !Array.isArray(r) &&
  Object.keys(r).length === keys.length && keys.every(k => Object.hasOwn(r, k));
const safe = n => Number.isSafeInteger(n) && n >= 0 && !Object.is(n, -0);
const label = s => typeof s === 'string' && LABEL.test(s) && !/[\r\n]/.test(s);
const hash = s => typeof s === 'string' && s.length === 64 && HASH.test(s);
function flat(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Reflect.ownKeys(value).some(k => typeof k !== 'string')) throw new TypeError('flat record required');
  const entries = Object.entries(Object.getOwnPropertyDescriptors(value));
  if (entries.length > 32) throw new RangeError('record capacity');
  const result = Object.create(null);
  for (const [key, d] of entries.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
    if (!label(key) || !Object.hasOwn(d, 'value')) throw new TypeError('invalid field');
    const v = d.value;
    if (!(v === null || typeof v === 'boolean' || typeof v === 'string' && v.length <= 256 ||
      typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0))) throw new TypeError('invalid value');
    result[key] = v;
  }
  return Object.freeze(result);
}
const answer = (ok, code, extra = {}) => Object.freeze({ok, code, ...extra});
function create({worldId, policyDigest, schemaVersion, resourcesJson, decide, reduce,
  maxReceipts = 4096, maxResources = 4096, maxCommandBytes = 16384}) {
  if (!label(worldId) || !hash(policyDigest) || !safe(schemaVersion) || schemaVersion < 1 ||
      typeof decide !== 'function' || typeof reduce !== 'function' ||
      isAsyncFunction(decide) || isAsyncFunction(reduce) ||
      !safe(maxReceipts) || maxReceipts < 1 || maxReceipts > 100000 ||
      !safe(maxResources) || maxResources < 1 || maxResources > 100000 ||
      !safe(maxCommandBytes) || maxCommandBytes < 256 || maxCommandBytes > 65536 ||
      typeof resourcesJson !== 'string' || Buffer.byteLength(resourcesJson) > 8 * 1024 * 1024)
    throw new TypeError('invalid authority configuration');
  const initial = JSON.parse(resourcesJson), resources = new Map(), receipts = new Map();
  if (!Array.isArray(initial) || initial.length > maxResources) throw new TypeError('invalid resources');
  for (const item of initial) {
    if (!exact(item, ['id', 'revision', 'state']) || !label(item.id) || !safe(item.revision) || resources.has(item.id))
      throw new TypeError('invalid resource');
    resources.set(item.id, Object.freeze({id: item.id, revision: item.revision, state: flat(item.state)}));
  }
  let busy = false;
  function execute(bytes) {
    if (busy) return answer(false, 'BUSY');
    if (typeof bytes !== 'string' || Buffer.byteLength(bytes) > maxCommandBytes) return answer(false, 'INPUT');
    let c;
    try {
      c = JSON.parse(bytes);
      if (!exact(c, ['worldId', 'commandId', 'actorId', 'resourceId', 'action', 'expectedRevision', 'policyDigest', 'schemaVersion', 'payload']) ||
        !['worldId', 'commandId', 'actorId', 'resourceId', 'action'].every(k => label(c[k])) ||
        !safe(c.expectedRevision) || !hash(c.policyDigest) || !safe(c.schemaVersion)) return answer(false, 'INPUT');
      c = Object.freeze({worldId: c.worldId, commandId: c.commandId, actorId: c.actorId, resourceId: c.resourceId,
        action: c.action, expectedRevision: c.expectedRevision, policyDigest: c.policyDigest,
        schemaVersion: c.schemaVersion, payload: flat(c.payload)});
    } catch { return answer(false, 'INPUT'); }
    const fingerprint = createHash('sha256').update(JSON.stringify(c)).digest('hex');
    const prior = receipts.get(c.commandId);
    if (prior) return prior.fingerprint === fingerprint ? prior.result : answer(false, 'COMMAND_CONFLICT');
    if (c.worldId !== worldId || c.policyDigest !== policyDigest || c.schemaVersion !== schemaVersion)
      return answer(false, 'BINDING');
    // Never evict receipts: eviction would permit old commands to run again.
    if (receipts.size >= maxReceipts) return answer(false, 'RECEIPT_CAPACITY');
    busy = true;
    const finish = result => { receipts.set(c.commandId, {fingerprint, result}); return result; };
    try {
      const current = resources.get(c.resourceId);
      if (!current) return finish(answer(false, 'NOT_FOUND'));
      if (current.revision !== c.expectedRevision) return finish(answer(false, 'STALE', {revision: current.revision}));
      if (!safe(current.revision + 1)) return finish(answer(false, 'REVISION_EXHAUSTED'));
      // Callbacks are trusted synchronous, pure host adapters, not sandboxed plugins.
      const facts = Object.freeze({command: c, resource: current});
      const decision = decide(facts);
      if (rejectAsyncResult(decision)) return finish(answer(false, 'TRAP'));
      if (!exact(decision, ['allow', 'reason']) || typeof decision.allow !== 'boolean' || !label(decision.reason))
        return finish(answer(false, 'TRAP'));
      if (!decision.allow) return finish(answer(false, 'DENY', {reason: decision.reason}));
      const proposed = reduce(facts);
      if (rejectAsyncResult(proposed)) return finish(answer(false, 'TRAP'));
      const nextState = flat(proposed);
      const next = Object.freeze({id: current.id, revision: current.revision + 1, state: nextState});
      const result = answer(true, 'COMMITTED', {worldId, commandId: c.commandId, policyDigest,
        schemaVersion, revision: next.revision, resource: next});
      // No await, external callback or user code between state and receipt writes.
      resources.set(current.id, next);
      return finish(result);
    } catch { return finish(answer(false, 'TRAP')); }
    finally { busy = false; }
  }
  function inspect(id) { return resources.get(id) || null; }
  return Object.freeze({profile, execute, inspect, stats: () => Object.freeze({resources: resources.size,
    receipts: receipts.size, maxReceipts, busy, durable: false})});
}
module.exports = Object.freeze({profile, create});
