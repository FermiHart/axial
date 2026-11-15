'use strict';
// SPDX-License-Identifier: LicenseRef-SPL-1.0
// Trusted Node host boundary. Never use a client supplied trust manifest.
const {createHash} = require('node:crypto');
const {TextDecoder} = require('node:util');
const decisionVM = require('./portable-decision-v2.js');
const numericVM = require('./portable-numeric-v1.js');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const token = /^[A-Za-z0-9_.:-]{1,96}$/;
function name(s) { return typeof s === 'string' && token.test(s) && !/[\r\n]/.test(s); }
function createPinnedAdmission(manifest, vm) {
  if (!Array.isArray(manifest) || manifest.length > 256) throw new TypeError('manifest');
  const trusted = new Map(), handles = new WeakMap(), revoked = new Set();
  for (const row of manifest) {
    if (!row || !name(row.id) || !name(row.schema) || !Number.isSafeInteger(row.version) || row.version < 1 ||
        typeof row.digest !== 'string' || !/^[a-f0-9]{64}$/.test(row.digest) || row.digest.length !== 64 || trusted.has(row.id)) throw new TypeError('entry');
    trusted.set(row.id, Object.freeze({id: row.id, schema: row.schema, version: row.version, digest: row.digest}));
  }
  function admit(id, bytes) {
    const entry = trusted.get(id);
    if (!entry || revoked.has(id) || !Buffer.isBuffer(bytes) || bytes.length > 65536) return null;
    // Copy before hashing/parsing, and reject shared backing memory.
    if (bytes.buffer instanceof SharedArrayBuffer) return null;
    const copy = Buffer.from(bytes);
    if (hash(copy) !== entry.digest) return null;
    let program;
    try { program = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(copy)); } catch (_) { return null; }
    if (!vm.validate(program)) return null;
    const handle = Object.freeze(Object.create(null));
    handles.set(handle, {entry, program});
    return handle;
  }
  function evaluate(handle, factsBytes, options = {fuel: 4096}) {
    const admitted = handles.get(handle);
    const refused = Object.freeze({ok:false, allowed:false, outcome:'refused', code:'AXG-ADMISSION', decision:null});
    if (!admitted || revoked.has(admitted.entry.id) || !Buffer.isBuffer(factsBytes) || factsBytes.length > 4096 || factsBytes.buffer instanceof SharedArrayBuffer) return refused;
    let facts;
    try { facts = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(Buffer.from(factsBytes))); } catch (_) { return refused; }
    const result = vm.evaluate(admitted.program, facts, options);
    return Object.freeze({...result, policy: admitted.entry});
  }
  // Revocation is monotonic for this loader; reload requires trusted host setup.
  function revoke(id) { if (!trusted.has(id)) return false; revoked.add(id); return true; }
  return Object.freeze({admit, evaluate, revoke});
}
const createAdmission = manifest => createPinnedAdmission(manifest, decisionVM);
const createNumericAdmission = manifest => createPinnedAdmission(manifest, numericVM);
module.exports = Object.freeze({createAdmission, createNumericAdmission, hash});
