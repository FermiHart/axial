/* Axial host invocation handles. Observation revisions are local to one issuer;
 * they are not world versions, authentication, durable receipts or signatures.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.AxialInvocationContextV1 = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const profile = 'axial.invocation-context.v1';
  const BINDING = Object.freeze(['requestId', 'actorId', 'resourceId', 'action']);
  const MAX_STRING = 128, DEFAULT_PENDING = 256, MAX_PENDING = 4096;
  const plain = value => value !== null && typeof value === 'object' &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value));
  const label = value => typeof value === 'string' && value.length > 0 &&
    value.length <= MAX_STRING && !/[\u0000-\u001f\u007f]/.test(value);
  function data(value, names, optional = []) {
    if (!plain(value)) return null;
    const fields = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(fields);
    if (keys.some(key => typeof key !== 'string' || !names.includes(key) && !optional.includes(key)) ||
      names.some(key => !Object.hasOwn(fields, key))) return null;
    const result = {};
    for (const key of keys) {
      const field = fields[key];
      if (!Object.hasOwn(field, 'value')) return null;
      result[key] = field.value;
    }
    return result;
  }
  function binding(value) {
    const result = data(value, BINDING);
    return result && BINDING.every(key => label(result[key])) ? Object.freeze(result) : null;
  }
  function create(options) {
    const settings = data(options, ['ownerId'], ['maxPending']);
    if (!settings || !label(settings.ownerId)) throw new TypeError('Invalid invocation context owner');
    const maxPending = settings.maxPending === undefined ? DEFAULT_PENDING : settings.maxPending;
    if (!Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > MAX_PENDING)
      throw new TypeError('Invalid invocation context capacity');
    const ownerId = settings.ownerId, tickets = new WeakMap(), pending = new Map();
    let ownerEpoch = 1, revision = 0, consumed = 0, retired = 0, superseded = 0, exhausted = false;
    const response = (ok, code, record = null, ticket = null) => Object.freeze({
      ok, code, context: record?.context || null, ...(ticket ? {ticket} : {})
    });
    function closePending(state) {
      for (const record of pending.values()) record.state = state;
      pending.clear();
    }
    function issue(value) {
      let bound;
      try { bound = binding(value); } catch { return response(false, 'AXC-BINDING'); }
      if (!bound) return response(false, 'AXC-BINDING');
      if (exhausted) return response(false, 'AXC-EXHAUSTED');
      const previous = pending.get(bound.requestId);
      if (!previous && pending.size >= maxPending) return response(false, 'AXC-CAPACITY');
      if (!Number.isSafeInteger(revision + 1)) {
        exhausted = true; closePending('exhausted');
        return response(false, 'AXC-EXHAUSTED');
      }
      // Reissuing this invocation invalidates only this request's old handle.
      if (previous) { previous.state = 'superseded'; superseded++; }
      const context = Object.freeze({schemaVersion: 1, ownerId, ownerEpoch, revision: ++revision, ...bound});
      const record = {context, state: 'pending'};
      const ticket = Object.freeze(Object.create(null));
      tickets.set(ticket, record); pending.set(bound.requestId, record);
      return response(true, 'AXC-ISSUED', record, ticket);
    }
    function inspect(ticket, expected) {
      const record = ticket && typeof ticket === 'object' ? tickets.get(ticket) : null;
      if (!record) return response(false, 'AXC-FOREIGN');
      // Even descriptor-only reads can invoke a Proxy trap. Finish every host
      // read before checking private state, so reentrant consume/rotate/reissue
      // cannot leave the outer call holding an authorization checked earlier.
      let bound;
      try { bound = binding(expected); } catch { return response(false, 'AXC-BINDING', record); }
      if (!bound || BINDING.some(key => bound[key] !== record.context[key])) return response(false, 'AXC-BINDING', record);
      if (exhausted) return response(false, 'AXC-EXHAUSTED', record);
      if (record.context.ownerEpoch !== ownerEpoch) return response(false, 'AXC-EPOCH', record);
      if (record.state !== 'pending') return response(false, 'AXC-' + record.state.toUpperCase(), record);
      if (pending.get(record.context.requestId) !== record) return response(false, 'AXC-SUPERSEDED', record);
      return response(true, 'AXC-CURRENT', record);
    }
    function check(ticket, expected) { return inspect(ticket, expected); }
    function consume(ticket, expected) {
      const result = inspect(ticket, expected);
      if (!result.ok) return result;
      const record = tickets.get(ticket);
      // Consumption precedes the host's effect. An effect that fails never
      // rearms the handle. The host must check its live native witness first.
      record.state = 'consumed'; pending.delete(record.context.requestId); consumed++;
      return response(true, 'AXC-CONSUMED', record);
    }
    function retire(ticket) {
      const record = ticket && typeof ticket === 'object' ? tickets.get(ticket) : null;
      if (!record) return response(false, 'AXC-FOREIGN');
      const expected = Object.fromEntries(BINDING.map(key => [key, record.context[key]]));
      const result = inspect(ticket, expected);
      if (!result.ok) return result;
      record.state = 'retired'; pending.delete(record.context.requestId); retired++;
      return response(true, 'AXC-RETIRED', record);
    }
    function rotate() {
      if (exhausted || !Number.isSafeInteger(ownerEpoch + 1)) {
        exhausted = true; closePending('exhausted');
        return response(false, 'AXC-EXHAUSTED');
      }
      closePending('rotated'); ownerEpoch++;
      return response(true, 'AXC-ROTATED');
    }
    function snapshot() {
      return Object.freeze({profile, schemaVersion: 1, ownerId, ownerEpoch,
        revision, revisionKind: 'observation', maxPending, pending: pending.size,
        consumed, retired, superseded, exhausted});
    }
    return Object.freeze({profile, issue, check, consume, retire, rotate, snapshot});
  }
  return Object.freeze({profile, BINDING, MAX_STRING, DEFAULT_PENDING, MAX_PENDING, create});
});
