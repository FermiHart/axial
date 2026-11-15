/* Copyright (c) 2026 Fermi Hart <contact@fermihart.com>
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
'use strict';
const PROFILE = 'axial.games-budget.v1';
const HARD = Object.freeze({queueItems:4096, queueBytes:4*1024*1024, itemBytes:65536,
  tickUnits:1000000, actorUnits:1000000, actorQueueItems:4096, actorQueueBytes:4*1024*1024});
const failure = code => Object.freeze({ok:false, code});
const positive = (n, max) => Number.isSafeInteger(n) && n > 0 && n <= max;
function create(options = {}) {
  const limits = {queueItems:256, queueBytes:262144, itemBytes:16384,
    tickUnits:4096, actorUnits:512, ...options};
  if (limits.actorQueueItems === undefined) limits.actorQueueItems = Math.min(32, limits.queueItems);
  if (limits.actorQueueBytes === undefined) limits.actorQueueBytes = Math.min(32768, limits.queueBytes);
  if (Object.keys(limits).some(k => !Object.hasOwn(HARD, k)) ||
      Object.keys(HARD).some(k => !positive(limits[k], HARD[k])) ||
      limits.itemBytes > limits.queueBytes || limits.actorUnits > limits.tickUnits ||
      limits.actorQueueItems > limits.queueItems || limits.actorQueueBytes > limits.queueBytes)
    throw new TypeError('invalid game budget limits');
  Object.freeze(limits);
  let queue = [], bytes = 0, tick = -1, units = 0;
  const actors = new Map(), pendingActors = new Map();
  function beginTick(next) {
    if (!Number.isSafeInteger(next) || next < 0 || Object.is(next, -0) || next <= tick)
      return failure('AXB-TICK');
    tick = next; units = 0; actors.clear();
    return Object.freeze({ok:true, tick});
  }
  // Actor identity and estimated work are HOST supplied, never trusted packet claims.
  function enqueue(actorId, payload, workUnits = 1) {
    if (typeof actorId !== 'string' || !/^[A-Za-z0-9:_-]{1,128}$/.test(actorId) ||
        /[\r\n\u2028\u2029]/.test(actorId)) return failure('AXB-ACTOR');
    if (typeof payload !== 'string') return failure('AXB-PAYLOAD');
    // Bound characters before UTF-8 scanning; JS string length cannot exceed bytes.
    if (payload.length > limits.itemBytes) return failure('AXB-ITEM-BYTES');
    const size = Buffer.byteLength(payload, 'utf8');
    if (size > limits.itemBytes) return failure('AXB-ITEM-BYTES');
    if (!positive(workUnits, limits.actorUnits)) return failure('AXB-WORK');
    const pending = pendingActors.get(actorId) || {items:0, bytes:0};
    if (pending.items >= limits.actorQueueItems) return failure('AXB-ACTOR-QUEUE-COUNT');
    if (size > limits.actorQueueBytes - pending.bytes) return failure('AXB-ACTOR-QUEUE-BYTES');
    if (queue.length >= limits.queueItems) return failure('AXB-QUEUE-COUNT');
    if (size > limits.queueBytes - bytes) return failure('AXB-QUEUE-BYTES');
    queue.push(Object.freeze({actorId, payload, workUnits, bytes:size})); bytes += size;
    pendingActors.set(actorId, {items:pending.items + 1, bytes:pending.bytes + size});
    return Object.freeze({ok:true});
  }
  // No callbacks, policy execution, clock, parsing or effects occur in this scheduler.
  function takeBatch(maxItems = limits.queueItems) {
    if (tick < 0) return failure('AXB-NO-TICK');
    if (!positive(maxItems, limits.queueItems)) return failure('AXB-BATCH');
    const selected = [], remaining = [];
    for (const item of queue) {
      const used = actors.get(item.actorId) || 0;
      if (selected.length >= maxItems || item.workUnits > limits.tickUnits - units ||
          item.workUnits > limits.actorUnits - used) { remaining.push(item); continue; }
      selected.push(item); units += item.workUnits;
      actors.set(item.actorId, used + item.workUnits); bytes -= item.bytes;
      const pending = pendingActors.get(item.actorId);
      if (pending.items === 1) pendingActors.delete(item.actorId);
      else pendingActors.set(item.actorId, {items:pending.items - 1, bytes:pending.bytes - item.bytes});
    }
    queue = remaining;
    return Object.freeze({ok:true, tick, items:Object.freeze(selected), units});
  }
  return Object.freeze({beginTick, enqueue, takeBatch,
    snapshot: () => Object.freeze({tick, queued:queue.length, queuedBytes:bytes,
      usedUnits:units, actors:actors.size, queuedActors:pendingActors.size, limits})});
}
module.exports = Object.freeze({PROFILE, HARD, create});
