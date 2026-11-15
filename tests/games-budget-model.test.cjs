'use strict';
// SPDX-License-Identifier: LicenseRef-SPL-1.0
// Deterministic state-machine differential test: seed 123, 100,000 operations.
// Independently models admission, first-fit batches, actor pending capacity,
// UTF-8 accounting and execution budgets across repeated batches/tick resets.
const test = require('node:test');
const assert = require('node:assert/strict');
const {create} = require('../runtime/games-budget-v1.cjs');

test('seed 123: 100000 scheduler transitions match an independent bounded model', () => {
  let seed = 123;
  const random = max => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return (seed >>> 8) % max;
  };
  const limits = {queueItems:32, queueBytes:256, itemBytes:16,
    tickUnits:20, actorUnits:5, actorQueueItems:4, actorQueueBytes:32};
  const queue = create(limits);
  let pending = [], tick = 0, used = 0;
  const actors = new Map();
  const counts = {ticks:0, accepted:0, refused:0, batches:0, selected:0, ascii:0, multibyte:0};
  assert.equal(queue.beginTick(tick).ok, true);

  for (let index = 0; index < 100000; index++) {
    const mode = random(10);
    if (mode === 0) {
      assert.equal(queue.beginTick(++tick).ok, true);
      used = 0;
      actors.clear();
      counts.ticks++;
    } else if (mode < 7) {
      const actorId = 'actor:' + random(8);
      const symbol = random(2) ? 'x' : '😀';
      counts[symbol === 'x' ? 'ascii' : 'multibyte']++;
      const payload = symbol.repeat(random(17));
      const workUnits = 1 + random(5);
      const bytes = Buffer.byteLength(payload, 'utf8');
      const actorPending = pending.filter(item => item.actorId === actorId);
      const actorBytes = actorPending.reduce((sum, item) => sum + item.bytes, 0);
      const queuedBytes = pending.reduce((sum, item) => sum + item.bytes, 0);
      const expected = bytes > limits.itemBytes ? 'AXB-ITEM-BYTES'
        : actorPending.length >= limits.actorQueueItems ? 'AXB-ACTOR-QUEUE-COUNT'
        : bytes > limits.actorQueueBytes - actorBytes ? 'AXB-ACTOR-QUEUE-BYTES'
        : pending.length >= limits.queueItems ? 'AXB-QUEUE-COUNT'
        : bytes > limits.queueBytes - queuedBytes ? 'AXB-QUEUE-BYTES' : null;
      const result = queue.enqueue(actorId, payload, workUnits);
      assert.equal(result.ok, expected === null, `admission at operation ${index}`);
      if (expected !== null) {
        assert.equal(result.code, expected);
        counts.refused++;
      } else {
        pending.push({actorId, payload, workUnits, bytes});
        counts.accepted++;
      }
    } else {
      const maxItems = 1 + random(32);
      const selected = [], remaining = [];
      for (const item of pending) {
        const actorUsed = actors.get(item.actorId) || 0;
        if (selected.length === maxItems || item.workUnits + used > limits.tickUnits
            || item.workUnits + actorUsed > limits.actorUnits) {
          remaining.push(item);
        } else {
          selected.push(item);
          used += item.workUnits;
          actors.set(item.actorId, actorUsed + item.workUnits);
        }
      }
      const result = queue.takeBatch(maxItems);
      assert.equal(result.ok, true);
      assert.deepEqual(result.items, selected, `batch at operation ${index}`);
      assert.equal(result.units, used);
      pending = remaining;
      counts.batches++;
      counts.selected += selected.length;
    }

    const snapshot = queue.snapshot();
    assert.equal(snapshot.tick, tick);
    assert.equal(snapshot.queued, pending.length);
    assert.equal(snapshot.queuedBytes, pending.reduce((sum, item) => sum + item.bytes, 0));
    assert.equal(snapshot.queuedActors, new Set(pending.map(item => item.actorId)).size);
    assert.equal(snapshot.usedUnits, used);
    assert.equal(snapshot.actors, actors.size);
    assert.ok(used <= limits.tickUnits);
    for (const actorUsed of actors.values()) assert.ok(actorUsed <= limits.actorUnits);
    for (const actor of new Set(pending.map(item => item.actorId))) {
      const items = pending.filter(item => item.actorId === actor);
      assert.ok(items.length <= limits.actorQueueItems);
      assert.ok(items.reduce((sum, item) => sum + item.bytes, 0) <= limits.actorQueueBytes);
    }
  }
  // Guard against a generator change silently skipping relevant transitions.
  for (const [kind, count] of Object.entries(counts)) assert.ok(count > 100, `${kind}: ${count}`);
});
