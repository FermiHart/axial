'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Context = require('../runtime/invocation-context-v1.js');
const binding = (requestId = 'request:1', values = {}) => ({requestId, actorId: 'member:1', resourceId: 'car:1', action: 'deliver', ...values});
const issuer = options => Context.create({ownerId: 'native-owner', ...options});

test('invocation handles bind one owner, epoch, request, actor, resource and action', () => {
  const first = issuer(), second = issuer(), bound = binding(), issued = first.issue(bound);
  assert.equal(Context.profile, 'axial.invocation-context.v1');
  assert.equal(issued.ok, true);
  assert.deepEqual(issued.context, {schemaVersion: 1, ownerId: 'native-owner', ownerEpoch: 1, revision: 1, ...bound});
  assert.equal(Object.isFrozen(issued.context), true);
  assert.equal(Object.isFrozen(issued.ticket), true);
  assert.equal(first.check(issued.ticket, bound).ok, true);
  assert.equal(second.check(issued.ticket, bound).code, 'AXC-FOREIGN');
  assert.equal(first.check({...issued.ticket}, bound).code, 'AXC-FOREIGN');
  assert.equal(first.check(JSON.parse(JSON.stringify(issued.context)), bound).code, 'AXC-FOREIGN');
  for (const key of Context.BINDING)
    assert.equal(first.check(issued.ticket, {...bound, [key]: 'another-value'}).code, 'AXC-BINDING');
});

test('each live request has its own monotonic observation; reissue only supersedes that request', () => {
  const owner = issuer(), first = owner.issue(binding()), other = owner.issue(binding('request:2'));
  const replacement = owner.issue(binding('request:1', {resourceId: 'car:2'}));
  assert.equal(first.context.revision, 1);
  assert.equal(other.context.revision, 2);
  assert.equal(replacement.context.revision, 3);
  assert.equal(owner.check(first.ticket, binding()).code, 'AXC-SUPERSEDED');
  assert.equal(owner.check(other.ticket, binding('request:2')).ok, true);
  assert.equal(owner.check(replacement.ticket, binding('request:1', {resourceId: 'car:2'})).ok, true);
  assert.equal(owner.snapshot().pending, 2);
});

test('consumption is one use and retirement cannot be promoted into execution', () => {
  const owner = issuer(), bound = binding(), live = owner.issue(bound);
  assert.equal(owner.consume(live.ticket, bound).ok, true);
  assert.equal(owner.consume(live.ticket, bound).code, 'AXC-CONSUMED');
  assert.equal(owner.retire(live.ticket).code, 'AXC-CONSUMED');
  assert.equal(owner.snapshot().consumed, 1);
  const preview = owner.issue(binding('preview:1'));
  assert.equal(owner.retire(preview.ticket).ok, true);
  assert.equal(owner.consume(preview.ticket, binding('preview:1')).code, 'AXC-RETIRED');
  assert.equal(owner.snapshot().pending, 0);
});

test('rotation invalidates old handles without resetting observation revisions', () => {
  const owner = issuer(), bound = binding(), before = owner.issue(bound);
  assert.equal(owner.rotate().ok, true);
  assert.equal(owner.check(before.ticket, bound).code, 'AXC-EPOCH');
  const after = owner.issue(bound);
  assert.equal(after.context.ownerEpoch, 2);
  assert.equal(after.context.revision, 2);
  assert.equal(owner.snapshot().revisionKind, 'observation');
});

test('capacity refuses new pending requests without evicting current handles', () => {
  const owner = issuer({maxPending: 1}), first = owner.issue(binding());
  const before = owner.snapshot();
  assert.equal(owner.issue(binding('request:2')).code, 'AXC-CAPACITY');
  assert.deepEqual(owner.snapshot(), before);
  assert.equal(owner.check(first.ticket, binding()).ok, true);
  assert.equal(owner.issue(binding()).ok, true, 'same request can supersede its own observation at capacity');
});

test('bindings and configuration reject accessors, exotic prototypes, extras and unbounded strings', () => {
  let reads = 0;
  const accessor = binding();
  Object.defineProperty(accessor, 'actorId', {get() { reads++; throw Error('getter executed'); }});
  const owner = issuer();
  const invalid = [accessor, Object.create(binding()), {...binding(), extra: true}, {...binding(), actorId: ''},
    {...binding(), resourceId: 'x'.repeat(129)}, {...binding(), action: 'a\u0000b'}, {...binding(), actorId: 1}];
  for (const input of invalid) assert.equal(owner.issue(input).code, 'AXC-BINDING');
  const live = owner.issue(binding());
  assert.equal(owner.consume(live.ticket, accessor).code, 'AXC-BINDING');
  assert.equal(owner.check(live.ticket, binding()).ok, true);
  assert.equal(reads, 0);
  for (const options of [Object.create({ownerId: 'x'}), {ownerId: 'x', extra: 1}, {ownerId: 'x', maxPending: Infinity}, {ownerId: 'x', maxPending: 0}])
    assert.throws(() => Context.create(options), TypeError);
  const settings = {};
  Object.defineProperty(settings, 'ownerId', {get() { reads++; return 'x'; }});
  assert.throws(() => Context.create(settings), TypeError);
  assert.equal(reads, 0);
});

test('reentrant binding descriptors cannot consume the same handle twice or bypass invalidation', () => {
  for (const operation of ['consume', 'retire', 'rotate', 'reissue']) {
    const owner = issuer(), bound = binding(), live = owner.issue(bound);
    let entered = false, inner;
    const expected = new Proxy(bound, {ownKeys(target) {
      if (!entered) {
        entered = true;
        inner = operation === 'rotate' ? owner.rotate() : operation === 'reissue' ? owner.issue(bound) : owner[operation](live.ticket, bound);
      }
      return Reflect.ownKeys(target);
    }});
    const outer = owner.consume(live.ticket, expected);
    assert.equal(inner.ok, true, operation);
    assert.equal(outer.ok, false, operation);
    assert.equal(owner.snapshot().consumed, operation === 'consume' ? 1 : 0, operation);
  }
});
