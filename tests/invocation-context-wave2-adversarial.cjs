'use strict';
// This API binds in-process native observations. A Proxy is hostile host code,
// not remote JSON; nevertheless reentrant observation must not double consume.
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const Context = require('../runtime/invocation-context-v1.js');
const binding = (requestId = 'request:1', change = {}) => ({
  requestId, actorId: 'player:1', resourceId: 'vehicle:1', action: 'deliver', ...change
});
const issuer = options => Context.create({ownerId: 'world:1', ...options});

test('every reentrant binding observation rechecks private state before a check or consumption', () => {
  for (const outerAction of ['check', 'consume']) {
    for (const hook of ['getPrototypeOf', 'ownKeys', 'getOwnPropertyDescriptor']) {
      for (const innerAction of ['consume', 'retire', 'reissue', 'rotate-and-reissue']) {
        const owner = issuer(), bound = binding(), issued = owner.issue(bound);
        let entered = false, inner, effects = 0;
        const enter = () => {
          if (entered) return;
          entered = true;
          if (innerAction === 'consume') {
            inner = owner.consume(issued.ticket, bound);
            if (inner.ok) effects++;
          } else if (innerAction === 'retire') inner = owner.retire(issued.ticket);
          else {
            if (innerAction === 'rotate-and-reissue') assert.equal(owner.rotate().ok, true);
            inner = owner.issue(bound);
          }
        };
        const expected = new Proxy(bound, {
          [hook](target, key) {
            enter();
            if (hook === 'getPrototypeOf') return Reflect.getPrototypeOf(target);
            if (hook === 'ownKeys') return Reflect.ownKeys(target);
            return Reflect.getOwnPropertyDescriptor(target, key);
          }
        });
        const outer = owner[outerAction](issued.ticket, expected);
        if (outer.ok && outerAction === 'consume') effects++;
        const label = `${outerAction}/${hook}/${innerAction}`;
        assert.equal(entered, true, label);
        assert.equal(inner.ok, true, label);
        assert.equal(outer.ok, false, label);
        assert.equal(effects, innerAction === 'consume' ? 1 : 0, label);
        assert.equal(owner.snapshot().consumed, innerAction === 'consume' ? 1 : 0, label);
        if (inner.ticket) assert.equal(owner.check(inner.ticket, bound).ok, true, label);
      }
    }
  }
});

test('snapshot fields, serialized context and identical owner labels never forge a live handle', () => {
  const owner = issuer(), other = issuer(), bound = binding(), issued = owner.issue(bound);
  const forgeries = [
    {...issued.ticket}, JSON.parse(JSON.stringify(issued.ticket)),
    {...issued.context}, {...issued.context, revision: issued.context.revision + 1},
    {...issued.context, ownerEpoch: issued.context.ownerEpoch + 1},
    Object.create(issued.ticket), new Proxy(issued.ticket, {}),
    {...issued, context: {...issued.context}}, null, undefined, 'ticket', 1
  ];
  for (const fake of forgeries) {
    assert.equal(owner.check(fake, bound).ok, false);
    assert.equal(owner.consume(fake, bound).ok, false);
    assert.equal(owner.retire(fake).ok, false);
  }
  assert.equal(other.consume(issued.ticket, bound).code, 'AXC-FOREIGN');
  assert.equal(owner.snapshot().consumed, 0);
  assert.equal(owner.check(issued.ticket, bound).ok, true);
  assert.equal(Object.isFrozen(issued.context), true);
  assert.equal(Object.isFrozen(issued.ticket), true);
});

test('older observations of another live request remain valid while reissue isolates supersession', () => {
  const owner = issuer(), firstBound = binding('a'), secondBound = binding('b');
  const first = owner.issue(firstBound), second = owner.issue(secondBound);
  const replace = owner.issue(binding('a', {resourceId: 'vehicle:2'}));
  assert.equal(owner.check(first.ticket, firstBound).code, 'AXC-SUPERSEDED');
  assert.equal(owner.check(second.ticket, secondBound).ok, true);
  assert.equal(owner.consume(second.ticket, secondBound).ok, true);
  assert.equal(owner.check(replace.ticket, binding('a', {resourceId: 'vehicle:2'})).ok, true);
  assert.equal(owner.snapshot().revision, 3);
  assert.equal(owner.snapshot().revisionKind, 'observation');
  owner.rotate();
  assert.equal(owner.consume(replace.ticket, binding('a', {resourceId: 'vehicle:2'})).code, 'AXC-EPOCH');
  const next = owner.issue(firstBound);
  assert.equal(next.context.revision, 4);
  assert.equal(next.context.ownerEpoch, 2);
});

test('preview retirement cannot execute; a fresh request can commit and a failed effect cannot rearm', () => {
  const owner = issuer(), bound = binding(), preview = owner.issue(bound);
  assert.equal(owner.check(preview.ticket, bound).ok, true);
  assert.equal(owner.retire(preview.ticket).ok, true);
  let effects = 0;
  const attempt = ticket => {
    const result = owner.consume(ticket, bound);
    if (result.ok) effects++;
    return result;
  };
  assert.equal(attempt(preview.ticket).code, 'AXC-RETIRED');
  const actual = owner.issue(bound);
  assert.equal(attempt(actual.ticket).ok, true);
  // The native operation may report failure. This helper deliberately grants
  // no rollback/rearm API; retries need another observation and decision.
  assert.equal(attempt(actual.ticket).code, 'AXC-CONSUMED');
  assert.equal(owner.retire(actual.ticket).code, 'AXC-CONSUMED');
  assert.equal(effects, 1);
  assert.equal(owner.snapshot().pending, 0);
});

test('capacity exhaustion leaves every pending handle and revision unchanged', () => {
  const owner = issuer({maxPending: 2});
  const first = owner.issue(binding('a')), second = owner.issue(binding('b'));
  const before = owner.snapshot();
  const refused = owner.issue(binding('c'));
  assert.equal(refused.code, 'AXC-CAPACITY');
  assert.equal(refused.ticket, undefined);
  assert.deepEqual(owner.snapshot(), before);
  assert.equal(owner.consume(first.ticket, binding('a')).ok, true);
  const third = owner.issue(binding('c'));
  assert.equal(third.context.revision, 3);
  assert.equal(owner.consume(second.ticket, binding('b')).ok, true);
  assert.equal(owner.consume(third.ticket, binding('c')).ok, true);
});

test('invalid bindings do not spend a handle and plain data is read without getters', () => {
  const owner = issuer(), bound = binding(), issued = owner.issue(bound);
  let reads = 0;
  const accessor = binding();
  Object.defineProperty(accessor, 'actorId', {enumerable: true, get() { reads++; throw Error('getter invoked'); }});
  const invalid = [
    accessor, Object.create(bound), vm.runInNewContext('(' + JSON.stringify(bound) + ')'),
    {...bound, ownerId: 'world:1'}, {...bound, revision: 1}, {...bound, action: 'deliver\u0000'},
    {...bound, resourceId: 'x'.repeat(129)}, {...bound, actorId: new String('player:1')},
    {...bound, actorId: ''}, {...bound, actorId: null}, {...bound, actorId: true},
    new Proxy(bound, {ownKeys() { throw Error('descriptor failure'); }})
  ];
  for (const supplied of invalid) {
    assert.equal(owner.check(issued.ticket, supplied).code, 'AXC-BINDING');
    assert.equal(owner.consume(issued.ticket, supplied).code, 'AXC-BINDING');
    assert.equal(owner.snapshot().consumed, 0);
    assert.equal(owner.check(issued.ticket, bound).ok, true);
  }
  assert.equal(reads, 0);
  assert.equal(owner.consume(issued.ticket, Object.assign(Object.create(null), bound)).ok, true);
  assert.equal(owner.snapshot().consumed, 1);
});
