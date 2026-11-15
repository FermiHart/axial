'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const N = require('../runtime/games-numeric-v1.cjs');
const yes = value => ({ok: true, value});
const no = code => ({ok: false, code});

test('canonical primitive wire integers only; no coercion', () => {
  for (const bad of [0, 1n, null, undefined, {}, [], '', '+1', '01', '-0', '1.0', '1e2', ' 1',
    '1\n', '1\r', '1\u2028', '1\u2029', '１', '0x10', '9'.repeat(100000)]) {
    assert.deepEqual(N.add(bad, '0'), no('AXN-INPUT'));
  }
  let touched = false;
  const hostile = {toString() { touched = true; throw Error('coercion'); }};
  assert.deepEqual(N.add(hostile, '0'), no('AXN-INPUT'));
  assert.equal(touched, false);
  assert.deepEqual(N.add('9007199254740993', '2'), yes('9007199254740995'));
});
test('i64 endpoints and checked arithmetic never wrap or saturate', () => {
  assert.deepEqual(N.add(N.max, '0'), yes(N.max));
  assert.deepEqual(N.add(N.min, '0'), yes(N.min));
  assert.deepEqual(N.add(N.max, '1'), no('AXN-OVERFLOW'));
  assert.deepEqual(N.sub(N.min, '1'), no('AXN-OVERFLOW'));
  assert.deepEqual(N.mul(N.max, '2'), no('AXN-OVERFLOW'));
  assert.deepEqual(N.div(N.min, '-1'), no('AXN-OVERFLOW'));
  assert.deepEqual(N.add('9223372036854775808', '0'), no('AXN-INPUT'));
  assert.deepEqual(N.add('-9223372036854775809', '0'), no('AXN-INPUT'));
  assert.deepEqual(N.div('2', '0'), no('AXN-ZERO'));
});
test('division truncates toward zero including fixed-point negative values', () => {
  assert.deepEqual(N.div('-7', '3'), yes('-2'));
  assert.deepEqual(N.div('7', '-3'), yes('-2'));
  assert.deepEqual(N.fixedMul('-101', '50', 2), yes('-50'));
  assert.deepEqual(N.fixedDiv('-100', '300', 2), yes('-33'));
  assert.deepEqual(N.fixedDiv('1', '0', 2), no('AXN-ZERO'));
  assert.deepEqual(N.fixedMul(N.max, '100', 2), yes(N.max));
});
test('rescaling is explicit, checked and bounded', () => {
  assert.deepEqual(N.rescale('123', 2, 4), yes('12300'));
  assert.deepEqual(N.rescale('-123', 2, 1), yes('-12'));
  assert.deepEqual(N.rescale(N.max, 0, 1), no('AXN-OVERFLOW'));
  for (const bad of [-0, -1, 10, 0.5, '2', Infinity, NaN, 1000000]) {
    assert.deepEqual(N.fixedMul('1', '1', bad), no('AXN-INPUT'));
    assert.deepEqual(N.rescale('1', bad, 0), no('AXN-INPUT'));
    assert.deepEqual(N.rescale('1', 0, bad), no('AXN-INPUT'));
  }
});
test('decimal parser uses no binary floating point and rejects excess precision', () => {
  assert.deepEqual(N.parseDecimal('1.23', 2), yes('123'));
  assert.deepEqual(N.parseDecimal('0.01', 2), yes('1'));
  assert.deepEqual(N.parseDecimal('-0.01', 2), yes('-1'));
  assert.deepEqual(N.parseDecimal('5', 3), yes('5000'));
  assert.deepEqual(N.parseDecimal('5', 0), yes('5'));
  assert.deepEqual(N.parseDecimal('0.010', 2), no('AXN-PRECISION'));
  assert.deepEqual(N.parseDecimal('92233720368547758.08', 2), no('AXN-OVERFLOW'));
  assert.deepEqual(N.parseDecimal('-92233720368547758.08', 2), yes(N.min));
  for (const bad of ['-0', '-0.00', '01', '.1', '1.', '1e-2', '1\n', '1\u2028', '+1', '1'.repeat(31)])
    assert.deepEqual(N.parseDecimal(bad, 2), no('AXN-INPUT'));
});
test('formatting and parse roundtrip at every scale and extreme', () => {
  for (let digits = 0; digits <= 9; digits++) {
    for (const value of [N.min, N.max, '0', '1', '-1', '123456789']) {
      const formatted = N.formatDecimal(value, digits);
      assert.equal(formatted.ok, true);
      assert.deepEqual(N.parseDecimal(formatted.value, digits), yes(value));
    }
  }
  assert.deepEqual(N.formatDecimal('-1', 2), yes('-0.01'));
  assert.deepEqual(N.formatDecimal('0', 2), yes('0.00'));
});
test('bounded deterministic arithmetic corpus matches exact oracle', () => {
  let seed = 7381n;
  const next = () => (seed = (seed * 1103515245n + 12345n) % (1n << 31n)) - (1n << 30n);
  for (let i = 0; i < 2000; i++) {
    const a = next(), b = next() || 1n;
    assert.deepEqual(N.add(String(a), String(b)), yes(String(a + b)));
    assert.deepEqual(N.sub(String(a), String(b)), yes(String(a - b)));
    assert.deepEqual(N.mul(String(a), String(b)), yes(String(a * b)));
    assert.deepEqual(N.div(String(a), String(b)), yes(String(a / b)));
    assert.deepEqual(N.fixedMul(String(a), String(b), 2), yes(String(a * b / 100n)));
    assert.deepEqual(N.fixedDiv(String(a), String(b), 2), yes(String(a * 100n / b)));
    assert.deepEqual(N.compare(String(a), String(b)), yes(a < b ? -1 : a > b ? 1 : 0));
  }
});
test('API and outcomes are immutable and JSON serializable', () => {
  assert.equal(Object.isFrozen(N), true);
  for (const outcome of [N.add('1', '2'), N.div('1', '0'), N.add({}, '1')]) {
    assert.equal(Object.isFrozen(outcome), true);
    assert.deepEqual(JSON.parse(JSON.stringify(outcome)), outcome);
  }
});
