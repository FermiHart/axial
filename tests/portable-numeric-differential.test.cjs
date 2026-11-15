'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const vm = require('node:vm');
const tool = require('../tools/portable-numeric-build.cjs');
const R = require('../runtime/portable-numeric-v1.js');
tool.build();
const fixtures = path.join(__dirname, 'portable-numeric');
const copy = p => JSON.parse(JSON.stringify(p));
const word = (op, a = 0, b = 0, c = 0) => (op | a << 8 | b << 16 | c << 24) >>> 0;
const load = name => JSON.parse(tool.exportPolicy(path.join(fixtures, name + '.axi')));
test('real compiler words and native VM agree for signed numeric profile', () => {
  const values = ['-9223372036854775808', '-9223372036854775807', '-9007199254740993', '-7', '-1', '0', '1', '3', '9007199254740993', '9223372036854775807'];
  const cases = [];
  for (const a of values) for (const b of values) for (const fuel of [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 64, 4096]) cases.push({a, b, fuel});
  let seed = 1234567n;
  const random = () => { seed = (seed * 6364136223846793005n + 1n) & ((1n << 64n) - 1n); return BigInt.asIntN(64, seed).toString(); };
  for (let i = 0; i < 200; i++) cases.push({a: random(), b: random(), fuel: 64});
  let count = 0;
  for (const name of fs.readdirSync(fixtures).filter(n => n.endsWith('.axi')).sort()) {
    const source = path.join(fixtures, name), p = JSON.parse(tool.exportPolicy(source));
    assert.equal(R.validate(p), true);
    const input = cases.map(c => `${c.a} ${c.b} ${c.fuel}\n`).join('');
    const native = tool.run(tool.binary, ['oracle', source], {input}).trim().split('\n').map(JSON.parse);
    assert.equal(native.length, cases.length);
    for (let i = 0; i < cases.length; i++) {
      const c = cases[i], actual = R.evaluate(p, {a: c.a, b: c.b}, {fuel: c.fuel});
      assert.deepEqual({ok: actual.ok, value: actual.value, fuelUsed: actual.fuelUsed,
        fuelLimit: actual.fuelLimit, fuelExhausted: actual.code === 'AXI-R008'}, native[i], `${name}: ${JSON.stringify(c)}`);
      count++;
    }
  }
  assert.equal(count, 16500);
});
test('native wrap differs intentionally from checked host helper', () => {
  const value = (name, a, b) => R.evaluate(load(name), {a, b}, {fuel: 64}).value;
  assert.equal(value('add', '9223372036854775807', '1'), '-9223372036854775808');
  assert.equal(value('div', '-9223372036854775808', '-1'), '-9223372036854775808');
  assert.equal(value('mod', '-9223372036854775808', '-1'), '0');
  assert.equal(R.evaluate(load('div'), {a: '1', b: '0'}, {fuel: 64}).code, 'AXI-R003');
});
test('strict structure, i64 fact encoding, opcodes and control bounds fail closed', () => {
  const p = load('add');
  for (const change of [q => q.code.push(word(14)), q => q.code[0] = word(12, 0, 255, 255),
    q => q.code[0] = word(12), q => q.code[0] = word(3, 32, 0, 1),
    q => q.code[0] = word(1, 2, 0, 32), q => q.code[0] = word(13, 0, 0, 127),
    q => q.returnType = 'u64', q => q.constants.push({kind: 'i64', value: '9223372036854775808'}),
    q => q.params[1] = 'a', q => q.code = Array(129).fill(0), q => q.fuelMax = 4097]) {
    const q = copy(p); change(q); assert.equal(R.validate(q), false);
    assert.equal(R.evaluate(q, {a: '1', b: '2'}, {fuel: 64}).outcome, 'refused');
  }
  for (const bad of [1, 1n, '-0', '01', '+1', '1\n', '1\u2028', '1'.repeat(1000), '9223372036854775808'])
    assert.equal(R.evaluate(p, {a: bad, b: '1'}, {fuel: 64}).code, 'AXP-A001');
  let touched = false;
  const facts = {b: '1'}; Object.defineProperty(facts, 'a', {enumerable: true, get() { touched = true; return '1'; }});
  assert.equal(R.evaluate(p, facts, {fuel: 64}).outcome, 'refused'); assert.equal(touched, false);
});
test('malformed register kinds trap rather than coerce', () => {
  const p = load('add');
  p.code = [word(3, 2, 3, 4), word(15, 2)];
  assert.equal(R.validate(p), true); // Structural validator; dynamic kinds still checked.
  assert.equal(R.evaluate(p, {a: '1', b: '2'}, {fuel: 64}).code, 'AXI-R004');
  p.code = [word(15, 3)];
  assert.equal(R.evaluate(p, {a: '1', b: '2'}, {fuel: 64}).code, 'AXI-R025');
});
test('standalone browser realm and profile separation', () => {
  const context = vm.createContext({}, {codeGeneration: {strings: false, wasm: false}});
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../runtime/portable-numeric-v1.js'), 'utf8'), context);
  const p = load('add');
  context.serialized = JSON.stringify(p);
  const browser = vm.runInContext("AxialPortableNumericV1.evaluate(JSON.parse(serialized), {a:'9223372036854775807', b:'1'}, {fuel:64})", context);
  assert.deepEqual(JSON.parse(JSON.stringify(browser)), R.evaluate(p, {a: '9223372036854775807', b: '1'}, {fuel: 64}));
  const decision = require('../runtime/portable-decision-v2.js');
  assert.equal(decision.validate(p), false);
  p.format = 'axial.portable-decision.v2';
  assert.equal(R.validate(p), false);
});
