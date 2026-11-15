'use strict';
// Independent API-boundary review. Build the native exporter first with:
// node tools/portable-policy-build.cjs
// The business fixture is still compiled by C; malformed candidates below
// deliberately exercise the separate JavaScript profile boundary.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const tool = require('../tools/portable-policy-build.cjs');
const runtime = require('../runtime/portable-pure-v1.js');
const source = process.env.AXIAL_POLICY_SOURCE || path.join(__dirname, 'portable-policy/access.axi');
if (!fs.existsSync(tool.binary)) throw new Error('Build the C exporter with node tools/portable-policy-build.cjs first');
const nativeProgram = JSON.parse(tool.exportPolicy(source));
const copy = value => JSON.parse(JSON.stringify(value));
const factsFor = (program, value) => Object.fromEntries(program.params.map(name => [name, value]));
const word = (op, a = 0, b = 0, c = 0) => (op | (a << 8) | (b << 16) | (c << 24)) >>> 0;
const noAllow = result => {
  assert.equal(result.ok, false);
  assert.equal(result.allowed, false);
  assert.ok(['refused', 'trap'].includes(result.outcome));
};

test('changing array lengths cannot escape the admitted program bounds', () => {
  // Reproducer: the first implementation validated one length, then read it
  // again for ownKeys and every copy iteration. A Proxy is host code, not
  // remotely supplied JSON, but the public object API must keep its bounds.
  const changes = [
    ['code', 129, () => { const a = Array(129).fill(word(0)); a[128] = word(15); return a; }],
    ['params', 17, () => Array.from({length: 17}, (_, i) => 'fact' + i)],
    ['constants', 33, () => Array(33).fill(0)]
  ];
  for (const [field, length, make] of changes) {
    const candidate = copy(nativeProgram);
    const values = make();
    let lengthReads = 0;
    candidate[field] = new Proxy(values, {get(target, key, receiver) {
      if (key === 'length') return ++lengthReads === 1 ? 1 : length;
      return Reflect.get(target, key, receiver);
    }});
    if (field === 'params') candidate.registers = 32;
    const supplied = field === 'params'
      ? Object.fromEntries(values.map(name => [name, true]))
      : factsFor(nativeProgram, true);
    const result = runtime.evaluate(candidate, supplied, {fuel: 256});
    noAllow(result);
    assert.equal(result.fuelUsed, 0, field);
    assert.equal(result.outcome, 'refused', field);
  }
});

test('accessor properties never run during program, fact or budget validation', () => {
  for (const position of ['program', 'word', 'fact', 'budget']) {
    const candidate = copy(nativeProgram), facts = factsFor(nativeProgram, true), options = {fuel: 256};
    let calls = 0;
    const getter = {enumerable: true, configurable: true, get() { calls++; throw new Error('getter executed'); }};
    if (position === 'program') Object.defineProperty(candidate, 'entry', getter);
    if (position === 'word') Object.defineProperty(candidate.code, '0', getter);
    if (position === 'fact') Object.defineProperty(facts, nativeProgram.params[0], getter);
    if (position === 'budget') Object.defineProperty(options, 'fuel', getter);
    noAllow(runtime.evaluate(candidate, facts, options));
    assert.equal(calls, 0, position);
  }
  const candidate = copy(nativeProgram);
  Object.defineProperty(candidate, Symbol('extension'), {value: true});
  noAllow(runtime.evaluate(candidate, factsFor(candidate, true), {fuel: 256}));
});

test('integer truncation, typed arrays and cyclic data cannot become instructions', () => {
  const malformed = [
    p => { p.code[0] = 0x100000000 + word(15); },
    p => { p.code[0] = -1; },
    p => { p.code[0] = -0; },
    p => { p.code[0] = 15.5; },
    p => { p.code[0] = NaN; },
    p => { p.code[0] = Infinity; },
    p => { p.code = Uint32Array.from(p.code); },
    p => { p.constants[0] = Number.MAX_SAFE_INTEGER + 1; },
    p => { p.constants[0] = p.constants; },
    p => { p.code = [p]; },
    p => { p.params[0] = p; }
  ];
  for (const mutate of malformed) {
    const candidate = copy(nativeProgram); mutate(candidate);
    const result = runtime.evaluate(candidate, factsFor(nativeProgram, true), {fuel: 256});
    noAllow(result); assert.equal(result.fuelUsed, 0);
  }
});

test('back edges and jumps beyond the code are refused before spending fuel', () => {
  for (const instruction of [word(12), word(12, 0, 255, 255), word(13, 0, 128, 0), word(12, 0, 0, 127)]) {
    const candidate = {...copy(nativeProgram), code: [instruction, word(15)]};
    const result = runtime.evaluate(candidate, factsFor(candidate, true), {fuel: 4096});
    noAllow(result); assert.equal(result.outcome, 'refused'); assert.equal(result.fuelUsed, 0);
  }
});

test('a numeric one, uninitialized return, HALT or falloff never grants an action', () => {
  for (const code of [[word(1, 0), word(15)], [word(15)], [word(22)], [word(0)]]) {
    const candidate = {...copy(nativeProgram), params: [], registers: 1, constants: [1], code};
    const result = runtime.evaluate(candidate, {}, {fuel: 256});
    noAllow(result); assert.equal(result.outcome, 'trap');
  }
  for (const value of [1, 'true', new Boolean(true), [], {}, null]) {
    const facts = factsFor(nativeProgram, true); facts[nativeProgram.params[0]] = value;
    noAllow(runtime.evaluate(nativeProgram, facts, {fuel: 256}));
  }
});

test('program snapshot isolates one invocation without a stale decision cache', () => {
  const candidate = copy(nativeProgram), supplied = factsFor(candidate, false);
  let changed = false;
  const facts = new Proxy(supplied, {getOwnPropertyDescriptor(target, key) {
    if (!changed) {
      changed = true;
      // Deliberately replace the caller-owned program after its snapshot.
      // A different valid program requires trust from the host; a declared
      // source hash is not asserted to authenticate this replacement.
      candidate.code = [word(1, 0), word(9, 0, 0, 0), word(15)];
    }
    return Reflect.getOwnPropertyDescriptor(target, key);
  }});
  const first = runtime.evaluate(candidate, facts, {fuel: 256});
  assert.equal(changed, true); assert.equal(first.ok, true); assert.equal(first.allowed, false);
  assert.equal(runtime.evaluate(candidate, supplied, {fuel: 256}).allowed, true);
  assert.equal(runtime.evaluate(nativeProgram, supplied, {fuel: 256}).allowed, false);
  assert.equal(Object.isFrozen(first), true);
});

test('null prototypes are data, inherited facts and foreign realm objects are refused', () => {
  const facts = factsFor(nativeProgram, true);
  assert.equal(runtime.evaluate(nativeProgram, Object.assign(Object.create(null), facts), {fuel: 256}).allowed, true);
  noAllow(runtime.evaluate(nativeProgram, Object.create(facts), {fuel: 256}));
  const foreign = vm.runInNewContext('(' + JSON.stringify(facts) + ')');
  noAllow(runtime.evaluate(nativeProgram, foreign, {fuel: 256}));
  assert.equal(runtime.evaluate(nativeProgram, JSON.parse(JSON.stringify(foreign)), {fuel: 256}).allowed, true);
  // A prototype-looking parameter is still an ordinary own boolean key.
  const ownKeyProgram = {...copy(nativeProgram), params: ['__proto__'], registers: 1, constants: [], code: [word(15)]};
  assert.equal(runtime.evaluate(ownKeyProgram, JSON.parse('{"__proto__":true}'), {fuel: 256}).allowed, true);
  assert.equal(Object.prototype.polluted, undefined);
});

test('browser realm runs admitted data while keeping hostile globals outside the policy', () => {
  const context = vm.createContext({calls: 0});
  vm.runInContext('globalThis.fetch = () => { calls++; throw Error("network"); }; globalThis.eval = () => { calls++; throw Error("eval"); };', context);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../runtime/portable-pure-v1.js'), 'utf8'), context, {timeout: 1000});
  const output = vm.runInContext('AxialPortablePureV1.evaluate(' + JSON.stringify(nativeProgram) + ',' + JSON.stringify(factsFor(nativeProgram, true)) + ',{fuel:256})', context, {timeout: 1000});
  assert.equal(output.allowed, true); assert.equal(context.calls, 0);
});
