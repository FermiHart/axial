'use strict';
// Independent v2 boundary tests. The ordinary policy comes from the native C
// compiler. Handcrafted candidates below test the profile, not artifact trust.
// Build first: node tools/portable-decision-build.cjs
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const tool = require('../tools/portable-decision-build.cjs');
const runtime = require('../runtime/portable-decision-v2.js');
const source = path.join(__dirname, 'portable-decision/access.axi');
if (!fs.existsSync(tool.binary)) throw new Error('Build the native decision exporter first');
const compiled = JSON.parse(tool.exportPolicy(source));
const clone = value => JSON.parse(JSON.stringify(value));
const word = (op, a = 0, b = 0, c = 0) => (op | (a << 8) | (b << 16) | (c << 24)) >>> 0;
const facts = (...values) => Object.fromEntries(compiled.params.map((key, index) => [key, values[index] ?? true]));
const evaluate = (program = compiled, supplied = facts(), fuel = 64) => runtime.evaluate(program, supplied, {fuel});
const closed = result => {
  assert.equal(result.ok, false);
  assert.equal(result.allowed, false);
  assert.ok(['refused', 'trap'].includes(result.outcome));
  assert.equal(result.decision, null);
};
const unitProgram = () => ({...clone(compiled), params: [], registers: 3, constants: [], code: [word(15, 2)]});

test('native decision reasons and precedence agree for every combination of the compiled fixture', () => {
  const oracle = tool.run(tool.binary, ['oracle', source]).trim().split('\n').map(line => JSON.parse(line));
  for (let mask = 0; mask < 8; mask++) {
    const supplied = facts(...compiled.params.map((_, index) => Boolean((mask >> index) & 1)));
    const actual = evaluate(compiled, supplied);
    const native = oracle.find(row => row.mask === mask && row.fuel === 64);
    assert.ok(native);
    assert.equal(actual.ok, native.ok);
    assert.equal(actual.allowed, native.allowed);
    assert.deepEqual(actual.decision, native.decision);
    assert.equal(actual.fuelUsed, native.fuelUsed);
    const expected = !supplied.identityKnown ? 'IdentityUnknown' : !supplied.resourceAllowed
      ? 'ResourceDenied' : !supplied.available ? 'Unavailable' : null;
    assert.deepEqual(actual.decision, expected ? {kind: 'deny', reason: expected} : {kind: 'allow'});
  }
});

test('declared atoms come from the executed constant, with no reason reconstructed from facts', () => {
  const candidate = clone(compiled);
  const first = candidate.constants.find(k => k.kind === 'error' && k.atom === 'IdentityUnknown');
  first.atom = 'Unavailable';
  // Source hashes are provenance fields, not authentication of arbitrary host
  // objects. An admitted different program must be pinned by its application.
  const output = evaluate(candidate, facts(false, false, false));
  assert.deepEqual(output.decision, {kind: 'deny', reason: 'Unavailable'});
  assert.equal(Object.isFrozen(output.decision), true);
  assert.deepEqual(evaluate(compiled, facts(false, false, false)).decision,
    {kind: 'deny', reason: 'IdentityUnknown'});
});

test('return contracts refuse extra union arms, payloads, undeclared atoms and ambiguous errors', () => {
  const invalid = [
    p => { delete p.returnType; },
    p => { p.format = 'axial.portable-pure.v1'; },
    p => { p.returnType.kind = 'union'; },
    p => { p.returnType.ok = 'bool'; },
    p => { p.returnType.payload = 'unit'; },
    p => { p.returnType.errors = []; },
    p => { p.returnType.errors = ['IdentityUnknown', 'IdentityUnknown']; },
    p => { p.returnType.errors = ['Unavailable', 'IdentityUnknown']; },
    p => { p.returnType.errors = ['err.IdentityUnknown']; },
    p => { p.returnType.errors = ['IdentityUnknown\u0000']; },
    p => { p.returnType.errors = Array.from({length: 17}, (_, i) => 'E' + String(i).padStart(2, '0')); },
    p => { p.returnType.errors = [{atom: 'IdentityUnknown'}]; },
    p => { p.constants.push({kind: 'error', atom: 'NotDeclared'}); },
    p => { p.constants.push({kind: 'error', atom: 'IdentityUnknown', payload: null}); },
    p => { p.constants.push({kind: 'error', atom: 'IdentityUnknown', value: 0}); },
    p => { p.constants.push({kind: 'u64', value: 1, atom: 'IdentityUnknown'}); },
    p => { p.constants.push({kind: 'unit'}); },
    p => { p.constants.push({kind: 'bool', value: true}); },
    p => { p.constants.push({kind: 'u64', value: -0}); },
    p => { p.constants.push({kind: 'u64', value: 2}); }
  ];
  for (const mutate of invalid) {
    const candidate = clone(compiled); mutate(candidate);
    assert.equal(runtime.validate(candidate), false);
    const result = evaluate(candidate); closed(result);
    assert.equal(result.outcome, 'refused');
    assert.equal(result.fuelUsed, 0);
  }
});

test('UNIT is the native success value; booleans and numerics cannot substitute for it', () => {
  const unit = unitProgram();
  assert.deepEqual(evaluate(unit, {}).decision, {kind: 'allow'});
  assert.equal(evaluate(unit, {}).fuelUsed, 1);
  for (const value of [0, 1]) {
    const numeric = {...unitProgram(), constants: [{kind: 'u64', value}], code: [word(1), word(15)]};
    const result = evaluate(numeric, {}); closed(result); assert.equal(result.code, 'AXI-R025');
  }
  for (const value of [false, true]) {
    const bool = {...unitProgram(), params: ['gate'], code: [word(15)]};
    const result = evaluate(bool, {gate: value}); closed(result); assert.equal(result.code, 'AXI-R025');
  }
  for (const code of [[word(22)], [word(0)]]) {
    const result = evaluate({...unitProgram(), code}, {}); closed(result);
    assert.equal(result.code, 'AXI-R001');
  }
});

test('ERR moves and comparisons preserve atom identity even when registers alias', () => {
  const declared = {kind: 'error', atom: 'IdentityUnknown'};
  const moved = {...unitProgram(), constants: [declared], code: [word(1), word(2, 1, 0), word(15, 1)]};
  assert.deepEqual(evaluate(moved, {}).decision, {kind: 'deny', reason: 'IdentityUnknown'});
  const cmp = (left, right) => ({...unitProgram(), registers: 4,
    constants: [{kind: 'error', atom: left}, {kind: 'error', atom: right}],
    code: [word(1, 0), word(1, 1, 0, 1), word(9, 0, 0, 1), word(13, 0, 0, 2), word(15, 3), word(15, 1)]});
  assert.deepEqual(evaluate(cmp('IdentityUnknown', 'IdentityUnknown'), {}).decision, {kind: 'allow'});
  assert.deepEqual(evaluate(cmp('IdentityUnknown', 'Unavailable'), {}).decision, {kind: 'deny', reason: 'Unavailable'});
  for (const opcode of [word(8, 0, 0), word(13, 0, 0, 1)]) {
    const candidate = {...unitProgram(), constants: [declared], code: [word(1), opcode, word(15, 2)]};
    const result = evaluate(candidate, {}); closed(result); assert.equal(result.code, 'AXI-R004');
  }
});

test('fuel exhaustion never retains a previous reason or permit', () => {
  for (const supplied of [facts(), facts(false, false, false), facts(true, true, false)]) {
    const successful = evaluate(compiled, supplied);
    for (let budget = 0; budget < successful.fuelUsed; budget++) {
      const result = evaluate(compiled, supplied, budget); closed(result);
      assert.equal(result.code, 'AXI-R008');
      assert.equal(result.fuelUsed, budget);
    }
    assert.deepEqual(evaluate(compiled, supplied, successful.fuelUsed).decision, successful.decision);
  }
});

test('v2 collections, integers and forward-only code retain bounded admission', () => {
  for (const [key, values] of [
    ['code', Array(129).fill(word(0))],
    ['params', Array.from({length: 17}, (_, i) => 'p' + i)],
    ['constants', Array.from({length: 33}, () => ({kind: 'u64', value: 0}))]
  ]) {
    const candidate = clone(compiled); let reads = 0;
    candidate[key] = new Proxy(values, {get(target, name, receiver) {
      if (name === 'length') return ++reads === 1 ? 1 : values.length;
      return Reflect.get(target, name, receiver);
    }});
    closed(evaluate(candidate)); assert.equal(reads, 0, key);
  }
  for (const instruction of [0x100000000 + word(15), -0, -1, NaN, Infinity, 15.5,
    word(12), word(12, 0, 255, 255), word(13, 0, 128, 0), word(12, 0, 0, 127), word(16)]) {
    const result = evaluate({...unitProgram(), code: [instruction, word(15, 2)]}, {});
    closed(result); assert.equal(result.fuelUsed, 0);
  }
});

test('getters and unknown fields cannot create a typed decision', () => {
  for (const location of ['contract', 'errors', 'constant', 'atom', 'facts', 'fuel']) {
    const candidate = clone(compiled), supplied = facts(), options = {fuel: 64};
    let calls = 0;
    const descriptor = {configurable: true, enumerable: true, get() { calls++; throw Error('accessor executed'); }};
    if (location === 'contract') Object.defineProperty(candidate, 'returnType', descriptor);
    if (location === 'errors') Object.defineProperty(candidate.returnType.errors, '0', descriptor);
    if (location === 'constant') Object.defineProperty(candidate.constants[1], 'kind', descriptor);
    if (location === 'atom') Object.defineProperty(candidate.constants[1], 'atom', descriptor);
    if (location === 'facts') Object.defineProperty(supplied, 'identityKnown', descriptor);
    if (location === 'fuel') Object.defineProperty(options, 'fuel', descriptor);
    closed(runtime.evaluate(candidate, supplied, options)); assert.equal(calls, 0, location);
  }
  const candidate = clone(compiled);
  candidate.returnType[Symbol('extra')] = 'unit';
  closed(evaluate(candidate));
  closed(evaluate(compiled, Object.create(facts())));
  closed(evaluate(compiled, vm.runInNewContext('(' + JSON.stringify(facts()) + ')')));
  assert.equal(evaluate(compiled, Object.assign(Object.create(null), facts())).allowed, true);
});

test('one invocation snapshots error atoms without caching caller-owned mutable programs', () => {
  const candidate = clone(compiled), supplied = facts(false, false, false);
  const constant = candidate.constants.find(k => k.kind === 'error' && k.atom === 'IdentityUnknown');
  let changed = false;
  const hostileFacts = new Proxy(supplied, {getOwnPropertyDescriptor(target, key) {
    if (!changed) { changed = true; constant.atom = 'Unavailable'; }
    return Reflect.getOwnPropertyDescriptor(target, key);
  }});
  const first = evaluate(candidate, hostileFacts);
  assert.equal(changed, true);
  assert.deepEqual(first.decision, {kind: 'deny', reason: 'IdentityUnknown'});
  assert.deepEqual(evaluate(candidate, supplied).decision, {kind: 'deny', reason: 'Unavailable'});
  assert.deepEqual(evaluate(compiled, supplied).decision, first.decision);
  assert.equal(Object.isFrozen(first), true);
});

test('browser realm produces the same typed reason without ambient I/O or dynamic code', () => {
  const context = vm.createContext({calls: 0});
  vm.runInContext('globalThis.fetch=()=>{calls++;throw Error("fetch")};globalThis.eval=()=>{calls++;throw Error("eval")};', context);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../runtime/portable-decision-v2.js'), 'utf8'), context, {timeout: 1000});
  const output = vm.runInContext('AxialPortableDecisionV2.evaluate(' + JSON.stringify(compiled) + ',' +
    JSON.stringify(facts(false, false, false)) + ',{fuel:64})', context, {timeout: 1000});
  assert.equal(output.allowed, false);
  assert.equal(output.decision.reason, 'IdentityUnknown');
  assert.equal(context.calls, 0);
});
