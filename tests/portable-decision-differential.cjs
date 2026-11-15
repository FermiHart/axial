'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const vm = require('node:vm');
const tool = require('../tools/portable-decision-build.cjs');
const runtime = require('../runtime/portable-decision-v2.js');
tool.build();
const fixture = path.join(__dirname, 'portable-decision', 'access.axi');
const source = process.env.AXIAL_DECISION_SOURCE || fixture;
const program = JSON.parse(tool.exportPolicy(source));
const allTrue = Object.fromEntries(program.params.map(k => [k, true]));
const copy = value => JSON.parse(JSON.stringify(value));
const word = (op, a = 0, b = 0, c = 0) => (op | (a << 8) | (b << 16) | (c << 24)) >>> 0;
const digest = value => crypto.createHash('sha256').update(value).digest('hex');

function compareNative(file, p) {
  const lines = tool.run(tool.binary, ['oracle', path.resolve(file)]).trim().split('\n');
  const counts = {combinations: 2 ** p.params.length, nativeComparisons: lines.length,
    allows: 0, denials: 0, exhausted: 0};
  for (const line of lines) {
    const oracle = JSON.parse(line);
    const facts = Object.fromEntries(p.params.map((name, i) => [name, !!((oracle.mask >>> i) & 1)]));
    const actual = runtime.evaluate(p, facts, {fuel: oracle.fuel});
    assert.deepEqual({ok: actual.ok, allowed: actual.allowed, decision: actual.decision,
      fuelUsed: actual.fuelUsed, fuelLimit: actual.fuelLimit, fuelExhausted: actual.code === 'AXI-R008'},
    {ok: oracle.ok, allowed: oracle.allowed, decision: oracle.decision,
      fuelUsed: oracle.fuelUsed, fuelLimit: oracle.fuelLimit, fuelExhausted: oracle.fuelExhausted},
    `mask=${oracle.mask}, requested fuel=${oracle.fuel}, source=${file}`);
    if (actual.allowed) {
      counts.allows++;
      assert.equal(actual.outcome, 'allow'); assert.equal(actual.code, 'AXP-ALLOW');
    } else if (actual.ok) {
      counts.denials++;
      assert.equal(actual.outcome, 'deny'); assert.equal(actual.code, 'AXP-DENY');
      assert.ok(p.returnType.errors.includes(actual.decision.reason));
    } else {
      counts.exhausted++;
      assert.equal(actual.decision, null); assert.equal(actual.outcome, 'trap');
    }
  }
  return counts;
}

function temporarySource(code, action) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'axial-decision-'));
  try {
    const file = path.join(directory, 'decision.axi'); fs.writeFileSync(file, code);
    const canonical = tool.run(path.join(tool.root, 'build', 'axi'), ['canon', file]);
    fs.writeFileSync(file, canonical);
    return action(file);
  } finally { fs.rmSync(directory, {recursive: true, force: true}); }
}

test('v2 source and compiler identity are exact and export is deterministic', () => {
  assert.equal(program.sourceSha256, digest(fs.readFileSync(source)));
  assert.equal(program.compilerSourceDigest, tool.coreDigest());
  assert.equal(tool.exportPolicy(source), tool.exportPolicy(source));
  assert.equal(program.format, runtime.profile);
  assert.equal(runtime.validate(program), true);
  assert.deepEqual(program.returnType, {kind: 'result', ok: 'unit',
    errors: [...program.returnType.errors].sort()});
});

test('all bool combinations, exact typed reasons and prefix fuel budgets match the C VM', () => {
  const counts = compareNative(source, program);
  assert.ok(counts.allows > 0 && counts.denials > 0 && counts.exhausted > 0);
  console.log(JSON.stringify({profile: runtime.profile, sourceSha256: program.sourceSha256, ...counts}));
});

test('multiple failed facts return the first reason specified by the compiled policy', () => {
  const p = JSON.parse(tool.exportPolicy(fixture));
  const reasons = ['IdentityUnknown', 'ResourceDenied', 'Unavailable'];
  for (let mask = 0; mask < 8; mask++) {
    const facts = Object.fromEntries(p.params.map((name, i) => [name, !!(mask & (1 << i))]));
    const failed = p.params.findIndex(name => !facts[name]);
    const actual = runtime.evaluate(p, facts, {fuel: 64});
    assert.deepEqual(actual.decision, failed < 0 ? {kind: 'allow'} : {kind: 'deny', reason: reasons[failed]});
    assert.equal(actual.ok, true);
    assert.ok(Object.isFrozen(actual) && Object.isFrozen(actual.decision));
  }
});

test('reordered opaque reasons and bool literals are executed, not reconstructed from facts', () => {
  temporarySource(`cell decide : fn(x: bool, y: bool) -> ok | err.Zeta | err.Alpha
  fuel 64
  pure
{
  if y == true { ret err.Zeta }
  if x == false { ret err.Alpha }
  ret ok
}
`, file => {
    const p = JSON.parse(tool.exportPolicy(file));
    assert.ok(p.code.some(w => (w & 255) === 9)); // Real compiled EQ.
    assert.deepEqual(p.returnType.errors, ['Alpha', 'Zeta']);
    assert.deepEqual(runtime.evaluate(p, {x: true, y: true}, {fuel: 64}).decision, {kind: 'deny', reason: 'Zeta'});
    assert.deepEqual(runtime.evaluate(p, {x: false, y: false}, {fuel: 64}).decision, {kind: 'deny', reason: 'Alpha'});
    assert.deepEqual(runtime.evaluate(p, {x: true, y: false}, {fuel: 64}).decision, {kind: 'allow'});
    const counts = compareNative(file, p);
    assert.ok(counts.allows && counts.denials && counts.exhausted);
  });
});

test('unknown result shapes, payloads, atoms and constants are refused before execution', () => {
  const mutate = change => { const candidate = copy(program); change(candidate); return candidate; };
  const bad = [
    mutate(p => { p.format = 'axial.portable-pure.v1'; }),
    mutate(p => { p.returnType = 'bool'; }),
    mutate(p => { p.returnType.kind = 'enum'; }),
    mutate(p => { p.returnType.ok = 'bool'; }),
    mutate(p => { p.returnType.payload = 'u64'; }),
    mutate(p => { p.returnType.errors = []; }),
    mutate(p => { p.returnType.errors = ['Same', 'Same']; }),
    mutate(p => { p.returnType.errors = ['Zeta', 'Alpha']; }),
    mutate(p => { p.returnType.errors = ['Spaced Atom']; }),
    mutate(p => { p.returnType.errors = ['err.Atom']; }),
    mutate(p => { p.returnType.errors = ['Atom\u0000']; }),
    mutate(p => { p.returnType.errors = ['Atom\n']; }),
    mutate(p => { p.returnType.errors = ['Atom\r']; }),
    mutate(p => { p.returnType.errors = ['Atom\u2028']; }),
    mutate(p => { p.returnType.errors = ['A'.repeat(64)]; }),
    mutate(p => { p.constants[0] = 0; }),
    mutate(p => { p.constants[0] = {kind: 'u64', value: 2}; }),
    mutate(p => { p.constants[0] = {kind: 'u64', value: '0'}; }),
    mutate(p => { p.constants[0] = {kind: 'unit'}; }),
    mutate(p => { p.constants[0] = {kind: 'union', tag: 0, payload: null}; }),
    mutate(p => { p.constants[0] = {kind: 'error', atom: 'UnknownAtom'}; }),
    mutate(p => { p.constants[0] = {kind: 'error', atom: p.returnType.errors[0], payload: ''}; }),
    mutate(p => { p.constants[0] = {kind: 'error', atom: p.returnType.errors[0], value: 0}; }),
    mutate(p => { p.constants[0] = {kind: 'error', atom: {toString() { throw Error('must not coerce'); }}}; })
  ];
  for (const candidate of bad) {
    const result = runtime.evaluate(candidate, allTrue, {fuel: 256});
    assert.equal(runtime.validate(candidate), false);
    assert.equal(result.allowed, false); assert.equal(result.outcome, 'refused');
    assert.equal(result.fuelUsed, 0); assert.equal(result.decision, null);
  }
});

test('invalid return kinds, halt and falloff never fabricate a decision', () => {
  for (const [code, expected] of [
    [[word(15, 0)], 'AXI-R025'], // bool argument is not a typed decision.
    [[word(1, 0), word(15, 0)], 'AXI-R025'], // u64 zero is not UNIT.
    [[word(22)], 'AXI-R001'], [[word(0)], 'AXI-R001'],
    [[word(1, 0), word(8, 0, 0)], 'AXI-R004']
  ]) {
    const candidate = {...copy(program), constants: [{kind: 'u64', value: 0}], code};
    const actual = runtime.evaluate(candidate, allTrue, {fuel: 256});
    assert.equal(actual.ok, false); assert.equal(actual.allowed, false);
    assert.equal(actual.decision, null); assert.equal(actual.code, expected);
  }
});

test('closed opcode, register, instruction count and forward jump bounds remain enforced', () => {
  const mutate = change => { const candidate = copy(program); change(candidate); return candidate; };
  for (const candidate of [
    mutate(p => { p.code[0] = word(14); }), // CALL
    mutate(p => { p.code[0] = word(20); }), // EFF
    mutate(p => { p.code[0] = word(23); }), // UMAKE
    mutate(p => { p.code[0] = word(1, 255); }),
    mutate(p => { p.code[0] = word(1, 0, 255, 255); }),
    mutate(p => { p.code[0] = word(12, 0, 255, 255); }),
    mutate(p => { p.code[0] = word(12); }),
    mutate(p => { p.code[0] = word(12, 0, 0, p.code.length); }),
    mutate(p => { p.code[0] = 0x100000000; }),
    mutate(p => { p.code = new Array(129).fill(word(0)); }),
    mutate(p => { p.registers = 33; }),
    mutate(p => { p.fuelMax = 4097; }),
    mutate(p => { p.entry += '\n'; }),
    mutate(p => { p.params[0] += '\n'; }),
    mutate(p => { p.ifaceHash += '\n'; }),
    mutate(p => { p.compilerSourceRevision += '\n'; })
  ]) {
    const actual = runtime.evaluate(candidate, allTrue, {fuel: 256});
    assert.equal(actual.outcome, 'refused'); assert.equal(actual.fuelUsed, 0);
    assert.equal(actual.decision, null);
  }
});

test('strict facts, explicit fuel, getters and mutable nested objects fail closed', () => {
  for (const value of [null, undefined, 0, 1, '', 'true', [], {}, NaN, Infinity]) {
    const facts = {...allTrue, [program.params[0]]: value};
    assert.equal(runtime.evaluate(program, facts, {fuel: 256}).code, 'AXP-A001');
  }
  for (const fuel of [undefined, null, '256', -1, -0, 0.5, NaN, Infinity, 4097])
    assert.equal(runtime.evaluate(program, allTrue, {fuel}).code, 'AXP-F001');
  const zero = runtime.evaluate(program, allTrue, {fuel: 0});
  assert.equal(zero.code, 'AXI-R008'); assert.equal(zero.fuelUsed, 0); assert.equal(zero.decision, null);
  let accessed = false;
  const candidate = copy(program);
  Object.defineProperty(candidate.constants[0], 'kind', {enumerable: true, get() { accessed = true; return 'u64'; }});
  assert.equal(runtime.evaluate(candidate, allTrue, {fuel: 256}).outcome, 'refused');
  assert.equal(accessed, false);
  const second = copy(program);
  Object.defineProperty(second.returnType, 'errors', {enumerable: true, get() { accessed = true; return []; }});
  assert.equal(runtime.evaluate(second, allTrue, {fuel: 256}).outcome, 'refused');
  assert.equal(accessed, false);
  const copied = copy(program);
  const facts = new Proxy({...allTrue}, {getOwnPropertyDescriptor(target, key) {
    // Changes after the program snapshot cannot replace the copied code/data.
    copied.constants = [{kind: 'error', atom: 'UnknownAtom'}]; copied.code = [word(22)];
    copied.returnType.errors = [];
    return Reflect.getOwnPropertyDescriptor(target, key);
  }});
  assert.deepEqual(runtime.evaluate(copied, facts, {fuel: 256}).decision, {kind: 'allow'});
});

test('native checker/exporter refuses bool, payload returns, dotted atoms and wider programs', () => {
  for (const code of [
    'cell decide : fn(x: bool) -> bool fuel 32 pure { ret x }',
    'cell decide : fn(x: bool) -> u64 | ok | err.No fuel 32 pure { if x { ret 1 } ret ok }',
    'cell decide : fn(x: bool) -> ok | err.Space.Name fuel 32 pure { if x { ret err.Space.Name } ret ok }',
    'cell decide : fn(x: u64) -> ok | err.No fuel 32 pure { if x == 0 { ret ok } ret err.No }',
    'cell decide : fn(x: bool) -> ok fuel 32 pure { if x { ret ok } ret ok }',
    'cell decide : fn(x: bool) -> ok | err.No fuel 32 pure { if x { ret err.Undeclared } ret ok }'
  ]) temporarySource(code, file => { assert.throws(() => tool.exportPolicy(file), /refused|AXI-T/); });
});

test('canonical source gate is enforced by both coordinator and native exporter', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'axial-decision-canon-'));
  try {
    const file = path.join(directory, 'not-canonical.axi');
    fs.writeFileSync(file, 'cell decide : fn(x: bool) -> ok | err.No fuel 32 pure { if x { ret ok } ret err.No }\n');
    assert.throws(() => tool.exportPolicy(file), /AXI-C/);
    assert.throws(() => tool.run(tool.binary, ['export', file]), /AXP-C001/);
  } finally { fs.rmSync(directory, {recursive: true, force: true}); }
});

test('v1 exporter artifact remains byte-identical and profiles refuse each other', () => {
  const legacyTool = require('../tools/portable-policy-build.cjs');
  const legacyRuntime = require('../runtime/portable-pure-v1.js');
  legacyTool.build();
  const bytes = legacyTool.exportPolicy(path.join(__dirname, 'portable-policy', 'access.axi'));
  assert.equal(digest(bytes), '1c38339cfd8fc6cfa7dd67704ad40e7b758cbea1bf3ef3248d921b61c202b2e3');
  const legacy = JSON.parse(bytes);
  assert.equal(legacyRuntime.validate(legacy), true); assert.equal(runtime.validate(legacy), false);
  assert.equal(legacyRuntime.validate(program), false);
  const facts = Object.fromEntries(legacy.params.map(k => [k, true]));
  assert.equal(legacyRuntime.evaluate(legacy, facts, {fuel: 64}).allowed, true);
  assert.equal('decision' in legacyRuntime.evaluate(legacy, facts, {fuel: 64}), false);
});

test('standalone browser runtime yields the exact decision without code generation', () => {
  const context = vm.createContext({});
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../runtime/portable-decision-v2.js'), 'utf8'), context,
    {timeout: 1000});
  const result = vm.runInContext(`AxialPortableDecisionV2.evaluate(${JSON.stringify(program)}, ${JSON.stringify(allTrue)}, {fuel:256})`, context,
    {timeout: 1000});
  assert.equal(result.allowed, true); assert.equal(result.decision.kind, 'allow');
  assert.equal(result.sourceSha256, program.sourceSha256);
});
