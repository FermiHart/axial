'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const vm = require('node:vm');
const tool = require('../tools/portable-policy-build.cjs');
const runtime = require('../runtime/portable-pure-v1.js');
tool.build();
const source = process.env.AXIAL_POLICY_SOURCE || path.join(__dirname, 'portable-policy', 'access.axi');
const program = JSON.parse(tool.exportPolicy(source));
const allTrue = Object.fromEntries(program.params.map(k => [k, true]));
const copy = value => JSON.parse(JSON.stringify(value));
const word = (op, a = 0, b = 0, c = 0) => (op | (a << 8) | (b << 16) | (c << 24)) >>> 0;

test('source bytes and native compiler output identify the exported policy', () => {
  assert.equal(program.sourceSha256, crypto.createHash('sha256').update(fs.readFileSync(source)).digest('hex'));
  assert.equal(program.compilerSourceDigest, tool.coreDigest());
  assert.equal(tool.exportPolicy(source), tool.exportPolicy(source));
  assert.equal(program.format, runtime.profile);
  assert.equal(runtime.validate(program), true);
});

test('all bool inputs and every prefix budget match the actual Axial C VM', () => {
  const lines = tool.run(tool.binary, ['oracle', path.resolve(source)]).trim().split('\n');
  let allows = 0, denials = 0, exhausted = 0;
  for (const line of lines) {
    const oracle = JSON.parse(line);
    const facts = Object.fromEntries(program.params.map((name, i) => [name, !!((oracle.mask >>> i) & 1)]));
    const actual = runtime.evaluate(program, facts, {fuel: oracle.fuel});
    assert.deepEqual({ok: actual.ok, allowed: actual.allowed, fuelUsed: actual.fuelUsed,
      fuelLimit: actual.fuelLimit, fuelExhausted: actual.code === 'AXI-R008'},
    {ok: oracle.ok, allowed: oracle.allowed, fuelUsed: oracle.fuelUsed,
      fuelLimit: oracle.fuelLimit, fuelExhausted: oracle.fuelExhausted},
    `mask=${oracle.mask}, requested fuel=${oracle.fuel}`);
    if (actual.allowed) allows++;
    else if (actual.ok) denials++;
    else exhausted++;
  }
  assert.ok(allows > 0 && denials > 0 && exhausted > 0);
  console.log(JSON.stringify({profile: runtime.profile, sourceSha256: program.sourceSha256,
    combinations: 2 ** program.params.length, nativeComparisons: lines.length, allows, denials, exhausted}));
});

test('strict input types, explicit budgets and hostile getters fail closed', () => {
  for (const value of [null, undefined, 0, 1, '', 'true', [], {}, NaN, Infinity]) {
    const facts = {...allTrue, [program.params[0]]: value};
    assert.equal(runtime.evaluate(program, facts, {fuel: 256}).allowed, false);
    assert.equal(runtime.evaluate(program, facts, {fuel: 256}).outcome, 'refused');
  }
  const missing = {...allTrue}; delete missing[program.params[0]];
  for (const facts of [missing, {...allTrue, unexpected: true}])
    assert.equal(runtime.evaluate(program, facts, {fuel: 256}).code, 'AXP-A001');
  for (const fuel of [undefined, null, '256', -1, -0, 0.5, NaN, Infinity, 4097])
    assert.equal(runtime.evaluate(program, allTrue, {fuel}).code, 'AXP-F001');
  assert.equal(runtime.evaluate(program, allTrue, {fuel: 0}).code, 'AXI-R008');
  let accessed = false;
  const getter = {...allTrue};
  Object.defineProperty(getter, program.params[0], {enumerable: true, get() { accessed = true; return true; }});
  assert.equal(runtime.evaluate(program, getter, {fuel: 256}).allowed, false);
  assert.equal(accessed, false);
});

test('unknown features and malformed words are refused before any execution', () => {
  const mutate = change => { const candidate = copy(program); change(candidate); return candidate; };
  const bad = [
    mutate(p => { p.format = 'axial.portable-pure.v2'; }),
    mutate(p => { p.effects = []; }),
    mutate(p => { p.constants[0] = 2; }),
    mutate(p => { p.constants[0] = '0'; }),
    mutate(p => { p.params.push(p.params[0]); }),
    mutate(p => { p.registers = 33; }),
    mutate(p => { p.code[0] = word(20); }), // EFF
    mutate(p => { p.code[0] = word(14); }), // CALL
    mutate(p => { p.code[0] = word(1, 255); }),
    mutate(p => { p.code[0] = word(1, 0, 255, 255); }),
    mutate(p => { p.code[0] = word(12, 0, 255, 255); }), // negative jump
    mutate(p => { p.code[0] = word(12); }), // self-loop
    mutate(p => { p.code[0] = word(12, 0, 0, 127); }),
    mutate(p => { p.code[0] = 0x100000000; }),
    mutate(p => { p.code = new Array(2); }),
    mutate(p => { p.fuelMax = 4097; }),
    mutate(p => { p.ifaceHash = 'not-a-hash'; })
  ];
  for (const candidate of bad) {
    const actual = runtime.evaluate(candidate, allTrue, {fuel: 256});
    assert.equal(actual.allowed, false);
    assert.equal(actual.outcome, 'refused');
    assert.equal(actual.fuelUsed, 0);
  }
  for (const [code, expected] of [[[word(22)], 'AXI-R001'], [[word(0)], 'AXI-R001'],
    [[word(1, 0), word(15, 0)], 'AXI-R025'], [[word(1, 0), word(8, 0, 0)], 'AXI-R004']]) {
    const candidate = {...copy(program), code};
    const actual = runtime.evaluate(candidate, allTrue, {fuel: 256});
    assert.equal(actual.allowed, false); assert.equal(actual.code, expected);
  }
});

test('exporter refuses wider programs instead of silently translating them', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'axial-portable-policy-'));
  try {
    for (const [name, code] of [
      ['number', 'cell decide : fn(x: u64) -> bool fuel 32 pure { ret x == 2 }'],
      ['calls', 'cell helper : fn(x: bool) -> bool fuel 32 pure { ret x }\ncell decide : fn(x: bool) -> bool fuel 64 pure { ret helper(x) }'],
      ['integer-return', 'cell decide : fn(x: bool) -> u64 fuel 32 pure { ret 1 }']
    ]) {
      const file = path.join(temporary, name + '.axi'); fs.writeFileSync(file, code);
      const canonical = tool.run(path.join(tool.root, 'build', 'axi'), ['canon', file]);
      fs.writeFileSync(file, canonical);
      assert.throws(() => tool.exportPolicy(file), /refused/);
    }
  } finally { fs.rmSync(temporary, {recursive: true, force: true}); }
});

test('noncanonical source is refused by the real Axial check gate', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'axial-portable-canon-'));
  try {
    const file = path.join(temporary, 'not-canonical.axi');
    fs.writeFileSync(file, 'cell decide : fn(x: bool) -> bool fuel 32 pure { ret x }\n');
    assert.throws(() => tool.exportPolicy(file), /AXI-C/);
    assert.throws(() => tool.run(tool.binary, ['export', file]), /AXP-C001/);
  } finally { fs.rmSync(temporary, {recursive: true, force: true}); }
});

test('standalone browser build runs the same compiled policy without code generation', () => {
  const context = vm.createContext({});
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../runtime/portable-pure-v1.js'), 'utf8'), context,
    {timeout: 1000});
  const result = vm.runInContext(`AxialPortablePureV1.evaluate(${JSON.stringify(program)}, ${JSON.stringify(allTrue)}, {fuel:256})`, context,
    {timeout: 1000});
  assert.equal(result.allowed, true);
  assert.equal(result.sourceSha256, program.sourceSha256);
});
