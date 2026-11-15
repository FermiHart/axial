#!/usr/bin/env node
/* Isolated build and deterministic native/JS numeric corpus.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const identity = require('./portable-numeric-build.cjs');
const runtime = require('../runtime/portable-numeric-v1.js');
const root = path.resolve(__dirname, '..');
const SEED = '0x6d1f009abeef1234';

function runGate({sanitize = false, leakDetection = true} = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'axial-numeric-seeded-'));
  const build = path.join(directory, 'build');
  const compiler = process.env.HOSTCC || 'cc';
  // Fail on findings, with no automatic fallback. Leak checking can only be
  // disabled explicitly for environments where LeakSanitizer cannot run.
  const env = {...process.env, ASAN_OPTIONS: `detect_leaks=${leakDetection ? 1 : 0}:halt_on_error=1`,
    UBSAN_OPTIONS: 'halt_on_error=1:print_stacktrace=1'};
  const run = (command, args, extra = {}) => {
    const r = cp.spawnSync(command, args, {cwd: root, env, encoding: 'utf8',
      timeout: 120000, maxBuffer: 64 * 1024 * 1024, ...extra});
    assert.equal(r.status, 0, `${command} ${args.join(' ')}: ${r.error || r.signal || ''}\n${r.stderr || ''}\n${r.stdout?.slice(0, 1000) || ''}`);
    return r.stdout;
  };
  try {
    const before = identity.coreDigest();
    const flags = ['-std=c99', '-Wall', '-Wextra', '-Werror', '-O1', '-D_POSIX_C_SOURCE=200809L', '-D_DARWIN_C_SOURCE'];
    if (sanitize) flags.push('-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie');
    const linker = sanitize ? ['-fsanitize=address,undefined', '-no-pie'] : [];
    run('make', ['-j4', `BUILD=${build}`, `HOSTCC=${compiler}`, `CFLAGS=${flags.join(' ')}`, `LDFLAGS=${linker.join(' ')}`, 'dev']);
    assert.equal(identity.coreDigest(), before, 'compiler source changed while building');
    const objects = fs.readdirSync(path.join(root, 'src')).filter(n => n.endsWith('.c') && n !== 'axi_main.c' && n !== 'axi_dossier_main.c')
      .sort().map(n => path.join(build, 'src', n.replace(/\.c$/, '.o')));
    const binary = path.join(directory, 'numeric-export');
    run(compiler, [...flags, '-Isrc', '-Iinclude', '-Ivendor',
      `-DAXIAL_PORTABLE_CORE_DIGEST="${before}"`,
      `-DAXIAL_PORTABLE_CORE_REVISION="${run('git', ['rev-parse', 'HEAD']).trim()}"`,
      'tools/portable-numeric-export.c', ...objects, path.join(build, 'vendor/ed25519.o'),
      ...linker, '-lm', '-o', binary]);
    const sources = fs.readdirSync(path.join(root, 'tests/portable-numeric')).filter(n => n.endsWith('.axi')).sort()
      .map(n => path.join(root, 'tests/portable-numeric', n));
    const compositions = {
      'branch-div': '  if b == a { ret a }\n  if b < a { ret a / b }\n  ret a * b',
      'remainder-chain': '  ret (a * b) % b',
      'multiply-chain': '  ret (a * b) + (a - b)',
      'nested-branch': '  if a < b {\n    if a + b < a { ret a - b }\n    ret b - a\n  }\n  ret a + b',
      'signed-constant': '  ret (a * -1) + (b / -1)'
    };
    for (const [name, body] of Object.entries(compositions)) {
      const file = path.join(directory, `${name}.axi`);
      fs.writeFileSync(file, `cell calculate : fn(a: i64, b: i64) -> i64\n  fuel 64\n  pure\n{\n${body}\n}\n`);
      fs.writeFileSync(file, run(path.join(build, 'axi'), ['canon', file]));
      sources.push(file);
    }
    let seed = BigInt(SEED);
    const random = () => { seed = (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n); return seed; };
    const values = ['-9223372036854775808', '-9223372036854775807', '-9007199254740993', '-4294967296', '-7', '-1', '0', '1', '2', '7', '4294967296', '9007199254740993', '9223372036854775806', '9223372036854775807'];
    const cases = [];
    for (const a of values) for (const b of values) for (let fuel = 0; fuel <= 24; fuel++) cases.push({a, b, fuel});
    for (let i = 0; i < 1024; i++) cases.push({a: BigInt.asIntN(64, random()).toString(), b: BigInt.asIntN(64, random()).toString(), fuel: Number(random() % 65n)});
    for (const a of values) for (const b of values) cases.push({a, b, fuel: 4096});
    const input = cases.map(c => `${c.a} ${c.b} ${c.fuel}\n`).join('');
    const counts = {comparisons: 0, success: 0, exhausted: 0, otherTraps: 0, malformedRefused: 0};
    for (const source of sources) {
      const p = JSON.parse(run(binary, ['export', source]));
      assert.equal(runtime.validate(p), true, source);
      const native = run(binary, ['oracle', source], {input}).trim().split('\n').map(JSON.parse);
      assert.equal(native.length, cases.length);
      for (let i = 0; i < cases.length; i++) {
        const c = cases[i], actual = runtime.evaluate(p, {a: c.a, b: c.b}, {fuel: c.fuel});
        assert.deepEqual({ok: actual.ok, value: actual.value, fuelUsed: actual.fuelUsed,
          fuelLimit: actual.fuelLimit, fuelExhausted: actual.code === 'AXI-R008'}, native[i], `${path.basename(source)} seed=${SEED} case=${i} ${JSON.stringify(c)}`);
        counts.comparisons++;
        if (actual.ok) counts.success++;
        else if (actual.code === 'AXI-R008') counts.exhausted++;
        else counts.otherTraps++;
      }
      // Unknown opcodes must be rejected structurally, independently of fuel.
      for (let i = 0; i < 32; i++) {
        const q = JSON.parse(JSON.stringify(p));
        const index = Number(random() % BigInt(q.code.length));
        q.code[index] = (q.code[index] & 0xffffff00 | (23 + Number(random() % 233n))) >>> 0;
        assert.equal(runtime.validate(q), false, `bad opcode accepted in ${source}`);
        assert.equal(runtime.evaluate(q, {a: '0', b: '0'}, {fuel: 4096}).outcome, 'refused');
        counts.malformedRefused++;
      }
    }
    assert.ok(counts.success && counts.exhausted && counts.otherTraps, 'missing outcome coverage');
    assert.equal(identity.coreDigest(), before, 'compiler source changed during gate');
    return {profile: runtime.profile, mode: sanitize ? 'asan-ubsan' : 'plain', leakDetection: sanitize && leakDetection, seed: SEED,
      compilerSourceDigest: before, compiler: run(compiler, ['--version']).split('\n')[0],
      node: process.version, platform: process.platform, arch: process.arch,
      fixtures: sources.length, casesPerFixture: cases.length,
      corpusSha256: crypto.createHash('sha256').update(input).digest('hex'), ...counts};
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
}
module.exports = {runGate};
if (require.main === module) {
  try { process.stdout.write(JSON.stringify(runGate({sanitize: process.argv.includes('--sanitize'), leakDetection: !process.argv.includes('--no-leaks')}), null, 2) + '\n'); }
  catch (error) { process.stderr.write(`${error.stack}\n`); process.exitCode = 1; }
}
