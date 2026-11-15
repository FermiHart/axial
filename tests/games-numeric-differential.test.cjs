/* Independent C __int128 oracle vs checked HOST helpers, not Axial VM parity.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {mkdtempSync, rmSync} = require('node:fs');
const {tmpdir} = require('node:os');
const {join, resolve} = require('node:path');
const {spawnSync} = require('node:child_process');
const N = require('../runtime/games-numeric-v1.cjs');

test('checked host arithmetic matches independent C __int128 oracle', {timeout: 30000}, () => {
  const directory = mkdtempSync(join(tmpdir(), 'axial-games-numeric-'));
  try {
    const binary = join(directory, 'oracle');
    const compile = spawnSync(process.env.CC || 'cc', ['-std=c99', '-Wall', '-Wextra', '-Werror', '-O2',
      resolve(__dirname, '../tools/games-numeric-oracle.c'), '-o', binary], {encoding: 'utf8', timeout: 15000});
    assert.equal(compile.status, 0, `C compiler with __int128 required: ${compile.error || compile.stderr}`);
    const cases = [];
    const add = (op, a, b = '0', scale = 0, target = 0) => cases.push({op, a, b, scale, target});
    const bounds = [N.min, (BigInt(N.min) + 1n).toString(), '-1001', '-3', '-1', '0', '1', '3',
      '1001', '9007199254740993', (BigInt(N.max) - 1n).toString(), N.max];
    for (const a of bounds) for (const b of bounds) {
      for (const op of ['add', 'sub', 'mul', 'div']) add(op, a, b);
      for (const scale of [-1, 0, 1, 2, 8, 9, 10]) {
        add('fixedMul', a, b, scale);
        add('fixedDiv', a, b, scale);
      }
    }
    for (const a of bounds) for (let from = -1; from <= 10; from++) for (let to = -1; to <= 10; to++)
      add('rescale', a, '0', from, to);
    for (const a of ['+1', '01', '-0', '1e2', '9223372036854775808', '-9223372036854775809'])
      for (const op of ['add', 'sub', 'mul', 'div', 'fixedMul', 'fixedDiv', 'rescale']) add(op, a, '1');
    let seed = 0x73819283n;
    const next = () => {
      seed = (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
      return BigInt.asIntN(64, seed).toString();
    };
    for (let i = 0; i < 1000; i++) {
      const a = next(), b = next();
      for (const op of ['add', 'sub', 'mul', 'div', 'fixedMul', 'fixedDiv']) add(op, a, b, i % 10);
      add('rescale', a, '0', i % 10, (i * 7) % 10);
    }
    const input = cases.map(c => `${c.op} ${c.a} ${c.b} ${c.scale} ${c.target}\n`).join('');
    const run = spawnSync(binary, [], {input, encoding: 'utf8', timeout: 10000, maxBuffer: 8 * 1024 * 1024});
    assert.equal(run.status, 0, `oracle failed: ${run.error || run.stderr}`);
    const answers = run.stdout.trimEnd().split('\n');
    assert.equal(answers.length, cases.length);
    for (let i = 0; i < cases.length; i++) {
      const c = cases[i];
      const got = c.op === 'rescale' ? N.rescale(c.a, c.scale, c.target) : N[c.op](c.a, c.b, c.scale);
      const encoded = got.ok ? `OK:${got.value}` : `ERR:${got.code}`;
      assert.equal(encoded, answers[i], `case ${i}: ${JSON.stringify(c)}`);
    }
    assert.equal(cases.length, 11362);
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
});
