'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {runGate} = require('../tools/portable-numeric-seeded-gate.cjs');
test('isolated native compiler/VM seeded arithmetic, branch and fuel corpus', {timeout: 180000}, () => {
  const result = runGate({sanitize: process.env.AXIAL_NUMERIC_SANITIZERS === '1', leakDetection: process.env.AXIAL_NUMERIC_LEAKS !== '0'});
  assert.equal(result.fixtures, 16);
  assert.equal(result.casesPerFixture, 6120);
  assert.equal(result.comparisons, 97920);
  assert.equal(result.malformedRefused, 512);
  console.log(JSON.stringify(result));
});
