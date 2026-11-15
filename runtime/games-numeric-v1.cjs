/* Exact bounded host-side numeric helpers for Axial game adapters.
 * Not a bytecode extension or an authority boundary.
 * Copyright (c) 2026 Fermi Hart <contact@fermihart.com>
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
'use strict';
const MIN = -(1n << 63n), MAX = (1n << 63n) - 1n;
const MAX_SCALE = 9;
const POW10 = Object.freeze(Array.from({length: MAX_SCALE + 1}, (_, i) => 10n ** BigInt(i)));
const fail = code => Object.freeze({ok: false, code});
const success = value => Object.freeze({ok: true, value});
const invalid = fail('AXN-INPUT');
function integer(text) {
  // Check primitive and length before regex/BigInt: no coercion or unbounded parse.
  if (typeof text !== 'string' || text.length < 1 || text.length > 20) return null;
  const match = /^(?:0|-?[1-9][0-9]*)$/.exec(text);
  if (!match || match[0] !== text) return null;
  const n = BigInt(text);
  return n < MIN || n > MAX ? null : n;
}
function scale(value) {
  return Number.isInteger(value) && !Object.is(value, -0) && value >= 0 && value <= MAX_SCALE;
}
function result(n) {
  return n < MIN || n > MAX ? fail('AXN-OVERFLOW') : success(n.toString());
}
function binary(a, b, fn) {
  const x = integer(a), y = integer(b);
  return x === null || y === null ? invalid : fn(x, y);
}
function add(a, b) { return binary(a, b, (x, y) => result(x + y)); }
function sub(a, b) { return binary(a, b, (x, y) => result(x - y)); }
function mul(a, b) { return binary(a, b, (x, y) => result(x * y)); }
function div(a, b) { return binary(a, b, (x, y) => y === 0n ? fail('AXN-ZERO') : result(x / y)); }
function compare(a, b) { return binary(a, b, (x, y) => success(x < y ? -1 : x > y ? 1 : 0)); }
function fixedMul(a, b, digits) {
  if (!scale(digits)) return invalid;
  return binary(a, b, (x, y) => result((x * y) / POW10[digits]));
}
function fixedDiv(a, b, digits) {
  if (!scale(digits)) return invalid;
  return binary(a, b, (x, y) => y === 0n ? fail('AXN-ZERO') : result((x * POW10[digits]) / y));
}
function rescale(a, from, to) {
  if (!scale(from) || !scale(to)) return invalid;
  const x = integer(a);
  if (x === null) return invalid;
  return result(to >= from ? x * POW10[to - from] : x / POW10[from - to]);
}
function parseDecimal(text, digits) {
  if (!scale(digits) || typeof text !== 'string' || text.length < 1 || text.length > 30) return invalid;
  const match = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?$/.exec(text);
  if (!match || match[0] !== text) return invalid;
  const fraction = match[3] || '';
  if (fraction.length > digits) return fail('AXN-PRECISION');
  const magnitude = BigInt(match[2]) * POW10[digits] + BigInt((fraction || '0').padEnd(digits, '0'));
  if (magnitude === 0n && match[1]) return invalid;
  return result(match[1] ? -magnitude : magnitude);
}
function formatDecimal(a, digits) {
  if (!scale(digits)) return invalid;
  const x = integer(a);
  if (x === null) return invalid;
  const sign = x < 0n ? '-' : '', absolute = (x < 0n ? -x : x).toString();
  if (digits === 0) return success(sign + absolute);
  const padded = absolute.padStart(digits + 1, '0');
  return success(sign + padded.slice(0, -digits) + '.' + padded.slice(-digits));
}
module.exports = Object.freeze({profile: 'axial.games-numeric.v1', min: MIN.toString(), max: MAX.toString(),
  maxScale: MAX_SCALE, add, sub, mul, div, compare, fixedMul, fixedDiv, rescale, parseDecimal, formatDecimal});
