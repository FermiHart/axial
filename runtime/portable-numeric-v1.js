/* Axial portable numeric v1. Executes bounded native compiler bytecode.
 * Native compiler i64/bool results; i64 arithmetic wraps exactly as native VM.
 * No application policy translation, eval, effects, or signature admission.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.AxialPortableNumericV1 = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const PROFILE = 'axial.portable-numeric.v1';
  const MAX_FUEL = 4096;
  const PROGRAM_KEYS = ['format', 'compilerSourceRevision', 'compilerSourceDigest', 'sourceSha256',
    'ifaceHash', 'bodyHash', 'entry', 'fuelMax', 'params', 'returnType', 'registers', 'constants', 'code'];
  const NAME = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
  const HASH = /^[0-9a-f]{64}$/;
  const REVISION = /^[0-9a-f]{40}$/;
  const OP = Object.freeze({NOP: 0, LDK: 1, MOV: 2, ADD: 3, SUB: 4, MUL: 5, DIV: 6, MOD: 7, NOT: 8, EQ: 9, LT: 10, LE: 11,
    JMP: 12, JF: 13, RET: 15, HALT: 22});
  // Private tags, not a cast between the public C and private VM value ABIs.
  const UNIT = 0, I64 = 2, BOOL = 4;
  function integer(s) {
    if (typeof s !== 'string' || s.length > 20 || !exactMatch(/^(?:0|-?[1-9][0-9]*)$/, s)) return null;
    const n = BigInt(s); return n >= -(1n << 63n) && n < (1n << 63n) ? n : null;
  }

  function boundedInteger(value, max, min) {
    return Number.isInteger(value) && !Object.is(value, -0) && value >= (min || 0) && value <= max;
  }
  function exactMatch(pattern, value) {
    if (typeof value !== 'string') return false;
    // JavaScript's $ also matches before a final line terminator. Atoms and
    // provenance fields must occupy the entire string, byte for byte.
    const match = pattern.exec(value);
    return match !== null && match[0] === value;
  }
  function record(value, keys) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return null;
    const names = Reflect.ownKeys(value);
    if (names.length !== keys.length || names.some(k => typeof k !== 'string' || !keys.includes(k))) return null;
    const copy = Object.create(null);
    for (const key of keys) {
      const d = Object.getOwnPropertyDescriptor(value, key);
      if (!d || !Object.prototype.hasOwnProperty.call(d, 'value') || !d.enumerable) return null;
      copy[key] = d.value;
    }
    return copy;
  }
  function array(value, max) {
    if (!Array.isArray(value)) return null;
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    if (!lengthDescriptor || !Object.prototype.hasOwnProperty.call(lengthDescriptor, 'value')) return null;
    const length = lengthDescriptor.value;
    if (!boundedInteger(length, max) || Reflect.ownKeys(value).length !== length + 1) return null;
    const copy = [];
    for (let i = 0; i < length; i++) {
      const d = Object.getOwnPropertyDescriptor(value, String(i));
      if (!d || !Object.prototype.hasOwnProperty.call(d, 'value') || !d.enumerable) return null;
      copy.push(d.value);
    }
    return copy;
  }
  function constant(value) {
    const k = record(value, ['kind', 'value']);
    return k && ((k.kind === 'i64' && integer(k.value) !== null) || (k.kind === 'u64' && (k.value === '0' || k.value === '1'))) ? Object.freeze(k) : null;
  }
  function snapshot(program) {
    const p = record(program, PROGRAM_KEYS);
    if (!p || p.format !== PROFILE || !exactMatch(REVISION, p.compilerSourceRevision)
      || ![p.compilerSourceDigest, p.sourceSha256, p.ifaceHash, p.bodyHash].every(v => exactMatch(HASH, v))
      || !exactMatch(NAME, p.entry)
      || !boundedInteger(p.fuelMax, MAX_FUEL, 1) || !boundedInteger(p.registers, 32, 1)) return null;
    if (p.returnType !== 'i64' && p.returnType !== 'bool') return null;
    p.params = array(p.params, 16); p.constants = array(p.constants, 32); p.code = array(p.code, 128);
    if (!p.params || !p.constants || !p.code || !p.code.length || p.params.length > p.registers
      || p.params.some(v => !exactMatch(NAME, v))
      || new Set(p.params).size !== p.params.length
      || p.code.some(v => !boundedInteger(v, 0xffffffff))) return null;
    p.constants = p.constants.map(k => constant(k));
    if (p.constants.some(k => !k)) return null;
    for (let pc = 0; pc < p.code.length; pc++) {
      const w = p.code[pc], op = w & 255, a = (w >>> 8) & 255;
      const b = (w >>> 16) & 255, c = w >>> 24, bc = (b << 8) | c;
      const jump = bc >= 32768 ? bc - 65536 : bc;
      switch (op) {
        case OP.NOP: case OP.HALT: if (a || b || c) return null; break;
        case OP.LDK: if (a >= p.registers || bc >= p.constants.length) return null; break;
        case OP.MOV: case OP.NOT: if (a >= p.registers || b >= p.registers || c) return null; break;
        case OP.ADD: case OP.SUB: case OP.MUL: case OP.DIV: case OP.MOD:
        case OP.LT: case OP.LE: case OP.EQ: if (a >= p.registers || b >= p.registers || c >= p.registers) return null; break;
        case OP.JMP: case OP.JF:
          if ((op === OP.JMP ? a !== 0 : a >= p.registers) || jump <= 0 || pc + jump >= p.code.length) return null;
          break;
        case OP.RET: if (a >= p.registers || b || c) return null; break;
        default: return null;
      }
    }
    Object.freeze(p.params); Object.freeze(p.constants); Object.freeze(p.code);
    return Object.freeze(p);
  }
  function result(ok, outcome, code, used = 0, limit = 0, value = null) {
    return Object.freeze({ok, outcome, code, fuelUsed: used, fuelLimit: limit, value, profile: PROFILE});
  }
  function evaluate(program, facts, options) {
    try {
      const p = snapshot(program);
      if (!p) return result(false, 'refused', 'AXP-P001');
      const opts = record(options, ['fuel']);
      if (!opts || !boundedInteger(opts.fuel, MAX_FUEL)) return result(false, 'refused', 'AXP-F001');
      const values = record(facts, p.params);
      if (!values || p.params.some(k => integer(values[k]) === null)) return result(false, 'refused', 'AXP-A001');
      const limit = Math.min(opts.fuel, p.fuelMax);
      const kinds = new Uint8Array(p.registers), bits = new Array(p.registers).fill(0n);
      p.params.forEach((key, i) => { kinds[i] = I64; bits[i] = integer(values[key]); });
      let pc = 0, used = 0;
      const trap = code => result(false, 'trap', code, used, limit);
      for (;;) {
        if (pc >= p.code.length) return trap('AXI-R001');
        const w = p.code[pc], op = w & 255, a = (w >>> 8) & 255;
        const b = (w >>> 16) & 255, c = w >>> 24, bc = (b << 8) | c;
        const cost = op === OP.MUL ? 2 : (op === OP.DIV || op === OP.MOD) ? 4 : 1;
        if (cost > limit - used) return trap('AXI-R008');
        used += cost;
        // Read operands before changing aliased output registers.
        const x = bits[b], y = bits[c], kx = kinds[b], ky = kinds[c];
        switch (op) {
          case OP.NOP: break;
          case OP.LDK: kinds[a] = p.constants[bc].kind === 'i64' ? I64 : 1; bits[a] = integer(p.constants[bc].value); break;
          case OP.MOV: kinds[a] = kx; bits[a] = x; break;
          case OP.NOT:
            if (kx !== BOOL) return trap('AXI-R004');
            kinds[a] = BOOL; bits[a] = x ? 0n : 1n; break;
          case OP.ADD: case OP.SUB: case OP.MUL: case OP.DIV: case OP.MOD:
            if (kx !== ky || (kx !== I64 && kx !== 1)) return trap('AXI-R004');
            if ((op === OP.DIV || op === OP.MOD) && y === 0n) return trap('AXI-R003');
            kinds[a] = kx;
            bits[a] = (kx === I64 ? BigInt.asIntN : BigInt.asUintN)(64, op === OP.ADD ? x + y : op === OP.SUB ? x - y : op === OP.MUL ? x * y : op === OP.DIV ? x / y : x % y);
            break;
          case OP.EQ:
            kinds[a] = BOOL; bits[a] = kx === ky && x === y ? 1n : 0n; break;
          case OP.LT: case OP.LE:
            if (kx !== ky || (kx !== I64 && kx !== 1)) return trap('AXI-R004');
            kinds[a] = BOOL; bits[a] = (op === OP.LT ? x < y : x <= y) ? 1n : 0n; break;
          case OP.JMP: pc += bc; continue;
          case OP.JF:
            if (kinds[a] !== BOOL) return trap('AXI-R004');
            if (!bits[a]) { pc += bc; continue; } break;
          case OP.RET:
            if (kinds[a] !== (p.returnType === 'i64' ? I64 : BOOL)) return trap('AXI-R025');
            return result(true, 'value', 'AXP-VALUE', used, limit, p.returnType === 'i64' ? bits[a].toString() : !!bits[a]);
          case OP.HALT: return trap('AXI-R001');
          default: return result(false, 'refused', 'AXP-P001', used, limit);
        }
        pc++;
      }
    } catch (_) { return result(false, 'refused', 'AXP-I001'); }
  }
  function validate(program) { try { return snapshot(program) !== null; } catch (_) { return false; } }
  return Object.freeze({profile: PROFILE, maxFuel: MAX_FUEL, evaluate, validate});
});
