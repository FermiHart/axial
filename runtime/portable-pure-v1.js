/* Axial portable pure v1. Executes bounded compiler bytecode; no eval or
 * JavaScript translation of application policies. Not embed-v1 or an AXBS
 * signature verifier. The application owns artifact trust and all effects.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.AxialPortablePureV1 = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const PROFILE = 'axial.portable-pure.v1';
  const MAX_FUEL = 4096;
  const PROGRAM_KEYS = ['format', 'compilerSourceRevision', 'compilerSourceDigest', 'sourceSha256',
    'ifaceHash', 'bodyHash', 'entry', 'fuelMax', 'params', 'registers', 'constants', 'code'];
  const NAME = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
  const HASH = /^[0-9a-f]{64}$/;
  const OP = Object.freeze({NOP: 0, LDK: 1, MOV: 2, NOT: 8, EQ: 9,
    JMP: 12, JF: 13, RET: 15, HALT: 22});

  function boundedInteger(value, max, min) {
    return Number.isInteger(value) && !Object.is(value, -0) && value >= (min || 0) && value <= max;
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
  function snapshot(program) {
    const p = record(program, PROGRAM_KEYS);
    if (!p || p.format !== PROFILE || typeof p.compilerSourceRevision !== 'string'
      || !/^[0-9a-f]{40}$/.test(p.compilerSourceRevision)
      || ![p.compilerSourceDigest, p.sourceSha256, p.ifaceHash, p.bodyHash].every(v => typeof v === 'string' && HASH.test(v))
      || typeof p.entry !== 'string' || !NAME.test(p.entry)
      || !boundedInteger(p.fuelMax, MAX_FUEL, 1) || !boundedInteger(p.registers, 32, 1)) return null;
    p.params = array(p.params, 16); p.constants = array(p.constants, 32); p.code = array(p.code, 128);
    if (!p.params || !p.constants || !p.code || !p.code.length || p.params.length > p.registers
      || p.params.some(v => typeof v !== 'string' || !NAME.test(v))
      || new Set(p.params).size !== p.params.length
      || p.constants.some(v => !boundedInteger(v, 1))
      || p.code.some(v => !boundedInteger(v, 0xffffffff))) return null;
    for (let pc = 0; pc < p.code.length; pc++) {
      const w = p.code[pc], op = w & 255, a = (w >>> 8) & 255;
      const b = (w >>> 16) & 255, c = w >>> 24, bc = (b << 8) | c;
      const jump = bc >= 32768 ? bc - 65536 : bc;
      switch (op) {
        case OP.NOP: case OP.HALT: if (a || b || c) return null; break;
        case OP.LDK: if (a >= p.registers || bc >= p.constants.length) return null; break;
        case OP.MOV: case OP.NOT: if (a >= p.registers || b >= p.registers || c) return null; break;
        case OP.EQ: if (a >= p.registers || b >= p.registers || c >= p.registers) return null; break;
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
  function result(p, ok, allowed, outcome, code, used, limit) {
    return Object.freeze({ok, allowed, outcome, code, fuelUsed: used || 0,
      fuelLimit: limit || 0, profile: PROFILE,
      sourceSha256: p ? p.sourceSha256 : null, ifaceHash: p ? p.ifaceHash : null,
      bodyHash: p ? p.bodyHash : null, entry: p ? p.entry : null});
  }
  function evaluate(program, facts, options) {
    let p = null;
    try {
      p = snapshot(program);
      if (!p) return result(null, false, false, 'refused', 'AXP-P001');
      const opts = record(options, ['fuel']);
      if (!opts || !boundedInteger(opts.fuel, MAX_FUEL)) return result(p, false, false, 'refused', 'AXP-F001');
      const values = record(facts, p.params);
      if (!values || p.params.some(k => typeof values[k] !== 'boolean')) return result(p, false, false, 'refused', 'AXP-A001');
      const limit = Math.min(opts.fuel, p.fuelMax);
      const kinds = new Uint8Array(p.registers), bits = new Uint8Array(p.registers);
      p.params.forEach((key, i) => { kinds[i] = 4; bits[i] = values[key] ? 1 : 0; });
      let pc = 0, used = 0;
      for (;;) {
        if (pc >= p.code.length) return result(p, false, false, 'trap', 'AXI-R001', used, limit);
        if (used >= limit) return result(p, false, false, 'trap', 'AXI-R008', used, limit);
        used++; // Every admitted opcode costs exactly one, before execution.
        const w = p.code[pc], op = w & 255, a = (w >>> 8) & 255;
        const b = (w >>> 16) & 255, c = w >>> 24, bc = (b << 8) | c;
        switch (op) {
          case OP.NOP: break;
          case OP.LDK: kinds[a] = 1; bits[a] = p.constants[bc]; break;
          case OP.MOV: kinds[a] = kinds[b]; bits[a] = bits[b]; break;
          case OP.NOT:
            if (kinds[b] !== 4) return result(p, false, false, 'trap', 'AXI-R004', used, limit);
            kinds[a] = 4; bits[a] = bits[b] ? 0 : 1; break;
          case OP.EQ: {
            const same = kinds[b] === kinds[c] && bits[b] === bits[c];
            kinds[a] = 4; bits[a] = same ? 1 : 0; break;
          }
          case OP.JMP: pc += bc; continue;
          case OP.JF:
            if (kinds[a] !== 4) return result(p, false, false, 'trap', 'AXI-R004', used, limit);
            if (!bits[a]) { pc += bc; continue; }
            break;
          case OP.RET:
            if (kinds[a] !== 4) return result(p, false, false, 'trap', 'AXI-R025', used, limit);
            return result(p, true, !!bits[a], bits[a] ? 'allow' : 'deny', bits[a] ? 'AXP-ALLOW' : 'AXP-DENY', used, limit);
          case OP.HALT: return result(p, false, false, 'trap', 'AXI-R001', used, limit);
          default: return result(p, false, false, 'refused', 'AXP-P001', used, limit);
        }
        pc++;
      }
    } catch (_) {
      return result(null, false, false, 'refused', 'AXP-I001');
    }
  }
  function validate(program) {
    try { return snapshot(program) !== null; } catch (_) { return false; }
  }
  return Object.freeze({profile: PROFILE, maxFuel: MAX_FUEL, evaluate, validate});
});
