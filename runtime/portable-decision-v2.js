/* Axial portable decision v2. Executes bounded native compiler bytecode.
 * UNIT permits; an exact declared ERR atom supplies the denial reason.
 * No application policy translation, eval, effects, or signature admission.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.AxialPortableDecisionV2 = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const PROFILE = 'axial.portable-decision.v2';
  const MAX_FUEL = 4096;
  const PROGRAM_KEYS = ['format', 'compilerSourceRevision', 'compilerSourceDigest', 'sourceSha256',
    'ifaceHash', 'bodyHash', 'entry', 'fuelMax', 'params', 'returnType', 'registers', 'constants', 'code'];
  const NAME = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
  const HASH = /^[0-9a-f]{64}$/;
  const REVISION = /^[0-9a-f]{40}$/;
  const OP = Object.freeze({NOP: 0, LDK: 1, MOV: 2, NOT: 8, EQ: 9,
    JMP: 12, JF: 13, RET: 15, HALT: 22});
  // Private tags, not a cast between the public C and private VM value ABIs.
  const UNIT = 0, U64 = 1, BOOL = 4, ERR = 7;

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
  function constant(value, errors) {
    // Inspect descriptors, never getters; the second snapshot owns execution.
    const tag = value && typeof value === 'object'
      ? Object.getOwnPropertyDescriptor(value, 'kind') : null;
    if (!tag || !Object.prototype.hasOwnProperty.call(tag, 'value') || !tag.enumerable) return null;
    const k = record(value, tag.value === 'u64' ? ['kind', 'value'] : ['kind', 'atom']);
    if (!k) return null;
    if (k.kind === 'u64' && boundedInteger(k.value, 1)) return Object.freeze(k);
    if (k.kind === 'error' && typeof k.atom === 'string' && errors.includes(k.atom)) return Object.freeze(k);
    return null;
  }
  function snapshot(program) {
    const p = record(program, PROGRAM_KEYS);
    if (!p || p.format !== PROFILE || !exactMatch(REVISION, p.compilerSourceRevision)
      || ![p.compilerSourceDigest, p.sourceSha256, p.ifaceHash, p.bodyHash].every(v => exactMatch(HASH, v))
      || !exactMatch(NAME, p.entry)
      || !boundedInteger(p.fuelMax, MAX_FUEL, 1) || !boundedInteger(p.registers, 32, 1)) return null;
    const returns = record(p.returnType, ['kind', 'ok', 'errors']);
    if (!returns || returns.kind !== 'result' || returns.ok !== 'unit') return null;
    returns.errors = array(returns.errors, 16);
    if (!returns.errors || !returns.errors.length
      || returns.errors.some((v, i, all) => !exactMatch(NAME, v) || (i && all[i - 1] >= v))) return null;
    Object.freeze(returns.errors); p.returnType = Object.freeze(returns);
    p.params = array(p.params, 16); p.constants = array(p.constants, 32); p.code = array(p.code, 128);
    if (!p.params || !p.constants || !p.code || !p.code.length || p.params.length > p.registers
      || p.params.some(v => !exactMatch(NAME, v))
      || new Set(p.params).size !== p.params.length
      || p.code.some(v => !boundedInteger(v, 0xffffffff))) return null;
    p.constants = p.constants.map(k => constant(k, returns.errors));
    if (p.constants.some(k => !k)) return null;
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
  function result(p, ok, allowed, outcome, code, used, limit, decision) {
    return Object.freeze({ok, allowed, outcome, code, fuelUsed: used || 0,
      fuelLimit: limit || 0, profile: PROFILE,
      sourceSha256: p ? p.sourceSha256 : null, ifaceHash: p ? p.ifaceHash : null,
      bodyHash: p ? p.bodyHash : null, entry: p ? p.entry : null,
      decision: decision ? Object.freeze(decision) : null});
  }
  // Only called with an owned, recursively frozen validated snapshot.
  function execute(p, facts, options) {
    try {
      const opts = record(options, ['fuel']);
      if (!opts || !boundedInteger(opts.fuel, MAX_FUEL)) return result(p, false, false, 'refused', 'AXP-F001');
      const values = record(facts, p.params);
      if (!values || p.params.some(k => typeof values[k] !== 'boolean')) return result(p, false, false, 'refused', 'AXP-A001');
      const limit = Math.min(opts.fuel, p.fuelMax);
      const kinds = new Uint8Array(p.registers), bits = new Uint8Array(p.registers);
      const atoms = new Array(p.registers).fill(null);
      p.params.forEach((key, i) => { kinds[i] = BOOL; bits[i] = values[key] ? 1 : 0; });
      let pc = 0, used = 0;
      for (;;) {
        if (pc >= p.code.length) return result(p, false, false, 'trap', 'AXI-R001', used, limit);
        if (used >= limit) return result(p, false, false, 'trap', 'AXI-R008', used, limit);
        used++; // Native cost one, charged before every admitted instruction.
        const w = p.code[pc], op = w & 255, a = (w >>> 8) & 255;
        const b = (w >>> 16) & 255, c = w >>> 24, bc = (b << 8) | c;
        switch (op) {
          case OP.NOP: break;
          case OP.LDK: {
            const k = p.constants[bc];
            kinds[a] = k.kind === 'u64' ? U64 : ERR;
            bits[a] = k.kind === 'u64' ? k.value : 0;
            atoms[a] = k.kind === 'error' ? k.atom : null;
            break;
          }
          case OP.MOV: kinds[a] = kinds[b]; bits[a] = bits[b]; atoms[a] = atoms[b]; break;
          case OP.NOT:
            if (kinds[b] !== BOOL) return result(p, false, false, 'trap', 'AXI-R004', used, limit);
            kinds[a] = BOOL; bits[a] = bits[b] ? 0 : 1; atoms[a] = null; break;
          case OP.EQ: {
            const same = kinds[b] === kinds[c]
              && (kinds[b] === ERR ? atoms[b] === atoms[c] : bits[b] === bits[c]);
            kinds[a] = BOOL; bits[a] = same ? 1 : 0; atoms[a] = null; break;
          }
          case OP.JMP: pc += bc; continue;
          case OP.JF:
            if (kinds[a] !== BOOL) return result(p, false, false, 'trap', 'AXI-R004', used, limit);
            if (!bits[a]) { pc += bc; continue; }
            break;
          case OP.RET:
            // Registers start at UNIT in the native VM; the compiler uses a
            // dedicated untouched UNIT register for `ret ok`.
            if (kinds[a] === UNIT && bits[a] === 0 && atoms[a] === null)
              return result(p, true, true, 'allow', 'AXP-ALLOW', used, limit, {kind: 'allow'});
            if (kinds[a] === ERR && bits[a] === 0 && p.returnType.errors.includes(atoms[a]))
              return result(p, true, false, 'deny', 'AXP-DENY', used, limit, {kind: 'deny', reason: atoms[a]});
            return result(p, false, false, 'trap', 'AXI-R025', used, limit);
          case OP.HALT: return result(p, false, false, 'trap', 'AXI-R001', used, limit);
          default: return result(p, false, false, 'refused', 'AXP-P001', used, limit);
        }
        pc++;
      }
    } catch (_) {
      return result(null, false, false, 'refused', 'AXP-I001');
    }
  }
  function evaluate(program, facts, options) {
    try {
      const p = snapshot(program);
      if (!p) return result(null, false, false, 'refused', 'AXP-P001');
      return execute(p, facts, options);
    } catch (_) { return result(null, false, false, 'refused', 'AXP-I001'); }
  }
  // Preparation confers no authority: admission/revocation remain host checks.
  // No program reference or unchecked entry point escapes this closure.
  function prepare(program) {
    try {
      const p = snapshot(program);
      if (!p) return null;
      const run = Object.freeze(function (facts, options) { return execute(p, facts, options); });
      return Object.freeze({evaluate: run});
    } catch (_) { return null; }
  }
  function validate(program) {
    try { return snapshot(program) !== null; } catch (_) { return false; }
  }
  return Object.freeze({profile: PROFILE, maxFuel: MAX_FUEL, evaluate, validate, prepare});
});
