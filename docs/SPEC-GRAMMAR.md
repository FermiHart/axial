# axial SPEC-GRAMMAR v0 — Bear Core

SPDX-License-Identifier: LicenseRef-SPL-1.0
Status: v0. Normative for the parser and the canonical form.
Companion: src/axi_lex.c (lexer of record).

> Publication note: markers like (W02)/(W04)/(AXI-T007) are traces of the
> internal build history; in this tree, authority is the gate
> (`tools/check.sh`) and the goldens in `tests/`.

## 0. Doctrine

axial is agents-first, humans-review. The grammar is not a convenience
interface; it is a repair contract: every error has ONE cause, ONE span
and ONE canonical fix. What elsewhere is style, here is law.

## 1. G-laws (grammar laws — violation = diagnostic, never warning)

- **G1 — One spelling.** Every concept has exactly one written form. No
  synonyms, no optional sugar, no two forms of the same if. (Diag: AXI-L001 family.)
- **G2 — Canonical form IS the form.** The formatter has no opinions: the
  canonical output is derivable from the grammar. Non-canonical code is an
  error with a mechanical fix, not style.
- **G3 — Every node is span-addressable.** Any diagnostic points at
  `file:line:column` 1-based, byte-exact. No error "near" anything.
- **G4 — Zero ambient authority in the grammar.** Capabilities (`cap`)
  exist only in signatures. There is no syntax for importing the world.
- **G5 — Fuel is syntax.** `fuel INT` is mandatory `cell` metadata;
  the grammar does not allow a cell without a budget.
- **G6 — Lookahead 1.** The grammar is LL(1). An agent repairs with local
  context; it never needs to read the whole file to understand an error.
- **G7 — No hidden flow.** Nothing executes outside a `cell` body. No
  top-level statements, no implicit init.
- **G8 — Caged diagnostics.** The lexer/parser never aborts on the first
  error: it emits the diag, applies the documented recovery and continues.
  rc=1 if it emitted any diag.

## 2. Alphabet and lexer (mirror of src/axi_lex.c — the lexer is of record)

- Source: UTF-8; outside strings/comments, only ASCII from the alphabet
  below. Stray byte → AXI-L001 (fix: remove it; one spelling for everything).
- Comment: `#` to end of line. No block comment (G1).
- Integer: `[0-9][0-9_]*` — `_` is a visual separator, normalized in the
  lexeme (`1_000_000` → `1000000`). Letter glued to a number → AXI-L004.
- Float: `INT "." INT` (v0; no exponent until a proven need exists).
- String: `"..."` on a single line. Valid escapes: `\n \t \\ \" \0`.
  Unknown escape → AXI-L003. Unterminated on the line → AXI-L002.
- Identifier: `[A-Za-z][A-Za-z0-9_]*`.
- Operators/punctuation: `( ) { } [ ] , . : | ? = -> < > <= >= == != ! + - * / %`

### Keywords (v0)

`cell fn fuel pure cap let if ret ok err true false` +
scalar types: `u64 i64 f64 bool str bytes`

Reserved (do not use as IDs; dedicated error once the parser is born):
`match loop break proof seal use`

## 3. Grammar (EBNF v0 — normative)

```
unit      = { cell } EOF ;
cell      = "cell" ID ":" sig { meta } block ;
sig       = "fn" "(" [ param { "," param } ] ")" "->" rettype ;
param     = ID ":" type ;
type      = scalar | "cap" path | path ;
scalar    = "u64" | "f64" | "bool" ;
path      = ID { "." ID } ;
rettype   = rtatom { "|" rtatom } ;
rtatom    = "ok" | "err" "." ID | type ;
meta      = "fuel" INT | "pure" ;
block     = "{" { stmt } "}" ;
stmt      = "let" ID "=" expr
          | "ret" [ expr ]
          | "if" expr block [ "else" block ]   (* else: reserved *)
          | expr ;
expr      = cmp ;
cmp       = add { ("<"|">"|"<="|">="|"=="|"!=") add } ;
add       = mul { ("+"|"-") mul } ;
mul       = unary { ("*"|"/"|"%") unary } ;
unary     = [ "!" | "-" ] postfix ;
postfix   = atom { "." ID | call | index | "?" } ;
call      = "(" [ expr { "," expr } ] ")" ;
index     = "[" expr "]" ;
atom      = INT | FLOAT | STR | "true" | "false" | "ok" | ID
          | "(" expr ")" | "[" [ expr { "," expr } ] "]" ;
```

Notes:
- `?` is postfix: it propagates `err.*` to the cell's return (runtime).
- `pure` forbids `cap` in the signature — a semantic check, not a
  grammatical one.
- v0 has no `while`/`loop`: recursion + fuel is the model until the VM
  is proven.

## 4. Canonical form

1. Signature on the `cell` line; each `meta` on its own line, indent 2;
   body `{` in column 1; body indent 2; `}` in column 1.
2. One space around binary operators; none before `, : ? ( [`;
   one after `,` and `:`.
3. Integers with ≥ 5 digits written with `_` every 3 (the fix is mechanical).
4. One stmt per line. No double blank line. File ends in `\n`.
5. Metas in grammar order: `fuel` before `pure`, always.
6. A single-stmt `if`, with no `else` and no nested `if`, is inline:
   `if n < 2 { ret n }`. Any other shape opens a block.
7. Parentheses only where precedence requires; redundant grouping
   is not canonical (`ret (x)` → `ret x`).
8. Floats: shortest decimal that round-trips; always with `.` or
   exponent (`2` as float spells `2.0`).
9. Comments live on their own line, at the indent of the point they
   precede; a trailing comment is hoisted to its own following line.
   Zero comments are lost (trivia sink in the lexer; the drop counter
   is honesty, not an excuse).
10. Shape alphabet: LF-only (CR = AXI-C004), spaces only
    (tab = AXI-C005), exactly one blank line between cells.
11. Fixpoint law (gate): `canon(canon(x)) == canon(x)` and
    `check(canon(x))` is green silence, for every parse-green fixture.

Non-canonical → `AXI-C0xx` diag with the exact replacement text (the fix
is the canonical text itself; an agent applies it without thinking).
Layers: grammar silences shape — a parse-red file receives only AXI-L/P;
shape speaks only when the parse is green.

## 5. Diagnostic space

| Range    | Owner            | Existing |
|----------|------------------|----------|
| AXI-L0xx | lexer            | L001 alphabet, L002 open string, L003 escape, L004 letter after number, L005 |
| AXI-C0xx | canonical shape  | C001 non-canonical line (fix = exact line), C002 extra/missing line, C003 final newline, C004 CR, C005 tab |
| AXI-P0xx | parser           | P001–P011 (source: `src/axi_parse.c`; goldens: `tests/parse/`) |
| AXI-T0xx | types/caps       | T001–T021 (source: `src/axi_types.c`; goldens: `tests/types/`) |
| AXI-D999 | internal panic   | always our bug; open an invariant |

Emission format (one line, greppable, stable — a tool contract):

```
AXI-XNNN path:line:col message | fix: canonical correction
```

## 6. What v0 refuses (decisions, not gaps)

- No macros, no eval, no source reflection: code that writes code
  breaks the attested chain.
- No exceptions: only `err.*` in the return type + `?`.
- No nil: absence is a named error or an option type.
- No implicit numeric coercion: `u64`, `i64` and `f64` never mix,
  period. v0 **has no cast** — the fix is to rewrite the literal in the
  right type. An explicit cast (`as`) only arrives once a real program
  proves the need, with a fixture.
- No truthiness: `if`/`!` require `bool` (AXI-T007/T009).
- No collections in v0: list literals are AXI-T020; composite data lives
  behind a cap.
- Cells are not values in v0: a cell name outside a call is AXI-T003/T021
  (function-as-value requires a content hash).

## 7. Type laws (T-laws — mirror of `src/axi_types.c`)

- **T-NAMES** T001 duplicate cell · T002 shadowing forbidden · T003
  unknown name/cell-as-value.
- **T-UNION** T005 union with >1 payload · T006 duplicate member · T018
  `err.X` outside the declared error set.
- **T-FLOW** T013 unhandled union (requires `?`) · T014 `?` on non-union ·
  T015 `?` re-raises an undeclared error · T016 `ret` with wrong type ·
  T017 control falls off the end of the body.
- **T-COERCE** T007 non-bool condition · T008 mixed operands · T009
  operator × type (`%` integers, unary `-` never on u64, `!` bool only).
- **T-CALL** T010 unknown cell · T011 arity · T012 argument type
  · T021 local is not callable.
- **T-EFFECT** T019 pure ⇒ zero caps (parameter, touch or impure callee —
  transitive) · T020 collections.
- **T-AUTHORITY** (the checker is TOTAL, opacity is dead):
  · T022 cap identity by declared path — `cap net.Send` never
    enters where the signature asks for `cap io.Write`; authority has a
    NAME, it does not convert (G4). Cap in scalar position is also T022.
  · T025 effects are one-way in v0: `path.method(args)` accepts only
    scalars and returns ok; cap does not flow through cap, unions do not
    flow through cap, methods are not values, caps do not index. Data that
    comes BACK from a cap arrives with the interface projection — until
    then, effects emit, they do not answer.
  · T026 dead authority: a declared-but-never-used cap is attack surface
    pretending to be a parameter — ambient blindness cuts BOTH ways
    (nothing enters hidden, nothing sits idle in hand).

## 8. AXB — bytecode (mirror of `src/axi_bc.h`)

- Fixed 4-byte word `op a b c`; register VM, ≤256 per cell;
  typed const pool (u64/i64/f64-bits/str/err); little-endian, sections with
  size prefix, zero padding. **Nothing in the file beyond what the header
  describes — an undescribed byte does not exist.**
- Determinism is gate law: `asm(dis(asm(x)))` byte-equal to `asm(x)`, and
  `dis` emits exactly the canonical spelling (.axs fixture is fixpoint).
- One X-macro table (`AXB_OPCODES`) feeds asm, dis and VM — fuel column
  reserved since birth; costs are filled in without moving the format.
  f64 spells as hex bits: decimal printing is not deterministic.
- `AXI-B0xx` diagnostics, same msg+fix protocol as the repair loop.

## 9. VM (`src/axi_vm.c`)

- Registers are born UNIT (zeroed); the call window copies `argc` values
  and NOTHING else — caller garbage never leaks into the callee.
- Every wrong move is an `AXI-R0xx` trap with a fix, never UB: no coercion
  at runtime (mirror of G2), no truthiness (G5), unsigned cmp stays
  unsigned. u64/i64 wrap defined; div/0 is a trap.
- `call rBASE @cell argc`: args in rBASE.., result returns in rBASE.
  Depth ≤ 256 — a deterministic wall.
- `eff` REFUSES until the host shim — fail-closed.
- Pre-fuel ceiling of 2^24 steps (AXI-R008): a runaway loop is a trap,
  not a hung gate. Fuel replaces it; the trap stays.

## 10. Fuel (deterministic)

- Every opcode costs what the AXB_OPCODES table says (div/mod 4, call 4,
  eff 8, rest 1–2).
- A budget ALWAYS exists (default 1_000_000; `--fuel N`, N>0). No
  unlimited mode — fail-closed even on CPU.
- Exhaustion = verdict AXI-R008, not a crash nor a hung gate.
- `--fuel-report` prints `fuel N`; the golden seals the exact number
  (fib(10) = 77 fuel) — if a cost changes without intent, the gate accuses.
- Honest cost recalibration: benchmark-driven, never by eye.

## 11. Seal (prove-or-nothing)

- `axi seal cell.axs -o cell.axb`: runs EVERY `law_*` cell on the VM
  (default fuel) and emits bytecode only if each judges `bool true`.
- No `law_*` = refusal AXI-S001. False law or trap = refusal AXI-S002.
- Truly fail-closed: refusal leaves NO `.axb` on disk — the gate
  checks for the artifact's absence, not just the rc.
- Goldens generated by the tool itself, never by hand.

Gate: `make gate` (lex, parse, canon, types, fixpoint, bc, run, seal —
all GREEN, MAX_FAILS=0). Every change to this spec requires a new fixture
in the suite in the same commit.
