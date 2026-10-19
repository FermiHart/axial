# Axial

### Code that answers for what it does.

> Agents write. Humans review and seal. The system enforces.

[![License: SPL-1.0](https://img.shields.io/badge/License-SPL--1.0-5EE1FF?style=flat-square)](LICENSE)
[![C99](https://img.shields.io/badge/C99-zero_deps-8A7CFF?style=flat-square)](Makefile)
[![Gate](https://img.shields.io/badge/gate-67%2F67-green?style=flat-square)](tools/check.sh)

---

There's a moment happening right now. Agents write more code every day than humans do. And every line of it runs somewhere — with keys, with network, with your filesystem one typo away.

We asked a different question.

**What if the code carried its own proof?**

Not a comment. Not a promise. A proof — checked before it runs, sealed into the artifact, verified every time it loads. What if reviewing agent-written code took one screen instead of one weekend? What if deploying it meant copying *one file* — and a flipped byte meant refusal, not silent drift?

That's Axial.

---

## Say hello to the cell.

Everything in Axial is a **cell**. One function. Its contract. Its budget. Its proof. Hashed together, sealed forever.

```axi
cell greet : fn(out: cap io.Write) -> u64
  fuel 10_000
{
  out.write("beyond> ")?
  ret 0
}
```

Read that again. Slowly.

In four lines you know *everything this code is allowed to do*. Not what the docs say. Not what the author intended. What it **can** do. The body cannot outgrow the header — two independent walls, the checker and the runtime, enforce the same promise.

**No hidden imports. No ambient filesystem. No network that snuck in. No bill you didn't approve.** If it's not in the signature, it cannot happen. That's not a guideline. That's the language.

## Three ideas. That's it.

**1. The signature is the blast radius.**
Types, error sets, fuel budget, every capability — declared up front, in the open. Review concentrates on the contract, because the body can't exceed it. One screen tells you the whole story.

**2. Every run has a budget.**
Every instruction has a deterministic price. A runaway computation doesn't hang your machine at 3 AM — it ends as a sealed verdict: *fuel exhausted*. Boring. Predictable. Beautiful.

**3. No green proof, no artifact.**
`axi seal` runs every proof cell on the real VM. All green? You get your artifact. One red law, one trap, zero proofs? **Nothing is emitted.** There is no partial seal, no "ship it anyway" mode. The gate doesn't negotiate.

## And one more thing…

The artifact is **one file**.

Bytecode. Capability manifest. Proof record. Signature. Together. Deploy means copying it. Copy it to a server, a shell, a sovereign OS — it runs, or it refuses *with a reason a machine can repair*:

```
AXI-R008 main:0: fuel exhausted: spent 100 of 100, next op needs 1
  | fix: raise that outer budget or make the cell cheaper
```

Every error has one cause, one location, one mechanical fix. Agents don't guess. They apply.

And every effect it ever performs lands in a **hash-chained ledger** — one ordered receipt line per action. "What did this run do?" finally has a cryptographic answer.

## See it. Then believe it.

Sixty seconds. No dependencies beyond a C compiler. No network. No account. No excuses.

```sh
make dev                          # builds ./build/axi — C99 only
./build/axi check examples/hello.axi
./build/axi iface examples/policy.axi   # read the whole contract

./build/axi asm tests/run/fib.axs -o /tmp/fib.axb --signing-key <seed>
./build/axi run /tmp/fib.axb fib 10 --trusted-key <key>
# u64 55

make gate-fast                     # 67 checks. Green is the definition of "works".
```

Want the full story — embed it in C, sign a policy, watch a shell ask permission?

```sh
make demo && sh scripts/jash_policy_demo.sh
# rm inside workspace   -> ALLOW (fuel=51)
# rm outside workspace  -> DENY  (fuel=51)
# export secret name    -> DENY
```

Four symbols. That's the entire C API: `abi_version`, `context_create`, `context_destroy`, `eval`. See `include/axial/axi_embed_v1.h`.

## Don't trust this page.

Seriously. Don't.

Trust is the old model — trust the package, trust the registry, trust the install script. Axial was built for people who stopped trusting. So verify instead:

```sh
git clone <repo> && cd axial
make dev && make gate
```

67 checks. Your machine. Your verdict. If a single one fails, open an issue — that's the deal. Green here is never decoration: it's always a machine talking.

## The honest fine print (short)

This tree is the **language beta**: grammar, types, bytecode, VM, fuel, effects, ledger, replay, sealing, and the C embed API — validated by golden suites on the host.

It is not yet end-to-end attestation to a boot root, not yet a universal policy plane, not yet a production trusted runner. Those are direction, not claims. We'd rather promise little and prove all of it.

## Inside the box

| Path | What |
|---|---|
| `src/` | The language: lexer, parser, canonical form, types, bytecode, VM, fuel, effects, ledger, replay, sealing, embed |
| `include/axial/` | Public C embed header (frozen v1 ABI) |
| `abi/` | Pinned ABI profile (`amd64-sysv-lp64`, 4 symbols) |
| `vendor/` | Vendored crypto (Ed25519, SHA-256) — zero external deps |
| `examples/` | Minimal current-syntax cells |
| `scripts/` | Policy demo + sealed supply-chain demo |
| `docs/` | `SPEC-GRAMMAR.md` (normative), `BETA-LANGUAGE.md` (scope), `OVERVIEW.md` |
| `tests/` | Golden fixtures across 10 suites |
| `tools/` | `check.sh` — the public gate (67 checks) |
| `website/` | This story as a page. Open `website/index.html`. Static, no build, no trackers. |

## License

Sovereign Public License 1.0 — see [`LICENSE`](LICENSE). Use it, ship it, build on it. Just keep the notice. `LicenseRef-SPL-1.0`.
