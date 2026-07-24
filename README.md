# solana-tx-guard

**Pre-sign transaction safety guardrails for AI agents on Solana.**

Simulate before signing, detect drains, and enforce policy — *before* an agent puts a signature on a transaction. Returns a `SAFE` / `WARN` / `BLOCK` verdict with explained findings.

> A skill + library for the [Solana AI Kit](https://github.com/solanabr/solana-ai-kit). MIT licensed, one runtime dependency, no paid APIs, no telemetry.

---

## The problem

In 2026, AI agents don't just read Solana — they **sign and send transactions** (SendAI / `solana-agent-kit`, trading bots, autonomous workflows). But the agent's signer has none of the safety net a human wallet has:

- A human sees Phantom's "this will move 2 SOL to an unknown address" preview. **An agent sees nothing** — it just signs.
- The transaction was often built from a **natural-language instruction that could be prompt-injected**. The model can be tricked into building a wallet-drainer.
- The kit's existing security skills (`trailofbits`, `safe-solana-builder`, `ghostsecurity`) review **source code**. None of them guard the **transaction an agent is about to sign at runtime**.

Wallet-side scanners (Blowfish, Blockaid) solve this for human end-users, but they're closed, paid APIs built into wallets — not something an autonomous signer can drop in.

**solana-tx-guard fills that gap:** an open, self-contained guardrail you place directly in front of an agent's signer.

## What it does

Three layers, combined into one verdict:

1. **Static analysis (offline)** — decodes every instruction, identifies the program, and flags asset-affecting actions: SOL/SPL transfers, account funding (`CreateAccount`), nonce withdrawals & authority handovers, `Approve` (delegation), `SetAuthority`, `CloseAccount`, `Burn`/`BurnChecked`, System `Assign`, priority-fee spikes (`SetComputeUnitPrice` drains), and calls into unverified programs.
2. **Simulation (online)** — runs `simulateTransaction` against your RPC and diffs the owner's pre/post native + token balances (pass `ownedTokenAccounts: "auto"` to discover and watch every token account), catching effects hidden inside CPIs.
3. **Policy (offline)** — enforces SOL / per-mint token / priority-fee caps, recipient allowlists, program allowlists, and block-on-delegation/close. Fail-closed by default.

```
any critical finding → BLOCK   (never sign)
any warning          → WARN    (don't sign autonomously; escalate)
otherwise            → SAFE    (may proceed)
```

By default every transfer is at least WARN. For agents that must act alone, set `allowCompliantTransfers: true`: transfers that satisfy **all** the configured caps + allowlists come back SAFE, while anything outside them is still flagged (WARN or BLOCK), never silently allowed. A CPI-hidden outflow simulation can't attribute to an allowlisted recipient stays WARN rather than SAFE.

## Install

### As a kit skill (Claude Code / Codex agents)

```bash
curl -fsSL https://raw.githubusercontent.com/Anon1one/solana-tx-guard/main/install.sh | bash
```

Installs the `skill/` into your project's `.claude/skills/solana-tx-guard/` (or `~/.claude/skills/` with `--global`) and registers it. Run from a project root, or pass `--dir <path>`.

### As a library

```bash
npm install solana-tx-guard
```

## Usage

```ts
import { guard } from "solana-tx-guard";

const result = await guard(tx, {
  connection,                                   // optional → enables simulation
  policy: {
    ownerPubkey: wallet.publicKey.toBase58(),
    maxLamportsOut: 0.25 * 1e9,                 // never move > 0.25 SOL
    maxFeeLamports: 0.01 * 1e9,                 // cap the worst-case priority fee
    recipientAllowlist: [treasury.toBase58()],  // only these may receive funds
    allowCompliantTransfers: true,              // within all limits → SAFE
  },
  ownedTokenAccounts: "auto",                   // optional → discover + diff token balances
});

if (result.verdict === "BLOCK") throw new Error(result.findings[0]?.message);
if (result.verdict === "WARN")  return escalateToHuman(result);
await wallet.signAndSend(tx);                   // SAFE
```

### Wrap a signer (guard everything)

```ts
import { guard } from "solana-tx-guard";

function guardedSigner(inner, opts) {
  return {
    async signTransaction(tx) {
      const r = await guard(tx, opts);
      if (r.verdict !== "SAFE") throw new Error(`tx-guard ${r.verdict}: ${r.findings[0]?.message}`);
      return inner.signTransaction(tx);
    },
  };
}
```

### CLI

```bash
txguard check --tx <base64> --owner <pubkey> --max-sol 0.5 --allow <addr,addr>
# exit codes: 0 SAFE · 1 WARN · 2 BLOCK · 3 usage/error
echo "$BASE64_TX" | txguard check --owner "$OWNER" --rpc "$RPC_URL" --watch auto --json
```

Also: `--max-fee <sol>` (priority-fee cap), `--allow-program <id,id>`, `--allow-compliant` (compliant transfers exit 0), `--allow-delegation`, `--allow-close`. Unknown flags or malformed values exit 3 — a typo never silently weakens the policy.

## How it's structured

```
solana-tx-guard/
├── skill/                  # the kit skill — progressive, token-efficient
│   ├── SKILL.md            #   routing hub (read first)
│   ├── drain-detection.md  #   what's detected + severity model
│   ├── simulate.md         #   RPC simulation + balance diffing
│   ├── policy.md           #   caps, allowlists, presets
│   ├── integration.md      #   API, agent-kit hook, wallet wrapper, CLI
│   └── resources.md        #   program ids, instruction layouts, refs
├── src/                    # the working implementation (TypeScript)
│   ├── index.ts            #   guard() — the public API
│   ├── analyzer.ts         #   static instruction analysis
│   ├── programs.ts         #   program registry + instruction decoders
│   ├── simulate.ts         #   simulation + balance diff
│   ├── policy.ts           #   policy enforcement
│   ├── verdict.ts          #   finding → verdict
│   └── cli.ts              #   txguard CLI
├── test/                   # node:test suite (79 tests, incl. CLI contract + regression tests)
├── commands/tx-guard.md    # /tx-guard agent command
├── install.sh
└── LICENSE                 # MIT
```

## Develop

```bash
npm install
npm run typecheck     # tsc --noEmit
npm test              # node:test — 79 tests
npm run guard -- check --tx <base64> --owner <pubkey>
npx tsx examples/demo.ts   # runnable walkthrough of verdicts
```

## Scope & honesty

This reduces risk; it does not eliminate it. Static analysis is fail-closed and explainable; simulation is the ground truth for net effect — **use both**, with a tight policy, and keep a human in the loop above your cap. It is not a wallet, not a code auditor, and not a guarantee about chain state at land time. It is the guardrail that belongs in front of an autonomous signer, which nothing in the kit currently provides.

## License

MIT © 2026 Anon1one
