---
name: solana-tx-guard
description: Pre-sign transaction safety guardrails for AI agents on Solana. Use this when an agent builds, signs, or sends transactions and you want a safety layer in front of the signer — simulate before signing, detect drains (SOL/SPL outflows, account funding, nonce drains, delegations, authority handovers, account closes, priority-fee spikes), and enforce policy (SOL/token spending caps, fee cap, recipient/program allowlists). Returns a SAFE / WARN / BLOCK verdict with explained findings; policy-compliant transfers can verdict SAFE so autonomous agents can act alone. Complements code-level auditors (trailofbits, safe-solana-builder); this guards transactions at runtime, not source code.
user-invocable: true
---

# Solana Transaction Guard

> **Layer**: runtime, pre-signature. Code-audit skills review the *program*; tx-guard reviews the *transaction the agent is about to sign*. Use both.

## What This Skill Is For

Use this skill when an agent (or any automated signer) is about to put a signature on a Solana transaction and you want a guardrail in front of it. Concretely, when the user asks for:

### Agent signing safety
- "Stop my agent from signing a transaction that drains the wallet"
- A safety check between transaction-building and `wallet.signTransaction` / `sendTransaction`
- Guardrails for `solana-agent-kit` / SendAI agents, trading bots, or any autonomous signer
- Spending limits, recipient allowlists, or program allowlists enforced per-transaction

### Drain & malicious-instruction detection
- Detecting unexpected SOL or SPL token outflows before they happen — including outflows disguised as account creation (`CreateAccount`) or nonce withdrawals
- Catching hidden `Approve` (delegation), `SetAuthority` / nonce-authority handovers, or `CloseAccount` instructions
- Catching priority-fee drains (an inflated `SetComputeUnitPrice` that burns the fee payer's balance)
- Flagging calls into unverified / unknown programs
- Surfacing prompt-injection-induced transactions (the model was tricked into building a malicious tx)

### Pre-sign simulation
- Running `simulateTransaction` and diffing the owner's balances (native + per-mint)
- Turning a raw transaction into a human/agent-readable "what will this actually do?" report

> Not a wallet, not a code auditor, not a paid scanning API. It is a self-contained, MIT-licensed, RPC-only check an agent runs on a transaction object before signing.

## Core Concept

A transaction is **untrusted input** to a signer — especially when an LLM built it from a natural-language request that could be poisoned. tx-guard runs three layers and combines them into one verdict:

1. **Static analysis (offline, always runs)** — decode every instruction, identify the program, and flag asset-affecting actions (transfers, account funding, nonce drains, delegations, authority changes, closes, fee spikes, unknown programs). No RPC needed.
2. **Simulation (online, when a connection is supplied)** — `simulateTransaction` against an RPC, then diff the owner's pre/post native + token balances. Catches effects hidden inside CPIs that static analysis can't read.
3. **Policy (offline)** — apply the caller's rules: SOL/per-mint token/fee caps, recipient allowlist, program allowlist, block-on-delegation/close. Policy escalates violations to a hard BLOCK, and (opt-in) downgrades transfers that comply with every configured limit so the transaction can verdict SAFE.

**Verdict** = max severity of all findings: any `critical` → **BLOCK**, any `warn` → **WARN**, else **SAFE**.

The agent contract is simple and the whole point of the skill:

```
BLOCK → never sign. Surface findings, stop.
WARN  → do not sign autonomously; escalate to a human or a stricter policy.
SAFE  → may proceed.
```

## Default Stack Decisions (Opinionated)

- **Library**: `@solana/web3.js` v1 transaction/`VersionedTransaction` objects (what `solana-agent-kit` and most agents use today). `@solana/kit` transactions can be converted to wire bytes and checked via the CLI.
- **Zero paid dependencies**: one runtime dep (`@solana/web3.js`). No Blowfish/Blockaid-style external API, no telemetry, no keys. Works against any RPC.
- **Fail-closed by default**: unknown programs BLOCK unless allowlisted; delegation and account-close BLOCK unless disabled. Loosen explicitly via policy.
- **Owner-scoped**: set `policy.ownerPubkey` (the agent's wallet) so the guard knows whose funds matter and can attribute simulated balance changes.

## Operating Procedure

### 1. Insert the guard before the signer

Find where the agent signs/sends (`signTransaction`, `signAndSendTransaction`, `sendTransaction`). Call `guard(tx, { policy, connection })` immediately *before* it and branch on `result.verdict`. See [integration.md](integration.md).

### 2. Classify what the user needs

| Need | Skill File |
|------|-----------|
| Wire guard into a signing flow / solana-agent-kit | [integration.md](integration.md) |
| Understand what instructions are detected & why | [drain-detection.md](drain-detection.md) |
| Configure caps / allowlists / block rules | [policy.md](policy.md) |
| Simulation + balance-diff details, token accounts | [simulate.md](simulate.md) |
| CLI usage / gate a shell script on exit code | [integration.md](integration.md) |
| APIs, addresses, source references | [resources.md](resources.md) |

### 3. Choose a policy posture

- **Autonomous agent handling user funds** → strict: set `maxLamportsOut`, `maxTokenOutByMint`, `maxFeeLamports`, `recipientAllowlist`, keep `allowUnverifiedPrograms: false`, keep delegation/close blocks on. Add `allowCompliantTransfers: true` so transactions within all of those limits verdict SAFE and the agent can act without a human.
- **Dev / power user with review-in-the-loop** → relaxed: allow unverified programs as WARN, no cap, rely on WARN escalation.
- See [policy.md](policy.md) for the full option matrix and recommended presets.

### 4. Always wire simulation when an RPC is available

Static analysis cannot see inside an unverified program's CPI. Pass a `connection` and `policy.ownerPubkey` so the transaction is simulated and real balance deltas are diffed. Use `ownedTokenAccounts: "auto"` to discover and watch all of the owner's token accounts. See [simulate.md](simulate.md).

### 5. Act on the verdict, log the findings

Never sign on BLOCK. On WARN, escalate. Always log `result.findings` (each has a stable `code`, `severity`, and human message) so decisions are auditable.

### 6. Test against adversarial transactions

Treat the guard like security code: write transactions that *should* be blocked (over-cap transfer, hidden Approve, unknown program, account close) and assert BLOCK. The repo's `test/` suite is the reference pattern.

---

## Progressive Disclosure (Read When Needed)

#### Detection
- [drain-detection.md](drain-detection.md) — full catalog of detected instructions, the severity model, and owner-scoping
- [simulate.md](simulate.md) — RPC simulation, pre/post balance diffing, watching token accounts, ALT limitations

#### Policy
- [policy.md](policy.md) — every `Policy` option, recommended presets, fail-closed rationale

#### Integration
- [integration.md](integration.md) — library API (`guard`), `solana-agent-kit` hook, wallet wrapper, CLI + exit codes, `@solana/kit` interop

#### Reference
- [resources.md](resources.md) — program ids, instruction layouts, RPC docs, related kit skills

---

## Task Routing Guide

| User asks about... | Primary skill file(s) |
|--------------------|----------------------|
| Stop agent from signing a draining tx | drain-detection.md, integration.md |
| Wire into solana-agent-kit / SendAI | integration.md |
| Wrap a wallet adapter with a guard | integration.md |
| Add a spending cap (SOL / token / fee) | policy.md |
| Let compliant transfers verdict SAFE | policy.md |
| Recipient / program allowlist | policy.md |
| Block delegations / setAuthority / nonce authority | policy.md, drain-detection.md |
| Priority-fee spike / compute budget drain | drain-detection.md, policy.md |
| What does the guard actually detect | drain-detection.md |
| Simulate a tx and see balance changes | simulate.md |
| Watch token accounts (ATAs / "auto") | simulate.md |
| Address lookup tables (v0) | simulate.md, drain-detection.md |
| CLI / CI gating on exit code | integration.md |
| Using @solana/kit transactions | integration.md, resources.md |
| Program ids / instruction layouts | resources.md |
| How this differs from a code audit | SKILL.md (this file), resources.md |

---

## Relationship to Other Kit Skills

| Skill | Layer | tx-guard's relation |
|-------|-------|--------------------|
| trailofbits, safe-solana-builder, ghostsecurity | source code (static) | Complementary — they harden the *program you write*; tx-guard guards *transactions your agent signs*, including ones calling programs you didn't write. |
| solana-dev (security.md) | program + client checklist | tx-guard operationalizes the client-side "simulate and verify before signing" guidance into runtime code. |
| helius | RPC / priority fees | Use a Helius (or any) RPC `connection` to power tx-guard's simulation. |
| sendai / solana-agent-kit | agent actions | tx-guard is the guardrail you place in front of the agent's signer. |

---

## Commands

- `/tx-guard <base64-tx>` — inspect a serialized transaction and print SAFE/WARN/BLOCK with findings. See [commands/tx-guard.md](../commands/tx-guard.md).

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/akshatodiya/solana-tx-guard/main/install.sh | bash
```

Or as a library: `npm install solana-tx-guard`. See the repo README for both paths.
