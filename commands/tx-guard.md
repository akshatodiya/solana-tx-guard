---
name: tx-guard
description: Inspect a Solana transaction before signing and return a SAFE / WARN / BLOCK verdict with explained findings. Use whenever you are about to sign or send a transaction, or when a user hands you a serialized transaction to vet.
---

# /tx-guard — pre-sign transaction check

Run the **solana-tx-guard** check on a transaction and act on the verdict. Use this BEFORE any signing/sending step, and whenever asked to vet a transaction.

## When to use

- You (the agent) built a transaction and are about to sign/send it.
- A user pastes a base64 transaction and asks "is this safe?" / "what does this do?".
- A signing flow needs a gate (CI, script, autonomous loop).

## How to run

**If the repo/library is available**, use the CLI (exit code = verdict, gate on it):

```bash
txguard check --tx <base64> --owner <ownerPubkey> [--rpc <url>] [--max-sol <n>] [--max-fee <n>] \
              [--allow <addr,addr>] [--allow-program <id,id>] [--watch <acct,acct|auto>] \
              [--allow-compliant] [--json]
# exit: 0 SAFE · 1 WARN · 2 BLOCK · 3 error
```

Prefer passing `--rpc` so the transaction is also **simulated** (real balance diff), `--owner` so findings are scoped to the wallet, and `--watch auto` so all the owner's token accounts are diffed. Unknown flags and malformed values exit 3 (fail-closed).

**From code**, call the library:

```ts
import { guard } from "solana-tx-guard";
const r = await guard(tx, {
  policy: { ownerPubkey, maxLamportsOut, recipientAllowlist, allowCompliantTransfers: true },
  connection,
  ownedTokenAccounts: "auto",
});
```

## How to act on the result

- **BLOCK** → do **not** sign. Report the findings (each has a `code` + message) and stop. Example: hidden `Approve`/delegation, transfer over the cap, unknown program, account close, inflated priority fee.
- **WARN** → do not sign autonomously. Summarize the findings and ask the human to approve, or apply a stricter policy.
- **SAFE** → proceed to sign/send.

## What it checks (summary)

Static decode of every instruction (SOL/SPL transfers, account funding, nonce withdrawals/authority handovers, delegations, authority changes, account closes, burns, priority-fee spikes, unknown programs) + optional RPC simulation with owner balance diffing + policy (SOL/token/fee caps, recipient/program allowlists, fail-closed defaults). Full detail in the skill files: `drain-detection.md`, `simulate.md`, `policy.md`, `integration.md`.

## Notes

- Always set `--owner` / `policy.ownerPubkey` — it scopes severity to the wallet that matters.
- Unknown programs and delegations are **blocked by default** (fail-closed). Loosen only with explicit policy flags.
- The check never signs, sends, or mutates the transaction.
