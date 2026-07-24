# Integration

Where to put the guard, and the exact API. The rule: **call `guard()` on the transaction immediately before the signer, and branch on the verdict.**

## Library API

```ts
import { guard } from "solana-tx-guard";

const result = await guard(tx, {
  policy: {
    ownerPubkey: wallet.publicKey.toBase58(),
    maxLamportsOut: 0.25 * 1e9,
    recipientAllowlist: [treasury.toBase58()],
    allowCompliantTransfers: true,    // transfers within the limits verdict SAFE
  },
  connection,                         // optional: enables simulation
  ownedTokenAccounts: "auto",         // optional: discover + diff the owner's token accounts
});

// result.verdict: "SAFE" | "WARN" | "BLOCK"
// result.findings: { code, severity, message, ix?, data? }[]
// result.simulated: boolean
// result.simulation?: { ownerLamportDelta, ownerTokenDeltas (bigint per mint), logs, err, unitsConsumed }
// result.summary: { programsInvoked, staticLamportsOut, worstCasePriorityFeeLamports,
//                   instructionCount, usesLookupTables }
```

`tx` is a `@solana/web3.js` `Transaction` (legacy) or `VersionedTransaction` (v0). The function never signs, sends, or mutates the transaction. An invalid `policy.ownerPubkey` throws immediately (fail-closed) rather than running with a mis-scoped policy.

### The verdict contract

```ts
if (result.verdict === "BLOCK") {
  throw new Error("tx-guard blocked: " + result.findings[0]?.message);
}
if (result.verdict === "WARN") {
  await escalateToHuman(result);   // do not sign autonomously
  return;
}
await wallet.signAndSend(tx);       // SAFE
```

By default every transfer is at least WARN (maximally conservative). For an agent that must act alone, configure the caps + allowlist and set `allowCompliantTransfers: true` so policy-compliant transactions come back SAFE — see [policy.md](policy.md).

## Pattern 1 — wrap a wallet / signer

The cleanest integration: a signer that guards every transaction before delegating to the real one.

```ts
import { guard, type Policy } from "solana-tx-guard";
import type { Connection, Transaction, VersionedTransaction } from "@solana/web3.js";

export function guardedSigner(
  inner: { signTransaction(tx: any): Promise<any> },
  opts: { policy: Policy; connection?: Connection },
) {
  return {
    async signTransaction(tx: Transaction | VersionedTransaction) {
      const r = await guard(tx, opts);
      if (r.verdict === "BLOCK") {
        throw new Error(`tx-guard BLOCK: ${r.findings.map((f) => f.code).join(", ")}`);
      }
      if (r.verdict === "WARN") {
        // policy choice: throw, or require an explicit approval callback
        throw new Error(`tx-guard WARN (needs approval): ${r.findings[0]?.message}`);
      }
      return inner.signTransaction(tx);
    },
  };
}
```

## Pattern 2 — solana-agent-kit / SendAI

`solana-agent-kit` actions build transactions and then sign with the agent's keypair. Put the guard between build and sign. If you use a custom signer or the `SolanaAgentKit` wallet, wrap it with `guardedSigner` above. For action-level checks, guard the transaction the action returns before sending:

```ts
const tx = await agent.methods.someTransferAction(...);   // builds, not yet sent
const r = await guard(tx, {
  policy: { ownerPubkey: agent.wallet.publicKey.toBase58(), maxLamportsOut: 0.5e9 },
  connection: agent.connection,
});
if (r.verdict !== "SAFE") throw new Error(`blocked by tx-guard: ${r.verdict}`);
await agent.connection.sendTransaction(tx);
```

This is especially valuable when the transaction was built from a natural-language instruction that could be prompt-injected — the guard is independent of the model.

## Pattern 3 — CLI / CI gating

For shell scripts, CI, or a `/tx-guard` agent command, use the CLI. It reads a base64 transaction and exits with a code you can gate on.

```bash
txguard check --tx <base64> --owner <pubkey> --max-sol 0.5 --allow <addr,addr>
# exit codes: 0 SAFE, 1 WARN, 2 BLOCK, 3 usage/error
```

```bash
# pipe from stdin, gate a signing step
txguard check --owner "$OWNER" --max-sol 0.5 < tx.b64 || { echo "refused"; exit 1; }
```

Flags:

| Flag | Meaning |
|------|---------|
| `--tx <base64>` | transaction wire bytes (omit to read stdin) |
| `--rpc <url>` | enables simulation |
| `--owner <pubkey>` | the agent's wallet (recommended, always) |
| `--max-sol <n>` | SOL outflow cap, in SOL |
| `--max-fee <n>` | worst-case priority-fee cap, in SOL |
| `--allow <a,b>` | recipient allowlist |
| `--allow-program <id,id>` | extra trusted program ids |
| `--watch <acct,acct\|auto>` | token accounts to diff in simulation |
| `--allow-unverified` | unknown programs WARN instead of BLOCK |
| `--allow-delegation` / `--allow-close` | switch off the delegation / close hard blocks |
| `--allow-compliant` | transfers within caps + allowlist verdict SAFE |
| `--json` | machine-readable output (bigints as strings) |

The CLI is **fail-closed on its own arguments**: an unknown flag or a malformed value (e.g. `--max-sol abc`) exits 3 instead of silently running with a weaker policy.

## @solana/kit interop

If your agent builds transactions with `@solana/kit` (web3.js v2), serialize to wire bytes and check via the CLI, or deserialize into a `VersionedTransaction` for the library:

```ts
import { VersionedTransaction } from "@solana/web3.js";
// kit gives you the compiled wire bytes:
const bytes = getTransactionEncoder().encode(kitTx);
const tx = VersionedTransaction.deserialize(bytes);
const r = await guard(tx, { policy, connection });
```

The guard only needs the compiled message + account keys, which both libraries produce.

## Logging & auditability

Every finding has a stable machine `code` (e.g. `POLICY_CAP_EXCEEDED`, `SIM_TOKEN_OUTFLOW`). Log `result.verdict` + `result.findings` on every check so an operator can later see exactly why a transaction was allowed or refused. Treat a BLOCK like a refused security gate, not a bug.
