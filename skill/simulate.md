# Simulation & Balance Diffing

Static analysis reads the *instructions*; simulation reads the *result*. `simulateTransaction` runs the transaction against an RPC node without submitting it, and — with the right config — returns post-execution account state. tx-guard diffs the owner's pre/post balances so you see the actual net effect, including anything hidden inside a CPI.

## When simulation runs

`guard()` simulates when **both** are provided:

- `options.connection` — any `@solana/web3.js` `Connection` (or a compatible object exposing `simulateTransaction` + `getMultipleAccountsInfo`)
- `policy.ownerPubkey` — so balance changes can be attributed to the owner

Without a connection, only static analysis runs (`result.simulated === false`). Without `ownerPubkey`, simulation is skipped with an `info` finding telling you to set it.

Legacy `Transaction` objects work even **before** they have a blockhash or fee payer: the guard compiles them with a placeholder blockhash (the RPC replaces it) and the owner as fee payer, without mutating your transaction.

## What it does

1. Fetches **pre-state** for the watched accounts via `getMultipleAccountsInfo`.
2. Calls `simulateTransaction(tx, { sigVerify: false, replaceRecentBlockhash: true, accounts: { encoding: "base64", addresses: [...] } })`.
3. Reads **post-state** from the returned `accounts` and diffs:
   - **Native lamports** of the owner account → `ownerLamportDelta` (negative = SOL left).
   - **SPL token amount** of each watched token account → `ownerTokenDeltas[mint]` as a `bigint` (negative = tokens left). Token amount is read from byte offset 64 (`u64` LE) of the token account; the mint from offset 0.
4. Emits findings:

| Condition | Finding | Severity |
|-----------|---------|----------|
| Simulation throws / RPC error | `SIMULATION_FAILED` | warn (falls back to static) |
| Connection has no `getMultipleAccountsInfo` (pre-state can't be fetched) | `SIM_PRESTATE_UNAVAILABLE` | warn (balances were NOT diffed) |
| Watched accounts the tx provably cannot touch (no lookup tables, not static keys) were skipped | `SIM_WATCH_FILTERED` | info |
| Watched accounts the tx COULD modify were dropped by the account limit — diff has a hole | `SIM_WATCH_FILTERED` | warn (fails closed, can't verdict SAFE) |
| `value.err` set (tx would revert) | `SIMULATION_ERROR` | warn |
| Owner native balance drops ≤ `feeLamportsTolerance` (default 20 000 lamports) | `SIM_NATIVE_OUTFLOW` | info — consistent with the tx fee |
| Owner native balance drops more than that | `SIM_NATIVE_OUTFLOW` | warn |
| Owner token balance drops | `SIM_TOKEN_OUTFLOW` | warn |

These feed the verdict like any other finding, and policy compares simulated outflows against `maxLamportsOut` / `maxTokenOutByMint` (it uses the larger of static and simulated outflow). The fee tolerance exists because the fee payer *always* shows a small negative delta — without it, every simulated transaction would be WARN.

### Full-drain edge cases (handled)

A transaction that drains an account to **exactly zero** deallocates it, and the RPC returns an explicit `null` for that account's post-state. tx-guard treats an in-range `null` on a successful transaction as a balance of 0 — so a 100% sweep of the owner's SOL (`ownerLamportDelta = -preBalance`) or a token account that is emptied *and closed* both show up as a full outflow, exactly like a 99% drain would. An account the RPC omits entirely (a short array, not an in-range `null`) is treated as unknown, never as a drain. `result.simulated` is `true` only when the RPC call actually returned; if it threw, `simulated` is `false` and `SIMULATION_FAILED` is raised.

## Watching token accounts

The owner's **native** account is always watched. For SPL balances you have two options:

```ts
// Option A (recommended): discover ALL of the owner's token accounts (2 extra RPC calls)
const result = await guard(tx, {
  connection,
  policy: { ownerPubkey: wallet.publicKey.toBase58() },
  ownedTokenAccounts: "auto",
});

// Option B: watch specific accounts
const result = await guard(tx, {
  connection,
  policy: { ownerPubkey: wallet.publicKey.toBase58() },
  ownedTokenAccounts: [usdcAta, bonkAta],   // base58 strings or PublicKeys
});
console.log(result.simulation?.ownerTokenDeltas); // { "<mint>": -250000n, ... }
```

`"auto"` queries `getTokenAccountsByOwner` for both the legacy Token and Token-2022 programs — it catches drains of accounts you forgot you had. For a hand-picked list, derive the ATA with `getAssociatedTokenAddressSync(mint, owner)` from `@solana/spl-token`.

**Watch list is capped at the transaction's account count.** An RPC caps the accounts it will return at the transaction's *total loaded* account count — static keys **plus** accounts pulled in from address lookup tables (`"Too many accounts provided"` otherwise). tx-guard computes that cap offline and keeps at most that many watched accounts, prioritizing the owner and any accounts that are static keys, then the rest. What happens to accounts that don't fit depends on whether the tx could touch them:

- **No lookup tables**: the tx's loaded accounts are exactly its static keys, so a watched account that isn't a static key *provably cannot change*. Those are skipped silently (`info` `SIM_WATCH_FILTERED`, `watchTruncated` stays `false`) — this is what makes `"auto"` usable on a wallet with hundreds of token accounts.
- **With lookup tables**: the loaded set can't be resolved offline, so *every* watched account is a potential target. If any is dropped for the cap, the diff has a hole a drainer could hide in (route the victim's ATA through an ALT, let the account limit push it off the watch list) — tx-guard fails closed with a **warn** `SIM_WATCH_FILTERED` and `watchTruncated: true`, so the result can never verdict SAFE, and if a per-mint cap is configured a `POLICY_TOKEN_CAP_UNVERIFIABLE` warn names the cap that became unenforceable.

## Why simulation is the backstop for static analysis

- **Unverified programs**: static analysis flags an unknown program but can't read its intent. Simulation shows whether it actually drains the owner. A tx that *looks* scary but nets zero owner outflow will show no `SIM_*_OUTFLOW`; one that hides a drain inside a CPI will.
- **Address Lookup Tables**: accounts the static layer couldn't resolve offline are fully resolved by the node during simulation, so the balance diff is still correct.
- **Unchecked token transfers**: plain `Transfer` doesn't carry the mint, so per-mint caps can't match it statically — the simulated per-mint delta closes that gap.
- **Net-of-everything**: fees, rent, multiple instructions, and CPIs all collapse into the observed delta.

## RPC notes

- `replaceRecentBlockhash: true` lets you simulate an unsigned/stale transaction without a fresh blockhash.
- `sigVerify: false` because the agent hasn't signed yet — that's the whole point.
- Some RPCs rate-limit the `accounts` return field; any decent provider (Helius, Triton, Solana mainnet-beta) supports it. If `accounts` comes back empty, deltas are `null` and only `SIMULATION_ERROR`/log-based findings apply — static analysis still stands.
- `ownerLamportDelta` is a JS `number` (that's what the RPC returns); token deltas are `bigint` (decoded from raw bytes, exact at any magnitude).
- Simulation reflects current chain state; it is the best available predictor but not a guarantee of the state at land time. Combine with a tight `recipientAllowlist`/cap for funds-handling agents.
