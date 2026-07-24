# Policy Configuration

Policy turns observations into decisions. Static analysis and simulation produce findings; policy decides which ones are hard **BLOCK**s — and, optionally, which compliant transfers may verdict **SAFE** so an autonomous agent can act without a human. Everything is optional — an empty policy still runs full analysis and reports findings.

## The `Policy` object

```ts
interface Policy {
  maxLamportsOut?: number;            // cap on native SOL (lamports) leaving the owner; over => BLOCK
  maxTokenOutByMint?: Record<string, number | string>; // per-mint caps in base units; over => BLOCK
  maxFeeLamports?: number;            // cap on worst-case priority fee (cuLimit × cuPrice); over => BLOCK
  recipientAllowlist?: string[];      // base58 addresses funds may go to; anything else => BLOCK
  programAllowlist?: string[];        // extra trusted program ids beyond the known-safe set
  allowUnverifiedPrograms?: boolean;  // default false: unknown program => BLOCK. true => WARN only
  blockOnDelegation?: boolean;        // default true: Approve / SetAuthority / Assign / nonce authorize => BLOCK
  blockOnAccountClose?: boolean;      // default true: CloseAccount => BLOCK
  allowCompliantTransfers?: boolean;  // default false: when true, transfers within the limits verdict SAFE
  feeLamportsTolerance?: number;      // default 20_000: simulated outflows up to this are info (tx fee)
  ownerPubkey?: string;               // the agent's wallet; scopes drain detection + simulation
}
```

**Allowlist gotcha:** SPL token transfers target token *accounts* (usually ATAs), not wallets. Put the destination token account address in `recipientAllowlist`, not just the wallet address (derive with `getAssociatedTokenAddressSync(mint, wallet)`).

## Fail-closed defaults

With `policy = {}` (only `ownerPubkey` recommended), these are already on:

- **Unknown programs BLOCK** (`allowUnverifiedPrograms` defaults to false). The known-safe set is System, SPL Token, Token-2022, Associated Token Account, Memo, Compute Budget.
- **Delegation / authority handover BLOCK** (`blockOnDelegation` defaults true): `Approve`, `SetAuthority`, System `Assign`/`AssignWithSeed`, `AuthorizeNonceAccount`.
- **Account close BLOCK** (`blockOnAccountClose` defaults true): `CloseAccount`.
- **Malformed policy values BLOCK** (`POLICY_INVALID_TOKEN_CAP`) — a typo must never weaken the policy.

This is deliberate: an agent should refuse the dangerous-by-default actions unless you explicitly loosen them.

## Policy findings

| Finding code | Trigger | Severity |
|--------------|---------|----------|
| `POLICY_UNVERIFIED_PROGRAM` | program not in known/allowlisted set and `allowUnverifiedPrograms` false | critical |
| `POLICY_CAP_EXCEEDED` | max(static, simulated) owner SOL outflow > `maxLamportsOut` | critical |
| `POLICY_TOKEN_CAP_EXCEEDED` | max(static known-mint, simulated) token outflow > per-mint cap | critical |
| `POLICY_FEE_EXCEEDED` | worst-case priority fee > `maxFeeLamports` | critical |
| `POLICY_RECIPIENT_NOT_ALLOWED` | funds target an address not in `recipientAllowlist` (transfers, account funding, nonce withdrawals; delegates / close destinations when their hard block is off) | critical |
| `POLICY_RECIPIENT_UNVERIFIABLE` | a `recipientAllowlist` is set and simulation shows the owner losing more lamports than the allowlist-checked static instructions account for — a CPI-hidden outflow whose recipient simulation can't reveal | warn |
| `POLICY_DELEGATION_BLOCKED` | delegation-family instruction while `blockOnDelegation` on | critical |
| `POLICY_ACCOUNT_CLOSE_BLOCKED` | `CloseAccount` while `blockOnAccountClose` on | critical |
| `POLICY_INVALID_TOKEN_CAP` | unparseable `maxTokenOutByMint` value | critical |
| `POLICY_TOKEN_CAP_UNVERIFIABLE` | a token cap is set but the cap couldn't be fully enforced: an unchecked owner outflow (no mint) simulation didn't observe, **or** the watch list was truncated (`watchTruncated`) so a capped mint's source may have been dropped | warn |

Any critical → verdict BLOCK.

### The unchecked-transfer gap (important)

A per-mint cap can only match an outflow when the mint is known. The `*Checked` instructions (`TransferChecked`, `ApproveChecked`, `BurnChecked`) carry the mint, so they're capped statically. The plain unchecked `Transfer`/`Approve`/`Burn` do **not** carry the mint — statically we see "some token leaving the owner" but not which one. tx-guard closes this two ways:

1. **Simulation** attributes the outflow by diffing the source token account's balance (the mint comes from account state), so the cap is enforced against the real per-mint delta. Always pass a `connection` and watch the source (`ownedTokenAccounts: "auto"`).
2. If a token cap is set and the cap could not be fully enforced — an unchecked owner outflow **not** observed by simulation (offline, or the source account wasn't watched), or the watch list was truncated (`watchTruncated`) so a capped mint's source may have been among the dropped accounts — tx-guard emits `POLICY_TOKEN_CAP_UNVERIFIABLE` (warn) and never lets the transaction verdict SAFE. It fails closed rather than pretend the cap held. (Truncation of accounts the tx could touch *also* fails closed on its own via a warn `SIM_WATCH_FILTERED`, independent of any cap — see [simulate.md](simulate.md).)

## SAFE for compliant transfers (`allowCompliantTransfers`)

By default every transfer is at least WARN — safe, but it means a payment agent can never act autonomously. Set `allowCompliantTransfers: true` and configure the matching limits, and transfer findings that comply are downgraded to `info`, so a fully compliant transaction verdicts **SAFE**:

| Finding | Downgraded to info when... |
|---------|---------------------------|
| `SOL_TRANSFER` / `ACCOUNT_FUNDING` / `NONCE_WITHDRAW` | `maxLamportsOut` **and** `recipientAllowlist` are both set (and satisfied) |
| `TOKEN_TRANSFER` | `recipientAllowlist` is set (and satisfied) — **and**, if a `maxTokenOutByMint` cap is set, only for `*Checked` transfers whose mint is known (an unchecked `Transfer` under a token cap stays WARN, since the cap couldn't be matched statically) |
| `SIM_NATIVE_OUTFLOW` | `maxLamportsOut` **and** `recipientAllowlist` are both set, and the simulated outflow is accounted for by the allowlist-checked static instructions. A simulated outflow that *exceeds* what those instructions moved is CPI-hidden — simulation can't reveal its recipient, so it raises `POLICY_RECIPIENT_UNVERIFIABLE` (warn) instead and stays out of SAFE |
| `SIM_TOKEN_OUTFLOW` | `maxTokenOutByMint` has a cap for that mint (and it's satisfied) |
| `HIGH_PRIORITY_FEE` | `maxFeeLamports` is set (and satisfied) |

Two hard rules keep this safe:
1. **Nothing is downgraded if any finding in the transaction is critical** — a partially malicious tx never gets its "nice parts" polished.
2. A finding is only downgraded when the limit that governs it is **configured** — compliance is then implied, because a violation would have produced a critical policy finding.

`TOKEN_BURN`, `UNKNOWN_PROGRAM` (unless program-allowlisted), and all delegation/close findings are never downgraded by this flag.

## Recommended presets

### Autonomous agent handling user funds (strict, can act alone)
```ts
{
  ownerPubkey: wallet.publicKey.toBase58(),
  maxLamportsOut: 0.25 * 1e9,                 // never move > 0.25 SOL in one tx
  maxTokenOutByMint: { [USDC_MINT]: 100e6 },  // never move > 100 USDC in one tx
  maxFeeLamports: 0.01 * 1e9,                 // cap the priority fee
  recipientAllowlist: [treasury, treasuryUsdcAta], // wallets AND token accounts
  allowCompliantTransfers: true,              // within all of the above => SAFE
  allowUnverifiedPrograms: false,             // unknown programs blocked
  blockOnDelegation: true,
  blockOnAccountClose: true,
}
```
Pair with simulation (pass a `connection` and `ownedTokenAccounts: "auto"`) so the caps also catch outflows hidden inside CPIs.

### DeFi agent that must call DEX/lending programs
```ts
{
  ownerPubkey: wallet.publicKey.toBase58(),
  programAllowlist: [jupiter, orca, raydium], // trust specific protocols (their WARN becomes info)
  maxLamportsOut: 1 * 1e9,
  maxTokenOutByMint: { [USDC_MINT]: 500e6 },  // bound what a swap may spend
  maxFeeLamports: 0.05 * 1e9,
  allowUnverifiedPrograms: false,             // still block everything else
}
```
Add only the program ids you actually integrate. Keep the list tight — each entry is trust you're extending. Leave `allowCompliantTransfers` off if you want a WARN-and-review flow for every swap.

### Dev / human-in-the-loop (relaxed, observe-only)
```ts
{
  ownerPubkey: wallet.publicKey.toBase58(),
  allowUnverifiedPrograms: true,              // unknown => WARN, not BLOCK
  blockOnDelegation: false,
  blockOnAccountClose: false,
}
```
Nothing auto-blocks; you rely on WARN escalation to a human. Good for tooling where a person approves each signature. Note: with delegation/close blocking off, `recipientAllowlist` (if set) still checks delegates and close destinations.

## How caps interact with simulation

- `maxLamportsOut` is checked against `max(staticLamportsOut, simulatedOwnerOutflow)`. Even if a transfer amount is obfuscated and only shows up in the simulated balance drop, the cap still catches it.
- `maxTokenOutByMint` is checked against `max(static known-mint amounts, simulated per-mint deltas)`. Statically, only `TransferChecked`/`ApproveChecked`/`BurnChecked` carry the mint; plain `Transfer` amounts are only attributable via simulation — one more reason to always pass a `connection`.

## Choosing the right knobs

- Handling real user funds, no human in the loop → **strict preset**, always, with simulation on.
- Need to call specific protocols → add their ids to `programAllowlist`, don't flip `allowUnverifiedPrograms`.
- Building dev tooling with review → **relaxed preset**, lean on WARN.
- Never disable `blockOnDelegation` for a fund-handling agent: a delegation is a *future* drain that simulation of *this* tx won't show as an outflow.
