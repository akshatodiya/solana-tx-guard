# Drain Detection (Static Analysis)

What tx-guard decodes offline, what severity each gets, and why. This layer runs with no RPC and is the first line of defense — it catches a malicious instruction before the transaction is ever sent to a node.

## How it works

1. **Normalize** the transaction (legacy `Transaction` or `VersionedTransaction`) into a flat list of instructions with every account resolved to a base58 address.
2. **Identify the program** of each instruction against a registry of known programs.
3. **Decode asset-affecting instructions** and emit a `Finding` (`code`, `severity`, `message`, `data`).

## Detected instructions

| Program | Instruction | Finding code | Default severity (owner-affected) |
|---------|------------|--------------|-----------------------------------|
| System | `Transfer` / `TransferWithSeed` | `SOL_TRANSFER` | warn |
| System | `CreateAccount` / `CreateAccountWithSeed` (funds a new account) | `ACCOUNT_FUNDING` | warn |
| System | `WithdrawNonceAccount` | `NONCE_WITHDRAW` | warn |
| System | `AuthorizeNonceAccount` (nonce authority handover) | `NONCE_AUTHORIZE` | **critical** |
| System | `Assign` / `AssignWithSeed` (reassign program owner) | `SYSTEM_ASSIGN` | **critical** |
| SPL Token / Token-2022 | `Transfer` / `TransferChecked` | `TOKEN_TRANSFER` | warn |
| SPL Token / Token-2022 | `Approve` / `ApproveChecked` (delegate) | `TOKEN_DELEGATION` | **critical** |
| SPL Token / Token-2022 | `SetAuthority` (new authority decoded into `data.newAuthority`) | `AUTHORITY_CHANGE` | **critical** |
| SPL Token / Token-2022 | `CloseAccount` | `ACCOUNT_CLOSE` | **critical** |
| SPL Token / Token-2022 | `Burn` / `BurnChecked` | `TOKEN_BURN` | warn |
| Compute Budget | `SetComputeUnitLimit` + `SetComputeUnitPrice` → worst-case priority fee > 0.01 SOL | `HIGH_PRIORITY_FEE` | warn |
| any program not in the known/allowlisted set | (whole instruction) | `UNKNOWN_PROGRAM` | warn (BLOCK via policy) |
| program loaded from an unresolved lookup table | (whole instruction) | `UNRESOLVED_PROGRAM` | warn |

Both the legacy **SPL Token** program and **Token-2022** are decoded with the same instruction tags (the discriminators match for these operations).

## Why these are the dangerous ones

- **Transfer (SOL / token)** — the obvious outflow. Amount is decoded from the instruction data (`u64` little-endian) so policy can cap it.
- **CreateAccount / CreateAccountWithSeed** — moves lamports out just like a transfer, only labeled "account creation". A drainer can fund an attacker-controlled account this way; the funding amount counts toward `staticLamportsOut` and the SOL cap.
- **WithdrawNonceAccount** — drains a durable-nonce account's lamports; counted as an outflow when the owner is the nonce authority.
- **AuthorizeNonceAccount** — hands the nonce account (and its lamports) to a new authority. Treated as a delegation-family action.
- **Approve / ApproveChecked** — the *non-obvious* drain. It doesn't move funds now; it grants a **delegate** that can move them later, outside this transaction. A classic wallet-drainer pattern. Treated as critical when the owner is the authority.
- **SetAuthority** — hands ownership of a token account or mint to someone else. The new authority is decoded from the instruction data and reported.
- **CloseAccount** — reclaims an account's rent lamports to a destination. Closing a **wrapped-SOL** account effectively withdraws its balance; closing an account with a non-zero token balance can be abused.
- **Assign / AssignWithSeed** (System) — reassigns an account to a different *program owner*, which can place it under hostile program control.
- **Burn / BurnChecked** — destroys the owner's tokens. Not a theft, but an irreversible loss.
- **Compute-budget fee spike** — a real drainer technique: `SetComputeUnitPrice` with an absurd micro-lamport price makes the network take the fee payer's balance as priority fees. tx-guard computes the worst case (`cuLimit × cuPrice`), reports it in `summary.worstCasePriorityFeeLamports`, flags anything over 0.01 SOL, and `policy.maxFeeLamports` can hard-block it.
- **Unknown program** — anything outside the known-safe set can do arbitrary things via CPI. Static analysis can't read its intent, so it's flagged and (by default policy) blocked unless allowlisted. Simulation is the backstop here.

## Owner-scoping (severity)

Set `policy.ownerPubkey` to the agent's wallet. Then:

- Actions that **debit or hand over the owner's accounts** keep their high severity (delegation/authority/close → critical; SOL/token transfers, funding, burns → warn).
- The same instruction between **unrelated third-party accounts** is de-escalated one step, never dropped to nothing: transfers / funding / nonce-withdraw / burns → `info`, but the delegation/authority/close family (Approve, SetAuthority, CloseAccount, nonce authorize, System Assign) stays at `warn` — handing control away is worth surfacing even when it isn't the owner's account.
- An account loaded from an **unresolved lookup table** *could* be the owner's, so it is treated as owner-affecting (fail-closed), never downgraded.

Without `ownerPubkey`, the guard is **conservative**: it assumes any outflow *could* be the owner's and counts it. Always pass `ownerPubkey` for accurate scoping.

## Known-safe programs

These are recognized and not flagged on their own (they can't silently move funds without an accompanying instruction that is itself inspected):

`System`, `SPL Token`, `Token-2022`, `Associated Token Account`, `Memo` (v1 + legacy), `Compute Budget`.

Add more trusted programs per-call via `policy.programAllowlist` (e.g. a specific DEX or your own program id). Allowlisted programs get their `UNKNOWN_PROGRAM` finding downgraded to `info`, so a transaction calling only programs you trust can verdict SAFE. See [policy.md](policy.md).

## Limitations (be honest about these)

- **Address Lookup Tables (v0)**: accounts loaded from ALTs cannot be resolved offline. The guard sets `summary.usesLookupTables = true`, marks unresolved accounts, treats them as potentially the owner's (severity stays warn), and emits `UNRESOLVED_PROGRAM` where needed. **Simulation covers this gap** — always simulate when ALTs are in play. See [simulate.md](simulate.md).
- **CPI depth**: a known program (e.g. an allowlisted DEX) can CPI into others. Static analysis sees the top-level instruction only; **simulation** observes the net balance effect.
- **Non-standard token programs / exotic instructions** beyond the decoded set fall under `UNKNOWN_PROGRAM` handling — flagged, not silently passed. Token-2022 extension instructions (e.g. transfer fees, confidential transfers) are not individually decoded; their net effect shows up in simulation.

The design principle: static analysis is **fail-closed and explainable**; simulation is the **ground truth** for net effect. Use both.
