# Resources & Reference

## Program ids (canonical)

| Program | Address |
|---------|---------|
| System | `11111111111111111111111111111111` |
| SPL Token | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` |
| Token-2022 | `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` |
| Associated Token Account | `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` |
| Memo (v2) | `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` |
| Memo (legacy) | `Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo` |
| Compute Budget | `ComputeBudget111111111111111111111111111111` |

## Instruction layouts decoded

**System program** — 4-byte `u32` LE discriminator:
- `0` CreateAccount `{ lamports: u64, space: u64, owner: pubkey }` — accounts `[from, new]`
- `1` Assign `{ owner: pubkey }` — accounts `[account]`
- `2` Transfer `{ lamports: u64 }` — accounts `[from, to]`
- `3` CreateAccountWithSeed `{ base: pubkey, seed: string, lamports: u64, space: u64, owner: pubkey }` — accounts `[from, created, (base)]` (bincode string = u64 length prefix + bytes)
- `5` WithdrawNonceAccount `{ lamports: u64 }` — accounts `[nonce, to, recentBlockhashes, rent, authority]`
- `7` AuthorizeNonceAccount `{ authorized: pubkey }` — accounts `[nonce, current authority]`
- `10` AssignWithSeed `{ base: pubkey, seed: string, owner: pubkey }` — accounts `[account, base]`
- `11` TransferWithSeed `{ lamports: u64, seed: string, owner: pubkey }` — accounts `[from, base, to]`

**SPL Token / Token-2022** — 1-byte `u8` discriminator:
- `3` Transfer `{ amount: u64 }` — `[source, dest, owner]`
- `12` TransferChecked `{ amount: u64, decimals: u8 }` — `[source, mint, dest, owner]`
- `4` Approve `{ amount: u64 }` — `[source, delegate, owner]`
- `13` ApproveChecked `{ amount: u64, decimals: u8 }` — `[source, mint, delegate, owner]`
- `6` SetAuthority `{ authority_type: u8, new_authority: COption<pubkey> }` — `[account|mint, current authority]`
- `8` Burn `{ amount: u64 }` — `[account, mint, owner]`
- `15` BurnChecked `{ amount: u64, decimals: u8 }` — `[account, mint, owner]`
- `9` CloseAccount — `[account, destination, owner]`

**Compute Budget** — 1-byte `u8` discriminator (priority-fee drain detection):
- `0` RequestUnits (deprecated) `{ units: u32, additionalFee: u32 }`
- `2` SetComputeUnitLimit `{ units: u32 }`
- `3` SetComputeUnitPrice `{ microLamports: u64 }` — worst-case fee = cuLimit × price / 10^6

**SPL token account layout** (for simulation diffing): `mint` at byte offset 0 (32 bytes), `amount` `u64` LE at offset 64.

> These discriminators and account orders are part of the stable SPL Token / System program ABI. Token-2022 shares the same tags for the operations above.

## RPC

- `simulateTransaction` config used: `{ sigVerify: false, replaceRecentBlockhash: true, accounts: { encoding: "base64", addresses: [...] } }`
- web3.js docs: https://solana.com/docs/clients/javascript
- JSON-RPC `simulateTransaction`: https://solana.com/docs/rpc/http/simulatetransaction
- Any RPC works; Helius/Triton/mainnet-beta all support the `accounts` return field.

## Related references

- SPL Token program: https://spl.solana.com/token
- Token-2022: https://spl.solana.com/token-2022
- Address Lookup Tables: https://solana.com/docs/advanced/lookup-tables
- solana-agent-kit (SendAI): https://github.com/sendaifun/solana-agent-kit

## Where tx-guard sits in the kit

- **Code-level security** (review the program you write): `trailofbits`, `safe-solana-builder`, `ghostsecurity`, `defending-code`.
- **Runtime transaction safety** (review the tx your agent signs): **this skill**.
- **RPC/data**: `helius` for the `connection` that powers simulation.
- **Agent actions**: `sendai` / `solana-agent-kit` — the thing you put the guard in front of.

## Honest scope

tx-guard is not a replacement for a wallet's own scanner (Blowfish/Blockaid) or for a code audit. It is an open, dependency-light, self-hostable guardrail for *autonomous signers*, which those tools don't specifically serve. It reduces — does not eliminate — risk: combine static + simulation + a tight policy, and keep a human in the loop for anything above your cap.
