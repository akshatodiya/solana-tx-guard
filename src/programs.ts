/**
 * Program registry + instruction decoders.
 *
 * Everything here is OFFLINE: given a normalized instruction (program id +
 * resolved account addresses + raw data bytes) we recognize the well-known
 * Solana programs and decode the instructions that can move or hand over a
 * user's assets. No network access is required.
 */

import { PublicKey } from "@solana/web3.js";

/** Well-known program ids. */
export const SYSTEM_PROGRAM = "11111111111111111111111111111111";
export const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
export const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
export const ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
export const MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
export const MEMO_PROGRAM_LEGACY = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo";
export const COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111";

/**
 * Programs that are safe to invoke on their own — they cannot, by themselves,
 * silently move a user's funds without an accompanying token/system transfer
 * that we already inspect. Unknown programs outside this set are flagged.
 */
export const KNOWN_SAFE_PROGRAMS = new Set<string>([
  SYSTEM_PROGRAM,
  TOKEN_PROGRAM,
  TOKEN_2022_PROGRAM,
  ASSOCIATED_TOKEN_PROGRAM,
  MEMO_PROGRAM,
  MEMO_PROGRAM_LEGACY,
  COMPUTE_BUDGET_PROGRAM,
]);

/** A transaction instruction with all account references resolved to base58 addresses. */
export interface NormalizedInstruction {
  programId: string;
  accounts: string[];
  data: Uint8Array;
}

/** The kinds of asset-affecting actions we decode. */
export type DecodedKind =
  | "sol_transfer"
  | "sol_create_account"
  | "system_assign"
  | "nonce_withdraw"
  | "nonce_authorize"
  | "token_transfer"
  | "token_approve"
  | "token_set_authority"
  | "token_close_account"
  | "token_burn";

export interface DecodedAction {
  kind: DecodedKind;
  /** Source account whose assets are affected (the account being debited / handed over). */
  source?: string;
  /** Destination / recipient / new-authority / delegate, depending on kind. */
  target?: string;
  /** The account authorizing the action (owner / current authority). */
  authority?: string;
  /** Raw amount in base units (lamports for SOL, token base units for SPL), when applicable. */
  amount?: bigint;
  /** Mint, for token instructions where it is present in the account list. */
  mint?: string;
  /** Which token program (for token_* kinds). */
  tokenProgram?: string;
}

function readU64LE(data: Uint8Array, offset: number): bigint {
  if (offset + 8 > data.length) return 0n;
  let result = 0n;
  for (let i = 0; i < 8; i++) {
    result |= BigInt(data[offset + i]!) << BigInt(8 * i);
  }
  return result;
}

function readU32LE(data: Uint8Array, offset: number): number {
  if (offset + 4 > data.length) return -1;
  return (
    data[offset]! |
    (data[offset + 1]! << 8) |
    (data[offset + 2]! << 16) |
    (data[offset + 3]! << 24)
  ) >>> 0;
}

/** Base58-encode a pubkey embedded in instruction data, or null if out of range. */
function readPubkey(data: Uint8Array, offset: number): string | null {
  if (offset + 32 > data.length) return null;
  return new PublicKey(data.subarray(offset, offset + 32)).toBase58();
}

/**
 * Rust bincode string prefix: u32 length + u32 padding, then the bytes.
 * Returns the offset of the first byte AFTER the string, or -1 if malformed.
 */
function skipRustString(data: Uint8Array, offset: number): number {
  const len = readU32LE(data, offset);
  if (len < 0) return -1;
  const end = offset + 8 + len;
  return end > data.length ? -1 : end;
}

/** Decode a System Program instruction. Returns null for instructions that don't move/assign assets. */
function decodeSystem(ix: NormalizedInstruction): DecodedAction | null {
  const tag = readU32LE(ix.data, 0);
  switch (tag) {
    case 2: // Transfer { lamports: u64 }  accounts: [from, to]
    case 11: {
      // TransferWithSeed { lamports, seed, owner } accounts: [from, base, to]
      const lamports = readU64LE(ix.data, 4);
      const from = ix.accounts[0];
      const to = tag === 2 ? ix.accounts[1] : ix.accounts[2];
      // For TransferWithSeed the debited `from` is a create-with-seed account
      // derived from `base` (the signer/controller). The owner controls the
      // funds when they control `base`, so scope on `base`, not the derived
      // `from` — otherwise a `base == owner` outflow is misread as third-party.
      const authority = tag === 11 ? ix.accounts[1] : undefined;
      return { kind: "sol_transfer", source: from, target: to, authority, amount: lamports };
    }
    case 0: {
      // CreateAccount { lamports: u64, space: u64, owner: pubkey } accounts: [from, new]
      return {
        kind: "sol_create_account",
        source: ix.accounts[0],
        target: ix.accounts[1],
        authority: ix.accounts[0],
        amount: readU64LE(ix.data, 4),
      };
    }
    case 3: {
      // CreateAccountWithSeed { base: pubkey, seed: string, lamports: u64, space: u64, owner: pubkey }
      // accounts: [from, created, (base)]
      const afterSeed = skipRustString(ix.data, 36); // 4 tag + 32 base
      return {
        kind: "sol_create_account",
        source: ix.accounts[0],
        target: ix.accounts[1],
        authority: ix.accounts[0],
        amount: afterSeed >= 0 ? readU64LE(ix.data, afterSeed) : 0n,
      };
    }
    case 5: {
      // WithdrawNonceAccount { lamports: u64 } accounts: [nonce, to, recentBlockhashes, rent, authority]
      return {
        kind: "nonce_withdraw",
        source: ix.accounts[0],
        target: ix.accounts[1],
        authority: ix.accounts[4],
        amount: readU64LE(ix.data, 4),
      };
    }
    case 7: {
      // AuthorizeNonceAccount { authorized: pubkey } accounts: [nonce, current authority]
      return {
        kind: "nonce_authorize",
        source: ix.accounts[0],
        target: readPubkey(ix.data, 4) ?? undefined,
        authority: ix.accounts[1],
      };
    }
    case 1: {
      // Assign { owner: pubkey } accounts: [account]  — reassigns program ownership of an account
      return {
        kind: "system_assign",
        source: ix.accounts[0],
        target: readPubkey(ix.data, 4) ?? undefined,
        authority: ix.accounts[0],
      };
    }
    case 10: {
      // AssignWithSeed { base: pubkey, seed: string, owner: pubkey } accounts: [account, base]
      const afterSeed = skipRustString(ix.data, 36);
      return {
        kind: "system_assign",
        source: ix.accounts[0],
        target: afterSeed >= 0 ? readPubkey(ix.data, afterSeed) ?? undefined : undefined,
        authority: ix.accounts[1],
      };
    }
    case 9: {
      // AllocateWithSeed { base: pubkey, seed: string, space: u64, owner: pubkey }
      // accounts: [account, base]. This is allocate_and_assign — like
      // AssignWithSeed it reassigns the account to the embedded `owner` program,
      // so it is the same ownership-handover threat and must not slip through.
      const afterSeed = skipRustString(ix.data, 36); // 4 tag + 32 base
      const ownerOffset = afterSeed >= 0 ? afterSeed + 8 : -1; // skip u64 space
      return {
        kind: "system_assign",
        source: ix.accounts[0],
        target: ownerOffset >= 0 ? readPubkey(ix.data, ownerOffset) ?? undefined : undefined,
        authority: ix.accounts[1],
      };
    }
    default:
      return null;
  }
}

/** Decode an SPL Token / Token-2022 instruction. Returns null for non-asset-affecting instructions. */
function decodeToken(ix: NormalizedInstruction): DecodedAction | null {
  const tag = ix.data[0];
  if (tag === undefined) return null;
  const tokenProgram = ix.programId;
  switch (tag) {
    case 3: {
      // Transfer { amount: u64 } accounts: [source, dest, owner]
      return {
        kind: "token_transfer",
        source: ix.accounts[0],
        target: ix.accounts[1],
        authority: ix.accounts[2],
        amount: readU64LE(ix.data, 1),
        tokenProgram,
      };
    }
    case 12: {
      // TransferChecked { amount: u64, decimals: u8 } accounts: [source, mint, dest, owner]
      return {
        kind: "token_transfer",
        source: ix.accounts[0],
        mint: ix.accounts[1],
        target: ix.accounts[2],
        authority: ix.accounts[3],
        amount: readU64LE(ix.data, 1),
        tokenProgram,
      };
    }
    case 4: // Approve { amount } accounts: [source, delegate, owner]
    case 13: {
      // ApproveChecked { amount, decimals } accounts: [source, mint, delegate, owner]
      const checked = tag === 13;
      return {
        kind: "token_approve",
        source: ix.accounts[0],
        mint: checked ? ix.accounts[1] : undefined,
        target: checked ? ix.accounts[2] : ix.accounts[1],
        authority: checked ? ix.accounts[3] : ix.accounts[2],
        amount: readU64LE(ix.data, 1),
        tokenProgram,
      };
    }
    case 6: {
      // SetAuthority { authority_type: u8, new_authority: COption<pubkey> }
      // accounts: [account-or-mint, current authority]
      const hasNew = ix.data[2] === 1;
      return {
        kind: "token_set_authority",
        source: ix.accounts[0],
        target: hasNew ? readPubkey(ix.data, 3) ?? undefined : undefined,
        authority: ix.accounts[1],
        tokenProgram,
      };
    }
    case 9: {
      // CloseAccount accounts: [account, destination, owner]
      return {
        kind: "token_close_account",
        source: ix.accounts[0],
        target: ix.accounts[1],
        authority: ix.accounts[2],
        tokenProgram,
      };
    }
    case 8: // Burn { amount } accounts: [account, mint, owner]
    case 15: {
      // BurnChecked { amount, decimals } accounts: [account, mint, owner]
      return {
        kind: "token_burn",
        source: ix.accounts[0],
        mint: ix.accounts[1],
        authority: ix.accounts[2],
        amount: readU64LE(ix.data, 1),
        tokenProgram,
      };
    }
    default:
      return null;
  }
}

/** Decode a single normalized instruction into an asset-affecting action, or null. */
export function decodeInstruction(ix: NormalizedInstruction): DecodedAction | null {
  if (ix.programId === SYSTEM_PROGRAM) return decodeSystem(ix);
  if (ix.programId === TOKEN_PROGRAM || ix.programId === TOKEN_2022_PROGRAM) {
    return decodeToken(ix);
  }
  return null;
}

/** A decoded Compute Budget request. Priority fees are a drain vector: fee = cuLimit × cuPrice. */
export type ComputeBudgetRequest =
  | { kind: "cu_limit"; units: number }
  | { kind: "cu_price"; microLamports: bigint };

/**
 * Decode a Compute Budget instruction (u8 discriminator). A huge
 * SetComputeUnitPrice can burn the fee payer's balance as priority fees, so the
 * analyzer computes the worst-case fee from these.
 */
export function decodeComputeBudget(ix: NormalizedInstruction): ComputeBudgetRequest | null {
  if (ix.programId !== COMPUTE_BUDGET_PROGRAM) return null;
  const tag = ix.data[0];
  switch (tag) {
    case 0: // RequestUnits (deprecated) { units: u32, additionalFee: u32 }
    case 2: {
      // SetComputeUnitLimit { units: u32 }
      const units = readU32LE(ix.data, 1);
      return units < 0 ? null : { kind: "cu_limit", units };
    }
    case 3: {
      // SetComputeUnitPrice { microLamports: u64 }
      return { kind: "cu_price", microLamports: readU64LE(ix.data, 1) };
    }
    default:
      return null;
  }
}
