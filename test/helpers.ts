/**
 * Shared test helpers: build real web3.js transactions and raw SPL token
 * instructions so the analyzer is exercised against actual wire bytes, not
 * mocked decoders.
 */

import {
  AddressLookupTableAccount,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import { TOKEN_PROGRAM } from "../src/programs.js";

export const BLOCKHASH = "11111111111111111111111111111111";

export function u64le(n: bigint): number[] {
  const out: number[] = [];
  for (let i = 0; i < 8; i++) out.push(Number((n >> BigInt(8 * i)) & 0xffn));
  return out;
}

export function key(): PublicKey {
  return Keypair.generate().publicKey;
}

/** Build a raw SPL token instruction with arbitrary discriminator + accounts. */
export function tokenIx(
  tag: number,
  extra: number[],
  accounts: PublicKey[],
  programId = TOKEN_PROGRAM,
): TransactionInstruction {
  return new TransactionInstruction({
    programId: new PublicKey(programId),
    keys: accounts.map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })),
    data: Buffer.from([tag, ...extra]),
  });
}

export function tokenTransfer(amount: bigint, source: PublicKey, dest: PublicKey, owner: PublicKey) {
  return tokenIx(3, u64le(amount), [source, dest, owner]);
}
export function tokenTransferChecked(
  amount: bigint,
  decimals: number,
  source: PublicKey,
  mint: PublicKey,
  dest: PublicKey,
  owner: PublicKey,
) {
  return tokenIx(12, [...u64le(amount), decimals], [source, mint, dest, owner]);
}
export function tokenApprove(amount: bigint, source: PublicKey, delegate: PublicKey, owner: PublicKey) {
  return tokenIx(4, u64le(amount), [source, delegate, owner]);
}
export function tokenSetAuthority(account: PublicKey, currentAuthority: PublicKey) {
  return tokenIx(6, [0, 0], [account, currentAuthority]);
}
export function tokenSetAuthorityTo(account: PublicKey, currentAuthority: PublicKey, newAuthority: PublicKey) {
  // authorityType 2 = AccountOwner, COption flag 1, then the new authority.
  return tokenIx(6, [2, 1, ...newAuthority.toBytes()], [account, currentAuthority]);
}
export function tokenCloseAccount(account: PublicKey, dest: PublicKey, owner: PublicKey) {
  return tokenIx(9, [], [account, dest, owner]);
}
export function tokenBurnChecked(amount: bigint, decimals: number, account: PublicKey, mint: PublicKey, owner: PublicKey) {
  return tokenIx(15, [...u64le(amount), decimals], [account, mint, owner]);
}

/** An instruction calling an arbitrary (unknown) program. */
export function unknownProgramIx(programId: PublicKey, accounts: PublicKey[] = []): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: accounts.map((pubkey) => ({ pubkey, isSigner: false, isWritable: false })),
    data: Buffer.from([1, 2, 3, 4]),
  });
}

/** Wrap instructions in a legacy Transaction (enough for static analysis). */
export function legacyTx(feePayer: PublicKey, ixs: TransactionInstruction[]): Transaction {
  const tx = new Transaction();
  for (const ix of ixs) tx.add(ix);
  tx.feePayer = feePayer;
  tx.recentBlockhash = BLOCKHASH;
  return tx;
}

/** Wrap instructions in a VersionedTransaction (v0). */
export function v0Tx(payer: PublicKey, ixs: TransactionInstruction[]): VersionedTransaction {
  const msg = new TransactionMessage({
    payerKey: payer,
    recentBlockhash: BLOCKHASH,
    instructions: ixs,
  }).compileToV0Message();
  return new VersionedTransaction(msg);
}

/** Wrap instructions in a v0 tx whose non-signer accounts come from an address lookup table. */
export function v0TxWithLookupTable(
  payer: PublicKey,
  ixs: TransactionInstruction[],
  lookupAddresses: PublicKey[],
): VersionedTransaction {
  const lut = new AddressLookupTableAccount({
    key: key(),
    state: {
      deactivationSlot: 18446744073709551615n,
      lastExtendedSlot: 0,
      lastExtendedSlotStartIndex: 0,
      addresses: lookupAddresses,
    },
  });
  const msg = new TransactionMessage({
    payerKey: payer,
    recentBlockhash: BLOCKHASH,
    instructions: ixs,
  }).compileToV0Message([lut]);
  return new VersionedTransaction(msg);
}

/** Build a fake SPL token account data buffer: mint at 0..32, amount u64 at 64..72. */
export function tokenAccountData(mint: PublicKey, amount: bigint): Buffer {
  const buf = Buffer.alloc(165);
  mint.toBuffer().copy(buf, 0);
  Buffer.from(u64le(amount)).copy(buf, 64);
  return buf;
}
