/**
 * Runnable demo: build a few transactions and guard them.
 *
 *   npx tsx examples/demo.ts
 *
 * Shows the verdict + findings for a safe tx, an over-cap transfer, a hidden
 * delegation (drainer pattern), and an unknown-program call. No RPC needed —
 * this is static analysis + policy only. Add a connection for simulation.
 */

import {
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import { guard } from "../src/index.js";

const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const owner = Keypair.generate().publicKey;
const recipient = Keypair.generate().publicKey;

function u64le(n: bigint): number[] {
  const out: number[] = [];
  for (let i = 0; i < 8; i++) out.push(Number((n >> BigInt(8 * i)) & 0xffn));
  return out;
}
function v0(ixs: TransactionInstruction[]) {
  const msg = new TransactionMessage({
    payerKey: owner,
    recentBlockhash: "11111111111111111111111111111111",
    instructions: ixs,
  }).compileToV0Message();
  return new VersionedTransaction(msg);
}

const policy = {
  ownerPubkey: owner.toBase58(),
  maxLamportsOut: 0.5 * 1e9,
  maxFeeLamports: 0.01 * 1e9,
  recipientAllowlist: [recipient.toBase58()],
  allowCompliantTransfers: true, // transfers within the caps + allowlist verdict SAFE
};

const cases: { name: string; tx: VersionedTransaction }[] = [
  {
    name: "SAFE: compute budget only",
    tx: v0([ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 })]),
  },
  {
    name: "SAFE: small transfer to allowlisted recipient, under cap (compliant)",
    tx: v0([SystemProgram.transfer({ fromPubkey: owner, toPubkey: recipient, lamports: 1_000_000 })]),
  },
  {
    name: "BLOCK: 2 SOL transfer, over 0.5 SOL cap",
    tx: v0([SystemProgram.transfer({ fromPubkey: owner, toPubkey: recipient, lamports: 2_000_000_000 })]),
  },
  {
    name: "BLOCK: transfer to non-allowlisted address",
    tx: v0([SystemProgram.transfer({ fromPubkey: owner, toPubkey: Keypair.generate().publicKey, lamports: 1 })]),
  },
  {
    name: "BLOCK: hidden token Approve (delegation / drainer pattern)",
    tx: v0([
      new TransactionInstruction({
        programId: new PublicKey(TOKEN_PROGRAM),
        keys: [owner, Keypair.generate().publicKey, owner].map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })),
        data: Buffer.from([4, ...u64le(1_000_000_000n)]),
      }),
    ]),
  },
  {
    name: "BLOCK: unknown program",
    tx: v0([
      new TransactionInstruction({
        programId: Keypair.generate().publicKey,
        keys: [{ pubkey: owner, isSigner: false, isWritable: true }],
        data: Buffer.from([1, 2, 3]),
      }),
    ]),
  },
  {
    name: "BLOCK: drain disguised as account creation (1 SOL of 'rent')",
    tx: v0([
      SystemProgram.createAccount({
        fromPubkey: owner,
        newAccountPubkey: Keypair.generate().publicKey,
        lamports: 1_000_000_000,
        space: 0,
        programId: Keypair.generate().publicKey,
      }),
    ]),
  },
  {
    name: "BLOCK: priority-fee drain (inflated compute-unit price)",
    tx: v0([
      ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 100_000_000_000n }),
      SystemProgram.transfer({ fromPubkey: owner, toPubkey: recipient, lamports: 1 }),
    ]),
  },
  {
    name: "BLOCK: nonce-account authority handover",
    tx: v0([
      SystemProgram.nonceAuthorize({
        noncePubkey: Keypair.generate().publicKey,
        authorizedPubkey: owner,
        newAuthorizedPubkey: Keypair.generate().publicKey,
      }),
    ]),
  },
];

for (const c of cases) {
  const r = await guard(c.tx, { policy });
  const icon = r.verdict === "SAFE" ? "✅" : r.verdict === "WARN" ? "⚠️ " : "⛔";
  console.log(`\n${icon} ${r.verdict}  —  ${c.name}`);
  for (const f of r.findings) {
    console.log(`     [${f.severity}] ${f.code}: ${f.message}`);
  }
}
console.log("");
