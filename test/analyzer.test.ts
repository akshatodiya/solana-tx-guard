import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeStatic, normalize } from "../src/analyzer.js";
import {
  key,
  legacyTx,
  v0Tx,
  v0TxWithLookupTable,
  tokenTransfer,
  tokenApprove,
  tokenSetAuthority,
  tokenSetAuthorityTo,
  tokenCloseAccount,
  tokenBurnChecked,
  unknownProgramIx,
} from "./helpers.js";
import { ComputeBudgetProgram, SystemProgram } from "@solana/web3.js";

test("decodes a native SOL transfer and sums outflow", () => {
  const owner = key();
  const to = key();
  const tx = legacyTx(owner, [
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 1_500_000 }),
  ]);
  const a = analyzeStatic(tx, owner.toBase58());
  const f = a.findings.find((x) => x.code === "SOL_TRANSFER");
  assert.ok(f, "expected SOL_TRANSFER finding");
  assert.equal(f!.data!.lamports, 1_500_000);
  assert.equal(a.staticLamportsOut, 1_500_000);
});

test("does not count outflow from a non-owner source", () => {
  const owner = key();
  const stranger = key();
  const to = key();
  const tx = legacyTx(owner, [
    SystemProgram.transfer({ fromPubkey: stranger, toPubkey: to, lamports: 999 }),
  ]);
  const a = analyzeStatic(tx, owner.toBase58());
  assert.equal(a.staticLamportsOut, 0, "stranger's transfer should not count as owner outflow");
});

test("flags an unverified program", () => {
  const owner = key();
  const prog = key();
  const tx = legacyTx(owner, [unknownProgramIx(prog, [owner])]);
  const a = analyzeStatic(tx, owner.toBase58());
  const f = a.findings.find((x) => x.code === "UNKNOWN_PROGRAM");
  assert.ok(f, "expected UNKNOWN_PROGRAM finding");
  assert.equal(f!.data!.programId, prog.toBase58());
});

test("decodes an SPL token transfer", () => {
  const owner = key();
  const source = key();
  const dest = key();
  const tx = legacyTx(owner, [tokenTransfer(42_000n, source, dest, owner)]);
  const a = analyzeStatic(tx, owner.toBase58());
  const f = a.findings.find((x) => x.code === "TOKEN_TRANSFER");
  assert.ok(f, "expected TOKEN_TRANSFER finding");
  assert.equal(f!.data!.amount, "42000");
  assert.equal(f!.data!.target, dest.toBase58());
});

test("treats token Approve to owner as critical delegation", () => {
  const owner = key();
  const source = key();
  const delegate = key();
  const tx = legacyTx(owner, [tokenApprove(1n, source, delegate, owner)]);
  const a = analyzeStatic(tx, owner.toBase58());
  const f = a.findings.find((x) => x.code === "TOKEN_DELEGATION");
  assert.ok(f, "expected TOKEN_DELEGATION finding");
  assert.equal(f!.severity, "critical");
  assert.equal(f!.data!.delegate, delegate.toBase58());
});

test("flags SetAuthority and CloseAccount", () => {
  const owner = key();
  const account = key();
  const dest = key();
  const tx = legacyTx(owner, [
    tokenSetAuthority(account, owner),
    tokenCloseAccount(account, dest, owner),
  ]);
  const a = analyzeStatic(tx, owner.toBase58());
  assert.ok(a.findings.find((x) => x.code === "AUTHORITY_CHANGE" && x.severity === "critical"));
  assert.ok(a.findings.find((x) => x.code === "ACCOUNT_CLOSE" && x.severity === "critical"));
});

test("normalizes a v0 VersionedTransaction identically", () => {
  const owner = key();
  const to = key();
  const tx = v0Tx(owner, [
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 7 }),
  ]);
  const { instructions, usesLookupTables } = normalize(tx);
  assert.equal(usesLookupTables, false);
  assert.ok(instructions.length >= 1);
  const a = analyzeStatic(tx, owner.toBase58());
  assert.ok(a.findings.find((x) => x.code === "SOL_TRANSFER"));
});

test("without an owner hint, outflows are still counted conservatively", () => {
  const someone = key();
  const to = key();
  const tx = legacyTx(someone, [
    SystemProgram.transfer({ fromPubkey: someone, toPubkey: to, lamports: 5 }),
  ]);
  const a = analyzeStatic(tx); // no owner
  assert.equal(a.staticLamportsOut, 5);
});

test("createAccount counts its lamports as owner outflow", () => {
  const owner = key();
  const fresh = key();
  const tx = legacyTx(owner, [
    SystemProgram.createAccount({
      fromPubkey: owner,
      newAccountPubkey: fresh,
      lamports: 3_000_000,
      space: 100,
      programId: key(),
    }),
  ]);
  const a = analyzeStatic(tx, owner.toBase58());
  const f = a.findings.find((x) => x.code === "ACCOUNT_FUNDING");
  assert.ok(f, "expected ACCOUNT_FUNDING finding");
  assert.equal(f!.severity, "warn");
  assert.equal(f!.data!.lamports, 3_000_000);
  assert.equal(a.staticLamportsOut, 3_000_000);
});

test("createAccountWithSeed decodes lamports past the seed string", () => {
  const owner = key();
  const tx = legacyTx(owner, [
    SystemProgram.createAccountWithSeed({
      fromPubkey: owner,
      newAccountPubkey: key(),
      basePubkey: owner,
      seed: "a-seed-string",
      lamports: 7_777_777,
      space: 0,
      programId: key(),
    }),
  ]);
  const a = analyzeStatic(tx, owner.toBase58());
  assert.equal(a.staticLamportsOut, 7_777_777);
});

test("nonce withdraw counts as outflow when the owner is the nonce authority", () => {
  const owner = key();
  const nonce = key();
  const to = key();
  const tx = legacyTx(owner, [
    SystemProgram.nonceWithdraw({
      noncePubkey: nonce,
      authorizedPubkey: owner,
      toPubkey: to,
      lamports: 9_000_000,
    }),
  ]);
  const a = analyzeStatic(tx, owner.toBase58());
  const f = a.findings.find((x) => x.code === "NONCE_WITHDRAW");
  assert.ok(f, "expected NONCE_WITHDRAW finding");
  assert.equal(a.staticLamportsOut, 9_000_000);
});

test("nonce authorize by the owner is a critical authority handover", () => {
  const owner = key();
  const nonce = key();
  const attacker = key();
  const tx = legacyTx(owner, [
    SystemProgram.nonceAuthorize({
      noncePubkey: nonce,
      authorizedPubkey: owner,
      newAuthorizedPubkey: attacker,
    }),
  ]);
  const a = analyzeStatic(tx, owner.toBase58());
  const f = a.findings.find((x) => x.code === "NONCE_AUTHORIZE");
  assert.ok(f, "expected NONCE_AUTHORIZE finding");
  assert.equal(f!.severity, "critical");
  assert.equal(f!.data!.newAuthority, attacker.toBase58());
});

test("assign with seed is flagged like Assign", () => {
  const owner = key();
  const account = key();
  const hostileProgram = key();
  const tx = legacyTx(owner, [
    SystemProgram.assign({
      accountPubkey: account,
      basePubkey: owner,
      seed: "seed",
      programId: hostileProgram,
    }),
  ]);
  const a = analyzeStatic(tx, owner.toBase58());
  const f = a.findings.find((x) => x.code === "SYSTEM_ASSIGN");
  assert.ok(f, "expected SYSTEM_ASSIGN finding");
  assert.equal(f!.severity, "critical", "owner is the base authority");
  assert.equal(f!.data!.newProgramOwner, hostileProgram.toBase58());
});

test("BurnChecked is decoded like Burn", () => {
  const owner = key();
  const account = key();
  const mint = key();
  const tx = legacyTx(owner, [tokenBurnChecked(123_456n, 6, account, mint, owner)]);
  const a = analyzeStatic(tx, owner.toBase58());
  const f = a.findings.find((x) => x.code === "TOKEN_BURN");
  assert.ok(f, "expected TOKEN_BURN finding for BurnChecked");
  assert.equal(f!.data!.amount, "123456");
});

test("SetAuthority exposes the new authority", () => {
  const owner = key();
  const account = key();
  const attacker = key();
  const tx = legacyTx(owner, [tokenSetAuthorityTo(account, owner, attacker)]);
  const a = analyzeStatic(tx, owner.toBase58());
  const f = a.findings.find((x) => x.code === "AUTHORITY_CHANGE");
  assert.ok(f);
  assert.equal(f!.data!.newAuthority, attacker.toBase58());
});

test("an inflated compute-unit price is flagged as a fee drain", () => {
  const owner = key();
  const to = key();
  const tx = legacyTx(owner, [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 100_000_000_000n }),
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 1 }),
  ]);
  const a = analyzeStatic(tx, owner.toBase58());
  const f = a.findings.find((x) => x.code === "HIGH_PRIORITY_FEE");
  assert.ok(f, "expected HIGH_PRIORITY_FEE finding");
  // 1_400_000 CU × 100_000_000_000 µlamports / 1e6 = 1.4e11 lamports (140 SOL)
  assert.equal(a.worstCasePriorityFeeLamports, 140_000_000_000);
});

test("a normal priority fee is not flagged", () => {
  const owner = key();
  const to = key();
  const tx = legacyTx(owner, [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 10_000n }),
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 1 }),
  ]);
  const a = analyzeStatic(tx, owner.toBase58());
  assert.ok(!a.findings.find((x) => x.code === "HIGH_PRIORITY_FEE"));
  assert.equal(a.worstCasePriorityFeeLamports, 2_000); // 200k CU × 10k µlamports / 1e6
});

test("accounts loaded from a lookup table are treated as potentially the owner's", () => {
  const owner = key();
  const source = key();
  const dest = key();
  const authority = key();
  const tx = v0TxWithLookupTable(
    owner,
    [tokenTransfer(1_000n, source, dest, authority)],
    [source, dest, authority],
  );
  const { instructions, usesLookupTables } = normalize(tx);
  assert.equal(usesLookupTables, true);
  assert.ok(
    instructions.some((ix) => ix.accounts.includes("__unresolved__")),
    "expected unresolved lookup-table accounts",
  );
  const a = analyzeStatic(tx, owner.toBase58());
  const f = a.findings.find((x) => x.code === "TOKEN_TRANSFER");
  assert.ok(f, "expected TOKEN_TRANSFER finding");
  assert.equal(f!.severity, "warn", "unresolved accounts must not be downgraded to info");
});
