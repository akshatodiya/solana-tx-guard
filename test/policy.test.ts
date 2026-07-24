import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeStatic } from "../src/analyzer.js";
import { applyPolicy, finalizeFindings } from "../src/policy.js";
import {
  key,
  legacyTx,
  tokenTransfer,
  tokenTransferChecked,
  tokenApprove,
  tokenCloseAccount,
  unknownProgramIx,
} from "./helpers.js";
import { ComputeBudgetProgram, SystemProgram } from "@solana/web3.js";

function findingsFor(tx: Parameters<typeof analyzeStatic>[0], owner: string, policy: Parameters<typeof applyPolicy>[1]) {
  const a = analyzeStatic(tx, owner);
  return applyPolicy(a, policy);
}

test("cap exceeded produces a critical block", () => {
  const owner = key();
  const to = key();
  const tx = legacyTx(owner, [
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 2_000_000 }),
  ]);
  const findings = findingsFor(tx, owner.toBase58(), { maxLamportsOut: 1_000_000 });
  const f = findings.find((x) => x.code === "POLICY_CAP_EXCEEDED");
  assert.ok(f);
  assert.equal(f!.severity, "critical");
});

test("cap respected produces no cap finding", () => {
  const owner = key();
  const to = key();
  const tx = legacyTx(owner, [
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 500 }),
  ]);
  const findings = findingsFor(tx, owner.toBase58(), { maxLamportsOut: 1_000_000 });
  assert.ok(!findings.find((x) => x.code === "POLICY_CAP_EXCEEDED"));
});

test("recipient not in allowlist is blocked", () => {
  const owner = key();
  const treasury = key();
  const attacker = key();
  const tx = legacyTx(owner, [
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: attacker, lamports: 1 }),
  ]);
  const findings = findingsFor(tx, owner.toBase58(), { recipientAllowlist: [treasury.toBase58()] });
  const f = findings.find((x) => x.code === "POLICY_RECIPIENT_NOT_ALLOWED");
  assert.ok(f);
  assert.equal(f!.data!.recipient, attacker.toBase58());
});

test("allowlisted recipient passes", () => {
  const owner = key();
  const treasury = key();
  const tx = legacyTx(owner, [
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: treasury, lamports: 1 }),
  ]);
  const findings = findingsFor(tx, owner.toBase58(), { recipientAllowlist: [treasury.toBase58()] });
  assert.ok(!findings.find((x) => x.code === "POLICY_RECIPIENT_NOT_ALLOWED"));
});

test("unverified program blocked by default, allowed when opted in", () => {
  const owner = key();
  const prog = key();
  const tx = legacyTx(owner, [unknownProgramIx(prog, [owner])]);

  const blocked = findingsFor(tx, owner.toBase58(), {});
  assert.ok(blocked.find((x) => x.code === "POLICY_UNVERIFIED_PROGRAM" && x.severity === "critical"));

  const allowedByFlag = findingsFor(tx, owner.toBase58(), { allowUnverifiedPrograms: true });
  assert.ok(!allowedByFlag.find((x) => x.code === "POLICY_UNVERIFIED_PROGRAM"));

  const allowedByList = findingsFor(tx, owner.toBase58(), { programAllowlist: [prog.toBase58()] });
  assert.ok(!allowedByList.find((x) => x.code === "POLICY_UNVERIFIED_PROGRAM"));
});

test("delegation is blocked when blockOnDelegation is on (default)", () => {
  const owner = key();
  const source = key();
  const delegate = key();
  const tx = legacyTx(owner, [tokenApprove(5n, source, delegate, owner)]);
  const findings = findingsFor(tx, owner.toBase58(), {});
  assert.ok(findings.find((x) => x.code === "POLICY_DELEGATION_BLOCKED" && x.severity === "critical"));
});

test("delegation allowed when blockOnDelegation disabled", () => {
  const owner = key();
  const source = key();
  const delegate = key();
  const tx = legacyTx(owner, [tokenApprove(5n, source, delegate, owner)]);
  const findings = findingsFor(tx, owner.toBase58(), { blockOnDelegation: false });
  assert.ok(!findings.find((x) => x.code === "POLICY_DELEGATION_BLOCKED"));
});

test("token transfer to non-allowlisted recipient is blocked", () => {
  const owner = key();
  const source = key();
  const dest = key();
  const treasury = key();
  const tx = legacyTx(owner, [tokenTransfer(10n, source, dest, owner)]);
  const findings = findingsFor(tx, owner.toBase58(), { recipientAllowlist: [treasury.toBase58()] });
  assert.ok(findings.find((x) => x.code === "POLICY_RECIPIENT_NOT_ALLOWED"));
});

test("worst-case priority fee above maxFeeLamports is blocked", () => {
  const owner = key();
  const to = key();
  const tx = legacyTx(owner, [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000_000n }), // 1e6 lamports worst case
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 1 }),
  ]);
  const blocked = findingsFor(tx, owner.toBase58(), { maxFeeLamports: 500_000 });
  assert.ok(blocked.find((x) => x.code === "POLICY_FEE_EXCEEDED" && x.severity === "critical"));
  const allowed = findingsFor(tx, owner.toBase58(), { maxFeeLamports: 2_000_000 });
  assert.ok(!allowed.find((x) => x.code === "POLICY_FEE_EXCEEDED"));
});

test("per-mint token cap blocks an over-cap TransferChecked", () => {
  const owner = key();
  const source = key();
  const mint = key();
  const dest = key();
  const tx = legacyTx(owner, [tokenTransferChecked(1_000_000n, 6, source, mint, dest, owner)]);
  const blocked = findingsFor(tx, owner.toBase58(), {
    ownerPubkey: owner.toBase58(),
    maxTokenOutByMint: { [mint.toBase58()]: 500_000 },
  });
  assert.ok(blocked.find((x) => x.code === "POLICY_TOKEN_CAP_EXCEEDED" && x.severity === "critical"));
  const allowed = findingsFor(tx, owner.toBase58(), {
    ownerPubkey: owner.toBase58(),
    maxTokenOutByMint: { [mint.toBase58()]: "2000000" },
  });
  assert.ok(!allowed.find((x) => x.code === "POLICY_TOKEN_CAP_EXCEEDED"));
});

test("a malformed token cap fails closed", () => {
  const owner = key();
  const mint = key();
  const tx = legacyTx(owner, []);
  const findings = findingsFor(tx, owner.toBase58(), {
    maxTokenOutByMint: { [mint.toBase58()]: "not-a-number" },
  });
  assert.ok(findings.find((x) => x.code === "POLICY_INVALID_TOKEN_CAP" && x.severity === "critical"));
});

test("recipient allowlist covers the delegate when delegation blocking is off", () => {
  const owner = key();
  const source = key();
  const delegate = key();
  const treasury = key();
  const tx = legacyTx(owner, [tokenApprove(5n, source, delegate, owner)]);
  const findings = findingsFor(tx, owner.toBase58(), {
    blockOnDelegation: false,
    recipientAllowlist: [treasury.toBase58()],
  });
  const f = findings.find((x) => x.code === "POLICY_RECIPIENT_NOT_ALLOWED");
  assert.ok(f, "delegate outside the allowlist must be blocked");
  assert.equal(f!.data!.recipient, delegate.toBase58());
});

test("recipient allowlist covers the close destination when close blocking is off", () => {
  const owner = key();
  const account = key();
  const attacker = key();
  const treasury = key();
  const tx = legacyTx(owner, [tokenCloseAccount(account, attacker, owner)]);
  const findings = findingsFor(tx, owner.toBase58(), {
    blockOnAccountClose: false,
    recipientAllowlist: [treasury.toBase58()],
  });
  assert.ok(findings.find((x) => x.code === "POLICY_RECIPIENT_NOT_ALLOWED"));
});

test("recipient allowlist covers account funding", () => {
  const owner = key();
  const fresh = key();
  const treasury = key();
  const tx = legacyTx(owner, [
    SystemProgram.createAccount({
      fromPubkey: owner,
      newAccountPubkey: fresh,
      lamports: 1_000_000,
      space: 0,
      programId: key(),
    }),
  ]);
  const findings = findingsFor(tx, owner.toBase58(), { recipientAllowlist: [treasury.toBase58()] });
  assert.ok(findings.find((x) => x.code === "POLICY_RECIPIENT_NOT_ALLOWED"));
});

test("nonce authorize is blocked by blockOnDelegation (default)", () => {
  const owner = key();
  const tx = legacyTx(owner, [
    SystemProgram.nonceAuthorize({
      noncePubkey: key(),
      authorizedPubkey: owner,
      newAuthorizedPubkey: key(),
    }),
  ]);
  const findings = findingsFor(tx, owner.toBase58(), {});
  assert.ok(findings.find((x) => x.code === "POLICY_DELEGATION_BLOCKED"));
});

test("finalizeFindings downgrades an allowlisted program's UNKNOWN_PROGRAM to info", () => {
  const owner = key();
  const dex = key();
  const tx = legacyTx(owner, [unknownProgramIx(dex, [owner])]);
  const a = analyzeStatic(tx, owner.toBase58());
  const policy = { programAllowlist: [dex.toBase58()] };
  const merged = [...a.findings, ...applyPolicy(a, policy)];
  const final = finalizeFindings(merged, policy);
  const f = final.find((x) => x.code === "UNKNOWN_PROGRAM");
  assert.ok(f);
  assert.equal(f!.severity, "info");
});
