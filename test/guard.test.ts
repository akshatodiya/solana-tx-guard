import { test } from "node:test";
import assert from "node:assert/strict";
import { ComputeBudgetProgram, PublicKey, SystemProgram, Transaction, TransactionInstruction } from "@solana/web3.js";
import { guard } from "../src/index.js";
import {
  key,
  legacyTx,
  v0Tx,
  v0TxWithLookupTable,
  tokenTransfer,
  tokenTransferChecked,
  tokenAccountData,
} from "./helpers.js";

test("end-to-end: SOL transfer over cap is BLOCKed (static only)", async () => {
  const owner = key();
  const to = key();
  const tx = legacyTx(owner, [
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 5_000_000 }),
  ]);
  const res = await guard(tx, { policy: { ownerPubkey: owner.toBase58(), maxLamportsOut: 1_000_000 } });
  assert.equal(res.verdict, "BLOCK");
  assert.ok(res.findings.find((f) => f.code === "POLICY_CAP_EXCEEDED"));
  assert.equal(res.simulated, false);
});

test("end-to-end: harmless compute-budget-only tx is SAFE", async () => {
  const owner = key();
  const tx = legacyTx(owner, [ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 })]);
  const res = await guard(tx, { policy: { ownerPubkey: owner.toBase58() } });
  assert.equal(res.verdict, "SAFE");
  assert.equal(res.findings.length, 0);
});

test("end-to-end: simulation surfaces a token outflow the owner did not expect", async () => {
  const owner = key();
  const source = key(); // owner's token account
  const dest = key();
  const mint = key();

  const tx = v0Tx(owner, [tokenTransfer(600n, source, dest, owner)]);

  // Mock RPC: pre 1000 tokens, post 400 tokens => -600 delta.
  const mockConnection = {
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map((a, i) =>
        i === 0
          ? { lamports: 1_000_000_000, data: Buffer.alloc(0), owner: "11111111111111111111111111111111" }
          : { lamports: 2_039_280, data: tokenAccountData(mint, 1000n), owner: "" },
      );
    },
    async simulateTransaction() {
      return {
        value: {
          err: null,
          logs: ["Program log: ok"],
          unitsConsumed: 1234,
          accounts: [
            { lamports: 1_000_000_000, data: ["", "base64"], owner: "" },
            { lamports: 2_039_280, data: [tokenAccountData(mint, 400n).toString("base64"), "base64"], owner: "" },
          ],
        },
      };
    },
  };

  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58() },
    connection: mockConnection as never,
    ownedTokenAccounts: [source],
  });

  assert.equal(res.simulated, true);
  assert.ok(res.simulation, "expected simulation block");
  assert.equal(res.simulation!.ownerTokenDeltas[mint.toBase58()], -600n);
  assert.ok(res.findings.find((f) => f.code === "SIM_TOKEN_OUTFLOW"));
});

test("end-to-end: compliant transfer verdicts SAFE with allowCompliantTransfers", async () => {
  const owner = key();
  const treasury = key();
  const tx = legacyTx(owner, [
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: treasury, lamports: 1_000_000 }),
  ]);
  const policyBase = {
    ownerPubkey: owner.toBase58(),
    maxLamportsOut: 500_000_000,
    recipientAllowlist: [treasury.toBase58()],
  };

  const withoutFlag = await guard(tx, { policy: policyBase });
  assert.equal(withoutFlag.verdict, "WARN", "default behavior: transfers stay WARN");

  const withFlag = await guard(tx, { policy: { ...policyBase, allowCompliantTransfers: true } });
  assert.equal(withFlag.verdict, "SAFE", "compliant transfer should be SAFE");
  const f = withFlag.findings.find((x) => x.code === "SOL_TRANSFER");
  assert.equal(f!.severity, "info");
});

test("end-to-end: nothing is downgraded when any finding is critical", async () => {
  const owner = key();
  const treasury = key();
  const attacker = key();
  const tx = legacyTx(owner, [
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: treasury, lamports: 1_000_000 }),
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: attacker, lamports: 1 }),
  ]);
  const res = await guard(tx, {
    policy: {
      ownerPubkey: owner.toBase58(),
      maxLamportsOut: 500_000_000,
      recipientAllowlist: [treasury.toBase58()],
      allowCompliantTransfers: true,
    },
  });
  assert.equal(res.verdict, "BLOCK");
  const compliantTransfer = res.findings.find(
    (x) => x.code === "SOL_TRANSFER" && x.data?.target === treasury.toBase58(),
  );
  assert.equal(compliantTransfer!.severity, "warn", "no downgrades in a blocked transaction");
});

test("end-to-end: allowlisted program can reach SAFE", async () => {
  const owner = key();
  const dex = key();
  const tx = legacyTx(owner, [
    { programId: dex, keys: [{ pubkey: owner, isSigner: false, isWritable: true }], data: Buffer.from([1]) },
  ]);
  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58(), programAllowlist: [dex.toBase58()] },
  });
  assert.equal(res.verdict, "SAFE");
  assert.equal(res.findings.find((x) => x.code === "UNKNOWN_PROGRAM")!.severity, "info");
});

test("end-to-end: fee-spike drain is blocked by maxFeeLamports", async () => {
  const owner = key();
  const to = key();
  const tx = legacyTx(owner, [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 100_000_000_000n }),
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 1 }),
  ]);
  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58(), maxFeeLamports: 1_000_000 },
  });
  assert.equal(res.verdict, "BLOCK");
  assert.ok(res.findings.find((f) => f.code === "POLICY_FEE_EXCEEDED"));
  assert.equal(res.summary.worstCasePriorityFeeLamports, 140_000_000_000);
});

test("end-to-end: fee-only simulated outflow is info, not WARN", async () => {
  const owner = key();
  const tx = v0Tx(owner, [ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 })]);

  const mockConnection = {
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map(() => ({ lamports: 1_000_000_000, data: Buffer.alloc(0), owner: "" }));
    },
    async simulateTransaction() {
      return {
        value: {
          err: null,
          logs: [],
          unitsConsumed: 150,
          accounts: [{ lamports: 999_995_000, data: ["", "base64"], owner: "" }], // -5000: the tx fee
        },
      };
    },
  };

  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58() },
    connection: mockConnection as never,
  });
  assert.equal(res.simulation!.ownerLamportDelta, -5_000);
  const f = res.findings.find((x) => x.code === "SIM_NATIVE_OUTFLOW");
  assert.equal(f!.severity, "info", "a fee-sized outflow must not force WARN");
  assert.equal(res.verdict, "SAFE");
});

test("end-to-end: simulated token outflow over the per-mint cap is blocked", async () => {
  const owner = key();
  const source = key();
  const dest = key();
  const mint = key();
  const tx = v0Tx(owner, [tokenTransfer(600n, source, dest, owner)]);

  const mockConnection = {
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map((_, i) =>
        i === 0
          ? { lamports: 1_000_000_000, data: Buffer.alloc(0), owner: "" }
          : { lamports: 2_039_280, data: tokenAccountData(mint, 1000n), owner: "" },
      );
    },
    async simulateTransaction() {
      return {
        value: {
          err: null,
          logs: [],
          unitsConsumed: 1,
          accounts: [
            { lamports: 1_000_000_000, data: ["", "base64"], owner: "" },
            { lamports: 2_039_280, data: [tokenAccountData(mint, 400n).toString("base64"), "base64"], owner: "" },
          ],
        },
      };
    },
  };

  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58(), maxTokenOutByMint: { [mint.toBase58()]: 500 } },
    connection: mockConnection as never,
    ownedTokenAccounts: [source],
  });
  assert.equal(res.verdict, "BLOCK");
  const f = res.findings.find((x) => x.code === "POLICY_TOKEN_CAP_EXCEEDED");
  assert.ok(f, "simulated outflow of 600 must exceed the cap of 500");
  assert.equal(f!.data!.source, "simulation");
});

test("end-to-end: ownedTokenAccounts 'auto' discovers accounts via the RPC", async () => {
  const owner = key();
  const tokenAcct = key();
  const dest = key();
  const mint = key();
  const tx = v0Tx(owner, [tokenTransfer(250n, tokenAcct, dest, owner)]);

  const mockConnection = {
    async getTokenAccountsByOwner() {
      return { value: [{ pubkey: tokenAcct, account: {} }] };
    },
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map((_, i) =>
        i === 0
          ? { lamports: 1_000_000_000, data: Buffer.alloc(0), owner: "" }
          : { lamports: 2_039_280, data: tokenAccountData(mint, 1000n), owner: "" },
      );
    },
    async simulateTransaction() {
      return {
        value: {
          err: null,
          logs: [],
          unitsConsumed: 1,
          accounts: [
            { lamports: 1_000_000_000, data: ["", "base64"], owner: "" },
            { lamports: 2_039_280, data: [tokenAccountData(mint, 750n).toString("base64"), "base64"], owner: "" },
          ],
        },
      };
    },
  };

  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58() },
    connection: mockConnection as never,
    ownedTokenAccounts: "auto",
  });
  assert.equal(res.simulation!.ownerTokenDeltas[mint.toBase58()], -250n);
  assert.ok(res.findings.find((f) => f.code === "SIM_TOKEN_OUTFLOW"));
});

test("end-to-end: a legacy tx without blockhash/feePayer can still be simulated", async () => {
  const owner = key();
  const to = key();
  const tx = new Transaction().add(
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 1_000 }),
  ); // no recentBlockhash, no feePayer — as freshly built by an agent

  let simulateCalled = false;
  const mockConnection = {
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map(() => null);
    },
    async simulateTransaction() {
      simulateCalled = true;
      return { value: { err: null, logs: [], unitsConsumed: 0, accounts: [null] } };
    },
  };

  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58() },
    connection: mockConnection as never,
  });
  assert.equal(simulateCalled, true, "simulation should run for an unsigned legacy tx");
  assert.equal(res.simulated, true);
  assert.ok(!res.findings.find((f) => f.code === "SIM_SKIPPED_LEGACY_UNSIGNED"));
});

test("end-to-end: an invalid ownerPubkey throws a clear error", async () => {
  const owner = key();
  const tx = legacyTx(owner, []);
  await assert.rejects(
    () => guard(tx, { policy: { ownerPubkey: "not-a-pubkey" } }),
    /ownerPubkey is not a valid base58 pubkey/,
  );
});

// --- Regression tests for confirmed review findings ---

test("regression: unchecked token transfer over the mint cap cannot verdict SAFE (offline)", async () => {
  // A plain (unchecked) Transfer carries no mint, so the per-mint cap can't be
  // enforced statically. Even with an allowlisted recipient + allowCompliantTransfers,
  // this must NOT reach SAFE.
  const owner = key();
  const source = key();
  const dest = key();
  const mint = key();
  const tx = legacyTx(owner, [tokenTransfer(1_000_000_000n, source, dest, owner)]); // 1000x a 1e6 cap
  const res = await guard(tx, {
    policy: {
      ownerPubkey: owner.toBase58(),
      maxTokenOutByMint: { [mint.toBase58()]: "1000000" },
      recipientAllowlist: [dest.toBase58()],
      allowCompliantTransfers: true,
    },
  });
  assert.notEqual(res.verdict, "SAFE", "an unenforceable token cap must not pass as SAFE");
  assert.ok(res.findings.find((f) => f.code === "POLICY_TOKEN_CAP_UNVERIFIABLE"));
});

test("regression: owner system account drained to exactly 0 is caught by the cap", async () => {
  const owner = key();
  const drainProgram = key();
  const tx = v0Tx(owner, [
    { programId: drainProgram, keys: [{ pubkey: owner, isSigner: true, isWritable: true }], data: Buffer.from([9]) },
  ]);
  const mockConnection = {
    async getMultipleAccountsInfo() {
      return [{ lamports: 2_000_000_000, data: Buffer.alloc(0), owner: "" }];
    },
    async simulateTransaction() {
      // Account drained to 0 => deallocated => node returns explicit null in-range.
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts: [null] } };
    },
  };
  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58(), maxLamportsOut: 100_000_000, programAllowlist: [drainProgram.toBase58()] },
    connection: mockConnection as never,
  });
  assert.equal(res.simulation!.ownerLamportDelta, -2_000_000_000, "full drain must show as -preBalance");
  assert.equal(res.verdict, "BLOCK");
  assert.ok(res.findings.find((f) => f.code === "POLICY_CAP_EXCEEDED"));
});

test("regression: a short accounts array is NOT read as a drain", async () => {
  // If the RPC omits the account entirely (short array, not an in-range null),
  // we must treat it as unknown, not as drained to zero.
  const owner = key();
  const tx = v0Tx(owner, [ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 })]);
  const mockConnection = {
    async getMultipleAccountsInfo() {
      return [{ lamports: 2_000_000_000, data: Buffer.alloc(0), owner: "" }];
    },
    async simulateTransaction() {
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts: [] } }; // empty
    },
  };
  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58(), maxLamportsOut: 100_000_000 },
    connection: mockConnection as never,
  });
  assert.equal(res.simulation!.ownerLamportDelta, null, "absent post must be unknown, not a drain");
  assert.ok(!res.findings.find((f) => f.code === "POLICY_CAP_EXCEEDED"));
});

test("regression: a watched token account emptied+closed shows a full outflow", async () => {
  const owner = key();
  const tokenAcct = key();
  const mint = key();
  const drainProgram = key();
  const tx = v0Tx(owner, [
    {
      programId: drainProgram,
      // A real drain references the token account it empties, so it appears in
      // the tx's account keys and survives the watch-list filter.
      keys: [
        { pubkey: owner, isSigner: true, isWritable: true },
        { pubkey: tokenAcct, isSigner: false, isWritable: true },
      ],
      data: Buffer.from([1]),
    },
  ]);
  const mockConnection = {
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map((_, i) =>
        i === 0
          ? { lamports: 1_000_000_000, data: Buffer.alloc(0), owner: "" }
          : { lamports: 2_039_280, data: tokenAccountData(mint, 5_000_000n), owner: "" },
      );
    },
    async simulateTransaction() {
      // Owner native goes UP (reclaimed rent); token account is closed => null.
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts: [
        { lamports: 1_002_039_280, data: ["", "base64"], owner: "" },
        null,
      ] } };
    },
  };
  const res = await guard(tx, {
    policy: {
      ownerPubkey: owner.toBase58(),
      programAllowlist: [drainProgram.toBase58()],
      maxTokenOutByMint: { [mint.toBase58()]: "1000" },
    },
    connection: mockConnection as never,
    ownedTokenAccounts: [tokenAcct],
  });
  assert.equal(res.simulation!.ownerTokenDeltas[mint.toBase58()], -5_000_000n, "closed account = full token outflow");
  assert.equal(res.verdict, "BLOCK");
  assert.ok(res.findings.find((f) => f.code === "POLICY_TOKEN_CAP_EXCEEDED"));
});

test("regression: a connection without getMultipleAccountsInfo warns that diffing was skipped", async () => {
  const owner = key();
  const tx = v0Tx(owner, [ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 })]);
  const minimalConnection = {
    async simulateTransaction() {
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts: [null] } };
    },
  };
  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58() },
    connection: minimalConnection as never,
  });
  assert.ok(res.findings.find((f) => f.code === "SIM_PRESTATE_UNAVAILABLE" && f.severity === "warn"));
  assert.notEqual(res.verdict, "SAFE", "must not claim SAFE when balances were never diffed");
});

test("regression: simulated flag is false when the RPC call throws", async () => {
  const owner = key();
  const to = key();
  const tx = v0Tx(owner, [SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 1 })]);
  const throwingConnection = {
    async getMultipleAccountsInfo() {
      return [null];
    },
    async simulateTransaction() {
      throw new Error("ECONNREFUSED");
    },
  };
  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58() },
    connection: throwingConnection as never,
  });
  assert.equal(res.simulated, false, "simulated must reflect that the RPC call never executed");
  assert.ok(res.findings.find((f) => f.code === "SIMULATION_FAILED"));
});

test("regression: findings gathered before a thrown simulateTransaction are preserved", async () => {
  // The catch branch must PREPEND the watch/pre-state findings it already
  // gathered, not discard them for SIMULATION_FAILED alone. An ALT tx whose
  // watch list overflows produces a warn SIM_WATCH_FILTERED before the RPC call;
  // if the call then throws, that fail-closed warn must survive.
  const owner = key();
  const victimAta = key();
  const evilProgram = key();
  const decoys = [key(), key()];
  const ix = new TransactionInstruction({
    programId: evilProgram,
    keys: [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: victimAta, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([0]),
  });
  const tx = v0TxWithLookupTable(owner, [ix], [victimAta]);
  const budget =
    tx.message.staticAccountKeys.length +
    tx.message.addressTableLookups.reduce((n, l) => n + l.writableIndexes.length + l.readonlyIndexes.length, 0);
  assert.ok(1 + 3 > budget, `precondition: 4 candidates must exceed the budget of ${budget}`);

  const throwingConnection = {
    async getTokenAccountsByOwner() {
      return { value: [...decoys, victimAta].map((pubkey) => ({ pubkey, account: {} })) };
    },
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map(() => ({ lamports: 2_039_280, data: Buffer.alloc(0), owner: "" }));
    },
    async simulateTransaction() {
      throw new Error("ECONNREFUSED");
    },
  };
  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58(), programAllowlist: [evilProgram.toBase58()] },
    connection: throwingConnection as never,
    ownedTokenAccounts: "auto",
  });
  const filtered = res.findings.find((f) => f.code === "SIM_WATCH_FILTERED");
  assert.equal(filtered!.severity, "warn", "the fail-closed truncation warn must survive the thrown RPC call");
  assert.ok(res.findings.find((f) => f.code === "SIMULATION_FAILED"));
  assert.notEqual(res.verdict, "SAFE", "a truncated ALT watch list must never verdict SAFE, even when the RPC throws");
});

test("regression: SIM_NATIVE_OUTFLOW is not downgraded without a recipient allowlist", async () => {
  const owner = key();
  const dexProgram = key();
  const tx = v0Tx(owner, [
    { programId: dexProgram, keys: [{ pubkey: owner, isSigner: true, isWritable: true }], data: Buffer.from([7]) },
  ]);
  const mockConnection = {
    async getMultipleAccountsInfo() {
      return [{ lamports: 2_000_000_000, data: Buffer.alloc(0), owner: "" }];
    },
    async simulateTransaction() {
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts: [{ lamports: 1_500_000_000, data: ["", "base64"], owner: "" }] } };
    },
  };
  const res = await guard(tx, {
    policy: {
      ownerPubkey: owner.toBase58(),
      maxLamportsOut: 1_000_000_000, // 0.5 SOL outflow is under the cap
      programAllowlist: [dexProgram.toBase58()],
      allowCompliantTransfers: true,
    },
    connection: mockConnection as never,
  });
  const f = res.findings.find((x) => x.code === "SIM_NATIVE_OUTFLOW");
  assert.equal(f!.severity, "warn", "a simulated outflow to an unrestricted recipient must stay WARN");
  assert.equal(res.verdict, "WARN");
});

// --- Regression tests for the fix re-review findings ---

test("regression: the watch list is capped at the tx's account count (never rejected)", async () => {
  // Agave caps accounts.addresses at the tx's total account count; auto-discovery
  // of a wallet with many token accounts must not blow past that and fail the call.
  const owner = key();
  const source = key();
  const dest = key();
  const unrelated = [key(), key(), key(), key()]; // 4 extra accounts not in this tx
  const tx = v0Tx(owner, [tokenTransfer(10n, source, dest, owner)]);
  const txAccountCount = tx.message.staticAccountKeys.length; // no ALT => this is the cap

  let requestedCount = -1;
  const mockConnection = {
    async getTokenAccountsByOwner() {
      // A wallet with many token accounts; only `source` is used by this tx.
      return { value: [source, ...unrelated].map((pubkey) => ({ pubkey, account: {} })) };
    },
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map((_, i) =>
        i === 0
          ? { lamports: 1_000_000_000, data: Buffer.alloc(0), owner: "" }
          : { lamports: 2_039_280, data: tokenAccountData(dest, 1000n), owner: "" },
      );
    },
    async simulateTransaction(_tx: unknown, cfg: { accounts: { addresses: string[] } }) {
      requestedCount = cfg.accounts.addresses.length;
      const accounts = cfg.accounts.addresses.map((_, i) =>
        i === 0 ? { lamports: 1_000_000_000, data: ["", "base64"], owner: "" } : null,
      );
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts } };
    },
  };
  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58() },
    connection: mockConnection as never,
    ownedTokenAccounts: "auto",
  });
  assert.equal(res.simulated, true, "simulation must actually run");
  assert.ok(
    requestedCount <= txAccountCount,
    `requested ${requestedCount} addresses, must not exceed the tx's account count ${txAccountCount}`,
  );
  // 1 owner + 5 discovered = 6 candidates > cap of 4, and `source` (a static
  // key) must be prioritized into the watch list.
  assert.ok(res.simulation!.diffedTokenAccounts.includes(source.toBase58()), "the in-tx source must be watched");
  // No ALTs: the 4 unrelated accounts provably cannot be touched by this tx, so
  // dropping them is safe — an INFO note, not a fail-closed truncation.
  const filtered = res.findings.find((x) => x.code === "SIM_WATCH_FILTERED");
  assert.equal(filtered!.severity, "info", "provably-irrelevant drops must not fail closed");
  assert.equal(filtered!.data!.potentiallyReferenced, false);
  assert.equal(res.simulation!.watchTruncated, false, "nothing the tx can modify was dropped");
});

test("regression: ALT tx whose account limit drops watched accounts can never verdict SAFE", async () => {
  // The round-4 HIGH: the victim's ATA is referenced through an address lookup
  // table, and "auto" discovery on a wallet with many token accounts pushes it
  // past the account limit — the drain happens in an account we never diffed.
  // With an allowlisted program, no caps, and allowCompliantTransfers, the old
  // behavior (info + no policy escalation without a token cap) verdicted SAFE.
  const owner = key();
  const victimAta = key();
  const mint = key();
  const evilProgram = key();
  const decoys = [key(), key()]; // discovered before the victim, eat the budget
  const ix = new TransactionInstruction({
    programId: evilProgram,
    keys: [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: victimAta, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([0]),
  });
  const tx = v0TxWithLookupTable(owner, [ix], [victimAta]); // victim is ALT-loaded
  assert.ok(
    !tx.message.staticAccountKeys.some((k) => k.equals(victimAta)),
    "precondition: victimAta must be ALT-resolved, not a static key",
  );
  // Budget = static keys + ALT-loaded count; discovery returns 3 accounts, so
  // at least one watched account must be dropped.
  const budget =
    tx.message.staticAccountKeys.length +
    tx.message.addressTableLookups.reduce((n, l) => n + l.writableIndexes.length + l.readonlyIndexes.length, 0);
  assert.ok(1 + 3 > budget, `precondition: 4 candidates must exceed the budget of ${budget}`);

  const mockConnection = {
    async getTokenAccountsByOwner() {
      // Victim discovered LAST — the arbitrary-order worst case.
      return { value: [...decoys, victimAta].map((pubkey) => ({ pubkey, account: {} })) };
    },
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map((a) =>
        a.equals(owner)
          ? { lamports: 1_000_000_000, data: Buffer.alloc(0), owner: "" }
          : { lamports: 2_039_280, data: tokenAccountData(mint, 5_000_000n), owner: "" },
      );
    },
    async simulateTransaction(_tx: unknown, cfg: { accounts: { addresses: string[] } }) {
      // The drain hits victimAta, but if it was dropped from the watch list the
      // returned accounts show nothing moving — that's the whole attack.
      const accounts = cfg.accounts.addresses.map((addr) =>
        addr === owner.toBase58()
          ? { lamports: 1_000_000_000, data: ["", "base64"], owner: "" }
          : { lamports: 2_039_280, data: [tokenAccountData(mint, 5_000_000n).toString("base64"), "base64"], owner: "" },
      );
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts } };
    },
  };
  const res = await guard(tx, {
    policy: {
      ownerPubkey: owner.toBase58(),
      programAllowlist: [evilProgram.toBase58()],
      allowCompliantTransfers: true, // no caps, no allowlist — worst-case lax policy
    },
    connection: mockConnection as never,
    ownedTokenAccounts: "auto",
  });
  assert.equal(res.simulation!.watchTruncated, true, "dropping a possibly-ALT-loaded account is a real truncation");
  const filtered = res.findings.find((x) => x.code === "SIM_WATCH_FILTERED");
  assert.equal(filtered!.severity, "warn", "truncation on an ALT tx must fail closed");
  assert.notEqual(res.verdict, "SAFE", "an unverified diff hole must never verdict SAFE");
});

test("regression: no-ALT tx with extra watched accounts still reaches SAFE when compliant", async () => {
  // Fail-closed must not become fail-always: on a tx WITHOUT lookup tables, a
  // wallet full of unrelated token accounts (all provably untouchable) must not
  // stop a fully policy-compliant transfer from verdicting SAFE.
  const owner = key();
  const to = key();
  const unrelated = [key(), key(), key(), key(), key()];
  const tx = v0Tx(owner, [SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 100_000 })]);
  const mockConnection = {
    async getTokenAccountsByOwner() {
      return { value: unrelated.map((pubkey) => ({ pubkey, account: {} })) };
    },
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map(() => ({ lamports: 1_000_000_000, data: Buffer.alloc(0), owner: "" }));
    },
    async simulateTransaction(_tx: unknown, cfg: { accounts: { addresses: string[] } }) {
      const accounts = cfg.accounts.addresses.map((addr) =>
        addr === owner.toBase58()
          ? { lamports: 1_000_000_000 - 100_000 - 5_000, data: ["", "base64"], owner: "" }
          : { lamports: 1_000_000_000, data: ["", "base64"], owner: "" },
      );
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts } };
    },
  };
  const res = await guard(tx, {
    policy: {
      ownerPubkey: owner.toBase58(),
      maxLamportsOut: 200_000,
      recipientAllowlist: [to.toBase58()],
      allowCompliantTransfers: true,
    },
    connection: mockConnection as never,
    ownedTokenAccounts: "auto",
  });
  assert.equal(res.simulation!.watchTruncated, false);
  assert.equal(res.verdict, "SAFE", "provably-irrelevant filtering must not block a compliant tx");
});

test("regression: an owner misconfigured as a token account still has its balance diffed", async () => {
  // ownerPubkey should be a wallet, but if a caller passes a token account as both
  // owner and watched account, dedupe must not silently drop the token diff.
  const ata = key();
  const dest = key();
  const mint = key();
  const tx = v0Tx(ata, [tokenTransfer(1_000_000n, ata, dest, ata)]);
  const mockConnection = {
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map(() => ({ lamports: 2_039_280, data: tokenAccountData(mint, 1_000_000n), owner: "" }));
    },
    async simulateTransaction() {
      // ATA emptied to 0 (transferred out), account not closed.
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts: [
        { lamports: 2_039_280, data: [tokenAccountData(mint, 0n).toString("base64"), "base64"], owner: "" },
      ] } };
    },
  };
  const res = await guard(tx, {
    policy: { ownerPubkey: ata.toBase58(), maxTokenOutByMint: { [mint.toBase58()]: "1000" } },
    connection: mockConnection as never,
    ownedTokenAccounts: [ata],
  });
  assert.equal(res.simulation!.ownerTokenDeltas[mint.toBase58()], -1_000_000n, "misconfigured owner token account must still diff");
  assert.equal(res.verdict, "BLOCK");
  assert.ok(res.findings.find((x) => x.code === "POLICY_TOKEN_CAP_EXCEEDED"));
});

test("regression: an unrelated mint inflow does not suppress the unverifiable-cap warning", async () => {
  // A benign inflow of mint A must not be treated as proof that an unchecked
  // outflow of mint B was observed.
  const owner = key();
  const sourceB = key();
  const destB = key();
  const usdcAta = key();
  const usdcMint = key();
  const bonkMint = key();
  const tx = v0Tx(owner, [tokenTransfer(5_000_000n, sourceB, destB, owner)]); // unchecked, no mint

  const mockConnection = {
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map((_, i) =>
        i === 0
          ? { lamports: 1_000_000_000, data: Buffer.alloc(0), owner: "" }
          : { lamports: 2_039_280, data: tokenAccountData(usdcMint, 1000n), owner: "" },
      );
    },
    async simulateTransaction() {
      // Only the watched USDC account moves — and it INCREASES (inflow).
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts: [
        { lamports: 1_000_000_000, data: ["", "base64"], owner: "" },
        { lamports: 2_039_280, data: [tokenAccountData(usdcMint, 1250n).toString("base64"), "base64"], owner: "" },
      ] } };
    },
  };
  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58(), maxTokenOutByMint: { [bonkMint.toBase58()]: "1000000" } },
    connection: mockConnection as never,
    ownedTokenAccounts: [usdcAta],
  });
  assert.ok(
    res.findings.find((x) => x.code === "POLICY_TOKEN_CAP_UNVERIFIABLE"),
    "an unrelated inflow must not vouch for an unobserved unchecked outflow",
  );
});

test("regression: an ALT-referenced ATA drained via an allowlisted CPI is still caught", async () => {
  // A drainer routes the victim's ATA through an address lookup table so it isn't
  // a static key. It's still loaded by the tx, so it must still be diffed.
  const owner = key();
  const usdcAta = key();
  const mint = key();
  const evilProgram = key();
  const ix = new TransactionInstruction({
    programId: evilProgram,
    keys: [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: usdcAta, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([0]),
  });
  const tx = v0TxWithLookupTable(owner, [ix], [usdcAta]); // usdcAta lives in the ALT
  assert.ok(
    !tx.message.staticAccountKeys.some((k) => k.equals(usdcAta)),
    "precondition: usdcAta must be ALT-resolved, not a static key",
  );

  const mockConnection = {
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map((a) =>
        a.equals(owner)
          ? { lamports: 1_000_000_000, data: Buffer.alloc(0), owner: "" }
          : { lamports: 2_039_280, data: tokenAccountData(mint, 5_000_000n), owner: "" },
      );
    },
    async simulateTransaction(_tx: unknown, cfg: { accounts: { addresses: string[] } }) {
      const accounts = cfg.accounts.addresses.map((addr) =>
        addr === owner.toBase58()
          ? { lamports: 1_000_000_000, data: ["", "base64"], owner: "" }
          : { lamports: 2_039_280, data: [tokenAccountData(mint, 0n).toString("base64"), "base64"], owner: "" },
      );
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts } };
    },
  };
  const res = await guard(tx, {
    policy: {
      ownerPubkey: owner.toBase58(),
      programAllowlist: [evilProgram.toBase58()],
      maxTokenOutByMint: { [mint.toBase58()]: "1000000" },
    },
    connection: mockConnection as never,
    ownedTokenAccounts: [usdcAta],
  });
  assert.equal(res.simulation!.ownerTokenDeltas[mint.toBase58()], -5_000_000n, "ALT-referenced ATA must be diffed");
  assert.equal(res.verdict, "BLOCK", "a full ALT-hidden drain must BLOCK, not pass SAFE");
  assert.ok(res.findings.find((f) => f.code === "POLICY_TOKEN_CAP_EXCEEDED"));
});

test("regression: unrelated mint OUTFLOW does not vouch for an unwatched unchecked drain", async () => {
  // Per-source check: an observed outflow of mint A must not suppress the
  // unverifiable warning for an unchecked drain of mint B whose source is unwatched.
  const owner = key();
  const ataA = key();
  const mintA = key();
  const destA = key();
  const sourceB = key(); // mint-B source, NOT watched
  const destB = key();
  const tx = legacyTx(owner, [
    tokenTransferChecked(10n, 6, ataA, mintA, destA, owner), // observed mint-A outflow
    tokenTransfer(5_000_000n, sourceB, destB, owner), // unchecked mint-B drain, unwatched
  ]);
  const mockConnection = {
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map((a) =>
        a.equals(owner)
          ? { lamports: 1_000_000_000, data: Buffer.alloc(0), owner: "" }
          : { lamports: 2_039_280, data: tokenAccountData(mintA, 100n), owner: "" },
      );
    },
    async simulateTransaction(_tx: unknown, cfg: { accounts: { addresses: string[] } }) {
      const accounts = cfg.accounts.addresses.map((addr) =>
        addr === owner.toBase58()
          ? { lamports: 1_000_000_000, data: ["", "base64"], owner: "" }
          : { lamports: 2_039_280, data: [tokenAccountData(mintA, 90n).toString("base64"), "base64"], owner: "" },
      );
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts } };
    },
  };
  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58(), maxTokenOutByMint: { [key().toBase58()]: "1000" } },
    connection: mockConnection as never,
    ownedTokenAccounts: [ataA], // only mint-A watched; mint-B source is not
  });
  assert.equal(res.simulation!.ownerTokenDeltas[mintA.toBase58()], -10n, "mint-A outflow is observed");
  assert.ok(
    res.findings.find((f) => f.code === "POLICY_TOKEN_CAP_UNVERIFIABLE"),
    "the unwatched unchecked mint-B drain must still be flagged unverifiable",
  );
});

// --- Regression tests for the full-pass (round 6) findings ---

test("regression: an ALT-masked mint cannot bypass a per-mint token cap (offline stays out of SAFE)", async () => {
  // A TransferChecked whose ONLY ALT-routed account is the mint resolves offline
  // to mint = UNRESOLVED, while source/dest/owner stay static. That must not
  // defeat maxTokenOutByMint: the cap can't be matched, so it fails closed.
  const owner = key();
  const source = key(); // owner's USDC ATA (static)
  const dest = key(); // allowlisted counterparty ATA (static)
  const mint = key(); // USDC — routed through the ALT
  const ix = tokenTransferChecked(1_000_000_000n, 6, source, mint, dest, owner);
  const tx = v0TxWithLookupTable(owner, [ix], [mint]);
  assert.ok(!tx.message.staticAccountKeys.some((k) => k.equals(mint)), "precondition: mint must be ALT-resolved");
  assert.ok(tx.message.staticAccountKeys.some((k) => k.equals(source)), "precondition: source must stay static");

  const res = await guard(tx, {
    policy: {
      ownerPubkey: owner.toBase58(),
      maxTokenOutByMint: { [mint.toBase58()]: "100000000" }, // 100 USDC
      recipientAllowlist: [dest.toBase58()],
      allowCompliantTransfers: true,
    },
  });
  assert.notEqual(res.verdict, "SAFE", "an ALT-masked mint must not defeat the per-mint cap");
  assert.ok(res.findings.find((f) => f.code === "POLICY_TOKEN_CAP_UNVERIFIABLE"));
  const tt = res.findings.find((f) => f.code === "TOKEN_TRANSFER");
  assert.notEqual(tt!.severity, "info", "an unverifiable-mint transfer must not be downgraded to info");
});

test("regression: simulation still catches an ALT-masked-mint drain via the source token account", async () => {
  const owner = key();
  const source = key();
  const dest = key();
  const mint = key();
  const ix = tokenTransferChecked(1_000_000_000n, 6, source, mint, dest, owner);
  const tx = v0TxWithLookupTable(owner, [ix], [mint]);
  const mockConnection = {
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map((a) =>
        a.equals(owner)
          ? { lamports: 1_000_000_000, data: Buffer.alloc(0), owner: "" }
          : { lamports: 2_039_280, data: tokenAccountData(mint, 1_000_000_000n), owner: "" },
      );
    },
    async simulateTransaction(_tx: unknown, cfg: { accounts: { addresses: string[] } }) {
      const accounts = cfg.accounts.addresses.map((addr) =>
        addr === owner.toBase58()
          ? { lamports: 1_000_000_000, data: ["", "base64"], owner: "" }
          : { lamports: 2_039_280, data: [tokenAccountData(mint, 0n).toString("base64"), "base64"], owner: "" },
      );
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts } };
    },
  };
  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58(), maxTokenOutByMint: { [mint.toBase58()]: "100000000" } },
    connection: mockConnection as never,
    ownedTokenAccounts: [source],
  });
  assert.equal(res.simulation!.ownerTokenDeltas[mint.toBase58()], -1_000_000_000n, "sim diffs the real mint from account state");
  assert.equal(res.verdict, "BLOCK");
  assert.ok(res.findings.find((f) => f.code === "POLICY_TOKEN_CAP_EXCEEDED"));
});

test("regression: System AllocateWithSeed (allocate_and_assign) is caught as an ownership handover", async () => {
  const owner = key(); // the base / signer
  const derived = key(); // stand-in for createWithSeed(owner, seed, System)
  const evilProgram = key();
  const ix = SystemProgram.allocate({
    accountPubkey: derived,
    basePubkey: owner,
    seed: "drain",
    space: 0,
    programId: evilProgram,
  });
  const tx = legacyTx(owner, [ix]);
  const res = await guard(tx, { policy: { ownerPubkey: owner.toBase58() } });
  const f = res.findings.find((x) => x.code === "SYSTEM_ASSIGN");
  assert.ok(f, "AllocateWithSeed must produce a SYSTEM_ASSIGN finding");
  assert.equal(f!.severity, "critical");
  assert.equal(f!.data!.newProgramOwner, evilProgram.toBase58(), "must decode the embedded new program owner");
  assert.equal(res.verdict, "BLOCK");
});

test("regression: TransferWithSeed from a base==owner account counts as an owner outflow", async () => {
  const owner = key(); // base / signer
  const fromDerived = key(); // create-with-seed account controlled by owner
  const attacker = key();
  const ix = SystemProgram.transfer({
    fromPubkey: fromDerived,
    basePubkey: owner,
    toPubkey: attacker,
    lamports: 5_000_000_000,
    seed: "vault",
    programId: SystemProgram.programId,
  });
  const tx = legacyTx(owner, [ix]);
  const res = await guard(tx, { policy: { ownerPubkey: owner.toBase58(), maxLamportsOut: 1_000_000_000 } });
  assert.equal(res.summary.staticLamportsOut, 5_000_000_000, "the base-controlled outflow must be counted");
  assert.equal(res.verdict, "BLOCK");
  assert.ok(res.findings.find((f) => f.code === "POLICY_CAP_EXCEEDED"));
});

test("regression: a CPI-hidden native outflow to a non-allowlisted recipient stays out of SAFE", async () => {
  // Simulation reveals only the net lamport delta, never the recipient. A
  // within-cap CPI drain to a NON-allowlisted address must not verdict SAFE just
  // because a recipientAllowlist happens to be configured.
  const owner = key();
  const treasury = key();
  const dexProgram = key();
  const ix = new TransactionInstruction({
    programId: dexProgram,
    keys: [{ pubkey: owner, isSigner: true, isWritable: true }],
    data: Buffer.from([7]),
  });
  const tx = v0Tx(owner, [ix]);
  const mockConnection = {
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map(() => ({ lamports: 1_000_000_000, data: Buffer.alloc(0), owner: "" }));
    },
    async simulateTransaction(_tx: unknown, cfg: { accounts: { addresses: string[] } }) {
      const accounts = cfg.accounts.addresses.map((addr) =>
        addr === owner.toBase58()
          ? { lamports: 900_000_000, data: ["", "base64"], owner: "" } // 0.1 SOL left via the CPI
          : { lamports: 1_000_000_000, data: ["", "base64"], owner: "" },
      );
      return { value: { err: null, logs: [], unitsConsumed: 1, accounts } };
    },
  };
  const res = await guard(tx, {
    policy: {
      ownerPubkey: owner.toBase58(),
      maxLamportsOut: 250_000_000, // 0.25 SOL cap; the 0.1 SOL outflow is under it
      recipientAllowlist: [treasury.toBase58()],
      programAllowlist: [dexProgram.toBase58()],
      allowCompliantTransfers: true,
    },
    connection: mockConnection as never,
  });
  assert.notEqual(res.verdict, "SAFE", "an unattributable CPI outflow must not verdict SAFE under a recipient allowlist");
  assert.ok(res.findings.find((f) => f.code === "POLICY_RECIPIENT_UNVERIFIABLE"));
});

test("end-to-end: simulation error is surfaced as a warning", async () => {
  const owner = key();
  const to = key();
  const tx = v0Tx(owner, [SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 1 })]);

  const mockConnection = {
    async getMultipleAccountsInfo(addrs: PublicKey[]) {
      return addrs.map(() => null);
    },
    async simulateTransaction() {
      return { value: { err: { InstructionError: [0, "Custom"] }, logs: [], unitsConsumed: 0, accounts: [null, null] } };
    },
  };

  const res = await guard(tx, {
    policy: { ownerPubkey: owner.toBase58() },
    connection: mockConnection as never,
  });
  assert.equal(res.simulated, true);
  assert.ok(res.findings.find((f) => f.code === "SIMULATION_ERROR"));
});
