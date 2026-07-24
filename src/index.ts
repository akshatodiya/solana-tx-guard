/**
 * solana-tx-guard — pre-sign transaction safety guardrails for AI agents.
 *
 * Public API. The one function an agent needs is {@link guard}: hand it a
 * transaction (and optionally a policy + RPC connection) BEFORE signing, and it
 * returns a SAFE / WARN / BLOCK verdict with explained findings.
 *
 * @example
 * ```ts
 * import { guard } from "solana-tx-guard";
 *
 * const result = await guard(tx, {
 *   connection,
 *   policy: {
 *     ownerPubkey: wallet.publicKey.toBase58(),
 *     maxLamportsOut: 0.5 * 1e9,
 *     recipientAllowlist: [treasury.toBase58()],
 *   },
 * });
 * if (result.verdict === "BLOCK") throw new Error("tx-guard blocked: " + result.findings[0]?.message);
 * if (result.verdict === "SAFE") await wallet.signAndSend(tx);
 * ```
 */

import {
  Connection,
  PublicKey,
  Transaction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import type { Finding, GuardResult, Policy, SimulationResult } from "./types.js";
import { analyzeStatic } from "./analyzer.js";
import { applyPolicy, finalizeFindings } from "./policy.js";
import {
  discoverOwnerTokenAccounts,
  simulateAndDiff,
  type SimulatorConnection,
} from "./simulate.js";
import { sortFindings, verdictFromFindings } from "./verdict.js";

export type {
  Finding,
  GuardResult,
  Policy,
  Severity,
  Verdict,
  SimulationResult,
} from "./types.js";
export { analyzeStatic, normalize } from "./analyzer.js";
export { applyPolicy, finalizeFindings } from "./policy.js";
export { discoverOwnerTokenAccounts, simulateAndDiff } from "./simulate.js";
export { verdictFromFindings } from "./verdict.js";
export {
  decodeComputeBudget,
  decodeInstruction,
  KNOWN_SAFE_PROGRAMS,
  SYSTEM_PROGRAM,
  TOKEN_PROGRAM,
  TOKEN_2022_PROGRAM,
} from "./programs.js";

export interface GuardOptions {
  policy?: Policy;
  /** RPC connection. When provided, the transaction is also simulated. */
  connection?: Connection | SimulatorConnection;
  /**
   * Owner token accounts to watch during simulation (base58 or PublicKey). The
   * owner's native account is always watched. Pass `"auto"` to discover all of
   * the owner's token accounts via the RPC (legacy Token + Token-2022) — the
   * safest option, at the cost of two extra RPC calls.
   */
  ownedTokenAccounts?: (string | PublicKey)[] | "auto";
}

/**
 * Inspect a transaction and return a verdict. Runs static analysis always, and
 * RPC simulation when a connection is supplied. Never signs or sends anything.
 */
export async function guard(
  tx: Transaction | VersionedTransaction,
  options: GuardOptions = {},
): Promise<GuardResult> {
  const { policy = {}, connection, ownedTokenAccounts = [] } = options;

  let owner: PublicKey | undefined;
  if (policy.ownerPubkey !== undefined) {
    try {
      owner = new PublicKey(policy.ownerPubkey);
    } catch {
      throw new Error(`policy.ownerPubkey is not a valid base58 pubkey: ${policy.ownerPubkey}`);
    }
  }

  const analysis = analyzeStatic(tx, policy.ownerPubkey);
  const findings: Finding[] = [...analysis.findings];

  let simulation: SimulationResult | undefined;
  let simulated = false;

  if (connection && owner) {
    const versioned = toVersioned(tx, owner);
    if (versioned) {
      let tokenAccts: PublicKey[];
      if (ownedTokenAccounts === "auto") {
        const discovered = await discoverOwnerTokenAccounts(connection, owner);
        tokenAccts = discovered ?? [];
        if (discovered === null) {
          findings.push({
            code: "TOKEN_ACCOUNTS_AUTO_UNAVAILABLE",
            severity: "info",
            message:
              "ownedTokenAccounts: \"auto\" requires a connection with getTokenAccountsByOwner; no token accounts are being watched.",
          });
        }
      } else {
        tokenAccts = ownedTokenAccounts.map((a) =>
          a instanceof PublicKey ? a : new PublicKey(a),
        );
      }
      const { result, findings: simFindings } = await simulateAndDiff(
        connection,
        versioned,
        owner,
        tokenAccts,
        { feeLamportsTolerance: policy.feeLamportsTolerance },
      );
      simulation = result;
      simulated = result.ran; // false when the RPC call itself threw
      findings.push(...simFindings);
    } else {
      findings.push({
        code: "SIM_SKIPPED_LEGACY_UNSIGNED",
        severity: "info",
        message:
          "Legacy transaction could not be converted for simulation. Static analysis still applied.",
      });
    }
  } else if (connection && !owner) {
    findings.push({
      code: "SIM_SKIPPED_NO_OWNER",
      severity: "info",
      message: "Simulation skipped: set policy.ownerPubkey so balance changes can be attributed to the owner.",
    });
  }

  // Policy runs last so it can see simulation results (e.g. cap vs simulated outflow).
  findings.push(...applyPolicy(analysis, policy, simulation));

  const ordered = sortFindings(finalizeFindings(findings, policy));
  return {
    verdict: verdictFromFindings(ordered),
    findings: ordered,
    simulated,
    simulation,
    summary: {
      programsInvoked: analysis.programsInvoked,
      staticLamportsOut: analysis.staticLamportsOut,
      worstCasePriorityFeeLamports: analysis.worstCasePriorityFeeLamports,
      instructionCount: analysis.instructions.length,
      usesLookupTables: analysis.usesLookupTables,
    },
  };
}

/** Placeholder blockhash for simulating with `replaceRecentBlockhash: true`. */
const PLACEHOLDER_BLOCKHASH = "11111111111111111111111111111111";

/**
 * Best-effort conversion to VersionedTransaction for simulation. Legacy
 * transactions without a blockhash / fee payer are compiled with a placeholder
 * blockhash (the RPC replaces it) and the owner as fee payer, without mutating
 * the caller's transaction.
 */
function toVersioned(
  tx: Transaction | VersionedTransaction,
  owner: PublicKey,
): VersionedTransaction | null {
  if (tx instanceof VersionedTransaction) return tx;
  try {
    const message = new TransactionMessage({
      payerKey: tx.feePayer ?? owner,
      recentBlockhash: tx.recentBlockhash ?? PLACEHOLDER_BLOCKHASH,
      instructions: tx.instructions,
    }).compileToV0Message();
    return new VersionedTransaction(message);
  } catch {
    return null;
  }
}
