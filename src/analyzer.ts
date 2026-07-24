/**
 * Static (offline) transaction analysis.
 *
 * Normalizes a legacy `Transaction` or a `VersionedTransaction` into a flat list
 * of instructions with resolved account addresses, decodes the asset-affecting
 * ones, and emits base {@link Finding}s plus a summary. No RPC is used here, so
 * this works fully offline and is the part that catches a malicious instruction
 * before it is ever sent to a node.
 */

import { Transaction, VersionedTransaction } from "@solana/web3.js";
import type { Finding } from "./types.js";
import {
  decodeComputeBudget,
  decodeInstruction,
  COMPUTE_BUDGET_PROGRAM,
  KNOWN_SAFE_PROGRAMS,
  type DecodedAction,
  type NormalizedInstruction,
} from "./programs.js";

/** Placeholder address for an account that lives in an address lookup table and can't be resolved offline. */
export const UNRESOLVED = "__unresolved__";

/** Runtime default CU limit: 200k per top-level instruction, capped at 1.4M. */
const DEFAULT_CU_PER_IX = 200_000;
const MAX_CU_LIMIT = 1_400_000;
/** Worst-case priority fee above this (0.01 SOL) gets flagged even without a policy. */
const SUSPICIOUS_FEE_LAMPORTS = 10_000_000;

export interface StaticAnalysis {
  instructions: NormalizedInstruction[];
  actions: { ix: number; action: DecodedAction }[];
  findings: Finding[];
  programsInvoked: string[];
  staticLamportsOut: number;
  /** Worst-case priority fee (lamports) implied by compute-budget instructions. */
  worstCasePriorityFeeLamports: number;
  usesLookupTables: boolean;
}

/** Normalize either transaction kind into a flat instruction list with base58 accounts. */
export function normalize(tx: Transaction | VersionedTransaction): {
  instructions: NormalizedInstruction[];
  usesLookupTables: boolean;
} {
  if (tx instanceof VersionedTransaction) {
    const msg = tx.message;
    const staticKeys = msg.staticAccountKeys.map((k) => k.toBase58());
    const lookups = "addressTableLookups" in msg ? msg.addressTableLookups : [];
    const resolve = (i: number): string => staticKeys[i] ?? UNRESOLVED;
    const instructions = msg.compiledInstructions.map((ci) => ({
      programId: resolve(ci.programIdIndex),
      accounts: Array.from(ci.accountKeyIndexes, resolve),
      data: Uint8Array.from(ci.data),
    }));
    return { instructions, usesLookupTables: lookups.length > 0 };
  }

  // Legacy web3.js Transaction: all keys are inline, nothing to look up.
  const instructions = tx.instructions.map((ix) => ({
    programId: ix.programId.toBase58(),
    accounts: ix.keys.map((k) => k.pubkey.toBase58()),
    data: Uint8Array.from(ix.data),
  }));
  return { instructions, usesLookupTables: false };
}

/**
 * Run static analysis. The owner pubkey (the agent's wallet) scopes severity:
 * actions that debit or hand over the owner's accounts are treated more harshly
 * than movements between third-party accounts.
 */
export function analyzeStatic(
  tx: Transaction | VersionedTransaction,
  ownerPubkey?: string,
): StaticAnalysis {
  const { instructions, usesLookupTables } = normalize(tx);
  const findings: Finding[] = [];
  const actions: { ix: number; action: DecodedAction }[] = [];
  const programsInvoked: string[] = [];
  let staticLamportsOut = 0n;
  let cuLimit: number | null = null;
  let cuPriceMicroLamports = 0n;
  let nonBudgetIxCount = 0;

  const ownsAccount = (addr?: string) => ownerPubkey !== undefined && addr === ownerPubkey;
  // Without an owner hint we cannot tell whose funds move, and an account
  // loaded from an unresolved lookup table COULD be the owner's — both cases
  // are treated conservatively as owner-affecting.
  const affectsOwner = (addr?: string) =>
    ownerPubkey === undefined || addr === UNRESOLVED || ownsAccount(addr);

  instructions.forEach((ix, i) => {
    if (!programsInvoked.includes(ix.programId)) programsInvoked.push(ix.programId);

    if (ix.programId === COMPUTE_BUDGET_PROGRAM) {
      const req = decodeComputeBudget(ix);
      if (req?.kind === "cu_limit") cuLimit = Math.max(cuLimit ?? 0, req.units);
      if (req?.kind === "cu_price" && req.microLamports > cuPriceMicroLamports) {
        cuPriceMicroLamports = req.microLamports;
      }
    } else {
      nonBudgetIxCount++;
    }

    // Flag programs we don't recognize: they could do anything via CPI.
    if (!KNOWN_SAFE_PROGRAMS.has(ix.programId) && ix.programId !== UNRESOLVED) {
      findings.push({
        code: "UNKNOWN_PROGRAM",
        severity: "warn",
        message: `Instruction ${i} invokes unverified program ${ix.programId}. It may move funds or change authorities in ways static analysis cannot see; rely on simulation and an allowlist.`,
        ix: i,
        data: { programId: ix.programId },
      });
    }
    if (ix.programId === UNRESOLVED) {
      findings.push({
        code: "UNRESOLVED_PROGRAM",
        severity: "warn",
        message: `Instruction ${i} calls a program loaded from an address lookup table that could not be resolved offline. Resolve lookup tables or simulate to inspect it.`,
        ix: i,
      });
    }

    const action = decodeInstruction(ix);
    if (!action) return;
    actions.push({ ix: i, action });

    switch (action.kind) {
      case "sol_transfer": {
        const lamports = action.amount ?? 0n;
        // TransferWithSeed debits a derived `source` controlled by `authority`
        // (the base signer); a plain Transfer has no authority and is scoped on
        // `source`. Either being the owner's makes this an owner outflow.
        const ownerOut = affectsOwner(action.source) || affectsOwner(action.authority);
        if (ownerOut) staticLamportsOut += lamports;
        findings.push({
          code: "SOL_TRANSFER",
          severity: ownerOut ? "warn" : "info",
          message: `Instruction ${i} transfers ${lamports} lamports from ${short(action.source)} to ${short(action.target)}.`,
          ix: i,
          data: { lamports: Number(lamports), source: action.source, target: action.target },
        });
        break;
      }
      case "sol_create_account": {
        const lamports = action.amount ?? 0n;
        if (affectsOwner(action.source)) staticLamportsOut += lamports;
        findings.push({
          code: "ACCOUNT_FUNDING",
          severity: affectsOwner(action.source) ? "warn" : "info",
          message: `Instruction ${i} creates account ${short(action.target)} funded with ${lamports} lamports from ${short(action.source)}. This moves SOL out just like a transfer.`,
          ix: i,
          data: { lamports: Number(lamports), source: action.source, target: action.target },
        });
        break;
      }
      case "nonce_withdraw": {
        const lamports = action.amount ?? 0n;
        if (affectsOwner(action.authority)) staticLamportsOut += lamports;
        findings.push({
          code: "NONCE_WITHDRAW",
          severity: affectsOwner(action.authority) ? "warn" : "info",
          message: `Instruction ${i} withdraws ${lamports} lamports from nonce account ${short(action.source)} to ${short(action.target)}.`,
          ix: i,
          data: { lamports: Number(lamports), nonceAccount: action.source, target: action.target, authority: action.authority },
        });
        break;
      }
      case "nonce_authorize": {
        findings.push({
          code: "NONCE_AUTHORIZE",
          severity: affectsOwner(action.authority) ? "critical" : "warn",
          message: `Instruction ${i} hands authority over nonce account ${short(action.source)} to ${short(action.target)}. The new authority can withdraw its lamports later.`,
          ix: i,
          data: { nonceAccount: action.source, newAuthority: action.target, authority: action.authority },
        });
        break;
      }
      case "token_transfer": {
        findings.push({
          code: "TOKEN_TRANSFER",
          severity: affectsOwner(action.authority) || affectsOwner(action.source) ? "warn" : "info",
          message: `Instruction ${i} transfers ${action.amount ?? 0n} token base units from ${short(action.source)} to ${short(action.target)} (authority ${short(action.authority)}).`,
          ix: i,
          data: {
            amount: String(action.amount ?? 0n),
            source: action.source,
            target: action.target,
            authority: action.authority,
            mint: action.mint,
          },
        });
        break;
      }
      case "token_approve": {
        findings.push({
          code: "TOKEN_DELEGATION",
          severity: affectsOwner(action.authority) ? "critical" : "warn",
          message: `Instruction ${i} delegates up to ${action.amount ?? 0n} token base units of ${short(action.source)} to ${short(action.target)}. A delegate can move these tokens later, outside this transaction.`,
          ix: i,
          data: {
            amount: String(action.amount ?? 0n),
            source: action.source,
            delegate: action.target,
            authority: action.authority,
          },
        });
        break;
      }
      case "token_set_authority": {
        findings.push({
          code: "AUTHORITY_CHANGE",
          severity: affectsOwner(action.authority) ? "critical" : "warn",
          message: `Instruction ${i} changes an authority on ${short(action.source)}${action.target ? ` to ${short(action.target)}` : " (authority removed)"}. This can hand control of a token account or mint to another party.`,
          ix: i,
          data: { account: action.source, newAuthority: action.target, currentAuthority: action.authority },
        });
        break;
      }
      case "token_close_account": {
        findings.push({
          code: "ACCOUNT_CLOSE",
          severity: affectsOwner(action.authority) ? "critical" : "warn",
          message: `Instruction ${i} closes token account ${short(action.source)} and sends its rent/remaining balance to ${short(action.target)}. Closing a wrapped-SOL account drains it.`,
          ix: i,
          data: { account: action.source, destination: action.target, authority: action.authority },
        });
        break;
      }
      case "token_burn": {
        findings.push({
          code: "TOKEN_BURN",
          severity: affectsOwner(action.authority) ? "warn" : "info",
          message: `Instruction ${i} burns ${action.amount ?? 0n} token base units from ${short(action.source)}.`,
          ix: i,
          data: { amount: String(action.amount ?? 0n), account: action.source },
        });
        break;
      }
      case "system_assign": {
        findings.push({
          code: "SYSTEM_ASSIGN",
          severity: affectsOwner(action.source) || affectsOwner(action.authority) ? "critical" : "warn",
          message: `Instruction ${i} reassigns program ownership of account ${short(action.source)}${action.target ? ` to program ${short(action.target)}` : ""}. This can place the account under a different program's control.`,
          ix: i,
          data: { account: action.source, newProgramOwner: action.target, authority: action.authority },
        });
        break;
      }
    }
  });

  // Worst-case priority fee: cuLimit × cuPrice. A drainer can set an absurd
  // compute-unit price and burn the fee payer's balance as priority fees.
  const effectiveCuLimit =
    cuLimit ?? Math.min(MAX_CU_LIMIT, DEFAULT_CU_PER_IX * Math.max(1, nonBudgetIxCount));
  const worstCasePriorityFeeLamports = Number(
    (BigInt(effectiveCuLimit) * cuPriceMicroLamports + 999_999n) / 1_000_000n,
  );
  if (worstCasePriorityFeeLamports > SUSPICIOUS_FEE_LAMPORTS) {
    findings.push({
      code: "HIGH_PRIORITY_FEE",
      severity: "warn",
      message: `Compute budget allows a priority fee of up to ${worstCasePriorityFeeLamports} lamports (cuLimit ${effectiveCuLimit} × ${cuPriceMicroLamports} µlamports). An inflated compute-unit price can drain the fee payer.`,
      data: {
        worstCaseFeeLamports: worstCasePriorityFeeLamports,
        cuLimit: effectiveCuLimit,
        cuPriceMicroLamports: String(cuPriceMicroLamports),
      },
    });
  }

  return {
    instructions,
    actions,
    findings,
    programsInvoked,
    staticLamportsOut: Number(staticLamportsOut),
    worstCasePriorityFeeLamports,
    usesLookupTables,
  };
}

function short(addr?: string): string {
  if (!addr) return "unknown";
  if (addr === UNRESOLVED) return "unresolved(ALT)";
  return addr.length > 12 ? `${addr.slice(0, 4)}…${addr.slice(-4)}` : addr;
}
