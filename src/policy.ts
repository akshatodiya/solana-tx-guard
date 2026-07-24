/**
 * Policy enforcement.
 *
 * Takes the static analysis (and, when available, the simulation) and applies
 * the caller's {@link Policy}: spending caps, recipient/program allowlists, and
 * whether delegations / authority changes / account closes are hard blocks.
 * Policy findings carry `critical` severity where the policy says "stop", which
 * the verdict step turns into a BLOCK.
 */

import type { Finding, Policy, SimulationResult } from "./types.js";
import { UNRESOLVED, type StaticAnalysis } from "./analyzer.js";
import { KNOWN_SAFE_PROGRAMS } from "./programs.js";
import { DEFAULT_FEE_TOLERANCE_LAMPORTS } from "./simulate.js";

const DEFAULTS = {
  allowUnverifiedPrograms: false,
  blockOnDelegation: true,
  blockOnAccountClose: true,
} as const;

/** Delegation-family kinds: they hand future control of assets to another party. */
const DELEGATION_KINDS = new Set(["token_approve", "token_set_authority", "system_assign", "nonce_authorize"]);

export function applyPolicy(
  analysis: StaticAnalysis,
  policy: Policy,
  simulation?: SimulationResult,
): Finding[] {
  const findings: Finding[] = [];
  const opts = { ...DEFAULTS, ...policy };
  const recipientAllow = policy.recipientAllowlist
    ? new Set(policy.recipientAllowlist)
    : null;
  const programAllow = new Set([
    ...KNOWN_SAFE_PROGRAMS,
    ...(policy.programAllowlist ?? []),
  ]);

  // 1. Unverified program policy: escalate or relax the analyzer's WARN.
  if (!opts.allowUnverifiedPrograms) {
    for (const program of analysis.programsInvoked) {
      if (!programAllow.has(program) && program !== "__unresolved__") {
        findings.push({
          code: "POLICY_UNVERIFIED_PROGRAM",
          severity: "critical",
          message: `Program ${program} is not in the allowlist and allowUnverifiedPrograms is false. Blocking. Add it to programAllowlist if you trust it.`,
          data: { programId: program },
        });
      }
    }
  }

  // 2. Spending cap on native SOL leaving the owner.
  if (policy.maxLamportsOut !== undefined) {
    const simOut =
      simulation && simulation.ownerLamportDelta !== null && simulation.ownerLamportDelta < 0
        ? -simulation.ownerLamportDelta
        : 0;
    const observed = Math.max(analysis.staticLamportsOut, simOut);
    if (observed > policy.maxLamportsOut) {
      findings.push({
        code: "POLICY_CAP_EXCEEDED",
        severity: "critical",
        message: `Transaction moves ${observed} lamports out of the owner account, over the cap of ${policy.maxLamportsOut}. Blocking.`,
        data: { observed, cap: policy.maxLamportsOut, source: simOut > analysis.staticLamportsOut ? "simulation" : "static" },
      });
    }
  }

  // 3. Per-mint token caps, against max(static known-mint amounts, simulated deltas).
  if (policy.maxTokenOutByMint) {
    // Same conservative owner-scoping as the analyzer: unknown owner or an
    // unresolved (ALT) authority counts as the owner's.
    const ownerish = (addr?: string) =>
      policy.ownerPubkey === undefined || addr === policy.ownerPubkey || addr === UNRESOLVED;
    const staticByMint = new Map<string, bigint>();
    for (const { action } of analysis.actions) {
      const spendsTokens =
        action.kind === "token_transfer" || action.kind === "token_approve" || action.kind === "token_burn";
      // Only a resolved mint can be attributed to a cap. An ALT-masked mint
      // decodes to UNRESOLVED — bucketing it under that marker would never match
      // a real per-mint cap, so skip it here and let the unverifiable check below
      // fail closed on it instead.
      if (spendsTokens && action.mint && action.mint !== UNRESOLVED && ownerish(action.authority)) {
        staticByMint.set(action.mint, (staticByMint.get(action.mint) ?? 0n) + (action.amount ?? 0n));
      }
    }
    for (const [mint, rawCap] of Object.entries(policy.maxTokenOutByMint)) {
      let cap: bigint;
      try {
        cap = BigInt(rawCap);
      } catch {
        findings.push({
          code: "POLICY_INVALID_TOKEN_CAP",
          severity: "critical",
          message: `maxTokenOutByMint["${mint}"] = ${JSON.stringify(rawCap)} is not a valid integer amount. Failing closed.`,
          data: { mint, value: rawCap },
        });
        continue;
      }
      const staticOut = staticByMint.get(mint) ?? 0n;
      const simDelta = simulation?.ownerTokenDeltas[mint];
      const simOut = simDelta !== undefined && simDelta < 0n ? -simDelta : 0n;
      const observed = staticOut > simOut ? staticOut : simOut;
      if (observed > cap) {
        findings.push({
          code: "POLICY_TOKEN_CAP_EXCEEDED",
          severity: "critical",
          message: `Transaction moves ${observed} base units of token ${mint} out of the owner, over the cap of ${cap}. Blocking.`,
          data: { mint, observed: String(observed), cap: String(cap), source: simOut > staticOut ? "simulation" : "static" },
        });
      }
    }

    // A plain (unchecked) Transfer/Approve/Burn carries no mint, so it can't be
    // attributed to a per-mint cap statically — only simulation diffing its
    // SOURCE token account can. Fail closed with a WARN for any unchecked owner
    // outflow whose source was not actually diffed (offline, source unwatched,
    // ALT-unresolved, or dropped by the account limit) so it can never verdict
    // SAFE. Watch the source (ownedTokenAccounts / "auto") to enforce the cap.
    const diffed = new Set(simulation?.diffedTokenAccounts ?? []);
    const uncheckedOutflowUnverified = analysis.actions.some(({ action }) => {
      // A missing mint (plain Transfer/Approve/Burn) OR an ALT-masked mint that
      // decoded to UNRESOLVED both mean the per-mint cap could not be matched
      // statically — treat both as unchecked and require simulation to verify.
      const isUncheckedTokenSpend =
        (action.kind === "token_transfer" || action.kind === "token_approve" || action.kind === "token_burn") &&
        (!action.mint || action.mint === UNRESOLVED) &&
        ownerish(action.authority) &&
        (action.amount ?? 0n) > 0n;
      if (!isUncheckedTokenSpend) return false;
      // Verified only if simulation actually diffed this outflow's source account.
      return !(action.source !== undefined && action.source !== UNRESOLVED && diffed.has(action.source));
    });
    // If watched accounts the tx could modify were dropped for the account
    // limit (watchTruncated), a capped mint's source may be among them — also
    // fail closed here. Note truncation ALREADY fails closed for every policy
    // via the warn-severity SIM_WATCH_FILTERED finding from the simulation
    // layer; this escalation just names the cap that became unenforceable.
    if (uncheckedOutflowUnverified || simulation?.watchTruncated) {
      findings.push({
        code: "POLICY_TOKEN_CAP_UNVERIFIABLE",
        severity: "warn",
        message:
          "A per-mint token cap could not be fully enforced: an owner token outflow was not diffed by simulation (unchecked instruction with its source unwatched/lookup-table-resolved, or dropped by the transaction's account limit). Watch the source token account (ownedTokenAccounts or \"auto\") to enforce the cap.",
      });
    }
  }

  // 4. Priority-fee cap: an inflated compute-unit price drains the fee payer.
  if (policy.maxFeeLamports !== undefined && analysis.worstCasePriorityFeeLamports > policy.maxFeeLamports) {
    findings.push({
      code: "POLICY_FEE_EXCEEDED",
      severity: "critical",
      message: `Worst-case priority fee is ${analysis.worstCasePriorityFeeLamports} lamports, over maxFeeLamports of ${policy.maxFeeLamports}. Blocking.`,
      data: { worstCaseFeeLamports: analysis.worstCasePriorityFeeLamports, cap: policy.maxFeeLamports },
    });
  }

  // 5. Recipient allowlist for value-moving actions. Delegates and close
  // destinations are included when their hard block is switched off — funds
  // can end up there, so the allowlist is the remaining line of defense.
  if (recipientAllow) {
    for (const { ix, action } of analysis.actions) {
      let dest: string | undefined;
      switch (action.kind) {
        case "sol_transfer":
        case "sol_create_account":
        case "nonce_withdraw":
        case "token_transfer":
          dest = action.target;
          break;
        case "token_approve":
        case "nonce_authorize":
          if (!opts.blockOnDelegation) dest = action.target;
          break;
        case "token_close_account":
          if (!opts.blockOnAccountClose) dest = action.target;
          break;
      }
      if (dest === undefined) continue;
      if (!recipientAllow.has(dest)) {
        findings.push({
          code: "POLICY_RECIPIENT_NOT_ALLOWED",
          severity: "critical",
          message: `Instruction ${ix} sends funds to ${dest}, which is not in the recipient allowlist. Blocking.`,
          ix,
          data: { recipient: dest, kind: action.kind },
        });
      }
    }

    // Static instructions above are recipient-checked, but a CPI-hidden native
    // outflow (no static action) only shows up as a simulated lamport delta —
    // and simulation reveals the net delta, never the recipient. If the owner
    // loses MORE lamports in simulation than the allowlist-checked static
    // instructions account for, that excess went somewhere we cannot confirm
    // against the allowlist. Fail closed with a warn so a recipientAllowlist can
    // never be silently bypassed via a CPI (and the outflow can't verdict SAFE).
    if (simulation && simulation.ownerLamportDelta !== null && simulation.ownerLamportDelta < 0) {
      const simOut = -simulation.ownerLamportDelta;
      const tolerance = policy.feeLamportsTolerance ?? DEFAULT_FEE_TOLERANCE_LAMPORTS;
      const unexplained = simOut - analysis.staticLamportsOut;
      if (unexplained > tolerance) {
        findings.push({
          code: "POLICY_RECIPIENT_UNVERIFIABLE",
          severity: "warn",
          message: `Simulation shows ${simOut} lamports leaving the owner — ${unexplained} more than the ${analysis.staticLamportsOut} moved by allowlist-checked instructions. Simulation cannot reveal the recipient of a CPI-hidden outflow, so it cannot be confirmed against recipientAllowlist. Failing closed.`,
          data: { simulatedOutflow: simOut, staticOutflow: analysis.staticLamportsOut, unexplained },
        });
      }
    }
  }

  // 6. Delegation / authority handover hard blocks.
  for (const { ix, action } of analysis.actions) {
    if (opts.blockOnDelegation && DELEGATION_KINDS.has(action.kind)) {
      findings.push({
        code: "POLICY_DELEGATION_BLOCKED",
        severity: "critical",
        message: `Instruction ${ix} (${action.kind}) hands authority or delegation to another party; blockOnDelegation is on. Blocking.`,
        ix,
        data: { kind: action.kind },
      });
    }
    if (opts.blockOnAccountClose && action.kind === "token_close_account") {
      findings.push({
        code: "POLICY_ACCOUNT_CLOSE_BLOCKED",
        severity: "critical",
        message: `Instruction ${ix} closes a token account; blockOnAccountClose is on. Blocking.`,
        ix,
        data: { account: action.source },
      });
    }
  }

  return findings;
}

/**
 * Post-process the merged finding list (static + simulation + policy):
 *
 * 1. `UNKNOWN_PROGRAM` findings for programs the caller explicitly allowlisted
 *    are downgraded to `info` — allowlisting is an explicit trust decision.
 * 2. When `policy.allowCompliantTransfers` is true AND no finding is critical,
 *    transfer findings whose corresponding limits are configured are
 *    downgraded to `info`, letting a fully compliant transaction verdict SAFE.
 *    (If any limit were violated there would be a critical policy finding, so
 *    "no criticals + limit configured" implies compliance.)
 */
export function finalizeFindings(findings: Finding[], policy: Policy): Finding[] {
  const programAllow = new Set(policy.programAllowlist ?? []);
  let out = findings.map((f) =>
    f.code === "UNKNOWN_PROGRAM" &&
    typeof f.data?.programId === "string" &&
    programAllow.has(f.data.programId)
      ? { ...f, severity: "info" as const, message: `${f.message} Allowlisted by policy.` }
      : f,
  );

  if (policy.allowCompliantTransfers && !out.some((f) => f.severity === "critical")) {
    const hasSolCap = policy.maxLamportsOut !== undefined;
    const hasRecipients = (policy.recipientAllowlist?.length ?? 0) > 0;
    const hasTokenCap = policy.maxTokenOutByMint !== undefined;
    const downgrade = (f: Finding): Finding => ({
      ...f,
      severity: "info",
      message: `${f.message} Within policy limits.`,
    });
    out = out.map((f) => {
      if (f.severity !== "warn") return f;
      switch (f.code) {
        case "SOL_TRANSFER":
        case "ACCOUNT_FUNDING":
        case "NONCE_WITHDRAW":
          return hasSolCap && hasRecipients ? downgrade(f) : f;
        case "TOKEN_TRANSFER": {
          // Only downgrade when compliance is actually provable. If a token cap
          // is configured but this transfer's mint is unknown — a plain
          // unchecked Transfer (no mint) OR an ALT-masked mint that decoded to
          // UNRESOLVED — the cap could not have been enforced statically, so
          // never let such a transfer reach SAFE just because its recipient is
          // allowlisted.
          const mintKnown = typeof f.data?.mint === "string" && f.data.mint !== UNRESOLVED;
          const capVerifiable = !hasTokenCap || mintKnown;
          return hasRecipients && capVerifiable ? downgrade(f) : f;
        }
        case "SIM_NATIVE_OUTFLOW":
          // Match the static SOL path + the documented contract: a simulated
          // native outflow to an unrestricted recipient must not be downgraded.
          return hasSolCap && hasRecipients ? downgrade(f) : f;
        case "SIM_TOKEN_OUTFLOW": {
          const mint = typeof f.data?.mint === "string" ? f.data.mint : undefined;
          return mint !== undefined && policy.maxTokenOutByMint?.[mint] !== undefined ? downgrade(f) : f;
        }
        case "HIGH_PRIORITY_FEE":
          return policy.maxFeeLamports !== undefined ? downgrade(f) : f;
        default:
          return f;
      }
    });
  }
  return out;
}
