/**
 * RPC simulation + balance diffing.
 *
 * `simulateTransaction` runs the transaction against a node WITHOUT submitting
 * it, and (with the right config) returns the post-execution account state. We
 * compare pre vs post for the owner's native lamports and token balances, so
 * the agent sees the *actual* effect — including anything hidden inside an
 * unverified program's CPI that static analysis can't read.
 */

import {
  Connection,
  PublicKey,
  Transaction,
  VersionedTransaction,
} from "@solana/web3.js";
import type { Finding, SimulationResult } from "./types.js";
import { TOKEN_2022_PROGRAM, TOKEN_PROGRAM } from "./programs.js";

/** Minimal slice of `Connection` we depend on, so tests can pass a mock. */
export interface SimulatorConnection {
  simulateTransaction(
    tx: VersionedTransaction,
    config?: unknown,
  ): Promise<{
    value: {
      err: unknown | null;
      logs: string[] | null;
      unitsConsumed?: number | null;
      accounts?: ({ lamports: number; data: [string, string] | Buffer; owner: string } | null)[] | null;
    };
  }>;
}

/** Options for {@link simulateAndDiff}. */
export interface SimulateOptions {
  /**
   * Native outflows up to this many lamports are reported as `info` instead of
   * `warn` — the fee payer always shows a small negative delta for the tx fee.
   */
  feeLamportsTolerance?: number;
}

export const DEFAULT_FEE_TOLERANCE_LAMPORTS = 20_000;

/**
 * Discover the owner's SPL token accounts (legacy Token + Token-2022) so they
 * can be watched without listing them by hand. Returns null when the
 * connection does not support `getTokenAccountsByOwner` (e.g. a minimal mock).
 */
export async function discoverOwnerTokenAccounts(
  connection: Connection | SimulatorConnection,
  owner: PublicKey,
): Promise<PublicKey[] | null> {
  const conn = connection as Connection;
  if (typeof conn.getTokenAccountsByOwner !== "function") return null;
  const results = await Promise.all(
    [TOKEN_PROGRAM, TOKEN_2022_PROGRAM].map((programId) =>
      conn.getTokenAccountsByOwner(owner, { programId: new PublicKey(programId) }),
    ),
  );
  return results.flatMap((r) => r.value.map((a) => a.pubkey));
}

/** SPL token account layout: amount is a u64 LE at byte offset 64. */
const TOKEN_AMOUNT_OFFSET = 64;
const TOKEN_MINT_OFFSET = 0;
/** An SPL token account is exactly 165 bytes (Token-2022 accounts are >= 165 with extensions). */
const SPL_TOKEN_ACCOUNT_LEN = 165;

/** Heuristic: does this account's data look like an SPL token account? */
function looksLikeTokenAccount(data: Uint8Array): boolean {
  return data.length >= SPL_TOKEN_ACCOUNT_LEN;
}

function decodeTokenAmount(data: Uint8Array): bigint {
  if (data.length < TOKEN_AMOUNT_OFFSET + 8) return 0n;
  let v = 0n;
  for (let i = 0; i < 8; i++) v |= BigInt(data[TOKEN_AMOUNT_OFFSET + i]!) << BigInt(8 * i);
  return v;
}

function decodeMint(data: Uint8Array): string | null {
  if (data.length < TOKEN_MINT_OFFSET + 32) return null;
  return new PublicKey(data.subarray(TOKEN_MINT_OFFSET, TOKEN_MINT_OFFSET + 32)).toBase58();
}

function toBytes(data: string[] | [string, string] | Buffer | Uint8Array): Uint8Array {
  if (Array.isArray(data)) {
    // [base64String, "base64"] as returned by simulateTransaction
    return Uint8Array.from(Buffer.from(data[0] ?? "", "base64"));
  }
  return Uint8Array.from(data as Uint8Array);
}

/**
 * Simulate the transaction and diff the owner's balances.
 *
 * To get post-state we ask the node to return the accounts we care about. The
 * owner's system account gives the native lamport delta; the owner's token
 * accounts give per-mint deltas. Pre-state is fetched alongside.
 */
export async function simulateAndDiff(
  connection: Connection | SimulatorConnection,
  tx: VersionedTransaction,
  owner: PublicKey,
  ownedTokenAccounts: PublicKey[] = [],
  options: SimulateOptions = {},
): Promise<{ result: SimulationResult; findings: Finding[] }> {
  const findings: Finding[] = [];
  const feeTolerance = options.feeLamportsTolerance ?? DEFAULT_FEE_TOLERANCE_LAMPORTS;

  // Only accounts the transaction actually references can change during
  // simulation. Restrict the watch list to the tx's static account keys: it's
  // the set that can move, AND the RPC caps `accounts.addresses` at the tx's
  // account count ("Too many accounts provided") — auto-discovery of a wallet's
  // many token accounts would otherwise make every simulateTransaction throw.
  // The cap is the transaction's TOTAL loaded accounts (static keys + accounts
  // pulled in from address lookup tables), both countable offline. We must NOT
  // restrict to static keys only: an account loaded via an ALT is a legitimate,
  // returnable simulation target, and a drainer can route the victim's ATA
  // through an ALT precisely to dodge a static-keys-only watch list.
  const staticKeyList = tx.message.staticAccountKeys.map((k) => k.toBase58());
  const txKeys = new Set(staticKeyList);
  const altLookups =
    "addressTableLookups" in tx.message ? tx.message.addressTableLookups : [];
  const altAccountCount = altLookups.reduce(
    (n, l) => n + l.writableIndexes.length + l.readonlyIndexes.length,
    0,
  );
  const maxWatch = staticKeyList.length + altAccountCount;

  // Dedupe (owner first so index 0 is the native account), then order by how
  // confident we are the account is relevant: owner, then accounts known to be
  // static keys, then the rest (which may be ALT-loaded). Keep as many as the
  // RPC will accept; any beyond the cap are dropped.
  const seen = new Set<string>();
  const deduped: PublicKey[] = [];
  for (const k of [owner, ...ownedTokenAccounts]) {
    const b58 = k.toBase58();
    if (seen.has(b58)) continue;
    seen.add(b58);
    deduped.push(k);
  }
  const ordered = [
    deduped[0]!, // owner
    ...deduped.slice(1).filter((k) => txKeys.has(k.toBase58())),
    ...deduped.slice(1).filter((k) => !txKeys.has(k.toBase58())),
  ];
  // A transaction can only modify accounts it loads. Without ALT lookups the
  // loaded set IS the static keys, so a watched account that is not a static
  // key provably cannot change — dropping it loses nothing. With ALT lookups
  // the loaded set is not resolvable offline, so EVERY watched account is a
  // potential target and none may be discarded as irrelevant.
  const candidates =
    altAccountCount > 0
      ? ordered
      : ordered.filter((k, i) => i === 0 || txKeys.has(k.toBase58()));
  const irrelevantDropped = ordered.length - candidates.length;
  const watch = candidates.slice(0, maxWatch);
  const droppedWatched = candidates.length - watch.length;
  // True only when accounts this tx COULD modify were dropped. That is a hole
  // in the diff a drainer can hide in (route the victim's ATA through an ALT,
  // rely on the account limit to push it off the watch list), so it must fail
  // closed as a WARN — the verdict can never be SAFE with an unverified hole.
  const watchTruncated = droppedWatched > 0;
  if (watchTruncated) {
    findings.push({
      code: "SIM_WATCH_FILTERED",
      severity: "warn",
      message: `${droppedWatched} watched account(s) exceeded this transaction's account limit and were NOT diffed, but the transaction may still modify them${altAccountCount > 0 ? " (they can be referenced through its address lookup tables)" : ""}. Failing closed: their balance changes are unverified, so this result cannot be SAFE.`,
      data: { dropped: droppedWatched, potentiallyReferenced: true },
    });
  } else if (irrelevantDropped > 0) {
    findings.push({
      code: "SIM_WATCH_FILTERED",
      severity: "info",
      message: `${irrelevantDropped} watched account(s) are not referenced by this transaction (which uses no address lookup tables), so they cannot change and were not diffed.`,
      data: { dropped: irrelevantDropped, potentiallyReferenced: false },
    });
  }

  // Pre-state (only when we have a real Connection with getMultipleAccountsInfo).
  const pre = new Map<string, { lamports: number; tokenAmount: bigint | null; tokenMint: string | null }>();
  const conn = connection as Connection;
  const havePreState = typeof conn.getMultipleAccountsInfo === "function";
  if (havePreState) {
    const infos = await conn.getMultipleAccountsInfo(watch);
    infos.forEach((info, i) => {
      const key = watch[i]!.toBase58();
      if (!info) {
        pre.set(key, { lamports: 0, tokenAmount: null, tokenMint: null });
        return;
      }
      const bytes = Uint8Array.from(info.data);
      // Decode token fields for ANY watched account whose data is a token-account
      // layout — including index 0. That way an owner mistakenly configured as a
      // token account still has its token balance diffed (native tracking of
      // index 0 is separate and harmless in that case).
      const isToken = looksLikeTokenAccount(bytes);
      pre.set(key, {
        lamports: info.lamports,
        tokenAmount: isToken ? decodeTokenAmount(bytes) : null,
        // Read the mint from PRE-state: if the account is closed by the tx its
        // post bytes are gone, so this is the only reliable place to get it.
        tokenMint: isToken ? decodeMint(bytes) : null,
      });
    });
  } else {
    // Fail-closed: a security tool must not silently report "no outflow" when it
    // never actually diffed balances. Surface that balance diffing was skipped.
    findings.push({
      code: "SIM_PRESTATE_UNAVAILABLE",
      severity: "warn",
      message:
        "The connection has no getMultipleAccountsInfo, so pre-state could not be fetched and balance changes were NOT diffed. Verdict reflects static analysis + simulation logs only. Pass a full web3.js Connection to enable balance diffing.",
    });
  }

  let sim;
  try {
    sim = await connection.simulateTransaction(tx, {
      sigVerify: false,
      replaceRecentBlockhash: true,
      accounts: { encoding: "base64", addresses: watch.map((k) => k.toBase58()) },
    });
  } catch (e) {
    return {
      result: {
        ran: false,
        err: e,
        ownerLamportDelta: null,
        ownerTokenDeltas: {},
        diffedTokenAccounts: [],
        watchTruncated,
        logs: [],
        unitsConsumed: null,
      },
      findings: [
        // Keep the watch/pre-state findings gathered before the call failed.
        ...findings,
        {
          code: "SIMULATION_FAILED",
          severity: "warn",
          message: `RPC simulation could not run (${(e as Error)?.message ?? e}). Falling back to static analysis only.`,
        },
      ],
    };
  }

  const value = sim.value;
  const post = value.accounts ?? [];
  const ownerPre = pre.get(owner.toBase58());
  // A conforming RPC returns an `accounts` entry for every requested address,
  // using an explicit `null` for an account that no longer exists post-execution.
  // A tx can drain the owner's system account to exactly 0 lamports, which
  // deallocates it and yields that null — treating it as "unknown" would hide the
  // single worst outcome (a full drain). So an IN-RANGE explicit null on a
  // successful tx means post = 0. An index the RPC didn't return at all (short
  // array) is genuinely unknown and must not be read as a drain.
  const ownerCovered = post.length > 0; // index 0 is in range
  const ownerPost = post[0];
  const ownerReaped = ownerPre !== undefined && ownerCovered && ownerPost == null && value.err === null;

  let ownerLamportDelta: number | null = null;
  if (ownerPre) {
    if (ownerPost) ownerLamportDelta = ownerPost.lamports - ownerPre.lamports;
    else if (ownerReaped) ownerLamportDelta = -ownerPre.lamports;
  }

  const ownerTokenDeltas: Record<string, bigint> = {};
  const diffedTokenAccounts: string[] = [];
  // Start at 0: index 0 is normally the native owner (tokenAmount null → skipped),
  // but if the owner was configured as a token account, diff it here too.
  for (let i = 0; i < watch.length; i++) {
    const key = watch[i]!.toBase58();
    const preEntry = pre.get(key);
    if (!preEntry || preEntry.tokenAmount === null) continue;
    const covered = i < post.length;
    const acctPost = post[i];
    // Determine the post token amount. A closed/deallocated account comes back as
    // an in-range null; an emptied account may come back with truncated data. In
    // both cases, if the tx succeeded, the post balance is 0 — a full outflow we
    // must see. An index the RPC didn't cover is unknown, so skip it.
    let postAmount: bigint;
    if (acctPost) {
      postAmount = decodeTokenAmount(toBytes(acctPost.data)); // 0n if data is truncated
    } else if (covered && value.err === null) {
      postAmount = 0n; // account deallocated by a successful tx
    } else {
      continue; // not covered by the RPC, or tx reverted — post state unreliable
    }
    diffedTokenAccounts.push(key); // pre + post both read — this account was diffed
    const mint = preEntry.tokenMint ?? key; // mint from PRE-state (post may be gone)
    const delta = postAmount - preEntry.tokenAmount;
    if (delta !== 0n) ownerTokenDeltas[mint] = (ownerTokenDeltas[mint] ?? 0n) + delta;
  }

  const result: SimulationResult = {
    ran: true,
    err: value.err,
    ownerLamportDelta,
    ownerTokenDeltas,
    diffedTokenAccounts,
    watchTruncated,
    logs: value.logs ?? [],
    unitsConsumed: value.unitsConsumed ?? null,
  };

  if (value.err) {
    findings.push({
      code: "SIMULATION_ERROR",
      severity: "warn",
      message: `Transaction fails in simulation (${JSON.stringify(value.err)}). It would revert on-chain; review before signing.`,
      data: { err: value.err },
    });
  }
  if (ownerLamportDelta !== null && ownerLamportDelta < 0) {
    const withinFeeTolerance = -ownerLamportDelta <= feeTolerance;
    findings.push({
      code: "SIM_NATIVE_OUTFLOW",
      severity: withinFeeTolerance ? "info" : "warn",
      message: `Simulation shows the owner's native balance dropping by ${-ownerLamportDelta} lamports.${withinFeeTolerance ? " Within the fee tolerance — consistent with the transaction fee." : ""}`,
      data: { lamportDelta: ownerLamportDelta, withinFeeTolerance },
    });
  }
  for (const [mint, delta] of Object.entries(ownerTokenDeltas)) {
    if (delta < 0n) {
      findings.push({
        code: "SIM_TOKEN_OUTFLOW",
        severity: "warn",
        message: `Simulation shows the owner losing ${-delta} base units of token ${mint}.`,
        data: { mint, delta: String(delta) },
      });
    }
  }

  return { result, findings };
}
