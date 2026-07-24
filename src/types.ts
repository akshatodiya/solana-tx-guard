/**
 * Core types for solana-tx-guard.
 *
 * The guard pipeline turns a transaction into a {@link GuardResult}: a verdict
 * (SAFE / WARN / BLOCK) plus a list of {@link Finding}s explaining why. The
 * verdict is the highest severity among findings, optionally escalated by the
 * caller's {@link Policy}.
 */

/** Severity of a single finding. Verdict is derived from the max severity. */
export type Severity = "info" | "warn" | "critical";

/** Final decision an agent should act on. */
export type Verdict = "SAFE" | "WARN" | "BLOCK";

/** A single thing the guard noticed about a transaction. */
export interface Finding {
  /** Stable machine code, e.g. "SOL_TRANSFER", "UNKNOWN_PROGRAM". */
  code: string;
  severity: Severity;
  /** Human-readable, agent-facing explanation. */
  message: string;
  /** Index of the instruction this finding came from, if applicable. */
  ix?: number;
  /** Structured extra data (amount, program id, recipient, ...). */
  data?: Record<string, unknown>;
}

/**
 * Policy the agent enforces. Everything is optional; an empty policy still runs
 * the full static + simulation analysis and reports findings, it just does not
 * escalate anything to BLOCK on its own.
 */
export interface Policy {
  /**
   * Maximum total native SOL (in lamports) the transaction may move OUT of the
   * owner account. Exceeding this is a BLOCK. Counts static outflows
   * (transfers, account funding, nonce withdrawals) and the simulated native
   * balance drop, whichever is larger.
   */
  maxLamportsOut?: number;
  /**
   * Per-mint caps on token base units leaving the owner, keyed by mint base58.
   * Values may be number or string (for amounts beyond 2^53). Exceeding a cap
   * is a BLOCK. Checked against static amounts (when the mint is identifiable,
   * i.e. Checked variants) and simulated per-mint deltas.
   */
  maxTokenOutByMint?: Record<string, number | string>;
  /**
   * Maximum worst-case priority fee (lamports) implied by compute-budget
   * instructions (cuLimit × cuPrice). Exceeding this is a BLOCK. An inflated
   * compute-unit price is a known drain vector against the fee payer.
   */
  maxFeeLamports?: number;
  /**
   * Base58 addresses the owner is allowed to send funds to. Empty/undefined =
   * no restriction. NOTE: token transfers target token ACCOUNTS (e.g. ATAs) —
   * allowlist the destination token account address, not just the wallet.
   */
  recipientAllowlist?: string[];
  /** Extra program ids (base58) considered trusted beyond the built-in known-safe set. */
  programAllowlist?: string[];
  /** If false (default), invoking a program not in the known/allowed set is a BLOCK. If true, it is only a WARN. */
  allowUnverifiedPrograms?: boolean;
  /** Treat delegation / authority handover (`Approve`, `SetAuthority`, System `Assign`, nonce authorize) as BLOCK. Default true. */
  blockOnDelegation?: boolean;
  /** Treat `CloseAccount` as BLOCK. Default true (closing the owner's token/wSOL accounts can drain them). */
  blockOnAccountClose?: boolean;
  /**
   * When true, transfer findings that comply with the configured limits are
   * downgraded to `info`, so a fully policy-compliant transaction can verdict
   * SAFE and an autonomous agent can act on it without escalation:
   * - SOL outflows: requires BOTH `maxLamportsOut` and `recipientAllowlist`.
   * - Token transfers: requires `recipientAllowlist`.
   * - Simulated token outflows: requires a `maxTokenOutByMint` cap for that mint.
   * - Priority fee: requires `maxFeeLamports`.
   * Nothing is downgraded if ANY finding in the transaction is critical.
   * Default false: every transfer stays at least WARN.
   */
  allowCompliantTransfers?: boolean;
  /**
   * Simulated native outflows up to this many lamports are reported as `info`
   * instead of `warn` (transaction fees always show up as a small negative
   * delta for the fee payer). Default 20_000 (~4× a single signature fee).
   */
  feeLamportsTolerance?: number;
  /**
   * The agent's own wallet pubkey (base58). Used to scope drain detection:
   * outflows, delegations, and authority changes that touch this account are
   * what matter; movements between unrelated accounts are informational.
   */
  ownerPubkey?: string;
}

/** Result of simulating the transaction against an RPC. */
export interface SimulationResult {
  /** True if the RPC simulation ran. False when no connection was provided or it threw. */
  ran: boolean;
  /** Simulation error (program error / failed tx), if any. */
  err: unknown | null;
  /** Native lamport delta for the owner account (negative = funds left the account). */
  ownerLamportDelta: number | null;
  /** Per-mint owner token deltas in base units (negative = tokens left), keyed by mint base58. */
  ownerTokenDeltas: Record<string, bigint>;
  /** Token-account addresses (base58) whose pre/post balance was actually diffed. */
  diffedTokenAccounts: string[];
  /**
   * True if watched accounts this transaction COULD modify were dropped because
   * the tx's account limit was exceeded — their balance changes are unverified,
   * and the guard fails closed (warn) on it. Watched accounts the tx provably
   * cannot reference (no lookup tables and not a static key) are filtered
   * silently and do NOT set this flag.
   */
  watchTruncated: boolean;
  /** Program log lines returned by the simulation, if any. */
  logs: string[];
  /** Compute units consumed, if reported. */
  unitsConsumed: number | null;
}

/** Everything the guard learned about a transaction. */
export interface GuardResult {
  verdict: Verdict;
  findings: Finding[];
  /** Whether RPC simulation was part of this result. */
  simulated: boolean;
  /** Raw simulation data, present when `simulated` is true. */
  simulation?: SimulationResult;
  /** Quick rollup for logging / display. */
  summary: {
    programsInvoked: string[];
    /** Total lamports statically leaving the owner (transfers, account funding, nonce withdrawals). */
    staticLamportsOut: number;
    /** Worst-case priority fee (lamports) implied by compute-budget instructions. */
    worstCasePriorityFeeLamports: number;
    instructionCount: number;
    /** True if the transaction uses address lookup tables whose accounts could not be resolved offline. */
    usesLookupTables: boolean;
  };
}
