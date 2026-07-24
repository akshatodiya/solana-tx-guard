#!/usr/bin/env -S npx tsx
/**
 * txguard CLI — inspect a serialized transaction from the shell or an agent.
 *
 *   txguard check --tx <base64> [--rpc <url>] [--owner <pubkey>]
 *                 [--max-sol <amount>] [--max-fee <amount>]
 *                 [--allow <addr,addr,...>] [--allow-program <id,id,...>]
 *                 [--watch <acct,acct|auto>] [--allow-unverified]
 *                 [--allow-delegation] [--allow-close] [--allow-compliant]
 *                 [--json]
 *
 * Reads the transaction from --tx, or from stdin if --tx is omitted. Prints a
 * SAFE / WARN / BLOCK verdict and the findings. Exit code: 0 SAFE, 1 WARN,
 * 2 BLOCK, 3 usage/error — so a signing script can gate on `$?`.
 *
 * Fail-closed: unknown flags and malformed values are errors (exit 3), never
 * silently ignored — a typo must not weaken the policy.
 */

import { Connection, PublicKey, VersionedTransaction } from "@solana/web3.js";
import { guard, type GuardOptions } from "./index.js";
import type { Policy } from "./types.js";

interface Args {
  [key: string]: string | boolean;
}

/** Flags that take a value; everything else recognized is boolean. */
const VALUE_FLAGS = new Set(["tx", "rpc", "owner", "max-sol", "max-fee", "allow", "allow-program", "watch"]);
const BOOLEAN_FLAGS = new Set(["allow-unverified", "allow-delegation", "allow-close", "allow-compliant", "json", "help"]);

function parseArgs(argv: string[]): { cmd: string; args: Args } {
  const cmd = argv[0] ?? "";
  const args: Args = {};
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith("--")) fail(`Unexpected argument: ${a}`);
    const key = a.slice(2);
    if (VALUE_FLAGS.has(key)) {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) fail(`Flag --${key} requires a value.`);
      args[key] = next!;
      i++;
    } else if (BOOLEAN_FLAGS.has(key)) {
      args[key] = true;
    } else {
      fail(`Unknown flag: --${key}`);
    }
  }
  return { cmd, args };
}

function fail(message: string): never {
  process.stderr.write(`Error: ${message}\nRun \`txguard check --help\` for usage.\n`);
  process.exit(3);
}

function usage(): never {
  process.stderr.write(
    "Usage: txguard check --tx <base64> [options]\n" +
      "  --tx <base64>            transaction wire bytes (omit to read from stdin)\n" +
      "  --rpc <url>              RPC endpoint; enables simulation\n" +
      "  --owner <pubkey>         the agent's wallet; scopes findings (recommended)\n" +
      "  --max-sol <amount>       cap on SOL leaving the owner (in SOL)\n" +
      "  --max-fee <amount>       cap on worst-case priority fee (in SOL)\n" +
      "  --allow <addr,addr>      recipient allowlist\n" +
      "  --allow-program <id,id>  extra trusted program ids\n" +
      "  --watch <acct,acct|auto> token accounts to diff in simulation\n" +
      "  --allow-unverified       unknown programs WARN instead of BLOCK\n" +
      "  --allow-delegation       do not hard-block delegations / authority changes\n" +
      "  --allow-close            do not hard-block CloseAccount\n" +
      "  --allow-compliant        transfers within caps + allowlist verdict SAFE\n" +
      "  --json                   machine-readable output\n" +
      "Exit codes: 0 SAFE · 1 WARN · 2 BLOCK · 3 usage/error\n",
  );
  process.exit(3);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8").trim();
}

function deserialize(raw: string): VersionedTransaction {
  const trimmed = raw.trim();
  // Base64 is the canonical wire format.
  try {
    return VersionedTransaction.deserialize(Uint8Array.from(Buffer.from(trimmed, "base64")));
  } catch {
    throw new Error("Could not deserialize transaction. Provide base64-encoded wire bytes.");
  }
}

function parseSolAmount(flag: string, value: string): number {
  const sol = Number(value);
  if (!Number.isFinite(sol) || sol < 0) fail(`--${flag} must be a non-negative number, got: ${value}`);
  return Math.round(sol * 1e9);
}

function parsePubkey(flag: string, value: string): string {
  try {
    return new PublicKey(value).toBase58();
  } catch {
    fail(`--${flag} is not a valid base58 pubkey: ${value}`);
  }
}

function parseList(value: string): string[] {
  return value.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
}

const VERDICT_EXIT = { SAFE: 0, WARN: 1, BLOCK: 2 } as const;

async function main() {
  const { cmd, args } = parseArgs(process.argv.slice(2));

  if (cmd !== "check" || args.help) usage();

  let raw: string;
  if (typeof args.tx === "string") raw = args.tx;
  else raw = await readStdin();
  if (!raw) fail("No transaction provided (use --tx or pipe via stdin).");

  let tx: VersionedTransaction;
  try {
    tx = deserialize(raw);
  } catch (e) {
    fail((e as Error).message);
  }

  const policy: Policy = {};
  if (typeof args.owner === "string") policy.ownerPubkey = parsePubkey("owner", args.owner);
  if (typeof args["max-sol"] === "string") policy.maxLamportsOut = parseSolAmount("max-sol", args["max-sol"]);
  if (typeof args["max-fee"] === "string") policy.maxFeeLamports = parseSolAmount("max-fee", args["max-fee"]);
  if (typeof args.allow === "string") policy.recipientAllowlist = parseList(args.allow);
  if (typeof args["allow-program"] === "string") {
    policy.programAllowlist = parseList(args["allow-program"]).map((p) => parsePubkey("allow-program", p));
  }
  if (args["allow-unverified"]) policy.allowUnverifiedPrograms = true;
  if (args["allow-delegation"]) policy.blockOnDelegation = false;
  if (args["allow-close"]) policy.blockOnAccountClose = false;
  if (args["allow-compliant"]) policy.allowCompliantTransfers = true;

  const connection = typeof args.rpc === "string" ? new Connection(args.rpc, "confirmed") : undefined;

  let ownedTokenAccounts: GuardOptions["ownedTokenAccounts"];
  if (typeof args.watch === "string") {
    // Fail closed: token diffing only happens during simulation, which needs
    // both an RPC and an owner. Silently ignoring --watch would let a caller
    // believe token-drain diffing is active when it is not.
    if (!connection) fail("--watch requires --rpc (token accounts are only diffed during simulation).");
    if (typeof policy.ownerPubkey !== "string") fail("--watch requires --owner so balance changes can be attributed.");
    ownedTokenAccounts =
      args.watch === "auto" ? "auto" : parseList(args.watch).map((a) => parsePubkey("watch", a));
  }

  const result = await guard(tx, { policy, connection, ownedTokenAccounts });

  if (args.json) {
    process.stdout.write(
      JSON.stringify(result, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n",
    );
  } else {
    const icon = result.verdict === "SAFE" ? "✅" : result.verdict === "WARN" ? "⚠️ " : "⛔";
    process.stdout.write(`\n${icon} ${result.verdict}\n`);
    process.stdout.write(
      `   ${result.summary.instructionCount} instruction(s), programs: ${result.summary.programsInvoked.join(", ") || "none"}\n`,
    );
    if (result.simulated) process.stdout.write(`   simulated: yes\n`);
    if (result.findings.length === 0) {
      process.stdout.write("   no findings.\n");
    } else {
      for (const f of result.findings) {
        const tag = f.severity === "critical" ? "[BLOCK]" : f.severity === "warn" ? "[WARN] " : "[info] ";
        process.stdout.write(`   ${tag} ${f.code}: ${f.message}\n`);
      }
    }
    process.stdout.write("\n");
  }

  process.exit(VERDICT_EXIT[result.verdict]);
}

main().catch((e) => {
  process.stderr.write(`Fatal: ${(e as Error)?.stack ?? e}\n`);
  process.exit(3);
});
