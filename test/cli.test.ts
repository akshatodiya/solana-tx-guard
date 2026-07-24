/**
 * CLI contract tests: exit codes are the interface a signing script gates on,
 * and argument validation must fail CLOSED (a typo'd flag or value is an
 * error, never a silently weaker policy).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { SystemProgram } from "@solana/web3.js";
import { key, v0Tx } from "./helpers.js";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

function runCli(args: string[]) {
  return spawnSync(process.execPath, ["--import", "tsx", CLI, ...args], {
    encoding: "utf8",
    timeout: 60_000,
  });
}

const owner = key();
const to = key();
const bigTransfer = Buffer.from(
  v0Tx(owner, [
    SystemProgram.transfer({ fromPubkey: owner, toPubkey: to, lamports: 2_000_000_000 }),
  ]).serialize(),
).toString("base64");

test("cli: over-cap transfer exits 2 (BLOCK)", () => {
  const r = runCli(["check", "--tx", bigTransfer, "--owner", owner.toBase58(), "--max-sol", "0.5"]);
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stdout, /BLOCK/);
  assert.match(r.stdout, /POLICY_CAP_EXCEEDED/);
});

test("cli: compliant transfer with --allow-compliant exits 0 (SAFE)", () => {
  const r = runCli([
    "check",
    "--tx", bigTransfer,
    "--owner", owner.toBase58(),
    "--max-sol", "5",
    "--allow", to.toBase58(),
    "--allow-compliant",
    "--json",
  ]);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  const parsed = JSON.parse(r.stdout);
  assert.equal(parsed.verdict, "SAFE");
});

test("cli: malformed --max-sol fails closed with exit 3", () => {
  const r = runCli(["check", "--tx", bigTransfer, "--max-sol", "abc"]);
  assert.equal(r.status, 3);
  assert.match(r.stderr, /--max-sol must be a non-negative number/);
});

test("cli: unknown flag fails closed with exit 3", () => {
  const r = runCli(["check", "--tx", bigTransfer, "--allw", to.toBase58()]);
  assert.equal(r.status, 3);
  assert.match(r.stderr, /Unknown flag/);
});

test("cli: invalid --owner fails with exit 3", () => {
  const r = runCli(["check", "--tx", bigTransfer, "--owner", "garbage"]);
  assert.equal(r.status, 3);
  assert.match(r.stderr, /not a valid base58 pubkey/);
});

test("cli: garbage transaction bytes fail with exit 3", () => {
  const r = runCli(["check", "--tx", "!!!not-base64!!!"]);
  assert.equal(r.status, 3);
});

test("cli: --watch without --rpc fails closed with exit 3", () => {
  const r = runCli(["check", "--tx", bigTransfer, "--owner", owner.toBase58(), "--watch", to.toBase58()]);
  assert.equal(r.status, 3);
  assert.match(r.stderr, /--watch requires --rpc/);
});

test("cli: --watch without --owner fails closed with exit 3", () => {
  const r = runCli(["check", "--tx", bigTransfer, "--rpc", "http://127.0.0.1:9", "--watch", to.toBase58()]);
  assert.equal(r.status, 3);
  assert.match(r.stderr, /--watch requires --owner/);
});
