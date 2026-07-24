import { test } from "node:test";
import assert from "node:assert/strict";
import { verdictFromFindings, sortFindings } from "../src/verdict.js";
import type { Finding } from "../src/types.js";

const info: Finding = { code: "A", severity: "info", message: "i" };
const warn: Finding = { code: "B", severity: "warn", message: "w" };
const crit: Finding = { code: "C", severity: "critical", message: "c" };

test("verdict is BLOCK when any finding is critical", () => {
  assert.equal(verdictFromFindings([info, warn, crit]), "BLOCK");
});

test("verdict is WARN when the worst finding is a warning", () => {
  assert.equal(verdictFromFindings([info, warn]), "WARN");
});

test("verdict is SAFE with only info findings or none", () => {
  assert.equal(verdictFromFindings([info]), "SAFE");
  assert.equal(verdictFromFindings([]), "SAFE");
});

test("sortFindings orders critical, then warn, then info, stable within tier", () => {
  const ordered = sortFindings([info, crit, warn]);
  assert.deepEqual(
    ordered.map((f) => f.severity),
    ["critical", "warn", "info"],
  );
});
