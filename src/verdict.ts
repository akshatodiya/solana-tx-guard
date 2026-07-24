/**
 * Combine findings into a single verdict.
 *
 *   any `critical`  -> BLOCK
 *   any `warn`      -> WARN
 *   otherwise       -> SAFE
 *
 * The agent's contract is simple: never sign a BLOCK; surface a WARN to a human
 * (or to its own policy) before signing; SAFE may proceed.
 */

import type { Finding, Verdict } from "./types.js";

export function verdictFromFindings(findings: Finding[]): Verdict {
  if (findings.some((f) => f.severity === "critical")) return "BLOCK";
  if (findings.some((f) => f.severity === "warn")) return "WARN";
  return "SAFE";
}

/** Stable ordering for display: critical first, then warn, then info; original order within a tier. */
export function sortFindings(findings: Finding[]): Finding[] {
  const rank = { critical: 0, warn: 1, info: 2 } as const;
  return findings
    .map((f, i) => ({ f, i }))
    .sort((a, b) => rank[a.f.severity] - rank[b.f.severity] || a.i - b.i)
    .map(({ f }) => f);
}
