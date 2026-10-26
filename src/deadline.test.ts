import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, before, test } from "node:test";
import { formatReport, runAudit } from "./audit.js";
import { loadThresholds } from "./decision.js";
import { loadConfig } from "./subq.js";

const realFetch = globalThis.fetch;
let calls = 0;

before(() => {
  process.env["SUBQ_VALIDATOR_PATH"] = "off"; // hermetic: do not depend on the locally installed skill
});
afterEach(() => {
  globalThis.fetch = realFetch;
  calls = 0;
});

const cfg = (totalTimeoutMs: number) => ({ apiKey: "test-key", baseUrl: "https://subq.test", model: "subq-snap-1.1", timeoutMs: 20_000, totalTimeoutMs });

function needsValidation(i: number) {
  return {
    fingerprint: `f${i}`,
    verdict: "needs_validation",
    title: `t${i}`,
    description: "d",
    claimed_root_cause: "c",
    blockers: ["b"],
    trace: [{ kind: "sink", file: "a.ts", line: 1, scope: "s", description: "x" }],
    evidence: [{ file: "a.ts", line: 1, description: "x" }],
  };
}

function setup(count: number): { root: string; findingsPath: string } {
  const root = mkdtempSync(path.join(os.tmpdir(), "subq-deadline-"));
  writeFileSync(path.join(root, "a.ts"), "const x = 1;\n");
  writeFileSync(path.join(root, "run-metadata.json"), JSON.stringify({ run_status: "complete" }));
  const findingsPath = path.join(root, "findings.json");
  writeFileSync(findingsPath, JSON.stringify(Array.from({ length: count }, (_, i) => needsValidation(i))));
  return { root, findingsPath };
}

/** A SubQ that never answers but, like real fetch, rejects as soon as its signal aborts. */
function hangingSubq(): void {
  globalThis.fetch = ((_url: unknown, init?: RequestInit) => {
    calls++;
    return new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
    });
  }) as typeof fetch;
}

test("the total deadline stops a hanging SubQ and skips the rest", async () => {
  hangingSubq();
  const { root, findingsPath } = setup(12); // 3 batches of 4; only the first batch may start
  const start = performance.now();
  const report = await runAudit({ findingsPath, repoRoot: root, config: cfg(1200), thresholds: loadThresholds({}) });
  const elapsed = performance.now() - start;

  assert.ok(elapsed < 3000, `returned after ${Math.round(elapsed)}ms; the per-request timeout is 20s, so the total deadline did not apply`);
  assert.equal(calls, 4, "later batches must not start after the deadline");
  assert.equal(report.subq.skipped, 12);
  assert.equal(report.subq.failed, 0);
  assert.equal(report.action, "MANUAL_REVIEW");
  assert.ok(report.reasons.some((r) => r.includes("Batas waktu total")));
  assert.ok(formatReport(report).includes("12 dilewati"));
});

test("retry backoff does not outlive the deadline", async () => {
  globalThis.fetch = (async () => {
    calls++;
    return new Response("{}", { status: 503 });
  }) as typeof fetch;
  const { root, findingsPath } = setup(4);
  const start = performance.now();
  const report = await runAudit({ findingsPath, repoRoot: root, config: cfg(1000), thresholds: loadThresholds({}) });
  const elapsed = performance.now() - start;
  // Without the deadline: 3 attempts with 500 ms + 1000 ms of backoff = about 1.5 s per finding.
  assert.ok(elapsed < 1400, `took ${Math.round(elapsed)}ms`);
  assert.equal(report.action, "MANUAL_REVIEW");
});

test("a client cancellation stops the call and says so", async () => {
  hangingSubq();
  const { root, findingsPath } = setup(8);
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 300);
  const start = performance.now();
  const report = await runAudit({ findingsPath, repoRoot: root, config: cfg(60_000), thresholds: loadThresholds({}), signal: controller.signal });
  assert.ok(performance.now() - start < 2000);
  assert.equal(report.action, "MANUAL_REVIEW");
  assert.equal(report.subq.skipped, 8);
  assert.ok(report.reasons.some((r) => r.includes("dibatalkan oleh klien")));
});

test("a normal call is unaffected by the deadline", async () => {
  globalThis.fetch = (async () => {
    calls++;
    return new Response(JSON.stringify({ answers: { exploitable: { type: "noul", noul: 0.05 }, reachable: { type: "noul", noul: 0.05 } } }), { status: 200 });
  }) as typeof fetch;
  const { root, findingsPath } = setup(6);
  const report = await runAudit({ findingsPath, repoRoot: root, config: cfg(60_000), thresholds: loadThresholds({}) });
  assert.equal(calls, 6);
  assert.deepEqual(report.subq, { ok: 6, failed: 0, skipped: 0 });
  assert.equal(report.action, "APPROVE");
  assert.deepEqual(report.reasons, []);
});

test("SUBQ_TOTAL_TIMEOUT_MS is validated and defaults to two minutes", () => {
  const env = { SUBQ_API_KEY: "k" };
  assert.equal(loadConfig(env).totalTimeoutMs, 120_000);
  assert.equal(loadConfig({ ...env, SUBQ_TOTAL_TIMEOUT_MS: "5000" }).totalTimeoutMs, 5000);
  for (const bad of ["0", "999", "abc", "1800001", "-5"]) {
    assert.throws(() => loadConfig({ ...env, SUBQ_TOTAL_TIMEOUT_MS: bad }), /SUBQ_TOTAL_TIMEOUT_MS/, bad);
  }
});
