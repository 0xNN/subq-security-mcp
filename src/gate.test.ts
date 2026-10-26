import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, before, test } from "node:test";
import { formatReport, runAudit } from "./audit.js";
import { loadThresholds } from "./decision.js";

const config = { apiKey: "test-key", baseUrl: "https://subq.test", model: "subq-snap-1.1", timeoutMs: 5000, totalTimeoutMs: 60_000 };
const realFetch = globalThis.fetch;
let calls = 0;

before(() => {
  process.env["SUBQ_VALIDATOR_PATH"] = "off"; // hermetic: do not depend on the locally installed skill
});
afterEach(() => {
  globalThis.fetch = realFetch;
  calls = 0;
});

function mockSubq(probability: number): void {
  globalThis.fetch = (async () => {
    calls++;
    return new Response(JSON.stringify({ answers: { exploitable: { type: "noul", noul: probability }, reachable: { type: "noul", noul: probability } } }), { status: 200 });
  }) as typeof fetch;
}

const loc = { file: "a.ts", line: 1 };
const base = (fingerprint: string) => ({
  fingerprint,
  title: "t",
  description: "d",
  trace: [{ kind: "sink", scope: "s", description: "x", ...loc }],
  evidence: [{ description: "x", ...loc }],
});
const rejected = (fp: string) => ({ ...base(fp), verdict: "rejected", claimed_root_cause: "c", reason: "r" });
const confirmed = (fp: string, severity: string) => ({
  ...base(fp),
  verdict: "confirmed",
  root_cause: "r",
  intended_behavior: "i",
  conditions: [],
  execution: { attacker_perspective: "a", payloads: ["p"], instructions: ["i"], observed_result: "o" },
  severity: { overall_severity: severity },
  confidence: { score: "high", reason: "r" },
});

type Metadata = "missing" | "complete" | "incomplete" | "malformed";

function setup(findings: unknown[], metadata: Metadata): { root: string; findingsPath: string } {
  const root = mkdtempSync(path.join(os.tmpdir(), "subq-gate-"));
  writeFileSync(path.join(root, "a.ts"), "const x = 1;\n");
  const findingsPath = path.join(root, "findings.json");
  writeFileSync(findingsPath, JSON.stringify(findings));
  const meta = path.join(root, "run-metadata.json");
  if (metadata === "complete") writeFileSync(meta, JSON.stringify({ run_status: "complete" }));
  if (metadata === "incomplete") writeFileSync(meta, JSON.stringify({ run_status: "incomplete" }));
  if (metadata === "malformed") writeFileSync(meta, "{not json");
  return { root, findingsPath };
}

const run = (findings: unknown[], metadata: Metadata) => {
  const { root, findingsPath } = setup(findings, metadata);
  return runAudit({ findingsPath, repoRoot: root, config, thresholds: loadThresholds({}) });
};

test("empty findings without run-metadata.json is MANUAL_REVIEW, not APPROVE", async () => {
  mockSubq(0.99);
  const report = await run([], "missing");
  assert.equal(report.action, "MANUAL_REVIEW");
  assert.equal(report.audit, "missing");
  assert.equal(calls, 0);
  assert.ok(formatReport(report).includes("Alasan gerbang:"));
});

test("empty findings with an unreadable run-metadata.json is MANUAL_REVIEW", async () => {
  const report = await run([], "malformed");
  assert.equal(report.action, "MANUAL_REVIEW");
  assert.equal(report.audit, "unreadable");
});

test("empty findings with a completed audit is APPROVE and still carries the advisory wording", async () => {
  mockSubq(0.99);
  const report = await run([], "complete");
  assert.equal(report.action, "APPROVE");
  assert.equal(report.audit, "complete");
  assert.deepEqual(report.reasons, []);
  assert.equal(calls, 0);
  assert.ok(formatReport(report).includes("bukan bukti kode bebas celah"));
});

test("only-rejected findings follow the same rule as empty findings", async () => {
  assert.equal((await run([rejected("r1")], "missing")).action, "MANUAL_REVIEW");
  assert.equal((await run([rejected("r1")], "complete")).action, "APPROVE");
});

test("an incomplete audit forces MANUAL_REVIEW even when findings are minor or absent", async () => {
  mockSubq(0.1);
  assert.equal((await run([], "incomplete")).action, "MANUAL_REVIEW");
  const minor = await run([confirmed("c1", "low")], "incomplete");
  assert.equal(minor.action, "MANUAL_REVIEW");
  assert.ok(minor.reasons.some((r) => r.includes("belum selesai")));
});

test("missing metadata forces MANUAL_REVIEW even with active findings; a completed audit keeps the policy", async () => {
  mockSubq(0.1);
  const missing = await run([confirmed("c1", "low")], "missing");
  assert.equal(missing.action, "MANUAL_REVIEW");
  assert.ok(missing.reasons.some((r) => r.includes("tidak ditemukan")));
  assert.equal((await run([confirmed("c1", "low")], "complete")).action, "APPROVE");
});

test("the gate never weakens a stricter per-finding decision", async () => {
  mockSubq(0.1);
  const report = await run([confirmed("c1", "high")], "complete");
  assert.equal(report.action, "BLOCK");
  assert.deepEqual(report.reasons, []);
});
