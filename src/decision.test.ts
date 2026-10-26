import assert from "node:assert/strict";
import { test } from "node:test";
import { aggregate, decideFinding, loadThresholds } from "./decision.js";
import type { Finding, Severity } from "./findings.js";

const t = loadThresholds({});
const loc = { file: "a.ts", line: 1 };
const common = {
  fingerprint: "fp1",
  title: "t",
  description: "d",
  trace: [{ kind: "sink" as const, scope: "s", description: "x", ...loc }],
  evidence: [{ description: "x", ...loc }],
};

const confirmed = (severity: Severity): Finding => ({
  ...common,
  verdict: "confirmed",
  root_cause: "r",
  intended_behavior: "i",
  conditions: [],
  execution: { attacker_perspective: "a", payloads: ["p"], instructions: ["i"], observed_result: "o" },
  severity: { overall_severity: severity },
  confidence: { score: "high", reason: "r" },
});
const needsValidation: Finding = { ...common, verdict: "needs_validation", claimed_root_cause: "c", blockers: ["b"] };

test("confirmed high/critical always blocks, even if SubQ disagrees", () => {
  const d = decideFinding(confirmed("high"), { exploitable: 0.01, reachable: 0.01 }, t);
  assert.equal(d.action, "BLOCK");
  assert.ok(d.note);
  assert.equal(decideFinding(confirmed("critical"), undefined, t).action, "BLOCK");
});

test("confirmed medium requests changes, low approves", () => {
  assert.equal(decideFinding(confirmed("medium"), undefined, t).action, "REQUEST_CHANGES");
  assert.equal(decideFinding(confirmed("low"), undefined, t).action, "APPROVE");
});

test("needs_validation follows thresholds and fails closed without SubQ", () => {
  assert.equal(decideFinding(needsValidation, { exploitable: 0.9, reachable: 0.9 }, t).action, "REQUEST_CHANGES");
  assert.equal(decideFinding(needsValidation, { exploitable: 0.9, reachable: 0.1 }, t).action, "MANUAL_REVIEW");
  assert.equal(decideFinding(needsValidation, { exploitable: 0.5, reachable: 0.9 }, t).action, "MANUAL_REVIEW");
  assert.equal(decideFinding(needsValidation, { exploitable: 0.1, reachable: 0.9 }, t).action, "APPROVE");
  assert.equal(decideFinding(needsValidation, undefined, t).action, "MANUAL_REVIEW");
});

test("aggregate takes the strictest action", () => {
  const ds = [decideFinding(confirmed("low"), undefined, t), decideFinding(needsValidation, undefined, t), decideFinding(confirmed("high"), undefined, t)];
  assert.equal(aggregate(ds), "BLOCK");
  assert.equal(aggregate([]), "APPROVE");
});

test("thresholds are validated", () => {
  assert.throws(() => loadThresholds({ SUBQ_EXPLOIT_THRESHOLD: "2" }));
  assert.throws(() => loadThresholds({ SUBQ_EXPLOIT_THRESHOLD: "0.3", SUBQ_REVIEW_THRESHOLD: "0.5" }));
});
