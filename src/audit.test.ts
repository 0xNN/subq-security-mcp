import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, before, test } from "node:test";
import { formatReport, runAudit } from "./audit.js";
import { loadThresholds } from "./decision.js";
import { isRepoRelative } from "./paths.js";

const SECRET = "AKIA" + "ABCDEFGHIJKLMNOP";
const config = { apiKey: "test-key", baseUrl: "https://subq.test", model: "subq-snap-1.1", timeoutMs: 5000, totalTimeoutMs: 60_000 };
const realFetch = globalThis.fetch;
before(() => {
  process.env["SUBQ_VALIDATOR_PATH"] = "off"; // hermetic: do not depend on the locally installed skill
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

function fixture(): { root: string; findingsPath: string } {
  const root = mkdtempSync(path.join(os.tmpdir(), "subq-audit-"));
  mkdirSync(path.join(root, "src"));
  writeFileSync(path.join(root, "src", "app.ts"), `const aws = "${SECRET}";\nel.innerHTML = location.hash;\n`);
  writeFileSync(path.join(root, ".env"), `DB_PASSWORD=supersecretvalue123\n`);
  const loc = (file: string) => ({ file, line: 2 });
  const finding = (fingerprint: string, file: string, verdict: "needs_validation" | "rejected") => ({
    fingerprint,
    verdict,
    title: "DOM XSS via location.hash",
    description: `Hash flows into innerHTML. key ${SECRET}`,
    trace: [{ kind: "sink", scope: "render", description: "innerHTML", ...loc(file) }],
    evidence: [{ description: "sink", ...loc(file) }],
    ...(verdict === "needs_validation" ? { claimed_root_cause: "unsanitized", blockers: ["needs browser"] } : { claimed_root_cause: "x", reason: "sanitized" }),
  });
  const findingsPath = path.join(root, "findings.json");
  writeFileSync(
    findingsPath,
    JSON.stringify([finding("fp-app", "src/app.ts", "needs_validation"), finding("fp-env", ".env", "needs_validation"), finding("fp-rej", "src/app.ts", "rejected")]),
  );
  // The skill writes run-metadata.json beside findings.json; a completed audit keeps these tests focused on
  // redaction/egress behavior rather than the missing-metadata escalation (which gate.test.ts covers).
  writeFileSync(path.join(root, "run-metadata.json"), JSON.stringify({ run_status: "complete" }));
  return { root, findingsPath };
}

function mockSubq(probability: number, bodies: string[]): void {
  globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
    bodies.push(String(init?.body));
    return new Response(JSON.stringify({ answers: { exploitable: { type: "noul", noul: probability }, reachable: { type: "noul", noul: probability } } }), { status: 200 });
  }) as typeof fetch;
}

test("never sends secrets or sensitive files; withholds .env content", async () => {
  const { root, findingsPath } = fixture();
  const bodies: string[] = [];
  mockSubq(0.95, bodies);
  const report = await runAudit({ findingsPath, repoRoot: root, config, thresholds: loadThresholds({}) });

  assert.equal(bodies.length, 2); // rejected finding is not sent
  for (const body of bodies) {
    assert.ok(!body.includes(SECRET), "AWS key leaked");
    assert.ok(!body.includes("supersecretvalue123"), ".env content leaked");
  }
  assert.ok(bodies.join("").includes("[REDACTED:aws_access_key]"));
  assert.ok(bodies.join("").includes("WITHHELD"));
  assert.equal(report.action, "REQUEST_CHANGES");
  assert.equal(report.withheld, 1); // only the .env location; its trace and evidence entries dedupe to one
  assert.ok(!formatReport(report).includes(SECRET));
});

test("isRepoRelative accepts plain relative paths only", () => {
  for (const f of ["src/a.ts", "./src/a.ts", "../x/a.ts", "a.ts", "src\\a.ts"]) assert.ok(isRepoRelative(f), f);
  for (const f of ["/etc/x", "C:/x", "C:\\x", "c:x", "\\\\host\\share\\a.ts", "//host/share/a.ts", "\\\\?\\C:\\a", "\\rooted"]) assert.ok(!isRepoRelative(f), f);
});

test("SubQ failure fails closed to MANUAL_REVIEW", async () => {
  const { root, findingsPath } = fixture();
  globalThis.fetch = (async () => new Response(JSON.stringify({ detail: { error_type: "unauthorized" } }), { status: 401 })) as typeof fetch;
  const report = await runAudit({ findingsPath, repoRoot: root, config, thresholds: loadThresholds({}) });
  assert.equal(report.action, "MANUAL_REVIEW");
  assert.equal(report.subq.failed, 2);
});

test("symlink escaping repo_root is withheld", async (t) => {
  const { root, findingsPath } = fixture();
  const outside = mkdtempSync(path.join(os.tmpdir(), "subq-outside-"));
  writeFileSync(path.join(outside, "leak.ts"), "const topsecret = 1;\n");
  try {
    symlinkSync(path.join(outside, "leak.ts"), path.join(root, "src", "link.ts"));
  } catch {
    t.skip("symlinks not permitted on this system");
    return;
  }
  const raw = JSON.parse((await import("node:fs")).readFileSync(findingsPath, "utf8"));
  raw[0].trace[0].file = "src/link.ts";
  raw[0].evidence[0].file = "src/link.ts";
  writeFileSync(findingsPath, JSON.stringify(raw));
  const bodies: string[] = [];
  mockSubq(0.1, bodies);
  await runAudit({ findingsPath, repoRoot: root, config, thresholds: loadThresholds({}) });
  assert.ok(!bodies.join("").includes("topsecret"));
});
