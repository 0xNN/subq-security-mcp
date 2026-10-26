import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import type { Finding } from "./findings.js";
import { buildState, capText } from "./state.js";

const root = mkdtempSync(path.join(os.tmpdir(), "subq-state-"));
writeFileSync(path.join(root, ".env"), "FOO=bar123\n");
writeFileSync(path.join(root, "ok.ts"), "const marker = 'plain-source-line';\n");
writeFileSync(path.join(root, "notes.weird"), "weird-extension-content\n");
writeFileSync(path.join(root, "long.ts"), `${"x".repeat(900)}\nshort-line-marker\n`);
mkdirSync(path.join(root, "folder.ts"));

const finding = (file: string, description = "d"): Finding => ({
  verdict: "needs_validation",
  fingerprint: "t",
  title: "t",
  description,
  claimed_root_cause: "c",
  blockers: ["b"],
  trace: [{ kind: "sink", file, line: 1, scope: "s", description: "x" }],
  evidence: [{ file, line: 1, description: "x" }],
});

const sent = (file: string, needle: string): boolean => buildState(finding(file), root).state.includes(needle);

test("regular allowlisted source is sent (positive control)", () => {
  assert.ok(sent("ok.ts", "plain-source-line"));
});

test("sensitive files and Windows alias spellings are withheld", () => {
  for (const file of [".env", ".env::$DATA", ".env ", ".env.", "ENV~1", ".ENV"]) {
    assert.ok(!sent(file, "bar123"), `leaked via ${JSON.stringify(file)}`);
  }
  assert.ok(buildState(finding(".env::$DATA"), root).state.includes("WITHHELD"));
});

test("absolute, rooted, drive-qualified and UNC spellings are withheld before any filesystem call", () => {
  // Unresolvable hosts would stall on a real SMB attempt; a rejected spelling returns immediately.
  const spellings = ["\\\\203.0.113.7\\share\\a.ts", "//203.0.113.7/share/a.ts", "\\\\?\\C:\\x\\a.ts", "C:/x/a.ts", "C:\\x\\a.ts", "/etc/hosts.txt", "\\rooted\\a.ts"];
  for (const file of spellings) {
    const start = performance.now();
    const built = buildState(finding(file), root);
    assert.ok(built.state.includes("WITHHELD"), `not withheld: ${JSON.stringify(file)}`);
    assert.ok(performance.now() - start < 500, `slow, probably touched the filesystem or network: ${JSON.stringify(file)}`);
  }
  assert.ok(sent("ok.ts", "plain-source-line"), "relative paths still work");
});

test("unknown extensions and non-regular files are withheld", () => {
  assert.ok(!sent("notes.weird", "weird-extension-content"));
  const built = buildState(finding("folder.ts"), root);
  assert.ok(built.state.includes("WITHHELD"));
  assert.equal(built.withheld, 1);
});

test("overlong lines are replaced, never cut mid-token", () => {
  const { state } = buildState(finding("long.ts"), root);
  assert.ok(state.includes("[line too long: 900 chars]"));
  assert.ok(!state.includes("x".repeat(100)));
});

test("a huge finding description is capped before redaction and egress", () => {
  const { state } = buildState(finding("ok.ts", "word ".repeat(400_000)), root);
  assert.ok(state.length < 40_000, `state was ${state.length} chars`);
  assert.ok(state.includes("[TRUNCATED]"));
});

test("capText drops a trailing partial token", () => {
  const text = `${"ab ".repeat(8000)}${"A1b2".repeat(5000)}`;
  const capped = capText(text);
  assert.ok(capped.endsWith("[TRUNCATED]"));
  assert.ok(!capped.slice(0, -"\n[TRUNCATED]".length).endsWith("A1b2"));
  assert.equal(capText("short"), "short");
  assert.equal(capText("x".repeat(50_000)), "\n[TRUNCATED]");
});
