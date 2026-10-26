import assert from "node:assert/strict";
import { test } from "node:test";
import { hasAliasSyntax, isAllowedSourceFile, isSensitivePath, redact } from "./redact.js";

const fake = {
  aws: "AKIA" + "ABCDEFGHIJKLMNOP",
  gh: "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
  jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123ghiJKL456",
};

test("redacts well-known credential shapes", () => {
  const input = [`const k = "${fake.aws}";`, `auth(${fake.gh})`, `jwt=${fake.jwt}`, "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"].join("\n");
  const { text, counts } = redact(input);
  for (const secret of [fake.aws, fake.gh, fake.jwt, "MIIabc"]) assert.ok(!text.includes(secret), `leaked ${secret}`);
  assert.ok(counts["private_key"] && counts["aws_access_key"] && counts["github_token"] && counts["jwt"]);
});

test("redacts assignments and url credentials but keeps code references", () => {
  const { text } = redact(`password = "hunter2hunter2"\nDB=postgres://admin:s3cretPw@db.local/app\napiKey: process.env.API_KEY\ntoken: string`);
  assert.ok(!text.includes("hunter2hunter2"));
  assert.ok(!text.includes("s3cretPw"));
  assert.ok(text.includes("process.env.API_KEY"));
  assert.ok(text.includes("token: string"));
});

test("redacts high-entropy blobs and emails, leaves ordinary prose", () => {
  const blob = "Zk9fQ2x1dGVyUmFuZG9tU2VjcmV0MTIzNDU2Nzg5MEFiQ2RF";
  const { text } = redact(`x ${blob} contact alice@example.com for the user input handler`);
  assert.ok(!text.includes(blob) && !text.includes("alice@example.com"));
  assert.ok(text.includes("user input handler"));
});

test("is idempotent", () => {
  const once = redact(`token = "abcdefghijk123"`).text;
  assert.equal(redact(once).text, once);
});

test("redact stays linear on long adversarial runs", () => {
  // Before the quantifier bounds these took 3-30s at 40-160 KB (quadratic).
  const inputs = ["a".repeat(200_000), "a.".repeat(100_000), "a-".repeat(100_000), "secret".repeat(33_000)];
  for (const input of inputs) {
    const start = performance.now();
    redact(input);
    const ms = performance.now() - start;
    assert.ok(ms < 1500, `redact took ${Math.round(ms)}ms on ${input.length} chars`);
  }
});

test("bounded quantifiers still redact secrets next to long keys", () => {
  const { text } = redact(`some_very_long_prefix_secret_key_name = "hunter2hunter2" and mail bob@example.com`);
  assert.ok(!text.includes("hunter2hunter2") && !text.includes("bob@example.com"));
});

test("allowlist is default-deny and alias spellings are rejected", () => {
  for (const f of ["src/a.ts", "lib/B.PY", "Dockerfile", "docs/readme.md"]) assert.ok(isAllowedSourceFile(f), f);
  for (const f of [".env", "x.pem", "notes.weird", "binary", "id_rsa", "a.tfvars"]) assert.ok(!isAllowedSourceFile(f), f);
  for (const f of [".env::$DATA", "a.ts::$DATA", "ENV~1", "src/PROGRA~1/a.ts", ".env ", ".env.", "dir /a.ts"]) assert.ok(hasAliasSyntax(f), f);
  for (const f of ["src/a.ts", "./src/a.ts", "../x/a.ts", "C:/repo/a.ts", "C:\\repo\\a.ts"]) assert.ok(!hasAliasSyntax(f), f);
});

test("flags sensitive file names", () => {
  for (const f of [".env", ".env.production", "certs/server.pem", "id_rsa", "config/secrets.yaml", "a/b/terraform.tfstate"]) {
    assert.ok(isSensitivePath(f), f);
  }
  for (const f of ["src/app.ts", "environment.ts", "README.md"]) assert.ok(!isSensitivePath(f), f);
});
