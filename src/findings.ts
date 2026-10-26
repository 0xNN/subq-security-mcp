import { execFile } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { z } from "zod";

const execFileAsync = promisify(execFile);

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_FINDINGS = 500;

const traceStep = z.object({
  kind: z.enum(["entrypoint", "propagation", "sink"]),
  file: z.string().min(1),
  line: z.number().int().min(1),
  scope: z.string(),
  description: z.string(),
});

const evidence = z.object({
  file: z.string().min(1),
  line: z.number().int().min(1),
  description: z.string(),
});

const base = {
  fingerprint: z.string().min(1),
  title: z.string().min(1),
  description: z.string().min(1),
  trace: z.array(traceStep).min(1),
  evidence: z.array(evidence).min(1),
};

const severityScore = z.enum(["informational", "low", "medium", "high", "critical"]);

const confirmed = z.object({
  ...base,
  verdict: z.literal("confirmed"),
  root_cause: z.string(),
  intended_behavior: z.string(),
  conditions: z.array(z.object({ kind: z.string(), description: z.string() })),
  execution: z.object({
    attacker_perspective: z.string(),
    payloads: z.array(z.string()).min(1),
    instructions: z.array(z.string()).min(1),
    observed_result: z.string(),
  }),
  severity: z.object({ overall_severity: severityScore }),
  confidence: z.object({ score: z.enum(["low", "medium", "high"]), reason: z.string() }),
});

const needsValidation = z.object({
  ...base,
  verdict: z.literal("needs_validation"),
  claimed_root_cause: z.string(),
  blockers: z.array(z.string()).min(1),
});

const rejected = z.object({
  ...base,
  verdict: z.literal("rejected"),
  claimed_root_cause: z.string(),
  reason: z.string(),
});

const findingSchema = z.discriminatedUnion("verdict", [confirmed, needsValidation, rejected]);
const findingsSchema = z.array(findingSchema).max(MAX_FINDINGS);

export type Finding = z.infer<typeof findingSchema>;
export type ConfirmedFinding = z.infer<typeof confirmed>;
export type NeedsValidationFinding = z.infer<typeof needsValidation>;
export type Severity = z.infer<typeof severityScore>;

export interface LoadedFindings {
  findings: Finding[];
  warnings: string[];
}

function validatorCandidates(): string[] {
  const fromEnv = process.env["SUBQ_VALIDATOR_PATH"];
  const home = os.homedir();
  return [
    ...(fromEnv ? [fromEnv] : []),
    path.join(home, ".agents", "skills", "security-audit", "validate-findings.cjs"),
    path.join(home, ".claude", "skills", "security-audit", "validate-findings.cjs"),
  ];
}

/** Runs the Cloudflare skill's own validator when it is installed; zod still enforces the fields we rely on. */
async function runSkillValidator(findingsPath: string): Promise<string | undefined> {
  if (process.env["SUBQ_VALIDATOR_PATH"] === "off") return "validator skill dimatikan (SUBQ_VALIDATOR_PATH=off); hanya validasi bawaan yang dipakai.";
  const validator = validatorCandidates().find((p) => existsSync(p));
  if (!validator) return "validate-findings.cjs dari skill security-audit tidak ditemukan; hanya validasi bawaan yang dipakai.";
  try {
    await execFileAsync(process.execPath, [validator, findingsPath], { timeout: 30_000, windowsHide: true });
    return undefined;
  } catch (error) {
    const { stdout = "", stderr = "" } = error as { stdout?: string; stderr?: string };
    const output = `${stdout}\n${stderr}`.trim();
    // The validator refuses to run on platforms without O_NOFOLLOW (e.g. Windows); that is not a verdict on the file.
    if (output.includes("protection is unavailable")) {
      return "validator skill tidak bisa berjalan di OS ini (butuh no-follow I/O); hanya validasi bawaan yang dipakai.";
    }
    throw new Error(`findings.json ditolak validator skill: ${output.slice(0, 500) || "exit non-zero"}`);
  }
}

export async function loadFindings(findingsPath: string): Promise<LoadedFindings> {
  const stat = statSync(findingsPath);
  if (!stat.isFile()) throw new Error("findings_path harus berupa file biasa.");
  const size = stat.size;
  if (size > MAX_FILE_BYTES) throw new Error(`findings.json terlalu besar (${size} byte, maks ${MAX_FILE_BYTES}).`);

  const warnings: string[] = [];
  const validatorWarning = await runSkillValidator(findingsPath);
  if (validatorWarning) warnings.push(validatorWarning);

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(findingsPath, "utf8"));
  } catch {
    throw new Error("findings.json bukan JSON yang valid.");
  }
  const parsed = findingsSchema.safeParse(raw);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    throw new Error(`findings.json tidak sesuai skema: ${first?.path.join(".") ?? "?"}: ${first?.message ?? "invalid"}`);
  }
  return { findings: parsed.data, warnings };
}
