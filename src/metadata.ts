import { readFileSync, statSync } from "node:fs";
import path from "node:path";
import { z } from "zod";

/** What `run-metadata.json` (written by the security-audit skill next to findings.json) says about the audit run. */
export type AuditStatus = "complete" | "incomplete" | "missing" | "unreadable";

const MAX_BYTES = 1024 * 1024;
const schema = z.object({ run_status: z.string() });

/**
 * An empty findings.json is only meaningful if the audit actually finished. The skill records that in
 * run-metadata.json beside findings.json; without it, "no findings" cannot be told apart from "audit never ran".
 */
export function readAuditStatus(findingsPath: string): AuditStatus {
  const file = path.join(path.dirname(findingsPath), "run-metadata.json");
  let size: number;
  try {
    const stat = statSync(file);
    if (!stat.isFile()) return "unreadable";
    size = stat.size;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT" ? "missing" : "unreadable";
  }
  if (size > MAX_BYTES) return "unreadable";
  try {
    const parsed = schema.safeParse(JSON.parse(readFileSync(file, "utf8")));
    if (!parsed.success) return "unreadable";
    return parsed.data.run_status === "complete" ? "complete" : "incomplete";
  } catch {
    return "unreadable";
  }
}
