import type { Finding, Severity } from "./findings.js";

export type Action = "APPROVE" | "REQUEST_CHANGES" | "MANUAL_REVIEW" | "BLOCK";

const RANK: Record<Action, number> = { APPROVE: 0, REQUEST_CHANGES: 1, MANUAL_REVIEW: 2, BLOCK: 3 };

export interface Thresholds {
  /** P(exploitable) at or above which an unconfirmed finding requires changes. */
  exploit: number;
  /** P(exploitable) at or above which an unconfirmed finding needs a human look. */
  review: number;
  /** P(reachable by untrusted input) required together with `exploit`. */
  reach: number;
}

export interface Probabilities {
  exploitable: number;
  reachable: number;
}

export interface FindingDecision {
  fingerprint: string;
  title: string;
  verdict: Finding["verdict"];
  severity?: Severity;
  probabilities?: Probabilities;
  action: Action;
  note?: string;
}

export function loadThresholds(env: NodeJS.ProcessEnv = process.env): Thresholds {
  const read = (name: string, fallback: number): number => {
    const value = Number(env[name] ?? fallback);
    if (!Number.isFinite(value) || value < 0 || value > 1) throw new Error(`${name} harus di antara 0 dan 1.`);
    return value;
  };
  const t = { exploit: read("SUBQ_EXPLOIT_THRESHOLD", 0.8), review: read("SUBQ_REVIEW_THRESHOLD", 0.4), reach: read("SUBQ_REACH_THRESHOLD", 0.5) };
  if (t.review > t.exploit) throw new Error("SUBQ_REVIEW_THRESHOLD tidak boleh lebih besar dari SUBQ_EXPLOIT_THRESHOLD.");
  return t;
}

export function maxAction(a: Action, b: Action): Action {
  return RANK[a] >= RANK[b] ? a : b;
}

/**
 * Deterministic policy. SubQ probabilities can raise or flag a finding but never lower a confirmed one,
 * and a missing probability can never produce APPROVE for an unconfirmed finding.
 */
export function decideFinding(finding: Finding, probabilities: Probabilities | undefined, t: Thresholds): FindingDecision {
  const common = { fingerprint: finding.fingerprint, title: finding.title, verdict: finding.verdict };
  const withProbs = probabilities ? { probabilities } : {};

  if (finding.verdict === "rejected") return { ...common, action: "APPROVE", note: "ditolak saat validasi" };

  if (finding.verdict === "confirmed") {
    const severity = finding.severity.overall_severity;
    const action: Action =
      severity === "critical" || severity === "high" ? "BLOCK" : severity === "medium" ? "REQUEST_CHANGES" : "APPROVE";
    const disagrees = probabilities !== undefined && probabilities.exploitable < t.review && action !== "APPROVE";
    return {
      ...common,
      ...withProbs,
      severity,
      action,
      ...(disagrees ? { note: "SubQ tidak setuju (probabilitas rendah); verifikasi manual, keputusan tetap dipertahankan" } : {}),
    };
  }

  if (!probabilities) return { ...common, action: "MANUAL_REVIEW", note: "SubQ tidak tersedia; tidak bisa di-approve otomatis" };
  if (probabilities.exploitable >= t.exploit && probabilities.reachable >= t.reach) {
    return { ...common, ...withProbs, action: "REQUEST_CHANGES" };
  }
  if (probabilities.exploitable >= t.review) return { ...common, ...withProbs, action: "MANUAL_REVIEW" };
  return { ...common, ...withProbs, action: "APPROVE", note: "probabilitas rendah, tetap perlu divalidasi" };
}

export function aggregate(decisions: FindingDecision[]): Action {
  return decisions.reduce<Action>((acc, d) => maxAction(acc, d.action), "APPROVE");
}
