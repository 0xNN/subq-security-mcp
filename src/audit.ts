import { aggregate, decideFinding, maxAction, type Action, type FindingDecision, type Thresholds } from "./decision.js";
import { loadFindings } from "./findings.js";
import { readAuditStatus, type AuditStatus } from "./metadata.js";
import { mergeCounts } from "./redact.js";
import { buildState } from "./state.js";
import { askNoul, type SubqConfig } from "./subq.js";

const CONCURRENCY = 4;

export interface AuditReport {
  action: Action;
  decisions: FindingDecision[];
  counts: { confirmed: number; needs_validation: number; rejected: number };
  subq: { ok: number; failed: number; skipped: number };
  redactions: Record<string, number>;
  withheld: number;
  warnings: string[];
  audit: AuditStatus;
  /** Why the gate is stricter than the per-finding policy alone would be. */
  reasons: string[];
}

export interface AuditOptions {
  findingsPath: string;
  repoRoot: string;
  config: SubqConfig;
  thresholds: Thresholds;
  /** Aborts the whole call (the MCP client cancelled or gave up). */
  signal?: AbortSignal;
}

export async function runAudit({ findingsPath, repoRoot, config, thresholds, signal }: AuditOptions): Promise<AuditReport> {
  // One deadline for the entire call, plus client cancellation. Both stop in-flight requests and retry waits.
  const deadline = AbortSignal.timeout(config.totalTimeoutMs);
  const stop = signal ? AbortSignal.any([deadline, signal]) : deadline;
  const { findings, warnings } = await loadFindings(findingsPath);
  const counts = { confirmed: 0, needs_validation: 0, rejected: 0 };
  const redactions: Record<string, number> = {};
  const decisions: FindingDecision[] = [];
  let withheld = 0;
  let ok = 0;
  let failed = 0;
  let skipped = 0;

  const evaluate = async (finding: (typeof findings)[number]): Promise<FindingDecision> => {
    counts[finding.verdict]++;
    if (finding.verdict === "rejected") return decideFinding(finding, undefined, thresholds);
    if (stop.aborted) {
      skipped++;
      return decideFinding(finding, undefined, thresholds);
    }
    const built = buildState(finding, repoRoot);
    mergeCounts(redactions, built.redactions);
    withheld += built.withheld;
    try {
      const answers = await askNoul(config, built.state, built.questions, stop);
      ok++;
      return decideFinding(finding, { exploitable: answers["exploitable"] ?? 0, reachable: answers["reachable"] ?? 0 }, thresholds);
    } catch (error) {
      if (stop.aborted) {
        skipped++;
        return decideFinding(finding, undefined, thresholds);
      }
      failed++;
      console.error(`SubQ gagal untuk ${finding.fingerprint}: ${error instanceof Error ? error.message : "unknown"}`);
      return decideFinding(finding, undefined, thresholds);
    }
  };

  for (let i = 0; i < findings.length; i += CONCURRENCY) {
    decisions.push(...(await Promise.all(findings.slice(i, i + CONCURRENCY).map(evaluate))));
  }

  const audit = readAuditStatus(findingsPath);
  const active = counts.confirmed + counts.needs_validation;
  const reasons: string[] = [];
  if (skipped > 0) {
    reasons.push(
      deadline.aborted
        ? `Batas waktu total ${Math.round(config.totalTimeoutMs / 1000)} detik habis; ${skipped} temuan tidak sempat dinilai SubQ.`
        : `Panggilan dibatalkan oleh klien; ${skipped} temuan tidak sempat dinilai SubQ.`,
    );
  }
  let action = aggregate(decisions);
  if (audit === "incomplete") {
    action = maxAction(action, "MANUAL_REVIEW");
    reasons.push("run-metadata.json menyatakan audit belum selesai (run_status bukan 'complete'); hasil temuan belum lengkap.");
  } else if (audit !== "complete") {
    // Missing or unreadable metadata means we cannot tell a clean audit from one that never ran,
    // so we never let it lower the gate regardless of how many findings are active.
    action = maxAction(action, "MANUAL_REVIEW");
    reasons.push(
      audit === "missing"
        ? "run-metadata.json tidak ditemukan di folder findings.json; tidak bisa dibedakan antara 'audit bersih' dan 'audit tidak pernah berjalan' atau file kedaluwarsa."
        : "run-metadata.json tidak dapat dibaca atau tidak valid; status audit tidak dapat dipastikan.",
    );
  }
  return { action, decisions, counts, subq: { ok, failed, skipped }, redactions, withheld, warnings, audit, reasons };
}

const oneLine = (text: string, max = 120): string => text.replaceAll(/\s+/g, " ").trim().slice(0, max);

const INSTRUCTIONS: Record<Action, string> = {
  BLOCK: 'Tulis "❌ PULL REQUEST DIBLOKIR KARENA ALASAN KEAMANAN" dengan huruf kapital, lalu sebutkan temuan berstatus BLOCK. Jangan sarankan merge.',
  MANUAL_REVIEW: "Jangan menyatakan PR aman dan jangan sarankan merge. Minta reviewer manusia memeriksa temuan MANUAL_REVIEW dan alasan gerbang di atas, lalu pastikan audit benar-benar dijalankan sampai selesai.",
  REQUEST_CHANGES: "Minta perbaikan untuk temuan REQUEST_CHANGES sebelum merge. Jangan menyatakan PR aman.",
  APPROVE: "Tidak ada temuan yang memerlukan tindakan menurut kebijakan ini. Ini bukan bukti kode bebas celah; sampaikan apa adanya lalu persilakan pengguna memutuskan merge.",
};

export function formatReport(report: AuditReport): string {
  const lines = [
    "=== KEPUTUSAN SUBQ GATEKEEPER ===",
    `Tindakan Wajib: ${report.action}`,
    `Temuan: confirmed=${report.counts.confirmed}, needs_validation=${report.counts.needs_validation}, rejected=${report.counts.rejected}`,
    `Status audit (run-metadata.json): ${report.audit}`,
    `SubQ: ${report.subq.ok} berhasil, ${report.subq.failed} gagal, ${report.subq.skipped} dilewati`,
    `Redaksi sebelum kirim: ${Object.entries(report.redactions).map(([k, v]) => `${k}=${v}`).join(", ") || "tidak ada"}; lokasi ditahan=${report.withheld} (nilai rahasia tidak pernah dikirim atau dicatat)`,
    "",
    ...report.decisions
      .filter((d) => d.verdict !== "rejected")
      .map((d) => {
        const p = d.probabilities ? ` P(exploit)=${d.probabilities.exploitable.toFixed(2)} P(reach)=${d.probabilities.reachable.toFixed(2)}` : "";
        const sev = d.severity ? `/${d.severity}` : "";
        return `- [${d.action}] ${oneLine(d.fingerprint, 60)} (${d.verdict}${sev})${p} ${oneLine(d.title)}${d.note ? ` -- ${d.note}` : ""}`;
      }),
    ...report.reasons.map((r) => `Alasan gerbang: ${r}`),
    ...report.warnings.map((w) => `Peringatan: ${w}`),
    "",
    "Hasil ini bersifat advisory (probabilitas model, bukan bukti).",
    `INSTRUKSI UNTUK AI AGENT: ${INSTRUCTIONS[report.action]}`,
    "=================================",
  ];
  return lines.join("\n");
}
