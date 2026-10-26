#!/usr/bin/env node
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { formatReport, runAudit } from "./audit.js";
import { loadThresholds } from "./decision.js";
import { loadConfig } from "./subq.js";

const server = new McpServer({ name: "SubQ-Security-Gatekeeper", version: "2.0.0" });

const failClosed = (reason: string) => ({
  content: [
    {
      type: "text" as const,
      text: `Gagal mengevaluasi audit: ${reason}\nINSTRUKSI UNTUK AI AGENT: Jangan menyatakan PR aman dan jangan sarankan merge sampai evaluasi berhasil dijalankan.`,
    },
  ],
  isError: true,
});

server.registerTool(
  "subq_evaluate_audit",
  {
    description:
      "WAJIB dipanggil SETELAH skill security-audit Cloudflare selesai menulis findings.json. Tool membaca findings.json dari disk (bukan dari teks agen), mengirim potongan kode yang sudah diredaksi ke SubQ, lalu memberi keputusan final: APPROVE, REQUEST_CHANGES, MANUAL_REVIEW, atau BLOCK.",
    inputSchema: {
      findings_path: z.string().min(1).optional().describe("Path ke findings.json. Default: <repo_root>/findings.json."),
      repo_root: z.string().min(1).optional().describe("Root repo yang diaudit. Default: SUBQ_REPO_ROOT atau direktori kerja."),
    },
  },
  async ({ findings_path, repo_root }, extra) => {
    try {
      const repoRoot = path.resolve(repo_root ?? process.env["SUBQ_REPO_ROOT"] ?? process.cwd());
      const findingsPath = path.resolve(repoRoot, findings_path ?? "findings.json");
      const report = await runAudit({ findingsPath, repoRoot, config: loadConfig(), thresholds: loadThresholds(), signal: extra.signal });
      return { content: [{ type: "text" as const, text: formatReport(report) }] };
    } catch (error) {
      return failClosed(error instanceof Error ? error.message : "kesalahan tidak dikenal");
    }
  },
);

await server.connect(new StdioServerTransport());
