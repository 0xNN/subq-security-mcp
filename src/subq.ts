import { z } from "zod";

export interface SubqConfig {
  apiKey: string;
  baseUrl: string;
  model: string;
  /** Deadline for a single HTTP attempt. */
  timeoutMs: number;
  /** Deadline for one whole tool call: all findings, retries and backoff together. */
  totalTimeoutMs: number;
}

export class SubqError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

export interface NoulQuestion {
  instructions: string;
  criteria: { true: string; false: string };
}

const responseSchema = z.object({
  answers: z.record(z.string(), z.object({ type: z.string(), noul: z.number().min(0).max(1).optional() })),
});

const errorSchema = z.object({
  detail: z.object({ error_type: z.string().optional(), message: z.string().optional() }).optional(),
});

const RETRYABLE = new Set([429, 500, 502, 503, 504]);
const MAX_ATTEMPTS = 3;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): SubqConfig {
  const apiKey = env["SUBQ_API_KEY"];
  if (!apiKey) throw new SubqError("SUBQ_API_KEY belum di-set.");
  const timeoutMs = Number(env["SUBQ_TIMEOUT_MS"] ?? 30_000);
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1000) throw new SubqError("SUBQ_TIMEOUT_MS tidak valid.");
  const totalTimeoutMs = Number(env["SUBQ_TOTAL_TIMEOUT_MS"] ?? 120_000);
  if (!Number.isFinite(totalTimeoutMs) || totalTimeoutMs < 1000 || totalTimeoutMs > 1_800_000) {
    throw new SubqError("SUBQ_TOTAL_TIMEOUT_MS harus antara 1000 dan 1800000.");
  }
  return {
    apiKey,
    baseUrl: (env["SUBQ_BASE_URL"] ?? "https://api.subq.ai").replace(/\/+$/, ""),
    model: env["SUBQ_MODEL"] ?? "subq-snap-1.1",
    timeoutMs,
    totalTimeoutMs,
  };
}

/** Resolves after `ms`, or immediately when `signal` aborts, so backoff never outlives the call's deadline. */
const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => (clearTimeout(timer), resolve()), { once: true });
  });

export const INTERRUPTED = "dihentikan sebelum selesai (batas waktu total habis atau klien membatalkan).";

/**
 * Sends noul questions and returns the probability of "yes" per question. Never echoes state or keys in errors.
 * `signal` stops the call, including any retry wait, as soon as the whole tool call is cancelled or out of time.
 */
export async function askNoul(
  config: SubqConfig,
  state: string,
  questions: Record<string, NoulQuestion>,
  signal?: AbortSignal,
): Promise<Record<string, number>> {
  const body = JSON.stringify({
    model: config.model,
    state,
    questions: Object.fromEntries(Object.entries(questions).map(([name, q]) => [name, { type: "noul", ...q }])),
  });

  let lastError: SubqError = new SubqError("permintaan ke SubQ gagal.");
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    if (attempt > 0) await sleep(500 * 2 ** (attempt - 1), signal);
    if (signal?.aborted) throw new SubqError(INTERRUPTED);
    let response: Response;
    try {
      const attemptTimeout = AbortSignal.timeout(config.timeoutMs);
      response = await fetch(`${config.baseUrl}/v1/systemone`, {
        method: "POST",
        headers: { Authorization: `Bearer ${config.apiKey}`, "Content-Type": "application/json" },
        body,
        signal: signal ? AbortSignal.any([attemptTimeout, signal]) : attemptTimeout,
      });
    } catch (error) {
      if (signal?.aborted) throw new SubqError(INTERRUPTED);
      lastError = new SubqError(error instanceof Error && error.name === "TimeoutError" ? "timeout menghubungi SubQ." : "gagal terhubung ke SubQ.");
      continue;
    }

    if (!response.ok) {
      const parsed = errorSchema.safeParse(await response.json().catch(() => undefined));
      const type = parsed.success ? parsed.data.detail?.error_type : undefined;
      lastError = new SubqError(`SubQ HTTP ${response.status}${type ? ` (${type})` : ""}`, response.status);
      if (RETRYABLE.has(response.status)) continue;
      throw lastError;
    }

    const parsed = responseSchema.safeParse(await response.json().catch(() => undefined));
    if (!parsed.success) throw new SubqError("respons SubQ tidak sesuai kontrak.");
    const result: Record<string, number> = {};
    for (const name of Object.keys(questions)) {
      const answer = parsed.data.answers[name];
      if (answer?.type !== "noul" || answer.noul === undefined) throw new SubqError(`jawaban SubQ untuk ${name} hilang.`);
      result[name] = answer.noul;
    }
    return result;
  }
  throw lastError;
}
