export interface Redaction {
  text: string;
  counts: Record<string, number>;
}

type Replacer = (match: string, g1: string, g2: string, g3: string) => string | undefined;

interface Rule {
  name: string;
  pattern: RegExp;
  replace: Replacer;
}

const placeholder = (name: string): string => `[REDACTED:${name}]`;

// Every quantifier that can restart at many positions is bounded; unbounded ones made redact() quadratic on long runs.
const KEY = String.raw`\b[\w.-]{0,64}(?:secret|passw(?:or)?d|pwd|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization)[\w.-]{0,64}["']?`;
const TYPE_WORDS = /^(?:string|number|boolean|any|unknown|null|undefined|true|false|none|nil|void)$/i;
const DOTTED_IDENTIFIER = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/;

export function shannonEntropy(value: string): number {
  const freq = new Map<string, number>();
  for (const ch of value) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const n of freq.values()) {
    const p = n / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const RULES: Rule[] = [
  {
    name: "private_key",
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g,
    replace: () => placeholder("private_key"),
  },
  {
    name: "aws_access_key",
    pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b/g,
    replace: () => placeholder("aws_access_key"),
  },
  {
    name: "github_token",
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g,
    replace: () => placeholder("github_token"),
  },
  {
    name: "slack_token",
    pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
    replace: () => placeholder("slack_token"),
  },
  {
    name: "api_key",
    pattern: /\b(?:(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})\b/g,
    replace: () => placeholder("api_key"),
  },
  {
    name: "jwt",
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    replace: () => placeholder("jwt"),
  },
  {
    name: "auth_header",
    pattern: /\b(Bearer|Basic)(\s{1,16})([A-Za-z0-9._~+/=-]{16,})/g,
    replace: (_m, scheme, space, token) =>
      /\d/.test(token) ? `${scheme}${space}${placeholder("auth_header")}` : undefined,
  },
  {
    name: "url_credentials",
    pattern: /\b([a-z][a-z0-9+.-]{0,31}:\/\/)[^\s:/@]{1,256}:[^\s@/]{1,256}@/gi,
    replace: (_m, scheme) => `${scheme}${placeholder("url_credentials")}@`,
  },
  {
    name: "secret_assignment",
    pattern: new RegExp(String.raw`(${KEY}\s{0,16}[:=]\s{0,16})(["'\`])(?!\[REDACTED)([^"'\`\n]{4,})\2`, "gi"),
    replace: (_m, prefix, quote) => `${prefix}${quote}${placeholder("secret_assignment")}${quote}`,
  },
  {
    name: "secret_assignment",
    pattern: new RegExp(String.raw`(${KEY}\s{0,16}[:=]\s{0,16})(?!\[REDACTED)([^\s"'\`,;()}\]]{6,})`, "gi"),
    replace: (_m, prefix, value) =>
      TYPE_WORDS.test(value) || DOTTED_IDENTIFIER.test(value)
        ? undefined
        : `${prefix}${placeholder("secret_assignment")}`,
  },
  {
    name: "high_entropy",
    pattern: /[A-Za-z0-9+/_=-]{32,}/g,
    replace: (token) => {
      if (token.startsWith("[REDACTED")) return undefined;
      const hex = /^[0-9a-f]{32,}$/i.test(token);
      const mixed = /[a-z]/.test(token) && /[A-Z]/.test(token) && /\d/.test(token);
      const entropy = shannonEntropy(token);
      if ((hex && entropy >= 3) || (mixed && entropy >= 4)) return placeholder("high_entropy");
      return undefined;
    },
  },
  {
    name: "email",
    pattern: /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}/g,
    replace: () => placeholder("email"),
  },
];

/** Replaces anything that looks like a secret or PII; matched values are never kept or logged. */
export function redact(input: string): Redaction {
  const counts: Record<string, number> = {};
  let text = input;
  for (const rule of RULES) {
    text = text.replace(rule.pattern, (...args: unknown[]) => {
      const [match, g1, g2, g3] = args as [string, string, string, string];
      const out = rule.replace(match, g1, g2, g3);
      if (out === undefined) return match;
      counts[rule.name] = (counts[rule.name] ?? 0) + 1;
      return out;
    });
  }
  return { text, counts };
}

export function mergeCounts(into: Record<string, number>, from: Record<string, number>): void {
  for (const [name, n] of Object.entries(from)) into[name] = (into[name] ?? 0) + n;
}

const SENSITIVE_BASENAME = [
  /^\.env(?:\..*)?$/i,
  /^\.(?:npmrc|netrc|pypirc|git-credentials|htpasswd)$/i,
  /^id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/i,
  /^(?:credentials?|secrets?)(?:\.(?:json|ya?ml|toml|ini|txt))?$/i,
  /\.(?:pem|key|p12|pfx|jks|keystore|kdbx|ppk|tfstate)$/i,
];

/** Files whose content is never read, regardless of redaction. */
export function isSensitivePath(file: string): boolean {
  const base = file.split(/[\\/]/).pop() ?? file;
  return SENSITIVE_BASENAME.some((re) => re.test(base));
}

const ALLOWED_EXTENSIONS = new Set(
  ("ts tsx mts cts js jsx mjs cjs py rb go rs java kt kts scala cs php swift c h cc cpp cxx hpp m mm sh bash zsh ps1 " +
    "sql html htm css scss vue svelte json yaml yml toml xml gradle tf md txt proto graphql lua pl dart ex exs").split(" "),
);
const ALLOWED_BASENAMES = new Set(["dockerfile", "makefile"]);

/** Default-deny: only recognised source and doc files may be read; the denylist above stays as a second layer. */
export function isAllowedSourceFile(file: string): boolean {
  const base = (file.split(/[\\/]/).pop() ?? file).toLowerCase();
  if (ALLOWED_BASENAMES.has(base)) return true;
  const dot = base.lastIndexOf(".");
  return dot > 0 && ALLOWED_EXTENSIONS.has(base.slice(dot + 1));
}

/** Windows spellings that name a file indirectly: alternate data streams (':'), 8.3 short names ('~1'), trailing dot or space. */
export function hasAliasSyntax(file: string): boolean {
  return file.split(/[\\/]/).some((part) => {
    if (part === "." || part === "..") return false;
    const stream = part.includes(":") && !/^[A-Za-z]:$/.test(part);
    return stream || /~\d/.test(part) || /[. ]$/.test(part);
  });
}
