import { basename } from 'node:path';
import { GITLEAKS_RULES } from '../vendor/gitleaks/rules.js';
import { shannonEntropy } from './entropy.js';
import type { Finding } from '../types.js';

/**
 * Masks credential values in every finding, whichever rule produced it.
 *
 * CTS030 has always redacted the key it reports. Nothing else did: CTS031 on a
 * `NEXT_PUBLIC_…_SECRET` line, and a dozen vendored community rules (VG003,
 * VG603, …) quote the offending line verbatim, so the same key CTS030 printed
 * as `sk-proj-…EfGh` was printed in full two lines further down — in the
 * terminal, the JSON, the PR comment and the fix prompt. And CTS030 itself
 * printed any value of 14 characters or fewer whole.
 *
 * So this runs once, after every scanner, on every finding: it finds the
 * credential-shaped values on each finding's source line (and in its own
 * snippet and detail), and masks each one everywhere it appears in any finding
 * for that file.
 */

/** Credential shapes worth masking wherever they appear. Mirrors secrets.ts. */
const BUILTIN: RegExp[] = [
  /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /\bsb_secret_[A-Za-z0-9_-]{16,}/g,
  /\bsk-(?:proj-|svcacct-|ant-)?[A-Za-z0-9_-]{24,}/g,
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
  /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/g,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g,
  /\bnpm_[A-Za-z0-9]{36}\b/g,
];

/** `scheme://user:password@host` — the password part. */
const URL_PASSWORD = /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:@/'"`]{1,200}:([^\s@/'"`]{1,200})@/gi;

/** A name that says its value is a credential. */
const SECRET_NAME =
  String.raw`[A-Za-z0-9_.-]{0,60}(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|apikey|private[_-]?key|access[_-]?key|credential|auth[_-]?key|signing[_-]?key)[A-Za-z0-9_.-]{0,60}`;

/** `password: "…"`, `API_KEY = '…'`: a quoted literal assigned to a credential name. */
const QUOTED_ASSIGNMENT = new RegExp(
  `${SECRET_NAME}["'\`]?[ \\t]*(?::|=|=>|:=)[ \\t]*(["'\`])([^"'\`\\s]{6,200})\\1`,
  'gi',
);

/** `API_KEY=value` in an env-style file, where values are not quoted. */
const ENV_ASSIGNMENT = new RegExp(`^[ \\t]*(?:export[ \\t]+)?${SECRET_NAME}[ \\t]*[=:][ \\t]*([^\\s"'\`#]{6,200})`, 'gim');

/** Files where `NAME=value` with no quotes is an assignment. */
function envStyle(file: string): boolean {
  const base = basename(file);
  return /^\.env/.test(base) || /\.(env|toml|ya?ml|tfvars|properties|ini|cfg|conf)$/i.test(base) || base === '.npmrc';
}

/** Gitleaks rules that match things which are not credentials often enough to hurt snippets. */
const NOISY = new Set(['sourcegraph-access-token', 'generic-api-key']);

/** Longest text a detector is run over: a minified line can be megabytes. */
const MAX_TEXT = 8192;

/**
 * The masked form of a credential. Long values keep a short prefix — usually
 * just the provider's (`sk-proj-`) — and the last few characters, the same
 * `prefix…last4` shape CTS030 has always used for a typical key, but never
 * more than three-eighths of any value. Short values show only a prefix.
 */
export function maskSecret(value: string): string {
  if (value.length > 14) {
    const pre = Math.min(8, Math.floor(value.length / 4));
    const suf = Math.min(4, Math.floor(value.length / 8));
    return `${value.slice(0, pre)}\u2026${value.slice(-suf)}`;
  }
  const pre = Math.min(4, Math.floor(value.length / 4));
  return `${value.slice(0, pre)}\u2026`;
}

/** Every credential-shaped value in `text`. */
export function findSecretValues(text: string, file = ''): string[] {
  const out = new Set<string>();
  const src = text.length > MAX_TEXT ? text.slice(0, MAX_TEXT) : text;
  const add = (v: string | undefined) => {
    if (v && v.length >= 6 && !v.includes('\u2026')) out.add(v);
  };
  for (const re of BUILTIN) {
    re.lastIndex = 0;
    for (const m of src.matchAll(re)) add(m[0]);
  }
  URL_PASSWORD.lastIndex = 0;
  for (const m of src.matchAll(URL_PASSWORD)) add(m[1]);
  QUOTED_ASSIGNMENT.lastIndex = 0;
  for (const m of src.matchAll(QUOTED_ASSIGNMENT)) add(m[2]);
  if (envStyle(file)) {
    ENV_ASSIGNMENT.lastIndex = 0;
    for (const m of src.matchAll(ENV_ASSIGNMENT)) add(m[1]);
  }
  const lower = src.toLowerCase();
  for (const rule of GITLEAKS_RULES) {
    if (NOISY.has(rule.id)) continue;
    if (rule.keywords.length > 0 && !rule.keywords.some((k) => lower.includes(k))) continue;
    rule.pattern.lastIndex = 0;
    let g: RegExpExecArray | null;
    let guard = 0;
    while ((g = rule.pattern.exec(src)) !== null && guard++ < 20) {
      if (g[0].length === 0) {
        rule.pattern.lastIndex++;
        continue;
      }
      const secret = g[1] ?? g[0];
      if (rule.entropy !== null && shannonEntropy(secret) < rule.entropy) continue;
      add(secret);
    }
    rule.pattern.lastIndex = 0;
  }
  return [...out];
}

/** Replaces each value in `text` by its masked form, longest value first. */
export function maskValues(text: string, values: readonly string[]): string {
  let out = text;
  for (const v of values) {
    if (out.includes(v)) out = out.split(v).join(maskSecret(v));
  }
  // A snippet cut at 160 characters can end part-way into a value, which the
  // exact replacement above cannot see. Mask that tail too.
  const cut = /(\.\.\.|\u2026)$/.exec(out);
  if (cut) {
    const body = out.slice(0, -cut[0].length);
    for (const v of values) {
      for (let k = v.length - 1; k >= 6; k--) {
        if (body.endsWith(v.slice(0, k))) {
          return body.slice(0, body.length - k) + maskSecret(v.slice(0, k)) + cut[0];
        }
      }
    }
  }
  return out;
}

function maskDeep(value: unknown, values: readonly string[], depth: number): unknown {
  if (typeof value === 'string') return maskValues(value, values);
  if (depth <= 0 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((v) => maskDeep(v, values, depth - 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) out[k] = maskDeep(v, values, depth - 1);
  return out;
}

/**
 * Returns the findings with every credential value masked. `sourceLine(file,
 * line)` supplies the raw source line a finding points at, or null.
 */
export function redactFindings(
  findings: readonly Finding[],
  sourceLine: (file: string, line: number) => string | null,
): Finding[] {
  const byFile = new Map<string, Set<string>>();
  const collect = (f: Finding) => {
    const key = f.file ?? '';
    let set = byFile.get(key);
    if (!set) byFile.set(key, (set = new Set()));
    const texts = [f.snippet ?? '', f.detail ?? ''];
    if (f.file && f.line) {
      const raw = sourceLine(f.file, f.line);
      if (raw !== null) texts.push(raw);
    }
    for (const t of texts) for (const v of findSecretValues(t, f.file ?? '')) set.add(v);
  };
  for (const f of findings) collect(f);

  return findings.map((f) => {
    const values = [...(byFile.get(f.file ?? '') ?? [])].sort((a, b) => b.length - a.length);
    if (values.length === 0) return f;
    const next: Finding = {
      ...f,
      title: maskValues(f.title, values),
      detail: maskValues(f.detail, values),
      fix: maskValues(f.fix, values),
    };
    if (f.snippet !== undefined) next.snippet = maskValues(f.snippet, values);
    if (f.meta) next.meta = maskDeep(f.meta, values, 4) as Record<string, unknown>;
    return next;
  });
}
