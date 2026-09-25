import { basename, sep } from 'node:path';
import { read, rel, exists, isScript, languagesFor } from '../utils/files.js';
import { LineIndex, clip } from '../utils/line-index.js';
import { commentStyleFor, lexSpans, isInside } from '../utils/spans.js';
import { rulesForPath } from '../utils/gitignore.js';
import { Suppressions } from '../utils/suppress.js';
import { promote } from '../utils/paths.js';
import { emptyResult } from '../types.js';
import type { Finding, ProjectContext, ScanResult, Scanner, Severity } from '../types.js';
import { join } from 'node:path';
import { shannonEntropy, redactCredential } from '../utils/entropy.js';
import {
  GITLEAKS_RULES, GITLEAKS_STOPWORDS, GITLEAKS_ATTRIBUTION,
} from '../vendor/gitleaks/rules.js';
import { matcherFor } from './community.js';

interface Pattern {
  id: string;
  label: string;
  re: RegExp;
  severity: Severity;
  /** Extra confirmation step; return false to discard the match. */
  confirm?: (match: string) => boolean;
  note?: string;
}

/** Decodes a JWT payload without verifying it — we only want the claims. */
function jwtPayload(token: string): any | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1]!.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

const PATTERNS: Pattern[] = [
  {
    id: 'supabase-service-role',
    label: 'Supabase service-role key',
    re: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    severity: 'critical',
    confirm: (m) => jwtPayload(m)?.role === 'service_role',
    note: 'This key bypasses every Row Level Security policy on the project.',
  },
  {
    id: 'supabase-anon',
    label: 'Supabase anon key',
    re: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    severity: 'info',
    confirm: (m) => jwtPayload(m)?.role === 'anon',
    note: 'The anon key is designed to be public; it is only as safe as your RLS policies.',
  },
  { id: 'supabase-secret', label: 'Supabase secret key', re: /\bsb_secret_[A-Za-z0-9_-]{16,}/g, severity: 'critical' },
  { id: 'openai', label: 'OpenAI API key', re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}/g, severity: 'critical' },
  { id: 'anthropic', label: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{24,}/g, severity: 'critical' },
  { id: 'stripe-live', label: 'Stripe live secret key', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}/g, severity: 'critical' },
  { id: 'stripe-test', label: 'Stripe test secret key', re: /\b(?:sk|rk)_test_[A-Za-z0-9]{16,}/g, severity: 'medium' },
  { id: 'aws', label: 'AWS access key id', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: 'critical' },
  { id: 'github-pat', label: 'GitHub personal access token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/g, severity: 'critical' },
  { id: 'google', label: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: 'high' },
  { id: 'slack', label: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, severity: 'critical' },
  { id: 'resend', label: 'Resend API key', re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/g, severity: 'high' },
  { id: 'sendgrid', label: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g, severity: 'critical' },
  { id: 'private-key', label: 'Private key block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, severity: 'critical' },
  {
    id: 'postgres-url',
    label: 'PostgreSQL connection string with password',
    re: /\bpostgres(?:ql)?:\/\/[^\s:'"$]+:[^\s@'"$]{6,}@[^\s/'"]+/g,
    severity: 'critical',
    confirm: (value) => {
      const url = parsePostgresUrl(value);
      return url === null || !DEFAULT_DB_PASSWORD.test(url.password);
    },
  },
];

/**
 * The two parts of a `postgres://user:password@host` URL that decide whether it is a leak.
 *
 * Measured on 154 real repositories: of 96 critical findings for this pattern, 63 were a
 * default password (`postgres:postgres`) on localhost — a docker-compose file — 18 were
 * template passwords, and 10 more were local development databases. Five, in two
 * repositories, were a real password to a remote host, hardcoded into deploy scripts.
 * The pattern used to report all 96 identically.
 */
function parsePostgresUrl(value: string): { password: string; host: string } | null {
  const m = /^postgres(?:ql)?:\/\/[^:@\s]+:([^@\s]+)@([^/\s:?]+)/i.exec(value);
  if (!m) return null;
  let password = m[1]!;
  try {
    password = decodeURIComponent(password);
  } catch {
    /* keep the raw text */
  }
  return { password, host: m[2]!.toLowerCase() };
}

/** Passwords that ship in tutorials and compose files. A live database never uses them. */
const DEFAULT_DB_PASSWORD =
  /(password|passwd|changeme|change_me|example|placeholder|dummy|secret)|^(postgres|root|admin|user|pass|dev|test|supabase|1234+5*6*)$/i;

/** A loopback address or a bare service name (`db`, `postgres`): a development database. */
function isLocalDbHost(host: string): boolean {
  return /^(127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)$/.test(host) || !host.includes('.');
}

/**
 * Values that are obviously stand-ins rather than live credentials. Docs,
 * READMEs and rule fixtures are full of these and reporting them is pure noise.
 */
const PLACEHOLDER_STRONG =
  /(your[_-]?|example|placeholder|sample|template|<[a-z_ -]+>|\.\.\.|\u2026|changeme|change_me|dummy|redacted|notreal|fake|mock)/i;

/**
 * Filler that also turns up by chance inside a genuine credential. An AWS key
 * id whose random half happens to run seven digits in sequence contains
 * `1234567`; `xxx` appears in a random 36-character token often enough to
 * matter. These were in the same list as the words above, so a live key
 * containing one was silently discarded — a scanner missing a real leak, which
 * is the one failure it cannot afford. They now only disqualify a value that is
 * filler throughout rather than a random string that happens to contain a run.
 *
 * (Spelled out rather than illustrated on purpose: an example key written here
 * would be a credential-shaped literal in shipped source, and this tool would
 * be right to report it. It did.)
 */
const PLACEHOLDER_WEAK = /(s3cret|abc123|deadbeef|1234567|xxx|yyy|zzz|\bfoo\b|\bbar\b)/i;

/** Below this, a value is filler rather than a credential (`your_api_key_here` scores ~3.4). */
const FILLER_ENTROPY = 3.5;

/** The same character five or more times running, as in a filler-value key. */
const REPEATED_RUN = /(.)\1{4,}/;

function isPlaceholder(value: string): boolean {
  if (REPEATED_RUN.test(value)) return true;
  if (PLACEHOLDER_STRONG.test(value)) return true;
  return PLACEHOLDER_WEAK.test(value) && shannonEntropy(value) < FILLER_ENTROPY;
}

/**
 * Vendored gitleaks rules withheld as noisy in this tool's context, measured
 * across the fixtures and the reference corpus. Each carries its reason.
 */
const GITLEAKS_WITHHELD = new Map<string, string>([
  [
    'generic-api-key',
    "gitleaks' own catch-all for unknown providers. It matches any `key`-ish identifier next " +
      "to a quoted string, so it fires on ordinary arrays of method names ('auth.getUser', " +
      "'auth.getClaims') and on SQL column lists — 97 of 118 hits across the reference corpus " +
      'were false. The providers that matter are covered precisely by PATTERNS above.',
  ],
  [
    'sourcegraph-access-token',
    'matches any 40-character hex string, so every SHA-pinned GitHub Action ' +
      '(`uses: actions/checkout@<sha>`) is reported as a leaked token',
  ],
]);

/** Git object ids and integrity digests are hashes, not credentials. */
const HEX_DIGEST = /^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;

/**
 * Paths where a credential-shaped string is a fixture, not a deployed secret.
 * Findings here are reported at `low` so they are visible but never blocking.
 */
const NON_PRODUCTION_PATH =
  /(^|\/)(tests?|__tests__|__mocks__|__fixtures__|fixtures?|spec|specs|examples?|docs?|demo|samples?|e2e|cypress|playwright|stories)(\/|$)|\.(test|spec|stories|fixture)\.[a-z]+$|(^|\/)(README|CHANGELOG|CONTRIBUTING)/i;

/**
 * Env var names that are meant to be public even though they read like secrets.
 *
 * Each of the vendor names below is documented by that vendor as a client-side
 * identifier: PostHog's project API key (`phc_…`; the *personal* key is a different
 * name), Mapbox `pk.` tokens, a Google Maps browser key (restricted by referrer),
 * Mixpanel's project token, Algolia's search-only key, reCAPTCHA/Turnstile site keys,
 * Amplitude's API key, Logo.dev's publishable token. On a batch of 154 real repos
 * about half of the `NEXT_PUBLIC_` findings were these, reported as critical
 * secrets in the bundle.
 */
const PUBLIC_BY_DESIGN =
  /(ANON_KEY|PUBLISHABLE_KEY|PUBLIC_KEY|CLIENT_ID|MEASUREMENT_ID|PROJECT_ID|APP_ID|SENDER_ID|FIREBASE_API_KEY|MAPBOX_TOKEN|POSTHOG_KEY|SENTRY_DSN|SHOPIFY_API_KEY|POSTHOG_(PROJECT_)?(API_)?(KEY|TOKEN)|MAPBOX_(API_|ACCESS_|PUBLIC_)?TOKEN|GOOGLE_MAPS(_API)?_KEY|MAPS_API_KEY|MIXPANEL_TOKEN|AMPLITUDE_API_KEY|ALGOLIA_SEARCH(_API)?_KEY|SITE_?KEY|LOGO_?DEV_TOKEN)$/;
const SECRETY_NAME = /(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|PASSWD|_TOKEN|API_KEY|ACCESS_KEY|CREDENTIAL)/;

/**
 * A `NEXT_PUBLIC_` credential whose name names an LLM or vector-store provider
 * is not just *a* secret in the bundle — it is a provider key or token, which
 * `llmCategory` (src/utils/owasp.ts) recognizes by this same provider vocabulary
 * and files under OWASP LLM02. Without a provider name in the finding text, the
 * generic wording below never earns that tag even though the finding still
 * fires — see the README's LLM Top 10 coverage table for why that count matters.
 */
const AI_PROVIDER_IN_NAME: [RegExp, string][] = [
  [/OPENAI/, 'OpenAI'],
  [/ANTHROPIC/, 'Anthropic'],
  [/GEMINI/, 'Gemini'],
  [/CLAUDE/, 'Claude'],
  [/MISTRAL/, 'Mistral'],
  [/COHERE/, 'Cohere'],
  [/HUGGINGFACE/, 'HuggingFace'],
  [/REPLICATE/, 'Replicate'],
  [/GROQ/, 'Groq'],
  [/PERPLEXITY/, 'Perplexity'],
  [/\bXAI\b/, 'xAI'],
  [/PINECONE/, 'Pinecone'],
];

/** The AI/vector provider a `NEXT_PUBLIC_` variable name points at, if any. */
function aiProviderIn(varName: string): string | null {
  for (const [pattern, name] of AI_PROVIDER_IN_NAME) {
    if (pattern.test(varName)) return name;
  }
  return null;
}

/**
 * Matches per rule, per file, that get their own finding. A vendored pattern
 * that hits fifty times in one file is describing the file, not fifty separate
 * problems — but the count is reported rather than dropped.
 */
const MAX_HITS_PER_RULE = 3;

/**
 * Regex matches examined per pattern, per file — reported or discarded. A
 * file that is one credential-shaped token repeated ninety thousand times is
 * not ninety thousand things to check, and examining every one is how a
 * scanner gets held up by the file it is reading. Past this, the file is named
 * in the check note and the run is marked incomplete: the matches that were
 * not examined were not checked, and saying nothing would read as clean.
 */
const MAX_MATCHES_EXAMINED = 200;

/** A read of the environment, or a type or keyword: code, not a value to hide. */
const NOT_A_VALUE = /^(?:process\.env|import\.meta\.env|os\.environ|Deno\.env|env\.)|^[a-z]+$/;

/**
 * A line with every credential-shaped value on it redacted, for a snippet.
 *
 * CTS030 and the gitleaks rules redact the value they matched; the rules that
 * report a *variable* (CTS031, CTS033, CTS040, CTS045) printed the line as it
 * was, so a `.env` line giving an OpenAI key to a `NEXT_PUBLIC_` variable put
 * the whole key in the report of the rule that exists to say the key is
 * exposed. The value assigned to a secret-named variable and anything a
 * built-in pattern recognises are both replaced, then the line is clipped — in
 * that order, or a long key cut off mid-way would escape the replacement.
 */
function redactedSnippet(lineText: string): string {
  let text = lineText;
  for (const pattern of PATTERNS) {
    // Every PATTERNS regex is global, and `replace` starts a global regex from 0.
    text = text.replace(pattern.re, (m) => redactCredential(m));
  }
  text = text.replace(
    /([A-Za-z_][A-Za-z0-9_]*)(\s*[=:]\s*)(["'`]?)([^\s"'`,;]{7,})/g,
    (whole, name: string, sep: string, quote: string, value: string) =>
      SECRETY_NAME.test(name.toUpperCase()) && !value.includes('…') && !NOT_A_VALUE.test(value)
        ? `${name}${sep}${quote}${redactCredential(value)}`
        : whole,
  );
  return clip(text.trim());
}

const LOCKFILES = new Set([
  'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb',
  'poetry.lock', 'Pipfile.lock', 'composer.lock',
]);

/**
 * Line-comment openers for one file, by its language.
 *
 * This used to be one list for every file — `#`, `//`, `*` and `--` — so a
 * Markdown bullet (`* OPENAI_API_KEY=sk-proj-…` in a SETUP.md) and a shell
 * continuation line (`  --api-key sk_live_…` in a deploy.sh) both read as
 * comments, and two live keys were dropped as "documented examples". `*` only
 * continues a comment in a language with `/* … *\/` blocks, and `--` only opens
 * one in SQL. Files with no language of their own (`.env`, `.toml`, Markdown,
 * a Makefile) keep the two openers that mean "comment" nearly everywhere.
 */
function commentOpenersFor(file: string): RegExp {
  const languages = languagesFor(file);
  const style = commentStyleFor(languages);
  const openers = new Set<string>();
  const slashes = ['\\/\\/', '\\/\\*'];
  if (style.slashes) [...slashes, '\\*'].forEach((o) => openers.add(o));
  if (style.hash) openers.add('#');
  if (style.dashes) openers.add('--');
  // HCL takes `//` and `/* */` as well as `#`; JSON-with-comments takes `//`.
  if (languages.includes('terraform') || languages.includes('json')) {
    slashes.forEach((o) => openers.add(o));
  }
  if (languages.length === 0) ['#', ...slashes].forEach((o) => openers.add(o));
  return new RegExp(`^(?:${[...openers].join('|')})`);
}

/** Inside a string literal, the text is prose in some other file's syntax. */
const EMBEDDED_COMMENT = /^(?:#|\/\/)/;

/**
 * True when the match sits on a commented-out line. Splits on real newlines and
 * on the two-character `\n` escape as well, because docs-in-a-string-literal
 * (`"# .env — WRONG\n# NEXT_PUBLIC_SECRET=..."`) are a common way to show the
 * wrong way to do something, and flagging those is noise.
 *
 * Only the match's own line is read. This used to take `source.slice(0, index)`
 * for every match, which made the scanner quadratic in the size of the file.
 */
function isCommentedOut(
  source: string,
  index: number,
  lineStart: number,
  openers: RegExp,
): boolean {
  const before = source.slice(lineStart, index);
  let start = -1;
  let embedded = false;
  const escaped = before.lastIndexOf('\\n');
  if (escaped !== -1) {
    start = escaped + 1;
    embedded = true;
  }
  for (const quote of ['"', "'", '`']) {
    const at = before.lastIndexOf(quote);
    if (at > start) {
      start = at;
      embedded = true;
    }
  }
  const segment = before.slice(start + 1).trimStart();
  return (embedded ? EMBEDDED_COMMENT : openers).test(segment);
}

/**
 * True when the offset sits inside a string literal on its own line. Security
 * tooling, docs and rule libraries quote the very patterns we search for, and
 * a quoted mention is prose, not configuration.
 */
function isQuoted(source: string, index: number, lineStart: number): boolean {
  const before = source.slice(lineStart, index);
  for (const quote of ['"', "'", '`']) {
    let count = 0;
    for (let i = 0; i < before.length; i++) {
      if (before[i] === quote && before[i - 1] !== '\\') count++;
    }
    if (count % 2 === 1) return true;
  }
  return false;
}

/**
 * Whether git would leave this file out of `git add .` — by a rule matching
 * the file, or by a rule excluding any directory above it. Git never descends
 * into an excluded directory, so nothing inside one can be added, whatever the
 * file's own name. Asking only about the file reported `config/secrets/.env`
 * as uncovered in a repository whose .gitignore lists `config/secrets/` — seen
 * under --no-gitignore, which walks into ignored directories on purpose.
 */
function gitWouldIgnore(root: string, abs: string): boolean {
  if (rulesForPath(root, abs, read).ignores(abs, false)) return true;
  const base = root.replace(/[/\\]+$/, '');
  if (!abs.startsWith(base + sep)) return false;
  const segments = abs.slice(base.length + 1).split(sep).slice(0, -1);
  let dir = base;
  for (const segment of segments) {
    dir = join(dir, segment);
    if (rulesForPath(root, dir, read).ignores(dir, true)) return true;
  }
  return false;
}

export const secretsScanner: Scanner = {
  name: 'Secrets & client-bundle boundary',

  applies() {
    return true;
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    let filesScanned = 0;
    const seen = new Set<string>();
    // Files where a rule matched more times than the per-file cap lists. Left
    // unsaid, this is a report that quietly stops counting: twenty leaked keys
    // in one file read as three.
    const truncated = new Set<string>();
    // Files where a pattern matched more often than MAX_MATCHES_EXAMINED, so
    // the remainder of that pattern's matches went unexamined.
    const overmatched = new Set<string>();

    for (const file of ctx.files) {
      const name = basename(file);
      if (LOCKFILES.has(name)) continue;
      const relPath = rel(ctx.root, file);
      // One file that throws — a pathological input, a bug in a helper — must
      // cost that file, not every file after it. Unguarded, the whole scanner
      // failed and every secret in the repository went unreported.
      try {
      const source = read(file);
      if (source === null) continue;
      const isExample = /\.(example|sample|template)$/.test(relPath) || /\.env\.example/.test(relPath);
      const fixtureFile = NON_PRODUCTION_PATH.test(relPath);
      filesScanned++;
      const suppress = new Suppressions(source);
      const clientComponent = /^\s*(['"])use client\1/m.test(source.slice(0, 400));
      const lines = new LineIndex(source);
      const openers = commentOpenersFor(file);
      const commented = (index: number, line: number) =>
        isCommentedOut(source, index, lines.lineStart(line), openers);
      /** Counts one examined match; false once the pattern has used its allowance. */
      const examine = (counter: { n: number }): boolean => {
        if (++counter.n <= MAX_MATCHES_EXAMINED) return true;
        overmatched.add(relPath);
        return false;
      };

      for (const pattern of PATTERNS) {
        if (pattern.id === 'supabase-anon') continue; // informational only, not reported
        pattern.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        const examined = { n: 0 };
        while ((m = pattern.re.exec(source)) !== null) {
          const value = m[0];
          const line = lines.lineAt(m.index);
          const key = `${relPath}:${line}:${pattern.id}`;
          // Already reported on this line: nothing left to decide, and cheap to skip.
          if (seen.has(key)) continue;
          if (!examine(examined)) break;
          if (pattern.confirm && !pattern.confirm(value)) continue;
          if (isPlaceholder(value)) continue;
          if (commented(m.index, line)) continue; // documented example, not a live secret
          if (suppress.suppressed(line, 'CTS030')) continue;

          seen.add(key);
          seen.add(`${relPath}:${line}:builtin`);

          const redacted = redactCredential(value);
          // Redact first, then truncate: a long key would otherwise be cut off
          // before the replacement could match, leaving the secret on screen.
          const rawLine = lines.lineText(line);
          const snippet = clip(rawLine.split(value).join(redacted).trim());
          // A client component compiles into the bundle every visitor
          // downloads, so the same value is worse there than on the server.
          // This used to read `clientComponent && pattern.severity === 'critical'
          // ? 'critical' : pattern.severity`, whose two arms are the same value —
          // so being in a client component never actually raised anything.
          // Promoted one step rather than pinned to critical: a Stripe *test*
          // key in the bundle is a real leak and not a critical one, and
          // overstating it is the failure this project exists to avoid.
          let severity: Severity =
            isExample || fixtureFile
              ? 'low'
              : clientComponent
                ? promote(pattern.severity)
                : pattern.severity;
          // A connection string to a local database is a development credential, not a
          // leaked production one.
          const dbUrl = pattern.id === 'postgres-url' ? parsePostgresUrl(value) : null;
          const localDb = dbUrl !== null && isLocalDbHost(dbUrl.host);
          if (localDb) severity = 'low';

          result.findings.push({
            id: 'CTS030',
            severity,
            title: `Hardcoded ${pattern.label}`,
            detail:
              `${pattern.label} \`${redacted}\` is written into ${relPath}. ` +
              (clientComponent
                ? 'This file is a client component, so the value is compiled into the JavaScript bundle every visitor downloads. '
                : 'Anything committed to git is recoverable from history even after you delete the line. ') +
              (pattern.note ?? '') +
              (localDb ? ' It points at a local database, so this is a development credential and is reported at low.' : '') +
              (isExample
                ? ' (This looks like an example file, so the severity is reduced — confirm the value is not real.)'
                : fixtureFile
                  ? ' (This path looks like tests or docs, so the severity is reduced — confirm the value is not real.)'
                  : ''),
            fix:
              'Move the value into an environment variable that is only read server-side, rotate the key ' +
              'at the provider (assume it is burned), and purge it from git history if it was ever committed.',
            file: relPath,
            line,
            snippet,
            cwe: 'CWE-798: Use of Hard-coded Credentials',
            owasp: 'A04:2025 - Cryptographic Failures',
            meta: { kind: pattern.id, clientComponent },
          });
        }
      }

      // Broad provider coverage from the vendored gitleaks ruleset. The
      // hand-written PATTERNS above stay first: they carry tuned severities and
      // extra verification (decoding a JWT to confirm `role: service_role`), so
      // anything they already reported on this line is not reported twice.
      const lowerSource = source.toLowerCase();
      for (const rule of GITLEAKS_RULES) {
        if (GITLEAKS_WITHHELD.has(rule.id)) continue;
        // Cheap substring prefilter before touching the regex.
        if (rule.keywords.length > 0 && !rule.keywords.some((k) => lowerSource.includes(k))) {
          continue;
        }
        // Through the linear-time matcher community.ts runs vendored patterns
        // on: gitleaks' `cohere` and `private_ai` nest `[\w.-]{0,50}?` inside
        // `[\w.-]{0,50}?`, which cost V8 ~4.7 s each on a 396 KB file of one
        // identifier. The matcher returns the same matches V8 would.
        const re = matcherFor(rule.pattern);
        re.lastIndex = 0;
        let g: RegExpExecArray | null;
        let hits = 0;
        const examined = { n: 0 };
        while ((g = re.exec(source)) !== null) {
          if (g[0].length === 0) {
            re.lastIndex++;
            continue;
          }
          const secret = g[1] ?? g[0];
          const line = lines.lineAt(g.index);
          const findingId = `GL-${rule.id}`;
          const key = `${relPath}:${line}:${findingId}`;
          // A hand-written pattern already claimed this location.
          if (seen.has(`${relPath}:${line}:builtin`) || seen.has(key)) continue;
          if (!examine(examined)) break;

          if (HEX_DIGEST.test(secret)) continue;
          if (rule.entropy !== null && shannonEntropy(secret) < rule.entropy) continue;
          if (isPlaceholder(secret)) continue;
          if (GITLEAKS_STOPWORDS.some((w) => secret.toLowerCase().includes(w))) continue;
          if (commented(g.index, line)) continue;
          if (suppress.suppressed(line, findingId)) continue;
          seen.add(key);

          const redacted = redactCredential(secret);
          const safeLine = lines.lineText(line).split(secret).join(redacted).trim();

          result.findings.push({
            id: findingId,
            severity: isExample || fixtureFile ? 'low' : clientComponent ? promote('high') : 'high',
            title: `Hardcoded credential (${rule.id})`,
            detail:
              rule.description +
              ` The matched value (\`${redacted}\`) scores ` +
              `${shannonEntropy(secret).toFixed(1)} bits/char of entropy, which is consistent with a ` +
              'real credential rather than a placeholder.' +
              (clientComponent
                ? ' This file is a client component, so the value ships in the browser bundle.'
                : '') +
              (isExample || fixtureFile
                ? ' (Path looks like an example, test or docs file, so the severity is reduced.)'
                : ''),
            fix:
              'Rotate this credential at the provider — assume it is burned — then move it to an ' +
              'environment variable read only on the server, and purge it from git history.',
            file: relPath,
            line,
            snippet: clip(safeLine),
            cwe: 'CWE-798: Use of Hard-coded Credentials',
            owasp: 'A04:2025 - Cryptographic Failures',
            meta: {
              source: 'gitleaks',
              rule: rule.id,
              attribution: GITLEAKS_ATTRIBUTION,
              entropy: Number(shannonEntropy(secret).toFixed(2)),
            },
          });
          if (++hits >= MAX_HITS_PER_RULE) {
            // Peek: only claim there is more if there actually is.
            if (re.exec(source) !== null) truncated.add(relPath);
            break;
          }
        }
      }

      // Server-only secrets routed through a NEXT_PUBLIC_ variable end up in the bundle.
      // Only a genuine read (`process.env.X`) or assignment (`X=...`) counts;
      // a variable merely named inside a string or a test description does not.
      const envRe = /process\.env\.(NEXT_PUBLIC_[A-Z0-9_]+)|(NEXT_PUBLIC_[A-Z0-9_]+)\s*[=:]/g;
      let e: RegExpExecArray | null;
      while ((e = envRe.exec(source)) !== null) {
        const varName = e[1] ?? e[2]!;
        if (PUBLIC_BY_DESIGN.test(varName)) continue;
        if (!SECRETY_NAME.test(varName)) continue;
        const key = `${relPath}:${varName}`;
        if (seen.has(key)) continue;
        const line = lines.lineAt(e.index);
        if (commented(e.index, line)) continue; // a documented counter-example
        if (suppress.suppressed(line, 'CTS031')) continue;
        seen.add(key);
        const provider = aiProviderIn(varName);
        result.findings.push({
          id: 'CTS031',
          severity: fixtureFile ? 'low' : 'critical',
          title: provider
            ? `${provider} API key exposed through a NEXT_PUBLIC_ variable`
            : 'Server secret exposed through a NEXT_PUBLIC_ variable',
          detail:
            `\`${varName}\` is prefixed \`NEXT_PUBLIC_\`, so Next.js inlines its value into the browser ` +
            'bundle at build time. ' +
            (provider
              ? `The name says it holds a ${provider} API key or token — every visitor can read it in ` +
                'devtools and spend your quota or query your data directly.'
              : 'The name says it holds a secret. Every visitor can read it in devtools.'),
          fix:
            `Rename it to \`${varName.replace('NEXT_PUBLIC_', '')}\`, read it only in server code (Server ` +
            'Actions, Route Handlers, server components), and rotate the current value.',
          file: relPath,
          line,
          // The line usually carries the value itself (`NEXT_PUBLIC_…_KEY=sk-…`
          // in a .env), and this finding is the one saying that value is exposed.
          snippet: redactedSnippet(lines.lineText(line)),
          cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
          // OWASP 2025 files CWE-200 under Broken Access Control, and CTS013 and
          // CTS019 already said so; this said Cryptographic Failures.
          owasp: 'A01:2025 - Broken Access Control',
          meta: { variable: varName },
        });
      }

      // Any server-side env var read in a client component is inlined into the
      // bundle as `undefined` at best, and as its value at worst. The named
      // secrets below are the critical case; this is the general one.
      if (clientComponent && isScript(file)) {
        const anyEnv = /process\.env\.(?!NEXT_PUBLIC_)([A-Z][A-Z0-9_]{2,})/g;
        const reported = new Set<string>();
        let g: RegExpExecArray | null;
        while ((g = anyEnv.exec(source)) !== null) {
          const varName = g[1]!;
          if (varName === 'NODE_ENV' || varName === 'VERCEL_ENV' || varName === 'NODE_OPTIONS') continue;
          if (SECRETY_NAME.test(varName)) continue; // covered at critical by CTS033
          if (reported.has(varName)) continue;
          const line = lines.lineAt(g.index);
          // Marked reported only once it is: a commented-out mention first in
          // the file used to hide every real read of the same variable below it.
          if (commented(g.index, line)) continue;
          if (suppress.suppressed(line, 'CTS040')) continue;
          reported.add(varName);
          result.findings.push({
            id: 'CTS040',
            severity: fixtureFile ? 'low' : 'high',
            title: 'Client component reads a server-side environment variable',
            detail:
              `${relPath} is a client component and reads \`process.env.${varName}\`. Next.js only ` +
              'inlines `NEXT_PUBLIC_*` variables into the browser bundle, so this is `undefined` at ' +
              'runtime — the logic depending on it is silently not running, and if the prefix is ever ' +
              'added to "fix" that, the value ships to every visitor.',
            fix:
              `Read \`${varName}\` in a Server Component, Server Action or Route Handler and pass the ` +
              'result down as a prop. Add the `NEXT_PUBLIC_` prefix only if the value is genuinely public.',
            file: relPath,
            line,
            snippet: redactedSnippet(lines.lineText(line)),
            cwe: 'CWE-668: Exposure of Resource to Wrong Sphere',
            owasp: 'A04:2025 - Cryptographic Failures',
            meta: { variable: varName },
          });
        }
      }

      // An AI SDK client told to run in the browser ships the API key with it.
      if (isScript(file)) {
        const browserFlag = /dangerouslyAllowBrowser\s*:\s*true/.exec(source);
        const flagLine = browserFlag ? lines.lineAt(browserFlag.index) : 0;
        if (
          browserFlag &&
          !commented(browserFlag.index, flagLine) &&
          !isQuoted(source, browserFlag.index, lines.lineStart(flagLine))
        ) {
          const line = flagLine;
          if (!suppress.suppressed(line, 'CTS045')) {
            result.findings.push({
              id: 'CTS045',
              severity: fixtureFile ? 'low' : 'critical',
              title: 'AI client configured to run in the browser',
              detail:
                `${relPath} sets \`dangerouslyAllowBrowser: true\`. That flag exists purely to disable ` +
                'the SDK\u2019s own guard against shipping your API key to the client. Every visitor can ' +
                'read the key out of the bundle and spend your quota.',
              fix:
                'Call the model from a Route Handler or Server Action and have the browser call that ' +
                'instead. If you need streaming, proxy the stream through your own endpoint.',
              file: relPath,
              line,
              // `new OpenAI({ apiKey: 'sk-…', dangerouslyAllowBrowser: true })`
              // is one line more often than not.
              snippet: redactedSnippet(lines.lineText(line)),
              cwe: 'CWE-522: Insufficiently Protected Credentials',
              owasp: 'A04:2025 - Cryptographic Failures',
              meta: { flag: 'dangerouslyAllowBrowser' },
            });
          }
        }
      }

      // A client component reaching for a service-role client is always wrong.
      if (clientComponent && isScript(file)) {
        // Only a reference in code counts. The first textual match used to be taken
        // wherever it fell, so `alert('Add STRIPE_SECRET_KEY to enable checkout')` —
        // a message that names the variable — was a critical "client component reads
        // a server-only secret". A name inside a string is still a read when it is the
        // key of a bracket access: process.env['STRIPE_SECRET_KEY'].
        const spans = lexSpans(source, commentStyleFor(languagesFor(file)));
        const namePattern = /SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY|STRIPE_SECRET_KEY/g;
        let hit: RegExpExecArray | null = null;
        for (let m: RegExpExecArray | null; (m = namePattern.exec(source)) !== null; ) {
          if (isInside(spans, m.index, 'comment')) continue;
          if (
            isInside(spans, m.index, 'string') &&
            !/(?:process|import\.meta)\.env\[\s*['"`]$/.test(source.slice(Math.max(0, m.index - 25), m.index))
          ) {
            continue;
          }
          hit = m;
          break;
        }
        if (hit) {
          const line = lines.lineAt(hit.index);
          if (!suppress.suppressed(line, 'CTS033')) {
            result.findings.push({
              id: 'CTS033',
              severity: 'critical',
              title: 'Client component references a server-only secret',
              detail:
                `${relPath} carries the \`'use client'\` directive and reads \`${hit[0]}\`. Even if the ` +
                'variable is undefined in the browser today, the reference means the code path was designed ' +
                'to run privileged work in an untrusted context.',
              fix:
                'Move the privileged work into a Server Action or Route Handler and call that from the ' +
                'client component instead.',
              file: relPath,
              line,
              snippet: redactedSnippet(lines.lineText(line)),
              cwe: 'CWE-668: Exposure of Resource to Wrong Sphere',
              owasp: 'A04:2025 - Cryptographic Failures',
            });
          }
        }
      }
      } catch (err) {
        result.incomplete!.push(
          `${relPath} could not be fully checked for secrets ` +
            `(${err instanceof Error ? err.message : String(err)}); a credential in it may be unreported.`,
        );
      }
    }

    // Are real .env files kept out of git? Answered by the same matcher the
    // walk uses, not by string-matching the text of a .gitignore: `/.env`,
    // `.env.local`, `**/.env` and a rule in a nested .gitignore all genuinely
    // cover the file, and a list of accepted literals called every one of them
    // uncovered.
    const envPaths = ctx.files.filter(
      (f) =>
        /(^|\/)\.env(\.|$)/.test(rel(ctx.root, f)) &&
        !/\.(example|sample|template)$/.test(f),
    );
    if (envPaths.length > 0 && exists(join(ctx.root, '.git'))) {
      const uncovered = envPaths
        .filter((abs) => !gitWouldIgnore(ctx.root, abs))
        .map((abs) => rel(ctx.root, abs));
      if (uncovered.length > 0) {
        const envFiles = uncovered;
        result.findings.push({
          id: 'CTS032',
          severity: 'high',
          title: '.env file is not covered by .gitignore',
          detail:
            `${envFiles.join(', ')} ${envFiles.length === 1 ? 'exists' : 'exist'} in a git repository ` +
            `and \`.gitignore\` has no rule matching ${envFiles.length === 1 ? 'it' : 'them'}. ` +
            `One \`git add .\` publishes every key ${envFiles.length === 1 ? 'it holds' : 'they hold'}.`,
          fix: 'Add `.env*` to .gitignore (keeping `!.env.example`), then `git rm --cached` any env file already tracked.',
          file: '.gitignore',
          line: 1,
          cwe: 'CWE-538: Insertion of Sensitive Information into an Externally-Accessible File',
          owasp: 'A04:2025 - Cryptographic Failures',
          meta: { envFiles },
        });
      }
    }

    const leaked = result.findings.filter((f) => f.id !== 'CTS032' && f.severity !== 'low').length;
    const notes = [`${GITLEAKS_WITHHELD.size} gitleaks rules withheld as noisy`];
    if (truncated.size > 0) {
      notes.push(
        `${truncated.size} file${truncated.size === 1 ? '' : 's'} had more matches than the ` +
          `${MAX_HITS_PER_RULE}-per-rule cap lists (${[...truncated].sort().slice(0, 3).join(', ')}` +
          `${truncated.size > 3 ? ', …' : ''}) — fix those files by hand, not one finding at a time`,
      );
    }
    if (overmatched.size > 0) {
      const names = [...overmatched].sort();
      const listed = `${names.slice(0, 3).join(', ')}${names.length > 3 ? ', …' : ''}`;
      notes.push(
        `${names.length} file${names.length === 1 ? '' : 's'} matched one credential pattern more than ` +
          `${MAX_MATCHES_EXAMINED} times (${listed}); matches past that were not examined`,
      );
      for (const file of names) {
        result.incomplete!.push(
          `${file}: a credential pattern matched more than ${MAX_MATCHES_EXAMINED} times, and the ` +
            'matches past that were not examined — a real key among them would not be reported.',
        );
      }
    }
    result.checks.push({
      label:
        `Secret & client-bundle boundary (${filesScanned} file${filesScanned === 1 ? '' : 's'}, ` +
        `${PATTERNS.length + GITLEAKS_RULES.length - GITLEAKS_WITHHELD.size} credential patterns)`,
      passed: leaked === 0,
      note: notes.join('; '),
    });
    return result;
  },
};
