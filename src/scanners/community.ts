import { read, rel, lineAt, snippetAt, languagesFor } from '../utils/files.js';
import { Suppressions } from '../utils/suppress.js';
import { adjustForPath } from '../utils/paths.js';
import { commentStyleFor, lexSpans, isInside } from '../utils/spans.js';
import type { Span } from '../utils/spans.js';
import {
  GUARDVIBE_RULES,
  GUARDVIBE_ATTRIBUTION,
  GUARDVIBE_REACT_NATIVE_RULE_IDS,
  GUARDVIBE_CVE_RULE_IDS,
} from '../vendor/guardvibe/index.js';
import { emptyResult } from '../types.js';
import type { ProjectContext, ScanResult, Scanner, Severity } from '../types.js';

/**
 * Upstream rules that restate a check ClearToShip already performs against the
 * AST or the parsed schema. The AST version reasons about a whole function body
 * instead of a fixed character window, so it is both more accurate and better
 * located — running both would double-report and import the weaker result.
 *
 * These are disabled here rather than deleted from the vendored files, so those
 * stay a faithful copy of upstream and re-vendoring is a straight overwrite.
 *
 * Nine of these ids (noted inline) are superseded by the RLS and Server
 * Actions scanners, which now live in the licensed `cleartoship-rules-pro`
 * package rather than always running in this MIT package. They stay
 * unconditionally suppressed here even without a license, on purpose: an
 * early attempt at standing them back up as free-tier fallback coverage was
 * reverted after it reported `VG1010` — critical — on `clean-app`'s
 * `updateProfile`, a Server Action proven safe by the fixture's own doc
 * comment (an explicit field list, no caller-controlled columns). The
 * vendored version is "the weaker result" for a reason: it is a
 * no-schema-library-detected pattern match, not real argument-flow analysis,
 * and reviving it trades a silent gap for a false "critical" on correct code
 * — worse for a tool whose whole trust model is "a true positive a developer
 * will act on, not coverage for its own sake." So: RLS and Server Actions get
 * zero free-tier coverage, first-party or vendored, the same honest way LLM05
 * gets zero coverage from any static source scan rather than a rule that
 * pretends otherwise.
 */
const SUPERSEDED = new Map<string, string>([
  ['VG400', 'CTS033/CTS040'],
  ['VG401', 'CTS002'], // Pro: Server Actions
  ['VG402', 'CTS001'], // Pro: Server Actions
  ['VG411', 'CTS031'],
  ['VG420', 'CTS001'], // Pro: Server Actions
  ['VG427', 'CTS041'], // Pro: Server Actions
  ['VG439', 'CTS016'], // Pro: RLS
  ['VG604', 'CTS031'],
  ['VG627', 'CTS031'],
  ['VG631', 'CTS031'],
  ['VG655', 'CTS031'],
  ['VG656', 'CTS030'],
  ['VG657', 'CTS030'],
  ['VG665', 'CTS030'],
  ['VG671', 'CTS031'],
  ['VG708', 'CTS030'],
  ['VG754', 'CTS031'],
  ['VG953', 'CTS043'], // Pro: Server Actions
  ['VG998', 'CTS045'],
  ['VG437', 'CTS033'],
  ['VG860', 'CTS028'],
  ['VG874', 'CTS028'],
  ['VG876', 'CTS031'],
  ['VG952', 'CTS001'], // Pro: Server Actions
  ['VG960', 'CTS044'], // Pro: Server Actions
  ['VG1007', 'CTS003'], // Pro: Server Actions
  ['VG1010', 'CTS002'], // Pro: Server Actions
]);

/**
 * Rules withheld because they misfire in this tool's context, measured against
 * the fixtures plus the reference corpus. Each is recorded with its reason so
 * the judgement can be revisited when upstream changes.
 */
const WITHHELD = new Map<string, string>([
  [
    'VG543',
    'matches `; DROP|DELETE|INSERT|…` anywhere in a .sql file, which is the normal shape of ' +
      'every migration — 43 hits across the corpus, all false',
  ],
  [
    'VG540',
    'flags any destructive DDL in a .sql file; migrations legitimately drop and alter objects',
  ],
  [
    'VG542',
    'flags DELETE/UPDATE without WHERE in .sql files, where a full-table statement in a ' +
      'migration is deliberate',
  ],
  [
    'VG863',
    'a packaging lint (missing "files" field), not a security finding, and wrong for apps ' +
      'rather than published libraries',
  ],
  [
    'VG865',
    'declares itself a `.npmignore` lint but is registered for the `shell` language, so it ' +
      'matches almost every line of every shell script — 6 hits on two `scripts/*.sh` files, ' +
      'all false, and it is a packaging lint rather than a security finding either way',
  ],
  [
    'VG1004',
    'matches every `use server` module with an exported function; it asserts "no rate limiting" ' +
      'without ever checking for it',
  ],
]);

/**
 * Machine-generated dependency lockfiles. Their entries describe the *transitive*
 * graph, which nobody in this repo wrote or can edit directly.
 */
const LOCKFILE =
  /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|composer\.lock|Pipfile\.lock|poetry\.lock)$/i;

/**
 * Rules whose signal only exists in a hand-authored manifest. The same JSON
 * shapes appear all over a lockfile describing packages a dependency chose, so
 * a hit there is both unactionable and, measured on the dogfooding corpus,
 * wrong: `fast-glob`, `fast-deep-equal`, `common-tags`, `core-js` and
 * `simple-statistics` all trip the deceptive-prefix list, and the "wildcard
 * version" rule fires on transitive `"node": ">=16"` engine constraints.
 * Declared package names are covered properly by CTS020-CTS027, which ask the
 * registry rather than matching a prefix.
 */
const MANIFEST_ONLY = new Map<string, string>([
  ['VG872', 'internal-name heuristic; in a lockfile it names a transitive dependency'],
  ['VG873', 'deceptive-prefix heuristic; matches ordinary transitive package names'],
  ['VG020', 'wildcard version; a transitive range is the dependency author\'s choice'],
]);

/** SQL verbs strong enough that the call is about a database by itself. */
const SQL_VERBS = /^(query|execute|raw|sql|prepare|QueryRow|QueryContext)$/i;

/** Words that make a string a query rather than a sentence. */
const SQL_KEYWORDS = /\b(select|insert\s+into|update|delete\s+from|from|where|values|set)\b/i;

/** Placeholder values that exist to be replaced, not to authenticate. */
const PLACEHOLDER =
  /^(your|my|the|a|change|changeme|replace|example|placeholder|dummy|sample|test|todo|none|null|undefined|x{3,}|\.{3}|<.*>|\$\{.*\}|process\.env)/i;

/**
 * Whether the quoted value in a `name = "value"` match reads as a credential.
 * Prose is not: three or more words, or a trailing full stop, is a sentence.
 */
function looksLikeSecretValue(match: string): boolean {
  const value = /['"]([^'"\n]*)['"]\s*$/.exec(match)?.[1];
  if (value === undefined) return true;
  const trimmed = value.trim();
  if (trimmed === '' || PLACEHOLDER.test(trimmed)) return false;
  if (trimmed.split(/\s+/).length >= 3) return false;
  if (/[.!?]$/.test(trimmed) && trimmed.includes(' ')) return false;
  return true;
}

/** Bind placeholders: `?`, `$1`, `:name`, `@name`, anywhere a value may go. */
const BIND_PLACEHOLDER = /[\s(,=]\?(?=[\s,)`;]|$)|\$\d+\b|[\s(,=]:[A-Za-z_]\w*|[\s(,=]@[A-Za-z_]\w*/;

/** `${...}` expressions that read straight from the request. */
const INTERPOLATES_REQUEST =
  /\$\{[^}]*\b(req|request|body|params|query|searchParams|argv|input|formData|payload)\b/i;

/**
 * The whole statement a match sits in. Both SQL rules stop matching at the first
 * `${`, so the bind placeholders that decide the question are usually *past* the
 * end of the match — `prepare(\`UPDATE ${table} SET csv_data = ? WHERE id = ?\`)`
 * matches only as far as `UPDATE ${`.
 */
function statementAround(source: string, index: number): string {
  const open = source.indexOf('`', index);
  if (open !== -1 && open - index < 120) {
    for (let i = open + 1; i < source.length && i < open + 800; i++) {
      if (source[i] === '\\') {
        i++;
        continue;
      }
      // A little past the closing backtick, so the chained `.bind(...)` that
      // decides whether the values are parameterized is inside the window.
      if (source[i] === '`') return source.slice(index, i + 121);
    }
  }
  return source.slice(index, index + 400);
}

/**
 * Whether the statement passes its values as bound parameters. Interpolating a
 * table name into an otherwise parameterized query is ordinary; interpolating
 * `${req.query.id}` is the bug, and a query doing both still fails this test.
 */
function isParameterized(statement: string): boolean {
  if (INTERPOLATES_REQUEST.test(statement)) return false;
  // Handing the statement to `.bind(...)` is the parameterizing itself, and it
  // covers the idioms a placeholder scan cannot see: `IN (${ids.map(() =>
  // '?').join(',')})`, or a constant SQL fragment interpolated beside binds.
  if (/\.\s*bind\s*\(\s*[^)\s]/.test(statement)) return true;
  // The other calling convention: the values follow the query.
  // `$executeRawUnsafe(\`… VALUES ${placeholders}\`, ...params)`,
  // `db.query(sql, [id])`. A closing backtick with an argument after it.
  if (/`\s*,\s*[^)\s]/.test(statement)) return true;
  // An interpolation that builds placeholders is parameterizing too:
  // `chunk.map(() => "(?, ?, ?)").join(", ")`.
  if (/\$\{[^}]*['"][^'"]*\?[^'"]*['"]/.test(statement)) return true;
  // Otherwise look for the placeholders themselves — with interpolations
  // dropped first, so a JavaScript ternary is not read as a `?` parameter.
  return BIND_PLACEHOLDER.test(statement.replace(/\$\{[^}]*\}/g, ' '));
}

/** The verb has to be a SQL verb, and the statement must not be parameterized. */
function sqlGuard(match: string, source: string, index: number): boolean {
  const verb = /^[A-Za-z_]+/.exec(match)?.[0] ?? '';
  if (!SQL_VERBS.test(verb) && !SQL_KEYWORDS.test(match)) return false;
  return !isParameterized(statementAround(source, index));
}

/**
 * A ceiling on what one model call or agent loop may spend, in any of the names
 * the SDKs actually use. `stopWhen` is the current Vercel AI SDK spelling of the
 * step cap; `maxSteps` is its predecessor.
 */
const HAS_STEP_CAP =
  /\b(stopWhen|stop_when|stopConditions|maxSteps|max_steps|max_iterations|maxIterations|maxTokens|max_tokens|maxOutputTokens|max_output_tokens)\b/;

/**
 * Per-rule filters for a match shape the upstream regex cannot exclude on its
 * own. Given the matched text plus where it sat, so a guard can look around it.
 */
const MATCH_GUARDS: Record<
  string,
  (match: string, source: string, index: number, spans: readonly Span[]) => boolean
> = {
  // A `"link": true` entry is a workspace or pnpm symlink resolved to a path on
  // disk rather than a tarball, so it has no integrity hash by design. Thirty of
  // them in one pnpm-managed lockfile, every one reported as a false critical.
  VG870: (match) => !/"link"\s*:\s*true/.test(match),

  // The verb list has no word boundary in front of it and includes `all`, `get`
  // and `run`, so `querySelectorAll(\`[name="${CSS.escape(k)}"]\`)` reads as a
  // SQL call. Weak verbs have to be backed by something that looks like SQL;
  // `query`, `execute` and friends stand on their own. A real interpolated
  // `exec(\`INSERT INTO ...\`)` still matches — checked against one.

  // `(?:child_process|cp)[\s\S]*?(?:exec|spawn…)` lets the bridge run to the end
  // of the file: one match measured 3,608 characters and 109 lines, pairing an
  // `import … from "node:child_process"` with an `exec(` far below it and
  // reporting the import as a critical. A real one is a single statement.
  VG011: (match) => (match.match(/\n/g)?.length ?? 0) <= 1,

  // `sk-[A-Za-z0-9-_]{20,}` has no boundary in front of it, so the slug
  // `best-disk-space-analyzer-mac-2026` contains an "OpenAI key" — the `sk-` in
  // "di*sk-*space...". Real keys start at a token boundary; substrings of a word
  // do not.
  VG003: (_match, source, index) => index === 0 || !/[A-Za-z0-9_-]/.test(source[index - 1]!),

  // Both rules key off a *name* — anything called password, secret, apiKey — and
  // accept any string as its value, so UI copy lands as a critical:
  // `password: "That password didn't match. Try again."` was one. A credential
  // is an opaque token, not a sentence and not a placeholder.
  VG001: (match) => looksLikeSecretValue(match),
  VG062: (match) => looksLikeSecretValue(match),

  // A statement whose values go through bind placeholders is parameterized:
  // `db.prepare(\`UPDATE ${table} SET csv_data = ? WHERE id = ?\`).bind(...)`
  // interpolates an identifier, not user input, and both rules read that as
  // injection. Held to two conditions, so a query that binds one value and
  // concatenates another still fires: there must be a placeholder, and no
  // interpolated expression may read from the request.
  VG010: (match, source, index) => sqlGuard(match, source, index),
  VG123: (_match, source, index) => !isParameterized(statementAround(source, index)),

  // The "base64 payload" test is a run of 20+ characters from the base64
  // alphabet, which any long camelCase identifier satisfies:
  // `description: \`${pct(clusteredAroundMedian, …)}\`` matched on the
  // identifier. Interpolated expressions are code, not the description text,
  // and real encoded content is not purely alphabetic.
  VG881: (match) => {
    const text = match.replace(/\$\{[^}]*\}/g, ' ');
    if (/(?:\\x[0-9a-f]{2}){4,}|(?:\\u[0-9a-f]{4}){4,}|(?:&#\d{2,4};){4,}/i.test(text)) return true;
    const run = /[A-Za-z0-9+/]{20,}={0,2}/.exec(text)?.[0];
    // A slash is not evidence: "new/used/refurbished" is twenty characters of
    // the base64 alphabet and a sentence. Real encoded content carries digits
    // or padding.
    return run !== undefined && /[0-9+=]/.test(run);
  },

  // `eval("require")` is the documented escape hatch for keeping a bundler from
  // statically resolving a require — a constant the author typed, with no input
  // reaching it. Dynamic code execution is about the dynamic part.
  VG014: (match, source, index, spans) => {
    if (isInside(spans, index, 'string')) return false;
    const after = source.slice(index, index + 60);
    return !/^(?:eval|new\s+Function)\s*\(\s*(['"])[A-Za-z_$][\w$]*\1\s*\)/.test(after);
  },

  // `$executeRawUnsafe` is named for who builds the SQL string, not for whether
  // values can be bound — Prisma takes positional parameters after the query.
  // `$executeRawUnsafe(\`INSERT … VALUES ${placeholders}\`, ...params)`, where
  // `placeholders` is `chunk.map(() => "(?, ?)").join(",")`, binds every value.
  VG433: (_match, source, index) => !isParameterized(statementAround(source, index)),

  // The rule's own fix text is "add an auth check at the top of every Server
  // Action that calls a paid LLM provider" — but the pattern only sees a
  // `'use server'` module that constructs a provider and exports a function. It
  // cannot tell whether the auth check is already there, and CTS001 can:
  // matching on the module's own vocabulary keeps this from contradicting it.
  VG1025: (_match, source) =>
    !/\b(auth\.getUser|getServerSession|getServerAuthSession|requireUser|requireAuth|requireUserId|currentUser|handleSessionToken|verifyRequest|getSession)\s*\(/.test(
      source,
    ),

  // `jwt.sign(payload, getJwtSecret(), { expiresIn: TOKEN_EXPIRY })` was
  // reported as a token without expiry: the pattern's `[^)]` scan for
  // `expiresIn` stops at the first `)`, which here belongs to `getJwtSecret()`.
  // Read the whole call before saying the option is absent.
  VG061: (_match, source, index) =>
    !/\b(expiresIn|exp\s*:|setExpirationTime)\b/.test(source.slice(index, index + 300)),

  // `console.log("[App] Got idToken, running audit...")` is a progress message,
  // not a logged credential: "idToken," satisfies the rule's `token` + delimiter
  // because both sit inside the string. What matters is whether the *value* is
  // being logged, and CTS070 checks that against the AST.
  VG080: (match, source, index, spans) => !isInside(spans, index + match.length - 1, 'string'),

  // The "sink" half of the upload rule matched the word *upload* inside a
  // sentence — "Please upload a CSV file exported from Shopify". A filename
  // reaching a string is not a filename reaching a filesystem.
  VG993: (match, source, index, spans) => !isInside(spans, index + match.length - 1, 'string'),

  // A login endpoint is server code. This fired on `<Link href="/login">Back to
  // sign in</Link>` in a client page, where "verify" and "login" are words in
  // markup rather than a password comparison behind an HTTP handler.
  VG148: (match, source) =>
    !/^\s*(['"])use client\1/m.test(source.slice(0, 400)) &&
    /(bcrypt\.compare|argon2\.verify|\b(compare|verify|verifyPassword)\s*\()/.test(match),

  // SSRF is a *server* being made to fetch a URL it should not. A module marked
  // `'use client'` runs in the browser, where the request leaves the user's own
  // machine and crosses no trust boundary of yours.
  VG120: (_match, source) => !/^\s*(['"])use client\1/m.test(source.slice(0, 400)),

  // The name list is prefix-matched with `\w*` after it, so `hashPage === 'x'`
  // and `tokenCount === 3` read as secret comparisons. A timing attack needs the
  // *secret itself* on one side, so the identifier has to be one of those words,
  // not merely start with one.
  // Both of these learned an API name that moved. The Vercel AI SDK replaced
  // `maxSteps` with `stopWhen`, and across a corpus of real agent apps
  // (vercel/ai-chatbot, assistant-ui, the MCP reference servers) `stopWhen` is
  // now the *more* common of the two — 21 files to 14. VG1033 looks only for
  // `maxSteps` / `max_iterations`, and VG999 does not count a step cap at all,
  // so between them they report every correctly-bounded agent loop written
  // against the current SDK. `stopWhen: stepCountIs(5)` is the fix these rules
  // are asking for, and it was being reported as the bug.
  //
  // Read from the whole call, not just the matched head: the regexes stop at
  // the opening brace, so the option that answers them sits past the match.
  VG1033: (_match, source, index) => !HAS_STEP_CAP.test(source.slice(index, index + 1200)),
  VG999: (_match, source, index) => !HAS_STEP_CAP.test(source.slice(index, index + 1200)),

  VG106: (match) => {
    const identifier = /^[A-Za-z_$][\w$]*/.exec(match)?.[0] ?? '';
    return /(secret|token|apikey|api_key|signature|hmac|hash|digest|webhook)$/i.test(identifier);
  },

  // "An attacker can request the entire table" is the rule's premise, and a
  // query filtered to the caller's own rows does not let them. An unbounded
  // fetch of your own data is a scalability question, not a security finding.
  VG955: (match) =>
    !/\bwhere\b[\s\S]{0,200}?\b(userId|user_id|ownerId|owner_id|orgId|org_id|organizationId|tenantId|tenant_id|workspaceId|workspace_id|accountId|account_id|teamId|team_id|shop|shopDomain|storeId|store_id)\b/i.test(
      match,
    ),

};

/** Regexes over very large files are where catastrophic backtracking bites. */
const MAX_BYTES = 400_000;

/** Upstream severities already use our vocabulary; this just narrows the type. */
function severityOf(value: string): Severity {
  return (['critical', 'high', 'medium', 'low', 'info'] as const).includes(value as Severity)
    ? (value as Severity)
    : 'medium';
}

/**
 * Rules that only apply on a platform this project is not. Skipping them is not
 * a judgement about the rule — it is that the advice cannot be followed here.
 */
function inapplicable(ctx: ProjectContext): { ids: ReadonlySet<string>; why: string[] } {
  const ids = new Set<string>();
  const why: string[] = [];

  if (!ctx.framework.reactNative) {
    for (const id of GUARDVIBE_REACT_NATIVE_RULE_IDS) ids.add(id);
    why.push(`${GUARDVIBE_REACT_NATIVE_RULE_IDS.size} React Native rules (not a mobile project)`);
  }

  // VG132 asks for an explicit request-body size limit and says itself that
  // Next.js and Vercel already impose one. On a Next.js project it is advice
  // about a limit the framework has already applied.
  if (ctx.framework.nextjs !== null) {
    ids.add('VG132');
    why.push('VG132 body-size limit (Next.js sets one by default)');
  }

  // A rule that names a platform cannot apply to a project that does not use
  // it. "Supabase Auth Missing Middleware" was reported against an app with no
  // Supabase dependency at all — advice about a library it does not import.
  for (const [name, present, keyword] of [
    ['Supabase', ctx.framework.supabase, /supabase/i],
    ['Firebase', ctx.framework.firebase, /firebase|firestore/i],
  ] as const) {
    if (present) continue;
    let n = 0;
    for (const rule of GUARDVIBE_RULES) {
      if (keyword.test(rule.name) || keyword.test(rule.description)) {
        ids.add(rule.id);
        n++;
      }
    }
    if (n > 0) why.push(`${n} ${name} rules (no ${name} dependency)`);
  }

  return { ids, why };
}

/**
 * Whether a dependency-manifest match sits under `devDependencies`, or in a
 * lockfile entry marked `"dev": true`. Both mean the package is a build-time
 * tool that no user ever runs — the split CTS024 already makes for CVEs found
 * through OSV, applied to the vendored CVE rules that run when offline.
 */
function inDevDependencies(source: string, index: number): boolean {
  const before = source.slice(Math.max(0, index - 4000), index);
  if (/"dev"\s*:\s*true[\s\S]{0,600}$/.test(before)) return true;
  const nearest = /"(dev|peer|optional)?[dD]ependencies"\s*:\s*\{(?![\s\S]*"[a-z]*[dD]ependencies"\s*:\s*\{)/.exec(
    before,
  );
  return nearest?.[1] === 'dev';
}

/**
 * Rules whose upstream severity is right for one shape they match and wrong for
 * another. Returning null leaves the rule's own severity alone.
 */
const SEVERITY_ADJUSTERS: Record<
  string,
  (match: string, source: string, index: number) => { severity: Severity; note: string } | null
> = {
  // The rule matches two different things. Explicitly accepting `alg: none` is
  // the critical it is named for. Merely calling `jwt.verify(token, secret)`
  // without pinning `algorithms` is not: jsonwebtoken has rejected `none` on a
  // keyed verify since v9, so what is left is defence against algorithm
  // confusion — worth doing, not worth blocking a deploy over.
  VG105: (match) =>
    /algorithms\s*:\s*\[\s*['"]none['"]/i.test(match)
      ? null
      : {
          severity: 'medium',
          note:
            ' (Reported at medium: no `algorithms` option is pinned, but nothing here accepts ' +
            '`alg: none` — a keyed `jwt.verify` rejects it. Pinning the algorithm is defence ' +
            'against algorithm confusion, which matters most when the key could be a public key.)',
        },
};

export const communityScanner: Scanner = {
  name: `Community ruleset (${GUARDVIBE_RULES.length - SUPERSEDED.size - WITHHELD.size} rules)`,

  applies() {
    return true;
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    const platform = inapplicable(ctx);
    const active = GUARDVIBE_RULES.filter(
      (r) => !SUPERSEDED.has(r.id) && !WITHHELD.has(r.id) && !platform.ids.has(r.id),
    );
    const seen = new Set<string>();
    let filesScanned = 0;

    for (const file of ctx.files) {
      const languages = languagesFor(file);
      if (languages.length === 0) continue;
      const source = read(file);
      if (source === null || source.length > MAX_BYTES) continue;

      const relPath = rel(ctx.root, file);
      const lockfile = LOCKFILE.test(relPath);
      const spans = lexSpans(source, commentStyleFor(languages));
      const suppress = new Suppressions(source);
      filesScanned++;

      for (const rule of active) {
        if (!rule.languages.some((l) => languages.includes(l))) continue;
        if (lockfile && MANIFEST_ONLY.has(rule.id)) continue;
        const guard = MATCH_GUARDS[rule.id];

        const re = rule.pattern;
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        let matches = 0;
        while ((m = re.exec(source)) !== null) {
          // A zero-width match would spin forever on a global regex.
          if (m[0].length === 0) {
            re.lastIndex++;
            continue;
          }
          // Skipping a match must not skip the non-global `break` below, or a
          // rule without /g would rescan from zero forever.
          // A rule that matched inside a comment matched prose about code, not
          // code. Nothing in the vendored ruleset targets comment content, and
          // a commented-out call is not a call.
          if (isInside(spans, m.index, 'comment')) {
            if (!re.global) break;
            continue;
          }
          if (guard && !guard(m[0], source, m.index, spans)) {
            if (!re.global) break;
            continue;
          }
          const line = lineAt(source, m.index);
          const key = `${relPath}:${line}:${rule.id}`;
          if (!seen.has(key) && !suppress.suppressed(line, rule.id)) {
            seen.add(key);
            let adjusted = SEVERITY_ADJUSTERS[rule.id]?.(m[0], source, m.index) ?? null;
            // A CVE in something that only ever runs on a build machine is not
            // a shipping vulnerability. OSV-sourced findings are already split
            // this way (CTS024); this is the same split for the vendored CVE
            // rules, which are what runs with --offline.
            if (
              !adjusted &&
              GUARDVIBE_CVE_RULE_IDS.has(rule.id) &&
              (lockfile || /(^|\/)package\.json$/.test(relPath)) &&
              inDevDependencies(source, m.index)
            ) {
              adjusted = {
                severity: 'low',
                note:
                  ' (Reported at low: this version is declared under devDependencies, so it is a ' +
                  'build-time tool rather than something your users run.)',
              };
            }
            const placed = adjustForPath(adjusted?.severity ?? severityOf(rule.severity), relPath);
            result.findings.push({
              id: rule.id,
              severity: placed.severity,
              title: rule.name,
              detail: rule.description + (adjusted?.note ?? '') + placed.note,
              fix: rule.fixCode ? `${rule.fix}\n\n${rule.fixCode}` : rule.fix,
              file: relPath,
              line,
              snippet: snippetAt(source, line),
              owasp: rule.owasp,
              meta: {
                source: 'guardvibe',
                attribution: GUARDVIBE_ATTRIBUTION,
                compliance: rule.compliance,
              },
            });
          }
          // One finding per rule per file is enough to act on.
          if (++matches >= 3) break;
          if (!re.global) break;
        }
      }
    }

    result.checks.push({
      label: `Community ruleset (${active.length} rules over ${filesScanned} files)`,
      passed: result.findings.every((f) => f.severity !== 'critical'),
      note:
        `${SUPERSEDED.size} superseded by ClearToShip's AST checks, ${WITHHELD.size} withheld as noisy, ` +
        `${MANIFEST_ONLY.size} manifest-only (not run over lockfiles)` +
        (platform.why.length ? `; skipped as inapplicable: ${platform.why.join(', ')}` : ''),
    });
    return result;
  },
};
