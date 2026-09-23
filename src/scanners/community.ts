import { performance } from 'node:perf_hooks';
import { read, rel, languagesFor } from '../utils/files.js';
import { LineIndex, clip } from '../utils/line-index.js';
import { redactCredential } from '../utils/entropy.js';
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
 * Those marked inline are superseded by the RLS and Server Actions scanners
 * (`rls.ts`, `server-actions.ts`). They stay suppressed on purpose: standing the
 * vendored versions up as fallback coverage reported `VG1010` — critical — on
 * `clean-app`'s `updateProfile`, a Server Action proven safe by the fixture's own
 * doc comment (an explicit field list, no caller-controlled columns). The vendored
 * version is "the weaker result" for a reason: it is a no-schema-library-detected
 * pattern match, not real argument-flow analysis, and running it would trade the
 * precise first-party result for a false "critical" on correct code — worse for a
 * tool whose whole trust model is "a true positive a developer will act on, not
 * coverage for its own sake."
 */
const SUPERSEDED = new Map<string, string>([
  ['VG400', 'CTS033/CTS040'],
  ['VG401', 'CTS002'], // Server Actions suite
  ['VG402', 'CTS001'], // Server Actions suite
  ['VG411', 'CTS031'],
  ['VG420', 'CTS001'], // Server Actions suite
  ['VG427', 'CTS041'], // Server Actions suite
  ['VG439', 'CTS016'], // RLS suite
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
  ['VG953', 'CTS043'], // Server Actions suite
  ['VG998', 'CTS045'],
  ['VG437', 'CTS033'],
  ['VG860', 'CTS028'],
  ['VG874', 'CTS028'],
  ['VG876', 'CTS031'],
  ['VG952', 'CTS001'], // Server Actions suite
  ['VG960', 'CTS044'], // Server Actions suite
  ['VG1007', 'CTS003'], // Server Actions suite
  ['VG1010', 'CTS002'], // Server Actions suite
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
 * The real argument list of a call whose name starts at `index`: counts parens
 * from the call's own `(` to its matching `)`, so a nested call inside an
 * argument does not look like the end of the outer one. Bounded, since this
 * only ever runs on the handful of matches one rule produces per file.
 */
function callArgs(source: string, index: number): string {
  const open = source.indexOf('(', index);
  if (open === -1) return '';
  let depth = 0;
  for (let i = open; i < source.length && i < open + 4000; i++) {
    if (source[i] === '(') depth++;
    else if (source[i] === ')') {
      depth--;
      if (depth === 0) return source.slice(open + 1, i);
    }
  }
  return source.slice(open + 1, open + 4000);
}

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

  // Two bugs stacked on one real app. First: the bare-identifier alternative
  // `verifyToken` matches the literal text "verifyToken(" wherever it appears —
  // including the function's own DECLARATION, `export function verifyToken(token:
  // string): JwtPayload | null {`, which is not a call at all. `function`
  // immediately before the name is the tell; a declaration's own body then reads
  // as if it were the call's arguments. Second, even at a genuine call, the "no
  // `algorithms` option" branch trusts its own `\s*\)` to mark where the call
  // ends — but the second argument is often itself a call,
  // `jwt.verify(token, getJwtSecret(), { algorithms: ["HS256"] })`, and the regex
  // backtracks onto getJwtSecret()'s own closing paren rather than reading past
  // it: it matches only `jwt.verify(token, getJwtSecret()` and never sees the
  // real options object. Re-find the call's actual matching paren by counting
  // braces instead of trusting where the regex gave up, and keep the finding
  // only when algorithms is truly absent from what is inside it. The other
  // alternative this rule matches — a literal `algorithms: ["none"]` — needs
  // neither check: it is unambiguous wherever it appears.
  VG105: (match, source, index) => {
    if (!/^(?:jwt\.verify|jwtVerify|verifyToken)/i.test(match)) return true;
    const before = source.slice(Math.max(0, index - 20), index);
    if (/(?:^|[\s;{}])(?:async\s+)?function\s*$/.test(before)) {
      // The match is anchored on the declaration, which swallowed everything up
      // to wherever the real call inside the function body happened to close —
      // not necessarily that call's own true end. What decides the question is
      // the genuine `jwt.verify`/`jwtVerify` call inside the body, wherever it
      // is, found by searching from the real source rather than trusting the
      // span the outer, wrong match already committed to.
      const inner = /(?:jwt\.verify|jwtVerify)\s*\(/.exec(match);
      if (!inner) return false;
      return !/algorithms\s*:/.test(callArgs(source, index + inner.index));
    }
    return !/algorithms\s*:/.test(callArgs(source, index));
  },

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

  // The negative lookahead in this rule can never fire: its tempered run may be
  // empty, so any `)` within 500 characters of the call's `(` completes a
  // match, and `new ApolloServer({ introspection: false })` — the fix the rule
  // asks for, and the rule's own `fixCode` — was reported as the problem. Read
  // the call's real argument list for the setting instead.
  VG974: (_match, source, index) =>
    !/\bintrospection\s*:\s*(?:false\b|[^,}\n]*(?:NODE_ENV|production|isProd|isDev))|useDisableIntrospection/.test(
      callArgs(source, index),
    ),

  // The name list is prefix-matched with `\w*` after it, so `hashPage === 'x'`
  // and `tokenCount === 3` read as secret comparisons. A timing attack needs the
  // *secret itself* on one side, so the identifier has to be one of those words,
  // not merely start with one.
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

/**
 * Bounded replacements for vendored patterns whose backtracking is super-linear
 * in the size of the file. The vendored files stay a faithful copy of upstream;
 * the replacement is used in its place at runtime. Each one matches at exactly
 * the positions upstream's does for any input with the features the rule is
 * about within a few kilobytes of each other — the only difference is that the
 * search from any one position is bounded, so a file of the rule's own trigger
 * word repeated cannot stall the scan. `test/rules-audit.test.js` checks each
 * against its original, position by position, on generated inputs.
 */
export const PATTERN_OVERRIDES: Record<string, RegExp> = {
  // Upstream: `TRIGGER[\s\S]{0,500}?(?:(?!X-Content-Type-Options|nosniff)[\s\S]){10,}?TERMINATOR`.
  // A lazy skip of up to 500 characters, then an *unbounded* tempered run —
  // every split of the gap between the two is tried, from every trigger. A file
  // of `res.sendFile(` repeated took 8.5 s at 8 KB and grew about 4.5x per
  // doubling. Reading the pattern for what it accepts: the skip can always be
  // stretched so the tempered run is its minimum of ten characters, so a
  // terminator 10-510 characters on matches unless `nosniff` starts in the ten
  // characters before it (`X-Content-Type-Options` is 22 long and cannot fit
  // there without overlapping the terminator), and a terminator further on
  // matches when nothing forbidden starts past the 500th character. The second
  // branch is where the bound is: 2,000 characters past that point.
  VG678:
    /(?:res\.sendFile|res\.download|createReadStream|getSignedUrl|getPublicUrl|\.pipe\s*\(\s*res)(?:[\s\S]{10,510}?(?<!nosniff[\s\S]{0,3})(?:res\.end|\.pipe|return|response)|[\s\S]{500}(?:(?!X-Content-Type-Options|nosniff)[\s\S]){11,2000}?(?:res\.end|\.pipe|return|response))/gi,

  // Upstream: `TRIGGER\s*\([\s\S]{0,500}?(?:(?!introspection\s*:\s*false)[\s\S]){0,300}\)`,
  // the same nested shape: 80 KB took 3 s. The tempered run may be empty, so
  // any `)` within 500 characters of the `(` matches outright, and one up to
  // 300 further matches when `introspection: false` does not start past the
  // 500th character. That is all this says, with each branch bounded.
  VG974:
    /(?:introspection\s*:\s*true|enableIntrospection|ApolloServer|createYoga|createHandler)\s*\((?:[\s\S]{0,500}?\)|[\s\S]{500}(?:(?!introspection\s*:\s*false)[\s\S]){0,300}?\))/g,

  // Upstream: `echo\s+['"]?[^'"|\n]+['"]?\s*\|…|(?:mysql|psql|mongosh?)\s+.*-p…`.
  // `[^'"|\n]+` and `.*` each run to the end of the line from every `echo` or
  // `mysql` on it and backtrack all the way home when there is no pipe or `-p`,
  // so one long line of them is quadratic. A command line is not 500
  // characters of echo payload or of flags before the password.
  VG533:
    /(?:echo\s+['"]?[^'"|\n]{1,500}['"]?\s*\|\s*sudo\s+-[Ss]|(?:mysql|psql|mongosh?)\s+.{0,500}-p\s*['"]?\w+['"]?)/gi,

  // Upstream: `TRIGGER\w*\s*(?:=\s*async|\([\s\S]*?\)\s*(?:=>|{))(?:(?!confirm|…)[\s\S]){10,}?(?:delete|…)\s*\(`.
  // Found on real code, not a fuzz input: `terminat` matches `terminator`, and
  // from each one the unbounded parameter list and tempered run search the
  // rest of the file — six seconds on @babel/parser's 480 KB build, against
  // single-digit milliseconds for every other rule. Bounded here to a
  // 1,000-character parameter list and a destructive call within 3,000
  // characters of it; a function body further from its own signature than
  // that is not what this rule is reading anyway.
  VG958:
    /(?:deleteAccount|deleteUser|cancelSubscription|transferFunds|refund|terminat)\w*\s*(?:=\s*async|\([\s\S]{0,1000}?\)\s*(?:=>|{))(?:(?!confirm|verify|reauthenticate|twoFactor|2fa|otp|challenge)[\s\S]){10,3000}?(?:delete|destroy|remove|cancel)\s*\(/gi,
};

/**
 * Files up to the walker's own 2 MB cap are run through the ruleset. This was
 * 400 KB, and a file between the two was skipped here without a word: an
 * `eval(req.body.code)` in a 420 KB module was never looked at, the run said
 * clear, and nothing said why.
 *
 * The 400 KB cap existed for a real reason — fuzzing the ruleset with each
 * rule's own trigger word repeated finds more than a dozen patterns whose cost
 * grows with the square of the input — so the files above it are not handed
 * to a regex whole. They are searched in line-aligned windows (below), which
 * caps what one uninterruptible `exec` can cost at what a WINDOW-sized input
 * costs, and makes the total linear in the size of the file.
 */
const MAX_BYTES = 2_000_000;

/** Files above this are searched in windows rather than whole. The old cap, so nothing it scanned changes. */
const WINDOW_FROM = 400_000;
/** Each window owns this many characters: a match is taken from the window it starts in. */
const WINDOW = 64_000;
/**
 * How far past its own region a window reads, so a match that starts near the
 * end of one window can finish. Real matches for these rules are a few
 * hundred characters; a match longer than this starting in the last stretch
 * of a window would be missed, and that is the only difference windowing makes.
 */
const WINDOW_OVERLAP = 16_000;

/**
 * A rule that spends longer than this per 400 KB of input on one file is
 * behaving super-linearly on it. It is not run on any file at least half that
 * size again (a quadratic rule at half the size costs a quarter), and each file
 * it was not run on is reported as not checked. The budget is checked before
 * each search, so a rule that exceeds it part-way through a file stops there,
 * and that file is reported too.
 */
const RULE_BUDGET_MS = 250;

function budgetFor(length: number): number {
  return RULE_BUDGET_MS * Math.max(1, length / WINDOW_FROM);
}

/**
 * A pattern anchored to the start of its *input* (leading `^` without the `m`
 * flag — VG964 reads the whole module through lookaheads from there) or to its
 * end (`$`: VG446) would match at window boundaries, so it is run over the
 * whole file. A `(?:^|\n)` alternative is fine windowed: windows start on a
 * line, where it would match anyway.
 */
export function anchoredToInput(re: RegExp): boolean {
  if (re.multiline) return false;
  const source = re.source.replace(/\\\\/g, '').replace(/\[(?:\\.|[^\]\\])*\]/g, '');
  return source.startsWith('^') || /(?:^|[^\\])\$/.test(source);
}

interface Segment {
  /** Offset of `text` in the file. */
  start: number;
  /** Matches starting at or past this offset belong to the next segment. */
  ownEnd: number;
  text: string;
}

/** The whole file, or line-aligned windows of it for a large file. */
function segmentsOf(source: string, whole: boolean): Segment[] {
  if (whole || source.length <= WINDOW_FROM) {
    return [{ start: 0, ownEnd: source.length, text: source }];
  }
  const segments: Segment[] = [];
  let start = 0;
  while (start < source.length) {
    let ownEnd = Math.min(source.length, start + WINDOW);
    if (ownEnd < source.length) {
      const newline = source.indexOf('\n', ownEnd);
      // A file with no newline for a long way is still windowed, just not on a line.
      ownEnd = newline === -1 || newline - ownEnd > WINDOW_OVERLAP / 2 ? ownEnd : newline + 1;
    }
    const end = Math.min(source.length, ownEnd + WINDOW_OVERLAP);
    segments.push({ start, ownEnd: ownEnd >= source.length ? source.length : ownEnd, text: source.slice(start, end) });
    start = ownEnd;
  }
  return segments;
}

/**
 * `lexSpans` declines inputs over 1 MB and returns no spans, which would read
 * every comment in a 1-2 MB file as code. Lex it in line-aligned halves
 * instead; only a block comment or template literal straddling the split can
 * be misread.
 */
function lexLarge(source: string, style: ReturnType<typeof commentStyleFor>): Span[] {
  const LIMIT = 900_000;
  if (source.length <= LIMIT) return lexSpans(source, style);
  const spans: Span[] = [];
  let start = 0;
  while (start < source.length) {
    let end = Math.min(source.length, start + LIMIT);
    if (end < source.length) {
      const newline = source.lastIndexOf('\n', end);
      if (newline > start) end = newline + 1;
    }
    for (const s of lexSpans(source.slice(start, end), style)) {
      spans.push({ start: s.start + start, end: s.end + start, kind: s.kind });
    }
    start = end;
  }
  return spans;
}

/**
 * Vendored rules about a credential, by their own name. Their match is the
 * credential more often than not, and the snippet printed it whole: `VG003`
 * on `--api-key sk_live_…` quoted the live key into the report.
 */
const CREDENTIAL_RULE =
  /hardcoded|hard-coded|secret|credential|api key|token|password|connection string|service account key/i;

/**
 * The line with every credential-looking value inside `match` redacted: a
 * quoted value with no spaces in it, or an opaque run of 16+ characters with a
 * digit (which leaves variable names like `STRIPE_SECRET_KEY` readable).
 */
function redactMatchInLine(lineText: string, match: string): string {
  const values = new Set<string>();
  for (const q of match.matchAll(/(["'`])([^\s"'`]{8,})\1/g)) values.add(q[2]!);
  for (const run of match.matchAll(/[A-Za-z0-9_\-+/=.]{16,}/g)) {
    if (/\d/.test(run[0]) && !/^(?:process\.env|import\.meta)/.test(run[0])) values.add(run[0]);
  }
  let text = lineText;
  for (const value of [...values].sort((a, b) => b.length - a.length)) {
    text = text.split(value).join(redactCredential(value));
  }
  return clip(text.trim());
}

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
    // Files the ruleset did not read, or read only partly, and why.
    const oversize: string[] = [];
    const failed: string[] = [];
    // Rule id -> the size of the file on which it overran RULE_BUDGET_MS.
    const slowRules = new Map<string, number>();
    // Rule id -> files it was skipped on, or stopped part-way through.
    const unchecked = new Map<string, string[]>();
    const markUnchecked = (id: string, relPath: string) => {
      const list = unchecked.get(id) ?? [];
      list.push(relPath);
      unchecked.set(id, list);
    };

    for (const file of ctx.files) {
      const languages = languagesFor(file);
      if (languages.length === 0) continue;
      const relPath = rel(ctx.root, file);
      // One file that throws must cost that file, not the rest of the run.
      try {
      const source = read(file);
      if (source === null) continue;
      if (source.length > MAX_BYTES) {
        oversize.push(relPath);
        continue;
      }

      const lockfile = LOCKFILE.test(relPath);
      const spans = lexLarge(source, commentStyleFor(languages));
      const suppress = new Suppressions(source);
      const lines = new LineIndex(source);
      filesScanned++;

      for (const rule of active) {
        if (!rule.languages.some((l) => languages.includes(l))) continue;
        if (lockfile && MANIFEST_ONLY.has(rule.id)) continue;
        const slowAt = slowRules.get(rule.id);
        if (slowAt !== undefined && source.length >= slowAt / 2) {
          markUnchecked(rule.id, relPath);
          continue;
        }
        const guard = MATCH_GUARDS[rule.id];
        const credential = CREDENTIAL_RULE.test(rule.name);

        const re = PATTERN_OVERRIDES[rule.id] ?? rule.pattern;
        let m: RegExpExecArray | null;
        let matches = 0;
        const started = performance.now();
        const budget = budgetFor(source.length);
        let cutShort = false;
        segments: for (const segment of segmentsOf(source, anchoredToInput(re))) {
        re.lastIndex = 0;
        // The budget is checked before each further search, so a match already
        // found is always handled and only the unsearched remainder is lost.
        for (;;) {
          if (performance.now() - started > budget) {
            cutShort = true;
            break segments;
          }
          m = re.exec(segment.text);
          if (m === null) break;
          // A zero-width match would spin forever on a global regex.
          if (m[0].length === 0) {
            re.lastIndex++;
            continue;
          }
          const index = segment.start + m.index;
          // Past this window's own region: the next window reads it from its start.
          if (index >= segment.ownEnd) break;
          // Skipping a match must not skip the non-global `break` below, or a
          // rule without /g would rescan from zero forever.
          // A rule that matched inside a comment matched prose about code, not
          // code. Nothing in the vendored ruleset targets comment content, and
          // a commented-out call is not a call.
          if (isInside(spans, index, 'comment')) {
            if (!re.global) break;
            continue;
          }
          if (guard && !guard(m[0], source, index, spans)) {
            if (!re.global) break;
            continue;
          }
          // Some rules open with `(?:^|\n)\s*`, so the match starts on the
          // newline ending the previous line. Locate the first character that
          // is actually part of the finding, or it is reported one line early.
          const line = lines.lineAt(index + (m[0].length - m[0].trimStart().length));
          const key = `${relPath}:${line}:${rule.id}`;
          if (!seen.has(key) && !suppress.suppressed(line, rule.id)) {
            seen.add(key);
            let adjusted = SEVERITY_ADJUSTERS[rule.id]?.(m[0], source, index) ?? null;
            // A CVE in something that only ever runs on a build machine is not
            // a shipping vulnerability. OSV-sourced findings are already split
            // this way (CTS024); this is the same split for the vendored CVE
            // rules, which are what runs with --offline.
            if (
              !adjusted &&
              GUARDVIBE_CVE_RULE_IDS.has(rule.id) &&
              (lockfile || /(^|\/)package\.json$/.test(relPath)) &&
              inDevDependencies(source, index)
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
              snippet: credential
                ? redactMatchInLine(lines.lineText(line), m[0])
                : lines.snippet(line),
              owasp: rule.owasp,
              meta: {
                source: 'guardvibe',
                attribution: GUARDVIBE_ATTRIBUTION,
                compliance: rule.compliance,
              },
            });
          }
          // One finding per rule per file is enough to act on.
          if (++matches >= 3) break segments;
          if (!re.global) break;
        }
        }
        if (cutShort) markUnchecked(rule.id, relPath);
        if (performance.now() - started > budget) {
          const previous = slowRules.get(rule.id);
          slowRules.set(rule.id, previous === undefined ? source.length : Math.min(previous, source.length));
        }
      }
      } catch (err) {
        failed.push(`${relPath} (${err instanceof Error ? err.message : String(err)})`);
      }
    }

    const notes = [
      `${SUPERSEDED.size} superseded by ClearToShip's AST checks, ${WITHHELD.size} withheld as noisy, ` +
        `${MANIFEST_ONLY.size} manifest-only (not run over lockfiles)`,
    ];
    if (Object.keys(PATTERN_OVERRIDES).length > 0) {
      notes.push(
        `${Object.keys(PATTERN_OVERRIDES).length} run with a bounded pattern in place of upstream's ` +
          `(${Object.keys(PATTERN_OVERRIDES).join(', ')})`,
      );
    }
    if (platform.why.length) notes.push(`skipped as inapplicable: ${platform.why.join(', ')}`);
    const incomplete = result.incomplete!;
    if (oversize.length > 0) {
      notes.push(`${oversize.length} file${oversize.length === 1 ? '' : 's'} over ${MAX_BYTES / 1_000_000} MB not read`);
      for (const f of oversize) {
        incomplete.push(`${f} is over the community ruleset's ${MAX_BYTES / 1_000_000} MB limit and was not checked by it.`);
      }
    }
    for (const [id, files] of [...unchecked].sort(([a], [b]) => a.localeCompare(b))) {
      const shown = `${files.slice(0, 3).join(', ')}${files.length > 3 ? `, and ${files.length - 3} more` : ''}`;
      notes.push(`${id} stopped on ${files.length} file${files.length === 1 ? '' : 's'} after exceeding its time budget (${RULE_BUDGET_MS} ms per 400 KB)`);
      incomplete.push(
        `${id} exceeded its time budget (${RULE_BUDGET_MS} ms per 400 KB of file) and was not run to completion on ${shown}; ` +
          'what it looks for there was not checked.',
      );
    }
    for (const f of failed) {
      incomplete.push(`The community ruleset could not finish ${f}; the rest of that file was not checked.`);
    }

    result.checks.push({
      label: `Community ruleset (${active.length} rules over ${filesScanned} files)`,
      passed: result.findings.every((f) => f.severity !== 'critical'),
      note: notes.join('; '),
    });
    return result;
  },
};
