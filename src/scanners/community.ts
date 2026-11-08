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
  // Same defect, same line, twice: CTS081 reads the call's own option keys for
  // `max_tokens` / `maxTokens` / `maxOutputTokens` off the AST, and only where
  // the call is reachable from a request — which is the calibration, not an
  // omission. A model call in a build script with no ceiling is not a bill
  // anyone else can run up.
  ['VG999', 'CTS081'], // LLM & agent suite
  // Every callee VG123 names (`query`, `execute`, `prepare`, `db.run`…) is in
  // VG010's own verb list, followed by the same backtick-plus-`${` shape, so the
  // two reported the same line twice across the sweep (24 of 24 VG123 findings).
  // Upstream agrees — its own test comments call VG010 "the concat rule (which
  // dedup-takes-over)". What VG123 added beyond the duplicates was only the
  // matches VG010's guard had dropped for not being SQL at all
  // (`querySelectorAll`-class verbs with no SQL keyword in the statement).
  ['VG123', 'VG010'],
  // VG408 matches `dangerouslySetInnerHTML={{ __html:` and VG012 matches
  // `innerHTML` followed by `=` or `:` — and `dangerouslySetInnerHTML` *ends*
  // in `InnerHTML`, case-insensitively, so every VG408 match is a VG012 match
  // at the same position. Proven, not assumed: 15 of 15 raw VG408 matches
  // across the seven dogfooding repos, and by construction too — VG408 needs a
  // `{` after the `=`, which is exactly what VG012's `(?!['"]<)` lookahead
  // lets through.
  //
  // Keeping both did not merely double-report. The 2026-10-13 audit spent a
  // pass teaching VG012 the difference between an HTML sink and a `<style>`
  // element's CSS text, an all-literal expression, and a value already through
  // an escaper. VG408 carries no guard, so it reported all of it again under a
  // different id: eight `<style dangerouslySetInnerHTML={{ __html: css }} />`
  // on app C — the very shape that audit cleared — plus three
  // `sanitizeJsonLd(...)` / `sanitizeThemeInit(...)` calls, and three lines
  // where it simply said what VG012 had already said. Fourteen findings, not
  // one of them a true positive VG012 does not already report. A guarded rule
  // beside an unguarded copy of itself means the guard does nothing.
  ['VG408', 'VG012'],
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
  // `password="[REDACTED]"` is what a log *sanitizer* writes — this fired on
  // the replacement string of a redaction helper, reported critical.
  if (/^\[[^\[\]]+\]$/.test(trimmed)) return false;
  if (/\b(?:REDACTED|MASKED|FILTERED|SANITIZED|CENSORED)\b/.test(trimmed)) return false;
  // A password hash is a verifier, not a credential: presenting it does not
  // authenticate anybody. `DUMMY_PASSWORD_HASH = '$2b$12$…'` — the standard
  // timing-equalization idiom on a login route — was a critical.
  if (/^\$(?:2[abxy]?\$\d{1,2}\$|argon2(?:id|i|d)?\$|scrypt\$|pbkdf2)/.test(trimmed)) return false;
  // Documentation samples: a token whose body is the keyboard walk
  // `1234567890abcdef`, or that ends in an ellipsis because the author cut it.
  if (/1234567890abcdef/i.test(trimmed)) return false;
  if (/(?:\.\.\.|…)$/.test(trimmed)) return false;
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

/**
 * The template literal a SQL match points into: its constant text with every
 * `${…}` hole blanked, and each hole's own expression. Null when no template
 * starts near the match or it does not close within the bound.
 */
function templateParts(source: string, index: number): { text: string; holes: string[] } | null {
  const open = source.indexOf('`', index);
  if (open === -1 || open - index > 160) return null;
  let text = '';
  const holes: string[] = [];
  for (let i = open + 1; i < source.length && i < open + 2000; i++) {
    const ch = source[i]!;
    if (ch === '\\') {
      text += ' ';
      i++;
      continue;
    }
    if (ch === '`') return { text, holes };
    if (ch === '$' && source[i + 1] === '{') {
      let depth = 1;
      let j = i + 2;
      for (; j < source.length && j < i + 600 && depth > 0; j++) {
        if (source[j] === '{') depth++;
        else if (source[j] === '}') depth--;
      }
      holes.push(source.slice(i + 2, j - 1));
      text += ' ';
      i = j - 1;
      continue;
    }
    text += ch;
  }
  return null;
}

/**
 * An interpolation that is itself a call to a SQL quoting helper —
 * `${quoteIdent(table)}`, `${escapeId(col)}`, `${mysql.escape(v)}` — is the
 * escaping the rule asks for, written inline where the guard can see it. The
 * HTML/URL escapers are excluded: `escapeHtml(v)` in a SQL string is still the
 * bug. A bare identifier that merely *holds* a quoted value stays reported,
 * because proving that is dataflow — the same line VG012 draws.
 */
const SQL_QUOTE_CALL = /^[\w$.]*(?:quote|escape|esc)[\w$]*\s*\(/i;
const NOT_SQL_ESCAPER = /html|xml|attr|ur[il]|regex/i;

/** The verb has to be a SQL verb, and the statement must not be parameterized. */
function sqlGuard(match: string, source: string, index: number): boolean {
  const verb = /^[A-Za-z_]+/.exec(match)?.[0] ?? '';
  if (!SQL_VERBS.test(verb) && !SQL_KEYWORDS.test(match)) return false;
  const tpl = templateParts(source, index);
  if (tpl) {
    // MAXRESULTS and STARTPOSITION are QuickBooks Query Language, which exists
    // only as a URL parameter to Intuit's HTTP API: no SQL driver ever parses
    // this string, and that API has no parameterized form to recommend. Three
    // criticals titled "SQL injection" on a QuickBooks integration's queries.
    if (/\b(?:MAXRESULTS|STARTPOSITION)\b/.test(tpl.text)) return false;
    if (
      tpl.holes.length > 0 &&
      tpl.holes.every((h) => {
        const hole = h.trim();
        return SQL_QUOTE_CALL.test(hole) && !NOT_SQL_ESCAPER.test(hole);
      })
    ) {
      return false;
    }
  }
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
/**
 * The function body a match sits in, back to that function's own opening brace.
 *
 * A guard that asks "is the check above this line?" must ask it of the scope
 * the line is in. Reading the whole file (which VG1025's guard does) credits a
 * check written in a different function; reading a fixed window backwards cuts
 * through the function header. So the walk goes backwards over balanced braces
 * and stops at the first unbalanced `{` that a function or arrow header opened,
 * climbing out of the `if`/`try`/`for` blocks on the way.
 */
export function enclosingBody(source: string, index: number, limit = 4000): string {
  const floor = Math.max(0, index - limit);
  let start = floor;
  let depth = 0;
  let climbs = 0;
  for (let i = index - 1; i >= floor; i--) {
    const c = source[i];
    if (c === '}') {
      depth++;
      continue;
    }
    if (c !== '{') continue;
    if (depth > 0) {
      depth--;
      continue;
    }
    start = i + 1;
    const header = source.slice(Math.max(floor, i - 80), i);
    const block = /\b(?:if|for|while|switch|try|catch|else|do)\s*(?:\([^()]*\))?\s*$/.test(header);
    const fn = /(?:function\b[^(){}]*\([^()]*\)|=>|\)\s*(?::\s*[\w<>[\].|,? ]+)?)\s*$/.test(header);
    if (fn && !block) break;
    if (++climbs >= 3) break;
  }
  return source.slice(start, index);
}

/**
 * The expression assigned at an `x.innerHTML = …` match: from the `=` to the
 * end of the statement, bounded, with nesting respected so a `}` inside a
 * callback does not end it early.
 */
function assignedExpression(source: string, index: number, limit = 1200): string {
  const at = /[=:]/.exec(source.slice(index, index + 40));
  if (!at) return '';
  const eq = index + at.index;
  let depth = 0;
  const end = Math.min(source.length, eq + limit);
  for (let i = eq + 1; i < end; i++) {
    const c = source[i]!;
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) return source.slice(eq + 1, i);
      depth--;
    } else if (depth === 0 && c === ';') {
      return source.slice(eq + 1, i);
    } else if (depth === 0 && c === '\n') {
      // A newline ends the expression only when nothing continues it. A
      // multi-line ternary of two string literals read as the bare condition
      // on the first line, which looks dynamic when the value cannot be.
      const before = source.slice(eq + 1, i).trimEnd();
      const after = source.slice(i + 1, i + 40).trimStart();
      const continues = /[?:+,.|&([{=-]$/.test(before) || /^[?:+.,|&)\]}]/.test(after);
      if (!continues) return source.slice(eq + 1, i);
    }
  }
  return source.slice(eq + 1, end);
}

/** Calls whose output is HTML-safe by the time it is assigned. */
const ESCAPES_HTML =
  /\b(?:esc|escape|htmlEsc|sanitiz|sanitis|purif|xss|encodeURI)[A-Za-z]*\s*\(|\bDOMPurify\b/i;

/**
 * Whether an expression carries anything that is not a literal.
 *
 * Deliberately conservative: a bare identifier counts. Proving that the string
 * behind one is a module constant rather than a request parameter is dataflow
 * work (what CTS084 does for model output), and a guard that assumed "bare
 * name = safe" would drop `el.innerHTML = untrustedHtml`, which is the finding.
 */
function hasDynamicPart(expr: string): boolean {
  // In `showing ? '<path …/>' : '<path …/>'` — an icon swap, and 1 of the 7
  // findings the first HTML-reading scan produced — the condition is a name and
  // both values are literals. Only the values reach the sink, so only they are
  // read: a `?` that opens a conditional, never `?.` or `??`, and never one
  // inside a string.
  const conditional = /^[^?'"`]*\?(?![.?])/.exec(expr);
  const body = conditional ? expr.slice(conditional[0].length) : expr;
  // Every string literal, template literal and number taken out: what is left
  // of `'<b>' + 'x'` is operators and whitespace, and of `'<b>' + name` is a name.
  const rest = body
    .replace(/`(?:[^`\\]|\\.)*`/g, ' ')
    .replace(/'(?:[^'\\\n]|\\.)*'/g, ' ')
    .replace(/"(?:[^"\\\n]|\\.)*"/g, ' ')
    .replace(/\b\d+(?:\.\d+)?\b/g, ' ')
    .replace(/\b(?:true|false|null|undefined)\b/g, ' ');
  // A template literal with an interpolation is dynamic whatever is around it.
  if (/`(?:[^`\\]|\\.)*\$\{/.test(body)) return true;
  return /[A-Za-z_$]/.test(rest);
}

/**
 * A call that establishes a URL is safe to fetch before it is fetched — an
 * allowlist check, a private-IP rejection, a URL parser used as a gate. This is
 * the SSRF equivalent of `ESCAPES_HTML`, and the same judgement: a call whose
 * name says it validates the URL is credited, because the alternative is to
 * report the mitigation.
 */
const SSRF_VALIDATED =
  /\b(?:assert|validate|check|ensure|guard|is)[A-Za-z]*(?:Url|URL|Uri|URI|Host|Origin|Fetchable|Address)[A-Za-z]*\s*\(/;

/** An origin no caller can move: an absolute literal, or one read from the environment. */
const LITERAL_ORIGIN = /^\s*['"`]https?:\/\/[^\s'"`$]/;
const ENV_ORIGIN =
  /^\s*(?:process\.env\b|Deno\.env\.get\s*\(|import\.meta\.env\b|(?:context\.|c\.)?env\.[A-Z_]\w*)/;
/**
 * A quoted hostname with no scheme — `const SHOP = "shop.myshopify.com"`, used
 * as `` `https://${SHOP}/admin/api/2026-04` ``. The scheme is in the template
 * and the host is this literal, so the origin is still fixed.
 */
// Written without a nested quantifier on purpose: `[\w-]+(?:\.[\w-]+)+` is the
// shape VG153 exists to find, and this project's own self-scan reported it the
// moment it was written. One character class plus a "has a dot" test says the
// same thing with nothing to backtrack over.
const LITERAL_HOST = /^\s*(['"])([\w.-]+)\1\s*$/;

function isLiteralHost(expr: string): boolean {
  const m = LITERAL_HOST.exec(expr);
  return m !== null && m[2]!.includes('.') && !m[2]!.startsWith('.') && !m[2]!.endsWith('.');
}

/**
 * Split a conditional expression at its top-level `?` and `:`, ignoring any
 * inside quotes. A regex cannot: both branches of
 * `sandbox ? "https://a.example" : "https://b.example"` contain the `:` of
 * their own scheme, which is how the first version of this guard reported two
 * QuickBooks callers it had cleared one line earlier.
 */
function splitTernary(expr: string): [string, string] | null {
  let quote = '';
  let depth = 0;
  let q = -1;
  let colon = -1;
  for (let i = 0; i < expr.length; i++) {
    const c = expr[i]!;
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = '';
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (depth === 0 && c === '?' && expr[i + 1] !== '.' && expr[i + 1] !== '?' && q === -1) q = i;
    else if (depth === 0 && c === ':' && q !== -1 && colon === -1) colon = i;
  }
  if (q === -1 || colon === -1) return null;
  return [expr.slice(q + 1, colon), expr.slice(colon + 1)];
}

/**
 * Is the URL handed to `fetch` built on an origin that is fixed by the code?
 *
 * The scheme and host are what SSRF turns on: a path or query appended to a
 * constant base cannot send the request to 169.254.169.254 or to localhost, no
 * matter who supplies the path. So the identifier is followed back through its
 * assignment — at most `depth` hops, which covers the two shapes that actually
 * occur (`const url = `${base}/v3/…`` over `const base = useSandbox ? A : B`) —
 * and the first segment of whatever it was assigned has to be a literal
 * `https://…`, an environment read, or another identifier that resolves to one.
 * A ternary has to resolve on both branches. Anything else is unknown, and
 * unknown stays reported.
 */
function hasKnownOrigin(name: string, source: string, index: number, depth: number): boolean {
  if (depth <= 0) return false;
  // `name` came out of the scanned repository and is about to be interpolated
  // into a pattern. Every caller already constrains it to an identifier, which
  // is why nothing can reach here with a metacharacter in it — checked anyway,
  // because a guard that depends on its callers staying careful is one edit
  // away from not holding.
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return false;
  // The nearest assignment at or above the use, so a later rebinding of the
  // same name in another function is not what gets credited.
  const assign = new RegExp(`\\b(?:const|let|var)\\s+${name}\\s*(?::[^=\\n]{0,60})?=\\s*([^;\\n]{0,400})`, 'g');
  let value: string | null = null;
  for (const m of source.slice(0, index).matchAll(assign)) value = m[1]!;
  if (value === null) {
    // A parameter or an import: unknown here. A *module-level* const declared
    // below the use is still in scope, so look forward — but only at column 0.
    // Without that anchor a `const url = new URL(request.url)` in some later
    // function credited an earlier function's `fetch(url)` on a bare
    // parameter, which is the opposite of what this guard is for.
    const later = new RegExp(
      `^(?:const|let|var)\\s+${name}\\s*(?::[^=\\n]{0,60})?=\\s*([^;\\n]{0,400})`,
      'm',
    ).exec(source.slice(index));
    if (!later) return false;
    value = later[1]!;
  }
  return resolvesToOrigin(value, source, index, depth - 1);
}

/**
 * Does this expression carry an origin the caller cannot move?
 *
 * The hop budget is spent only on following a name to its assignment; reading a
 * ternary or a template literal is free, because `const base = sandbox ? A : B`
 * and `const url = `${base}/v3/…`` are one idiom written across three lines,
 * and charging each line would run out before reaching the literal.
 */
function resolvesToOrigin(expr: string, source: string, index: number, depth: number): boolean {
  const e = expr.trim();
  if (ENV_ORIGIN.test(e)) return true;
  if (LITERAL_ORIGIN.test(e)) return true;
  const tpl = /^`([^`]*?)(?:\$\{([^{}]{0,160})\}|`)/.exec(e);
  if (tpl) {
    const prefix = tpl[1] ?? '';
    // `https://${host}/path` is NOT a fixed origin: the host is the hole, and
    // the host is the whole of SSRF. The prefix has to reach past the `//` into
    // a hostname before the first interpolation, or the hole itself has to
    // resolve to an origin.
    if (/^https?:\/\/[^\s/$]+/.test(prefix)) return true;
    const hole = tpl[2]?.trim();
    if (hole && /^https?:\/\/$|^$/.test(prefix)) {
      // With the scheme already written, the hole only has to carry the host.
      if (prefix !== '' && isFixedHost(hole, source, index, depth)) return true;
      return resolvesToOrigin(hole, source, index, depth);
    }
    return false;
  }
  const ternary = splitTernary(e);
  if (ternary) {
    return (
      resolvesToOrigin(ternary[0], source, index, depth) &&
      resolvesToOrigin(ternary[1], source, index, depth)
    );
  }
  // A concatenation is its first operand's origin.
  const concat = /^([^+]{1,200}?)\s*\+/.exec(e);
  if (concat) return resolvesToOrigin(concat[1]!, source, index, depth);
  if (/^[A-Za-z_$]\w*$/.test(e)) return hasKnownOrigin(e, source, index, depth);
  return false;
}

/**
 * How many arguments the call at `index` is passed, counting only top-level
 * commas so an object literal, an array or a nested call counts as one. Returns
 * 0 when no argument list is found within a bounded window.
 */
function argumentList(source: string, index: number): { arity: number; after: string } | null {
  const open = source.indexOf('(', index);
  if (open === -1 || open > index + 40) return null;
  let depth = 0;
  let quote = '';
  let args = 1;
  const end = Math.min(source.length, open + 4000);
  for (let i = open; i < end; i++) {
    const c = source[i]!;
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = '';
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) return { arity: args, after: source.slice(i + 1, i + 80) };
    } else if (depth === 1 && c === ',') args++;
  }
  return null;
}

/** The host half of a `https://${…}/…` template: a literal hostname, an env read, or a name for one. */
function isFixedHost(expr: string, source: string, index: number, depth: number): boolean {
  const e = expr.trim();
  if (isLiteralHost(e) || ENV_ORIGIN.test(e)) return true;
  const ternary = splitTernary(e);
  if (ternary) {
    return (
      isFixedHost(ternary[0], source, index, depth) && isFixedHost(ternary[1], source, index, depth)
    );
  }
  if (!/^[A-Za-z_$][\w$]*$/.test(e) || depth <= 0) return false;
  // Before the use, else a module-level declaration at column 0 — the same rule
  // as `hasKnownOrigin`, so a later local of the same name cannot be credited.
  const assign = new RegExp(`\\b(?:const|let|var)\\s+${e}\\s*(?::[^=\\n]{0,60})?=\\s*([^;\\n]{0,400})`, 'g');
  let value: string | null = null;
  for (const m of source.slice(0, index).matchAll(assign)) value = m[1]!;
  if (value === null) {
    const later = new RegExp(`^(?:const|let|var)\\s+${e}\\s*(?::[^=\\n]{0,60})?=\\s*([^;\\n]{0,400})`, 'm').exec(
      source.slice(index),
    );
    value = later ? later[1]! : null;
  }
  return value === null ? false : isFixedHost(value, source, index, depth - 1);
}

/**
 * A `<style>` element's own text. `<style dangerouslySetInnerHTML={{ __html:
 * css }} />` is how React injects a stylesheet, and it was 7 of the 14 real
 * VG012 findings across the dogfooding repos — reported `high` as cross-site
 * scripting, on the idiom this project's own README calls "a regex, not a
 * finding" when CTS084 was written. CSS text in a style tag is not an HTML sink.
 */
function inStyleElement(source: string, index: number): boolean {
  const before = source.slice(Math.max(0, index - 200), index);
  const open = before.lastIndexOf('<');
  return open !== -1 && /^<style\b[^<>]*$/i.test(before.slice(open));
}

/**
 * An authorization decision — not merely an authentication one. A named guard,
 * the caller's own role / admin flag / permission being tested, or the refusal
 * that only an authorization check returns.
 *
 * Deliberately excludes a bare `auth()` / `getUser()` / 401: "any authenticated
 * user can promote themselves" is the bug VG1008 is about, so a signed-in check
 * alone must not clear it.
 */
const AUTHORIZATION_CHECK = new RegExp(
  [
    String.raw`\b(?:require|assert|ensure|check|verify)(?:Admin|Role|Owner|Permission|Permissions|Authori[sz]ation|Authori[sz]ed|Access)\w*\s*\(`,
    String.raw`\b(?:hasRole|hasPermission|hasAnyRole|canAccess|isAuthorized|isAuthorised|authorize|authorise|requirePermission|checkAdmin)\s*\(`,
    String.raw`[!(&|,]\s*[\w$.?[\]'"]*\b(?:is_?admin|isSuperAdmin|is_?owner|role|roles|permission|permissions)\b`,
    String.raw`\b(?:is_?admin|isSuperAdmin|role|roles|permission|permissions)\b[^\n]{0,60}(?:===|!==|==|!=|\bin\b|\.includes\s*\()`,
    String.raw`\b403\b|\bForbidden\b|\bFORBIDDEN\b|\bPERMISSION_DENIED\b`,
  ].join('|'),
);

const MATCH_GUARDS: Record<
  string,
  (
    match: string,
    source: string,
    index: number,
    spans: readonly Span[],
    /** Path relative to the scan root, for the guards that are about where a file sits. */
    relPath?: string,
  ) => boolean
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
  // The string check: a `db.query(\`SELECT …${v}\`)` that sits inside a string
  // literal is example code being *described* — a rule-definition file's own
  // `description:` field carried two criticals. Code in a string is data.
  VG010: (match, source, index, spans) =>
    !isInside(spans, index, 'string') && sqlGuard(match, source, index),

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
  //
  // Three more things the pattern cannot tell apart, all of them on the corpus.
  // The rule's own name is "SSRF via User-Controlled URL" and its description
  // says "user-controlled input is passed directly to fetch()", but what it
  // matches is `fetch(` followed by any bare identifier — the same gap between
  // a rule's name and its pattern that VG1008 had.
  //
  // 1. A *definition* is not a call. `export default { fetch(request, env, ctx)
  //    { … } }` is the Cloudflare Workers entry point — the most common shape
  //    there is — and `fetch(request, env, ctx)` one line below it delegates
  //    the same Request object to the next handler. Neither takes a URL at all;
  //    WHATWG `fetch` has two parameters, so a three-argument one is never it.
  //    VG105 was fixed for reading a declaration as a call in 0.13.10; this is
  //    the same mistake in another rule.
  // 2. SSRF is about controlling the *host*. The pattern already refuses
  //    `fetch("https://…")` and `fetch(`${process.env.X}/…`)` written inline;
  //    one `const` in between defeats it, which is how it is normally written.
  //    `const endpoint = "https://biz.dataly.us/api/cron/run-schedules"` and
  //    `const url = `${baseUrl}/v3/company/${realmId}/query?…`` over a
  //    literal or env-derived base are not URLs an attacker can point
  //    anywhere, whatever the path says. So the origin is resolved up to two
  //    assignments back; a bare identifier whose origin cannot be established
  //    stays reported, the line VG012 draws.
  // 3. A URL that went through an SSRF validator is the fix, not the bug.
  //    app E's `fetchNoOpenRedirect` calls `assertFetchableImageUrl(startUrl)`,
  //    sets `redirect: 'manual'`, bounds the chain at three hops and
  //    re-validates every `Location` — it implements what this rule's own
  //    `fix` text asks for, and was reported `high` for it.
  VG120: (match, source, index) => {
    if (/^\s*(['"])use client\1/m.test(source.slice(0, 400))) return false;
    const arg = /([A-Za-z_$]\w*)\s*[,)]\s*$/.exec(match)?.[1];
    const args = argumentList(source, index);
    // A method shorthand or function declaration: `fetch(request, env, ctx) {`
    // — its *own* argument list is followed by the body's brace. Read off the
    // matching close paren, not a regex: `[^)]{0,120}\)\s*\{` found the next
    // `if (…) {` after an ordinary call and cleared it, which is how an
    // app B edge function's `fetch(imageUrl)` went quiet.
    if (
      args &&
      /^\s*(?::\s*[\w<>[\].|,? ]+\s*)?\{/.test(args.after) &&
      /^\s*(?:async\s+)?(?:function\s*\*?\s*)?fetch\s*\(/.test(match)
    ) {
      return false;
    }
    // `fetch(request, env, ctx)` — three arguments is never WHATWG fetch, which
    // takes two. This is a Workers handler, or a delegation to one.
    //
    // Counted by walking the argument list, not by regex: the first version of
    // this used `[^(),]{1,40},\s*[^(),]{1,40},` and a character class does not
    // stop at an object literal, so `fetch(url, { method, headers })` — the
    // commonest shape there is — read as three arguments and was cleared.
    // app G's `fetch(url, { ...opts, signal: controller.signal })` is how
    // that turned up, on a `url` that is a bare parameter.
    if (args && args.arity >= 3) return false;
    if (!arg) return true;
    const scope = enclosingBody(source, index);
    // A function that returns before the fetch when there is no `window` runs
    // only in a browser, where the request crosses no trust boundary of yours —
    // the same judgement as the `'use client'` check above, for an isomorphic
    // module that states it at the top of the function instead of the file.
    // Read from a bounded window rather than `scope`, because the fetch is
    // normally a few frames in (`srcs.map(async (url) => { … fetch(url) })`)
    // and the guard sits at the top of the function that owns the map.
    if (
      /typeof\s+window\s*===?\s*(['"])undefined\1[^;\n]{0,80}\breturn\b/.test(
        source.slice(Math.max(0, index - 1500), index),
      )
    ) {
      return false;
    }
    if (
      /^[A-Za-z_$][\w$]*$/.test(arg) &&
      (SSRF_VALIDATED.test(scope) || SSRF_VALIDATED.test(source.slice(0, index)))
    ) {
      // Credited only when the validated value is the one being fetched, or is
      // what it was assigned from.
      if (new RegExp(`\\b${arg}\\b\\s*=[^;\\n]{0,200}?${SSRF_VALIDATED.source}`).test(source)) {
        return false;
      }
    }
    return !hasKnownOrigin(arg, source, index, 4);
  },

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

  // The rule is named "Weak *password* hashing" and its pattern is any md5 or
  // sha1 use at all, so `hashlib.md5(hostname + mac)` — deriving a stable
  // device id, with nothing secret in sight — was two criticals on one app.
  // MD5 is only this finding when a password is what goes in, so a password
  // has to be somewhere near the call. An etag, cache key or machine id is not
  // weakly hashed; it is not a secret at all.
  VG060: (_match, source, index) =>
    /\b(?:password|passwd|pwd|passphrase)\b/i.test(
      source.slice(Math.max(0, index - 400), index + 400),
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

  // The rule's own name is "…Without Authorization Check", and its pattern
  // contains no notion of one: it matches `.update({ is_admin: true })` and
  // reports critical whatever sits above it. So a route that reads the caller's
  // own admin flag, returns 403 when it is not set, and only then promotes
  // somebody — the shape the rule's `fixCode` asks for — was reported as the
  // bug, while CTS001 read the same function and (correctly) said nothing. Two
  // criticals on correct code is the worst failure this project has, and the
  // same contradiction CTS001 already settles for VG1025 above.
  VG1008: (_match, source, index) => !AUTHORIZATION_CHECK.test(enclosingBody(source, index)),

  // The rule is about a *tool schema's* enum list being computed at runtime, so
  // its JSON-Schema branch looks for `"enum":` followed by a lowercase name.
  // `case "enum": return "≡";` is that, character for character — a switch over
  // a JSON-Schema type name, mapping it to an icon or a badge colour. Seven
  // findings across app C's query builder and type-colour table, every one
  // a switch label; the `case` keyword in front and the `return` behind it are
  // both visible from the match. A statement keyword can never be a schema's
  // enum values, and a `case` label is not an object property.
  VG1021: (match, source, index) => {
    if (/^["']enum["']/.test(match)) {
      if (/\bcase\s*$/.test(source.slice(Math.max(0, index - 12), index))) return false;
      if (/^["']enum["']\s*:\s*(?:return|break|continue|throw|yield|await|new|typeof|delete|void|in|instanceof)\b/.test(match)) {
        return false;
      }
    }
    return true;
  },

  // "Server-Only Module Missing in Sensitive File": a module that reads a
  // secret and imports from `next` but never marks itself `server-only` could
  // be pulled into a client component, taking the secret into the bundle. A
  // route handler cannot be. `app/**/route.ts` is a route entry point that Next
  // invokes on the server — it is not importable from a client component, which
  // is the whole hazard the rule exists for, and `server-only` in one would
  // guard nothing. Six of the seven findings on the corpus were route handlers
  // (`api/cron/run-schedules`, `api/shopify/callback`, `auth/quickbooks/callback`
  // …), reported `high` on line 1, at the import. The seventh is a shared
  // `src/lib/session.js` that really is importable from both sides, and stays.
  // Pages and layouts are server components by default in the App Router and
  // are equally not importable, so they are credited the same way.
  VG964: (_match, _source, _index, _spans, relPath) =>
    !/(?:^|\/)app\/.*\/(?:route|page|layout|template|default|error|loading|not-found)\.[cm]?[jt]sx?$/.test(
      relPath ?? '',
    ) && !/(?:^|\/)pages\/api\/.*\.[cm]?[jt]sx?$/.test(relPath ?? ''),

  // `select('*', { count: 'exact', head: true })` is Supabase's own documented
  // way to count rows: `head: true` sends the request with `Prefer: head=true`
  // and returns **no rows at all**, only the count header. The rule's pattern
  // stops at the `'*'` and never reads the second argument, so a query that
  // returns zero columns was reported as "Exposes All Columns" — three of
  // app F's eleven, all of them rate-limit counters in edge functions.
  // Without `head: true` the rows do come back alongside the count, so that
  // stays reported; the other eight are real `select('*')` fetches and are
  // untouched.
  VG1006: (_match, source, index) => {
    const call = source.slice(index, index + 220);
    return !/\.select\s*\(\s*(?:["']\*["']|)\s*,[^)]*\bhead\s*:\s*true\b/.test(call);
  },

  // "XSS via innerHTML" is about untrusted data reaching the sink, and the
  // pattern is `innerHTML\s*=\s*` with a lookahead for a quoted `<` — so
  // anything that is not a literal starting with a tag is a high finding. This
  // project's own landing page was the proof, the moment HTML files started
  // being read at all: `out.innerHTML = LINES.map(l => '<span>' + esc(l[1]) +
  // '</span>').join('\n')` — a hardcoded constant, escaped on the way in,
  // reported as cross-site scripting. An expression with no dynamic part, or
  // whose dynamic parts go through an escaper, is not this; `el.innerHTML = '<b>'
  // + data.name` still is.
  VG012: (_match, source, index) => {
    if (inStyleElement(source, index)) return false;
    const expr = assignedExpression(source, index);
    if (ESCAPES_HTML.test(expr)) return false;
    return hasDynamicPart(expr);
  },

  // Check-then-act is a race when the value checked is the value written — the
  // credits balance of the rule's own example. An access-control gate has the
  // same shape and is not: `select('is_admin').single()` → `if (!admin) return
  // 403` → `update(...)` is how an admin endpoint is supposed to be written,
  // and no amount of concurrency makes the caller an admin. Reported critical
  // on exactly that, beside VG1008, on the same correct route.
  //
  // Two more shapes with the same select-if-write outline and no race worth the
  // word, all four of this rule's hits in the sweep:
  // — the select and the write touch *different tables*: a profile page that
  //   counts the user's posts and later saves their notification prefs is
  //   load-then-save, not check-then-act — nothing read is what gets written.
  // — a count-based guard clause that *rejects* and otherwise appends the very
  //   row being counted (`if (count >= 5) return 429` → `.insert(…)`) is how
  //   every soft rate limiter is written; concurrency can overshoot the limit
  //   by the number of in-flight requests, which is the accepted property of
  //   the pattern, not a critical.
  // The credits race keeps both its tables the same and its write an update,
  // and stays reported — pinned by its regression test.
  VG154: (match) => {
    if (AUTHORIZATION_CHECK.test(match)) return false;
    const act = /\.(update|insert|delete|upsert)\s*\(/.exec(
      match.slice(match.search(/\bif\s*\(/) + 1),
    );
    const actIndex = act ? match.search(/\bif\s*\(/) + 1 + act.index : -1;
    if (act && actIndex !== -1) {
      const tables = [...match.matchAll(/\.from\s*\(\s*["']([^"']+)["']\s*\)/g)];
      const checked = tables[0]?.[1];
      const actedOn = tables.filter((t) => t.index! < actIndex).at(-1)?.[1];
      if (checked && actedOn && checked !== actedOn) return false;
      if (act[1] === 'insert') {
        // The first `if` body: reject-and-return, then an append, is a rate
        // limiter or dedupe, not a lost update. `[^{;]` lets the condition
        // carry its own nested parens (`if ((count ?? 0) >= 5)`).
        const cond = /\bif\s*\([^{;]{0,300}?\)\s*\{?\s*(return|throw)\b/.exec(match);
        if (cond) return false;
      }
    }
    return true;
  },

};

/**
 * Bounded replacements for vendored patterns whose backtracking is super-linear
 * in the size of the file. The vendored files stay a faithful copy of upstream;
 * the replacement is used in its place at runtime. Each one matches at exactly
 * the positions upstream's does for any input with the features the rule is
 * about within a few kilobytes of each other — the only difference is that the
 * search from any one position is bounded, so a file of the rule's own trigger
 * word repeated cannot stall the scan. `test/rules-audit.test.js` checks each
 * against its original, position by position, on generated inputs. These four
 * predate the linear-time matcher below, which now runs them as well.
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

// ---------------------------------------------------------------------------
// Linear-time matching
// ---------------------------------------------------------------------------
//
// The overrides above fix four patterns by hand. Fuzzing the whole ruleset
// the same way — each rule's own trigger words, prefixes of its matches and
// its quantifiers pumped, at 16 KB to 400 KB — found 209 of the 435 active
// patterns over 50 ms at 400 KB, 151 over the 250 ms time budget, and 125
// past eight seconds. The shape is almost always the same: a trigger, then a
// gap (`[\s\S]{0,500}?`, `[^)]*`, `.*`, `\s*`) the engine tries every end of,
// from every trigger. `eval.*\(` alone spends 50 s on a 400 KB line of `eval`,
// inside one uninterruptible `exec`. Rewriting 200 patterns by hand, and
// proving each rewrite, is not a job that ends; so they are not rewritten.
//
// Instead each one is run, unchanged, by a small backtracking matcher that
// explores exactly the paths V8's own would, in the same order — so it finds
// exactly the same match — but remembers every (state, position) it has
// already seen fail, and never explores one twice. A failed path depends only
// on where it is in the pattern and in the text (these patterns have no
// backreferences), so skipping a repeat can change nothing but the time. What
// is left is linear in the text, times the size of the pattern.
//
// Speed comes from letting V8's engine do everything it does in linear time:
// finding where a match could start, testing single characters and short
// lookaheads, listing where a character class breaks. A pattern V8 already
// searches in linear time (`linearInIrregexp`) is not routed here at all.
// `test/redos-overrides.test.js` compares the two engines on every rule.

class UnsupportedPattern extends Error {}

type ReNode =
  | { t: 'alt'; alts: ReNode[]; raw: string }
  | { t: 'seq'; items: ReNode[]; raw: string }
  | { t: 'char'; raw: string }
  | { t: 'assert'; kind: string; raw: string }
  | { t: 'group'; body: ReNode; raw: string }
  | { t: 'look'; behind: boolean; neg: boolean; body: ReNode; raw: string }
  | { t: 'quant'; min: number; max: number; lazy: boolean; body: ReNode; raw: string };

type AltNode = Extract<ReNode, { t: 'alt' }>;

/**
 * A parse of the regex syntax the vendored patterns use (no `u` or `v` flag).
 * Anything else — a backreference, a quantified assertion — throws
 * UnsupportedPattern, and that pattern is left to V8.
 */
function parsePattern(src: string): ReNode {
  let i = 0;
  const at = (s: string) => src.startsWith(s, i);
  function alt(): AltNode {
    const start = i;
    const alts = [seq()];
    while (src[i] === '|') {
      i++;
      alts.push(seq());
    }
    return { t: 'alt', alts, raw: src.slice(start, i) };
  }
  function seq(): ReNode {
    const start = i;
    const items: ReNode[] = [];
    while (i < src.length && src[i] !== '|' && src[i] !== ')') items.push(term());
    return { t: 'seq', items, raw: src.slice(start, i) };
  }
  function quantifier(): [number, number, number] | null {
    const c = src[i];
    if (c === '*') return [0, Infinity, 1];
    if (c === '+') return [1, Infinity, 1];
    if (c === '?') return [0, 1, 1];
    if (c !== '{') return null;
    const m = /^\{(\d+)(,(\d*))?\}/.exec(src.slice(i, i + 24));
    if (!m) return null; // Annex B: a `{` that is not a quantifier is a literal.
    const min = Number(m[1]);
    const max = m[2] === undefined ? min : m[3] === '' ? Infinity : Number(m[3]);
    return [min, max, m[0].length];
  }
  function term(): ReNode {
    const start = i;
    const c = src[i]!;
    let atom: ReNode;
    if (c === '^' || c === '$') {
      i++;
      atom = { t: 'assert', kind: c, raw: c };
    } else if (c === '(') {
      let kind = 'group';
      if (at('(?:')) i += 3;
      else if (at('(?=')) (kind = 'ahead'), (i += 3);
      else if (at('(?!')) (kind = 'nahead'), (i += 3);
      else if (at('(?<=')) (kind = 'behind'), (i += 4);
      else if (at('(?<!')) (kind = 'nbehind'), (i += 4);
      else if (at('(?<')) i = src.indexOf('>', i) + 1;
      else i += 1;
      const body = alt();
      if (src[i] !== ')') throw new UnsupportedPattern('unbalanced group');
      i++;
      const raw = src.slice(start, i);
      atom =
        kind === 'group'
          ? { t: 'group', body, raw }
          : { t: 'look', behind: kind.endsWith('behind'), neg: kind.startsWith('n'), body, raw };
    } else if (c === '[') {
      let j = i + 1;
      if (src[j] === '^') j++;
      while (j < src.length && src[j] !== ']') j += src[j] === '\\' ? 2 : 1;
      if (j >= src.length) throw new UnsupportedPattern('unterminated class');
      i = j + 1;
      atom = { t: 'char', raw: src.slice(start, i) };
    } else if (c === '\\') {
      const d = src[i + 1] ?? '';
      if (d === 'b' || d === 'B') {
        i += 2;
        atom = { t: 'assert', kind: d, raw: src.slice(start, i) };
      } else if (/[1-9kpP]/.test(d)) {
        throw new UnsupportedPattern(`\\${d}`);
      } else {
        if (d === 'x' && /^[0-9a-fA-F]{2}$/.test(src.slice(i + 2, i + 4))) i += 4;
        else if (d === 'u' && /^[0-9a-fA-F]{4}$/.test(src.slice(i + 2, i + 6))) i += 6;
        else if (d === 'c' && /^[A-Za-z]$/.test(src[i + 2] ?? '')) i += 3;
        else i += 2;
        atom = { t: 'char', raw: src.slice(start, i) };
      }
    } else {
      i++;
      atom = { t: 'char', raw: c };
    }
    const q = quantifier();
    if (!q) return atom;
    if (atom.t === 'assert' || atom.t === 'look') throw new UnsupportedPattern('quantified assertion');
    i += q[2];
    const lazy = src[i] === '?';
    if (lazy) i++;
    return { t: 'quant', min: q[0], max: q[1], lazy, body: atom, raw: src.slice(start, i) };
  }
  const ast = alt();
  if (i !== src.length) throw new UnsupportedPattern('unbalanced group');
  return ast;
}

/** A code-unit table for one single-character atom, filled on demand by V8's own verdict. */
interface CharMap {
  key: string;
  map: Uint8Array; // 0 unknown, 1 in, 2 out
  re: RegExp;
}

const CHAR_MAPS = new Map<string, CharMap>();

function charMap(raw: string, flags: string): CharMap {
  const key = flags + '\u0000' + raw;
  let cm = CHAR_MAPS.get(key);
  if (!cm) {
    cm = { key, map: new Uint8Array(65536), re: new RegExp('^(?:' + raw + ')$', flags) };
    CHAR_MAPS.set(key, cm);
  }
  return cm;
}

function inMap(cm: CharMap, c: number): boolean {
  let v = cm.map[c]!;
  if (v === 0) cm.map[c] = v = cm.re.test(String.fromCharCode(c)) ? 1 : 2;
  return v === 1;
}

let ALL_CODE_UNITS: string | null = null;
const DISJOINT = new Map<string, boolean>();

/**
 * The code units a single literal character atom (`a`, `\(`) matches: itself,
 * and its other case under `i` — which, without the `u` flag, only ever folds
 * ASCII to ASCII. Null for anything else.
 */
function literalUnits(raw: string, flags: string): string[] | null {
  let ch: string;
  if (raw.length === 1 && !'.^$|?*+()[]{}\\'.includes(raw)) ch = raw;
  else if (raw.length === 2 && raw[0] === '\\' && /[^A-Za-z0-9]/.test(raw[1]!)) ch = raw[1]!;
  else return null;
  const re = new RegExp('^(?:' + raw + ')$', flags);
  return [...new Set([ch, ch.toLowerCase(), ch.toUpperCase()])].filter((c) => c.length === 1 && re.test(c));
}

/** Whether no code unit matches both `raw` and one of `others` — asked of V8. */
function disjoint(raw: string, others: readonly string[], flags: string): boolean {
  const key = flags + '\u0000' + raw + '\u0000' + others.join('\u0001');
  let v = DISJOINT.get(key);
  if (v !== undefined) return v;
  // Mostly one side is a literal character: then only its few code units need asking about.
  const mine = literalUnits(raw, flags);
  const theirs = others.map((o) => literalUnits(o, flags));
  if (mine !== null) {
    const re = new RegExp('^(?:' + others.join('|') + ')$', flags);
    v = !mine.some((c) => re.test(c));
  } else if (theirs.every((t) => t !== null)) {
    const re = new RegExp('^(?:' + raw + ')$', flags);
    v = !theirs.some((t) => t!.some((c) => re.test(c)));
  }
  if (v === undefined) {
    if (ALL_CODE_UNITS === null) {
      const units: string[] = [];
      for (let c = 0; c < 65536; c++) units.push(String.fromCharCode(c));
      ALL_CODE_UNITS = units.join('');
    }
    v = !new RegExp('(?=' + raw + ')(?:' + others.join('|') + ')', flags).test(ALL_CODE_UNITS);
  }
  DISJOINT.set(key, v);
  return v;
}

function nullable(n: ReNode): boolean {
  switch (n.t) {
    case 'alt':
      return n.alts.some(nullable);
    case 'seq':
      return n.items.every(nullable);
    case 'char':
      return false;
    case 'group':
      return nullable(n.body);
    case 'look':
    case 'assert':
      return true;
    case 'quant':
      return n.min === 0 || nullable(n.body);
  }
}

/**
 * Whether V8 can evaluate `n` at every position of a text in linear total
 * time. Every quantifier has to be small, except a run of one class C fenced
 * on both sides by characters outside C: the character before it anchors each
 * attempt that reads the run (and cannot occur inside it, so no attempt starts
 * part-way along), and the one after gives the run exactly one place to end.
 * A run like that is read by a bounded number of attempts however long it is.
 * `readFile\s*\(` passes; `readFile\s*\([^)]*req\.` does not — every `(` in
 * a run of them starts its own read of the rest.
 */
function evaluatesLinearly(n: ReNode, flags: string): boolean {
  const outside = (x: ReNode, raw: string) => x.t === 'char' && disjoint(x.raw, [raw], flags);
  const endsOutside = (x: ReNode, raw: string): boolean => {
    switch (x.t) {
      case 'alt':
        return x.alts.every((a) => endsOutside(a, raw));
      case 'seq':
        return x.items.length > 0 && endsOutside(x.items[x.items.length - 1]!, raw);
      case 'group':
        return endsOutside(x.body, raw);
      default:
        return outside(x, raw);
    }
  };
  const startsOutside = (x: ReNode, raw: string): boolean => {
    switch (x.t) {
      case 'alt':
        return x.alts.every((a) => startsOutside(a, raw));
      case 'seq':
        return x.items.length > 0 && startsOutside(x.items[0]!, raw);
      case 'group':
        return startsOutside(x.body, raw);
      case 'quant':
        return x.min >= 1 && startsOutside(x.body, raw);
      default:
        return outside(x, raw);
    }
  };
  const ok = (x: ReNode, atEnd: boolean): boolean => {
    switch (x.t) {
      case 'alt':
        return x.alts.every((a) => ok(a, atEnd));
      case 'seq':
        return x.items.every((it, i) => {
          if (it.t === 'quant' && it.max > 16) {
            if (it.body.t !== 'char') return false;
            const prev = x.items[i - 1];
            const next = x.items[i + 1];
            if (prev === undefined || !endsOutside(prev, it.body.raw)) return false;
            return next === undefined ? atEnd : startsOutside(next, it.body.raw);
          }
          return ok(it, atEnd && i === x.items.length - 1);
        });
      case 'group':
        return ok(x.body, atEnd);
      case 'char':
      case 'assert':
        return true;
      case 'look':
        return ok(x.body, true);
      case 'quant':
        return x.max <= 16 && ok(x.body, false);
    }
  };
  return ok(n, true);
}

// --- Filters -----------------------------------------------------------------
//
// Cheap, necessary conditions, run by V8: a match can only start where
// `prefixOf` matches, and a gap can only end where what follows it can start.

const SMALL = 16;

function cheap(n: ReNode): boolean {
  switch (n.t) {
    case 'alt':
      return n.alts.every(cheap);
    case 'seq':
      return n.items.every(cheap);
    case 'group':
      return cheap(n.body);
    case 'char':
    case 'assert':
      return true;
    case 'look':
      return false;
    case 'quant':
      return n.max <= SMALL && cheap(n.body);
  }
}

/** [source, complete]: a cheap regex that matches wherever `n` can start a match. */
function prefixOf(n: ReNode): [string, boolean] {
  switch (n.t) {
    case 'alt': {
      const parts = n.alts.map(prefixOf);
      if (parts.some((p) => p[0] === '')) return ['', false];
      return ['(?:' + parts.map((p) => p[0]).join('|') + ')', parts.every((p) => p[1])];
    }
    case 'seq': {
      let s = '';
      for (let i = 0; i < n.items.length; i++) {
        const it = n.items[i]!;
        const [p, complete] = prefixOf(it);
        if (complete) {
          s += p;
          continue;
        }
        // An optional item that is not cheap: either it starts here or what
        // follows it does.
        if (it.t === 'quant' && it.min === 0 && p === '') {
          const [a] = prefixOf(it.body);
          const [b] = prefixOf({ t: 'seq', items: n.items.slice(i + 1), raw: '' });
          if (a !== '' && b !== '' && a.length + b.length < 600) return [s + '(?:' + a + '|' + b + ')', false];
        }
        return [s + p, false];
      }
      return [s, true];
    }
    case 'group': {
      const [p, complete] = prefixOf(n.body);
      return [p === '' ? '' : '(?:' + p + ')', complete];
    }
    case 'char':
    case 'assert':
      return [n.raw, true];
    case 'look':
      return ['', true]; // dropped: a weaker condition, still a necessary one
    case 'quant':
      return n.max <= SMALL && cheap(n.body) ? [n.raw, true] : ['', false];
  }
}

/** [source, score]: a regex matching somewhere inside every match, scored by its literal characters. */
function requiredText(n: ReNode): [string, number] | null {
  const literal = (x: ReNode) => x.t === 'char' && !/^(?:\[|\.$|\\[dDsSwWbBtnrvf0-9xuc])/.test(x.raw);
  switch (n.t) {
    case 'char':
      return [n.raw, literal(n) ? 1 : 0];
    case 'group':
      return requiredText(n.body);
    case 'quant':
      return n.min >= 1 ? requiredText(n.body) : null;
    case 'alt': {
      const parts = n.alts.map(requiredText);
      if (parts.some((p) => p === null)) return null;
      const all = parts as [string, number][];
      if (all.length === 1) return all[0]!;
      return ['(?:' + all.map((p) => p[0]).join('|') + ')', Math.min(...all.map((p) => p[1]))];
    }
    case 'seq': {
      let best: [string, number] | null = null;
      let run = '';
      let score = 0;
      const close = () => {
        if (run !== '' && (best === null || score > best[1])) best = [run, score];
        run = '';
        score = 0;
      };
      for (const it of n.items) {
        if (it.t === 'char') {
          run += it.raw;
          score += literal(it) ? 1 : 0;
          continue;
        }
        close();
        const r = requiredText(it);
        if (r !== null && (best === null || r[1] > best[1])) best = r;
      }
      close();
      return best;
    }
    default:
      return null;
  }
}

/** The single-character atoms `n` can begin with (null: unknown), and whether it can match empty. */
function firstAtoms(n: ReNode): { atoms: string[] | null; empty: boolean } {
  switch (n.t) {
    case 'char':
      return { atoms: [n.raw], empty: false };
    case 'assert':
    case 'look':
      return { atoms: [], empty: true };
    case 'group':
      return firstAtoms(n.body);
    case 'quant': {
      const f = firstAtoms(n.body);
      return { atoms: f.atoms, empty: f.empty || n.min === 0 };
    }
    case 'alt': {
      const fs = n.alts.map(firstAtoms);
      const empty = fs.some((f) => f.empty);
      if (fs.some((f) => f.atoms === null)) return { atoms: null, empty };
      return { atoms: [...new Set(fs.flatMap((f) => f.atoms!))], empty };
    }
    case 'seq': {
      const atoms = new Set<string>();
      for (const it of n.items) {
        const f = firstAtoms(it);
        if (f.atoms === null) return { atoms: null, empty: false };
        for (const a of f.atoms) atoms.add(a);
        if (!f.empty) return { atoms: [...atoms], empty: false };
      }
      return { atoms: [...atoms], empty: true };
    }
  }
}

/** What must follow a point in the pattern: its prefix, and the atoms it can start with (null: anything, or nothing). */
interface Continuation {
  src: string;
  complete: boolean;
  first: string[] | null;
}

const PATTERN_END: Continuation = { src: '', complete: true, first: null };

function precede(item: ReNode, cont: Continuation): Continuation {
  const f = firstAtoms(item);
  let first: string[] | null;
  if (!f.empty) first = f.atoms;
  else if (cont.first === null || f.atoms === null) first = null;
  else first = [...new Set([...f.atoms, ...cont.first])];
  if (first !== null && first.length > 64) first = null;
  const [s, complete] = prefixOf(item);
  if (!complete || s.length + cont.src.length > 400) return { src: s, complete: false, first };
  return { src: s + cont.src, complete: cont.complete, first };
}

/** A leading atom that matches most characters filters nothing. */
const BROAD = /^(?:\[\^|\.|\\[SWD]|\[\\[sSwWdD]\\[sSwWdD]\])/;

/** Classes that match every code unit. */
const UNIVERSAL = new Set(['[\\s\\S]', '[\\S\\s]', '[^]', '[\\w\\W]', '[\\W\\w]', '[\\d\\D]', '[\\D\\d]']);

interface FirstMap {
  cms: CharMap[];
  map: Uint8Array;
}

const FIRST_MAPS = new Map<string, FirstMap>();

function firstMap(atoms: string[] | null, flags: string): FirstMap | null {
  if (atoms === null || atoms.length === 0 || atoms.some((a) => BROAD.test(a))) return null;
  const key = flags + '\u0000' + atoms.join('\u0001');
  let f = FIRST_MAPS.get(key);
  if (f === undefined) {
    f = { cms: atoms.map((a) => charMap(a, flags)), map: new Uint8Array(65536) };
    FIRST_MAPS.set(key, f);
  }
  return f;
}

function inFirst(f: FirstMap, c: number): boolean {
  let v = f.map[c]!;
  if (v === 0) f.map[c] = v = f.cms.some((cm) => inMap(cm, c)) ? 1 : 2;
  return v === 1;
}

// --- Program -----------------------------------------------------------------

const CHAR = 0;
const SPLIT = 1;
const ASSERT = 2;
const LOOK = 3;
/** A run of one class (`\s*`, `[^)]{0,200}?`, a tempered `(?:(?!x)[\s\S])*`) with a choice of ends. */
const GAP = 4;
const MATCH = 5;
/** A gap whose only viable end is where its run ends: what follows cannot start inside it. */
const RUN = 6;

/** A zero-width regex for where a continuation can start: its prefix, or else its first atoms. */
function seekFor(cont: Continuation, flags: string): RegExp | null {
  let src: string | null = null;
  if (cont.src !== '' && !BROAD.test(cont.src)) src = cont.src;
  else if (cont.first !== null && cont.first.length > 0 && !cont.first.some((a) => BROAD.test(a))) src = cont.first.join('|');
  return src === null ? null : new RegExp('(?=(?:' + src + '))', flags + 'g');
}

/** Every instruction has one shape, so the matcher's property reads stay monomorphic. */
interface Ins {
  op: number;
  next: number;
  /** SPLIT: preferred and fallback branches; memoized when it heads a loop. */
  x: number;
  y: number;
  memo: boolean;
  /** SPLIT: the atom the preferred branch must open with, to skip it without a frame. */
  xFirst: CharMap | null;
  /** SPLIT: no other branch can start where this one's first atom matches. */
  commit: boolean;
  cm: CharMap | null;
  kind: string;
  /** LOOK: evaluated by V8 (lookbehinds, and lookaheads it evaluates linearly). */
  re: RegExp | null;
  neg: boolean;
  /** LOOK: subprogram, when V8 cannot be trusted with it. */
  sub: number;
  /** GAP/RUN (tempered): the forbidden-word subprogram, or V8's regex for it. */
  forbid: number;
  forbidRe: RegExp | null;
  forbidKey: string;
  min: number;
  max: number;
  lazy: boolean;
  /** GAP: the atoms the continuation can start with. */
  first: FirstMap | null;
  /** GAP: a zero-width regex V8 can use to find the next place the continuation can start. */
  seek: RegExp | null;
  universal: boolean;
  // Per-text caches: the break and forbidden-word lists, the last run end asked for.
  listGen: number;
  forbidList: Positions | null;
  breakList: Positions | null;
  lastGen: number;
  lastQ: number;
  lastEnd: number;
}

function instruction(o: Partial<Ins> & { op: number }): Ins {
  return {
    op: o.op,
    next: o.next ?? -1,
    x: o.x ?? -1,
    y: o.y ?? -1,
    memo: o.memo ?? false,
    xFirst: o.xFirst ?? null,
    commit: o.commit ?? false,
    cm: o.cm ?? null,
    kind: o.kind ?? '',
    re: o.re ?? null,
    neg: o.neg ?? false,
    sub: o.sub ?? -1,
    forbid: o.forbid ?? -1,
    forbidRe: o.forbidRe ?? null,
    forbidKey: o.forbidKey ?? '',
    min: o.min ?? 0,
    max: o.max ?? 0,
    lazy: o.lazy ?? false,
    first: o.first ?? null,
    seek: o.seek ?? null,
    universal: o.universal ?? false,
    listGen: 0,
    forbidList: null,
    breakList: null,
    lastGen: 0,
    lastQ: 0,
    lastEnd: 0,
  };
}

/**
 * `\s*\{?\s*` as `\s*(?:\{\s*)?`. Whenever the optional item is skipped, the
 * second run can only re-read what the first, greedy, already consumed and
 * gave back — and since the optional item cannot start inside the run, it is
 * skipped everywhere but the run's end. Both spellings then try what follows
 * at the run's end first and one position further back each time; the second
 * does it without re-entering a second gap at every position, which halves
 * the work on a long run of whitespace in the patterns that are full of these.
 */
function collapseRuns(n: ReNode, flags: string): ReNode {
  switch (n.t) {
    case 'alt':
      return { ...n, alts: n.alts.map((a) => collapseRuns(a, flags)) };
    case 'group':
    case 'look':
    case 'quant':
      return { ...n, body: collapseRuns(n.body, flags) } as ReNode;
    case 'seq': {
      const items = n.items.map((it) => collapseRuns(it, flags));
      const greedyRun = (x: ReNode | undefined): x is Extract<ReNode, { t: 'quant' }> =>
        x !== undefined && x.t === 'quant' && x.body.t === 'char' && x.max === Infinity && !x.lazy;
      // `\s*[^,]+` as `[^,]+`: two greedy runs side by side, one optional and
      // its class inside the other's. Together they consume exactly what the
      // wider one alone does, and try what follows at the same ends in the
      // same order (furthest first), so the narrower one only costs time.
      const within = (a: string, b: string) => disjoint(a, ['(?!' + b + ')[\\s\\S]'], flags);
      for (let i = 0; i + 1 < items.length; ) {
        const [a, b] = [items[i], items[i + 1]];
        if (greedyRun(a) && greedyRun(b)) {
          if (a.min === 0 && within(a.body.raw, b.body.raw)) {
            items.splice(i, 1);
            continue;
          }
          if (b.min === 0 && within(b.body.raw, a.body.raw)) {
            items.splice(i + 1, 1);
            continue;
          }
        }
        i++;
      }
      for (let i = 0; i + 2 < items.length; i++) {
        const [g1, o, g2] = [items[i], items[i + 1]!, items[i + 2]];
        if (!greedyRun(g1) || !greedyRun(g2) || g2.min !== 0 || g1.body.raw !== g2.body.raw) continue;
        if (o.t !== 'quant' || o.min !== 0 || o.max !== 1 || o.lazy || nullable(o.body)) continue;
        const f = firstAtoms(o.body);
        if (f.atoms === null || f.atoms.length === 0 || !disjoint(g1.body.raw, f.atoms, flags)) continue;
        const raw = '(?:' + o.body.raw + g2.raw + ')';
        const body: ReNode = {
          t: 'group',
          raw,
          body: { t: 'alt', raw: raw.slice(3, -1), alts: [{ t: 'seq', raw: raw.slice(3, -1), items: [o.body, g2] }] },
        };
        items.splice(i + 1, 2, { t: 'quant', min: 0, max: 1, lazy: false, body, raw: raw + '?' });
      }
      return { ...n, items };
    }
    default:
      return n;
  }
}

/** Compiles to a program whose paths, taken in order, are the paths V8 takes. */
function compilePattern(ast: ReNode, flags: string): { prog: Ins[]; start: number } {
  const prog: Ins[] = [];
  const cflags = flags.replace(/[gy]/g, '');
  const sflags = cflags.replace('m', '');
  const emit = (o: Partial<Ins> & { op: number }) => (prog.push(instruction(o)), prog.length - 1);
  const match = emit({ op: MATCH });
  const sticky = (n: ReNode) => new RegExp('(?:' + n.raw + ')', cflags + 'y');
  const firstOf = (pc: number) => (prog[pc]!.op === CHAR ? prog[pc]!.cm : null);

  const tempered = (b: ReNode) => {
    if (b.t !== 'group' || b.body.t !== 'alt' || b.body.alts.length !== 1) return null;
    const only = b.body.alts[0]!;
    if (only.t !== 'seq' || only.items.length !== 2) return null;
    const [look, ch] = only.items as [ReNode, ReNode];
    return look.t === 'look' && !look.behind && look.neg && ch.t === 'char' ? { look, ch } : null;
  };

  function unroll(n: Extract<ReNode, { t: 'quant' }>, next: number, cont: Continuation): number {
    const b = n.body;
    if (nullable(b)) throw new UnsupportedPattern('quantified body can match empty');
    let pc: number;
    if (n.max === Infinity) {
      const loop = emit({ op: SPLIT, memo: true });
      const body = c(b, loop, PATTERN_END);
      prog[loop]!.x = n.lazy ? next : body;
      prog[loop]!.y = n.lazy ? body : next;
      pc = loop;
    } else {
      if (n.max - n.min > 20) throw new UnsupportedPattern('large bounded quantifier');
      pc = next;
      for (let j = 0; j < n.max - n.min; j++) {
        const body = c(b, pc, PATTERN_END);
        const xFirst = firstOf(body);
        // What follows cannot start with the body's first character: where
        // that character is here, skipping the body cannot succeed.
        const commit =
          !n.lazy && xFirst !== null && cont.first !== null && cont.first.length > 0 &&
          disjoint(xFirst.re.source.slice(4, -2), cont.first, sflags);
        pc = n.lazy
          ? emit({ op: SPLIT, x: next, y: body, xFirst: firstOf(next) })
          : emit({ op: SPLIT, x: body, y: next, xFirst, commit });
      }
    }
    if (n.min > 20) throw new UnsupportedPattern('large bounded quantifier');
    for (let j = 0; j < n.min; j++) pc = c(b, pc, PATTERN_END);
    return pc;
  }

  function c(n: ReNode, next: number, cont: Continuation): number {
    switch (n.t) {
      case 'seq': {
        let pc = next;
        let k = cont;
        for (let j = n.items.length - 1; j >= 0; j--) {
          pc = c(n.items[j]!, pc, k);
          k = precede(n.items[j]!, k);
        }
        return pc;
      }
      case 'alt': {
        const entries = n.alts.map((a) => c(a, next, cont));
        let pc = entries[entries.length - 1]!;
        // The atoms the alternatives after j can open with, when all of them must open with one.
        let rest: string[] | null = [];
        for (let j = entries.length - 2; j >= 0; j--) {
          const f = firstAtoms(n.alts[j + 1]!);
          rest = rest === null || f.empty || f.atoms === null ? null : [...rest, ...f.atoms];
          const xFirst = firstOf(entries[j]!);
          // Where this branch's first character is here, no later one can
          // start here at all, so it is taken without keeping the others open.
          const commit = xFirst !== null && rest !== null && rest.length > 0 && disjoint(xFirst.re.source.slice(4, -2), rest, sflags);
          pc = emit({ op: SPLIT, x: entries[j]!, y: pc, xFirst, commit });
        }
        return pc;
      }
      case 'group':
        return c(n.body, next, cont);
      case 'char':
        return emit({ op: CHAR, cm: charMap(n.raw, cflags), next });
      case 'assert':
        return emit({ op: ASSERT, kind: n.kind, next });
      case 'look':
        // cleartoship-ignore VG126: `n.raw` is a slice of a vendored rule's own
        // pattern, compiled once per rule — never text from a scanned repo.
        if (n.behind) return emit({ op: LOOK, re: new RegExp(n.raw, cflags + 'y'), next });
        if (evaluatesLinearly(n.body, sflags)) return emit({ op: LOOK, re: sticky(n.body), neg: n.neg, next });
        return emit({ op: LOOK, sub: c(n.body, match, PATTERN_END), neg: n.neg, next });
      case 'quant': {
        const t = n.body.t === 'char' ? null : tempered(n.body);
        const atom = n.body.t === 'char' ? n.body : t?.ch;
        if (atom === undefined) return unroll(n, next, cont);
        // When what follows can never start with a character this run
        // consumes, the run can only end where it stops: every earlier end
        // fails on its next character, in greedy order or lazy.
        const run = cont.first !== null && cont.first.length > 0 && disjoint(atom.raw, cont.first, sflags);
        // A short one (`['"]?`, `\d{2}`) is cheaper spelled out.
        if (!run && t === null && n.max <= 4) return unroll(n, next, cont);
        let forbid = -1;
        let forbidRe: RegExp | null = null;
        if (t !== null) {
          if (evaluatesLinearly(t.look.body, sflags)) forbidRe = sticky(t.look.body);
          else forbid = c(t.look.body, match, PATTERN_END);
        }
        return emit({
          op: run ? RUN : GAP,
          cm: charMap(atom.raw, cflags),
          forbid,
          forbidRe,
          forbidKey: forbidRe ? cflags + '\u0000' + forbidRe.source : '',
          min: n.min,
          max: n.max,
          lazy: n.lazy,
          next,
          first: firstMap(cont.first, cflags),
          seek: seekFor(cont, cflags),
          universal: UNIVERSAL.has(atom.raw),
        });
      }
    }
  }

  return { prog, start: c(ast, match, PATTERN_END) };
}

// --- Per-text state ----------------------------------------------------------

const isWordUnit = (c: number) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
const isLineTerminator = (c: number) => c === 10 || c === 13 || c === 0x2028 || c === 0x2029;

/** The sorted positions where a zero-width regex matches, listed lazily left to right. */
class Positions {
  private readonly list: number[] = [];
  private frontier = 0; // every match before this is listed
  private hint = 0;
  constructor(
    private readonly re: RegExp,
    private readonly text: string,
  ) {}

  private extendTo(q: number): void {
    const n = this.text.length;
    while (this.frontier <= q && this.frontier <= n) {
      this.re.lastIndex = this.frontier;
      if (!this.re.test(this.text)) {
        this.frontier = n + 1;
        return;
      }
      const at = this.re.lastIndex;
      this.list.push(at);
      this.frontier = at + 1;
    }
  }

  private lowerBound(q: number): number {
    const l = this.list;
    const h = this.hint;
    if (h < l.length && l[h]! >= q && (h === 0 || l[h - 1]! < q)) return h;
    let a = 0;
    let b = l.length;
    while (a < b) {
      const mid = (a + b) >> 1;
      if (l[mid]! < q) a = mid + 1;
      else b = mid;
    }
    return (this.hint = a);
  }

  /** The first position at or after q, or the text's length + 1. */
  next(q: number): number {
    const l = this.list;
    for (;;) {
      if (l.length > 0 && l[l.length - 1]! >= q) return l[this.lowerBound(q)]!;
      if (this.frontier > this.text.length) return this.text.length + 1;
      this.extendTo(Math.max(q, this.frontier));
    }
  }
}

/**
 * Where a gap's continuation can start, with a union-find over the positions
 * known to fail from there, so that a gap entered again skips all of them in
 * near-constant time. That skip is what makes the matcher linear: without it,
 * each entry walks every failure the last one found.
 */
class Candidates {
  // 0: not known to fail; otherwise (the next position that might not) + 1.
  private up: Int32Array | null = null;
  // 0: no pointer, the next is x - 1; otherwise (the next that might not) + 2.
  private down: Int32Array | null = null;
  constructor(
    private readonly first: FirstMap | null,
    /** Where V8 finds the continuation can start next, listed once per text. */
    private readonly seek: Positions | null,
    private readonly text: string,
  ) {}

  markFailed(x: number): void {
    if (this.up === null) {
      this.up = new Int32Array(this.text.length + 2);
      this.down = new Int32Array(this.text.length + 2);
    }
    if (this.up[x] === 0) this.up[x] = x + 2;
  }

  private viable(x: number): boolean {
    return this.first === null || (x < this.text.length && inFirst(this.first, this.text.charCodeAt(x)));
  }

  private findUp(i: number): number {
    const u = this.up;
    if (u === null) return i;
    let x = i;
    let j: number;
    while ((j = u[x]!) !== 0) x = j - 1;
    for (let y = i; y !== x; y = j) {
      j = u[y]! - 1;
      u[y] = x + 1;
    }
    return x;
  }

  private findDown(i: number): number {
    const u = this.up;
    const d = this.down;
    if (u === null || d === null) return i;
    let x = i;
    while (x >= 0 && u[x] !== 0) {
      const j = d[x]!;
      x = j === 0 ? x - 1 : j - 2;
    }
    for (let y = i; y > x; ) {
      const j = d[y]!;
      d[y] = x + 2;
      y = j === 0 ? y - 1 : j - 2;
    }
    return x;
  }

  /** The first position in [i, hi] not known to fail, or -1. */
  upFrom(i: number, hi: number): number {
    let walked = 0;
    for (let x = this.findUp(i); x <= hi; x = this.findUp(x + 1)) {
      if (this.viable(x)) return x;
      this.markFailed(x);
      // A long stretch where nothing can follow: let V8 find the next place
      // something can, and point past the stretch in one step.
      if (++walked === 16 && this.seek !== null) {
        walked = 0;
        const next = this.seek.next(x + 1);
        // Everything strictly between x and next is known not to be viable.
        if (next > x + 1) this.up![x + 1] = next + 1;
      }
    }
    return -1;
  }

  /** The last position in [lo, i] not known to fail, or -1. */
  downFrom(i: number, lo: number): number {
    for (let x = this.findDown(i); x >= lo; x = this.findDown(x - 1)) {
      if (this.viable(x)) return x;
      this.markFailed(x);
    }
    return -1;
  }
}

// Run breaks and forbidden-word positions depend only on the text and the
// class, so every pattern reading the same text shares them.
let sharedText: string | null = null;
let sharedLists = new Map<string, Positions>();
let generation = 0;

function sharedFor(text: string): Map<string, Positions> {
  if (text !== sharedText) {
    sharedText = text;
    sharedLists = new Map();
  }
  return sharedLists;
}

/** The subset of RegExp the scanner uses. */
export interface Matcher {
  lastIndex: number;
  readonly global: boolean;
  readonly multiline: boolean;
  readonly source: string;
  readonly flags: string;
  exec(text: string): RegExpExecArray | null;
}

/**
 * A vendored pattern run by the memoizing matcher. Behaves as its RegExp does
 * under `exec` with `lastIndex`: same matches, same order, same `m[0]`.
 */
export class LinearMatcher implements Matcher {
  lastIndex = 0;
  readonly global: boolean;
  readonly multiline: boolean;
  readonly source: string;
  readonly flags: string;
  private readonly prog: Ins[];
  private readonly start: number;
  private readonly prefilter: RegExp | null;
  private readonly required: RegExp | null;

  private text: string | null = null;
  private n = 0;
  private gen = 0;
  private shared = new Map<string, Positions>();
  private requiredAt = -1;
  /** Where the previous search on this text started; see exec(). */
  private lastFrom = -1;
  // Indexed by instruction: failed (state, position) pairs, candidate sets,
  // lookahead verdicts, forbidden-word verdicts, run ends.
  private memo: (Uint8Array | undefined)[] = [];
  private cands: (Candidates | undefined)[] = [];
  private looks: (Uint8Array | undefined)[] = [];
  private forbids: (Uint8Array | undefined)[] = [];
  private runs: (Int32Array | undefined)[] = [];
  // Backtracking frames, five numbers each (see `run`).
  private stack: Int32Array = new Int32Array(1024);
  private sp = 0;

  constructor(re: RegExp) {
    this.global = re.global;
    this.multiline = re.multiline;
    this.source = re.source;
    this.flags = re.flags;
    const ast = collapseRuns(parsePattern(re.source), re.flags.replace(/[gmy]/g, ''));
    const { prog, start } = compilePattern(ast, re.flags);
    this.prog = prog;
    this.start = start;
    const flags = re.flags.replace(/[gy]/g, '');
    const top = precede(ast, PATTERN_END);
    const p0 = top.src !== '' && !BROAD.test(top.src) ? top.src : null;
    const f0 = firstMap(top.first, flags) !== null ? '(?:' + top.first!.join('|') + ')' : null;
    const filter = p0 ?? f0;
    this.prefilter = filter === null ? null : new RegExp('(?=' + filter + ')', flags + 'g');
    const req = requiredText(ast);
    this.required = req !== null && req[1] >= 3 ? new RegExp(req[0], flags + 'g') : null;
  }

  /** Drops the per-text tables, which hold a few bytes per character per state. */
  release(): void {
    this.text = null;
    this.memo = [];
    this.cands = [];
    this.looks = [];
    this.forbids = [];
    this.runs = [];
  }

  private reset(text: string): void {
    this.text = text;
    this.n = text.length;
    this.gen = ++generation;
    this.shared = sharedFor(text);
    this.requiredAt = -1;
    const len = this.prog.length;
    this.memo = new Array(len);
    this.cands = new Array(len);
    this.looks = new Array(len);
    this.forbids = new Array(len);
    this.runs = new Array(len);
  }

  private grow(sp: number): Int32Array {
    const bigger = new Int32Array(Math.max(this.stack.length * 2, sp + 1024));
    bigger.set(this.stack.subarray(0, sp));
    return (this.stack = bigger);
  }

  private fail(pc: number, q: number): void {
    let t = this.memo[pc];
    if (t === undefined) t = this.memo[pc] = new Uint8Array(this.n + 2);
    t[q] = 1;
  }

  private candidatesFor(ins: Ins): Candidates {
    let c = this.cands[ins.next];
    if (c === undefined) {
      const seek = ins.seek === null ? null : this.positions('S' + ins.seek.flags + ins.seek.source, ins.seek.source, ins.seek.flags);
      c = this.cands[ins.next] = new Candidates(ins.first, seek, this.text!);
    }
    return c;
  }

  private forbidden(pc: number, ins: Ins, q: number): boolean {
    if (ins.forbidRe !== null) {
      ins.forbidRe.lastIndex = q;
      return ins.forbidRe.test(this.text!);
    }
    if (ins.forbid < 0) return false;
    let t = this.forbids[pc];
    if (t === undefined) t = this.forbids[pc] = new Uint8Array(this.n + 2);
    let v = t[q]!;
    if (v === 0) t[q] = v = this.run(ins.forbid, q) >= 0 ? 1 : 2;
    return v === 1;
  }

  private positions(key: string, source: string, flags: string): Positions {
    let p = this.shared.get(key);
    if (p === undefined) {
      // cleartoship-ignore VG126: `source` is derived from a vendored rule's
      // pattern, not from the scanned text it is run over.
      p = new Positions(new RegExp(source, flags), this.text!);
      this.shared.set(key, p);
    }
    return p;
  }

  /** Where the run a gap may consume from q ends: the first character out of its class, or forbidden word. */
  private runEnd(pc: number, ins: Ins, q: number): number {
    const text = this.text!;
    const n = this.n;
    const cm = ins.cm!;
    let x = q;
    if (ins.forbid < 0) {
      if (ins.lastGen === this.gen && q >= ins.lastQ && q <= ins.lastEnd) return ins.lastEnd;
      if (ins.listGen !== this.gen) {
        ins.listGen = this.gen;
        ins.forbidList = null;
        ins.breakList = null;
      }
      let limit = n;
      if (ins.forbidRe !== null) {
        if (ins.forbidList === null) {
          const flags = ins.forbidRe.flags.replace('y', '') + 'g';
          ins.forbidList = this.positions('F' + ins.forbidKey, '(?=' + ins.forbidRe.source + ')', flags);
        }
        limit = Math.min(n, ins.forbidList.next(q));
      }
      let end: number;
      if (ins.universal) end = limit;
      else {
        // Short runs are walked. A greedy gap asks from right to left, so a
        // walk that reaches the run asked about last ends where that one does.
        // A long run is finished from the class's break positions, sparse
        // exactly when runs are long.
        const joins = ins.lastGen === this.gen && q < ins.lastQ && ins.lastQ - q <= 64;
        const stop = Math.min(limit, joins ? ins.lastQ : q + 24);
        while (x < stop && inMap(cm, text.charCodeAt(x))) x++;
        if (x < stop || x === limit) end = x;
        else if (joins) end = Math.min(ins.lastEnd, limit);
        else {
          if (ins.breakList === null) {
            const cls = cm.re.source.slice(4, -2); // `^(?:` … `)$`
            ins.breakList = this.positions('B' + cm.key, '(?!' + cls + ')(?=[\\s\\S])', cm.re.flags + 'g');
          }
          end = Math.min(limit, ins.breakList.next(x));
        }
      }
      ins.lastGen = this.gen;
      ins.lastQ = q;
      ins.lastEnd = end;
      return end;
    }
    // Forbidden words only the matcher can evaluate: walk, remembering run ends.
    let t = this.runs[pc];
    if (t === undefined) t = this.runs[pc] = new Int32Array(n + 2);
    const walked: number[] = [];
    let end: number;
    for (;;) {
      const cached = t[x]!;
      if (cached !== 0) {
        end = cached - 1;
        break;
      }
      if (x >= n || !inMap(cm, text.charCodeAt(x)) || this.forbidden(pc, ins, x)) {
        end = x;
        break;
      }
      walked.push(x);
      x++;
    }
    for (const w of walked) t[w] = end + 1;
    return end;
  }

  private look(pc: number, ins: Ins, q: number): boolean {
    if (ins.re !== null) {
      ins.re.lastIndex = q;
      return ins.re.test(this.text!) !== ins.neg;
    }
    let t = this.looks[pc];
    if (t === undefined) t = this.looks[pc] = new Uint8Array(this.n + 2);
    let v = t[q]!;
    if (v === 0) t[q] = v = this.run(ins.sub, q) >= 0 ? 1 : 2;
    return (v === 1) !== ins.neg;
  }

  /**
   * Where the first path from (pc0, pos0) that V8 would take reaches the
   * end, or -1. Frames are five numbers: [0, pc, pos] marks a memoized state
   * to record as failed once everything above it has; [1, pc, pos] is a
   * branch still to try; [2, gap pc, candidate, hi, lo] is a gap's place in
   * its list of ends.
   */
  private run(pc0: number, pos0: number): number {
    const prog = this.prog;
    const text = this.text!;
    const n = this.n;
    const memo = this.memo;
    // One stack for every nested run (lookaheads, forbidden words): this
    // run's frames start at `base`, and a nested run restores `sp` on return.
    let stack: Int32Array = this.stack;
    const base = this.sp;
    let sp = base;
    let pc = pc0;
    let pos = pos0;
    for (;;) {
      let ok = true;
      const ins = prog[pc]!;
      if (sp + 10 > stack.length) stack = this.grow(sp);
      switch (ins.op) {
        case CHAR: {
          if (pos < n) {
            const c = text.charCodeAt(pos);
            const v = ins.cm!.map[c];
            if (v === 1 || (v === 0 && inMap(ins.cm!, c))) {
              pos++;
              pc = ins.next;
              break;
            }
          }
          ok = false;
          break;
        }
        case ASSERT: {
          let r: boolean;
          if (ins.kind === '^') r = pos === 0 || (this.multiline && isLineTerminator(text.charCodeAt(pos - 1)));
          else if (ins.kind === '$') r = pos === n || (this.multiline && isLineTerminator(text.charCodeAt(pos)));
          else {
            const a = pos > 0 && isWordUnit(text.charCodeAt(pos - 1));
            const b = pos < n && isWordUnit(text.charCodeAt(pos));
            r = ins.kind === 'b' ? a !== b : a === b;
          }
          if (r) pc = ins.next;
          else ok = false;
          break;
        }
        case LOOK:
          this.sp = sp;
          ok = this.look(pc, ins, pos);
          stack = this.stack;
          if (ok) pc = ins.next;
          break;
        case SPLIT: {
          // A branch that must open with a character that is not here.
          if (ins.xFirst !== null && (pos >= n || !inMap(ins.xFirst, text.charCodeAt(pos)))) {
            pc = ins.y;
            break;
          }
          if (ins.commit) {
            pc = ins.x;
            break;
          }
          if (ins.memo) {
            const t = memo[pc];
            if (t !== undefined && t[pos] === 1) {
              ok = false;
              break;
            }
            stack[sp] = 0;
            stack[sp + 1] = pc;
            stack[sp + 2] = pos;
            sp += 5;
          }
          stack[sp] = 1;
          stack[sp + 1] = ins.y;
          stack[sp + 2] = pos;
          sp += 5;
          pc = ins.x;
          break;
        }
        case GAP: {
          const t = memo[pc];
          if (t !== undefined && t[pos] === 1) {
            ok = false;
            break;
          }
          const lo = pos + ins.min;
          const cap = ins.max === Infinity ? n : Math.min(n, pos + ins.max);
          if (lo <= cap) {
            this.sp = sp;
            const hi = Math.min(cap, this.runEnd(pc, ins, pos));
            stack = this.stack;
            if (lo <= hi) {
              const cands = this.candidatesFor(ins);
              const x = ins.lazy ? cands.upFrom(lo, hi) : cands.downFrom(hi, lo);
              if (x >= 0) {
                stack[sp] = 0;
                stack[sp + 1] = pc;
                stack[sp + 2] = pos;
                stack[sp + 5] = 2;
                stack[sp + 6] = pc;
                stack[sp + 7] = x;
                stack[sp + 8] = hi;
                stack[sp + 9] = lo;
                sp += 10;
                pc = ins.next;
                pos = x;
                break;
              }
            }
          }
          this.fail(pc, pos);
          ok = false;
          break;
        }
        case RUN: {
          let e: number;
          if (ins.max <= 4 && ins.forbid < 0 && ins.forbidRe === null) {
            e = pos;
            const stop = Math.min(n, pos + ins.max + 1);
            while (e < stop && inMap(ins.cm!, text.charCodeAt(e))) e++;
          } else {
            this.sp = sp;
            e = this.runEnd(pc, ins, pos);
            stack = this.stack;
          }
          if (e - pos >= ins.min && e - pos <= ins.max) {
            pos = e;
            pc = ins.next;
          } else ok = false;
          break;
        }
        case MATCH:
          this.sp = base;
          return pos;
      }
      if (ok) continue;
      // Backtrack to the most recent choice still open.
      for (;;) {
        if (sp === base) {
          this.sp = base;
          return -1;
        }
        const kind = stack[sp - 5]!;
        if (kind === 2) {
          const gap = prog[stack[sp - 4]!]!;
          const tried = stack[sp - 3]!;
          const cands = this.cands[gap.next]!;
          cands.markFailed(tried);
          const x = gap.lazy ? cands.upFrom(tried + 1, stack[sp - 2]!) : cands.downFrom(tried - 1, stack[sp - 1]!);
          if (x < 0) {
            sp -= 5;
            continue;
          }
          stack[sp - 3] = x;
          pc = gap.next;
          pos = x;
          break;
        }
        sp -= 5;
        if (kind === 0) {
          this.fail(stack[sp + 1]!, stack[sp + 2]!);
          continue;
        }
        pc = stack[sp + 1]!;
        pos = stack[sp + 2]!;
        break;
      }
    }
  }

  exec(text: string): RegExpExecArray | null {
    let from = this.global ? this.lastIndex : 0;
    // The per-text tables assume searches move forward. Searching the same
    // text again from an earlier position — a second file with identical
    // content, or the same file in a later scan in one process — used to reuse
    // `requiredAt` from the finished search, which said nothing was left, so
    // every match was lost. Start over whenever the search moves backwards.
    if (text !== this.text || from < this.lastFrom) this.reset(text);
    this.lastFrom = from;
    const n = this.n;
    for (;;) {
      if (from > n) break;
      // Nothing from here on holds the text every match must: no match.
      if (this.required !== null && this.requiredAt < from) {
        this.required.lastIndex = from;
        const r = this.required.exec(text);
        this.requiredAt = r === null ? n + 1 : r.index;
      }
      if (this.requiredAt > n) break;
      let p = from;
      if (this.prefilter !== null) {
        this.prefilter.lastIndex = from;
        if (!this.prefilter.test(text)) break;
        p = this.prefilter.lastIndex;
      }
      this.sp = 0;
      const end = this.run(this.start, p);
      if (end >= 0) {
        const m = Object.assign([text.slice(p, end)], { index: p, input: text, groups: undefined });
        if (this.global) this.lastIndex = end;
        return m as RegExpExecArray;
      }
      from = p + 1;
    }
    if (this.global) this.lastIndex = 0;
    return null;
  }
}

/** Whether V8 already searches `re` in linear time, so it is best left to V8. */
export function linearInIrregexp(re: RegExp): boolean {
  try {
    return evaluatesLinearly(parsePattern(re.source), re.flags.replace(/[gmy]/g, ''));
  } catch (err) {
    if (err instanceof UnsupportedPattern) return false;
    throw err;
  }
}

const MATCHERS = new WeakMap<RegExp, Matcher>();

/**
 * What the scanner runs for a pattern: the pattern itself when V8 already
 * searches it in linear time (or it uses syntax the matcher does not handle,
 * which is one rule, VG1094's backreference), and a LinearMatcher otherwise.
 */
export function matcherFor(re: RegExp): Matcher {
  let m = MATCHERS.get(re);
  if (m === undefined) {
    m = re;
    if (!linearInIrregexp(re)) {
      try {
        m = new LinearMatcher(re);
      } catch (err) {
        if (!(err instanceof UnsupportedPattern)) throw err;
      }
    }
    MATCHERS.set(re, m);
  }
  return m;
}

/**
 * Files up to the walker's own 2 MB cap are run through the ruleset. This was
 * 400 KB, and a file between the two was skipped here without a word: an
 * `eval(req.body.code)` in a 420 KB module was never looked at, the run said
 * clear, and nothing said why.
 *
 * The 400 KB cap existed for a real reason — fuzzing the ruleset with each
 * rule's own trigger word repeated finds patterns whose cost grows with the
 * square of the input — so the files above it are not handed to a regex whole.
 * They are searched in line-aligned windows (below), which caps what one
 * uninterruptible `exec` can cost at what a WINDOW-sized input costs, and
 * makes the total linear in the size of the file. Every pattern V8 could
 * backtrack on now runs on the linear-time matcher instead, so the windows
 * are a second line of defence; they also bound the matcher's per-position
 * tables to a window's size.
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
 *
 * With every pattern either linear in V8 or on the linear-time matcher, this
 * is a safety net rather than the thing that contains ReDoS: the worst input
 * the whole-ruleset fuzz and a hill-climbing search could find costs one rule
 * about 120 ms per 400 KB on a loaded developer machine.
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
export function anchoredToInput(re: { readonly multiline: boolean; readonly source: string }): boolean {
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

/**
 * The counts the README quotes about this ruleset, exported so the docs can be
 * asserted against the code rather than remembered. The 2026-10-13 audit found
 * "435 additional rules vendored" (435 is the count that *runs*; 468 are
 * vendored) and "21 carry a match guard" (22 did) — two numbers no check read.
 */
export const RULE_COUNTS = {
  vendored: GUARDVIBE_RULES.length,
  superseded: SUPERSEDED.size,
  withheld: WITHHELD.size,
  guarded: Object.keys(MATCH_GUARDS).length,
  overridden: Object.keys(PATTERN_OVERRIDES).length,
  manifestOnly: MANIFEST_ONLY.size,
  active: GUARDVIBE_RULES.length - SUPERSEDED.size - WITHHELD.size,
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
      const suppress = new Suppressions(source, relPath);
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

        const re = matcherFor(PATTERN_OVERRIDES[rule.id] ?? rule.pattern);
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
          if (guard && !guard(m[0], source, index, spans, relPath)) {
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
        if (re instanceof LinearMatcher) re.release();
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
    const linear = active.filter((r) => matcherFor(PATTERN_OVERRIDES[r.id] ?? r.pattern) instanceof LinearMatcher);
    if (linear.length > 0) {
      notes.push(`${linear.length} run by a linear-time matcher (same matches, no super-linear backtracking)`);
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
