import {
  read, rel, isSql, snippetAt,
  splitStatements, normaliseTable, isAlwaysTrue, QUALIFIED_NAME,
  Suppressions, emptyResult,
} from '../internal.js';
// Not re-exported through internal.ts; sql.ts has no imports of its own, so
// reaching it directly cannot introduce an initialisation-order cycle.
import { readBalanced } from '../utils/sql.js';
import type { Finding, ProjectContext, ScanResult, Scanner, Severity } from '../internal.js';
import { existsSync } from 'node:fs';
import { basename, dirname, join, relative, resolve, isAbsolute } from 'node:path';

/* ------------------------------------------------------------------------- *
 * Which .sql files are PostgreSQL at all.
 *
 * `ctx.framework.supabase` is a repo-wide flag, so one Supabase package in a
 * monorepo used to make every .sql file in it — a Cloudflare D1 (SQLite)
 * migration included — read as a Supabase table with RLS off. Each file is
 * now judged on its own. A file is *excluded* only on positive evidence that
 * it is not Postgres; without that evidence the old behaviour stands, because
 * dropping a Postgres file on a guess is a clean report on unread code.
 * ------------------------------------------------------------------------- */

/** RLS / Supabase-auth idioms: a file carrying these is Postgres, whatever else is true. */
const PG_RLS_IDIOMS =
  /\brow\s+level\s+security\b|\bauth\.(uid|jwt|role)\s*\(|\bto\s+(anon|authenticated)\b|\bcreate\s+policy\b/i;

/**
 * SQLite-only syntax. Each of these is a syntax error or an unknown function
 * in PostgreSQL, so one of them is real evidence — unlike `INTEGER PRIMARY
 * KEY` or `TEXT`, which both dialects accept.
 */
const SQLITE_ONLY =
  /\bautoincrement\b|\bunixepoch\s*\(|\bwithout\s+rowid\b|^\s*pragma\s+\w|\bstrftime\s*\(|\bdatetime\s*\(\s*'now'/im;

/** Postgres-only syntax; any of it vetoes the SQLite reading. */
const POSTGRES_ONLY =
  /\b(uuid|jsonb|timestamptz|bigserial|serial|gen_random_uuid|plpgsql|security\s+definer)\b|\bcreate\s+(extension|schema|type)\b|\$\$|\bauth\s*\.\s*users\b/i;

const WRANGLER_CONFIGS = ['wrangler.toml', 'wrangler.json', 'wrangler.jsonc'];

function isWithin(dir: string, file: string): boolean {
  const r = relative(dir, file);
  return r !== '' && !r.startsWith('..') && !isAbsolute(r);
}

/** Directories from `start` up to and including `root` (start must be inside root). */
function ancestors(start: string, root: string): string[] {
  const out: string[] = [];
  let dir = start;
  for (;;) {
    out.push(dir);
    if (dir === root || !isWithin(root, dir)) break;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return out;
}

function dependsOnSupabase(pkg: any): boolean {
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies']) {
    const deps = pkg?.[field];
    if (deps && typeof deps === 'object' && Object.keys(deps).some((d) => d === 'supabase' || d.startsWith('@supabase/'))) {
      return true;
    }
  }
  return false;
}

interface DialectModel {
  /** Absolute dirs holding a wrangler config that declares D1 databases. */
  d1ConfigDirs: Set<string>;
  /** Absolute D1 `migrations_dir` paths, resolved against their config. */
  d1MigrationDirs: Set<string>;
  /** Absolute Prisma migrations dirs whose `migration_lock.toml` names a non-Postgres provider. */
  prismaOtherDirs: Set<string>;
  /** Directory → whether its nearest package.json depends on Supabase (null: none found). */
  pkgCache: Map<string, boolean | null>;
}

function buildDialectModel(ctx: ProjectContext): DialectModel {
  const d1ConfigDirs = new Set<string>();
  const d1MigrationDirs = new Set<string>();
  // Every directory the scan touched and its ancestors: that is where a
  // wrangler config next to (or above) a migration, or one pointing at it
  // through `migrations_dir`, can live. `.jsonc` is not a scanned extension,
  // so configs are looked up on disk rather than taken from ctx.files.
  const dirs = new Set<string>();
  for (const f of ctx.files) for (const d of ancestors(dirname(f), ctx.root)) dirs.add(d);
  const prismaOtherDirs = new Set<string>();
  for (const dir of dirs) {
    // Prisma writes the datasource provider next to its migrations. Its
    // SQLite output (`"id" TEXT NOT NULL PRIMARY KEY`, `DATETIME`) carries no
    // SQLite-only syntax, so without this a Prisma-on-SQLite app read as a
    // Supabase table with RLS off on every model.
    const lock = read(join(dir, 'migration_lock.toml'));
    const provider = lock === null ? undefined : /^\s*provider\s*=\s*"([^"]+)"/m.exec(lock)?.[1];
    if (provider && !/^(postgres(ql)?|cockroachdb)$/i.test(provider)) prismaOtherDirs.add(dir);
    for (const name of WRANGLER_CONFIGS) {
      const path = join(dir, name);
      if (!existsSync(path)) continue;
      const src = read(path);
      if (!src || !/\bd1_databases\b/.test(src)) continue;
      d1ConfigDirs.add(dir);
      const declared = [...src.matchAll(/["']?migrations_dir["']?\s*[:=]\s*["']([^"']+)["']/g)].map((m) => m[1]!);
      for (const m of declared.length ? declared : ['migrations']) d1MigrationDirs.add(resolve(dir, m));
    }
  }
  return { d1ConfigDirs, d1MigrationDirs, prismaOtherDirs, pkgCache: new Map() };
}

function nearestPackageSupabase(model: DialectModel, file: string, root: string): boolean | null {
  const chain = ancestors(dirname(file), root);
  let answer: boolean | null = null;
  let resolvedAt = chain.length;
  for (let i = 0; i < chain.length; i++) {
    const cached = model.pkgCache.get(chain[i]!);
    if (cached !== undefined) { answer = cached; resolvedAt = i; break; }
    const raw = read(join(chain[i]!, 'package.json'));
    if (raw === null) continue;
    try {
      answer = dependsOnSupabase(JSON.parse(raw));
    } catch {
      answer = null;
    }
    resolvedAt = i;
    break;
  }
  for (let i = 0; i <= Math.min(resolvedAt, chain.length - 1); i++) model.pkgCache.set(chain[i]!, answer);
  return answer;
}

const dialectCache = new WeakMap<ProjectContext, string[]>();

/**
 * The .sql files this scanner should model as PostgreSQL.
 *
 * Excluded (not Postgres) — only when the file is not under a `supabase/`
 * directory and carries no RLS / Supabase-auth idiom, and then either:
 *   - it sits in a D1 `migrations_dir`, or under a directory whose wrangler
 *     config declares `d1_databases` while its nearest package.json does not
 *     depend on Supabase; or
 *   - it uses SQLite-only syntax (AUTOINCREMENT, unixepoch(), …) and no
 *     Postgres-only syntax; or
 *   - it sits under a Prisma migrations dir whose `migration_lock.toml` names
 *     a provider other than PostgreSQL/CockroachDB, and has no Postgres-only
 *     syntax.
 * Included — everything else, provided something says Postgres/Supabase: the
 * file is under `supabase/`, its nearest package.json depends on Supabase, or
 * the repo-wide signals (the root dependency set, a root `supabase/` dir, RLS
 * idioms in any remaining SQL file) hold.
 */
function postgresSqlFiles(ctx: ProjectContext): string[] {
  const cached = dialectCache.get(ctx);
  if (cached) return cached;
  const sql = ctx.files.filter(isSql);
  if (sql.length === 0) { dialectCache.set(ctx, []); return []; }

  const model = buildDialectModel(ctx);
  const candidates: { file: string; src: string; perFile: boolean }[] = [];
  for (const file of sql) {
    const src = read(file) ?? '';
    const underSupabase = rel(ctx.root, file).split('/').slice(0, -1).includes('supabase');
    const idioms = PG_RLS_IDIOMS.test(src);
    const pkgSupabase = nearestPackageSupabase(model, file, ctx.root) === true;
    if (!underSupabase && !idioms) {
      const inMigrationsDir = [...model.d1MigrationDirs].some((d) => isWithin(d, file));
      const underD1Worker = !pkgSupabase && [...model.d1ConfigDirs].some((d) => isWithin(d, file));
      const sqliteDialect = SQLITE_ONLY.test(src) && !POSTGRES_ONLY.test(src);
      const prismaOther = [...model.prismaOtherDirs].some((d) => isWithin(d, file)) && !POSTGRES_ONLY.test(src);
      if (inMigrationsDir || underD1Worker || sqliteDialect || prismaOther) continue;
    }
    candidates.push({ file, src, perFile: underSupabase || idioms || pkgSupabase });
  }
  const repoSignal = ctx.framework.supabase || candidates.some((c) => PG_RLS_IDIOMS.test(c.src));
  const out = candidates.filter((c) => repoSignal || c.perFile).map((c) => c.file);
  dialectCache.set(ctx, out);
  return out;
}

/* ------------------------------------------------------------------------- *
 * Which .sql files belong to the same database.
 *
 * A whole-repo scan used to replay every .sql file into one schema, so two
 * projects' migrations mixed: a monorepo's second app, or this repository's
 * own test fixtures, had one project's policies judged against the other's
 * tables (the clean fixture got the vulnerable one's CTS050, the vulnerable
 * one lost a CTS014). Each file now belongs to the nearest directory, walking
 * up from it towards the scan root, that is a project root:
 *
 *   - it has a `supabase/` directory holding `config.toml` or `migrations/`
 *     (the Supabase CLI layout: migrations/, seed.sql and schemas/ all sit
 *     under it, so every one of them resolves to the same parent); or
 *   - it has a `package.json`; or
 *   - it is the scan root.
 *
 * A directory named `supabase` is never a root itself, even with a
 * package.json of its own (edge-function tooling often puts one there), so
 * `supabase/migrations` always joins the app that owns the `supabase/` dir.
 * A single-app repo — root package.json, SQL in supabase/, db/ or migrations/
 * — is therefore one project; `packages/db/supabase/…` in a monorepo is its
 * own.
 * ------------------------------------------------------------------------- */

function isProjectRoot(dir: string): boolean {
  if (basename(dir) === 'supabase') return false;
  if (existsSync(join(dir, 'package.json'))) return true;
  const supa = join(dir, 'supabase');
  return existsSync(join(supa, 'config.toml')) || existsSync(join(supa, 'migrations'));
}

/** Groups files by project root; each group keeps the input (sorted) order. */
function partitionIntoProjects(files: string[], root: string): Map<string, string[]> {
  const rootCache = new Map<string, boolean>();
  const projects = new Map<string, string[]>();
  for (const file of files) {
    let owner = root;
    for (const dir of ancestors(dirname(file), root)) {
      if (dir === root || !isWithin(root, dir)) break;
      let isRoot = rootCache.get(dir);
      if (isRoot === undefined) { isRoot = isProjectRoot(dir); rootCache.set(dir, isRoot); }
      if (isRoot) { owner = dir; break; }
    }
    const list = projects.get(owner) ?? [];
    list.push(file);
    projects.set(owner, list);
  }
  return projects;
}

const OWNER_COLUMNS = [
  'user_id', 'owner_id', 'tenant_id', 'org_id', 'organization_id', 'account_id',
  'profile_id', 'created_by', 'author_id', 'auth_id', 'uid', 'customer_id',
  'workspace_id', 'team_id', 'member_id',
];

const SENSITIVE_COLUMNS = [
  'email', 'phone', 'address', 'ssn', 'social_security', 'password', 'password_hash',
  'token', 'access_token', 'refresh_token', 'secret', 'api_key', 'private_key',
  'stripe_customer', 'stripe_account', 'card', 'iban', 'account_number', 'salary',
  'balance', 'date_of_birth', 'dob', 'birth_date', 'passport', 'license_number',
  'ip_address', 'full_name', 'first_name', 'last_name',
];

/** Roles reachable with nothing but the public anon key. */
const PUBLIC_ROLES = new Set(['anon', 'public', 'authenticated']);
const UNAUTHENTICATED_ROLES = new Set(['anon', 'public']);

interface Policy {
  name: string;
  table: string;
  command: string;
  roles: string[];
  permissive: boolean;
  using: string | null;
  withCheck: string | null;
  file: string;
  line: number;
}

interface Table {
  name: string;
  columns: string[];
  rlsEnabled: boolean;
  file: string;
  line: number;
  createdInPublic: boolean;
}

function parseColumns(body: string): string[] {
  const cols: string[] = [];
  let depth = 0;
  let current = '';
  let inString: string | null = null;
  for (const ch of body) {
    if (inString) {
      current += ch;
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === "'" || ch === '"') { inString = ch; current += ch; continue; }
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) { cols.push(current); current = ''; continue; }
    current += ch;
  }
  cols.push(current);
  return cols
    .map((c) => c.trim())
    .filter(Boolean)
    .map((c) => /^("[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)/.exec(c)?.[1] ?? '')
    .map((c) => c.replace(/^"(.*)"$/, '$1').toLowerCase())
    .filter((c) => c && !['constraint', 'primary', 'foreign', 'unique', 'check', 'exclude', 'like'].includes(c));
}

/**
 * Parses what follows `CREATE POLICY <name> ON <table>`:
 *   [AS PERMISSIVE|RESTRICTIVE] [FOR cmd] [TO role, ...] [USING (…)] [WITH CHECK (…)]
 * The name and table are already consumed, so words inside a policy name
 * ("Enable read access for all users", "Anyone can add to cart") can no longer
 * be mistaken for the FOR or TO clause, and only the header — the part before
 * USING / WITH CHECK — is searched for them, so a string literal inside a
 * predicate cannot be either.
 */
function parsePolicyTail(tail: string): Pick<Policy, 'command' | 'roles' | 'permissive' | 'using' | 'withCheck'> {
  const bodyStart = /\busing\s*\(|\bwith\s+check\s*\(/i.exec(tail);
  const header = bodyStart ? tail.slice(0, bodyStart.index) : tail;
  const body = bodyStart ? tail.slice(bodyStart.index) : '';

  const permissive = !/^\s*as\s+restrictive\b/i.test(header);
  const command = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(header)?.[1]?.toUpperCase() ?? 'ALL';
  const toClause = /\bto\s+(.+?)\s*$/i.exec(header)?.[1];
  const roles = toClause
    ? toClause.split(',').map((r) => r.trim().replace(/^"(.*)"$/, '$1').toLowerCase()).filter(Boolean)
    : ['public'];

  let using: string | null = null;
  let withCheck: string | null = null;
  let rest = body;
  const usingKw = /^\s*using\s*(?=\()/i.exec(rest);
  if (usingKw) {
    const open = usingKw[0].length;
    using = readBalanced(rest, open);
    if (using !== null) rest = rest.slice(open + using.length + 2);
  }
  const checkKw = /^\s*with\s+check\s*(?=\()/i.exec(rest);
  if (checkKw) withCheck = readBalanced(rest, checkKw[0].length);
  return { command, roles, permissive, using, withCheck };
}

/** True when a policy admits nobody but the service role. */
function serviceRoleOnly(p: Policy): boolean {
  if (p.roles.length > 0 && p.roles.every((r) => r === 'service_role')) return true;
  const predicates = [p.using, p.withCheck].filter((e): e is string => e !== null);
  return predicates.length > 0 &&
    predicates.every((e) => /^[\s(]*(?:select\s+)?auth\.role\(\)[\s)]*=\s*'service_role'[\s)]*$/i.test(e));
}

/* ------------------------------------------------------------------------- *
 * Does a predicate isolate one user's rows from another's?
 *
 * Isolation means comparing the row to *who* the caller is: auth.uid(), a JWT
 * claim, a request setting, current_user, or a helper function whose body does
 * one of those. Checks that only establish *that* the caller is signed in —
 * `auth.role() = 'authenticated'`, `auth.uid() IS NOT NULL`, the JWT's role /
 * aud / aal / is_anonymous claims — are "gates": they let every signed-in user
 * through. They are rewritten to marker tokens first, so `auth.uid() IS NOT
 * NULL AND user_id = auth.uid()` still isolates and `auth.uid() IS NOT NULL`
 * alone does not.
 * ------------------------------------------------------------------------- */

const CALLER_REF = /\bauth\s*\.\s*(?:uid|jwt|email)\s*\(\s*\)|\bcurrent_setting\s*\(|\bcurrent_user\b|\bsession_user\b/i;
const GATE = '__cts_gate__';
const NEUTRAL = '__cts_role__';

/** `= 'authenticated'` and `<> 'anon'` admit every signed-in user; other role comparisons admit nobody in particular. */
function roleComparison(op: string, role: string): string {
  const eq = op === '=';
  return (eq && role === 'authenticated') || (!eq && role === 'anon') ? GATE : NEUTRAL;
}

const ROLE_SOURCE =
  String.raw`(?:\(\s*)?(?:select\s+)?(?:auth\s*\.\s*role\s*\(\s*\)` +
  String.raw`|\(?\s*auth\s*\.\s*jwt\s*\(\s*\)\s*\)?\s*->>\s*'role'` +
  String.raw`|current_setting\s*\(\s*'request\.jwt\.claim\.role'[^)]*\)` +
  String.raw`|current_setting\s*\(\s*'request\.jwt\.claims'[^)]*\)\s*(?:::\s*jsonb?\s*)?->>\s*'role'` +
  String.raw`|current_user)(?:\s*\))?(?:\s*::\s*text)?`;

function markGates(expr: string): string {
  return expr
    .replace(new RegExp(`${ROLE_SOURCE}\\s*(=|<>|!=)\\s*'(\\w+)'(?:\\s*::\\s*text)?`, 'gi'),
      (_m, op: string, role: string) => roleComparison(op, role.toLowerCase()))
    .replace(new RegExp(`'(\\w+)'(?:\\s*::\\s*text)?\\s*(=|<>|!=)\\s*${ROLE_SOURCE}`, 'gi'),
      (_m, role: string, op: string) => roleComparison(op, role.toLowerCase()))
    .replace(/\bauth\s*\.\s*jwt\s*\(\s*\)\s*\)?\s*->>?\s*'(?:aud|aal|amr|is_anonymous)'/gi, GATE)
    .replace(/\bauth\s*\.\s*(?:uid|jwt)\s*\(\s*\)(?:\s*\))?\s*is\s+not\s+null/gi, GATE)
    .replace(/\bauth\s*\.\s*role\s*\(\s*\)/gi, NEUTRAL);
}

interface CallerFunctions {
  /** Bare, lower-cased names of functions whose body identifies the caller. */
  isolating: Set<string>;
  /** Bare names of functions whose body only checks that the caller is signed in. */
  gate: Set<string>;
}

function callsAny(expr: string, names: Set<string>): boolean {
  for (const name of names) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (new RegExp(`(?:^|[^\\w$])"?${escaped}"?\\s*\\(`, 'i').test(expr)) return true;
  }
  return false;
}

type Isolation = 'isolating' | 'gate' | 'other';

function classify(expr: string, fns: CallerFunctions): Isolation {
  const marked = markGates(expr);
  if (CALLER_REF.test(marked) || callsAny(marked, fns.isolating)) return 'isolating';
  if (marked.includes(GATE) || callsAny(marked, fns.gate)) return 'gate';
  return 'other';
}

/** Classifies every function body; a helper that calls an isolating helper isolates too. */
function classifyFunctions(bodies: Map<string, string>): CallerFunctions {
  const fns: CallerFunctions = { isolating: new Set(), gate: new Set() };
  for (let changed = true; changed;) {
    changed = false;
    for (const [name, body] of bodies) {
      const kind = classify(body, fns);
      if (kind === 'isolating' && !fns.isolating.has(name)) {
        fns.isolating.add(name);
        fns.gate.delete(name);
        changed = true;
      } else if (kind === 'gate' && !fns.gate.has(name) && !fns.isolating.has(name)) {
        fns.gate.add(name);
        changed = true;
      }
    }
  }
  return fns;
}

const COMMANDS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] as const;
type Command = (typeof COMMANDS)[number];

function covers(p: Policy, cmd: Command): boolean {
  return p.command === 'ALL' || p.command === cmd;
}

/**
 * The expression that decides which rows `cmd` reaches under this policy:
 * USING for SELECT / DELETE / UPDATE (the rows a caller can see or target),
 * WITH CHECK for INSERT (the rows a caller can create). A FOR ALL policy with
 * only USING uses it as the check too, as PostgreSQL does.
 */
function predicateFor(p: Policy, cmd: Command): string | null {
  if (cmd === 'INSERT') return p.withCheck ?? p.using;
  if (cmd === 'UPDATE') return p.using ?? p.withCheck;
  return p.using;
}

/** Policies whose roles include signed-in users: `authenticated`, or `public` (every role). */
function reachesSignedIn(p: Policy): boolean {
  return p.roles.some((r) => r === 'authenticated' || r === 'public');
}

const VERBS: Record<Command, string> = {
  SELECT: 'read',
  INSERT: 'create rows on behalf of',
  UPDATE: 'overwrite',
  DELETE: 'delete',
};

/** `DROP TABLE [IF EXISTS] a, b [CASCADE | RESTRICT]` → the tables it drops. */
function droppedTables(flat: string): string[] | null {
  const m = /^drop\s+table\s+(?:if\s+exists\s+)?(.+?)(?:\s+(?:cascade|restrict))?\s*$/i.exec(flat);
  if (!m) return null;
  const nameRe = new RegExp(`^${QUALIFIED_NAME}$`);
  return m[1]!
    .split(',')
    .map((n) => n.trim())
    .filter((n) => nameRe.test(n))
    .map(normaliseTable);
}

export const rlsScanner: Scanner = {
  name: 'Supabase / PostgreSQL Row Level Security',

  applies(ctx) {
    // Row Level Security is a PostgreSQL feature that Supabase builds on. This
    // scanner must not fire on SQLite / Cloudflare D1 / Prisma-sqlite schemas,
    // which have no RLS concept at all — doing so turns every CREATE TABLE into
    // a false "RLS disabled" critical. See postgresSqlFiles for how each file
    // is judged.
    return postgresSqlFiles(ctx).length > 0;
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    const findings: Finding[] = [];
    const suppressors = new Map<string, Suppressions>();
    const sources = new Map<string, string>();
    let publicTableCount = 0;
    let policyCount = 0;

    const sqlFiles = [...postgresSqlFiles(ctx)].sort();
    for (const projectFiles of partitionIntoProjects(sqlFiles, ctx.root).values()) {
      const project = analyseProject(ctx, projectFiles, sources, suppressors);
      findings.push(...project.findings);
      publicTableCount += project.publicTables;
      policyCount += project.policies;
    }

    // Apply inline suppressions now that every finding has a location.
    for (const f of findings) {
      const sup = f.file ? suppressors.get(f.file) : undefined;
      if (sup && f.line && sup.suppressed(f.line, f.id)) continue;
      const src = f.file ? sources.get(f.file) : undefined;
      if (src && f.line) f.snippet = snippetAt(src, f.line);
      result.findings.push(f);
    }

    if (publicTableCount > 0) {
      const unprotected = result.findings.filter((f) => f.id === 'CTS010').length;
      result.checks.push({
        label: `Row Level Security (${publicTableCount} public table${publicTableCount === 1 ? '' : 's'}, ${policyCount} polic${policyCount === 1 ? 'y' : 'ies'})`,
        passed: unprotected === 0,
      });
    } else if (sqlFiles.length > 0) {
      result.checks.push({
        label: 'Row Level Security',
        passed: true,
        note: 'no CREATE TABLE statements found in the scanned SQL',
      });
    }
    return result;
  },
};

/**
 * Replays one project's migrations into a schema model and judges it. Every
 * table, policy, function and bucket here is local to the project: two apps
 * in one repository (or this repository's test fixtures) each have their own
 * database, and a policy in one says nothing about a table in the other.
 */
function analyseProject(
  ctx: ProjectContext,
  sqlFiles: string[],
  sources: Map<string, string>,
  suppressors: Map<string, Suppressions>,
): { findings: Finding[]; publicTables: number; policies: number } {
    const tables = new Map<string, Table>();
    const policies: Policy[] = [];
    const definerFunctions = new Set<string>();
    const functionBodies = new Map<string, string>();
    const publicBuckets: { id: string; file: string; line: number }[] = [];
    const findings: Finding[] = [];

    // Pass 1: build a model of the schema by replaying every migration in order.
    for (const file of sqlFiles) {
      const source = read(file);
      if (source === null) continue;
      const relPath = rel(ctx.root, file);
      sources.set(relPath, source);
      suppressors.set(relPath, new Suppressions(source));

      for (const stmt of splitStatements(source)) {
        const text = stmt.text;
        const flat = text.replace(/\s+/g, ' ');

        const create = new RegExp(
          `^create\\s+(?:unlogged\\s+|temp(?:orary)?\\s+)?table\\s+(if\\s+not\\s+exists\\s+)?(${QUALIFIED_NAME})`,
          'i',
        ).exec(flat);
        if (create) {
          const name = normaliseTable(create[2]!);
          // `CREATE TABLE IF NOT EXISTS` on a table that is already there does nothing.
          // Replaying it as a fresh table reset the model's RLS state to "disabled", so a
          // schema dump re-declaring tables after the migrations that had enabled RLS on
          // them reported every one as unprotected.
          if (create[1] && tables.has(name)) continue;
          const open = text.indexOf('(', create[0].length - create[2]!.length);
          const body = open === -1 ? '' : text.slice(open + 1, text.lastIndexOf(')'));
          tables.set(name, {
            name,
            columns: parseColumns(body),
            rlsEnabled: false,
            file: relPath,
            line: stmt.line,
            createdInPublic: name.startsWith('public.'),
          });
          continue;
        }

        const alter = new RegExp(
          `^alter\\s+table\\s+(?:only\\s+)?(?:if\\s+exists\\s+)?(${QUALIFIED_NAME})\\s+(enable|disable|force|no\\s+force)\\s+row\\s+level\\s+security`,
          'i',
        ).exec(flat);
        if (alter) {
          const name = normaliseTable(alter[1]!);
          const verb = alter[2]!.toLowerCase().replace(/\s+/g, ' ');
          // FORCE / NO FORCE only decide whether the table owner is also subject
          // to the policies. They do not turn RLS on or off: FORCE without ENABLE
          // leaves the table unprotected, and NO FORCE after ENABLE leaves it on.
          if (verb !== 'enable' && verb !== 'disable') continue;
          const t = tables.get(name);
          if (t) t.rlsEnabled = verb === 'enable';
          else {
            tables.set(name, {
              name, columns: [], rlsEnabled: verb === 'enable',
              file: relPath, line: stmt.line, createdInPublic: name.startsWith('public.'),
            });
          }
          continue;
        }

        const dropped = droppedTables(flat);
        if (dropped) { for (const name of dropped) tables.delete(name); continue; }

        const policy = new RegExp(
          `^create\\s+policy\\s+(${QUALIFIED_NAME}|"[^"]+")\\s+on\\s+(${QUALIFIED_NAME})`,
          'i',
        ).exec(flat);
        if (policy) {
          const parsed = parsePolicyTail(flat.slice(policy[0].length));
          policies.push({
            name: policy[1]!.replace(/^"(.*)"$/, '$1'),
            table: normaliseTable(policy[2]!),
            file: relPath,
            line: stmt.line,
            ...parsed,
          });
          continue;
        }

        const dropPolicy = new RegExp(
          `^drop\\s+policy\\s+(?:if\\s+exists\\s+)?(${QUALIFIED_NAME}|"[^"]+")\\s+on\\s+(${QUALIFIED_NAME})`,
          'i',
        ).exec(flat);
        if (dropPolicy) {
          const pname = dropPolicy[1]!.replace(/^"(.*)"$/, '$1');
          const ptable = normaliseTable(dropPolicy[2]!);
          for (let k = policies.length - 1; k >= 0; k--) {
            if (policies[k]!.name === pname && policies[k]!.table === ptable) policies.splice(k, 1);
          }
          continue;
        }

        // GRANT write privileges directly to the anonymous role.
        const grant = /^grant\s+(.+?)\s+on\s+(.+?)\s+to\s+([a-z_",\s]+)/i.exec(flat);
        if (grant) {
          const privs = grant[1]!.toLowerCase();
          const grantees = grant[3]!.split(',').map((r) => r.trim().replace(/^"(.*)"$/, '$1').toLowerCase());
          const writes = /\ball\b|\binsert\b|\bupdate\b|\bdelete\b|\btruncate\b/.test(privs);
          const target = grant[2]!.toLowerCase();
          if (target.includes('function') && /\bexecute\b|\ball\b/.test(privs)) {
            const fnName = new RegExp(`function\\s+(${QUALIFIED_NAME})`, 'i').exec(grant[2]!)?.[1];
            const normalised = fnName ? normaliseTable(fnName) : null;
            if (normalised && definerFunctions.has(normalised) && grantees.some((g) => UNAUTHENTICATED_ROLES.has(g))) {
              findings.push({
                id: 'CTS052',
                severity: 'high',
                title: 'SECURITY DEFINER function is callable without signing in',
                detail:
                  `\`${normalised}\` runs with its owner's privileges and EXECUTE is granted to ` +
                  `${grantees.join(', ')}. Anyone holding the public anon key can call it, and whatever ` +
                  'it does happens with the definer’s rights rather than theirs — Row Level Security ' +
                  'included.',
                fix:
                  `REVOKE EXECUTE ON FUNCTION ${normalised} FROM anon, public;\n` +
                  'Grant it to `authenticated` only, and check the caller inside the function body.',
                file: relPath,
                line: stmt.line,
                cwe: 'CWE-269: Improper Privilege Management',
                owasp: 'A01:2025 - Broken Access Control',
                meta: { function: normalised, grantees },
              });
            }
            continue;
          }
          if (writes && grantees.some((g) => UNAUTHENTICATED_ROLES.has(g)) && !target.includes('sequence')) {
            findings.push({
              id: 'CTS017',
              severity: 'critical',
              title: 'Write privileges granted to the anonymous role',
              detail:
                `\`GRANT ${grant[1]!.trim()} ON ${grant[2]!.trim()} TO ${grant[3]!.trim()}\` hands write access ` +
                'to unauthenticated callers. Anyone holding the public anon key can invoke it.',
              fix:
                'Revoke the grant and give the privilege to `authenticated` only, then let a Row Level ' +
                'Security policy decide which rows that role may touch.',
              file: relPath,
              line: stmt.line,
              cwe: 'CWE-732: Incorrect Permission Assignment for Critical Resource',
              owasp: 'A01:2025 - Broken Access Control',
            });
          }
          continue;
        }

        // Supabase Storage: a bucket marked public serves every object in it
        // to unauthenticated callers over a predictable URL.
        if (/^insert\s+into\s+storage\s*\.\s*buckets\b/i.test(flat) && /\btrue\b/i.test(flat)) {
          const id = /values\s*\(\s*'([^']+)'/i.exec(flat)?.[1] ?? 'unknown';
          publicBuckets.push({ id, file: relPath, line: stmt.line });
          continue;
        }

        // Every function body, so a policy calling a helper such as
        // `is_org_member(org_id)` can be judged by what the helper checks.
        const fnDecl = new RegExp(`^create\\s+(?:or\\s+replace\\s+)?function\\s+(${QUALIFIED_NAME})`, 'i').exec(flat);
        if (fnDecl) {
          const bare = normaliseTable(fnDecl[1]!).split('.').pop()!;
          functionBodies.set(bare, flat.slice(fnDecl[0].length));
        }

        // SECURITY DEFINER functions without a pinned search_path.
        if (/^create\s+(or\s+replace\s+)?function/i.test(flat) && /security\s+definer/i.test(flat)) {
          const declared = new RegExp(`^create\\s+(?:or\\s+replace\\s+)?function\\s+(${QUALIFIED_NAME})`, 'i').exec(flat)?.[1];
          if (declared) definerFunctions.add(normaliseTable(declared));
          if (!/set\s+search_path/i.test(flat)) {
            const fname = declared ?? 'function';
            findings.push({
              id: 'CTS015',
              severity: 'medium',
              title: 'SECURITY DEFINER function without a pinned search_path',
              detail:
                `\`${fname}\` runs with the definer's privileges but inherits the caller's \`search_path\`. ` +
                'A caller who can create objects in a schema earlier on that path can shadow a table or ' +
                'operator the function uses and have their own code run as the definer.',
              fix: 'Add `SET search_path = \'\'` (or an explicit schema list) to the function definition.',
              file: relPath,
              line: stmt.line,
              cwe: 'CWE-426: Untrusted Search Path',
              owasp: 'A01:2025 - Broken Access Control',
            });
          }
          continue;
        }

        // Views bypass the RLS of their base tables unless security_invoker is set.
        const view = new RegExp(
          `^create\\s+(?:or\\s+replace\\s+)?(materialized\\s+)?view\\s+(?:if\\s+not\\s+exists\\s+)?(${QUALIFIED_NAME})`,
          'i',
        ).exec(flat);
        if (view) {
          const materialized = Boolean(view[1]);
          const name = normaliseTable(view[2]!);

          // A view over auth.users republishes every account's email and, on
          // older projects, the encrypted password, through the REST API.
          if (name.startsWith('public.') && /\bauth\s*\.\s*users\b/i.test(flat)) {
            findings.push({
              id: 'CTS019',
              severity: 'critical',
              title: 'auth.users is republished through the public schema',
              detail:
                `${materialized ? 'Materialized view' : 'View'} \`${name}\` selects from \`auth.users\` ` +
                'and lives in the schema PostgREST exposes. Supabase keeps that table out of the API ' +
                'precisely because it holds every user’s email address, phone number and auth metadata; ' +
                'a view over it hands all of that back to the API.',
              fix:
                `Drop the view, or move it to a private schema and expose only the columns you need ` +
                'through a `security_invoker` view over your own `profiles` table.',
              file: relPath,
              line: stmt.line,
              cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
              owasp: 'A01:2025 - Broken Access Control',
              meta: { view: name, materialized },
            });
            continue;
          }

          // Materialized views never consult the RLS of their base tables.
          if (name.startsWith('public.') && materialized) {
            findings.push({
              id: 'CTS016',
              severity: 'high',
              title: 'Materialized view is exposed over the Data API',
              detail:
                `Materialized view \`${name}\` is in the public schema. Materialized views hold their ` +
                'own copy of the data and never evaluate the Row Level Security policies of the tables ' +
                'they were built from, so every row in the snapshot is readable by anyone who can reach ' +
                'the API.',
              fix:
                'Move the materialized view into a private schema and expose a filtered, ' +
                '`security_invoker` view over it, or revoke SELECT from `anon` and `authenticated`.',
              file: relPath,
              line: stmt.line,
              cwe: 'CWE-863: Incorrect Authorization',
              owasp: 'A01:2025 - Broken Access Control',
              meta: { view: name, materialized: true },
            });
            continue;
          }

          if (name.startsWith('public.') && !/security_invoker\s*=\s*(on|true)/i.test(flat)) {
            findings.push({
              id: 'CTS016',
              severity: 'medium',
              title: 'API-exposed view runs with definer rights',
              detail:
                `View \`${name}\` is in the public schema, so PostgREST exposes it over the REST API. ` +
                'Without `security_invoker`, it queries its base tables as the view owner and the ' +
                'caller-side RLS policies on those tables are not applied.',
              fix:
                "Recreate the view with `WITH (security_invoker = on)`, or move it out of the `public` " +
                'schema so it is not exposed through the API.',
              file: relPath,
              line: stmt.line,
              cwe: 'CWE-863: Incorrect Authorization',
              owasp: 'A01:2025 - Broken Access Control',
            });
          }
          continue;
        }
      }
    }

    // Pass 2: judge the resulting schema.
    const callerFns = classifyFunctions(functionBodies);
    /** `table|command|policy` for each gate policy CTS014 reported, so CTS050 does not repeat it. */
    const gateLeaks = new Set<string>();
    /** `table|command|policy` for the scoped policies those gates defeat. */
    const defeated = new Set<string>();
    const policiesByTable = new Map<string, Policy[]>();
    for (const p of policies) {
      const list = policiesByTable.get(p.table) ?? [];
      list.push(p);
      policiesByTable.set(p.table, list);
    }

    for (const table of tables.values()) {
      if (!table.createdInPublic) continue;
      const tablePolicies = policiesByTable.get(table.name) ?? [];

      if (!table.rlsEnabled) {
        const hasPolicies = tablePolicies.length > 0;
        findings.push({
          id: 'CTS010',
          severity: 'critical',
          title: 'Public table with Row Level Security disabled',
          detail:
            `Table \`${table.name}\` is in the schema PostgREST exposes, and RLS was never enabled on it. ` +
            'Every row is readable — and writable — by anyone holding the anon key, which ships in your ' +
            'client bundle.' +
            (hasPolicies
              ? ` ${tablePolicies.length} polic${tablePolicies.length === 1 ? 'y is' : 'ies are'} defined on this table but they are inert until RLS is on.`
              : ''),
          fix: `ALTER TABLE "${table.name.split('.')[1]}" ENABLE ROW LEVEL SECURITY;\n` +
            (hasPolicies ? 'The existing policies then take effect.' : 'Then add a policy scoping rows to `auth.uid()`.'),
          file: table.file,
          line: table.line,
          cwe: 'CWE-1220: Insufficient Granularity of Access Control',
          owasp: 'A01:2025 - Broken Access Control',
          meta: { table: table.name, policyCount: tablePolicies.length },
        });
        continue;
      }

      // RESTRICTIVE policies are AND-ed onto the permissive ones and never grant
      // a row by themselves; with none permissive, RLS denies everything.
      const grantingPolicies = tablePolicies.filter((p) => p.permissive);

      if (grantingPolicies.length === 0) {
        findings.push({
          id: 'CTS011',
          severity: 'low',
          title: 'RLS enabled but no policy defined',
          detail:
            `Table \`${table.name}\` has RLS on and ` +
            (tablePolicies.length > 0 ? 'only restrictive policies, which grant nothing on their own' : 'no policies') +
            ', so PostgreSQL denies every row to every ' +
            'non-superuser role. This is fail-closed and therefore safe, but it usually means a feature ' +
            'silently returns empty results.',
          fix: 'Add the policies this table needs, or confirm it is only ever reached via a service-role client.',
          file: table.file,
          line: table.line,
          owasp: 'A01:2025 - Broken Access Control',
          meta: { table: table.name },
        });
        continue;
      }

      const ownerColumn = table.columns.find((c) => OWNER_COLUMNS.includes(c));
      const sensitive = table.columns.filter((c) =>
        SENSITIVE_COLUMNS.some((s) => c === s || c.includes(s)),
      );
      // Tenant isolation means comparing a row to *who* the caller is (see
      // classify). `auth.role() = 'authenticated'` or `auth.uid() IS NOT NULL`
      // only says the caller is signed in — every signed-in user then sees
      // every row, which is exactly what CTS014 is about — so it does not count.
      const referencesAuth = tablePolicies.some((p) =>
        [p.using, p.withCheck].some((e) => e !== null && classify(e, callerFns) === 'isolating'),
      );
      // A policy that only admits the service role reaches no end user (and the
      // service role bypasses RLS anyway), so it cannot leak rows across users.
      const reachesUsers = grantingPolicies.some((p) => !serviceRoleOnly(p));

      if (ownerColumn && referencesAuth) {
        // Some policy isolates, but PostgreSQL ORs the permissive policies for
        // each command: one "signed in is enough" policy beside a scoped one
        // makes the scoping dead code. Judged per command, with FOR ALL
        // counting towards each; a RESTRICTIVE policy that isolates is AND-ed
        // on and closes the leak for its commands.
        //
        // Only gates count (`auth.role() = 'authenticated'`, `auth.uid() IS
        // NOT NULL`): a constant `USING (true)` or a row filter such as
        // `published = true` is an explicit decision to publish, and CTS012 /
        // CTS013 judge those. A gate on SELECT is reported only beside a scoped
        // SELECT policy — "members can read every comment" is a common,
        // deliberate design — while a gate on a write is reported whenever the
        // table is otherwise per-user: letting every signed-in user overwrite
        // or delete everyone's rows is not.
        const leaks = new Map<Policy, { commands: Command[]; scopedBy: Set<string> }>();
        for (const cmd of COMMANDS) {
          const restrictiveIsolates = tablePolicies.some((p) => {
            const e = predicateFor(p, cmd);
            return !p.permissive && covers(p, cmd) && reachesSignedIn(p) && e !== null &&
              classify(e, callerFns) === 'isolating';
          });
          if (restrictiveIsolates) continue;
          const reach = grantingPolicies.filter((p) => covers(p, cmd) && reachesSignedIn(p) && !serviceRoleOnly(p));
          const kind = (p: Policy): Isolation | null => {
            const e = predicateFor(p, cmd);
            return e === null ? null : classify(e, callerFns);
          };
          const gates = reach.filter((p) => kind(p) === 'gate');
          if (gates.length === 0) continue;
          const scoped = reach.filter((p) => kind(p) === 'isolating');
          if (cmd === 'SELECT' && scoped.length === 0) continue;
          for (const g of gates) {
            const entry = leaks.get(g) ?? { commands: [], scopedBy: new Set<string>() };
            entry.commands.push(cmd);
            for (const s of scoped) {
              entry.scopedBy.add(s.name);
              defeated.add(`${table.name}|${cmd}|${s.name}`);
            }
            leaks.set(g, entry);
            gateLeaks.add(`${table.name}|${cmd}|${g.name}`);
          }
        }
        for (const [g, { commands, scopedBy }] of leaks) {
          const scopedNames = [...scopedBy];
          const predicate = (predicateFor(g, commands[0]!) ?? '').replace(/\s+/g, ' ').trim();
          findings.push({
            id: 'CTS014',
            severity: 'high',
            title: 'A policy lets every signed-in user past a per-user table’s isolation',
            detail:
              `Policy \`${g.name}\` on \`${table.name}\` grants ${commands.join(', ')} with ` +
              `\`${predicate.length > 80 ? `${predicate.slice(0, 77)}...` : predicate}\`, which only checks ` +
              'that the caller is signed in, not who they are. PostgreSQL ORs permissive policies for ' +
              'the same command' +
              (scopedNames.length
                ? `, so the \`${ownerColumn}\` scoping in ${scopedNames.map((n) => `\`${n}\``).join(', ')} never narrows anything`
                : '') +
              `: any authenticated user can ${commands.map((c) => VERBS[c]).join(' / ')} every other user’s rows.`,
            fix:
              `Scope \`${g.name}\` to the caller — USING (${ownerColumn} = (SELECT auth.uid()))` +
              (commands.includes('INSERT') || commands.includes('UPDATE')
                ? ` WITH CHECK (${ownerColumn} = (SELECT auth.uid()))`
                : '') +
              ' — or drop it if the scoped policies already cover what it was for.',
            file: g.file,
            line: g.line,
            cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { table: table.name, ownerColumn, policy: g.name, commands, scopedBy: scopedNames },
          });
        }
      }

      if (ownerColumn && !referencesAuth && reachesUsers) {
        findings.push({
          id: 'CTS014',
          severity: 'high',
          title: 'Per-user table with no tenant isolation in its policies',
          detail:
            `Table \`${table.name}\` has an ownership column (\`${ownerColumn}\`), but none of the ` +
            `${tablePolicies.length} polic${tablePolicies.length === 1 ? 'y' : 'ies'} defined on it compare ` +
            'that column against `auth.uid()`. Every authenticated user therefore sees every other ' +
            'user’s rows.',
          fix:
            `CREATE POLICY "own rows" ON "${table.name.split('.')[1]}"\n` +
            `  FOR ALL TO authenticated\n` +
            `  USING (${ownerColumn} = (SELECT auth.uid()))\n` +
            `  WITH CHECK (${ownerColumn} = (SELECT auth.uid()));`,
          file: tablePolicies[0]!.file,
          line: tablePolicies[0]!.line,
          cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
          owasp: 'A01:2025 - Broken Access Control',
          meta: { table: table.name, ownerColumn },
        });
      }

      for (const p of tablePolicies) {
        const publicFacing = p.roles.some((r) => PUBLIC_ROLES.has(r));
        if (!publicFacing) continue;
        const anonFacing = p.roles.some((r) => UNAUTHENTICATED_ROLES.has(r));
        const isWrite = p.command !== 'SELECT';
        // An always-true RESTRICTIVE policy is a no-op filter, not a grant.
        const permissive = p.permissive && (isAlwaysTrue(p.using) || isAlwaysTrue(p.withCheck));

        if (permissive && isWrite) {
          findings.push({
            id: 'CTS012',
            severity: 'critical',
            title: 'Policy allows unrestricted writes',
            detail:
              `Policy \`${p.name}\` on \`${p.table}\` grants \`${p.command}\` to ` +
              `${p.roles.join(', ')} with an always-true predicate. ` +
              (anonFacing
                ? 'Anyone with the public anon key can insert, overwrite or delete arbitrary rows.'
                : 'Any signed-up user can overwrite or delete every other user’s rows.'),
            fix:
              'Replace `USING (true)` / `WITH CHECK (true)` with a predicate that ties the row to the ' +
              'caller, e.g. `user_id = (SELECT auth.uid())`.',
            file: p.file,
            line: p.line,
            cwe: 'CWE-863: Incorrect Authorization',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { table: p.table, policy: p.name, command: p.command, roles: p.roles },
          });
        } else if (permissive && anonFacing && sensitive.length > 0) {
          findings.push({
            id: 'CTS013',
            severity: 'high',
            title: 'Policy exposes sensitive columns to anonymous readers',
            detail:
              `Policy \`${p.name}\` grants unauthenticated SELECT over \`${p.table}\`, which holds ` +
              `${sensitive.slice(0, 4).map((c) => `\`${c}\``).join(', ')}` +
              `${sensitive.length > 4 ? ` and ${sensitive.length - 4} more sensitive column(s)` : ''}. ` +
              'The whole table is downloadable with the anon key.',
            fix:
              'Restrict the policy to `authenticated` and scope it to the caller, or expose only the ' +
              'non-sensitive columns through a `security_invoker` view.',
            file: p.file,
            line: p.line,
            cwe: 'CWE-200: Exposure of Sensitive Information',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { table: p.table, policy: p.name, columns: sensitive },
          });
        }

        if (/user_metadata/i.test(`${p.using ?? ''} ${p.withCheck ?? ''}`)) {
          findings.push({
            id: 'CTS018',
            severity: 'critical',
            title: 'Policy trusts user-editable JWT metadata',
            detail:
              `Policy \`${p.name}\` on \`${p.table}\` reads \`user_metadata\` from the JWT. That claim is ` +
              'writable by the user themselves through the auth API, so anyone can set the field the ' +
              'policy checks and grant themselves access.',
            fix:
              'Move the attribute into `app_metadata` (server-writable only) or into a table the user ' +
              'cannot update, and have the policy read it from there.',
            file: p.file,
            line: p.line,
            cwe: 'CWE-807: Reliance on Untrusted Inputs in a Security Decision',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { table: p.table, policy: p.name },
          });
        }
      }
    }

    // Permissive policies are OR-ed together, so a second broad policy silently
    // widens whatever the first one narrowed (splinter 0006).
    const overlap = new Map<string, Policy[]>();
    for (const p of policies) {
      if (!p.permissive) continue;
      const commands = p.command === 'ALL' ? ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] : [p.command];
      for (const cmd of commands) {
        for (const role of p.roles) {
          const key = `${p.table}|${cmd}|${role}`;
          const list = overlap.get(key) ?? [];
          list.push(p);
          overlap.set(key, list);
        }
      }
    }
    const alreadyReported = new Set<string>();
    for (const [key, group] of overlap) {
      if (group.length < 2) continue;
      const [table, cmd, role] = key.split('|');
      const names = [...new Set(group.map((p) => p.name))];
      if (names.length < 2) continue;
      // CTS014 already reported this exact overlap — a gate OR'd onto the
      // scoped policies it defeats — with the specific consequence. The same
      // root cause and the same fix; a second, vaguer finding adds nothing.
      if (
        names.some((n) => gateLeaks.has(`${table}|${cmd}|${n}`)) &&
        names.every((n) => gateLeaks.has(`${table}|${cmd}|${n}`) || defeated.has(`${table}|${cmd}|${n}`))
      ) continue;
      const dedupe = `${table}|${cmd}|${role}|${names.join(',')}`;
      if (alreadyReported.has(dedupe)) continue;
      alreadyReported.add(dedupe);
      findings.push({
        id: 'CTS050',
        severity: 'medium',
        title: 'Overlapping permissive policies widen access',
        detail:
          `\`${table}\` has ${names.length} permissive policies covering \`${cmd}\` for \`${role}\` ` +
          `(${names.map((n) => `\`${n}\``).join(', ')}). PostgreSQL ORs permissive policies together, ` +
          'so a row is visible if *any* of them allows it — adding a policy can only ever widen access, ' +
          'never narrow it. A carefully scoped policy is defeated by a broad one sitting beside it.',
        fix:
          'Merge them into a single policy whose predicate expresses the whole rule, or make the ' +
          'narrowing one `AS RESTRICTIVE` so it is AND-ed instead of OR-ed.',
        file: group[0]!.file,
        line: group[0]!.line,
        cwe: 'CWE-863: Incorrect Authorization',
        owasp: 'A01:2025 - Broken Access Control',
        meta: { table, command: cmd, role, policies: names },
      });
    }

    // Supabase Storage listing: a broad SELECT policy on storage.objects lets a
    // caller enumerate every file in every bucket, public or not (splinter 0025).
    for (const p of policies) {
      if (p.table !== 'storage.objects' || !p.permissive) continue;
      if (p.command !== 'SELECT' && p.command !== 'ALL') continue;
      if (!p.roles.some((r) => UNAUTHENTICATED_ROLES.has(r))) continue;
      const predicate = `${p.using ?? ''} ${p.withCheck ?? ''}`;
      const constrained = /bucket_id|owner|auth\.uid\(\)|name\s*(like|~)/i.test(predicate);
      if (constrained && !isAlwaysTrue(p.using)) continue;
      findings.push({
        id: 'CTS051',
        severity: 'high',
        title: 'Storage policy allows listing every object in every bucket',
        detail:
          `Policy \`${p.name}\` grants unauthenticated SELECT on \`storage.objects\` without ` +
          'constraining `bucket_id` or `owner`. Reading an object needs only its URL, but listing is ' +
          'what turns "unguessable filename" into "here is the index" — a caller can enumerate every ' +
          'upload in the project, including buckets that are not public.' +
          (publicBuckets.length
            ? ` ${publicBuckets.length} public bucket(s) are also declared (${publicBuckets.map((b) => `\`${b.id}\``).join(', ')}).`
            : ''),
        fix:
          "Scope the policy to one bucket and to the caller, e.g. `bucket_id = 'avatars' AND owner = " +
          '(select auth.uid())`, and keep private buckets out of any `anon` policy entirely.',
        file: p.file,
        line: p.line,
        cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
        owasp: 'A01:2025 - Broken Access Control',
        meta: { policy: p.name, publicBuckets: publicBuckets.map((b) => b.id) },
      });
    }

    return {
      findings,
      publicTables: [...tables.values()].filter((t) => t.createdInPublic).length,
      policies: policies.length,
    };
}

export const _internals = { parseColumns };
