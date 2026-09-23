import {
  read, rel, isSql, snippetAt,
  splitStatements, normaliseTable, isAlwaysTrue, QUALIFIED_NAME,
  Suppressions, emptyResult,
} from '../internal.js';
// Not re-exported through internal.ts; sql.ts has no imports of its own, so
// reaching it directly cannot introduce an initialisation-order cycle.
import { readBalanced } from '../utils/sql.js';
import type { Finding, ProjectContext, ScanResult, Scanner, Severity } from '../internal.js';

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
    if (!ctx.files.some(isSql)) return false;
    // Row Level Security is a PostgreSQL feature that Supabase builds on. This
    // scanner must not fire on SQLite / Cloudflare D1 / Prisma-sqlite schemas,
    // which have no RLS concept at all — doing so turns every CREATE TABLE into
    // a false "RLS disabled" critical. Require a genuine Postgres/Supabase
    // signal: the dependency set, a supabase/ directory, or RLS/auth idioms in
    // the SQL itself.
    if (ctx.framework.supabase) return true;
    for (const file of ctx.files) {
      if (!isSql(file)) continue;
      const src = read(file);
      if (src && /\brow\s+level\s+security\b|\bauth\.(uid|jwt|role)\s*\(|\bto\s+(anon|authenticated)\b|\bcreate\s+policy\b/i.test(src)) {
        return true;
      }
    }
    return false;
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    const tables = new Map<string, Table>();
    const policies: Policy[] = [];
    const definerFunctions = new Set<string>();
    const publicBuckets: { id: string; file: string; line: number }[] = [];
    const findings: Finding[] = [];
    const suppressors = new Map<string, Suppressions>();
    const sources = new Map<string, string>();

    const sqlFiles = ctx.files.filter(isSql).sort();

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
      // Tenant isolation means comparing a row to *who* the caller is: auth.uid(),
      // a JWT claim, or the request claims. `auth.role() = 'authenticated'` only
      // says the caller is signed in — every signed-in user then sees every
      // row, which is exactly what CTS014 is about — so it does not count.
      const referencesAuth = tablePolicies.some((p) =>
        /auth\.uid\(\)|auth\.jwt\(\)|current_setting\s*\(/i.test(
          `${p.using ?? ''} ${p.withCheck ?? ''}`,
        ),
      );
      // A policy that only admits the service role reaches no end user (and the
      // service role bypasses RLS anyway), so it cannot leak rows across users.
      const reachesUsers = grantingPolicies.some((p) => !serviceRoleOnly(p));

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

    // Apply inline suppressions now that every finding has a location.
    for (const f of findings) {
      const sup = f.file ? suppressors.get(f.file) : undefined;
      if (sup && f.line && sup.suppressed(f.line, f.id)) continue;
      const src = f.file ? sources.get(f.file) : undefined;
      if (src && f.line) f.snippet = snippetAt(src, f.line);
      result.findings.push(f);
    }

    const publicTables = [...tables.values()].filter((t) => t.createdInPublic);
    if (publicTables.length > 0) {
      const unprotected = result.findings.filter((f) => f.id === 'CTS010').length;
      result.checks.push({
        label: `Row Level Security (${publicTables.length} public table${publicTables.length === 1 ? '' : 's'}, ${policies.length} polic${policies.length === 1 ? 'y' : 'ies'})`,
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

export const _internals = { parseColumns };
