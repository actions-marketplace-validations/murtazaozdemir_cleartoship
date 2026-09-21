import { read, parseSource, calleeName, calleeTail } from '../internal.js';
import type { ModuleIndex } from '../internal.js';
import type { File } from '@babel/types';

/**
 * Recognising an authenticated caller only when the check is written inline
 * inside the action is wrong for the way real apps are built: session
 * verification is factored into `lib/auth.ts` (or a framework helper such as
 * Shopify's `handleSessionToken`) and every action calls that. Reading only the
 * action body then reports each of them as unauthenticated — four false
 * criticals on one dogfooded Shopify app, which is exactly the kind of finding
 * that teaches people to ignore the tool.
 *
 * This module answers the narrower question the scanner actually needs: which
 * *names*, as spelled in this file, stand for "the caller was authenticated"?
 * A name qualifies when the function behind it — defined here, or exported by a
 * first-party module this file imports — itself performs a recognised auth call,
 * directly or through another such helper. Third-party packages are never
 * followed, so a call into `node_modules` still proves nothing on its own.
 */

/**
 * Request headers that carry a credential. A handler that reads one and compares it
 * against a server-side secret is how a cron or machine-to-machine endpoint
 * authenticates — there is no session to look up.
 */
export const CREDENTIAL_HEADERS =
  /^(authorization|proxy-authorization|x-api-key|x-apikey|api-key|x-admin-key|x-access-code|x-passcode|(?!x-[cx]srf)x-[a-z0-9-]+-(secret|token))$/i;

/**
 * `process.env.SOMETHING_SECRET` and friends — the other half of that check. Also the
 * typed wrapper most apps put in front of it (`env.CRON_SECRET`, from `@/lib/env` or
 * t3-env), which reads the same variable.
 */
export const SECRET_ENV = /^(?:process\.env|env)\.[A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|PASS)[A-Z0-9_]*$/;

// Recorded alongside a function's callee names. A helper that reads a credential
// header AND a secret from the environment authenticates its caller by shared
// secret — `authenticateApiRequest(request)` — however it is named, and a route that
// calls it is authenticated. Only the pair counts: reading a header alone proves
// nothing, and neither does touching an env var.
const MARK_CREDENTIAL_HEADER = '\u0000credential-header';
const MARK_SECRET_ENV = '\u0000secret-env';

/** How many import hops to follow before giving up. */
const MAX_DEPTH = 3;

/** Rounds of the same-file fixed point — helpers calling helpers calling helpers. */
const MAX_ROUNDS = 4;

const EMPTY: ReadonlySet<string> = new Set();

export interface AuthHelperOptions {
  /** Callee names that prove the caller's identity was checked. */
  authCalls: string[];
  /** Higher-order wrappers that apply auth for the function they wrap. */
  authWrappers: string[];
  index: ModuleIndex;
  /** Per-scan memo, keyed by absolute file path. */
  cache: Map<string, ReadonlySet<string>>;
}

function matchesAny(name: string, list: string[]): boolean {
  for (const candidate of list) {
    if (name === candidate || name.endsWith('.' + candidate)) return true;
  }
  return false;
}

/** Every callee name (dotted and bare) reachable inside one function body. */
function callNamesIn(node: any, out: Set<string>, depth = 0): void {
  if (!node || typeof node !== 'object' || depth > 400) return;
  if (Array.isArray(node)) {
    for (const child of node) callNamesIn(child, out, depth + 1);
    return;
  }
  if (typeof node.type !== 'string') return;
  if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression') {
    const full = calleeName(node.callee);
    if (full) {
      out.add(full);
      out.add(calleeTail(node.callee));
      if (/headers\.get$/.test(full)) {
        const arg = node.arguments?.[0];
        if (arg?.type === 'StringLiteral' && CREDENTIAL_HEADERS.test(arg.value)) {
          out.add(MARK_CREDENTIAL_HEADER);
        }
      }
    }
  }
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    const member = calleeName(node);
    if (member && SECRET_ENV.test(member)) out.add(MARK_SECRET_ENV);
  }
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'leadingComments' || key === 'trailingComments') continue;
    const value = (node as any)[key];
    if (value && typeof value === 'object') callNamesIn(value, out, depth + 1);
  }
}

/** Top-level `function f()` / `const f = () => {}`, exported or not. */
function collectFunctions(ast: File): Map<string, Set<string>> {
  const found = new Map<string, Set<string>>();

  const addFunction = (name: string | undefined, body: any) => {
    if (!name || !body) return;
    const calls = new Set<string>();
    callNamesIn(body, calls);
    found.set(name, calls);
  };

  const fromDeclaration = (decl: any) => {
    if (!decl) return;
    if (decl.type === 'FunctionDeclaration') {
      addFunction(decl.id?.name, decl.body);
      return;
    }
    if (decl.type !== 'VariableDeclaration') return;
    for (const d of decl.declarations ?? []) {
      if (d?.id?.type !== 'Identifier') continue;
      const init = d.init;
      if (init?.type === 'ArrowFunctionExpression' || init?.type === 'FunctionExpression') {
        addFunction(d.id.name, init.body);
      }
    }
  };

  for (const stmt of ast.program.body) {
    if (stmt.type === 'ExportNamedDeclaration') fromDeclaration((stmt as any).declaration);
    else fromDeclaration(stmt);
  }
  return found;
}

/**
 * Names that mean "authenticated" when used inside `file`. Includes helpers
 * defined in the file and symbols imported from first-party modules.
 */
export function authNamesFor(
  file: string,
  opts: AuthHelperOptions,
  preparsed?: File | null,
  depth = 0,
  stack: Set<string> = new Set(),
): ReadonlySet<string> {
  const memo = opts.cache.get(file);
  if (memo) return memo;
  // A cycle (a imports b imports a) resolves to nothing rather than looping.
  if (stack.has(file) || depth > MAX_DEPTH) return EMPTY;

  let ast = preparsed ?? null;
  if (!ast) {
    const source = read(file);
    if (source === null) return EMPTY;
    // Cheap bail-out: a file that mentions none of the auth vocabulary cannot
    // define an auth helper, and most files in a repo are that file.
    if (
      !opts.authCalls.some((c) => source.includes(c.split('.').pop()!)) &&
      !/authorization|x-api-key|x-apikey|api-key|x-[a-z0-9-]+-(secret|token)|x-access-code|x-passcode|x-admin-key/i.test(source)
    ) {
      opts.cache.set(file, EMPTY);
      return EMPTY;
    }
    ast = parseSource(source, file);
    if (!ast) {
      opts.cache.set(file, EMPTY);
      return EMPTY;
    }
  }

  stack.add(file);
  const credited = new Set<string>();

  for (const stmt of ast.program.body) {
    if (stmt.type !== 'ImportDeclaration') continue;
    const spec = (stmt.source as any)?.value;
    const target = typeof spec === 'string' ? opts.index.resolve(spec, file) : null;
    if (!target) continue;
    const exported = authNamesFor(target, opts, null, depth + 1, stack);
    if (exported.size === 0) continue;
    for (const s of stmt.specifiers ?? []) {
      const local = (s as any).local?.name;
      if (!local) continue;
      const imported =
        s.type === 'ImportSpecifier'
          ? ((s.imported as any).name ?? (s.imported as any).value)
          : s.type === 'ImportDefaultSpecifier'
            ? 'default'
            : null;
      if (imported && exported.has(imported)) credited.add(local);
    }
  }

  const functions = collectFunctions(ast);
  for (let round = 0; round < MAX_ROUNDS; round++) {
    let changed = false;
    for (const [name, calls] of functions) {
      if (credited.has(name)) continue;
      if (calls.has(MARK_CREDENTIAL_HEADER) && calls.has(MARK_SECRET_ENV)) {
        credited.add(name);
        changed = true;
        continue;
      }
      for (const call of calls) {
        if (
          matchesAny(call, opts.authCalls) ||
          matchesAny(call, opts.authWrappers) ||
          credited.has(call)
        ) {
          credited.add(name);
          changed = true;
          break;
        }
      }
    }
    if (!changed) break;
  }

  stack.delete(file);
  const result: ReadonlySet<string> = credited;
  opts.cache.set(file, result);
  return result;
}
