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

/** Supabase's `auth.getSession()`: decodes the cookie, verifies nothing server-side. */
export const SUPABASE_GET_SESSION = /(^|\.)auth\.getSession$/;

/** Methods on a promise: `getUser().then(...)` is still the auth call, not an accessor. */
const PROMISE_METHODS = new Set(['then', 'catch', 'finally']);

/**
 * A call whose result is only the receiver of another method call is an accessor for a
 * client, not a check: `admin.auth().deleteUser(uid)` (firebase-admin) and
 * `(await clerkClient()).users.deleteUser(id)` hand back an admin SDK, and what the code
 * then does with it — delete a user — is the opposite of authenticating the caller. The
 * outer call is judged on its own name. A property read (`auth().userId`) is not this.
 */
export function isAccessorOnly(receiverOfMethod: string | null): boolean {
  return receiverOfMethod !== null && !PROMISE_METHODS.has(receiverOfMethod);
}

/**
 * `getUser` on an admin SDK looks a user up by an id it is handed; it says nothing about
 * who is calling. `clerkClient.users.getUser(id)`, `admin.auth().getUser(uid)`,
 * `getAuth().getUser(uid)`: a receiver that is itself a call, or one named `users` /
 * `admin`. Supabase's `supabase.auth.getUser()` has a plain `auth` member as receiver and
 * is the session check this list exists for.
 */
export function isUserLookup(call: any): boolean {
  const callee = call?.callee;
  if (!callee || (callee.type !== 'MemberExpression' && callee.type !== 'OptionalMemberExpression')) return false;
  if (calleeTail(callee) !== 'getUser') return false;
  let obj = callee.object;
  while (obj && (obj.type === 'AwaitExpression' || obj.type === 'TSNonNullExpression')) obj = obj.argument ?? obj.expression;
  if (!obj) return false;
  if (obj.type === 'CallExpression' || obj.type === 'OptionalCallExpression') return true;
  const receiver =
    obj.type === 'Identifier'
      ? obj.name
      : obj.type === 'MemberExpression' || obj.type === 'OptionalMemberExpression'
        ? calleeTail(obj)
        : '';
  return receiver === 'users' || receiver === 'admin';
}

// Recorded alongside a function's callee names. A helper that reads a credential
// header AND a secret from the environment authenticates its caller by shared
// secret — `authenticateApiRequest(request)` — however it is named, and a route that
// calls it is authenticated. Only the pair counts: reading a header alone proves
// nothing, and neither does touching an env var.
const MARK_CREDENTIAL_HEADER = '\u0000credential-header';
const MARK_SECRET_ENV = '\u0000secret-env';
/** The helper calls Supabase's `auth.getSession()`, which proves nothing on the server. */
const MARK_GET_SESSION = '\u0000supabase-get-session';
/** Prefix for a callee's bare tail, recorded beside its full dotted name. */
const TAIL = '\u0001';

/** How many import hops to follow before giving up. */
const MAX_DEPTH = 3;

/** Rounds of the same-file fixed point — helpers calling helpers calling helpers. */
const MAX_ROUNDS = 4;

export interface ModuleAuth {
  /** Names that stand for "the caller was authenticated" in this file. */
  credited: ReadonlySet<string>;
  /**
   * First-party helpers whose only session check is Supabase's `auth.getSession()`.
   * Called from an action they must not count as auth, whatever they are named —
   * `getSession()` or `getCurrentUser()` match the generic auth vocabulary.
   */
  sessionOnly: ReadonlySet<string>;
}

const EMPTY_AUTH: ModuleAuth = { credited: new Set(), sessionOnly: new Set() };

export interface AuthHelperOptions {
  /** Callee names that prove the caller's identity was checked. */
  authCalls: string[];
  /** Higher-order wrappers that apply auth for the function they wrap. */
  authWrappers: string[];
  index: ModuleIndex;
  /** Per-scan memo, keyed by absolute file path. */
  cache: Map<string, ModuleAuth>;
}

function matchesAny(name: string, list: string[]): boolean {
  for (const candidate of list) {
    if (name === candidate || name.endsWith('.' + candidate)) return true;
  }
  return false;
}

function unwrap(node: any): any {
  let cur = node;
  while (cur && (cur.type === 'AwaitExpression' || cur.type === 'TSNonNullExpression' || cur.type === 'ParenthesizedExpression')) {
    cur = cur.argument ?? cur.expression;
  }
  return cur;
}

/** Every callee name (dotted and bare) reachable inside one function body. */
function callNamesIn(node: any, out: Set<string>, depth = 0, receiverOf: WeakMap<object, string> = new WeakMap()): void {
  if (!node || typeof node !== 'object' || depth > 400) return;
  if (Array.isArray(node)) {
    for (const child of node) callNamesIn(child, out, depth + 1, receiverOf);
    return;
  }
  if (typeof node.type !== 'string') return;
  if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression') {
    const callee = node.callee;
    // `x().method()`: remember that the inner call's result is only a receiver.
    if (callee && (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression')) {
      const inner = unwrap(callee.object);
      if (inner && (inner.type === 'CallExpression' || inner.type === 'OptionalCallExpression')) {
        receiverOf.set(inner, callee.property?.name ?? '*');
      }
    }
    const full = calleeName(callee);
    if (full) {
      if (SUPABASE_GET_SESSION.test(full)) {
        out.add(MARK_GET_SESSION);
      } else if (!isAccessorOnly(receiverOf.get(node) ?? null) && !isUserLookup(node)) {
        out.add(full);
        // The bare tail is kept, marked, only so `x.requireUser()` still meets a
        // `requireUser` credited here; it is not matched against the auth vocabulary,
        // which the full name already is (suffix match).
        const tail = calleeTail(callee);
        if (tail !== full) out.add(TAIL + tail);
      }
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
    if (value && typeof value === 'object') callNamesIn(value, out, depth + 1, receiverOf);
  }
}

interface ModuleShape {
  /** Top-level functions, exported or not, with the calls in each. */
  functions: Map<string, Set<string>>;
  /** Exported name -> local name: `export { a as b }`, `export default a`. */
  aliases: Map<string, string>;
}

/**
 * Top-level `function f()` / `const f = () => {}`, exported or not; `export default
 * function` under `default` as well as its own name; and local re-export aliases.
 */
function collectFunctions(ast: File): ModuleShape {
  const functions = new Map<string, Set<string>>();
  const aliases = new Map<string, string>();

  const addFunction = (name: string | undefined, body: any) => {
    if (!name || !body) return;
    const calls = new Set<string>();
    callNamesIn(body, calls);
    functions.set(name, calls);
  };

  const fromDeclaration = (decl: any, isDefault = false) => {
    if (!decl) return;
    if (decl.type === 'FunctionDeclaration' || decl.type === 'FunctionExpression' || decl.type === 'ArrowFunctionExpression') {
      addFunction(decl.id?.name, decl.body);
      // `export default function requireAdmin()` is imported as `import requireAdmin
      // from './guard'`, which asks for `default`.
      if (isDefault) addFunction('default', decl.body);
      return;
    }
    if (isDefault && decl.type === 'Identifier') {
      aliases.set('default', decl.name);
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

  for (const stmt of ast.program.body as any[]) {
    if (stmt.type === 'ExportNamedDeclaration') {
      fromDeclaration(stmt.declaration);
      // `export { requireUser as guard }` with no `from`: an alias for a local function.
      if (!stmt.source) {
        for (const s of stmt.specifiers ?? []) {
          if (s.type !== 'ExportSpecifier') continue;
          const local = s.local?.name;
          const exported = s.exported?.name ?? s.exported?.value;
          if (local && exported && local !== exported) aliases.set(exported, local);
        }
      }
    } else if (stmt.type === 'ExportDefaultDeclaration') {
      fromDeclaration(stmt.declaration, true);
    } else {
      fromDeclaration(stmt);
    }
  }
  return { functions, aliases };
}

/** Re-exports and imports that point at another first-party module. */
const FOLLOWS_MODULES = /\b(import|export)\b[^;]*\bfrom\b/;

/**
 * Names that mean "authenticated" when used inside `file`, and names of helpers that only
 * call Supabase's `getSession()`. Includes helpers defined in the file, symbols imported
 * from first-party modules (named, default and namespace imports), and names a module
 * re-exports (`export { x } from`, `export * from`).
 */
export function authHelpersFor(
  file: string,
  opts: AuthHelperOptions,
  preparsed?: File | null,
  depth = 0,
  stack: Set<string> = new Set(),
): ModuleAuth {
  const memo = opts.cache.get(file);
  if (memo) return memo;
  // A cycle (a imports b imports a) resolves to nothing rather than looping.
  if (stack.has(file) || depth > MAX_DEPTH) return EMPTY_AUTH;

  let ast = preparsed ?? null;
  if (!ast) {
    const source = read(file);
    if (source === null) return EMPTY_AUTH;
    // Cheap bail-out: a file that mentions none of the auth vocabulary, and imports
    // or re-exports nothing it could be passing an auth helper through, cannot define
    // one — and most files in a repo are that file. A barrel (`export * from './auth'`)
    // mentions no auth call itself, which is why the second half is there.
    if (
      !opts.authCalls.some((c) => source.includes(c.split('.').pop()!)) &&
      !/authorization|x-api-key|x-apikey|api-key|x-[a-z0-9-]+-(secret|token)|x-access-code|x-passcode|x-admin-key/i.test(source) &&
      !FOLLOWS_MODULES.test(source)
    ) {
      opts.cache.set(file, EMPTY_AUTH);
      return EMPTY_AUTH;
    }
    ast = parseSource(source, file);
    if (!ast) {
      opts.cache.set(file, EMPTY_AUTH);
      return EMPTY_AUTH;
    }
  }

  stack.add(file);
  const credited = new Set<string>();
  const sessionOnly = new Set<string>();
  const follow = (spec: unknown): ModuleAuth | null => {
    const target = typeof spec === 'string' ? opts.index.resolve(spec, file) : null;
    if (!target) return null;
    const got = authHelpersFor(target, opts, null, depth + 1, stack);
    return got.credited.size === 0 && got.sessionOnly.size === 0 ? null : got;
  };
  const exportedNames = (set: ReadonlySet<string>) => [...set].filter((n) => !n.includes('.'));

  for (const stmt of ast.program.body as any[]) {
    if (stmt.type === 'ImportDeclaration') {
      const exported = follow(stmt.source?.value);
      if (!exported) continue;
      for (const s of stmt.specifiers ?? []) {
        const local = s.local?.name;
        if (!local) continue;
        if (s.type === 'ImportNamespaceSpecifier') {
          // `import * as guard from './guard'` is called as `guard.requireUser()`.
          for (const n of exportedNames(exported.credited)) credited.add(`${local}.${n}`);
          for (const n of exportedNames(exported.sessionOnly)) sessionOnly.add(`${local}.${n}`);
          continue;
        }
        const imported =
          s.type === 'ImportSpecifier'
            ? (s.imported?.name ?? s.imported?.value)
            : s.type === 'ImportDefaultSpecifier'
              ? 'default'
              : null;
        if (!imported) continue;
        if (exported.credited.has(imported)) credited.add(local);
        else if (exported.sessionOnly.has(imported)) sessionOnly.add(local);
      }
    } else if (stmt.type === 'ExportAllDeclaration') {
      // `export * from './auth'` — a barrel. `default` is never re-exported this way.
      const exported = follow(stmt.source?.value);
      if (!exported) continue;
      for (const n of exportedNames(exported.credited)) if (n !== 'default') credited.add(n);
      for (const n of exportedNames(exported.sessionOnly)) if (n !== 'default') sessionOnly.add(n);
    } else if (stmt.type === 'ExportNamedDeclaration' && stmt.source) {
      // `export { requireUser } from './auth'`, `export { default as requireUser } from`.
      const exported = follow(stmt.source.value);
      if (!exported) continue;
      for (const s of stmt.specifiers ?? []) {
        const from = s.type === 'ExportNamespaceSpecifier' ? null : (s.local?.name ?? s.local?.value);
        const as = s.exported?.name ?? s.exported?.value;
        if (!from || !as) continue;
        if (exported.credited.has(from)) credited.add(as);
        else if (exported.sessionOnly.has(from)) sessionOnly.add(as);
      }
    }
  }

  const { functions, aliases } = collectFunctions(ast);

  /** A call that proves identity by itself, judged by name — not a session-only helper. */
  const provesByName = (call: string): boolean => {
    if (call.startsWith(TAIL)) return credited.has(call.slice(TAIL.length));
    if (sessionOnly.has(call)) return false;
    return matchesAny(call, opts.authCalls) || matchesAny(call, opts.authWrappers) || credited.has(call);
  };
  const credentialPair = (calls: Set<string>) => calls.has(MARK_CREDENTIAL_HEADER) && calls.has(MARK_SECRET_ENV);

  // First, which local helpers only ever read a session through Supabase's
  // `getSession()`? Settled before anything is credited, so a helper named
  // `getSession` — which the generic vocabulary would accept by name — does not
  // credit its callers before its body has been looked at.
  for (let changed = true; changed; ) {
    changed = false;
    for (const [name, calls] of functions) {
      if (sessionOnly.has(name) || credentialPair(calls)) continue;
      const readsSession = calls.has(MARK_GET_SESSION) || [...calls].some((c) => sessionOnly.has(c));
      if (!readsSession) continue;
      const other = [...calls].some((c) => !c.startsWith('\u0000') && provesByName(c) && !functions.has(c));
      const otherLocal = [...calls].some((c) => functions.has(c) && !sessionOnly.has(c) && c !== name && provesByName(c));
      if (other || otherLocal) continue;
      sessionOnly.add(name);
      changed = true;
    }
  }

  for (let round = 0; round < MAX_ROUNDS; round++) {
    let changed = false;
    for (const [name, calls] of functions) {
      if (credited.has(name) || sessionOnly.has(name)) continue;
      if (credentialPair(calls)) {
        credited.add(name);
        changed = true;
        continue;
      }
      for (const call of calls) {
        if (provesByName(call)) {
          credited.add(name);
          changed = true;
          break;
        }
      }
    }
    if (!changed) break;
  }
  for (const [exported, local] of aliases) {
    if (credited.has(local)) credited.add(exported);
    else if (sessionOnly.has(local)) sessionOnly.add(exported);
  }

  stack.delete(file);
  const result: ModuleAuth = { credited, sessionOnly };
  opts.cache.set(file, result);
  return result;
}

/** Names that mean "authenticated" when used inside `file`. See authHelpersFor. */
export function authNamesFor(
  file: string,
  opts: AuthHelperOptions,
  preparsed?: File | null,
): ReadonlySet<string> {
  return authHelpersFor(file, opts, preparsed).credited;
}
