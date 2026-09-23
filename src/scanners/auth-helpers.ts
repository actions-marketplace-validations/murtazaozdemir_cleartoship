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

/*
 * ---------------------------------------------------------------- auth wrappers
 *
 * `export default withSomething(handler)` used to count as authenticated whenever the
 * wrapper's NAME looked like auth — `/auth|protect|guard|session|require|.../`. That
 * credited iron-session's `withIronSessionApiRoute`, which attaches a session object to
 * the request and hands every caller through, signed in or not: a handler under it that
 * writes without looking at `req.session.user` is an unauthenticated write, reported as
 * authenticated. A wrapper is now judged by what it does:
 *
 * - First-party (defined in this file, or imported from one the module index finds):
 *   the definition is read. It is credited only when it provably turns an
 *   unauthenticated caller away before invoking the handler — an auth call plus a guard
 *   that exits, or a `require*()`-style call that throws. One that resolves a session
 *   and passes it on without rejecting "attaches": the handler is then analysed with
 *   that session as an auth result, so `if (!session) return 401` inside it counts.
 * - Third-party: a short allowlist of wrappers documented to REQUIRE a session, and a
 *   list of known session-attaching ones that do not. Anything else from a package keeps
 *   the old name-based credit — a flood of criticals on wrappers nobody here can read
 *   would be worse — but is recorded as `name-only` so the scan says it guessed.
 */

/** What a wrapper does for the function it wraps. */
export type WrapperKind =
  /** Provably rejects an unauthenticated caller before the handler runs. */
  | 'requires'
  /** Resolves a session and hands it to the handler, but lets every caller through. */
  | 'attaches'
  /** Credited on its name alone: its source was not (or could not be) read. */
  | 'name-only'
  /** Not an auth wrapper. */
  | 'none';

/** Where an attaching wrapper puts the session, as seen from the wrapped handler. */
export interface SessionShape {
  /** Handler parameter positions that receive the session (or an object carrying it). */
  positions: number[];
  /** Properties set on the handler's parameters: `req.session`, `req.auth`, `req.user`. */
  members: string[];
  /** A next-safe-action / tRPC style `ctx` carries it. */
  ctx: boolean;
}

export interface WrapperVerdict {
  kind: WrapperKind;
  /** The wrapper as written at the call site. */
  wrapper: string;
  /** Package it was imported from, when third-party. */
  from?: string;
  session?: SessionShape;
}

/** Predicates owned by the scanner that calls this, passed in so the two agree. */
export interface WrapperPredicates {
  /** A call whose result speaks to who the caller is (handed the request, reads a cookie...). */
  isCredentialSource(node: any): boolean;
  /** `return ...{ status: 401 }`, `throw new Error('Unauthorized')`, `unauthorized()`. */
  isUnauthorisedExit(node: any): boolean;
  /** A statement that leaves the function: return, throw, `redirect()`. */
  exits(stmt: any): boolean;
}

export interface WrapperOptions extends AuthHelperOptions, WrapperPredicates {
  /** Per-scan memo, keyed by `file \0 wrapper`. */
  wrapperCache: Map<string, WrapperVerdict>;
  /** Per-scan memo of parsed first-party modules. */
  astCache: Map<string, File | null>;
}

/**
 * Third-party wrappers documented to reject a request with no session — a 401 for an
 * API route, a redirect to login for a page — before the wrapped function runs.
 */
const REQUIRING_WRAPPERS: Record<string, readonly string[]> = {
  '@auth0/nextjs-auth0': ['withApiAuthRequired', 'withPageAuthRequired', 'withMiddlewareAuthRequired'],
  '@auth0/nextjs-auth0/edge': ['withApiAuthRequired', 'withPageAuthRequired', 'withMiddlewareAuthRequired'],
  '@supabase/auth-helpers-nextjs': ['withApiAuth', 'withPageAuth', 'withMiddlewareAuth'],
  'next-auth/middleware': ['withAuth'],
  '@kinde-oss/kinde-auth-nextjs/middleware': ['withAuth'],
  '@kinde-oss/kinde-auth-nextjs/server': ['withAuth'],
};

/**
 * Third-party wrappers that attach a session and let every caller through: the handler
 * must check it. iron-session's (`withIronSessionApiRoute`, `withIronSessionSsr`) and
 * next-iron-session's put it on `req.session`.
 */
const ATTACHING_WRAPPERS: Record<string, { names: readonly string[]; members: readonly string[] }> = {
  'iron-session/next': { names: ['withIronSessionApiRoute', 'withIronSessionSsr'], members: ['session'] },
  'iron-session': { names: ['withIronSessionApiRoute', 'withIronSessionSsr'], members: ['session'] },
  'next-iron-session': { names: ['withIronSession', 'withSession', 'ironSession'], members: ['session'] },
};

/**
 * Third-party builders that authenticate nothing on their own. `createSafeActionClient()`
 * and zsa's `createServerAction()` are the base a project adds its own auth middleware to;
 * crediting them by name (they were in the old wrapper list) credited every action built
 * on an unauthenticated client.
 */
const NON_AUTH_BUILDERS: Record<string, readonly string[]> = {
  'next-safe-action': ['createSafeActionClient', 'createMiddleware'],
  zsa: ['createServerAction', 'createServerActionProcedure'],
  '@trpc/server': ['initTRPC'],
};

/** A name that *sounds* like auth. Only ever the last resort: see `name-only`. */
export const AUTH_WRAPPER_NAME = /auth|protect|guard|session|require|admin|secure|signed|permission|role|apikey|api_key|token/i;

/** Calls that throw (or redirect) by contract when there is no authenticated caller. */
const SELF_REJECTING =
  /(^|\.)((require|assert|ensure)[A-Z_]\w*|protect|authenticate\.(admin|public|flow)|verifyIdToken|jwtVerify|decodeSessionToken|verifyToken|verifyJWT|verifyJwt)$/;

/** Reading the credential itself off the request: `req.headers.authorization`, `req.cookies`. */
const CREDENTIAL_MEMBER = /(^|\.)(headers\.(authorization|cookie)|cookies)(\.|$)/i;

function nameMatchesAuth(wrapper: string, authWrappers: string[]): boolean {
  const root = wrapper.split('.')[0]!;
  const tail = wrapper.slice(wrapper.lastIndexOf('.') + 1);
  return (
    matchesAny(wrapper, authWrappers) ||
    authWrappers.includes(root) ||
    AUTH_WRAPPER_NAME.test(root) ||
    AUTH_WRAPPER_NAME.test(tail)
  );
}

/** Dotted name of an expression, optional chaining included: `req.session?.user` -> `req.session.user`. */
export function memberPath(node: any): string {
  const parts: string[] = [];
  let cur = node;
  for (let guard = 0; cur && guard < 24; guard++) {
    if (cur.type === 'Identifier') {
      parts.unshift(cur.name);
      return parts.join('.');
    }
    if (
      (cur.type === 'MemberExpression' || cur.type === 'OptionalMemberExpression') &&
      !cur.computed &&
      cur.property?.type === 'Identifier'
    ) {
      parts.unshift(cur.property.name);
      cur = cur.object;
      continue;
    }
    if (cur.type === 'TSNonNullExpression' || cur.type === 'ParenthesizedExpression' || cur.type === 'TSAsExpression') {
      cur = cur.expression;
      continue;
    }
    return '';
  }
  return '';
}

/** Visit every node under `node`, not descending where `visit` returns false. */
function walk(node: any, visit: (n: any, parent: any) => boolean | void, parent: any = null, depth = 0): void {
  if (!node || typeof node !== 'object' || depth > 300) return;
  if (Array.isArray(node)) {
    for (const child of node) walk(child, visit, parent, depth + 1);
    return;
  }
  if (typeof node.type !== 'string') return;
  if (visit(node, parent) === false) return;
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'leadingComments' || key === 'trailingComments' || key === 'innerComments' || key === 'extra') continue;
    const v = node[key];
    if (v && typeof v === 'object') walk(v, visit, node, depth + 1);
  }
}

function some(node: any, pred: (n: any) => boolean): boolean {
  let hit = false;
  walk(node, (n) => {
    if (hit) return false;
    if (pred(n)) {
      hit = true;
      return false;
    }
    return true;
  });
  return hit;
}

function bindingNames(pattern: any, out: Set<string>, depth = 0): void {
  if (!pattern || depth > 8) return;
  switch (pattern.type) {
    case 'Identifier':
      out.add(pattern.name);
      return;
    case 'AssignmentPattern':
      bindingNames(pattern.left, out, depth + 1);
      return;
    case 'RestElement':
      bindingNames(pattern.argument, out, depth + 1);
      return;
    case 'ObjectPattern':
      for (const p of pattern.properties ?? []) bindingNames(p.type === 'ObjectProperty' ? p.value : p, out, depth + 1);
      return;
    case 'ArrayPattern':
      for (const el of pattern.elements ?? []) bindingNames(el, out, depth + 1);
      return;
    default:
      return;
  }
}

type TopBinding =
  | { kind: 'import'; source: string; imported: string }
  | { kind: 'function'; node: any }
  | { kind: 'value'; init: any; id: any }
  | null;

/** How a top-level name is bound in a module: imported, a function, or a value. */
function topBinding(ast: File, name: string): TopBinding {
  for (const stmt of ast.program.body as any[]) {
    if (stmt.type === 'ImportDeclaration') {
      for (const s of stmt.specifiers ?? []) {
        if (s.local?.name !== name) continue;
        const imported =
          s.type === 'ImportSpecifier'
            ? (s.imported?.name ?? s.imported?.value)
            : s.type === 'ImportDefaultSpecifier'
              ? 'default'
              : '*';
        return { kind: 'import', source: stmt.source?.value, imported };
      }
      continue;
    }
    const decl =
      stmt.type === 'ExportNamedDeclaration' || stmt.type === 'ExportDefaultDeclaration' ? stmt.declaration : stmt;
    if (!decl) continue;
    if (decl.type === 'FunctionDeclaration' && decl.id?.name === name) return { kind: 'function', node: decl };
    if (decl.type !== 'VariableDeclaration') continue;
    for (const d of decl.declarations ?? []) {
      if (!d?.init) continue;
      const names = new Set<string>();
      bindingNames(d.id, names);
      if (!names.has(name)) continue;
      const init = unwrap(d.init);
      if (d.id.type === 'Identifier' && (init?.type === 'ArrowFunctionExpression' || init?.type === 'FunctionExpression')) {
        return { kind: 'function', node: init };
      }
      return { kind: 'value', init: d.init, id: d.id };
    }
  }
  return null;
}

/** The local name a module exports as `exported`, or where it re-exports it from. */
function exportTarget(ast: File, exported: string): { local: string } | { from: string[]; name: string } | null {
  const star: string[] = [];
  for (const stmt of ast.program.body as any[]) {
    if (stmt.type === 'ExportDefaultDeclaration' && exported === 'default') {
      const d = stmt.declaration;
      if (d?.type === 'Identifier') return { local: d.name };
      if ((d?.type === 'FunctionDeclaration' || d?.type === 'FunctionExpression') && d.id) return { local: d.id.name };
      return null;
    }
    if (stmt.type === 'ExportNamedDeclaration') {
      const d = stmt.declaration;
      if (d?.type === 'FunctionDeclaration' && d.id?.name === exported) return { local: exported };
      if (d?.type === 'VariableDeclaration') {
        for (const v of d.declarations ?? []) {
          const names = new Set<string>();
          bindingNames(v.id, names);
          if (names.has(exported)) return { local: exported };
        }
      }
      for (const s of stmt.specifiers ?? []) {
        const as = s.exported?.name ?? s.exported?.value;
        if (as !== exported) continue;
        const from = s.local?.name ?? s.local?.value;
        if (stmt.source) return { from: [stmt.source.value], name: from };
        return { local: from };
      }
    }
    if (stmt.type === 'ExportAllDeclaration' && stmt.source && exported !== 'default') star.push(stmt.source.value);
  }
  return star.length ? { from: star, name: exported } : null;
}

function loadAst(file: string, opts: WrapperOptions): File | null {
  if (opts.astCache.has(file)) return opts.astCache.get(file)!;
  const source = read(file);
  const ast = source === null ? null : parseSource(source, file);
  opts.astCache.set(file, ast);
  return ast;
}

/**
 * What the wrapper spelled `wrapper` (a dotted callee name, as written in `file`) does
 * for the function it wraps.
 */
export function resolveWrapper(wrapper: string, file: string, ast: File, opts: WrapperOptions, depth = 0): WrapperVerdict {
  const key = `${file}\u0000${wrapper}`;
  const memo = opts.wrapperCache.get(key);
  if (memo) return memo;
  // Placeholder while resolving, so a cycle ends as "not an auth wrapper" instead of looping.
  opts.wrapperCache.set(key, { kind: 'none', wrapper });
  const verdict = { ...resolveUncached(wrapper, file, ast, opts, depth), wrapper };
  opts.wrapperCache.set(key, verdict);
  return verdict;
}

function resolveUncached(wrapper: string, file: string, ast: File, opts: WrapperOptions, depth: number): WrapperVerdict {
  const byName = (): WrapperVerdict => ({
    kind: nameMatchesAuth(wrapper, opts.authWrappers) ? 'name-only' : 'none',
    wrapper,
  });
  if (!wrapper || depth > MAX_DEPTH + 2) return byName();
  const segments = wrapper.split('.');
  const root = segments[0]!;
  const binding = topBinding(ast, root);
  if (!binding) return byName();

  if (binding.kind === 'import') {
    // `import * as guard from './guard'` is called as `guard.withUser(...)`.
    const imported = binding.imported === '*' ? segments[1] : binding.imported;
    const target = opts.index.resolve(binding.source, file);
    if (!target) return thirdParty(binding.source, imported ?? '', wrapper, opts);
    if (!imported) return byName();
    const found = findExport(target, imported, opts, depth + 1);
    const v = found ? definitionVerdict(found.file, found.ast, found.local, opts, depth + 1) : null;
    return v ?? byName();
  }
  return definitionVerdict(file, ast, root, opts, depth) ?? byName();
}

function thirdParty(pkg: string, imported: string, wrapper: string, opts: WrapperOptions): WrapperVerdict {
  if (REQUIRING_WRAPPERS[pkg]?.includes(imported)) return { kind: 'requires', wrapper, from: pkg };
  const attaching = ATTACHING_WRAPPERS[pkg];
  if (attaching?.names.includes(imported)) {
    return { kind: 'attaches', wrapper, from: pkg, session: { positions: [], members: [...attaching.members], ctx: false } };
  }
  if (NON_AUTH_BUILDERS[pkg]?.includes(imported)) return { kind: 'none', wrapper, from: pkg };
  const named = nameMatchesAuth(wrapper, opts.authWrappers) || nameMatchesAuth(imported, opts.authWrappers);
  return { kind: named ? 'name-only' : 'none', wrapper, from: pkg };
}

function findExport(
  file: string,
  exported: string,
  opts: WrapperOptions,
  depth: number,
): { file: string; ast: File; local: string } | null {
  if (depth > MAX_DEPTH + 2) return null;
  const ast = loadAst(file, opts);
  if (!ast) return null;
  const t = exportTarget(ast, exported);
  if (!t) return null;
  if ('local' in t) {
    // `import { x } from './a'; export { x }` — follow the import.
    const b = topBinding(ast, t.local);
    if (b?.kind === 'import' && b.imported !== '*') {
      const next = opts.index.resolve(b.source, file);
      if (next) return findExport(next, b.imported, opts, depth + 1);
    }
    return { file, ast, local: t.local };
  }
  for (const spec of t.from) {
    const next = opts.index.resolve(spec, file);
    const got = next ? findExport(next, t.name, opts, depth + 1) : null;
    if (got) return got;
  }
  return null;
}

/**
 * The verdict for the top-level binding `name` in `file`, read from its definition.
 * Null when there is nothing there this can read — the caller falls back to the name.
 */
function definitionVerdict(file: string, ast: File, name: string, opts: WrapperOptions, depth: number): WrapperVerdict | null {
  if (depth > MAX_DEPTH + 4) return null;
  const b = topBinding(ast, name);
  if (!b) return null;
  if (b.kind === 'import') {
    const target = opts.index.resolve(b.source, file);
    if (!target) return thirdParty(b.source, b.imported, name, opts);
    const found = b.imported === '*' ? null : findExport(target, b.imported, opts, depth + 1);
    return found ? definitionVerdict(found.file, found.ast, found.local, opts, depth + 1) : null;
  }
  if (b.kind === 'function') return functionVerdict(b.node, name, file, ast, opts, depth, 'handler');
  const init = unwrap(b.init);
  // `export const { auth, handlers } = NextAuth(config)`: next-auth v5's `auth(handler)`
  // puts the session on `req.auth` and calls the handler whether or not there is one.
  if (b.id?.type === 'ObjectPattern' && init?.type === 'CallExpression' && /(^|\.)NextAuth$/.test(calleeName(init.callee))) {
    return name === 'auth'
      ? { kind: 'attaches', wrapper: name, from: 'next-auth', session: { positions: [], members: ['auth'], ctx: false } }
      : null;
  }
  if (b.id?.type !== 'Identifier') return null;
  // `export const withAuth = withApiAuthRequired` — an alias.
  if (init?.type === 'Identifier' || init?.type === 'MemberExpression') {
    const alias = calleeName(init);
    return alias && alias !== name ? resolveWrapper(alias, file, ast, opts, depth + 1) : null;
  }
  if (init?.type === 'CallExpression' || init?.type === 'OptionalCallExpression') {
    return chainVerdict(init, name, file, ast, opts, depth);
  }
  return null;
}

const isFunctionNode = (n: any) =>
  n?.type === 'ArrowFunctionExpression' || n?.type === 'FunctionExpression' || n?.type === 'ObjectMethod';

/**
 * A client built by chaining: `actionClient.use(mw)`, `createSafeActionClient({ middleware })`,
 * `t.procedure.use(isAuthed)`, `createServerActionProcedure(fn)`. Each middleware is judged
 * like a wrapper whose "handler" is `next`; the chain's base is resolved in turn.
 */
function chainVerdict(init: any, name: string, file: string, ast: File, opts: WrapperOptions, depth: number): WrapperVerdict {
  const middlewares: any[] = [];
  let base: string | null = null;
  let cur = init;
  for (let guard = 0; cur && guard < 24; guard++) {
    cur = unwrap(cur);
    if (cur?.type === 'CallExpression' || cur?.type === 'OptionalCallExpression') {
      for (const arg of cur.arguments ?? []) middlewares.push(arg);
      cur = cur.callee;
      continue;
    }
    if (cur?.type === 'MemberExpression' || cur?.type === 'OptionalMemberExpression') {
      cur = cur.object;
      continue;
    }
    if (cur?.type === 'Identifier') base = cur.name;
    break;
  }
  const verdicts: WrapperVerdict[] = [];
  for (const arg of middlewares) {
    const a = unwrap(arg);
    if (isFunctionNode(a)) {
      verdicts.push(functionVerdict(a, name, file, ast, opts, depth + 1, 'middleware'));
    } else if (a?.type === 'ObjectExpression') {
      // `createSafeActionClient({ middleware: async () => { ... } })` (v5 and earlier).
      for (const p of a.properties ?? []) {
        const k = p.key?.name ?? p.key?.value ?? '';
        if (!/middleware/i.test(k)) continue;
        const v = p.type === 'ObjectMethod' ? p : unwrap(p.value);
        if (isFunctionNode(v)) verdicts.push(functionVerdict(v, name, file, ast, opts, depth + 1, 'middleware'));
      }
    } else if (a?.type === 'Identifier' && a.name !== base && a.name !== name) {
      // `t.procedure.use(isAuthed)` where `const isAuthed = t.middleware(fn)`.
      const b = topBinding(ast, a.name);
      if (b?.kind === 'function') verdicts.push(functionVerdict(b.node, a.name, file, ast, opts, depth + 1, 'middleware'));
      else if (b) {
        const v = definitionVerdict(file, ast, a.name, opts, depth + 1);
        if (v) verdicts.push(v);
      }
    }
  }
  if (base && base !== name) {
    const v = definitionVerdict(file, ast, base, opts, depth + 1);
    if (v) verdicts.push(v);
  }
  return combine(verdicts, name);
}

function combine(verdicts: WrapperVerdict[], wrapper: string): WrapperVerdict {
  const req = verdicts.find((v) => v.kind === 'requires');
  if (req) return { ...req, wrapper };
  const att = verdicts.filter((v) => v.kind === 'attaches');
  if (att.length) {
    return {
      kind: 'attaches',
      wrapper,
      from: att[0]!.from,
      session: {
        positions: [...new Set(att.flatMap((v) => v.session?.positions ?? []))],
        members: [...new Set(att.flatMap((v) => v.session?.members ?? []))],
        ctx: att.some((v) => v.session?.ctx),
      },
    };
  }
  const named = verdicts.find((v) => v.kind === 'name-only');
  if (named) return { ...named, wrapper };
  return { kind: 'none', wrapper };
}

/**
 * Read a wrapper (or middleware) function. `role` says what its "handler" is: the
 * identifier parameters for a wrapper, `next` for a middleware.
 */
function functionVerdict(
  fn: any,
  name: string,
  file: string,
  ast: File,
  opts: WrapperOptions,
  depth: number,
  role: 'handler' | 'middleware',
): WrapperVerdict {
  const credited = authHelpersFor(file, opts, ast).credited;

  // The handler: a wrapper's own identifier parameters; a middleware's `next`.
  const handlers = new Set<string>();
  const ctxNames = new Set<string>();
  const params: any[] = fn.params ?? [];
  for (const p of params) {
    if (role === 'handler' && p.type === 'Identifier') handlers.add(p.name);
    if (p.type === 'ObjectPattern') {
      for (const prop of p.properties ?? []) {
        const k = prop.key?.name ?? prop.key?.value;
        if (k === 'next' || k === 'handler') bindingNames(prop.value, handlers);
        // A middleware's `ctx` is what createContext or an earlier middleware resolved
        // server-side — `if (!ctx.user) throw` in it is the auth check.
        if (k === 'ctx' && role === 'middleware') bindingNames(prop.value, ctxNames);
      }
    }
  }
  if (role === 'middleware' && params[0]?.type === 'Identifier') {
    // `(opts) => { ... opts.next() }`
    handlers.add(`${params[0].name}.next`);
    ctxNames.add(`${params[0].name}.ctx`);
  }

  const isAuthSource = (n: any): boolean => {
    if (n.type === 'CallExpression' || n.type === 'OptionalCallExpression') {
      const full = calleeName(n.callee);
      if (!full || isUserLookup(n)) return false;
      return (
        matchesAny(full, opts.authCalls) ||
        credited.has(full) ||
        SUPABASE_GET_SESSION.test(full) ||
        opts.isCredentialSource(n)
      );
    }
    if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') {
      const path = memberPath(n);
      if (!path) return false;
      if (CREDENTIAL_MEMBER.test(path)) return true;
      return [...ctxNames].some((c) => path === c || path.startsWith(c + '.'));
    }
    if (n.type === 'Identifier') return ctxNames.has(n.name);
    return false;
  };

  // Names bound to an auth result, directly or derived from one.
  const derived = new Set<string>();
  const touches = (n0: any) => some(n0, (n) => (n.type === 'Identifier' && derived.has(n.name)) || isAuthSource(n));
  for (let pass = 0; pass < 2; pass++) {
    walk(fn.body, (n) => {
      if (n.type === 'VariableDeclarator' && n.init && touches(n.init)) bindingNames(n.id, derived);
      return true;
    });
  }

  const isHandlerCall = (n: any): boolean => {
    if (n.type !== 'CallExpression' && n.type !== 'OptionalCallExpression') return false;
    const c = n.callee?.type === 'Identifier' ? n.callee.name : memberPath(n.callee);
    return handlers.has(c);
  };

  // Every place the handler is invoked, and every call it is handed to (delegation).
  const invocations: any[] = [];
  const delegations: { call: any; verdict: WrapperVerdict }[] = [];
  walk(fn.body, (n) => {
    if (isHandlerCall(n)) invocations.push(n);
    else if (
      (n.type === 'CallExpression' || n.type === 'OptionalCallExpression') &&
      (n.arguments ?? []).some((a: any) => a?.type === 'Identifier' && handlers.has(a.name))
    ) {
      const callee = calleeName(n.callee);
      if (callee) delegations.push({ call: n, verdict: resolveWrapper(callee, file, ast, opts, depth + 1) });
    }
    return true;
  });
  const firstUse = Math.min(
    Infinity,
    ...invocations.map((n) => n.start ?? Infinity),
    ...delegations.map((d) => d.call.start ?? Infinity),
  );

  const hasAuth = some(fn.body, isAuthSource);

  // (1) A call that throws or redirects by contract, before the handler runs.
  const selfRejects = some(fn.body, (n) => {
    if (n.type !== 'CallExpression' && n.type !== 'OptionalCallExpression') return false;
    const full = calleeName(n.callee);
    return SELF_REJECTING.test(full) && (n.start ?? Infinity) < firstUse && (isAuthSource(n) || credited.has(full));
  });

  // (2) `if (!session) return 401` before the handler; (3) `if (session) return handler(); return 401`.
  let guarded = false;
  walk(fn.body, (n, parent) => {
    if (guarded) return false;
    if (n.type !== 'IfStatement' || !touches(n.test)) return true;
    const callsHandler = some(n.consequent, isHandlerCall);
    if (!callsHandler && (n.start ?? Infinity) < firstUse) {
      if (opts.exits(n.consequent) || some(n.consequent, opts.isUnauthorisedExit)) guarded = true;
    } else if (callsHandler && opts.exits(n.consequent)) {
      if (n.alternate && (opts.exits(n.alternate) || some(n.alternate, opts.isUnauthorisedExit))) guarded = true;
      const siblings: any[] = parent?.type === 'BlockStatement' ? parent.body : [];
      const i = siblings.indexOf(n);
      const next = i >= 0 ? siblings[i + 1] : undefined;
      if (next && !some(next, isHandlerCall) && (opts.exits(next) || some(next, opts.isUnauthorisedExit))) guarded = true;
    }
    return true;
  });

  const inner = combine(
    delegations.map((d) => d.verdict),
    name,
  );
  if (inner.kind === 'requires') return { ...inner, wrapper: name };
  if (hasAuth && (selfRejects || guarded)) return { kind: 'requires', wrapper: name };
  if (invocations.length === 0 && delegations.length === 0) {
    // A zsa-style procedure returns the context instead of calling `next`.
    if (role === 'middleware' && hasAuth) {
      return { kind: 'attaches', wrapper: name, session: { positions: [], members: [], ctx: true } };
    }
    // Nothing here invokes what it wraps — not a shape this can read.
    return { kind: nameMatchesAuth(name, opts.authWrappers) ? 'name-only' : 'none', wrapper: name };
  }
  if (inner.kind === 'attaches' || hasAuth) {
    const session: SessionShape = {
      positions: [...(inner.session?.positions ?? [])],
      members: [...(inner.session?.members ?? [])],
      ctx: role === 'middleware' || Boolean(inner.session?.ctx),
    };
    for (const call of invocations) {
      (call.arguments ?? []).forEach((a: any, i: number) => {
        if (a && touches(a) && !session.positions.includes(i)) session.positions.push(i);
      });
    }
    // `req.session = session; return handler(req, res)`, `req.user = user`.
    walk(fn.body, (n) => {
      if (n.type === 'AssignmentExpression' && n.left?.type === 'MemberExpression' && touches(n.right)) {
        const prop = n.left.property?.name;
        if (prop && !session.members.includes(prop)) session.members.push(prop);
      }
      return true;
    });
    return { kind: 'attaches', wrapper: name, from: inner.from, session };
  }
  return { kind: inner.kind === 'name-only' ? 'name-only' : 'none', wrapper: name, from: inner.from };
}
