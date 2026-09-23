import {
  read, rel, isScript, snippetAt,
  parseSource, calleeName, calleeTail, hasDirective,
  traverse, buildModuleIndex, Suppressions, emptyResult,
} from '../internal.js';
import {
  authHelpersFor, isAccessorOnly, isUserLookup, memberPath, resolveWrapper,
  CREDENTIAL_HEADERS, SECRET_ENV, SUPABASE_GET_SESSION,
} from './auth-helpers.js';
import type { ModuleAuth, SessionShape, WrapperOptions, WrapperVerdict } from './auth-helpers.js';
import { inertNamesFor } from './effects.js';
import type { Finding, ProjectContext, ScanResult, Scanner } from '../internal.js';

/**
 * Calls that prove the caller's identity was checked server-side.
 * Matched on the dotted callee name (suffix match) so `supabase.auth.getUser`,
 * `client.auth.getUser` and a bare `getUser` all hit.
 */
const AUTH_CALLS = [
  'auth.getUser', 'auth.getClaims', 'getUser', 'getSession',
  'getServerSession', 'getServerAuthSession', 'currentUser', 'auth', 'clerkClient',
  'getAuth', 'validateRequest', 'verifySession', 'requireUser', 'requireAuth',
  'requireSession', 'assertAuthenticated', 'getCurrentUser', 'getLoggedInUser',
  'getToken', 'verifyToken', 'verifyIdToken', 'protect', 'ensureUser',
  // Framework primitives that verify a signed session token rather than read
  // one: Shopify App Bridge's session-token exchange, Shopify Remix's
  // `authenticate.admin(request)`, and jose's JWT verification.
  'session.decodeSessionToken', 'decodeSessionToken', 'authenticate.admin',
  'authenticate.public', 'authenticate.flow', 'jwtVerify', 'verifyJWT', 'verifyJwt',
];

/** Higher-order wrappers that apply auth (and often validation) for the action. */
const AUTH_WRAPPERS = [
  'withAuth', 'withUser', 'withSession', 'authedProcedure', 'protectedProcedure',
  'authActionClient', 'authenticatedAction', 'actionClient', 'createSafeActionClient',
  'createServerAction', 'safeAction', 'guarded', 'requireAuth', 'withGuard',
];

/**
 * Calls that end in a mutation verb but write nothing:
 * `openai.chat.completions.create(...)` is an outbound API call, and reporting
 * it as "performs a database mutation" is a claim about code that is not there.
 * The AI-specific rules cover what that call actually risks.
 */
const NOT_A_DATA_WRITE =
  /(^|\.)(chat\.completions|completions|responses|messages|embeddings|images|audio|moderations|files|threads|runs|assistants)\.(create|update)$/;

/**
 * `.delete` / `.remove` on something that is not a data store. `cookies().delete(name)`,
 * `url.searchParams.delete('preview')` and `headers.delete(...)` clear a cookie, a query
 * parameter or a header on the caller's own request — read as "performs a database
 * mutation" they turned three logout handlers and a preview-exit route into criticals.
 */
const NOT_A_DATA_RECEIVER =
  /(^|\.)(cookies|cookieStore|cookieJar|searchParams|headers|params|url|urlObj|nextUrl)\.(delete|remove)$/i;

/**
 * Calls into an LLM or embedding provider. What such a call risks is cost and prompt
 * abuse, which the AI-specific rules name; it writes nothing, so a POST whose only
 * effect is one is not "a write with no auth check". A receiver named for the provider
 * is matched, not a bare `.create`, which `db.messages.create` would also satisfy.
 */
const AI_CALLS = new RegExp(
  '^(?:streamText|generateText|generateObject|streamObject|embed|embedMany|convertToModelMessages|' +
    'convertToCoreMessages|createUIMessageStreamResponse|createOpenAI|createAnthropic|' +
    'createGoogleGenerativeAI|openai|anthropic|zodResponseFormat|zodTextFormat|zodFunction)$' +
    '|(?:^|\\.)chat\\.completions\\.(?:create|stream|parse)$' +
    '|(?:^|\\.)(?:openai|anthropic|genai|genAI|groq|mistral|cohere|deepseek|gemini|openrouter)\\.[\\w.]+$' +
    '|(?:^|\\.)(?:generateContent|generateContentStream|getGenerativeModel)$',
);

/**
 * Calls with no effect outside the process: reading the request, string and array
 * helpers, logging, building the response. A handler whose only other calls are LLM
 * calls has nothing but that call to do.
 */
const INERT_CALL_TAILS = new Set([
  // Reading the request, and the response builders.
  'json', 'text', 'formData', 'arrayBuffer', 'blob', 'get', 'getAll', 'has', 'entries', 'keys',
  'values', 'redirect', 'notFound', 'toDataStreamResponse', 'toUIMessageStreamResponse',
  'toTextStreamResponse', 'toDataStream', 'pipeThrough',
  // Strings, arrays, numbers, JSON.
  'map', 'filter', 'slice', 'join', 'trim', 'trimStart', 'trimEnd', 'split', 'includes',
  'startsWith', 'endsWith', 'replace', 'replaceAll', 'toLowerCase', 'toUpperCase', 'push',
  'concat', 'find', 'findIndex', 'findLast', 'some', 'every', 'reduce', 'flat', 'flatMap',
  'forEach', 'sort', 'reverse', 'fill', 'splice', 'shift', 'unshift', 'pop', 'at', 'indexOf',
  'lastIndexOf', 'charAt', 'codePointAt', 'padStart', 'padEnd', 'repeat', 'normalize',
  'substring', 'substr', 'search', 'localeCompare', 'match', 'matchAll', 'test', 'toFixed',
  'parse', 'safeParse', 'stringify', 'isArray', 'from', 'fromEntries', 'assign', 'isInteger',
  'isFinite', 'isNaN', 'parseInt', 'parseFloat', 'floor', 'ceil', 'round', 'min', 'max',
  'abs', 'random', 'String', 'Number', 'Boolean', 'encodeURIComponent', 'decodeURIComponent',
  'btoa', 'atob', 'structuredClone',
  // Logging.
  'log', 'warn', 'error', 'info', 'debug',
]);

/** Outbound HTTP clients: a `.get` on one is a network call, not a lookup. */
const HTTP_CLIENT_ROOT = /^(axios|got|ky|superagent|needle)\./;

/** A call with no effect outside the process. */
function isInertCall(full: string, tail: string): boolean {
  if (AI_CALLS.test(full)) return true;
  if (HTTP_CLIENT_ROOT.test(full)) return false;
  return (
    RESPONSE_CALLS.test(full) ||
    TRIVIAL_CALLS.test(full) ||
    INERT_CALL_TAILS.has(tail) ||
    REQUEST_INPUT_READ.test(full)
  );
}

/** Data-writing calls across Supabase, Prisma, Drizzle, Mongoose and raw SQL. */
const MUTATION_CALLS = new Set([
  'insert', 'update', 'upsert', 'delete', 'create', 'createMany', 'updateMany',
  'deleteMany', 'upsertMany', 'destroy', 'save', 'remove', 'findOneAndUpdate',
  'findOneAndDelete', 'updateOne', 'updateMany', 'deleteOne', 'insertOne',
  'insertMany', 'replaceOne', 'bulkWrite', 'increment', 'decrement',
]);

/**
 * A mutation verb called on something that only lives in this process. `update` on a
 * hash (`createHash('md5').update(email).digest('hex')`), `delete` on a `Set` or `Map`
 * built here, `Object.create(null, …)`: each matched MUTATION_CALLS by its last segment
 * and was reported as a database write, which it is nowhere near.
 */
const IN_PROCESS_CTORS = /^(Set|Map|WeakSet|WeakMap|URLSearchParams|Headers|FormData|URL|Array)$/;
const CRYPTO_OBJECT_CALL = /(^|\.)(createHash|createHmac|createCipheriv|createDecipheriv|createSign|createVerify)$/;
const CRYPTO_CHAIN = /(^|\.)(createHash|createHmac|createCipheriv|createDecipheriv|createSign|createVerify)\./;
const JS_BUILTIN_ROOT = /^(Object|Reflect|Array|Promise|JSON|Math|Date|Symbol|Number|String|Intl|Map|Set|WeakMap|WeakSet)\./;

/** `new Set(...)`, `createHash('sha256')`: an initializer whose value never leaves the process. */
function isInProcessValue(init: any): boolean {
  let cur = init;
  while (cur && (cur.type === 'AwaitExpression' || cur.type === 'TSNonNullExpression' || cur.type === 'TSAsExpression')) {
    cur = cur.argument ?? cur.expression;
  }
  if (!cur) return false;
  if (cur.type === 'NewExpression') return IN_PROCESS_CTORS.test(calleeName(cur.callee));
  if (cur.type === 'CallExpression') {
    const full = calleeName(cur.callee);
    return CRYPTO_OBJECT_CALL.test(full) || CRYPTO_CHAIN.test(full + '.');
  }
  return false;
}

/** Names bound, anywhere in `root`, to one of those in-process values. */
function inProcessNames(root: any): Set<string> {
  const names = new Set<string>();
  someNode(root, (n) => {
    if (n.type === 'VariableDeclarator' && n.id?.type === 'Identifier' && isInProcessValue(n.init)) names.add(n.id.name);
    return false;
  });
  return names;
}

/** True when a mutation-verb call writes to an in-process value, not a data store. */
function isInProcessMutation(call: any, local: ReadonlySet<string>): boolean {
  const callee = call.callee;
  const full = calleeName(callee);
  if (JS_BUILTIN_ROOT.test(full) || CRYPTO_CHAIN.test(full)) return true;
  if (callee?.type !== 'MemberExpression' && callee?.type !== 'OptionalMemberExpression') return false;
  const receiver = callee.object;
  if (receiver?.type === 'Identifier') return local.has(receiver.name);
  return isInProcessValue(receiver);
}

/** Runtime schema validation. Absence of all of these on a parameterised action is a finding. */
const VALIDATION_CALLS = new Set([
  'parse', 'safeParse', 'parseAsync', 'safeParseAsync', 'validate', 'validateSync',
  'assert', 'check', 'decode', 'is', 'coerce', 'cast', 'schema', 'input', 'with',
]);

/**
 * Verification calls that make an inbound webhook trustworthy.
 */
const SIGNATURE_CHECKS = [
  'webhooks.constructEvent', 'constructEvent', 'constructEventAsync', 'verifyHeader',
  'verify', 'verifySignature', 'createHmac', 'timingSafeEqual', 'Webhook', 'validateRequest',
  'verifyWebhook', 'verifyWebhookSignature',
  // Framework webhook handlers that verify the signature internally, so the
  // route body delegates rather than calling an hmac primitive directly.
  'authenticate.webhook', 'webhooks.process', 'webhooks.validate', 'processWebhook',
  'handleWebhook', 'validateWebhook', 'wh.verify', 'svix.verify',
];

/**
 * A callee *named* like a signature check — `verifyProviderWebhook`,
 * `isValidSignature`, `checkHmac` — verifies a signature whatever it is called from.
 * A route that delegates to its own per-provider verifier is not an unverified
 * webhook, and the fixed list above can never enumerate every such name.
 */
const SIGNATURE_VERIFY_NAME =
  /(?=.*(?:signature|hmac|webhook|signed[_-]?request))(?=.*(?:verif|valid|check|authent|authori[sz]|assert|construct))/i;

/**
 * The narrower reading of the same idea, for a route whose PATH does not say webhook: a
 * callee or member named for verifying a signature — `verifyAndDecodeSignedRequest`,
 * `parsed.isValidSignature` — proves the caller wherever the route lives. `webhook` and
 * `check` are left out on purpose: `checkWebhookStatus()` is not a verification.
 */
const STRONG_SIGNATURE_NAME =
  /(?=.*(?:signature|hmac|signed[_-]?request))(?=.*(?:verif|valid|authent|authori[sz]|assert|construct))/i;

/** `requireVerifiedActor(req.headers)`, `authorizeRequest(request)`: an auth verb handed the request. */
const AUTH_VERB_HELPER = /^(?:require|assert|ensure|authorize|authenticate)[A-Z_]/;
const REQUEST_PARAM = /^(req|request|_req|_request|nextRequest)$/;

/**
 * Request headers that only exist to carry a webhook signature. A handler that
 * reads one is participating in signature verification — a route that genuinely
 * forgot it would not reference the header at all — so reading one clears the
 * "unverified webhook" check.
 */
const SIGNATURE_HEADERS =
  /(x-shopify-hmac-sha256|x-hub-signature(-256)?|stripe-signature|svix-signature|svix-id|x-signature|x-webhook-signature|x-slack-signature|x-line-signature|paypal-transmission-sig)/i;

/**
 * Headers that exist to carry a caller credential. Reading one *and* comparing
 * it against a server-side secret is how a cron or machine-to-machine endpoint
 * authenticates — there is no session to look up.
 */
// CREDENTIAL_HEADERS and SECRET_ENV — the two halves of that check — live in
// auth-helpers.ts, which applies them to the helper a route calls as well.

/**
 * Calls that only build the HTTP response. A handler whose body contains
 * nothing else is a static responder — a health check — with no work to trigger.
 */
const RESPONSE_CALLS =
  /^(NextResponse\.(json|redirect|next|rewrite)|Response\.(json|redirect|error)|json|res\.(json|send|status))$/;

/**
 * Calls that compute a value and touch nothing: a timestamp in a health check, a
 * string conversion. They are not "work" the endpoint could be made to do.
 */
const TRIVIAL_CALLS = /(^|\.)(toISOString|toJSON|getTime|now|uptime|toString|stringify|toLocaleString|toUTCString)$/;

/**
 * Reading the request body. Anchored on the receiver so `NextResponse.json(...)`
 * — which writes the response — is not mistaken for reading the request.
 */
const REQUEST_INPUT_READ =
  /(^|\.)(req|request|nextRequest|_req|_request)\??\.(json|text|formData|arrayBuffer|blob)$/i;

/** Schema escape hatches that make validation decorative. */
const LOOSE_SCHEMA = /\.passthrough\s*\(|z\s*\.\s*(any|unknown)\s*\(|\.catchall\s*\(/g;

const SERVICE_ROLE_HINTS = [
  'SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_SERVICE_KEY', 'SERVICE_ROLE_KEY',
  'SUPABASE_SECRET_KEY',
];

/**
 * Dotted expressions that plausibly carry the authenticated principal's id.
 * The principal is not always a person: in a B2B or platform app it is the
 * tenant — a store, org, workspace or team — and a write scoped to it is
 * scoped just as tightly as one scoped to a user id.
 */
const OWNER_HINTS = [
  'user.id', 'user?.id', 'session.user.id', 'userId', 'user_id', 'auth.uid',
  'currentUser.id', 'ctx.user', 'claims.sub', 'uid',
  'store.id', 'shop.id', 'org.id', 'organization.id', 'tenant.id', 'workspace.id',
  'account.id', 'team.id', 'company.id', 'session.shop', 'session.shopDomain',
];

/** Bare identifiers carrying that same principal. */
const OWNER_IDENTIFIERS = new Set([
  'userId', 'user_id', 'ownerId', 'owner_id', 'shop', 'shopDomain', 'shop_domain',
  'storeId', 'store_id', 'orgId', 'org_id', 'organizationId', 'organization_id',
  'tenantId', 'tenant_id', 'workspaceId', 'workspace_id', 'accountId', 'account_id',
  'teamId', 'team_id', 'companyId', 'company_id',
]);

/** Names bound by a function's own parameter list, destructuring included. */
function parameterNames(params: any[]): Set<string> {
  const names = new Set<string>();
  const visit = (node: any, depth = 0) => {
    if (!node || depth > 8) return;
    switch (node.type) {
      case 'Identifier':
        names.add(node.name);
        return;
      case 'AssignmentPattern':
        visit(node.left, depth + 1);
        return;
      case 'RestElement':
        visit(node.argument, depth + 1);
        return;
      case 'ObjectPattern':
        for (const prop of node.properties ?? []) {
          visit(prop.type === 'ObjectProperty' ? prop.value : prop, depth + 1);
        }
        return;
      case 'ArrayPattern':
        for (const el of node.elements ?? []) visit(el, depth + 1);
        return;
      default:
        return;
    }
  };
  for (const p of params ?? []) visit(p);
  return names;
}

/** Root identifier of `a.b.c` — the binding the expression reads from. */
function rootObject(node: any): string | null {
  let cur = node;
  let guard = 0;
  while (cur && guard++ < 16) {
    if (cur.type === 'Identifier') return cur.name;
    cur = cur.object ?? cur.expression ?? cur.argument;
  }
  return null;
}

function matchesAny(name: string, list: string[]): boolean {
  for (const candidate of list) {
    if (name === candidate || name.endsWith('.' + candidate)) return true;
  }
  return false;
}

/** True when any node in the subtree satisfies `pred`. */
function someNode(node: any, pred: (n: any) => boolean, depth = 0): boolean {
  if (!node || typeof node !== 'object' || depth > 200) return false;
  if (Array.isArray(node)) return node.some((child) => someNode(child, pred, depth + 1));
  if (typeof node.type !== 'string') return false;
  if (pred(node)) return true;
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'leadingComments' || key === 'trailingComments') continue;
    const value = node[key];
    if (value && typeof value === 'object' && someNode(value, pred, depth + 1)) return true;
  }
  return false;
}

/**
 * Module-level bindings that hold a server-side secret: `const API_KEY = process.env.CRON_API_KEY`.
 * The handler compares the header against `API_KEY`, so the environment read it is
 * checked against sits outside the function the scanner is looking at.
 */
function moduleSecretConsts(ast: any): Set<string> {
  const names = new Set<string>();
  for (const stmt of ast.program.body) {
    const decl = stmt.type === 'ExportNamedDeclaration' ? stmt.declaration : stmt;
    if (decl?.type !== 'VariableDeclaration') continue;
    for (const d of decl.declarations ?? []) {
      if (d?.id?.type !== 'Identifier') continue;
      let init = d.init;
      // `process.env.X!`, `process.env.X as string`, `process.env.X ?? ''`
      while (
        init &&
        (init.type === 'TSNonNullExpression' || init.type === 'TSAsExpression' || init.type === 'LogicalExpression')
      ) {
        init = init.type === 'LogicalExpression' ? init.left : init.expression;
      }
      if (init?.type === 'MemberExpression' && SECRET_ENV.test(calleeName(init))) names.add(d.id.name);
    }
  }
  return names;
}

/**
 * The request, or the part of it that carries credentials: `req`, `request.headers`,
 * `request.cookies`, `headers()`, `cookies()`. Not its body or URL — those are what the
 * caller chose to say, and handing them to a function is not handing it a credential.
 */
function isRequestish(arg: any): boolean {
  let inner = arg;
  while (inner && (inner.type === 'AwaitExpression' || inner.type === 'TSNonNullExpression')) {
    inner = inner.argument ?? inner.expression;
  }
  if (!inner) return false;
  if (inner.type === 'CallExpression') {
    return inner.callee?.type === 'Identifier' && (inner.callee.name === 'headers' || inner.callee.name === 'cookies');
  }
  if (inner.type === 'Identifier') {
    return REQUEST_PARAM.test(inner.name) || inner.name === 'headers' || inner.name === 'cookies';
  }
  if (inner.type === 'MemberExpression' || inner.type === 'OptionalMemberExpression') {
    const prop = inner.property?.name;
    return (
      inner.object?.type === 'Identifier' &&
      REQUEST_PARAM.test(inner.object.name) &&
      (prop === 'headers' || prop === 'cookies')
    );
  }
  return false;
}

/**
 * Checks that are about where a request came from or how often, not who sent it. A 403 from
 * one of these is not authentication.
 */
const NOT_AN_IDENTITY_CHECK = /origin|csrf|xsrf|referer|cors|rate|limit|throttle|captcha/i;

/**
 * A helper that only reads a value off the request — `header(request, 'x-actor-role')`,
 * `getQuery(req)`. It hands back what the caller sent, verified by nothing, so its result
 * is a claim however many `if`s it later feeds.
 */
const RAW_REQUEST_READER = /^(?:get|read)?_?(?:header|headers|param|params|query|search|body|ip|url|origin|host|locale|lang|json|text)s?$/i;

/**
 * A call whose result speaks to who the caller is: it is handed the request (or its
 * headers/cookies), or it reads a credential header or a cookie itself.
 */
function isCredentialSource(n: any): boolean {
  if (n.type !== 'CallExpression') return false;
  const full = calleeName(n.callee);
  const tail = calleeTail(n.callee);
  if (NOT_AN_IDENTITY_CHECK.test(tail) || RAW_REQUEST_READER.test(tail)) return false;
  const first = n.arguments?.[0];
  if (/(^|\.)headers\.get$/.test(full)) {
    return first?.type === 'StringLiteral' && CREDENTIAL_HEADERS.test(first.value);
  }
  if (/(^|\.)cookies\.get$/.test(full)) return true;
  return (n.arguments ?? []).some((arg: any) => isRequestish(arg));
}

/** `return ...{ status: 401 }`, `res.status(403)`, `unauthorized()`, `throw new Error('Unauthorized')`. */
function isUnauthorisedExit(n: any): boolean {
  if (n.type === 'ObjectProperty') {
    return propertyKey(n) === 'status' && n.value?.type === 'NumericLiteral' && (n.value.value === 401 || n.value.value === 403);
  }
  if (n.type === 'CallExpression') {
    const callee = n.callee;
    if (callee?.type === 'Identifier') return callee.name === 'unauthorized' || callee.name === 'forbidden';
    return (
      callee?.type === 'MemberExpression' &&
      callee.property?.name === 'status' &&
      n.arguments?.[0]?.type === 'NumericLiteral' &&
      (n.arguments[0].value === 401 || n.arguments[0].value === 403)
    );
  }
  if (n.type === 'ThrowStatement') {
    return someNode(
      n.argument,
      (m) => m.type === 'StringLiteral' && /unauthori[sz]ed|unauthenticated|forbidden|not authori[sz]ed/i.test(m.value),
    );
  }
  return false;
}

/*
 * Where an auth check sits, not only whether one appears. An auth call used to count
 * wherever it was in the function: after the write (`await db.post.delete(); await
 * auth()`), inside a closure nothing calls, or inside `if (process.env.NODE_ENV ===
 * 'test')`, which production never enters. Each of those was reported as authenticated.
 * What follows works out, for a node inside the analysed function, the position in the
 * enclosing function at which that code actually runs.
 */

/** Code that provably never runs: a local function nothing references. */
const NEVER_RUNS = Number.POSITIVE_INFINITY;

/**
 * Where, in `scope`'s own body, the code at `p` runs: its own position if no function
 * stands between them, otherwise where that function is invoked.
 */
function runPosition(p: any, scope: any, depth = 0): number {
  let cur = p.parentPath;
  while (cur && cur.node !== scope.node) {
    if (cur.isFunction()) return functionRunPosition(cur, scope, depth);
    cur = cur.parentPath;
  }
  // The END of the node: a call runs once its arguments are evaluated, so a check
  // written inside the write's own arguments — `delete({ where: { authorId: (await
  // requireUser()).id } })` — runs before it.
  return p.node.end ?? 0;
}

function functionRunPosition(fn: any, scope: any, depth: number): number {
  // Deep indirection: fall back to where the function is written, as before.
  if (depth > 6) return fn.node.start ?? 0;
  const parent = fn.parentPath;
  const pn = parent?.node;
  // `(async () => { ... })()`, and a callback handed to a call (`$transaction(async
  // (tx) => ...)`, `items.map(...)`): runs where that call is evaluated.
  if (pn && (pn.type === 'CallExpression' || pn.type === 'OptionalCallExpression' || pn.type === 'NewExpression')) {
    return runPosition(parent, scope, depth + 1);
  }
  let name: string | null = null;
  if (fn.node.type === 'FunctionDeclaration' && fn.node.id) name = fn.node.id.name;
  else if (pn?.type === 'VariableDeclarator' && pn.id?.type === 'Identifier' && pn.init === fn.node) name = pn.id.name;
  if (!name) return fn.node.start ?? 0;
  // A named local function runs where it is first called or handed to a call.
  const binding = parent.scope?.getBinding?.(name);
  const refs = (binding?.referencePaths ?? []).filter(
    (r: any) => !r.findParent((q: any) => q.node === fn.node) && r.findParent((q: any) => q.node === scope.node),
  );
  if (refs.length === 0) return NEVER_RUNS;
  let best = NEVER_RUNS;
  for (const r of refs) {
    const rp = r.parentPath;
    const t = rp?.node?.type;
    const at = t === 'CallExpression' || t === 'OptionalCallExpression' || t === 'NewExpression' ? rp : r;
    best = Math.min(best, runPosition(at, scope, depth + 1));
  }
  return best;
}

/** The innermost function (at or inside `root`) that contains both paths. */
function commonFunction(a: any, b: any, root: any): any {
  const chain = (p: any): any[] => {
    const out: any[] = [];
    let cur = p.parentPath;
    while (cur) {
      if (cur.isFunction()) {
        out.push(cur);
        if (cur.node === root.node) break;
      }
      cur = cur.parentPath;
    }
    return out;
  };
  const inB = new Set(chain(b).map((p) => p.node));
  for (const f of chain(a)) if (inB.has(f.node)) return f;
  return root;
}

/** `process.env.NODE_ENV === 'test'`, evaluated for production: true, false, or unknown. */
function whenProduction(expr: any, scopePath: any, depth = 0): boolean | undefined {
  if (!expr || depth > 6) return undefined;
  switch (expr.type) {
    case 'TSAsExpression':
    case 'TSNonNullExpression':
    case 'ParenthesizedExpression':
      return whenProduction(expr.expression, scopePath, depth + 1);
    case 'BooleanLiteral':
      return expr.value;
    case 'UnaryExpression': {
      if (expr.operator !== '!') return undefined;
      const v = whenProduction(expr.argument, scopePath, depth + 1);
      return v === undefined ? undefined : !v;
    }
    case 'LogicalExpression': {
      const l = whenProduction(expr.left, scopePath, depth + 1);
      const r = whenProduction(expr.right, scopePath, depth + 1);
      if (expr.operator === '&&') return l === false || r === false ? false : l === true && r === true ? true : undefined;
      if (expr.operator === '||') return l === true || r === true ? true : l === false && r === false ? false : undefined;
      return undefined;
    }
    case 'BinaryExpression': {
      if (!['===', '==', '!==', '!='].includes(expr.operator)) return undefined;
      const isEnv = (n: any) => /(^|\.)env\.NODE_ENV$/.test(calleeName(n));
      const lit = isEnv(expr.left) ? expr.right : isEnv(expr.right) ? expr.left : null;
      if (lit?.type !== 'StringLiteral') return undefined;
      const equal = lit.value === 'production';
      return expr.operator === '===' || expr.operator === '==' ? equal : !equal;
    }
    case 'MemberExpression': {
      // Set only by a test runner.
      if (/(^|\.)env\.(VITEST|JEST_WORKER_ID)$/.test(calleeName(expr))) return false;
      return undefined;
    }
    case 'Identifier': {
      // `const isTest = process.env.NODE_ENV === 'test'`, here or at module scope.
      const binding = scopePath?.scope?.getBinding?.(expr.name);
      if (binding?.kind !== 'const' || binding.path?.node?.type !== 'VariableDeclarator') return undefined;
      return whenProduction(binding.path.node.init, binding.path, depth + 1);
    }
    default:
      return undefined;
  }
}

/** True when `p` sits in a branch that production provably never takes. */
function skippedInProduction(p: any, root: any): boolean {
  let child = p;
  let cur = p.parentPath;
  while (cur && child.node !== root.node) {
    const n = cur.node;
    if (n.type === 'IfStatement' || n.type === 'ConditionalExpression') {
      const taken = whenProduction(n.test, cur);
      if (child.node === n.consequent && taken === false) return true;
      if (child.node === n.alternate && taken === true) return true;
    } else if (n.type === 'LogicalExpression' && child.node === n.right) {
      const left = whenProduction(n.left, cur);
      if (n.operator === '&&' && left === false) return true;
      if (n.operator === '||' && left === true) return true;
    }
    child = cur;
    cur = cur.parentPath;
  }
  return false;
}

/** A statement that leaves the function: return, throw, `redirect()`, a block ending in one. */
function exits(stmt: any): boolean {
  if (!stmt) return false;
  if (stmt.type === 'ReturnStatement' || stmt.type === 'ThrowStatement') return true;
  if (stmt.type === 'BlockStatement') return exits(stmt.body[stmt.body.length - 1]);
  if (stmt.type === 'ExpressionStatement') {
    let e = stmt.expression;
    if (e?.type === 'AwaitExpression') e = e.argument;
    return e?.type === 'CallExpression' && /^(redirect|permanentRedirect|notFound)$/.test(calleeName(e.callee));
  }
  return false;
}

/**
 * `const session = await auth(); if (session) return` — the result is used only to turn
 * *signed-in* callers away, so everyone without a session falls through to the write.
 * True when every use of the bound result is a truthy test whose branch exits.
 */
function onlyInvertedGuard(call: any): boolean {
  let cur = call;
  while (cur.parentPath && /^(AwaitExpression|TSNonNullExpression|TSAsExpression|ParenthesizedExpression)$/.test(cur.parentPath.node.type)) {
    cur = cur.parentPath;
  }
  const decl = cur.parentPath;
  if (decl?.node?.type !== 'VariableDeclarator' || decl.node.init !== cur.node) return false;
  const refs: any[] = [];
  for (const name of parameterNames([decl.node.id])) {
    refs.push(...(decl.scope?.getBinding?.(name)?.referencePaths ?? []));
  }
  if (refs.length === 0) return false;
  return refs.every((ref) => {
    let e = ref;
    // `session.user`, `session?.user?.id`
    while (
      (e.parentPath?.node.type === 'MemberExpression' || e.parentPath?.node.type === 'OptionalMemberExpression') &&
      e.parentPath.node.object === e.node
    ) {
      e = e.parentPath;
    }
    const pn = e.parentPath?.node;
    if (pn?.type === 'UnaryExpression' && pn.operator === '!' && e.parentPath.parentPath?.node.type === 'UnaryExpression') {
      e = e.parentPath.parentPath; // `!!session`
    } else if (pn?.type === 'CallExpression' && calleeName(pn.callee) === 'Boolean') {
      e = e.parentPath;
    } else if (
      pn?.type === 'BinaryExpression' &&
      (pn.operator === '!=' || pn.operator === '!==') &&
      (pn.right?.type === 'NullLiteral' || (pn.right?.type === 'Identifier' && pn.right.name === 'undefined'))
    ) {
      e = e.parentPath;
    }
    const guard = e.parentPath?.node;
    return guard?.type === 'IfStatement' && guard.test === e.node && exits(guard.consequent);
  });
}

/*
 * Wrappers — `export default withX(handler)`, `authActionClient.action(fn)` — are judged by
 * what they do, not what they are called: see resolveWrapper in ./auth-helpers.ts. The old
 * name test (`/auth|protect|guard|session|.../`) is only the fallback for a wrapper whose
 * source cannot be read, and a handler credited that way is counted and said out loud.
 */

/** `!x`, `x == null`, `x === undefined`, `!a || !b`: true when the tested value is missing. */
function isMissingTest(test: any, isSession: (n: any) => boolean): boolean {
  if (!test) return false;
  if (test.type === 'UnaryExpression' && test.operator === '!') return touchesSession(test.argument, isSession);
  if (test.type === 'BinaryExpression' && (test.operator === '==' || test.operator === '===')) {
    const nullish = (n: any) => n?.type === 'NullLiteral' || (n?.type === 'Identifier' && n.name === 'undefined');
    return (nullish(test.right) && touchesSession(test.left, isSession)) || (nullish(test.left) && touchesSession(test.right, isSession));
  }
  if (test.type === 'LogicalExpression' && test.operator === '||') {
    return isMissingTest(test.left, isSession) || isMissingTest(test.right, isSession);
  }
  return false;
}

/** `x`, `x.user`, `!!x`, `x != null`, `a && b`: true when the tested value is present. */
function isPresentTest(test: any, isSession: (n: any) => boolean): boolean {
  if (!test) return false;
  if (isSession(test)) return true;
  if (test.type === 'UnaryExpression' && test.operator === '!' && test.argument?.type === 'UnaryExpression' && test.argument.operator === '!') {
    return touchesSession(test.argument.argument, isSession);
  }
  if (test.type === 'BinaryExpression' && (test.operator === '!=' || test.operator === '!==')) {
    const nullish = (n: any) => n?.type === 'NullLiteral' || (n?.type === 'Identifier' && n.name === 'undefined');
    return (nullish(test.right) && touchesSession(test.left, isSession)) || (nullish(test.left) && touchesSession(test.right, isSession));
  }
  if (test.type === 'LogicalExpression' && test.operator === '&&') {
    return isPresentTest(test.left, isSession) || isPresentTest(test.right, isSession);
  }
  return false;
}

function touchesSession(n: any, isSession: (n: any) => boolean): boolean {
  return someNode(n, isSession);
}

/** True when any node in `node` satisfies `pred`, skipping property names and object keys. */
function mentions(node: any, pred: (id: string) => boolean, depth = 0): boolean {
  if (!node || typeof node !== 'object' || depth > 60) return false;
  if (Array.isArray(node)) return node.some((c) => mentions(c, pred, depth + 1));
  if (node.type === 'Identifier') return pred(node.name);
  if ((node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') && !node.computed) {
    return mentions(node.object, pred, depth + 1);
  }
  if (node.type === 'ObjectProperty' && !node.computed) return mentions(node.value, pred, depth + 1);
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'leadingComments' || key === 'trailingComments' || key === 'extra') continue;
    const v = node[key];
    if (v && typeof v === 'object' && mentions(v, pred, depth + 1)) return true;
  }
  return false;
}

/** What a function is analysed with: the file's auth vocabulary and module-level facts. */
interface FileFacts {
  /** Names that stand for an auth check in this file — see ./auth-helpers.ts. */
  credited: ReadonlySet<string>;
  /** First-party helpers whose only check is Supabase `getSession()`. */
  sessionOnly: ReadonlySet<string>;
  /** Module-level `const KEY = process.env.SOME_SECRET` names, read by identifier. */
  secretConsts: ReadonlySet<string>;
  /** Module-level names bound to a `Set`, `Map`, hash and the like. */
  inProcess: ReadonlySet<string>;
}

interface ActionInfo {
  name: string;
  line: number;
  params: number;
  hasAuth: boolean;
  hasMutation: boolean;
  hasRead: boolean;
  hasValidation: boolean;
  serviceRoleLine: number | null;
  ownerScoped: boolean;
  mutationLine: number | null;
  /** Line of a Supabase `auth.getSession()` used where getUser() is required. */
  getSessionLine: number | null;
  hasSignatureCheck: boolean;
  /** Line where a whole request body is spread into a write. */
  spreadLine: number | null;
  looseSchemaLine: number | null;
  readsAuthHeader: boolean;
  /** Reads a credential-carrying header (not just any header). */
  readsCredentialHeader: boolean;
  /** References a server-side secret, e.g. `process.env.CRON_SECRET`. */
  readsSecretEnv: boolean;
  /** Calls that do something other than build the response. */
  workCalls: number;
  /** Reads caller-supplied input: a request body, query string or route param. */
  readsRequestInput: boolean;
  /** Line where the caller's payload object is written whole, not field by field. */
  wholePayloadLine: number | null;
  /** Calls into an LLM provider. */
  aiCalls: number;
  /** Callee names that are none of: response, trivial, request read, string/array helper, LLM. */
  effectCalls: string[];
  /** A signature check that authenticates the caller wherever the route lives. */
  verifiesSignature: boolean;
  /**
   * The only use of the session is to turn signed-in callers away
   * (`if (session) redirect('/')`): reachable by every signed-out caller, by design.
   */
  guestOnly: boolean;
  /** Wrappers credited on their name alone — their source was not read. */
  nameOnlyWrappers: WrapperVerdict[];
  /** What in this function a guest-only flow would have no business doing. */
  privilege: {
    /** A privilege field set to something a fresh sign-up should not get: `role: 'ADMIN'`. */
    escalation: string | null;
    /** Tables written that are not account tables (`?` when the table could not be told). */
    tables: string[];
    /** Calls that are none of: inert, a guest-flow call, a write judged by its table. */
    calls: string[];
  };
}

function analyseFunction(
  path: any,
  name: string,
  facts: FileFacts,
  /** Calls this function is handed to from outside its own path: `export default withAuth(handler)`. */
  outerWrappers: string[] = [],
  /** What a wrapper, spelled as in this file, does for what it wraps. */
  resolve: (wrapper: string) => WrapperVerdict = (w) => ({ kind: 'none', wrapper: w }),
): ActionInfo {
  const { credited, sessionOnly, secretConsts } = facts;
  const node = path.node;

  // The wrappers, first: one that attaches a session decides what counts as an auth
  // check inside the function, so it has to be known before the body is read.
  const wrapperNames: string[] = [];
  {
    let parent = path.parentPath;
    let hops = 0;
    while (parent && hops++ < 4) {
      if (parent.node?.type === 'CallExpression') wrapperNames.push(calleeName(parent.node.callee));
      parent = parent.parentPath;
    }
    wrapperNames.push(...outerWrappers);
  }
  const verdicts = wrapperNames.filter(Boolean).map(resolve);
  const session: SessionShape = { positions: [], members: [], ctx: false };
  for (const v of verdicts) {
    if (v.kind !== 'attaches' || !v.session) continue;
    session.positions.push(...v.session.positions);
    session.members.push(...v.session.members);
    session.ctx ||= v.session.ctx;
  }
  const info: ActionInfo = {
    name,
    line: node.loc?.start.line ?? 0,
    params: (node.params ?? []).length,
    hasAuth: false,
    hasMutation: false,
    hasRead: false,
    hasValidation: false,
    serviceRoleLine: null,
    ownerScoped: false,
    mutationLine: null,
    getSessionLine: null,
    hasSignatureCheck: false,
    spreadLine: null,
    looseSchemaLine: null,
    readsAuthHeader: false,
    readsCredentialHeader: false,
    readsSecretEnv: false,
    workCalls: 0,
    // A Server Action's arguments *are* its input; a Route Handler has to go
    // and read one, so that is detected below.
    readsRequestInput: false,
    wholePayloadLine: null,
    aiCalls: 0,
    effectCalls: [],
    verifiesSignature: false,
    guestOnly: false,
    nameOnlyWrappers: [],
    privilege: { escalation: null, tables: [], calls: [] },
  };

  // An id the caller passed in is not proof of ownership — it is the IDOR.
  // Only a principal resolved inside the function counts as scoping.
  const params = parameterNames(node.params ?? []);
  // Except `ctx`: in a wrapped action (`authActionClient.action(async ({ parsedInput, ctx })`)
  // or a tRPC procedure it is what the auth middleware resolved, not what the caller sent —
  // `ctx.userId` is the session's id.
  params.delete('ctx');

  // What an attaching wrapper handed in: `handler(req, res, session)` puts it in a
  // parameter, iron-session on `req.session`, next-auth v5 on `req.auth`, a safe-action
  // client in `ctx`. Server-resolved, so not caller input, and a guard on it is an auth check.
  const sessionNames = new Set<string>();
  const sessionPaths: string[] = [];
  {
    const ps: any[] = node.params ?? [];
    for (const i of session.positions) if (ps[i]) for (const n of parameterNames([ps[i]])) sessionNames.add(n);
    for (const m of session.members) {
      for (const p of ps) {
        if (p?.type === 'Identifier') sessionPaths.push(`${p.name}.${m}`);
        // `withIronSessionSsr(async ({ req }) => ...)`
        if (p?.type === 'ObjectPattern') {
          for (const prop of p.properties ?? []) {
            if (prop.type === 'ObjectProperty' && prop.value?.type === 'Identifier') sessionPaths.push(`${prop.value.name}.${m}`);
          }
        }
      }
    }
    if (session.ctx) {
      sessionNames.add('ctx');
      for (const p of ps) {
        if (p?.type !== 'ObjectPattern') continue;
        for (const prop of p.properties ?? []) {
          if (prop.type === 'ObjectProperty' && propertyKey(prop) === 'ctx') {
            for (const n of parameterNames([prop.value])) sessionNames.add(n);
          }
        }
      }
    }
    for (const n of sessionNames) params.delete(n);
  }
  const sessionDerived = new Set<string>();
  const isSessionExpr = (n: any): boolean => {
    if (n.type === 'Identifier') return sessionNames.has(n.name) || sessionDerived.has(n.name);
    if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') {
      const p = memberPath(n);
      return p !== '' && sessionPaths.some((sp) => p === sp || p.startsWith(sp + '.'));
    }
    return false;
  };
  if (sessionNames.size > 0 || sessionPaths.length > 0) {
    for (let pass = 0; pass < 2; pass++) {
      path.traverse({
        VariableDeclarator(inner: any) {
          if (inner.node.init && someNode(inner.node.init, isSessionExpr)) {
            for (const n of parameterNames([inner.node.id])) sessionDerived.add(n);
          }
        },
      });
    }
  }

  /**
   * Names holding the caller's payload as one object: a Server Action's own
   * parameter, or a variable assigned from a request-body read. Writing one of
   * these whole is mass assignment; pulling named fields out of it and writing
   * those is the safe pattern this rule used to report anyway.
   */
  const payloads = new Set<string>();
  for (const p of node.params ?? []) {
    // Only whole-object parameters. `({ name, role })` is already field by field.
    // Not `ctx` either: the auth middleware's context, see `params` above.
    if (p?.type === 'Identifier' && !/^(req|request|_req|_request|nextRequest|ctx)$/i.test(p.name)) {
      payloads.add(p.name);
    }
  }
  path.traverse({
    VariableDeclarator(inner: any) {
      const id = inner.node.id;
      if (id?.type !== 'Identifier') return; // destructuring is field by field
      let init = inner.node.init;
      while (init && (init.type === 'AwaitExpression' || init.type === 'TSNonNullExpression')) {
        init = init.argument ?? init.expression;
      }
      if (!init) return;
      if (init.type === 'CallExpression' || init.type === 'OptionalCallExpression') {
        const callee = calleeName(init.callee);
        // `await request.json()`, and `JSON.parse(raw)` over one of these.
        if (REQUEST_INPUT_READ.test(callee)) {
          payloads.add(id.name);
          return;
        }
        // `JSON.parse(raw)` and `Schema.parse(body)` both hand back the
        // caller's object with its key set intact — a passthrough schema
        // validates the fields it declares and keeps the rest (CTS044).
        // A local helper that reads named fields into a literal is NOT this:
        // its key set is fixed, which is exactly why it is safe to spread.
        if (
          /(^|\.)JSON\.parse$/.test(callee) ||
          PAYLOAD_PRESERVING_CALLS.has(calleeTail(init.callee))
        ) {
          for (const arg of init.arguments ?? []) {
            const root = arg?.type === 'Identifier' ? arg.name : rootObject(arg);
            if (root && payloads.has(root)) {
              payloads.add(id.name);
              break;
            }
          }
        }
        return;
      }
      // A plain alias: `const input = raw`.
      if (init.type === 'Identifier' && payloads.has(init.name)) payloads.add(id.name);
    },
  });
  // `export async function GET(_req, { params })` — the segment values are
  // caller-supplied input just as much as a body is.
  if (params.has('params')) info.readsRequestInput = true;

  // A handler that turns a caller away with 401/403 on the strength of what a credential
  // check returned — `const authInfo = getAuthInfoFromCookie(request); if (!authInfo) return
  // 401`, or a bearer key looked up in a table — authenticates, whatever the helper is called.
  // Two things do not count. A value that never touched a credential (`getUserId()` that mints
  // an id when none exists). And a claim: `x-actor-role: owner` compared to a literal, or an
  // approval flag read from a row the body's own id selected, is the caller describing
  // themselves or their request, not proving who they are — both were real bugs in the sample.
  const credentialDerived = new Set<string>();
  const touchesCredential = (n0: any) =>
    someNode(n0, (n) => (n.type === 'Identifier' && credentialDerived.has(n.name)) || isCredentialSource(n));

  /**
   * Names holding something the caller chose: a non-request parameter (`formData`, `id`,
   * `input`), a request body or query read, or a value computed from one. An id read from
   * one of these is the caller naming a row, not the session naming its owner — so it is
   * never owner scoping (CTS004), and `getUser(id)` on it is a lookup, not auth.
   */
  const callerParams = new Set([...params].filter((p) => !REQUEST_PARAM.test(p) && p !== 'res' && p !== 'response'));
  const callerDerived = new Set<string>();
  const isCallerName = (id: string) => callerParams.has(id) || payloads.has(id) || callerDerived.has(id);
  const readsCaller = (n0: any): boolean =>
    mentions(n0, isCallerName) ||
    someNode(n0, (n) => {
      if (n.type === 'CallExpression' || n.type === 'OptionalCallExpression') return REQUEST_INPUT_READ.test(calleeName(n.callee));
      if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') {
        return /(^|\.)(req|request|_req|_request|nextRequest)\??\.(body|query|nextUrl|url)$/.test(calleeName(n)) || /(^|\.)searchParams$/.test(calleeName(n));
      }
      return false;
    });
  const provesIdentityIn = (n0: any) =>
    someNode(n0, (n) => {
      if (n.type !== 'CallExpression' && n.type !== 'OptionalCallExpression') return false;
      const f = calleeName(n.callee);
      return (matchesAny(f, AUTH_CALLS) && !isUserLookup(n)) || credited.has(f);
    });
  // Two passes so a value derived from one declared later in a loop body still resolves.
  for (let pass = 0; pass < 2; pass++) {
    path.traverse({
      VariableDeclarator(inner: any) {
        const init = inner.node.init;
        if (!init) return;
        if (touchesCredential(init)) {
          for (const n of parameterNames([inner.node.id])) credentialDerived.add(n);
          return;
        }
        if (provesIdentityIn(init)) return;
        // Only the input itself, read or converted: `String(formData.get('userId'))`,
        // `body.userId`. A row looked up BY a caller's id is not the caller's input —
        // `report.userId !== user.id` after `findUnique({ where: { id } })` is the
        // ownership check, and reading it as caller-supplied was a false positive on it.
        const looksSomethingUp = someNode(init, (n) => {
          if (n.type !== 'CallExpression' && n.type !== 'OptionalCallExpression') return false;
          return !isInertCall(calleeName(n.callee), calleeTail(n.callee));
        });
        if (looksSomethingUp) return;
        if (readsCaller(init)) for (const n of parameterNames([inner.node.id])) callerDerived.add(n);
      },
    });
  }
  const localInProcess = inProcessNames(node.body);
  for (const n of facts.inProcess) localInProcess.add(n);

  /**
   * Every auth check found, as the path it sits at. Credited only after the walk, once
   * the writes are known too: a check counts if it runs before each write it guards.
   */
  const authEvents: any[] = [];
  /** Every write, as the path of the call that makes it. */
  const mutationPaths: any[] = [];
  /** Calls a guest-only flow does not make by design (writes are filtered out after the walk). */
  const guestCandidates: any[] = [];

  /** `admin.auth().deleteUser(uid)`: the method a call's result is immediately used for. */
  const methodCalledOnResult = (p: any): string | null => {
    let cur = p;
    while (cur.parentPath && /^(AwaitExpression|TSNonNullExpression|ParenthesizedExpression)$/.test(cur.parentPath.node.type)) {
      cur = cur.parentPath;
    }
    const member = cur.parentPath;
    const mt = member?.node?.type;
    if ((mt !== 'MemberExpression' && mt !== 'OptionalMemberExpression') || member.node.object !== cur.node) return null;
    const call = member.parentPath?.node;
    if ((call?.type !== 'CallExpression' && call?.type !== 'OptionalCallExpression') || call.callee !== member.node) {
      // `(await clerkClient()).users.getUser(id)`: a property of the result, then a call on it.
      let up = member;
      while (up.parentPath && (up.parentPath.node.type === 'MemberExpression' || up.parentPath.node.type === 'OptionalMemberExpression') && up.parentPath.node.object === up.node) {
        up = up.parentPath;
      }
      const c = up.parentPath?.node;
      if (up !== member && (c?.type === 'CallExpression' || c?.type === 'OptionalCallExpression') && c.callee === up.node) {
        return calleeTail(up.node);
      }
      return null;
    }
    return member.node.property?.name ?? '*';
  };

  const inspect = (inner: any) => {
    const full = calleeName(inner.node.callee);
    const tail = calleeTail(inner.node.callee);
    if (!RESPONSE_CALLS.test(full) && !TRIVIAL_CALLS.test(full)) info.workCalls++;
    if (REQUEST_INPUT_READ.test(full)) info.readsRequestInput = true;
    const isAiCall = AI_CALLS.test(full);
    if (isAiCall) info.aiCalls++;
    else if (!isInertCall(full, tail) && !info.effectCalls.includes(full)) info.effectCalls.push(full);
    if (!isAiCall && !isInertCall(full, tail) && !isGuestFlowCall(full, tail)) guestCandidates.push(inner);
    // `requireVerifiedActor(req.headers, 'read')`, `authorizeRequest(request)`: an
    // authorisation verb handed the request. Only the pair counts — `requireEnv()` or
    // `ensureDirectory(path)` is not handed a request to check.
    if (
      AUTH_VERB_HELPER.test(tail) &&
      (inner.node.arguments ?? []).some((arg: any) => isRequestish(arg))
    ) {
      authEvents.push(inner);
    }

    // `supabase.auth.getSession()` reads the cookie without asking the auth
    // server whether the token is still valid, so it proves nothing on the
    // server. It must not satisfy the auth check via the generic `getSession`
    // entry, which exists for hand-rolled helpers — nor through a first-party
    // helper, whatever it is named, whose only check is that call.
    const isSupabaseGetSession = SUPABASE_GET_SESSION.test(full) || sessionOnly.has(full);
    // `admin.auth().deleteUser(uid)`, `(await clerkClient()).users.getUser(id)`: the auth-named
    // call only hands back an admin client. The call made on it is judged on its own.
    const accessorOnly = isAccessorOnly(methodCalledOnResult(inner));
    // `clerkClient.users.getUser(id)`, `admin.auth().getUser(uid)`, or `getUser(id)` on an id
    // the caller supplied: looking a user up is not checking who is calling.
    const firstArg = inner.node.arguments?.[0];
    const lookup =
      tail === 'getUser' &&
      (isUserLookup(inner.node) ||
        (firstArg !== undefined && !isRequestish(firstArg) && !touchesCredential(firstArg) && readsCaller(firstArg)));
    if (isSupabaseGetSession) {
      info.getSessionLine ??= inner.node.loc?.start.line ?? info.line;
    } else if (accessorOnly || lookup) {
      // not an auth check
    } else if (matchesAny(full, AUTH_CALLS)) {
      authEvents.push(inner);
    } else if (credited.has(full)) {
      // The check lives in a first-party helper this file imports, or one
      // defined above in the same file. Matched on the whole callee name, not
      // its tail: a helper is called by the name this file binds it to, and
      // crediting `crypto.verify()` because some other module exports a
      // `verify` helper would hide a real finding.
      authEvents.push(inner);
    }
    if (matchesAny(full, AUTH_WRAPPERS) && !accessorOnly) authEvents.push(inner);
    if (matchesAny(full, SIGNATURE_CHECKS) || SIGNATURE_VERIFY_NAME.test(tail)) info.hasSignatureCheck = true;
    if (STRONG_SIGNATURE_NAME.test(tail) || /(^|\.)(webhooks\.)?constructEvent(Async)?$/.test(full)) {
      info.verifiesSignature = true;
    }
    if (VALIDATION_CALLS.has(tail)) info.hasValidation = true;
    if (
      MUTATION_CALLS.has(tail) &&
      !NOT_A_DATA_WRITE.test(full) &&
      !NOT_A_DATA_RECEIVER.test(full) &&
      !isInProcessMutation(inner.node, localInProcess) &&
      !isAiCall
    ) {
      info.hasMutation = true;
      mutationPaths.push(inner);
      if (info.mutationLine === null) {
        info.mutationLine = inner.node.loc?.start.line ?? info.line;
      }
      // What actually reaches the columns: `.update({ ...body })`,
      // `.insert(body)`, `prisma.x.update({ data: { ...body } })` — the last of
      // which hides one level down, where a top-level scan never saw it.
      const inspectWritten = (arg: any, depth: number): void => {
        if (!arg || depth > 2) return;
        if (arg.type === 'Identifier') {
          if (payloads.has(arg.name)) {
            info.wholePayloadLine ??= arg.loc?.start.line ?? info.line;
          }
          return;
        }
        if (arg.type !== 'ObjectExpression') return;
        for (const prop of arg.properties ?? []) {
          if (prop?.type === 'SpreadElement') {
            // Only the caller's own object counts. Spreading a locally built
            // literal — `...(x && { k: v })`, or an object a helper assembled
            // from named fields — writes a key set this code chose, which is
            // the safe pattern rather than the bug.
            const root = rootObject(prop.argument);
            if (!root || !payloads.has(root)) continue;
            info.spreadLine ??= prop.loc?.start.line ?? info.line;
            continue;
          }
          if (prop?.type !== 'ObjectProperty') continue;
          if (!WRITE_PAYLOAD_KEYS.has(propertyKey(prop))) continue;
          inspectWritten(prop.value, depth + 1);
        }
      };
      for (const arg of inner.node.arguments ?? []) inspectWritten(arg, 0);
    }
    if (tail === 'from' || tail === 'select' || tail === 'findMany' || tail === 'findUnique' || tail === 'findFirst') {
      info.hasRead = true;
    }
    // Reading a webhook-signature header counts as participating in
    // verification (see SIGNATURE_HEADERS).
    for (const arg of inner.node.arguments ?? []) {
      if (arg?.type !== 'StringLiteral') continue;
      if (SIGNATURE_HEADERS.test(arg.value)) info.hasSignatureCheck = true;
      if (CREDENTIAL_HEADERS.test(arg.value) && /headers\.get$/.test(full)) {
        info.readsCredentialHeader = true;
      }
    }

    // Raw SQL: db.query(`DELETE FROM ...`) / sql`UPDATE ...`
    if (tail === 'query' || tail === 'execute' || tail === 'unsafe' || tail === 'raw') {
      for (const arg of inner.node.arguments ?? []) {
        const text =
          arg?.type === 'StringLiteral'
            ? arg.value
            : arg?.type === 'TemplateLiteral'
              ? arg.quasis.map((q: any) => q.value.raw).join(' ')
              : '';
        if (/\b(insert\s+into|update\s+|delete\s+from|drop\s+|alter\s+)/i.test(text)) {
          info.hasMutation = true;
          mutationPaths.push(inner);
          if (info.mutationLine === null) {
            info.mutationLine = inner.node.loc?.start.line ?? info.line;
          }
        }
      }
    }
  };

  path.traverse({
    CallExpression: inspect,
    OptionalCallExpression: inspect,
    TaggedTemplateExpression(inner: any) {
      const tag = calleeName(inner.node.tag);
      if (!/(^|\.)sql$/.test(tag)) return;
      const text = inner.node.quasi.quasis.map((q: any) => q.value.raw).join(' ');
      if (/\b(insert\s+into|update\s+|delete\s+from)/i.test(text)) {
        info.hasMutation = true;
        mutationPaths.push(inner);
        if (info.mutationLine === null) {
          info.mutationLine = inner.node.loc?.start.line ?? info.line;
        }
      }
    },
    // A signature header named anywhere in the handler — `headers.get('stripe-signature')`,
    // but also `headers.get(name) ?? 'x-webhook-signature'` — means it takes part in
    // verification. Only call arguments used to count, which missed the fallback form.
    StringLiteral(inner: any) {
      if (SIGNATURE_HEADERS.test(inner.node.value)) info.hasSignatureCheck = true;
    },
    MemberExpression(inner: any) {
      const full = calleeName(inner.node);
      if (/headers\.get$/.test(full) || full.endsWith('CRON_SECRET')) info.readsAuthHeader = true;
      if (SECRET_ENV.test(full)) info.readsSecretEnv = true;
      // `parsed.isValidSignature` — an SDK hands back the verdict as a property.
      if (STRONG_SIGNATURE_NAME.test(calleeTail(inner.node))) info.verifiesSignature = true;
      // `request.url` / `req.nextUrl` are read to get at the query string.
      if (/(^|\.)searchParams$/.test(full) || /(^|\.)(req|request)\??\.(url|nextUrl)$/i.test(full)) {
        info.readsRequestInput = true;
      }
      for (const hint of SERVICE_ROLE_HINTS) {
        if (full.endsWith(hint)) {
          info.serviceRoleLine ??= inner.node.loc?.start.line ?? info.line;
        }
      }
      // `body.userId` after `const body = await req.json()` is the caller naming an id;
      // only a principal the function resolved itself scopes the write.
      const root = rootObject(inner.node);
      // `req.session.user.id` under iron-session: the request's root, but a server-resolved value.
      if (!root || (!params.has(root) && !isCallerName(root)) || isSessionExpr(inner.node)) {
        for (const hint of OWNER_HINTS) {
          if (full === hint || full.endsWith('.' + hint)) info.ownerScoped = true;
        }
      }
    },
    ObjectProperty(inner: any) {
      // `where: { ownerId: me.id }` — a key naming the owner column, given a value that is
      // not the caller's own input. `{ userId: body.userId }` is not scoping.
      const prop = inner.node;
      if (prop.computed || prop.shorthand || !OWNER_IDENTIFIERS.has(propertyKey(prop))) return;
      if (prop.value?.type === 'StringLiteral' || prop.value?.type === 'NumericLiteral') return;
      const fromSession = someNode(prop.value, isSessionExpr);
      if (!fromSession && (mentions(prop.value, (id) => params.has(id) || isCallerName(id)) || readsCaller(prop.value))) return;
      info.ownerScoped = true;
    },
    Identifier(inner: any) {
      if (SERVICE_ROLE_HINTS.includes(inner.node.name)) {
        info.serviceRoleLine ??= inner.node.loc?.start.line ?? info.line;
      }
      // Only a reference to a binding counts — not `body.userId`'s property name, nor an
      // object key (handled above) — and not one holding what the caller sent.
      if (
        OWNER_IDENTIFIERS.has(inner.node.name) &&
        !params.has(inner.node.name) &&
        !isCallerName(inner.node.name) &&
        inner.isReferencedIdentifier()
      ) {
        info.ownerScoped = true;
      }
      // `const { searchParams } = new URL(request.url)` — destructured, so it
      // never appears as a member expression.
      if (inner.node.name === 'searchParams') info.readsRequestInput = true;
      // `const API_KEY = process.env.CRON_API_KEY` at module scope, compared below.
      if (secretConsts.has(inner.node.name)) info.readsSecretEnv = true;
    },
  });

  // A handler that turns a caller away with 401/403 on the strength of what a credential
  // check returned — `const authInfo = getAuthInfoFromCookie(request); if (!authInfo) return
  // 401`, or a bearer key looked up in a table — authenticates, whatever the helper is called.
  // Two things do not count. A value that never touched a credential (`getUserId()` that mints
  // an id when none exists). And a claim: `x-actor-role: owner` compared to a literal, or an
  // approval flag read from a row the body's own id selected, is the caller describing
  // themselves or their request, not proving who they are — both were real bugs in the sample.
  // (credentialDerived is worked out above, before the call walk.) A 401/403 guard on it
  // is an auth check like any other, and is placed like one: a guard after the write
  // turns the caller away once the row is already changed.
  const guardEvents: any[] = [];
  /** `if (session) { ...write... }` on a wrapper-provided session: the writes inside it. */
  const presentGuards: any[] = [];
  const hasSession = sessionNames.size > 0 || sessionPaths.length > 0;
  path.traverse({
    IfStatement(inner: any) {
      const test = inner.node.test;
      if (touchesCredential(test) && someNode(inner.node.consequent, isUnauthorisedExit)) {
        guardEvents.push(inner);
        return;
      }
      if (!hasSession) return;
      // `if (!req.session.user) return res.status(401)...`, `if (!ctx.user) throw ...`
      if (isMissingTest(test, isSessionExpr) && (exits(inner.node.consequent) || someNode(inner.node.consequent, isUnauthorisedExit))) {
        guardEvents.push(inner);
      } else if (isPresentTest(test, isSessionExpr)) {
        presentGuards.push(inner);
      }
    },
  });
  const insidePresentGuard = (m: any) =>
    presentGuards.some((g) => !skippedInProduction(g, path) && m.findParent((q: any) => q.node === g.node.consequent));

  /**
   * Whether a check at `ev` protects the write at `m`: it runs, in production, before it.
   * Compared inside the innermost function holding both, so a check and a write in the
   * same `$transaction` callback are ordered by where they sit in it.
   */
  const guards = (ev: any, m: any | null): boolean => {
    if (m === null) return runPosition(ev, path) !== NEVER_RUNS;
    const scope = commonFunction(ev, m, path);
    const at = runPosition(ev, scope);
    return at !== NEVER_RUNS && at <= runPosition(m, scope);
  };
  const live = authEvents.filter((ev) => !skippedInProduction(ev, path));
  const inverted = live.filter((ev) => onlyInvertedGuard(ev));
  const events = [
    ...live.filter((ev) => !inverted.includes(ev)),
    ...guardEvents.filter((ev) => !skippedInProduction(ev, path)),
  ];
  info.hasAuth =
    (events.length > 0 || presentGuards.length > 0) &&
    (mutationPaths.length === 0
      ? events.some((ev) => guards(ev, null)) || presentGuards.length > 0
      : mutationPaths.every((m) => insidePresentGuard(m) || events.some((ev) => guards(ev, m))));

  // An action wrapped by an auth HOC inherits the check from its wrapper — when the
  // wrapper provably requires one, or (the fallback) when all that is known is its name.
  verdicts.forEach((v, i) => {
    const wrapper = wrapperNames[i]!;
    if (v.kind === 'requires') info.hasAuth = true;
    if (v.kind === 'name-only') {
      if (!info.hasAuth) info.nameOnlyWrappers.push(v);
      info.hasAuth = true;
    }
    // `verifySignatureAppRouter(async (req) => ...)` (Upstash QStash) and the like.
    if (STRONG_SIGNATURE_NAME.test(wrapper)) info.verifiesSignature = true;
    if (VALIDATION_CALLS.has(wrapper.slice(wrapper.lastIndexOf('.') + 1))) info.hasValidation = true;
  });

  // Nothing authenticates, and a session WAS read — only to turn signed-in callers away.
  info.guestOnly = !info.hasAuth && inverted.length > 0;
  // What it does, for deciding whether public-by-design is believable (see handle()).
  if (!info.hasAuth) {
    const written = new Set(mutationPaths.map((m) => m.node));
    for (const c of guestCandidates) {
      if (written.has(c.node)) continue;
      const name = calleeName(c.node.callee) || '(anonymous call)';
      if (!info.privilege.calls.includes(name)) info.privilege.calls.push(name);
    }
    for (const m of mutationPaths) {
      const n = m.node;
      let table: string | null;
      if (n.type === 'TaggedTemplateExpression') {
        table = sqlTable(n.quasi.quasis.map((q: any) => q.value.raw).join(' '));
      } else {
        const sql = (n.arguments ?? [])
          .map((a: any) => (a?.type === 'StringLiteral' ? a.value : a?.type === 'TemplateLiteral' ? a.quasis.map((q: any) => q.value.raw).join(' ') : ''))
          .join(' ');
        table = /\b(insert\s+into|update\s+|delete\s+from)/i.test(sql) ? sqlTable(sql) : mutationTable(n);
      }
      const label = table ?? '?';
      if ((table === null || !ACCOUNT_TABLE.test(table)) && !info.privilege.tables.includes(label)) {
        info.privilege.tables.push(label);
      }
    }
    info.privilege.escalation = privilegeEscalation(path, isCallerName, new Set(mutationPaths.map((m) => m.node)));
  }

  return info;
}

/**
 * `role: 'ADMIN'`, `isAdmin: true`, `user.role = role`: a privilege field given a value a
 * fresh account should not get, or one the caller chose. Anywhere in the function except a
 * query filter — `where: { role: 'admin' }` reads, it does not grant.
 */
function privilegeEscalation(
  path: any,
  isCallerName: (id: string) => boolean,
  written: ReadonlySet<any>,
): string | null {
  let found: string | null = null;
  /**
   * Whether an object literal can reach a write: it sits in a write's arguments (or a
   * `.values()` / `.set()` chained on one), or is bound to a name first
   * (`const data = { role }; create({ data })`). Not a response body, not a return
   * value: `NextResponse.json({ user: { role: user.role } })` after a login grants nothing.
   */
  const reachesWrite = (p: any): boolean => {
    let cur = p.parentPath;
    while (cur && cur.node !== path.node) {
      const t = cur.node.type;
      if (t === 'CallExpression' || t === 'OptionalCallExpression' || t === 'NewExpression') {
        return written.has(cur.node) || someNode(cur.node.callee, (n) => written.has(n));
      }
      if (t === 'VariableDeclarator' || t === 'AssignmentExpression') return true;
      if (t === 'ReturnStatement' || t === 'ArrowFunctionExpression' || t === 'FunctionExpression' || t === 'ThrowStatement') return false;
      cur = cur.parentPath;
    }
    return false;
  };
  const judge = (key: string, value: any, at: any) => {
    if (found || !PRIVILEGE_KEY.test(key)) return;
    // `const role = 'member'; ... { role }` — a local constant is judged by its value.
    if (value?.type === 'Identifier' && !isCallerName(value.name)) {
      const binding = at.scope?.getBinding?.(value.name);
      const init = binding?.kind === 'const' ? binding.path?.node?.init : null;
      if (init) value = init;
    }
    // A caller-chosen value is escalation whatever it is; anything else unrecognised is too.
    if (value && mentions(value, isCallerName)) found = `${key}: <caller-supplied>`;
    else if (!isBenignPrivilegeValue(value)) found = snippetOf(key, value);
  };
  path.traverse({
    ObjectProperty(inner: any) {
      if (inner.node.computed) return;
      const inFilter = inner.findParent(
        (q: any) => q.node?.type === 'ObjectProperty' && FILTER_KEYS.has(propertyKey(q.node)),
      );
      if (inFilter || !reachesWrite(inner)) return;
      judge(propertyKey(inner.node), inner.node.value, inner);
    },
    AssignmentExpression(inner: any) {
      const left = inner.node.left;
      if (left?.type !== 'MemberExpression' || left.computed) return;
      judge(left.property?.name ?? '', inner.node.right, inner);
    },
  });
  return found;
}

function snippetOf(key: string, value: any): string {
  if (value?.type === 'StringLiteral') return `${key}: '${value.value}'`;
  if (value?.type === 'BooleanLiteral' || value?.type === 'NumericLiteral') return `${key}: ${value.value}`;
  const name = value ? calleeName(value) : '';
  return name ? `${key}: ${name}` : `${key}: <computed>`;
}

/**
 * Keys that hold the columns being written, one level inside the call argument.
 * `prisma.user.update({ where, data: { ... } })`, `db.insert(t).values({ ... })`.
 */
const WRITE_PAYLOAD_KEYS = new Set(['data', 'values', 'set', 'create', 'update', 'insert', 'doc']);

/**
 * Calls that return the caller's object with its keys intact. A schema `.parse`
 * belongs here because a passthrough schema — the CTS044 case — validates what
 * it declares and hands back everything else untouched.
 */
const PAYLOAD_PRESERVING_CALLS = new Set([
  'parse', 'parseAsync', 'safeParse', 'safeParseAsync', 'validate', 'validateSync', 'cast',
]);

/*
 * ---------------------------------------------------------------- guest-only actions
 *
 * `const session = await auth(); if (session) redirect('/dashboard')` in a sign-up,
 * sign-in or forgot-password action reads the session only to turn signed-in callers
 * away. It is public by design, like a sign-in route, and was a CTS001 critical. It is
 * reported low — but only when what it does is what such a flow does: write the account
 * tables, hash a password, send an email. A name list alone once hid two real bugs here
 * (`register` hardcoding an Admin role; `leads` running paid enrichment), so the
 * downgrade is decided on the writes and calls themselves, and anything this cannot
 * positively recognise keeps the full severity.
 */

/** Tables a sign-up / sign-in / password-reset flow writes by design. */
const ACCOUNT_TABLE =
  /^(users?|user_?profiles?|profiles?|accounts?|user_?accounts?|sessions?|user_?sessions?|verification_?tokens?|verifications?|email_?verifications?(_?tokens?)?|(password_?)?reset_?tokens?|password_?resets?|password_?reset_?requests?|magic_?links?|login_?tokens?|otps?|otp_?codes?|one_?time_?(codes?|tokens?|passwords?))$/i;

/** `usersTable`, `schema.users`, `UserModel`, `"public"."users"` -> `users`, `User` -> `user`. */
function tableKey(raw: string): string {
  const last = raw.replace(/["'`]/g, '').split('.').pop() ?? '';
  return last.replace(/(Table|_table|Tbl|Schema|Model|Collection|Repo|Repository)$/, '');
}

/** Fields whose value decides what a user may do. */
const PRIVILEGE_KEY =
  /^(roles?|user_?roles?|is_?admin|admin|is_?super_?(admin|user)?|super_?user|is_?staff|permissions?|scopes?|access_?level|privileges?|is_?owner|plan|tier|subscription_?(tier|plan))$/i;

/** A value for one of those that grants more than a fresh sign-up should get. */
const PRIVILEGED_VALUE =
  /^(.*admin.*|owner|super.*|staff|root|manager|moderator|mod|editor|pro|premium|enterprise|unlimited|business|paid|lifetime|all|\*|write|full|god)$/i;

/** True when `v`, written to a privilege field, provably grants nothing special. */
function isBenignPrivilegeValue(v: any, depth = 0): boolean {
  if (!v || depth > 4) return false;
  switch (v.type) {
    case 'BooleanLiteral':
      return v.value === false;
    case 'NullLiteral':
      return true;
    case 'NumericLiteral':
      return v.value === 0;
    case 'Identifier':
      return v.name === 'undefined';
    case 'StringLiteral':
      return !PRIVILEGED_VALUE.test(v.value.trim());
    case 'TemplateLiteral':
      return v.expressions.length === 0 && !PRIVILEGED_VALUE.test(v.quasis.map((q: any) => q.value.cooked ?? '').join('').trim());
    case 'ArrayExpression':
      return v.elements.every((e: any) => isBenignPrivilegeValue(e, depth + 1));
    case 'ObjectExpression':
      return v.properties.length === 0;
    // `Role.USER`, `UserRole.Member` — an enum member, judged by its name.
    case 'MemberExpression':
      return !v.computed && v.property?.type === 'Identifier' && /^[A-Z]/.test(calleeName(v)) && !PRIVILEGED_VALUE.test(v.property.name);
    case 'ConditionalExpression':
      return isBenignPrivilegeValue(v.consequent, depth + 1) && isBenignPrivilegeValue(v.alternate, depth + 1);
    case 'TSAsExpression':
    case 'TSSatisfiesExpression':
    case 'TSNonNullExpression':
      return isBenignPrivilegeValue(v.expression, depth + 1);
    default:
      return false;
  }
}

/** Keys under which an object is a query filter, not a write: `where: { role: 'admin' }`. */
const FILTER_KEYS = new Set(['where', 'filter', 'select', 'include', 'orderBy', 'omit', 'query', 'match']);

/**
 * The table a write goes to, or null when it cannot be told. Prisma `db.user.create`,
 * Supabase `from('profiles').insert`, Drizzle `db.insert(users)`, Mongo
 * `db.collection('users').insertOne`, Mongoose `User.create` / `user.save()`.
 */
function mutationTable(call: any): string | null {
  const callee = call.callee;
  if (callee?.type !== 'MemberExpression' && callee?.type !== 'OptionalMemberExpression') return null;
  const tail = calleeTail(callee);
  // `from('profiles')` / `collection('users')` / `table('users')` somewhere up the chain.
  let cur = callee.object;
  for (let guard = 0; cur && guard < 12; guard++) {
    if (cur.type === 'CallExpression' || cur.type === 'OptionalCallExpression') {
      const t = calleeTail(cur.callee);
      const arg = cur.arguments?.[0];
      if (/^(from|collection|table|into)$/.test(t) && arg?.type === 'StringLiteral') return tableKey(arg.value);
      cur = cur.callee;
      continue;
    }
    if (cur.type === 'MemberExpression' || cur.type === 'OptionalMemberExpression') {
      cur = cur.object;
      continue;
    }
    break;
  }
  // Drizzle: `db.insert(users)`, `tx.update(schema.users)`, `db.delete(sessions)`.
  const first = call.arguments?.[0];
  if (/^(insert|update|delete)$/.test(tail) && (first?.type === 'Identifier' || first?.type === 'MemberExpression')) {
    const receiver = calleeName(callee.object);
    if (/^(db|tx|trx|database|drizzle|client|conn)$|\.db$/.test(receiver)) return tableKey(calleeName(first));
  }
  // Prisma / Mongoose: the segment before the verb.
  const full = calleeName(callee);
  const segs = full.split('.');
  if (segs.length >= 2) {
    const before = segs[segs.length - 2]!;
    if (!/^(db|prisma|tx|trx|client|database|\$transaction|this|\*)$/.test(before)) return tableKey(before);
  }
  return null;
}

/** Table named in raw SQL: `INSERT INTO users`, `UPDATE "public"."profiles"`, `DELETE FROM sessions`. */
function sqlTable(text: string): string | null {
  const m = /\b(?:insert\s+into|update|delete\s+from)\s+((?:["`]?\w+["`]?\.)?["`]?\w+["`]?)/i.exec(text);
  return m ? tableKey(m[1]!) : null;
}

/**
 * Calls a guest-only flow makes by design, judged by name: reading, the auth provider's
 * own sign-up / sign-in / reset calls, password hashing and token generation, sending
 * the confirmation email, rate limiting and captcha, cache revalidation. A write to an
 * account table (named like Prisma's `db.user.create`) is one too; any other write is not.
 */
const GUEST_FLOW_TAILS = new Set([
  // Reads and query-builder links.
  'findUnique', 'findUniqueOrThrow', 'findFirst', 'findFirstOrThrow', 'findMany', 'findOne', 'findById',
  'count', 'exists', 'select', 'from', 'eq', 'neq', 'ilike', 'like', 'match', 'where', 'limit', 'single',
  'maybeSingle', 'returning', 'values', 'set', 'onConflictDoNothing', 'onConflictDoUpdate', 'first',
  'all', 'then', 'execute', 'executeTakeFirst', 'lean', 'exec',
  // The auth provider's own flow.
  'signIn', 'signUp', 'signOut', 'signUpEmail', 'signInEmail', 'signInWithPassword', 'signInWithOtp',
  'signInWithOAuth', 'resetPasswordForEmail', 'verifyOtp', 'exchangeCodeForSession', 'forgetPassword',
  'requestPasswordReset', 'resetPassword', 'sendVerificationEmail', 'createSession', 'createSessionCookie',
  'createBlankSessionCookie', 'invalidateSession', 'setSession',
  // Hashing and token generation.
  'hash', 'hashSync', 'genSalt', 'genSaltSync', 'compare', 'compareSync', 'verify', 'hashPassword',
  'verifyPassword', 'randomBytes', 'randomUUID', 'randomInt', 'getRandomValues', 'nanoid', 'uuid', 'uuidv4',
  'v4', 'v7', 'createId', 'cuid', 'generateId', 'generateToken', 'generateRandomString', 'sign',
  'setProtectedHeader', 'setExpirationTime', 'setIssuedAt', 'digest', 'toString',
  // Next.js plumbing.
  'revalidatePath', 'revalidateTag', 'cookies', 'headers', 'redirect', 'permanentRedirect', 'notFound',
  'after',
]);

function isGuestFlowCall(full: string, tail: string): boolean {
  if (!full) return false;
  if (matchesAny(full, AUTH_CALLS)) return true;
  if (/(^|\.)auth\.(api\.)?\w+$/.test(full)) return true; // supabase.auth.*, better-auth's auth.api.*
  if (/^(bcrypt|bcryptjs|argon2|crypto|scrypt|jose|jwt)\./.test(full)) return true;
  if (/rate_?limit|ratelimit|throttle|captcha|turnstile/i.test(full)) return true;
  if (VALIDATION_CALLS.has(tail)) return true;
  // Getting the client the writes go through: `createClient()`, `createServerClient(...)`.
  if (/^(create\w*Client|getSupabase\w*|getDb|getPrisma)$/.test(tail)) return true;
  // The confirmation / reset email: `resend.emails.send`, `transporter.sendMail`, `sendResetEmail`.
  if (/^send\w*(e?mail)$/i.test(tail) || /(^|\.)(emails?|resend|mail|mailer|transporter|nodemailer|sendgrid|sgMail|postmark|ses)\.send\w*$/i.test(full)) {
    return true;
  }
  // `cookies().set(...)`, `cookieStore.delete(...)`.
  if (/(^|\.)(cookies|cookieStore)\.(set|delete|get)$/.test(full)) return true;
  if (MUTATION_CALLS.has(tail)) {
    const segs = full.split('.');
    return segs.length >= 2 && ACCOUNT_TABLE.test(tableKey(segs[segs.length - 2]!));
  }
  // Drizzle's `db.update(users).set({...})`: the update itself is judged as a write.
  if (tail === 'set') return /\.update\.set$/.test(full);
  return GUEST_FLOW_TAILS.has(tail);
}

/**
 * Calls that spend money or reach a paid third party on the caller's say-so: payment,
 * lead enrichment, SMS. Used for routes whose NAME says public intake, where any other
 * unrecognised call is normal and cannot be held against it.
 */
const PAID_CALL =
  /stripe|checkout|payment|paypal|paddle|lemon_?squeezy|braintree|\bcharge|enrich|apollo|clearbit|hunter|peopledatalabs|proxycurl|zoominfo|lusha|snov|dropcontact|rocketreach|twilio|\bsms/i;

function propertyKey(prop: any): string {
  const key = prop?.key;
  if (!key) return '';
  return key.type === 'Identifier' ? key.name : key.type === 'StringLiteral' ? key.value : '';
}

const HTTP_MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/** An App Router route handler — including the root one, `app/route.ts`. */
function isRouteHandlerFile(relPath: string): boolean {
  return /(^|\/)(src\/)?app\/(.*\/)?route\.(t|j)sx?$/.test(relPath);
}

/** A Pages Router API route: its default export answers every method. */
function isPagesApiFile(relPath: string): boolean {
  return /(^|\/)(src\/)?pages\/api\/.+\.(t|j)sx?$/.test(relPath) && !/\.d\.ts$|\.(test|spec)\.[tj]sx?$/.test(relPath);
}

/**
 * The method label for a Pages Router handler. It answers GET as well as POST, so it is
 * judged on a write it actually makes, never on its method alone (not in HTTP_MUTATION_METHODS).
 */
const ANY_METHOD = 'ANY';

const ROUTE_METHOD = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/;

function unwrapExpression(p: any): any {
  let cur = p;
  while (cur?.node && /^(TSAsExpression|TSSatisfiesExpression|TSNonNullExpression|ParenthesizedExpression)$/.test(cur.node.type)) {
    cur = cur.get('expression');
  }
  return cur;
}

export const serverActionsScanner: Scanner = {
  name: 'Next.js Server Actions & Route Handlers',

  applies(ctx) {
    return ctx.framework.nextjs !== null || ctx.files.some(isScript);
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    let actionCount = 0;
    let routeCount = 0;
    // Shared across the whole scan: resolving `@/lib/auth` costs one parse of
    // that helper, however many actions import it.
    const helperOptions = {
      authCalls: AUTH_CALLS,
      authWrappers: AUTH_WRAPPERS,
      index: buildModuleIndex(ctx.files, ctx.root),
      cache: new Map<string, ModuleAuth>(),
    };

    const effectOptions = {
      isInert: isInertCall,
      index: helperOptions.index,
      cache: new Map<string, ReadonlySet<string>>(),
    };

    // First-party helpers that only do what a guest-only flow does (see isGuestFlowCall):
    // the same whole-body fixed point as the inert helpers, with a wider whitelist.
    // An LLM call is inert for the method-only question, but not here — it costs money.
    const guestFlowOptions = {
      isInert: (full: string, tail: string) =>
        !AI_CALLS.test(full) && (isInertCall(full, tail) || isGuestFlowCall(full, tail)),
      index: helperOptions.index,
      cache: new Map<string, ReadonlySet<string>>(),
    };

    const wrapperOptions: WrapperOptions = {
      ...helperOptions,
      isCredentialSource,
      isUnauthorisedExit,
      exits,
      wrapperCache: new Map(),
      astCache: new Map(),
    };
    /** Handlers credited to a wrapper by its name alone, by wrapper (and package). */
    const nameOnly = new Map<string, string[]>();

    for (const file of ctx.files) {
      if (!isScript(file)) continue;
      const source = read(file);
      if (source === null) continue;

      const relPath = rel(ctx.root, file);
      const routeFile = isRouteHandlerFile(relPath);
      const pagesApi = !routeFile && isPagesApiFile(relPath);
      if (!routeFile && !pagesApi && !source.includes('use server')) continue;

      // One file that cannot be read — a parse failure, or a stack overflow on a
      // pathologically deep expression — is that file NOT checked. It must neither
      // end the scan for every other file nor pass as clear.
      try {
        const ast = parseSource(source, file);
        if (!ast) {
          result.incomplete!.push(
            `could not parse ${relPath}, so its Server Actions / Route Handlers were NOT checked for authorization`,
          );
          continue;
        }
        analyseFile(file, relPath, source, ast, routeFile, pagesApi);
      } catch (err) {
        result.incomplete!.push(
          `could not analyse ${relPath} (${err instanceof Error ? err.message : String(err)}), so its ` +
            'Server Actions / Route Handlers were NOT checked for authorization',
        );
      }
    }

    function analyseFile(file: string, relPath: string, source: string, ast: any, routeFile: boolean, pagesApi: boolean) {
      const suppress = new Suppressions(source);
      // The program's own directive prologue. A regex over the first lines used to read
      // an indented inline `'use server'` as the module's, turning every export into an action.
      const programUseServer = hasDirective(ast.program, 'use server');
      const helpers = authHelpersFor(file, helperOptions, ast);
      const facts: FileFacts = {
        credited: helpers.credited,
        sessionOnly: helpers.sessionOnly,
        secretConsts: moduleSecretConsts(ast),
        inProcess: new Set(
          (ast.program.body as any[])
            .flatMap((st) => (st.type === 'ExportNamedDeclaration' ? [st.declaration] : [st]))
            .filter((d) => d?.type === 'VariableDeclaration')
            .flatMap((d) => d.declarations)
            .filter((d: any) => d?.id?.type === 'Identifier' && isInProcessValue(d.init))
            .map((d: any) => d.id.name),
        ),
      };
      /** Function nodes already reported, so one reached two ways is analysed once. */
      const analysed = new Set<any>();

      const push = (f: Omit<Finding, 'file'> & { line: number }) => {
        if (suppress.suppressed(f.line, f.id)) return;
        result.findings.push({
          ...f,
          file: relPath,
          snippet: snippetAt(source, f.line),
        });
      };

      const handle = (path: any, name: string, exported: boolean, httpMethod?: string, wrappers: string[] = []) => {
        const node = path?.node;
        if (!node || analysed.has(node)) return;
        const inlineUseServer = hasDirective(node, 'use server');
        // An inline `'use server'` makes the function an action whether or not it is
        // exported: `<form action={deletePost}>` posts to it by id all the same.
        const isAction = (exported && programUseServer) || inlineUseServer;
        const isRoute = Boolean(httpMethod);
        if (!isAction && !isRoute) return;
        analysed.add(node);

        const info = analyseFunction(path, name, facts, wrappers, (w) => resolveWrapper(w, file, ast, wrapperOptions));
        for (const v of info.nameOnlyWrappers) {
          const key = v.from ? `\`${v.wrapper}\` from \`${v.from}\`` : `\`${v.wrapper}\``;
          nameOnly.set(key, [...(nameOnly.get(key) ?? []), `${relPath}:${name}`]);
        }
        if (isAction) actionCount++;
        if (isRoute) routeCount++;

        const kind = isRoute ? 'Route Handler' : 'Server Action';
        const routePath = pagesApi
          ? relPath.replace(/^(.*\/)?(src\/)?pages/, '').replace(/\.[tj]sx?$/, '').replace(/\/index$/, '')
          : relPath.replace(/^(src\/)?app/, '').replace(/\/route\.[tj]sx?$/, '');
        const exposure = isRoute
          ? `\`${httpMethod === ANY_METHOD ? '*' : httpMethod} ${routePath || '/'}\` is a public HTTP endpoint.`
          : 'Server Actions compile to public HTTP POST endpoints — anyone can invoke this by ID, the UI is not a gate.';

        // `PUT`/`POST` are assumed to write, but a handler that reads nothing from the
        // caller, touches no data and does no work — a health check answering with a
        // constant and a timestamp — has nothing to protect, whatever its method.
        const doesNothing =
          isRoute && !info.hasMutation && !info.hasRead && info.workCalls === 0 && !info.readsRequestInput;
        // Likewise a handler whose only effect is an LLM call: it writes nothing, and what it
        // risks — someone else spending your key — is what the AI rules name.
        // The same holds when the calls that are left are helpers that provably do nothing
        // outside the process (see ./effects.ts). Only worked out for the method-only case,
        // since that is the only place it changes the answer.
        const methodOnly =
          isRoute && !info.hasMutation && HTTP_MUTATION_METHODS.has(httpMethod!) && !doesNothing;
        let effectFree = false;
        if (methodOnly && (info.aiCalls > 0 || info.effectCalls.length > 0)) {
          const inert = inertNamesFor(file, effectOptions, ast);
          effectFree = info.effectCalls.every((call) => inert.has(call));
        }
        const writes = info.hasMutation || (methodOnly && !effectFree);
        const isWebhook =
          isRoute &&
          (httpMethod === 'POST' || httpMethod === ANY_METHOD) &&
          /webhook|\bhooks?\b|stripe|clerk|svix/i.test(relPath);
        const isCron = isRoute && /(^|\/)(cron|scheduled|jobs?)(\/|$)/i.test(relPath);

        // Some endpoints are unauthenticated by design — the sign-in and
        // account-recovery flow (you have no session yet), and public intake
        // forms. Flagging "missing auth" there is a false positive, so it is
        // reported at low rather than as a blocking critical.
        const PUBLIC_BY_DESIGN_ROUTE =
          /(^|\/|-)(login|signin|sign-in|register|signup|sign-up|forgot-password|reset-password|verify-email|resend-verification|magic-link|contact|lead|leads|waitlist|subscribe|unsubscribe|newsletter)(\/|-|\.|$)/i;
        // Signing out only ends the caller's own session, so it needs no session to be
        // recognised — unless it reads who to sign out from the request, which is the
        // one way a logout endpoint is a bug (`/logout` taking a `userId` from the body).
        const LOGOUT_ROUTE = /(^|\/|-)(logout|log-out|signout|sign-out)(\/|-|\.|$)/i;
        const intentionallyPublic =
          isRoute &&
          (PUBLIC_BY_DESIGN_ROUTE.test(relPath) || (LOGOUT_ROUTE.test(relPath) && !info.readsRequestInput));

        // A machine-to-machine endpoint has no session to look up: it proves the
        // caller by comparing a credential header against a server-side secret.
        // That is an authorization check, so it must not read as a missing one.
        const secretAuth = info.readsCredentialHeader && info.readsSecretEnv;
        // For a webhook, the provider signature *is* the caller's identity.
        // CTS042 below is the rule for a webhook that verifies nothing.
        const verifiedWebhook = isWebhook && info.hasSignatureCheck;
        const authenticated = info.hasAuth || secretAuth || verifiedWebhook || info.verifiesSignature;

        // Public by design — a sign-in / intake route by its name, or an action that reads the
        // session only to turn signed-in callers away — is reported low. Unless it does
        // something such a flow has no business doing for a stranger: grant a role, write
        // somewhere other than the account tables, spend money. Then it is what it looks like.
        const guestOnly = info.guestOnly && !intentionallyPublic;
        const reasons: string[] = [];
        if (writes && !authenticated && (intentionallyPublic || guestOnly)) {
          const { escalation, tables } = info.privilege;
          if (escalation) reasons.push(`sets \`${escalation}\``);
          if (intentionallyPublic) {
            const paid = info.privilege.calls.filter((c) => PAID_CALL.test(c));
            if (paid.length) reasons.push(`calls \`${paid.slice(0, 3).join('`, `')}\``);
          } else {
            if (info.wholePayloadLine !== null || info.spreadLine !== null) reasons.push("writes the caller's object whole");
            const other = tables.filter((t) => t !== '?');
            if (other.length) reasons.push(`writes to \`${other.slice(0, 3).join('`, `')}\``);
            else if (tables.includes('?')) reasons.push('writes somewhere this cannot tell is an account table');
            const safe = info.privilege.calls.length ? inertNamesFor(file, guestFlowOptions, ast) : new Set<string>();
            const calls = info.privilege.calls.filter((c) => !safe.has(c));
            if (calls.length) reasons.push(`calls \`${calls.slice(0, 3).join('`, `')}\``);
            if (info.aiCalls > 0) reasons.push('calls an LLM provider');
          }
        }
        const publicByDesign = (intentionallyPublic || guestOnly) && reasons.length === 0;
        const listed = reasons.length > 1 ? `${reasons.slice(0, -1).join(', ')} and ${reasons[reasons.length - 1]}` : reasons[0];

        if (writes && !authenticated && info.getSessionLine === null) {
          push({
            id: 'CTS001',
            severity: publicByDesign ? 'low' : info.hasMutation ? 'critical' : 'high',
            title: !publicByDesign
              ? `Missing ${kind} authorization`
              : guestOnly
                ? `${kind} is reachable by signed-out callers (guest-only by design)`
                : `${kind} is unauthenticated (appears public by design)`,
            detail:
              `${kind} \`${name}\` ` +
              (info.hasMutation
                ? 'performs a database mutation without verifying the caller. '
                : `accepts ${httpMethod ?? 'POST'} and never verifies the caller. No database write ` +
                  'is visible in the handler itself, so this is judged on the method alone — a ' +
                  'read-only endpoint here is a lower risk than the severity suggests. ') +
              exposure +
              (publicByDesign && guestOnly
                ? ' It reads the session only to turn signed-in callers away, so anyone who is signed out reaches it — by design for a sign-up, sign-in or password-reset flow, and everything it visibly does is what such a flow does. Review what it writes, and confirm it is rate limited and does not trust a caller-supplied role or identifier.'
                : publicByDesign
                  ? ' This route name suggests a sign-in / account-recovery or public-intake endpoint, which is unauthenticated by design — confirm it has rate limiting and does not trust caller-supplied identifiers.'
                  : guestOnly && reasons.length
                    ? ` It reads the session only to turn signed-in callers away, so every signed-out caller reaches it — and it ${listed}, which a sign-up or sign-in flow has no reason to do for a stranger.`
                    : intentionallyPublic && reasons.length
                      ? ` The route name suggests a public sign-in or intake endpoint, but it ${listed}, so it is reported at full severity.`
                      : ''),
            fix:
              'Resolve and check the session before touching the database, e.g.\n' +
              '  const { data: { user } } = await supabase.auth.getUser()\n' +
              "  if (!user) throw new Error('Unauthorized')\n" +
              'then scope the write to that user. A wrapper such as next-safe-action’s ' +
              '`authActionClient` also satisfies this check.',
            line: info.mutationLine ?? info.line,
            cwe: 'CWE-306: Missing Authentication for Critical Function',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { action: name, kind, ...(info.guestOnly ? { guestOnly: true } : {}) },
          });
        }

        // Narrowed deliberately. The old condition — parameters, a write, no
        // `.parse()` — reported the ordinary safe pattern: pull named fields out
        // of the payload, write an explicit column list. 92 of 92 hits on one
        // dogfooded app were that shape. What actually carries the danger is the
        // payload reaching the columns *as an object*, which is the only case
        // where a field the caller invented can land in the row. A spread is
        // that same danger and CTS043 already names it, so it is left to CTS043.
        const massAssignable = info.wholePayloadLine !== null && info.spreadLine === null;
        if (info.params > 0 && writes && massAssignable && !info.hasValidation) {
          push({
            id: 'CTS002',
            severity: 'high',
            title: `${kind} writes caller-supplied data without validating it`,
            detail:
              `\`${name}\` passes an object it received straight into a database write, with no ` +
              'runtime schema validation. TypeScript types are erased at runtime, so every key the ' +
              'caller chose to send is written — adding `"is_admin": true` to the payload is enough ' +
              'to set that column (mass assignment).',
            fix:
              'Parse the input before use:\n' +
              "  const parsed = MySchema.safeParse(raw)\n" +
              "  if (!parsed.success) throw new Error('Invalid input')\n" +
              'and pass `parsed.data` — never the raw argument — to the query.',
            line: info.wholePayloadLine ?? info.line,
            cwe: 'CWE-20: Improper Input Validation',
            owasp: 'A05:2025 - Injection',
            meta: { action: name, kind },
          });
        }

        if (info.serviceRoleLine !== null) {
          push({
            id: 'CTS003',
            severity: 'critical',
            title: `Service-role key used inside a ${kind}`,
            detail:
              `\`${name}\` builds a Supabase client with the service-role key. That key bypasses ` +
              'every Row Level Security policy, so any authorization bug in this function exposes ' +
              'the whole table rather than one row.',
            fix:
              'Use the request-scoped anon client (`createClient()` from your server helper) so RLS ' +
              'still applies. Reserve the service-role key for trusted background jobs that no user ' +
              'request can reach.',
            line: info.serviceRoleLine,
            cwe: 'CWE-250: Execution with Unnecessary Privileges',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { action: name, kind },
          });
        }

        if (info.getSessionLine !== null && !info.hasAuth) {
          push({
            id: 'CTS041',
            severity: 'high',
            title: `${kind} authenticates with getSession() instead of getUser()`,
            detail:
              `\`${name}\` calls \`supabase.auth.getSession()\` to decide who the caller is. On the ` +
              'server that only decodes the session cookie — it never asks the auth server whether the ' +
              'token is still valid, so a forged or revoked cookie passes. Supabase documents ' +
              '`getSession()` as safe on the client only.',
            fix:
              'Use `const { data: { user } } = await supabase.auth.getUser()` instead, which revalidates ' +
              'the JWT against the auth server, and branch on `user`.',
            line: info.getSessionLine,
            cwe: 'CWE-287: Improper Authentication',
            owasp: 'A07:2025 - Authentication Failures',
            meta: { action: name, kind },
          });
        }

        if (info.spreadLine !== null) {
          push({
            id: 'CTS043',
            severity: 'high',
            title: `${kind} spreads caller-supplied data into a write`,
            detail:
              `\`${name}\` spreads an object it received into a database write, so every key the ` +
              'caller chose to send is written. Adding `"is_admin": true` or `"credits": 999999` to the ' +
              'request body is enough to set those columns — the classic mass-assignment escalation.',
            fix:
              'Write an explicit column list built from validated fields — ' +
              '`{ name: parsed.data.name }` — rather than spreading the request body.',
            line: info.spreadLine,
            cwe: 'CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { action: name, kind },
          });
        }

        // A route is only an unverified *webhook* if nothing else identifies the caller.
        // A path containing `stripe` or `webhook` that requires a signed-in user, or a
        // shared secret (`CRON_SECRET`), is an ordinary authenticated endpoint that
        // happens to be named for a provider: a checkout creator, a reconcile cron, a
        // notifier. Reporting those as forgeable webhooks was five of six sampled
        // findings on real repositories.
        if (isWebhook && !info.hasSignatureCheck && !info.hasAuth && !secretAuth) {
          push({
            id: 'CTS042',
            severity: 'critical',
            title: 'Webhook endpoint does not verify its signature',
            detail:
              `\`${relPath}\` looks like a webhook receiver but nothing in \`${name}\` verifies the ` +
              'provider signature. Webhook URLs are not secret and the payload is entirely ' +
              'attacker-controlled, so anyone who learns the URL can post a forged event — a fake ' +
              '`checkout.session.completed` grants themselves a paid plan.',
            fix:
              'Verify before trusting anything in the body, e.g. ' +
              '`stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET)` ' +
              'for Stripe or `new Webhook(secret).verify(payload, headers)` for Clerk/svix. Read the ' +
              'raw body, not the parsed JSON.',
            line: info.line,
            cwe: 'CWE-345: Insufficient Verification of Data Authenticity',
            owasp: 'A08:2025 - Software & Data Integrity Failures',
            meta: { kind, route: relPath },
          });
        }

        // A cron route's GET health check that returns a constant has nothing to
        // trigger, so "callable by anyone" is not a finding about it.
        const doesWork = info.workCalls > 0 || HTTP_MUTATION_METHODS.has(httpMethod ?? '');
        if (isCron && doesWork && !info.readsAuthHeader && !info.hasAuth && !secretAuth) {
          push({
            id: 'CTS046',
            severity: 'high',
            title: 'Cron endpoint is callable by anyone',
            detail:
              `\`${relPath}\` is a scheduled job route, but \`${name}\` checks neither a shared ` +
              'secret nor a session. The path is public HTTP like any other, so anyone can trigger the ' +
              'job — repeatedly, and at a time of their choosing.',
            fix:
              'Compare an `Authorization` header against `process.env.CRON_SECRET` and return 401 on ' +
              'mismatch. Vercel Cron sends that header automatically when the variable is set.',
            line: info.line,
            cwe: 'CWE-306: Missing Authentication for Critical Function',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { kind, route: relPath },
          });
        }

        // A Route Handler always has a `request` parameter, so "takes an
        // argument" says nothing about it — `POST /api/auth/logout`, which
        // resolves the session and destroys it, was reported as an IDOR. What
        // the rule needs is a real write keyed on something the caller sent.
        const idorShaped = isRoute
          ? info.hasMutation && info.readsRequestInput
          : info.params > 0;
        if (writes && info.hasAuth && !info.ownerScoped && idorShaped) {
          push({
            id: 'CTS004',
            severity: 'medium',
            title: `${kind} mutation is authenticated but not owner-scoped`,
            detail:
              `\`${name}\` checks that *someone* is logged in, then mutates a row identified only by ` +
              'a caller-supplied argument. Any logged-in user can pass another tenant’s id (IDOR).',
            fix:
              'Constrain the write to the authenticated principal, e.g. ' +
              "`.eq('id', id).eq('user_id', user.id)`, or rely on an RLS policy that compares " +
              '`auth.uid()` against the owning column.',
            line: info.mutationLine ?? info.line,
            cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { action: name, kind },
          });
        }
      };

      // Validation that opts out of validating. Reported per file, since the
      // schema is usually declared at module scope, away from the action.
      if (programUseServer || routeFile || pagesApi) {
        LOOSE_SCHEMA.lastIndex = 0;
        const loose = LOOSE_SCHEMA.exec(source);
        if (loose) {
          const line = source.slice(0, loose.index).split('\n').length;
          push({
            id: 'CTS044',
            severity: 'medium',
            title: 'Schema opts out of validating',
            detail:
              `\`${loose[0]}\` in a server-side module means the schema accepts keys it does not ` +
              'declare. Input then passes validation while still carrying whatever extra fields the ' +
              'caller attached, which is the situation the schema was added to prevent.',
            fix:
              'Drop `.passthrough()` / `.catchall()` and replace `z.any()` or `z.unknown()` with the ' +
              'shape you actually expect. Zod strips unknown keys by default — that default is the point.',
            line,
            cwe: 'CWE-20: Improper Input Validation',
            owasp: 'A05:2025 - Injection',
          });
        }
      }

      const methodFor = (exportedName: string) =>
        routeFile && ROUTE_METHOD.test(exportedName) ? exportedName : undefined;

      /**
       * The function an expression stands for, and the calls wrapping it: a function
       * itself; `cache(async () => ...)` or `withAuth(handler)` — any call handed a function
       * or a local function's name, however deeply nested; or the name of a local
       * function. Wrappers are recorded so an auth wrapper still credits what it wraps,
       * and anything else is looked through, so `cache()` no longer hides the action.
       */
      const resolveFn = (
        p: any,
        locals: Map<string, { fn: any; wrappers: string[] }>,
        depth = 0,
      ): { fn: any; wrappers: string[] } | null => {
        const cur = unwrapExpression(p);
        const n = cur?.node;
        if (!n || depth > 4) return null;
        if (n.type === 'ArrowFunctionExpression' || n.type === 'FunctionExpression' || n.type === 'FunctionDeclaration') {
          return { fn: cur, wrappers: [] };
        }
        if (n.type === 'Identifier') {
          const local = locals.get(n.name);
          return local ?? null;
        }
        if (n.type === 'CallExpression' || n.type === 'OptionalCallExpression') {
          const wrapper = calleeName(n.callee);
          const args = cur.get('arguments') as any[];
          for (const arg of args) {
            const inner = resolveFn(arg, locals, depth + 1);
            if (!inner) continue;
            // A function argument sits inside the call, where analyseFunction's own
            // parent walk sees the wrapper; a name does not, so it is carried along.
            const direct = inner.fn.node === unwrapExpression(arg)?.node || inner.fn.findParent?.((q: any) => q.node === n);
            return { fn: inner.fn, wrappers: direct ? inner.wrappers : [wrapper, ...inner.wrappers] };
          }
        }
        return null;
      };

      traverse(ast, {
        Program(program: any) {
          // Top-level functions by name, for `export { x }`, `export default x` and
          // `withAuth(x)`. Declarations first, then values built from them.
          const locals = new Map<string, { fn: any; wrappers: string[] }>();
          const statements = (program.get('body') as any[]).map((st) =>
            st.node.type === 'ExportNamedDeclaration' || st.node.type === 'ExportDefaultDeclaration'
              ? st.get('declaration')
              : st,
          );
          for (const st of statements) {
            if (st?.node?.type === 'FunctionDeclaration' && st.node.id) locals.set(st.node.id.name, { fn: st, wrappers: [] });
          }
          for (let round = 0; round < 2; round++) {
            for (const st of statements) {
              if (st?.node?.type !== 'VariableDeclaration') continue;
              (st.get('declarations') as any[]).forEach((d: any) => {
                if (d.node.id?.type !== 'Identifier' || !d.node.init || locals.has(d.node.id.name)) return;
                const r = resolveFn(d.get('init'), locals);
                if (r) locals.set(d.node.id.name, r);
              });
            }
          }

          for (const st of program.get('body') as any[]) {
            const n = st.node;
            if (n.type === 'ExportNamedDeclaration') {
              const decl = n.declaration;
              if (decl?.type === 'FunctionDeclaration' && decl.id) {
                handle(st.get('declaration'), decl.id.name, true, methodFor(decl.id.name));
              } else if (decl?.type === 'VariableDeclaration') {
                (st.get('declaration.declarations') as any[]).forEach((d: any) => {
                  if (d.node.id?.type !== 'Identifier' || !d.node.init) return;
                  const name = d.node.id.name;
                  const r = resolveFn(d.get('init'), locals);
                  if (r) handle(r.fn, name, true, methodFor(name), r.wrappers);
                });
              } else if (!decl && !n.source) {
                // `export { deletePost }`, `export { handler as POST, handler as DELETE }`.
                for (const s of n.specifiers ?? []) {
                  if (s.type !== 'ExportSpecifier') continue;
                  const exportedName = s.exported?.name ?? s.exported?.value;
                  const local = locals.get(s.local?.name);
                  if (!local || !exportedName) continue;
                  // One function exported as two methods is one handler, reported once.
                  handle(local.fn, exportedName, true, methodFor(exportedName), local.wrappers);
                }
              }
            } else if (n.type === 'ExportDefaultDeclaration') {
              const method = pagesApi ? ANY_METHOD : undefined;
              const r = resolveFn(st.get('declaration'), locals);
              if (!r) continue;
              const decl = n.declaration;
              const name =
                decl?.id?.name ?? (decl?.type === 'Identifier' ? decl.name : r.fn.node.id?.name) ?? 'default';
              handle(r.fn, name, true, method, r.wrappers);
            }
          }
        },
        // Inline actions: any function whose own body opens with `'use server'`, exported
        // or not — typically declared inside a Server Component and passed to a form.
        Function(path: any) {
          if (!hasDirective(path.node, 'use server')) return;
          const n = path.node;
          const pn = path.parentPath?.node;
          const name =
            n.id?.name ??
            (pn?.type === 'VariableDeclarator' && pn.id?.type === 'Identifier' ? pn.id.name : null) ??
            (pn?.type === 'ObjectProperty' ? propertyKey(pn) || null : null) ??
            (n.type === 'ObjectMethod' || n.type === 'ClassMethod' ? propertyKey(n) || null : null) ??
            'inline action';
          handle(path, name, false);
        },
      });
    }

    // A wrapper credited on its name alone is a guess, not a verified check. Not a finding —
    // most are fine, and a finding per handler would bury the real ones — but the scan
    // must not present it as verified either, so it is said, with the handlers it covers.
    let nameOnlyCount = 0;
    for (const [wrapper, handlers] of nameOnly) {
      nameOnlyCount += handlers.length;
      result.warnings.push(
        `${handlers.length} Server Action / Route Handler${handlers.length === 1 ? ' was' : 's were'} counted as ` +
          `authenticated because ${wrapper} is named like an auth wrapper; its source was not read, so that is ` +
          `unverified (${handlers.slice(0, 3).join(', ')}${handlers.length > 3 ? ', …' : ''})`,
      );
    }
    const nameOnlyNote = nameOnlyCount
      ? `${nameOnlyCount} credited to a wrapper by name only, unverified`
      : undefined;
    if (actionCount > 0) {
      result.checks.push({
        label: `Server Action authorization (${actionCount} action${actionCount === 1 ? '' : 's'} analysed)`,
        passed: !result.findings.some((f) => f.id === 'CTS001' || f.id === 'CTS003'),
        ...(nameOnlyNote ? { note: nameOnlyNote } : {}),
      });
    }
    if (routeCount > 0) {
      result.checks.push({
        label: `Route Handler authorization (${routeCount} handler${routeCount === 1 ? '' : 's'} analysed)`,
        passed: !result.findings.some((f) => f.id === 'CTS001' && f.meta?.kind === 'Route Handler'),
        ...(nameOnlyNote ? { note: nameOnlyNote } : {}),
      });
    }
    if (actionCount === 0 && routeCount === 0) {
      result.checks.push({
        label: 'Server Action authorization',
        passed: true,
        note: 'no Server Actions or Route Handlers found',
      });
    }
    return result;
  },
};
