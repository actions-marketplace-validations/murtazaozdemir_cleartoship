import {
  read, rel, isScript, snippetAt,
  parseSource, calleeName, calleeTail, hasDirective,
  traverse, buildModuleIndex, Suppressions, emptyResult,
} from '../internal.js';
import { authNamesFor, CREDENTIAL_HEADERS, SECRET_ENV } from './auth-helpers.js';
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
}

function analyseFunction(
  path: any,
  name: string,
  /** Names that stand for an auth check in this file — see ./auth-helpers.ts. */
  credited: ReadonlySet<string>,
  /** Module-level `const KEY = process.env.SOME_SECRET` names, read by identifier. */
  secretConsts: ReadonlySet<string>,
): ActionInfo {
  const node = path.node;
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
  };

  // An id the caller passed in is not proof of ownership — it is the IDOR.
  // Only a principal resolved inside the function counts as scoping.
  const params = parameterNames(node.params ?? []);

  /**
   * Names holding the caller's payload as one object: a Server Action's own
   * parameter, or a variable assigned from a request-body read. Writing one of
   * these whole is mass assignment; pulling named fields out of it and writing
   * those is the safe pattern this rule used to report anyway.
   */
  const payloads = new Set<string>();
  for (const p of node.params ?? []) {
    // Only whole-object parameters. `({ name, role })` is already field by field.
    if (p?.type === 'Identifier' && !/^(req|request|_req|_request|nextRequest)$/i.test(p.name)) {
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

  const inspect = (inner: any) => {
    const full = calleeName(inner.node.callee);
    const tail = calleeTail(inner.node.callee);
    if (!RESPONSE_CALLS.test(full) && !TRIVIAL_CALLS.test(full)) info.workCalls++;
    if (REQUEST_INPUT_READ.test(full)) info.readsRequestInput = true;
    const isAiCall = AI_CALLS.test(full);
    if (isAiCall) info.aiCalls++;
    else if (!isInertCall(full, tail) && !info.effectCalls.includes(full)) info.effectCalls.push(full);
    // `requireVerifiedActor(req.headers, 'read')`, `authorizeRequest(request)`: an
    // authorisation verb handed the request. Only the pair counts — `requireEnv()` or
    // `ensureDirectory(path)` is not handed a request to check.
    if (
      AUTH_VERB_HELPER.test(tail) &&
      (inner.node.arguments ?? []).some((arg: any) => isRequestish(arg))
    ) {
      info.hasAuth = true;
    }

    // `supabase.auth.getSession()` reads the cookie without asking the auth
    // server whether the token is still valid, so it proves nothing on the
    // server. It must not satisfy the auth check via the generic `getSession`
    // entry, which exists for hand-rolled helpers.
    const isSupabaseGetSession = /(^|\.)auth\.getSession$/.test(full);
    if (isSupabaseGetSession) {
      info.getSessionLine ??= inner.node.loc?.start.line ?? info.line;
    } else if (matchesAny(full, AUTH_CALLS)) {
      info.hasAuth = true;
    } else if (credited.has(full)) {
      // The check lives in a first-party helper this file imports, or one
      // defined above in the same file. Matched on the whole callee name, not
      // its tail: a helper is called by the name this file binds it to, and
      // crediting `crypto.verify()` because some other module exports a
      // `verify` helper would hide a real finding.
      info.hasAuth = true;
    }
    if (matchesAny(full, AUTH_WRAPPERS)) info.hasAuth = true;
    if (matchesAny(full, SIGNATURE_CHECKS) || SIGNATURE_VERIFY_NAME.test(tail)) info.hasSignatureCheck = true;
    if (STRONG_SIGNATURE_NAME.test(tail) || /(^|\.)(webhooks\.)?constructEvent(Async)?$/.test(full)) {
      info.verifiesSignature = true;
    }
    if (VALIDATION_CALLS.has(tail)) info.hasValidation = true;
    if (
      MUTATION_CALLS.has(tail) &&
      !NOT_A_DATA_WRITE.test(full) &&
      !NOT_A_DATA_RECEIVER.test(full) &&
      !isAiCall
    ) {
      info.hasMutation = true;
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
      const root = rootObject(inner.node);
      if (!root || !params.has(root)) {
        for (const hint of OWNER_HINTS) {
          if (full === hint || full.endsWith('.' + hint)) info.ownerScoped = true;
        }
      }
    },
    Identifier(inner: any) {
      if (SERVICE_ROLE_HINTS.includes(inner.node.name)) {
        info.serviceRoleLine ??= inner.node.loc?.start.line ?? info.line;
      }
      if (OWNER_IDENTIFIERS.has(inner.node.name) && !params.has(inner.node.name)) {
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
  const credentialDerived = new Set<string>();
  const touchesCredential = (node: any) =>
    someNode(node, (n) => (n.type === 'Identifier' && credentialDerived.has(n.name)) || isCredentialSource(n));
  path.traverse({
    VariableDeclarator(inner: any) {
      if (!inner.node.init || !touchesCredential(inner.node.init)) return;
      for (const n of parameterNames([inner.node.id])) credentialDerived.add(n);
    },
    IfStatement(inner: any) {
      if (info.hasAuth || !touchesCredential(inner.node.test)) return;
      // A guard after the write turns the caller away once the row is already changed.
      const guardLine = inner.node.loc?.start.line ?? 0;
      if (info.mutationLine !== null && guardLine > info.mutationLine) return;
      if (someNode(inner.node.consequent, isUnauthorisedExit)) info.hasAuth = true;
    },
  });

  // An action wrapped by an auth HOC inherits the check from its wrapper.
  let parent = path.parentPath;
  let hops = 0;
  while (parent && hops++ < 4) {
    if (parent.node?.type === 'CallExpression') {
      const wrapper = calleeName(parent.node.callee);
      if (matchesAny(wrapper, AUTH_WRAPPERS) || credited.has(wrapper)) info.hasAuth = true;
      if (VALIDATION_CALLS.has(calleeTail(parent.node.callee))) info.hasValidation = true;
    }
    parent = parent.parentPath;
  }

  return info;
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

function propertyKey(prop: any): string {
  const key = prop?.key;
  if (!key) return '';
  return key.type === 'Identifier' ? key.name : key.type === 'StringLiteral' ? key.value : '';
}

const HTTP_MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function isRouteHandlerFile(relPath: string): boolean {
  return /(^|\/)(app|src\/app)\/.*\/route\.(t|j)sx?$/.test(relPath);
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
      cache: new Map<string, ReadonlySet<string>>(),
    };

    const effectOptions = {
      isInert: isInertCall,
      index: helperOptions.index,
      cache: new Map<string, ReadonlySet<string>>(),
    };

    for (const file of ctx.files) {
      if (!isScript(file)) continue;
      const source = read(file);
      if (source === null) continue;

      const relPath = rel(ctx.root, file);
      const routeFile = isRouteHandlerFile(relPath);
      const moduleUseServer = /^\s*(['"])use server\1/m.test(source.slice(0, 400));
      if (!moduleUseServer && !routeFile && !source.includes('use server')) continue;

      const ast = parseSource(source, file);
      if (!ast) {
        result.warnings.push(`could not parse ${relPath}`);
        continue;
      }
      const suppress = new Suppressions(source);
      const programUseServer = moduleUseServer || hasDirective(ast.program, 'use server');
      const credited = authNamesFor(file, helperOptions, ast);
      const secretConsts = moduleSecretConsts(ast);

      const push = (f: Omit<Finding, 'file'> & { line: number }) => {
        if (suppress.suppressed(f.line, f.id)) return;
        result.findings.push({
          ...f,
          file: relPath,
          snippet: snippetAt(source, f.line),
        });
      };

      const handle = (path: any, name: string, exported: boolean, httpMethod?: string) => {
        const node = path.node;
        const inlineUseServer = hasDirective(node, 'use server');
        const isAction = exported && (programUseServer || inlineUseServer);
        const isRoute = Boolean(httpMethod);
        if (!isAction && !isRoute) return;

        const info = analyseFunction(path, name, credited, secretConsts);
        if (isAction) actionCount++;
        if (isRoute) routeCount++;

        const kind = isRoute ? 'Route Handler' : 'Server Action';
        const exposure = isRoute
          ? `\`${httpMethod} ${relPath.replace(/^(src\/)?app/, '').replace(/\/route\.[tj]sx?$/, '') || '/'}\` is a public HTTP endpoint.`
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
          isRoute && httpMethod === 'POST' && /webhook|\bhooks?\b|stripe|clerk|svix/i.test(relPath);
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

        if (writes && !authenticated && info.getSessionLine === null) {
          push({
            id: 'CTS001',
            severity: intentionallyPublic ? 'low' : info.hasMutation ? 'critical' : 'high',
            title: intentionallyPublic
              ? `${kind} is unauthenticated (appears public by design)`
              : `Missing ${kind} authorization`,
            detail:
              `${kind} \`${name}\` ` +
              (info.hasMutation
                ? 'performs a database mutation without verifying the caller. '
                : `accepts ${httpMethod ?? 'POST'} and never verifies the caller. No database write ` +
                  'is visible in the handler itself, so this is judged on the method alone — a ' +
                  'read-only endpoint here is a lower risk than the severity suggests. ') +
              exposure +
              (intentionallyPublic
                ? ' This route name suggests a sign-in / account-recovery or public-intake endpoint, which is unauthenticated by design — confirm it has rate limiting and does not trust caller-supplied identifiers.'
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
            meta: { action: name, kind },
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
      if (programUseServer || routeFile) {
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

      traverse(ast, {
        ExportNamedDeclaration(path: any) {
          const decl = path.node.declaration;
          if (!decl) return;
          if (decl.type === 'FunctionDeclaration' && decl.id) {
            const name = decl.id.name;
            const method = routeFile && /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(name) ? name : undefined;
            handle(path.get('declaration'), name, true, method);
          } else if (decl.type === 'VariableDeclaration') {
            decl.declarations.forEach((d: any, i: number) => {
              if (d.id?.type !== 'Identifier') return;
              if (d.init?.type !== 'ArrowFunctionExpression' && d.init?.type !== 'FunctionExpression') return;
              const name = d.id.name;
              const method = routeFile && /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(name) ? name : undefined;
              const initPath = path.get(`declaration.declarations.${i}.init`);
              handle(initPath, name, true, method);
            });
          }
        },
        ExportDefaultDeclaration(path: any) {
          const decl = path.node.declaration;
          if (decl?.type === 'FunctionDeclaration' || decl?.type === 'ArrowFunctionExpression') {
            handle(path.get('declaration'), decl.id?.name ?? 'default', true);
          }
        },
      });
    }

    if (actionCount > 0) {
      result.checks.push({
        label: `Server Action authorization (${actionCount} action${actionCount === 1 ? '' : 's'} analysed)`,
        passed: !result.findings.some((f) => f.id === 'CTS001' || f.id === 'CTS003'),
      });
    }
    if (routeCount > 0) {
      result.checks.push({
        label: `Route Handler authorization (${routeCount} handler${routeCount === 1 ? '' : 's'} analysed)`,
        passed: !result.findings.some((f) => f.id === 'CTS001' && f.meta?.kind === 'Route Handler'),
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
