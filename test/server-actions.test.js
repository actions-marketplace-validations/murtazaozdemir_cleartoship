import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { scan } from '../dist/index.js';
import { buildFixtures } from './fixture-setup.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => join(here, 'fixtures', name);
const VULNERABLE = fixture('vulnerable-app');
const CLEAN = fixture('clean-app');
const INDIRECT = fixture('indirect-auth-app');

buildFixtures();

const SERVER_ACTIONS_IDS = ['CTS001', 'CTS002', 'CTS003', 'CTS004', 'CTS041', 'CTS042', 'CTS043', 'CTS044', 'CTS046'];

test('the Server Actions suite fires on the vulnerable fixture', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const found = new Set(result.findings.map((f) => f.id));
  for (const id of SERVER_ACTIONS_IDS) assert.ok(found.has(id), `expected ${id} to be reported`);
  assert.equal(
    result.findings.find((f) => f.id === 'CTS001').file,
    'app/actions/admin.ts',
  );
});

test('the correctly written action is not flagged', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const safe = result.findings.filter((f) => f.file === 'app/actions/safe.ts');
  assert.deepEqual(safe, [], `safe.ts should be clean, got ${safe.map((f) => f.id).join(', ')}`);
});

test('the clean fixture is silent on Server Actions', async () => {
  const result = await scan({ root: CLEAN, offline: true });
  const sa = result.findings.filter((f) => SERVER_ACTIONS_IDS.includes(f.id));
  assert.deepEqual(sa, []);
});

test('auth resolved in an imported helper counts as auth', async () => {
  const result = await scan({ root: INDIRECT, offline: true });
  const action = result.findings.filter((f) => f.file === 'app/actions/team.ts');
  assert.deepEqual(
    action.map((f) => f.id),
    [],
    `renameTeam authenticates via requireUser() from @/lib/auth, got ${action.map((f) => `${f.id}@${f.line}`).join(', ')}`,
  );
});

test('a shared-secret cron endpoint is authenticated, and its health check is not a finding', async () => {
  const result = await scan({ root: INDIRECT, offline: true });
  const route = result.findings.filter((f) => f.file === 'app/api/cron/digest/route.ts');
  assert.deepEqual(
    route.filter((f) => f.id === 'CTS001' || f.id === 'CTS046').map((f) => `${f.id}@${f.line}`),
    [],
    'the POST compares Authorization against CRON_SECRET; the GET returns a constant',
  );
  assert.equal(route.filter((f) => f.id === 'CTS002').length, 0);
});

test('mass assignment is the payload arriving whole, not any write of caller input', async () => {
  const bad = await scan({ root: VULNERABLE, offline: true });
  const flagged = bad.findings.filter((f) => f.file === 'app/actions/mass-assign.ts');

  assert.ok(flagged.some((f) => f.id === 'CTS002' && f.line === 10), 'a payload written whole is CTS002');
  assert.ok(flagged.some((f) => f.id === 'CTS043' && f.line === 18), 'a nested spread of the payload is CTS043');

  const clean = await scan({ root: CLEAN, offline: true });
  assert.deepEqual(clean.findings.map((f) => `${f.id} ${f.file}:${f.line}`), []);
});

test('getSession() does not satisfy the auth check, and replaces CTS001 there', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const settings = result.findings.filter((f) => f.file === 'app/actions/settings.ts');
  const found = new Set(settings.map((f) => f.id));
  assert.ok(found.has('CTS041'), 'supabase.auth.getSession() must be reported');
  assert.ok(!found.has('CTS001'), 'CTS041 is the precise diagnosis; the generic missing-auth rule should not double-report');
});

test('webhook that verifies via a framework helper or sig header is not flagged', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const cts042 = result.findings.filter((f) => f.id === 'CTS042').map((f) => f.file);
  assert.ok(cts042.includes('app/api/webhooks/stripe/route.ts'), 'the unverified webhook must still be flagged');
  assert.ok(
    !cts042.some((f) => f.includes('stripe-verified')),
    'a webhook that reads the signature header + verifies must not be flagged',
  );
});

test('a route named for a provider is only an unverified webhook if nothing else identifies the caller', async () => {
  // Five of six CTS042 findings sampled from real repositories were ordinary
  // authenticated endpoints whose PATH mentioned `stripe` or `webhook`: a checkout
  // creator behind getUser(), a reconcile cron behind CRON_SECRET, a notifier behind a
  // session, a route delegating to its own per-provider verifier. Only the receiver
  // that trusts an unauthenticated body is the finding.
  const { mkdtempSync, mkdirSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'cts-webhook-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { next: '15.5.24', react: '19.0.0' } }),
  );
  const route = (path, body) => {
    mkdirSync(join(dir, 'app', 'api', path), { recursive: true });
    writeFileSync(join(dir, 'app', 'api', path, 'route.ts'), body);
  };
  route('stripe/create-checkout', [
    "import { createClient } from '@/lib/supabase/server';",
    'export async function POST(request: Request) {',
    '  const supabase = await createClient();',
    '  const { data: { user } } = await supabase.auth.getUser();',
    "  if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });",
    '  return Response.json({ url: "https://checkout.example/session" });',
    '}',
  ].join('\n'));
  route('cron/stripe-reconcile', [
    'export async function POST(request: Request) {',
    '  const authorization = request.headers.get("authorization");',
    '  if (authorization !== `Bearer ${process.env.CRON_SECRET}`) return new Response("no", { status: 401 });',
    '  return Response.json({ ok: true });',
    '}',
  ].join('\n'));
  route('webhooks/[provider]', [
    "import { verifyProviderWebhook } from '@/lib/webhooks';",
    'export async function POST(request: Request) {',
    '  const rawBody = await request.text();',
    '  await verifyProviderWebhook(rawBody, request);',
    '  return Response.json({ received: true });',
    '}',
  ].join('\n'));
  route('cron/stripe-typed-env', [
    "import { env } from '@/lib/env';",
    'export async function POST(request: Request) {',
    '  const cronSecret = env.CRON_SECRET;',
    '  if (request.headers.get("authorization") !== `Bearer ${cronSecret}`) return new Response("no", { status: 401 });',
    '  return Response.json({ ok: true });',
    '}',
  ].join('\n'));
  route('webhooks/custom-provider', [
    'export async function POST(request: Request) {',
    '  const rawBody = await request.text();',
    '  const header = PROVIDER_HEADERS[new URL(request.url).pathname] ?? "x-webhook-signature";',
    '  const signature = request.headers.get(header) ?? "";',
    '  return Response.json(await handleProviderWebhook(rawBody, signature));',
    '}',
  ].join('\n'));
  route('webhooks/gmail', [
    'export async function POST(req: Request) {',
    '  const body = await req.json();',
    '  await enqueue(body);',
    '  return Response.json({ received: true });',
    '}',
  ].join('\n'));

  const result = await scan({ root: dir, offline: true, noCommunity: true });
  const flagged = result.findings.filter((f) => f.id === 'CTS042').map((f) => f.file).sort();
  assert.deepEqual(flagged, ['app/api/webhooks/gmail/route.ts'], 'only the receiver that verifies nothing is unverified');
});

test('a helper that checks a credential header against a server-side secret authenticates its callers', async () => {
  // Sampled from a real repository: a route calls `authenticateApiRequest(request)`,
  // imported through the `@/` alias, and that helper compares the Authorization header
  // with a secret from the environment. That IS authentication, and the route was
  // reported as missing it because the helper resolver only looked at callee names.
  const { mkdtempSync, mkdirSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'cts-helper-'));
  const put = (rel, body) => {
    const full = join(dir, rel);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, body);
  };
  put('package.json', JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { next: '15.5.24', react: '19.0.0', '@supabase/supabase-js': '2.0.0' } }));
  put('tsconfig.json', JSON.stringify({ compilerOptions: { baseUrl: '.', paths: { '@/*': ['./*'] } } }));
  // Authenticates: reads the credential header AND a secret from the environment.
  put('lib/api-auth.ts', [
    'export async function authenticateApiRequest(request: Request) {',
    '  const expected = process.env.API_KEY;',
    "  const header = request.headers.get('authorization');",
    '  if (!expected || header !== `Bearer ${expected}`) throw new Error("Unauthorized");',
    '  return { id: "service" };',
    '}',
  ].join('\n'));
  // Does NOT authenticate: reads a header, compares it to nothing secret.
  put('lib/read-header.ts', [
    'export async function readCaller(request: Request) {',
    "  return request.headers.get('authorization');",
    '}',
  ].join('\n'));
  const insertRoute = (call, importLine) => [
    "import { createClient } from '@supabase/supabase-js';",
    importLine,
    'const db = createClient(process.env.URL!, process.env.ANON!);',
    'export async function POST(request: Request) {',
    `  ${call}`,
    "  await db.from('seasons').insert(await request.json());",
    '  return Response.json({ ok: true });',
    '}',
  ].join('\n');
  put('app/api/guarded/route.ts', insertRoute('await authenticateApiRequest(request);', "import { authenticateApiRequest } from '@/lib/api-auth';"));
  put('app/api/bare/route.ts', insertRoute('', ''));
  put('app/api/header-only/route.ts', insertRoute('await readCaller(request);', "import { readCaller } from '@/lib/read-header';"));

  const result = await scan({ root: dir, offline: true, noCommunity: true });
  const flagged = result.findings.filter((f) => f.id === 'CTS001').map((f) => f.file).sort();
  assert.deepEqual(
    flagged,
    ['app/api/bare/route.ts', 'app/api/header-only/route.ts'],
    'the route calling the shared-secret helper is authenticated; the other two are not',
  );
});

test('a handler that does nothing but answer with a constant has nothing to protect, on any method', async () => {
  // Sampled from a real repository: a health check whose `PUT` handler returns a constant
  // and a timestamp was reported "missing authorization" because PUT is assumed to write.
  // Handlers that DO something — read the caller's input, or call anything — stay findings.
  const { mkdtempSync, mkdirSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'cts-constant-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { next: '15.5.24', react: '19.0.0' } }),
  );
  const route = (path, body) => {
    mkdirSync(join(dir, 'app', 'api', path), { recursive: true });
    writeFileSync(join(dir, 'app', 'api', path, 'route.ts'), body);
  };
  route('health', [
    "import { NextResponse } from 'next/server';",
    'export async function GET() { return NextResponse.json({ ok: true }); }',
    'export async function PUT() {',
    "  return NextResponse.json({ ok: true, method: 'PUT', timestamp: new Date().toISOString() });",
    '}',
  ].join('\n'));
  route('does-work', [
    "import { NextResponse } from 'next/server';",
    'export async function PUT() {',
    '  await rebuildEverything();',
    '  return NextResponse.json({ ok: true });',
    '}',
  ].join('\n'));
  route('reads-input', [
    "import { NextResponse } from 'next/server';",
    'export async function POST(request: Request) {',
    '  const body = await request.json();',
    '  return NextResponse.json({ echoed: body });',
    '}',
  ].join('\n'));

  const result = await scan({ root: dir, offline: true, noCommunity: true });
  const flagged = result.findings.filter((f) => f.id === 'CTS001').map((f) => f.file).sort();
  assert.deepEqual(flagged, ['app/api/does-work/route.ts', 'app/api/reads-input/route.ts']);
});
