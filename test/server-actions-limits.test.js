import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import { scan } from '../dist/index.js';

// Two limits the 2026-09-23 audit left on purpose, now closed:
//
// 1. Auth wrappers were credited by NAME. `withIronSessionApiRoute` matched /session/ and
//    counted as authenticated, though iron-session attaches a session and lets every
//    caller through. Wrappers are now read (first-party) or looked up (third-party).
// 2. An action that reads the session only to turn signed-in users away
//    (`if (session) redirect('/dashboard')`) became a CTS001 critical in the audit. It is
//    now low when what it does is what a sign-up flow does — and stays critical when it
//    grants a role, writes elsewhere or spends money. A name list once hid exactly that
//    (`register` hardcoding an Admin role; `leads` running paid enrichment), so both
//    shapes are pinned here.

const IDS = /^CTS0(0[1-4]|4[1-6])$/;

async function scanApp(files) {
  const dir = mkdtempSync(join(tmpdir(), 'sa-limits-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { next: '15.5.24', react: '19.0.0' } }),
  );
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), Array.isArray(body) ? body.join('\n') : body);
  }
  const result = await scan({ root: dir, offline: true, noCommunity: true });
  const found = result.findings
    .filter((f) => IDS.test(f.id))
    .map((f) => `${f.id}:${f.severity}:${f.file}:${f.meta?.action ?? ''}`)
    .sort();
  return { found, result };
}

// ---------------------------------------------------------------- 1. wrappers

test('iron-session attaches a session but does not require one: the handler must check it', async () => {
  const { found } = await scanApp({
    'pages/api/unchecked.ts': [
      "import { withIronSessionApiRoute } from 'iron-session/next'",
      'async function handler(req, res) {',
      '  await db.post.create({ data: { title: String(req.body.title) } })',
      '  res.json({ ok: true })',
      '}',
      "export default withIronSessionApiRoute(handler, { cookieName: 'x', password: 'y' })",
    ],
    'pages/api/checked.ts': [
      "import { withIronSessionApiRoute } from 'iron-session/next'",
      'export default withIronSessionApiRoute(async function handler(req, res) {',
      '  if (!req.session.user) return res.status(401).end()',
      '  await db.post.create({ data: { title: String(req.body.title), userId: req.session.user.id } })',
      '  res.json({ ok: true })',
      "}, { cookieName: 'x', password: 'y' })",
    ],
    'pages/api/positive.ts': [
      "import { withIronSessionApiRoute } from 'iron-session/next'",
      'export default withIronSessionApiRoute(async (req, res) => {',
      '  if (req.session?.user) {',
      '    await db.post.create({ data: { title: String(req.body.title), userId: req.session.user.id } })',
      '  }',
      '  res.json({ ok: true })',
      "}, { cookieName: 'x', password: 'y' })",
    ],
  });
  assert.deepEqual(found, ['CTS001:critical:pages/api/unchecked.ts:handler']);
});

test('next-auth v5 auth(handler) puts the session on req.auth and still calls the handler', async () => {
  const { found } = await scanApp({
    'auth.ts': ["import NextAuth from 'next-auth'", 'export const { auth, handlers, signIn } = NextAuth({ providers: [] })'],
    'app/api/open/route.ts': [
      "import { auth } from '@/auth'",
      'export const POST = auth(async (req) => {',
      '  const { title } = await req.json()',
      '  await db.post.create({ data: { title } })',
      '  return Response.json({ ok: true })',
      '})',
    ],
    'app/api/closed/route.ts': [
      "import { auth } from '@/auth'",
      'export const POST = auth(async (req) => {',
      "  if (!req.auth) return Response.json({ error: 'no' }, { status: 401 })",
      '  const { title } = await req.json()',
      '  await db.post.create({ data: { title, userId: req.auth.user.id } })',
      '  return Response.json({ ok: true })',
      '})',
    ],
  });
  assert.deepEqual(found, ['CTS001:critical:app/api/open/route.ts:POST']);
});

test('a first-party wrapper is credited only when it provably rejects before calling the handler', async () => {
  const { found } = await scanApp({
    'lib/wrappers.ts': [
      "import { getServerSession } from 'next-auth'",
      // Rejects: auth call, guard, exit — then the handler.
      'export function withAuth(handler) {',
      '  return async (req) => {',
      '    const session = await getServerSession()',
      "    if (!session) return Response.json({ error: 'unauthorized' }, { status: 401 })",
      '    return handler(req, session)',
      '  }',
      '}',
      // Attaches: resolves the session, hands it on, lets everyone through.
      'export function withSession(handler) {',
      '  return async (req) => {',
      '    const session = await getServerSession()',
      '    return handler(req, session)',
      '  }',
      '}',
      // Named like auth, does no auth at all.
      'export function withAdminGuard(handler) {',
      '  return async (req) => {',
      "    console.log('admin route', req.url)",
      '    return handler(req)',
      '  }',
      '}',
    ],
    'app/api/a/route.ts': [
      "import { withAuth } from '@/lib/wrappers'",
      'export const POST = withAuth(async (req, session) => {',
      '  await db.post.create({ data: { userId: session.user.id } })',
      '  return Response.json({})',
      '})',
    ],
    'app/api/b/route.ts': [
      "import { withSession } from '@/lib/wrappers'",
      'export const POST = withSession(async (req, session) => {',
      '  await db.post.create({ data: { userId: session?.user?.id } })',
      '  return Response.json({})',
      '})',
    ],
    'app/api/c/route.ts': [
      "import { withSession } from '@/lib/wrappers'",
      'export const POST = withSession(async (req, session) => {',
      "  if (!session) return Response.json({ error: 'unauthorized' }, { status: 401 })",
      '  await db.post.create({ data: { userId: session.user.id } })',
      '  return Response.json({})',
      '})',
    ],
    'app/api/d/route.ts': [
      "import { withAdminGuard } from '@/lib/wrappers'",
      'export const POST = withAdminGuard(async (req) => {',
      '  await db.setting.deleteMany({})',
      '  return Response.json({})',
      '})',
    ],
  });
  assert.deepEqual(found, ['CTS001:critical:app/api/b/route.ts:POST', 'CTS001:critical:app/api/d/route.ts:POST']);
});

test('a first-party wrapper around iron-session is followed to it', async () => {
  const { found } = await scanApp({
    'lib/session.ts': [
      "import { withIronSessionApiRoute } from 'iron-session/next'",
      "const opts = { cookieName: 'x', password: 'y' }",
      'export function withSessionRoute(handler) { return withIronSessionApiRoute(handler, opts) }',
    ],
    'pages/api/save.ts': [
      "import { withSessionRoute } from '../../lib/session'",
      'export default withSessionRoute(async function save(req, res) {',
      '  await db.post.create({ data: { title: String(req.body.title) } })',
      '  res.json({})',
      '})',
    ],
    'pages/api/save-checked.ts': [
      "import { withSessionRoute } from '../../lib/session'",
      'export default withSessionRoute(async function saveChecked(req, res) {',
      '  const user = req.session.user',
      "  if (!user) return res.status(401).json({ error: 'no' })",
      '  await db.post.create({ data: { title: String(req.body.title), userId: user.id } })',
      '  res.json({})',
      '})',
    ],
  });
  assert.deepEqual(found, ['CTS001:critical:pages/api/save.ts:save']);
});

test('third-party wrappers: an allowlisted requiring one is trusted, an unknown one is credited but said to be a guess', async () => {
  const { found, result } = await scanApp({
    'pages/api/auth0.ts': [
      "import { withApiAuthRequired } from '@auth0/nextjs-auth0'",
      'export default withApiAuthRequired(async function handler(req, res) {',
      '  await db.post.create({ data: {} })',
      '  res.json({})',
      '})',
    ],
    'pages/api/unknown.ts': [
      "import { withProtection } from 'some-auth-lib'",
      'export default withProtection(async function handler(req, res) {',
      '  await db.post.create({ data: {} })',
      '  res.json({})',
      '})',
    ],
  });
  assert.deepEqual(found, []);
  const warned = result.warnings.filter((w) => /named like an auth wrapper/.test(w));
  assert.equal(warned.length, 1, JSON.stringify(result.warnings));
  assert.match(warned[0], /`withProtection` from `some-auth-lib`/);
  assert.match(warned[0], /pages\/api\/unknown\.ts/);
  assert.doesNotMatch(warned[0], /auth0/);
  const check = result.checks.find((c) => /Route Handler authorization/.test(c.label));
  assert.match(check.note ?? '', /1 credited to a wrapper by name only/);
});

test('a next-safe-action client is followed: its middleware decides, not its name', async () => {
  const { found } = await scanApp({
    'lib/safe-action.ts': [
      "import { createSafeActionClient } from 'next-safe-action'",
      "import { auth } from '@/auth'",
      'export const actionClient = createSafeActionClient()',
      'export const authActionClient = actionClient.use(async ({ next }) => {',
      '  const session = await auth()',
      "  if (!session) throw new Error('Unauthorized')",
      '  return next({ ctx: { userId: session.user.id } })',
      '})',
    ],
    'auth.ts': ["import NextAuth from 'next-auth'", 'export const { auth } = NextAuth({ providers: [] })'],
    'app/actions.ts': [
      "'use server'",
      "import { z } from 'zod'",
      "import { actionClient, authActionClient } from '@/lib/safe-action'",
      'const s = z.object({ id: z.string() })',
      'export const deleteMine = authActionClient.schema(s).action(async ({ parsedInput, ctx }) => {',
      '  await db.post.delete({ where: { id: parsedInput.id, userId: ctx.userId } })',
      '})',
      'export const deleteAny = actionClient.schema(s).action(async ({ parsedInput }) => {',
      '  await db.post.delete({ where: { id: parsedInput.id } })',
      '})',
    ],
  });
  assert.deepEqual(found, ['CTS001:critical:app/actions.ts:deleteAny']);
});

// ---------------------------------------------------------------- 2. guest-only actions

test('a sign-up or password-reset action that only turns signed-in users away is low, not critical', async () => {
  const { found, result } = await scanApp({
    'app/(auth)/actions.ts': [
      "'use server'",
      "import bcrypt from 'bcryptjs'",
      "import { randomBytes } from 'node:crypto'",
      "import { redirect } from 'next/navigation'",
      "import { auth } from '@/auth'",
      'export async function signup(formData: FormData) {',
      '  const session = await auth()',
      "  if (session) redirect('/dashboard')",
      "  const hash = await bcrypt.hash(String(formData.get('password')), 10)",
      "  await db.user.create({ data: { email: String(formData.get('email')), password: hash, role: 'USER' } })",
      "  redirect('/login')",
      '}',
      'export async function forgotPassword(formData: FormData) {',
      '  const session = await auth()',
      "  if (session) redirect('/')",
      "  const email = String(formData.get('email'))",
      "  const token = randomBytes(32).toString('hex')",
      '  await db.passwordResetToken.create({ data: { email, token } })',
      "  await resend.emails.send({ to: email, subject: 'Reset', html: token })",
      '}',
    ],
    'app/(auth)/supabase.ts': [
      "'use server'",
      "import { createClient } from '@/utils/supabase/server'",
      'export async function register(formData: FormData) {',
      '  const supabase = await createClient()',
      '  const { data: { user } } = await supabase.auth.getUser()',
      "  if (user) return { error: 'already signed in' }",
      "  const { data } = await supabase.auth.signUp({ email: String(formData.get('email')), password: String(formData.get('password')) })",
      "  await supabase.from('profiles').insert({ id: data.user.id, full_name: String(formData.get('name')) })",
      '}',
    ],
    'auth.ts': ["import NextAuth from 'next-auth'", 'export const { auth } = NextAuth({ providers: [] })'],
  });
  assert.deepEqual(found, [
    'CTS001:low:app/(auth)/actions.ts:forgotPassword',
    'CTS001:low:app/(auth)/actions.ts:signup',
    'CTS001:low:app/(auth)/supabase.ts:register',
  ]);
  const f = result.findings.find((x) => x.meta?.action === 'signup');
  assert.match(f.title, /reachable by signed-out callers/);
  assert.match(f.detail, /by design/);
});

test('`register` hardcoding an Admin role stays critical — as an action and as a route named for sign-up', async () => {
  const { found, result } = await scanApp({
    'app/actions.ts': [
      "'use server'",
      "import { redirect } from 'next/navigation'",
      'export async function register(formData: FormData) {',
      '  const session = await auth()',
      "  if (session) redirect('/')",
      "  await db.user.create({ data: { email: String(formData.get('email')), role: 'ADMIN' } })",
      '}',
      // The role the caller chose is the same bug with one more step.
      'export async function registerAs(formData: FormData) {',
      '  const session = await auth()',
      "  if (session) redirect('/')",
      "  const role = String(formData.get('role'))",
      "  await db.user.create({ data: { email: String(formData.get('email')), role } })",
      '}',
      'export async function registerEnum(formData: FormData) {',
      '  const session = await auth()',
      "  if (session) redirect('/')",
      "  await db.user.create({ data: { email: String(formData.get('email')), role: Role.SUPER_ADMIN, isAdmin: true } })",
      '}',
    ],
    // The name-list heuristic: /register/ made this low, whatever it wrote.
    'app/api/register/route.ts': [
      'export async function POST(req: Request) {',
      '  const { email, password } = await req.json()',
      "  await prisma.user.create({ data: { email, password, role: 'Admin' } })",
      '  return Response.json({ ok: true })',
      '}',
    ],
  });
  assert.deepEqual(found, [
    'CTS001:critical:app/actions.ts:register',
    'CTS001:critical:app/actions.ts:registerAs',
    'CTS001:critical:app/actions.ts:registerEnum',
    'CTS001:critical:app/api/register/route.ts:POST',
  ]);
  const f = result.findings.find((x) => x.meta?.action === 'register');
  assert.match(f.detail, /role: 'ADMIN'/);
});

test('`leads` running paid enrichment stays critical — as an action and as a route named for intake', async () => {
  const { found } = await scanApp({
    'lib/enrich.ts': [
      'export async function enrichLead(email: string) {',
      "  const res = await fetch('https://api.apollo.io/v1/people/match', { method: 'POST', body: JSON.stringify({ email }) })",
      '  return res.json()',
      '}',
    ],
    'app/actions.ts': [
      "'use server'",
      "import { enrichLead } from '@/lib/enrich'",
      'export async function captureLead(formData: FormData) {',
      '  const session = await auth()',
      "  if (session) return { ok: true }",
      "  const email = String(formData.get('email'))",
      '  const person = await enrichLead(email)',
      '  await db.lead.create({ data: { email, company: person.company } })',
      '}',
      // Even writing only the users table, a paid call on a stranger's say-so is not a sign-up.
      'export async function signupAndEnrich(formData: FormData) {',
      '  const session = await auth()',
      "  if (session) return { ok: true }",
      "  const email = String(formData.get('email'))",
      '  await db.user.create({ data: { email } })',
      '  await enrichLead(email)',
      '}',
    ],
    'app/api/leads/route.ts': [
      "import { enrichLead } from '@/lib/enrich'",
      'export async function POST(req: Request) {',
      '  const { email } = await req.json()',
      '  const person = await enrichLead(email)',
      '  await db.lead.create({ data: { email, company: person.company } })',
      '  return Response.json({ ok: true })',
      '}',
    ],
    // A plain intake form keeps the name-based low.
    'app/api/contact/route.ts': [
      'export async function POST(req: Request) {',
      '  const { email, message } = await req.json()',
      '  await db.message.create({ data: { email, message } })',
      '  return Response.json({ ok: true })',
      '}',
    ],
  });
  assert.deepEqual(found, [
    'CTS001:critical:app/actions.ts:captureLead',
    'CTS001:critical:app/actions.ts:signupAndEnrich',
    'CTS001:low:app/api/contact/route.ts:POST',
    'CTS001:critical:app/api/leads/route.ts:POST',
  ].sort());
});

test('a role echoed back in a login response is not a role granted', async () => {
  // Real shape (a sign-in route on one of the calibration repos): the first cut read the
  // response body's `role: user.role` as a privilege write and made the login route high.
  const { found } = await scanApp({
    'app/api/auth/login/route.ts': [
      "import { verifyCredentials } from '@/lib/users'",
      'export async function POST(req: Request) {',
      '  const { email, password } = await req.json()',
      '  const user = await verifyCredentials(email, password)',
      "  if (!user) return Response.json({ error: 'bad' }, { status: 401 })",
      "  await db.auditLog.create({ data: { action: 'login', email } })",
      '  return Response.json({ user: { id: user.id, role: user.role } })',
      '}',
    ],
  });
  assert.deepEqual(found, ['CTS001:low:app/api/auth/login/route.ts:POST']);
});

test('a guest-only action writing a non-account table, or its payload whole, keeps full severity', async () => {
  const { found } = await scanApp({
    'app/actions.ts': [
      "'use server'",
      'export async function joinTeam(formData: FormData) {',
      '  const session = await auth()',
      "  if (session) redirect('/')",
      "  await db.teamMember.create({ data: { teamId: String(formData.get('team')) } })",
      '}',
      'export async function signupRaw(input) {',
      '  const session = await auth()',
      "  if (session) redirect('/')",
      '  await db.user.create({ data: input })',
      '}',
    ],
  });
  assert.deepEqual(found, [
    'CTS001:critical:app/actions.ts:joinTeam',
    'CTS001:critical:app/actions.ts:signupRaw',
    'CTS002:high:app/actions.ts:signupRaw',
  ]);
});
