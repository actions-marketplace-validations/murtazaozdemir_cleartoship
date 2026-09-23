import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import { scan } from '../dist/index.js';

// A limit the 2026-09-23 audit left on purpose, now closed: auth wrappers were credited
// by NAME. `withIronSessionApiRoute` matched /session/ and counted as authenticated,
// though iron-session attaches a session and lets every caller through. Wrappers are now
// read (first-party) or looked up (third-party).

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
