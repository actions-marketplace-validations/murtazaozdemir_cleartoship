import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import { scan } from '../dist/index.js';

// Every case here is an audit finding against the Server Actions / Route Handlers scanner,
// reproduced before it was fixed. Most were the scanner going quiet on code it never
// actually judged — an export shape it did not recognise, an auth call credited wherever
// it sat. Each is paired with the correct shape that must stay quiet, because the fix for
// a silent miss must not become a false positive on the code everyone writes.

const IDS = /^CTS0(0[1-4]|4[1-6])$/;

async function scanApp(files) {
  const dir = mkdtempSync(join(tmpdir(), 'sa-audit-'));
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

// ---------------------------------------------------------------- 1. unreadable files

test('a file that does not parse makes the run incomplete, not clear', async () => {
  const { result } = await scanApp({
    'app/actions.ts': ["'use server'", 'export async function x( {', '  await db.post.delete('],
  });
  assert.ok(
    result.incomplete.some((s) => /could not parse app\/actions\.ts/.test(s)),
    `expected an incomplete entry, got ${JSON.stringify(result.incomplete)}`,
  );
  assert.notEqual(result.verdict, 'clear');
});

test('one file the analysis cannot finish is that file incomplete, and the others are still judged', async () => {
  // A 20,000-deep member chain overflows the stack in traversal. It used to take the
  // whole scanner down with it, so the unauthenticated write next door went unreported.
  const { found, result } = await scanApp({
    'app/deep.ts': ["'use server'", 'export async function x(id) {', `  return a${'.b'.repeat(20000)};`, '}'],
    'app/ok.ts': ["'use server'", 'export async function y(id: string) { await db.post.delete({ where: { id } }) }'],
  });
  assert.ok(found.includes('CTS001:critical:app/ok.ts:y'), JSON.stringify(found));
  assert.ok(!result.incomplete.some((s) => /Next\.js Server Actions & Route Handlers failed/.test(s)));
  if (result.incomplete.some((s) => /app\/deep\.ts/.test(s))) assert.notEqual(result.verdict, 'clear');
});

// ---------------------------------------------------------------- 2. route files

test('a Pages Router API route is a route handler', async () => {
  const { found } = await scanApp({
    'pages/api/delete-post.ts': [
      'export default async function handler(req, res) {',
      '  await db.post.delete({ where: { id: req.body.id } })',
      '  res.status(200).json({ ok: true })',
      '}',
    ],
  });
  assert.deepEqual(found, ['CTS001:critical:pages/api/delete-post.ts:handler']);
});

test('a Pages Router route that authenticates, or only reads, is not a finding', async () => {
  const { found } = await scanApp({
    'pages/api/posts.ts': [
      "import { getServerSession } from 'next-auth'",
      'export default async function handler(req, res) {',
      '  const session = await getServerSession(req, res, {})',
      '  if (!session) return res.status(401).end()',
      '  await db.post.delete({ where: { id: req.body.id, userId: session.user.id } })',
      '  res.json({})',
      '}',
    ],
    // Answers GET too: never judged on its method alone.
    'pages/api/list.ts': 'export default async function handler(req, res) { res.json(await db.post.findMany()) }',
  });
  assert.deepEqual(found, []);
});

test('the root route handler, app/route.ts, is a route handler', async () => {
  const { found } = await scanApp({
    'app/route.ts': [
      'export async function POST(req: Request) {',
      '  const { id } = await req.json()',
      '  await db.post.delete({ where: { id } })',
      '  return Response.json({ ok: true })',
      '}',
    ],
  });
  assert.deepEqual(found, ['CTS001:critical:app/route.ts:POST']);
});

// ---------------------------------------------------------------- 3. export shapes

test('export { x }, export { x as y } and export default x are all actions', async () => {
  const { found } = await scanApp({
    'app/a.ts': [
      "'use server'",
      'async function deletePost(id: string) { await db.post.delete({ where: { id } }) }',
      'async function renamePost(id: string) { await db.post.update({ where: { id }, data: {} }) }',
      'export { deletePost, renamePost as rename }',
    ],
    'app/b.ts': [
      "'use server'",
      'async function purge(id: string) { await db.post.delete({ where: { id } }) }',
      'export default purge',
    ],
  });
  assert.deepEqual(found, [
    'CTS001:critical:app/a.ts:deletePost',
    'CTS001:critical:app/a.ts:rename',
    'CTS001:critical:app/b.ts:purge',
  ]);
});

test('an action wrapped in cache() is looked through; one wrapped in an auth wrapper is credited', async () => {
  const { found } = await scanApp({
    'app/cached.ts': [
      "'use server'",
      "import { cache } from 'react'",
      'export const deletePost = cache(async (id: string) => { await db.post.delete({ where: { id } }) })',
    ],
    'app/wrapped.ts': [
      "'use server'",
      "import { withAuth } from '@/lib/x'",
      'async function del(id: string, ctx) { await db.post.delete({ where: { id, userId: ctx.userId } }) }',
      'export const deletePost = withAuth(del)',
      'export const d2 = withAuth(async (id: string, ctx) => { await db.post.delete({ where: { id, userId: ctx.userId } }) })',
    ],
  });
  assert.deepEqual(found, ['CTS001:critical:app/cached.ts:deletePost']);
});

test('export { handler as POST, handler as DELETE } maps the names to methods; NextAuth stays quiet', async () => {
  const { found } = await scanApp({
    'app/api/posts/route.ts': [
      'async function handler(req: Request) {',
      '  const { id } = await req.json()',
      '  await db.post.delete({ where: { id } })',
      '  return Response.json({})',
      '}',
      'export { handler as POST, handler as DELETE }',
    ],
    'app/api/auth/[...nextauth]/route.ts': [
      "import NextAuth from 'next-auth'",
      'const handler = NextAuth({ providers: [] })',
      'export { handler as GET, handler as POST }',
    ],
  });
  // One function exported twice is one handler, reported once.
  assert.deepEqual(found, ['CTS001:critical:app/api/posts/route.ts:POST']);
});

// ---------------------------------------------------------------- 4. inline 'use server'

test('an indented inline directive is not the module directive', async () => {
  const { found } = await scanApp({
    'app/x.ts': [
      'export async function saveDraft(id: string) {',
      "  'use server'",
      "  const s = await auth(); if (!s) throw new Error('Unauthorized')",
      '  await db.draft.update({ where: { id, userId: s.user.id }, data: {} })',
      '}',
      // Not an action: this module has no module-level directive.
      'export async function purge(id: string) { await db.post.delete({ where: { id } }) }',
    ],
  });
  assert.deepEqual(found, []);
});

test('an inline action declared inside a Server Component is analysed, exported or not', async () => {
  const { found } = await scanApp({
    'app/posts/page.tsx': [
      'export default async function Page() {',
      '  const posts = await db.post.findMany()',
      '  async function deletePost(formData: FormData) {',
      "    'use server'",
      "    await db.post.delete({ where: { id: String(formData.get('id')) } })",
      '  }',
      '  return <form action={deletePost}><button>Delete</button></form>',
      '}',
    ],
  });
  assert.deepEqual(found, ['CTS001:critical:app/posts/page.tsx:deletePost']);
});

// ---------------------------------------------------------------- 5. where the auth check sits

test('an auth check after the write, inverted, test-only or never called does not authenticate', async () => {
  const { found } = await scanApp({
    'app/after.ts': [
      "'use server'",
      'export async function a(id: string) {',
      '  await db.post.delete({ where: { id } })',
      "  const session = await auth(); if (!session) throw new Error('Unauthorized')",
      '}',
    ],
    'app/inverted.ts': [
      "'use server'",
      'export async function b(id: string) {',
      '  const session = await auth()',
      '  if (session) return { ok: true }',
      '  await db.post.delete({ where: { id } })',
      '}',
    ],
    'app/testonly.ts': [
      "'use server'",
      'export async function c(id: string) {',
      "  if (process.env.NODE_ENV === 'test') {",
      '    const { data: { user } } = await supabase.auth.getUser()',
      "    if (!user) throw new Error('Unauthorized')",
      '  }',
      '  await db.post.delete({ where: { id } })',
      '}',
    ],
    'app/closure.ts': [
      "'use server'",
      'export async function d(id: string) {',
      "  const check = async () => { const s = await auth(); if (!s) throw new Error('Unauthorized') }",
      '  await db.post.delete({ where: { id } })',
      '}',
    ],
  });
  assert.deepEqual(found, [
    'CTS001:critical:app/after.ts:a',
    'CTS001:critical:app/closure.ts:d',
    'CTS001:critical:app/inverted.ts:b',
    'CTS001:critical:app/testonly.ts:c',
  ]);
});

test('the ordinary auth shapes stay credited', async () => {
  const { found } = await scanApp({
    'lib/x.ts': "export function isAdmin() { return getServerSession().then((s) => s?.user.role === 'admin') }",
    'app/actions.ts': [
      "'use server'",
      "import { isAdmin } from '@/lib/x'",
      "export async function a1(id: string) { const session = await auth(); if (!session) throw new Error('x'); await db.post.delete({ where: { id, userId: session.user.id } }) }",
      'export async function a2(id: string) { const user = await requireUser(); await db.post.delete({ where: { id, userId: user.id } }) }',
      "export async function a4() { if (!(await isAdmin())) redirect('/'); await db.post.deleteMany({}) }",
      'export async function a5(id: string) { const { userId } = auth(); if (!userId) return; await db.post.delete({ where: { id, userId } }) }',
      "export async function a6(id: string) { const u = await auth(); const check = async () => { if (!u) throw new Error('x') }; await check(); await db.post.delete({ where: { id, userId: u.user.id } }) }",
      "export async function a7(id: string) { await db.$transaction(async (tx) => { const u = await getUser(); if (!u) throw new Error('x'); await tx.post.delete({ where: { id, userId: u.id } }) }) }",
      "export async function a8(id: string) { let uid; if (process.env.NODE_ENV !== 'development') { const s = await auth(); if (!s) throw new Error('x'); uid = s.user.id } await db.post.delete({ where: { id, userId: uid } }) }",
      'export async function a9(id: string) { await db.post.delete({ where: { id, userId: (await requireUser()).id } }) }',
      'export async function a10(id: string) { const session = await auth(); if (session) { await db.post.delete({ where: { id, userId: session.user.id } }) } }',
      "export async function a11(id: string) { const { data: { user } } = await supabase.auth.getUser(); if (!user) throw new Error('x'); await db.post.delete({ where: { id, userId: user.id } }) }",
      "export async function a12(id: string) { const check = async () => { const s = await auth(); if (!s) throw new Error('x'); return s }; const s = await check(); await db.post.delete({ where: { id, userId: s.user.id } }) }",
    ],
  });
  assert.deepEqual(found, []);
});

// ---------------------------------------------------------------- 6. auth-named lookups

test('an admin SDK accessor or a user lookup by caller id is not an auth check', async () => {
  const { found } = await scanApp({
    'app/actions.ts': [
      "'use server'",
      "import admin from 'firebase-admin'",
      'export async function removeUser(uid: string) { await admin.auth().deleteUser(uid); await db.profile.delete({ where: { uid } }) }',
      'export async function lookup(id: string) { const u = await clerkClient.users.getUser(id); await db.note.create({ data: { name: u.firstName } }) }',
      'export async function lookup2(uid: string) { const u = await admin.auth().getUser(uid); await db.note.create({ data: { email: u.email } }) }',
    ],
  });
  assert.deepEqual(found, [
    'CTS001:critical:app/actions.ts:lookup',
    'CTS001:critical:app/actions.ts:lookup2',
    'CTS001:critical:app/actions.ts:removeUser',
  ]);
});

test('supabase getUser with a bearer token, and firebase verifyIdToken, still authenticate', async () => {
  const { found } = await scanApp({
    'app/api/x/route.ts': [
      'export async function POST(req: Request) {',
      "  const token = req.headers.get('authorization')?.replace('Bearer ', '')",
      '  const { data: { user } } = await supabase.auth.getUser(token)',
      "  if (!user) return new Response('no', { status: 401 })",
      '  await db.note.create({ data: { userId: user.id } })',
      '  return Response.json({})',
      '}',
    ],
    'app/actions.ts': [
      "'use server'",
      'export async function v(t: string) { const d = await admin.auth().verifyIdToken(t); await db.note.create({ data: { uid: d.uid } }) }',
    ],
  });
  assert.deepEqual(found, []);
});

// ---------------------------------------------------------------- 7. getSession through a helper

test('a helper whose only check is supabase getSession() reports CTS041 through it', async () => {
  const helperBody = (call) => [
    'export async function getCurrentUser() {',
    `  const { data } = await supabase.auth.${call}()`,
    '  return data.session?.user ?? data.user',
    '}',
  ];
  const action = [
    "'use server'",
    "import { getCurrentUser } from '@/lib/auth'",
    'export async function deletePost(id: string) {',
    '  const user = await getCurrentUser()',
    "  if (!user) throw new Error('Unauthorized')",
    '  await db.post.delete({ where: { id, userId: user.id } })',
    '}',
  ];
  const bad = await scanApp({ 'lib/auth.ts': helperBody('getSession'), 'app/actions.ts': action });
  assert.deepEqual(bad.found, ['CTS041:high:app/actions.ts:deletePost']);
  const good = await scanApp({ 'lib/auth.ts': helperBody('getUser'), 'app/actions.ts': action });
  assert.deepEqual(good.found, []);
});

// ---------------------------------------------------------------- 8. following helpers

test('auth helpers are followed through default exports, barrels, re-exports and namespace imports', async () => {
  const guard = [
    'export async function mustBeMember() {',
    '  const s = await getServerSession()',
    "  if (!s) throw new Error('Unauthorized')",
    '  return s',
    '}',
  ];
  const { found } = await scanApp({
    'lib/admin.ts': guard.map((l) => l.replace('export async function mustBeMember', 'export default async function checkAdmin')),
    'lib/session/check.ts': guard,
    'lib/session/index.ts': "export * from './check'",
    'lib/other.ts': "export { mustBeMember as member } from './session/check'",
    'lib/guard.ts': guard,
    'app/actions.ts': [
      "'use server'",
      "import checkAdmin from '@/lib/admin'",
      "import { mustBeMember } from '@/lib/session'",
      "import { member } from '@/lib/other'",
      "import * as guard from '@/lib/guard'",
      'export async function a(id: string) { const s = await checkAdmin(); await db.post.delete({ where: { id, ownerId: s.user.id } }) }',
      'export async function b(id: string) { const s = await mustBeMember(); await db.post.delete({ where: { id, ownerId: s.user.id } }) }',
      'export async function c(id: string) { const s = await member(); await db.post.delete({ where: { id, ownerId: s.user.id } }) }',
      'export async function d(id: string) { const s = await guard.mustBeMember(); await db.post.delete({ where: { id, ownerId: s.user.id } }) }',
      // A namespace member that is not an auth helper proves nothing.
      'export async function e(id: string) { await guard.somethingElse(); await db.post.delete({ where: { id } }) }',
    ],
  });
  assert.deepEqual(found, ['CTS001:critical:app/actions.ts:e']);
});

// ---------------------------------------------------------------- 9. in-process "mutations"

test('a hash update, a local Set delete and Object.create are not database writes', async () => {
  const { found } = await scanApp({
    'app/actions.ts': [
      "'use server'",
      "import { createHash, createHmac } from 'node:crypto'",
      'const cache = new Map()',
      'export async function gravatarUrl(email: string) {',
      "  const hash = createHash('md5').update(email.trim().toLowerCase()).digest('hex')",
      "  const h = createHmac('sha256', 'k'); h.update(email)",
      '  cache.delete(email)',
      '  return `https://www.gravatar.com/avatar/${hash}`',
      '}',
      'export async function dedupe(ids: string[]) {',
      '  const seen = new Set(ids)',
      "  seen.delete('')",
      '  new Set(ids).delete(ids[0])',
      '  return Object.create(null, { ids: { value: [...seen] } })',
      '}',
      // The real thing, in the same file, is still a write.
      'export async function del(id: string) { await db.post.delete({ where: { id } }) }',
      "export async function upd(id: string) { await supabase.from('p').update({ a: 1 }).eq('id', id) }",
    ],
  });
  assert.deepEqual(found, ['CTS001:critical:app/actions.ts:del', 'CTS001:critical:app/actions.ts:upd']);
});

// ---------------------------------------------------------------- 10. owner scoping

test('an owner id the caller supplied is not owner scoping', async () => {
  const { found } = await scanApp({
    'app/api/account/route.ts': [
      "import { auth } from '@/auth'",
      'export async function POST(req: Request) {',
      '  const session = await auth()',
      "  if (!session) return new Response('no', { status: 401 })",
      '  const body = await req.json()',
      '  await db.account.delete({ where: { id: body.userId } })',
      '  return Response.json({ ok: true })',
      '}',
    ],
    'app/actions.ts': [
      "'use server'",
      "import { auth } from '@/auth'",
      'export async function deleteAccount(formData: FormData) {',
      '  const session = await auth()',
      "  if (!session) throw new Error('Unauthorized')",
      "  const userId = String(formData.get('userId'))",
      '  await db.account.delete({ where: { id: userId } })',
      '}',
      'export async function deleteOther(formData: FormData) {',
      '  const session = await auth()',
      "  if (!session) throw new Error('Unauthorized')",
      "  await db.account.delete({ where: { id: 'x', userId: formData.get('userId') } })",
      '}',
    ],
  });
  assert.deepEqual(found, [
    'CTS004:medium:app/actions.ts:deleteAccount',
    'CTS004:medium:app/actions.ts:deleteOther',
    'CTS004:medium:app/api/account/route.ts:POST',
  ]);
});

test('an owner id resolved from the session is still owner scoping', async () => {
  const { found } = await scanApp({
    'app/actions.ts': [
      "'use server'",
      'export async function a(formData: FormData) {',
      '  const session = await auth()',
      "  if (!session) throw new Error('Unauthorized')",
      '  const userId = session.user.id',
      "  await db.account.delete({ where: { id: String(formData.get('id')), userId } })",
      '}',
      'export async function b(id: string) {',
      '  const { userId } = await auth()',
      "  if (!userId) throw new Error('x')",
      '  await db.post.delete({ where: { id, ownerId: userId } })',
      '}',
      'export async function c(id: string) {',
      '  const me = await requireUser()',
      '  await db.post.delete({ where: { id, ownerId: me.id } })',
      '}',
    ],
    // Found by the before/after run on a real app while fixing the above: a row fetched by
    // the caller's id and compared against the session is the ownership check, not caller input.
    'app/api/clients/route.ts': [
      'export async function DELETE(request: Request) {',
      '  const authed = await requireUser(request)',
      "  if (!authed) return Response.json({ error: 'Unauthorized' }, { status: 401 })",
      '  const { searchParams } = new URL(request.url)',
      "  const id = searchParams.get('id')",
      '  const client = await prisma.client.findUnique({ where: { id } })',
      "  if (!client || client.userId !== authed.id) return Response.json({ error: 'Not found' }, { status: 404 })",
      '  await prisma.client.delete({ where: { id } })',
      '  return Response.json({ success: true })',
      '}',
    ],
  });
  assert.deepEqual(found, []);
});
