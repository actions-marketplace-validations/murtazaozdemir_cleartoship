import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import { scan } from '../dist/index.js';

// Every case below was found by reading the code behind a CTS001 finding on a real public
// repository (a seeded sample of AI-built Next.js apps): 60 of 77 were wrong. The shapes are
// reduced, not invented. Each false-positive shape is paired with a look-alike that must
// STAY a finding, because a rule fixed by going quiet is worse than the noise it replaced.

async function scanApp(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cts001-cal-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { next: '15.5.24', react: '19.0.0' } }),
  );
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), Array.isArray(body) ? body.join('\n') : body);
  }
  const result = await scan({ root: dir, offline: true, noCommunity: true });
  const out = {};
  for (const f of result.findings) if (f.id === 'CTS001') (out[f.file] ??= []).push(f.severity);
  return out;
}

const route = (path) => `app/api/${path}/route.ts`;

test('clearing a cookie, a query parameter or a header is not a database delete', async () => {
  // Three logouts and a preview-exit were reported critical because `.delete` was read as a
  // row deletion. `db.session.delete` in the same shape is the real thing and stays critical.
  const found = await scanApp({
    [route('auth/logout')]: [
      "import { NextResponse } from 'next/server';",
      "import { cookies } from 'next/headers';",
      'export async function POST() {',
      '  const cookieStore = await cookies();',
      "  cookieStore.delete('session');",
      '  return NextResponse.json({ ok: true });',
      '}',
    ],
    [route('preview/exit')]: [
      "import { NextResponse } from 'next/server';",
      'export async function DELETE(request: Request) {',
      '  const url = new URL(request.url);',
      "  url.searchParams.delete('preview');",
      '  return NextResponse.redirect(url);',
      '}',
    ],
    [route('sessions/purge')]: [
      "import { db } from '@/lib/db';",
      'export async function POST(request: Request) {',
      '  const { id } = await request.json();',
      '  await db.session.delete({ where: { id } });',
      '  return Response.json({ ok: true });',
      '}',
    ],
  });
  assert.ok(!(found[route('auth/logout')] ?? []).some((s) => s === 'critical'), 'a cookie delete is not a row delete');
  assert.ok(!(found[route('preview/exit')] ?? []).some((s) => s === 'critical'));
  assert.deepEqual(found[route('sessions/purge')], ['critical'], 'a real delete stays critical');
});

test('a logout that reads who to sign out from the request is still a finding', async () => {
  // `/logout` with no input only ends the caller's own session. One that takes a `userId`
  // from the body and writes to it is the bug — it must not ride the logout downgrade.
  const found = await scanApp({
    [route('auth/logout')]: [
      "import { admin } from '@/lib/admin';",
      'export async function POST(request: Request) {',
      '  const { userId } = await request.json();',
      '  await admin.updateUserPartial(userId, { updatedAt: Date.now() });',
      '  return Response.json({ ok: true });',
      '}',
    ],
  });
  assert.deepEqual(found[route('auth/logout')], ['high']);
});

test('a POST whose only effect is an LLM call writes nothing', async () => {
  const found = await scanApp({
    [route('chat')]: [
      "import { streamText } from 'ai';",
      "import { openai } from '@ai-sdk/openai';",
      'export async function POST(req: Request) {',
      '  const { messages } = await req.json();',
      "  const result = streamText({ model: openai('gpt-4o'), messages: messages.map((m) => m) });",
      '  return result.toDataStreamResponse();',
      '}',
    ],
    [route('recipe')]: [
      "import { GoogleGenerativeAI } from '@google/generative-ai';",
      "import { NextResponse } from 'next/server';",
      'function clean(text: string) { return text.trim().substring(text.indexOf("{")); }',
      'export async function POST(request: Request) {',
      '  const body = await request.json();',
      '  const model = new GoogleGenerativeAI(process.env.GEMINI_API_KEY!).getGenerativeModel({ model: "x" });',
      '  const result = await model.generateContent(body.prompt);',
      '  return NextResponse.json(JSON.parse(clean(result.response.text())));',
      '}',
    ],
    // Same shape, but it also sends mail through something the scanner cannot vouch for.
    [route('chat-and-notify')]: [
      "import { streamText } from 'ai';",
      "import { notifyOwner } from 'some-sdk';",
      'export async function POST(req: Request) {',
      '  const { messages } = await req.json();',
      '  await notifyOwner(messages);',
      '  return streamText({ messages }).toDataStreamResponse();',
      '}',
    ],
  });
  assert.equal(found[route('chat')], undefined);
  assert.equal(found[route('recipe')], undefined, 'a same-file helper made of string methods is inert');
  assert.deepEqual(found[route('chat-and-notify')], ['high'], 'an unknown call is still work');
});

test('a helper that provably does nothing outside the process does not make the POST a write', async () => {
  // `refineQuery` in the real repo was an OpenAI completion and nothing else. The same call
  // shape into a helper that fetches or writes must stay a finding.
  const found = await scanApp({
    'lib/refine.ts': [
      "import OpenAI from 'openai';",
      'const client = new OpenAI();',
      'export async function refineQuery(q: string) {',
      '  const res = await client.chat.completions.create({ model: "x", messages: [{ role: "user", content: q.trim() }] });',
      '  return res.choices[0].message.content;',
      '}',
    ],
    'lib/publish.ts': [
      'export async function publish(q: string) {',
      '  await fetch("https://hooks.example.com/publish", { method: "POST", body: q });',
      '}',
    ],
    'lib/format.ts': ['export function format(s: string) { return s.trim().toLowerCase(); }'],
    [route('refine')]: [
      "import { refineQuery } from '@/lib/refine';",
      'export async function POST(request: Request) {',
      '  const { q } = await request.json();',
      '  return Response.json({ q: await refineQuery(q) });',
      '}',
    ],
    [route('publish')]: [
      "import { publish } from '@/lib/publish';",
      'export async function POST(request: Request) {',
      '  const { q } = await request.json();',
      '  await publish(q);',
      '  return Response.json({ ok: true });',
      '}',
    ],
    [route('format')]: [
      "import { format } from '@/lib/format';",
      'export async function POST(request: Request) {',
      '  const { q } = await request.json();',
      '  return Response.json({ q: format(q) });',
      '}',
    ],
  });
  assert.equal(found[route('refine')], undefined);
  assert.equal(found[route('format')], undefined);
  assert.deepEqual(found[route('publish')], ['high'], 'a helper that calls out is not inert');
});

test('a signature check is recognised by what it is called, wherever the route lives', async () => {
  const found = await scanApp({
    [route('meta/data-deletion')]: [
      "import { verifyAndDecodeSignedRequest } from '@/lib/meta';",
      "import { db } from '@/lib/db';",
      'export async function POST(request: Request) {',
      '  const form = await request.formData();',
      "  const payload = verifyAndDecodeSignedRequest(String(form.get('signed_request')), process.env.APP_SECRET!);",
      '  if (!payload) return new Response("bad", { status: 400 });',
      '  await db.user.delete({ where: { id: payload.user_id } });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    [route('blog/revalidate')]: [
      "import { parseBody } from 'next-sanity/webhook';",
      "import { db } from '@/lib/db';",
      'export async function POST(req: Request) {',
      '  const parsed = await parseBody(req, process.env.SANITY_WEBHOOK_SECRET);',
      '  if (!parsed.isValidSignature) return new Response("no", { status: 401 });',
      '  await db.post.update({ where: { id: 1 }, data: {} });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    // Names a webhook and a check, but verifies nothing: not a signature.
    [route('status/ping')]: [
      "import { db } from '@/lib/db';",
      'export async function POST(req: Request) {',
      '  const ok = checkWebhookStatus();',
      '  await db.ping.create({ data: { ok } });',
      '  return Response.json({ ok });',
      '}',
    ],
  });
  assert.equal(found[route('meta/data-deletion')], undefined);
  assert.equal(found[route('blog/revalidate')], undefined);
  assert.deepEqual(found[route('status/ping')], ['critical']);
});

test('a header checked against a secret held in a module-level constant is a shared-secret check', async () => {
  const found = await scanApp({
    [route('cron/update')]: [
      "import { db } from '@/lib/db';",
      'const API_KEY = process.env.CRON_API_KEY;',
      'export async function POST(request: Request) {',
      '  if (request.headers.get("authorization") !== `Bearer ${API_KEY}`) return new Response("no", { status: 401 });',
      '  await db.launch.update({ where: { id: 1 }, data: {} });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    [route('hooks/revalidate')]: [
      "import { db } from '@/lib/db';",
      'export async function POST(request: Request) {',
      '  const given = request.headers.get("x-sanity-revalidate-secret");',
      '  if (given !== process.env.SANITY_REVALIDATE_SECRET) return new Response("no", { status: 401 });',
      '  await db.post.update({ where: { id: 1 }, data: {} });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    // A constant that is not a secret, and a header that is read but never gates anything.
    [route('cron/other')]: [
      "import { db } from '@/lib/db';",
      'const SITE = process.env.SITE_NAME;',
      'export async function POST(request: Request) {',
      '  console.log(SITE, request.headers.get("authorization"));',
      '  await db.launch.update({ where: { id: 1 }, data: {} });',
      '  return Response.json({ ok: true });',
      '}',
    ],
  });
  assert.equal(found[route('cron/update')], undefined);
  assert.equal(found[route('hooks/revalidate')], undefined, 'x-*-secret is a credential header');
  assert.deepEqual(found[route('cron/other')], ['critical']);
});

test('an authorisation helper handed the request, or a 401 on what the request carried, authenticates', async () => {
  const found = await scanApp({
    [route('skills/inspect')]: [
      "import { requireVerifiedActor } from '@/lib/ctx';",
      "import { db } from '@/lib/db';",
      'export async function POST(req: Request) {',
      "  const actor = await requireVerifiedActor(req.headers, 'skill:read');",
      '  await db.skill.update({ where: { id: actor.id }, data: {} });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    [route('admin/user')]: [
      "import { getAuthInfoFromCookie } from '@/lib/session';",
      "import { db } from '@/lib/db';",
      'export async function POST(request: Request) {',
      '  const authInfo = getAuthInfoFromCookie(request);',
      "  if (!authInfo) return Response.json({ error: 'nope' }, { status: 401 });",
      '  await db.user.update({ where: { id: authInfo.id }, data: {} });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    [route('v1/complete')]: [
      "import { db } from '@/lib/db';",
      'export async function POST(req: Request) {',
      '  const key = (req.headers.get("authorization") ?? "").replace("Bearer ", "");',
      '  const record = await db.apiKey.findUnique({ where: { key } });',
      "  if (!record) return Response.json({ error: 'bad key' }, { status: 401 });",
      '  await db.usage.create({ data: { keyId: record.id } });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    // getUserId() reads nothing from the request it was handed — it mints an id when none
    // exists — so its 401 is dead code and the write is open. The real gramstr shape.
    [route('instagram/upload')]: [
      "import { getUserId } from '@/lib/visitor-id';",
      "import { db } from '@/lib/db';",
      'export async function POST(request: Request) {',
      '  const userId = await getUserId();',
      "  if (!userId) return Response.json({ error: 'Unauthorized' }, { status: 401 });",
      '  await db.session.create({ data: { userId } });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    // The same 401, but the row is already written by the time it is reached.
    [route('late/guard')]: [
      "import { getAuthInfoFromCookie } from '@/lib/session';",
      "import { db } from '@/lib/db';",
      'export async function POST(request: Request) {',
      '  const authInfo = getAuthInfoFromCookie(request);',
      '  await db.user.update({ where: { id: 1 }, data: {} });',
      "  if (!authInfo) return Response.json({ error: 'nope' }, { status: 401 });",
      '  return Response.json({ ok: true });',
      '}',
    ],
    // A helper with an authorisation verb that is not handed the request.
    [route('misc/env')]: [
      "import { requireEnv } from '@/lib/env';",
      "import { db } from '@/lib/db';",
      'export async function POST() {',
      "  requireEnv('X');",
      '  await db.thing.create({ data: {} });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    // 401 for something the request never touched.
    [route('misc/flag')]: [
      "import { db } from '@/lib/db';",
      'export async function POST() {',
      "  if (!process.env.FEATURE) return Response.json({ error: 'off' }, { status: 403 });",
      '  await db.thing.create({ data: {} });',
      '  return Response.json({ ok: true });',
      '}',
    ],
  });
  assert.equal(found[route('skills/inspect')], undefined);
  assert.equal(found[route('admin/user')], undefined);
  assert.equal(found[route('v1/complete')], undefined);
  assert.deepEqual(found[route('instagram/upload')], ['critical'], 'an id minted server-side is not the caller');
  assert.deepEqual(found[route('late/guard')], ['critical'], 'a guard after the write is not a guard');
  assert.deepEqual(found[route('misc/env')], ['critical']);
  assert.deepEqual(found[route('misc/flag')], ['critical']);
});

test('a 401/403 on something the caller said about themselves is not authentication', async () => {
  // Both were real bugs the first version of the 401-branch rule hid, found by reading what
  // it removed. A role read from a header the caller sets, compared to a literal allowlist;
  // an approval flag read from a row the body's own id selected; an Origin check.
  const found = await scanApp({
    [route('gateway/connectors')]: [
      "import { db } from '@/lib/db';",
      'export async function POST(request: Request) {',
      "  const role = request.headers.get('x-actor-role') || request.headers.get('x-user-role');",
      "  if (!['owner', 'admin'].includes(role ?? '')) return Response.json({ error: 'role_not_allowed' }, { status: 403 });",
      '  await db.connector.upsert({ where: { id: 1 }, update: {}, create: {} });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    // The real shape: the role is read through a local helper that is handed the request.
    [route('gateway/connectors-helper')]: [
      "import { db } from '@/lib/db';",
      'function header(request: Request, name: string) { return request.headers.get(name)?.trim() ?? ""; }',
      'export async function POST(request: Request) {',
      "  const role = header(request, 'x-actor-role');",
      "  if (!['owner', 'admin'].includes(role)) return Response.json({ error: 'role_not_allowed' }, { status: 403 });",
      '  await db.connector.upsert({ where: { id: 1 }, update: {}, create: {} });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    [route('remediation/execute')]: [
      "import { db } from '@/lib/db';",
      'export async function POST(request: Request) {',
      '  const { org_id, plan_id } = await request.json();',
      '  const plan = await db.plan.findUnique({ where: { id: plan_id, org_id } });',
      "  if (plan.requires_approval && plan.status !== 'approved') return Response.json({ error: 'approval' }, { status: 403 });",
      '  await db.execution.create({ data: { org_id } });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    [route('origin/only')]: [
      "import { db } from '@/lib/db';",
      "import { isSameOrigin } from '@/lib/origin';",
      'export async function POST(request: Request) {',
      "  if (!isSameOrigin(request)) return Response.json({ error: 'origin' }, { status: 403 });",
      '  await db.thing.create({ data: {} });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    // The real thing, for contrast: the result of a credential check gates the write.
    [route('gateway/verified')]: [
      "import { verifySession } from '@/lib/session';",
      "import { db } from '@/lib/db';",
      'export async function POST(request: Request) {',
      '  const session = await verifySession(request.headers);',
      "  if (!session || session.role !== 'admin') return Response.json({ error: 'no' }, { status: 403 });",
      '  await db.connector.upsert({ where: { id: 1 }, update: {}, create: {} });',
      '  return Response.json({ ok: true });',
      '}',
    ],
  });
  assert.deepEqual(found[route('gateway/connectors')], ['critical'], 'a role header is a claim, not a credential');
  assert.deepEqual(found[route('gateway/connectors-helper')], ['critical'], 'a helper that only reads a header verifies nothing');
  assert.deepEqual(found[route('remediation/execute')], ['critical'], 'row state chosen by the body is not identity');
  assert.deepEqual(found[route('origin/only')], ['critical'], 'an Origin check is not authentication');
  assert.equal(found[route('gateway/verified')], undefined);
});

test('the unauthenticated writes the sample really had are still reported', async () => {
  const found = await scanApp({
    [route('log')]: [
      "import { db, logsTable } from '@/lib/db';",
      'export async function POST(request: Request) {',
      '  const body = await request.json();',
      '  await db.insert(logsTable).values(body);',
      '  return Response.json({ ok: true });',
      '}',
    ],
    [route('rooms')]: [
      "import { getRoomService } from '@/lib/livekit';",
      'export async function POST(request: Request) {',
      '  const { name } = await request.json();',
      '  await getRoomService().createRoom({ name });',
      '  return Response.json({ ok: true });',
      '}',
    ],
    [route('grafana')]: [
      'export async function POST(request: Request) {',
      '  const { queries } = await request.json();',
      '  const res = await fetch(`${process.env.GRAFANA_URL}/api/ds/query`, {',
      '    method: "POST", headers: { Authorization: `Bearer ${process.env.GRAFANA_API_TOKEN}` }, body: JSON.stringify({ queries }),',
      '  });',
      '  return Response.json(await res.json());',
      '}',
    ],
  });
  assert.deepEqual(found[route('log')], ['critical']);
  assert.deepEqual(found[route('rooms')], ['high']);
  assert.deepEqual(found[route('grafana')], ['high']);
});
