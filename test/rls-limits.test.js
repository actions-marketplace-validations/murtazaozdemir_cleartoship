import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { scan } from '../dist/index.js';

// Regression tests for the two RLS "known limits" the 2026-09-23 audit left
// open: one schema built from every .sql file in the repo, and CTS014
// crediting a table as isolated when any one policy used auth.uid(). Each case
// is the reproduction, built as a throwaway project.

const SUPABASE_PKG = JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { '@supabase/supabase-js': '2.0.0' } });

function project(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cts-rls-limits-'));
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(join(dir, rel, '..'), { recursive: true });
    writeFileSync(join(dir, rel), Array.isArray(body) ? body.join('\n') : body);
  }
  return dir;
}

async function rlsFindings(files) {
  const result = await scan({ root: project(files), offline: true, noCommunity: true });
  return result.findings.filter((f) => /^CTS0(1\d|5[0-2])$/.test(f.id));
}

const where = (findings) => findings.map((f) => `${f.id} ${f.file}:${f.meta?.table ?? ''}`).sort();

// --- 1. One schema per project ----------------------------------------------

const CLEAN = [
  'create table public.workspaces (id uuid primary key, user_id uuid not null, name text);',
  'alter table public.workspaces enable row level security;',
  'create policy "own workspaces" on public.workspaces for select to authenticated using (user_id = (select auth.uid()));',
];
const VULNERABLE = [
  'create table public.workspaces (id uuid primary key, user_id uuid not null, name text);',
  'alter table public.workspaces enable row level security;',
  'create policy "team can read" on public.workspaces for select to authenticated using (true);',
];

test('two apps in one repo each get their own schema (the fixtures-in-one-repo reproduction)', async () => {
  const f = await rlsFindings({
    'package.json': JSON.stringify({ name: 'root' }),
    'fixtures/clean/package.json': SUPABASE_PKG,
    'fixtures/clean/supabase/migrations/001.sql': CLEAN,
    'fixtures/vulnerable/package.json': SUPABASE_PKG,
    'fixtures/vulnerable/supabase/migrations/001.sql': VULNERABLE,
  });
  // Mixed into one schema, the two `workspaces` tables were one table with
  // both policies: the clean app got a CTS050 and the vulnerable app's CTS014
  // disappeared because the clean app's policy used auth.uid().
  assert.deepEqual(where(f), ['CTS014 fixtures/vulnerable/supabase/migrations/001.sql:public.workspaces']);
});

test('the same table name in two monorepo packages is two tables', async () => {
  const f = await rlsFindings({
    'package.json': JSON.stringify({ name: 'mono', private: true, workspaces: ['apps/*', 'packages/*'] }),
    'apps/web/package.json': SUPABASE_PKG,
    'packages/db/package.json': SUPABASE_PKG,
    'apps/admin/package.json': SUPABASE_PKG,
    'apps/admin/supabase/migrations/001.sql': ['create table public.notes (id uuid primary key, body text);'],
    'packages/db/supabase/config.toml': 'project_id = "db"',
    'packages/db/supabase/migrations/001.sql': [
      'create table public.notes (id uuid primary key, body text);',
      'alter table public.notes enable row level security;',
    ],
  });
  // The db package's ENABLE must not switch RLS on for the admin app's table:
  // it sorts after it, so a shared schema reported neither.
  assert.deepEqual(
    f.filter((x) => x.id === 'CTS010').map((x) => x.file),
    ['apps/admin/supabase/migrations/001.sql'],
  );
});

test('a single-app repo stays one project: migrations, schemas/, seed.sql, a root db/ dir, supabase/package.json', async () => {
  const f = await rlsFindings({
    'package.json': SUPABASE_PKG,
    'supabase/package.json': JSON.stringify({ name: 'edge-tooling' }),
    'supabase/config.toml': 'project_id = "app"',
    'supabase/migrations/001_tables.sql': ['create table public.notes (id uuid primary key, user_id uuid, body text);'],
    'supabase/schemas/rls.sql': ['alter table public.notes enable row level security;'],
    'db/policies.sql': ['create policy "own" on public.notes for all to authenticated using (user_id = auth.uid());'],
    'supabase/seed.sql': ["insert into public.notes (id, body) values (gen_random_uuid(), 'hello');"],
  });
  assert.deepEqual(f, [], 'RLS enabled in schemas/ and a policy in db/ both apply to the table from migrations/');
});

test('a repo with no package.json and SQL in migrations/ is one project rooted at the scan root', async () => {
  const f = await rlsFindings({
    'migrations/001.sql': ['create table public.notes (id uuid primary key, body text);'],
    'migrations/002.sql': [
      'alter table public.notes enable row level security;',
      'create policy "r" on public.notes for select to authenticated using (auth.uid() is not null and false);',
    ],
  });
  assert.deepEqual(f, []);
});

test('Prisma migrations whose migration_lock.toml says sqlite are not Postgres tables', async () => {
  const init = [
    '-- CreateTable',
    'CREATE TABLE "Session" (',
    '    "id" TEXT NOT NULL PRIMARY KEY,',
    '    "shop" TEXT NOT NULL,',
    '    "expires" DATETIME',
    ');',
  ];
  const f = await rlsFindings({
    'package.json': JSON.stringify({ name: 'shopify-app' }),
    'prisma/migrations/migration_lock.toml': 'provider = "sqlite"\n',
    'prisma/migrations/20260101_init/migration.sql': init,
    // A Supabase app beside it, with an RLS idiom, switches the repo-wide
    // Postgres signal on — which is what swept the Prisma models in.
    'saas/package.json': SUPABASE_PKG,
    'saas/supabase/migrations/001.sql': [
      'create table public.accounts (id uuid primary key);',
      'create table public.notes (id uuid primary key, body text);',
      'alter table public.notes enable row level security;',
      'create policy "r" on public.notes for select to authenticated using (auth.uid() is not null and false);',
    ],
  });
  assert.deepEqual(where(f), ['CTS010 saas/supabase/migrations/001.sql:public.accounts']);

  const pg = await rlsFindings({
    'package.json': SUPABASE_PKG,
    'prisma/migrations/migration_lock.toml': 'provider = "postgresql"\n',
    'prisma/migrations/20260101_init/migration.sql': init,
  });
  assert.deepEqual(where(pg), ['CTS010 prisma/migrations/20260101_init/migration.sql:public.Session'],
    'a postgresql lock leaves the migration modelled');
});

// --- 2. CTS014 per command: a gate OR'd onto a scoped policy ----------------

const supa = (lines) => ({ 'package.json': SUPABASE_PKG, 'supabase/migrations/001.sql': lines });
const ids = (findings) => findings.map((f) => f.id).sort();
const NOTES = [
  'create table public.notes (id uuid primary key, user_id uuid not null, body text);',
  'alter table public.notes enable row level security;',
];

test("an auth.role() = 'authenticated' policy OR'd with a scoped one is CTS014, and absorbs the CTS050", async () => {
  const f = await rlsFindings(supa([
    ...NOTES,
    'create policy "own notes" on public.notes for all to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));',
    "create policy \"signed in can read\" on public.notes for select to authenticated using (auth.role() = 'authenticated');",
  ]));
  assert.deepEqual(ids(f), ['CTS014'], 'the old rule saw auth.uid() somewhere and passed the table; CTS050 is the same root cause');
  assert.equal(f[0].meta.policy, 'signed in can read');
  assert.deepEqual(f[0].meta.commands, ['SELECT']);
  assert.deepEqual(f[0].meta.scopedBy, ['own notes']);
});

test('the gate is recognised however it is spelled', async () => {
  for (const gate of [
    "(select auth.role()) = 'authenticated'",
    "'authenticated' = auth.role()",
    "auth.role() <> 'anon'",
    "(auth.jwt() ->> 'role') = 'authenticated'",
    '(select auth.uid()) is not null',
    "auth.uid() IS NOT NULL AND (auth.jwt() ->> 'aal') = 'aal2'",
    "current_setting('request.jwt.claim.role', true) = 'authenticated'",
  ]) {
    const f = await rlsFindings(supa([
      ...NOTES,
      'create policy "own" on public.notes for select using (user_id = auth.uid());',
      `create policy "gate" on public.notes for select using (${gate});`,
    ]));
    assert.deepEqual(ids(f), ['CTS014'], gate);
  }
});

test('an isolating RESTRICTIVE policy closes the leak; one on another command does not', async () => {
  const closed = await rlsFindings(supa([
    ...NOTES,
    "create policy \"gate\" on public.notes for all to authenticated using (auth.role() = 'authenticated');",
    'create policy "owner only" on public.notes as restrictive for all to authenticated using (user_id = auth.uid());',
  ]));
  assert.deepEqual(ids(closed), []);

  const partly = await rlsFindings(supa([
    ...NOTES,
    "create policy \"gate\" on public.notes for all to authenticated using (auth.role() = 'authenticated');",
    'create policy "owner reads" on public.notes as restrictive for select to authenticated using (user_id = auth.uid());',
  ]));
  assert.deepEqual(ids(partly), ['CTS014']);
  assert.deepEqual(partly[0].meta.commands, ['INSERT', 'UPDATE', 'DELETE']);
});

test('a gate on a write is CTS014 even with no scoped policy for that command', async () => {
  const f = await rlsFindings(supa([
    ...NOTES,
    'create policy "read own" on public.notes for select to authenticated using (user_id = auth.uid());',
    'create policy "insert own" on public.notes for insert to authenticated with check (user_id = auth.uid());',
    "create policy \"edit\" on public.notes for update to authenticated using (auth.role() = 'authenticated');",
  ]));
  assert.deepEqual(ids(f), ['CTS014']);
  assert.deepEqual(f[0].meta.commands, ['UPDATE']);
  assert.deepEqual(f[0].meta.scopedBy, []);
});

test('correct code stays clean: deliberate reads-for-everyone beside owner-scoped writes', async () => {
  // Members read every comment, write only their own.
  const members = await rlsFindings(supa([
    'create table public.comments (id uuid primary key, user_id uuid not null, body text);',
    'alter table public.comments enable row level security;',
    "create policy \"members read\" on public.comments for select using (auth.role() = 'authenticated');",
    'create policy "write own" on public.comments for insert to authenticated with check (user_id = auth.uid());',
    'create policy "delete own" on public.comments for delete to authenticated using (user_id = auth.uid());',
  ]));
  assert.deepEqual(ids(members), []);

  // The Supabase tutorial shape: public read, owner manages. An explicit publication, not a gate.
  const posts = await rlsFindings(supa([
    'create table public.posts (id uuid primary key, user_id uuid not null, title text);',
    'alter table public.posts enable row level security;',
    'create policy "anyone reads" on public.posts for select using (true);',
    'create policy "own posts" on public.posts for all to authenticated using (auth.uid() = user_id);',
  ]));
  assert.deepEqual(ids(posts), []);

  // Signed-in check AND ownership still isolates; the service-role escape hatch reaches no user.
  const combined = await rlsFindings(supa([
    ...NOTES,
    'create policy "own" on public.notes for all using (auth.uid() is not null and user_id = auth.uid());',
    "create policy \"service\" on public.notes for all using ((select auth.role()) = 'service_role');",
  ]));
  // (Two FOR ALL policies for `public` still overlap: that CTS050 is unchanged and beside the point.)
  assert.deepEqual(ids(combined).filter((id) => id !== 'CTS050'), []);
});

test('auth.uid() IS NOT NULL alone is not isolation: the whole-table CTS014 fires', async () => {
  const f = await rlsFindings(supa([
    ...NOTES,
    'create policy "signed in" on public.notes for select to authenticated using (auth.uid() is not null);',
  ]));
  assert.deepEqual(ids(f), ['CTS014'], 'the old rule counted any mention of auth.uid() as isolation');
});

test('membership subqueries and helper functions that read auth.uid() isolate', async () => {
  const helper = await rlsFindings(supa([
    'create table public.members (org_id uuid, user_id uuid);',
    'alter table public.members enable row level security;',
    'create policy "self" on public.members for select using (user_id = auth.uid());',
    'create table public.docs (id uuid primary key, org_id uuid not null, body text);',
    'alter table public.docs enable row level security;',
    "create or replace function public.is_member(o uuid) returns boolean language sql security definer set search_path = '' as $$",
    '  select exists (select 1 from public.members m where m.org_id = o and m.user_id = auth.uid())',
    '$$;',
    'create or replace function public.can_read(o uuid) returns boolean language sql as $$ select public.is_member(o) $$;',
    'create policy "org read" on public.docs for select to authenticated using (public.can_read(org_id));',
    'create policy "org write" on public.docs for insert to authenticated with check (org_id in (select org_id from public.members where user_id = auth.uid()));',
  ]));
  assert.deepEqual(ids(helper), [], 'a helper, even one calling another helper, isolates by what its body checks');

  const gateHelper = await rlsFindings(supa([
    ...NOTES,
    'create function public.signed_in() returns boolean language sql as $$ select auth.uid() is not null $$;',
    'create policy "own" on public.notes for select to authenticated using (user_id = auth.uid());',
    'create policy "anyone signed in edits" on public.notes for delete to authenticated using (public.signed_in());',
  ]));
  assert.deepEqual(ids(gateHelper), ['CTS014']);
  assert.deepEqual(gateHelper[0].meta.commands, ['DELETE']);
});
