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
