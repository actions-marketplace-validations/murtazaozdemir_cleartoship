import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { scan } from '../dist/index.js';

// Regression tests for the RLS-scanner audit findings. Each case is the
// reproduction that showed the bug, built as a throwaway project so nothing
// here depends on the shared fixtures.

const SUPABASE_PKG = JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { '@supabase/supabase-js': '2.0.0' } });

function project(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cts-rls-audit-'));
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

const migration = (lines) => ({ 'package.json': SUPABASE_PKG, 'supabase/migrations/001.sql': lines });
const ids = (findings) => findings.map((f) => f.id).sort();

test('words in a quoted policy name are not read as its FOR clause (Supabase default read policy)', async () => {
  const f = await rlsFindings(migration([
    'create table public.posts (id uuid primary key, title text, body text);',
    'alter table public.posts enable row level security;',
    'create policy "Enable read access for all users" on public.posts for select using (true);',
  ]));
  assert.deepEqual(ids(f), [], 'a public SELECT with USING (true) on a non-sensitive table is not a write');
});

test('" to " inside a policy name does not swallow the role list', async () => {
  const f = await rlsFindings(migration([
    'create table cart (id uuid primary key, item text, qty int);',
    'alter table cart enable row level security;',
    'create policy "Anyone can add to cart" on cart for delete using (true);',
  ]));
  assert.deepEqual(ids(f), ['CTS012']);
  assert.equal(f[0].meta.command, 'DELETE');
  assert.deepEqual(f[0].meta.roles, ['public']);
});

test('an unquoted policy name and header words inside a predicate string are ignored', async () => {
  const f = await rlsFindings(migration([
    'create table public.notes (id uuid primary key, kind text);',
    'alter table public.notes enable row level security;',
    "create policy for_all on public.notes for select to authenticated using (kind = 'for all to anon');",
  ]));
  assert.deepEqual(ids(f), []);
});

test('FORCE ROW LEVEL SECURITY without ENABLE leaves RLS off', async () => {
  const f = await rlsFindings(migration([
    'create table public.notes (id uuid primary key, body text);',
    'alter table public.notes force row level security;',
    'create policy "read" on public.notes for select to authenticated using (true);',
  ]));
  assert.deepEqual(ids(f), ['CTS010']);
});

test('NO FORCE after ENABLE leaves RLS on', async () => {
  const f = await rlsFindings(migration([
    'create table public.notes (id uuid primary key, body text);',
    'alter table public.notes enable row level security;',
    'alter table public.notes force row level security;',
    'alter table public.notes no force row level security;',
    'create policy "read" on public.notes for select to authenticated using (true);',
  ]));
  assert.deepEqual(ids(f), []);
});

test('an always-true RESTRICTIVE policy grants nothing and is not an unrestricted write', async () => {
  const f = await rlsFindings(migration([
    'create table public.notes (id uuid primary key, user_id uuid, body text);',
    'alter table public.notes enable row level security;',
    'create policy "own" on public.notes for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());',
    'create policy "no-op restrictive" on public.notes as restrictive for update to authenticated using (true);',
  ]));
  assert.deepEqual(ids(f), []);
});

test('restrictive policies do not count toward overlapping-permissive CTS050', async () => {
  const f = await rlsFindings(migration([
    'create table public.notes (id uuid primary key, user_id uuid, body text);',
    'alter table public.notes enable row level security;',
    'create policy "own" on public.notes for select to authenticated using (user_id = auth.uid());',
    "create policy \"not banned\" on public.notes as restrictive for select to authenticated using ((auth.jwt() ->> 'banned') is null);",
  ]));
  assert.deepEqual(ids(f), []);
});

test('only restrictive policies on a table is fail-closed: CTS011, not CTS012', async () => {
  const f = await rlsFindings(migration([
    'create table public.notes (id uuid primary key, body text);',
    'alter table public.notes enable row level security;',
    'create policy "r" on public.notes as restrictive for delete to anon using (true);',
  ]));
  assert.deepEqual(ids(f), ['CTS011']);
});

test('unquoted identifiers are case-folded; quoted ones are not', async () => {
  const folded = await rlsFindings(migration([
    'CREATE TABLE Profiles (id uuid primary key, bio text);',
    'ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;',
    'CREATE POLICY "own" ON PROFILES FOR SELECT TO authenticated USING (id = auth.uid());',
  ]));
  assert.deepEqual(ids(folded), []);

  const quoted = await rlsFindings(migration([
    'CREATE TABLE "Profiles" (id uuid primary key, bio text);',
    'ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;',
  ]));
  assert.ok(ids(quoted).includes('CTS010'), '"Profiles" and profiles are different tables');
  assert.equal(quoted.find((x) => x.id === 'CTS010').meta.table, 'public.Profiles');
});

for (const predicate of ['1 = 1', '1=1', "'a'='a'", 'true = true', '((true))', 'not false', 'true::boolean', '( 1 = 1 )']) {
  test(`always-true predicate \`${predicate}\` on an anon DELETE is CTS012`, async () => {
    const f = await rlsFindings(migration([
      'create table public.orders (id uuid primary key, total int);',
      'alter table public.orders enable row level security;',
      `create policy "w" on public.orders for delete to anon using (${predicate});`,
    ]));
    assert.deepEqual(ids(f), ['CTS012']);
  });
}

for (const predicate of ['1 = 2', 'not true', 'false', 'id = id', "auth.uid() = '1'", '1 >= 1', 'user_id = auth.uid()']) {
  test(`predicate \`${predicate}\` is not judged always-true`, async () => {
    const f = await rlsFindings(migration([
      'create table public.orders (id uuid primary key, total int);',
      'alter table public.orders enable row level security;',
      `create policy "w" on public.orders for delete to anon using (${predicate});`,
    ]));
    assert.ok(!ids(f).includes('CTS012'), `${predicate} should not be an unrestricted write`);
  });
}

test("auth.role() = 'authenticated' is not tenant isolation: CTS014 fires", async () => {
  const f = await rlsFindings(migration([
    'create table public.invoices (id uuid primary key, user_id uuid, amount int);',
    'alter table public.invoices enable row level security;',
    "create policy \"signed in can read\" on public.invoices for select using (auth.role() = 'authenticated');",
  ]));
  assert.deepEqual(ids(f), ['CTS014']);
});

test('a per-user table whose only policy admits the service role is not CTS014', async () => {
  const f = await rlsFindings(migration([
    'create table public.invoices (id uuid primary key, user_id uuid, amount int);',
    'alter table public.invoices enable row level security;',
    "create policy \"service\" on public.invoices for all using ((select auth.role()) = 'service_role');",
  ]));
  assert.deepEqual(ids(f), []);
});

test('DROP TABLE drops every table in its list, with IF EXISTS and CASCADE', async () => {
  const f = await rlsFindings(migration([
    'create table public.a (id int);',
    'create table public.b (id int);',
    'create table public.c (id int);',
    'drop table if exists a, public.b cascade;',
  ]));
  assert.deepEqual(f.filter((x) => x.id === 'CTS010').map((x) => x.meta.table), ['public.c']);
});

// --- Which .sql files are Postgres at all -----------------------------------

const D1_TABLE = [
  'CREATE TABLE IF NOT EXISTS licenses (',
  '  jti TEXT PRIMARY KEY,',
  '  email TEXT NOT NULL,',
  '  created_at INTEGER NOT NULL DEFAULT (unixepoch())',
  ');',
];
const D1_PLAIN = ['CREATE TABLE licenses (jti TEXT PRIMARY KEY, email TEXT NOT NULL);'];
const tablesOf = (findings) => findings.filter((f) => f.id === 'CTS010').map((f) => `${f.file}:${f.meta.table}`).sort();

test('a Cloudflare D1 migration in a Supabase repo is not a Supabase table (wrangler.jsonc d1_databases)', async () => {
  const f = await rlsFindings({
    'package.json': SUPABASE_PKG,
    'supabase/migrations/001.sql': 'create table public.unprotected (id uuid primary key);',
    'site/package.json': JSON.stringify({ name: 'site', dependencies: { wrangler: '4.0.0' } }),
    'site/wrangler.jsonc': '{\n  // comment\n  "d1_databases": [{ "binding": "DB", "migrations_dir": "migrations" }]\n}',
    'site/migrations/0001_licenses.sql': D1_PLAIN,
  });
  assert.deepEqual(tablesOf(f), ['supabase/migrations/001.sql:public.unprotected'],
    'the D1 table is skipped, the real Supabase table is still reported');
});

test('a D1 migrations_dir outside the worker directory is recognised (wrangler.toml)', async () => {
  const f = await rlsFindings({
    'package.json': SUPABASE_PKG,
    'worker/wrangler.toml': '[[d1_databases]]\nbinding = "DB"\nmigrations_dir = "../db/d1"\n',
    'db/d1/0001.sql': D1_PLAIN,
    'db/pg/0001.sql': 'create table public.accounts (id uuid primary key);',
  });
  assert.deepEqual(tablesOf(f), ['db/pg/0001.sql:public.accounts']);
});

test('SQL under supabase/, or carrying RLS idioms, is Postgres even inside a D1 worker tree', async () => {
  const f = await rlsFindings({
    'package.json': JSON.stringify({ name: 'worker' }),
    'wrangler.toml': '[[d1_databases]]\nbinding = "DB"\n',
    'supabase/migrations/001.sql': 'create table public.a (id uuid primary key);',
    'sql/policies.sql': [
      'create table public.b (id uuid primary key);',
      'create policy "p" on public.b for select to anon using (true);',
    ],
    'sql/d1.sql': D1_PLAIN,
  });
  assert.deepEqual(tablesOf(f), ['sql/policies.sql:public.b', 'supabase/migrations/001.sql:public.a']);
});

test('SQLite-only syntax outside supabase/ is not modelled as Postgres; plain SQL still is', async () => {
  const f = await rlsFindings({
    'package.json': SUPABASE_PKG,
    'db/sqlite.sql': 'CREATE TABLE cache (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);',
    'db/local.sql': D1_TABLE,
    'db/plain.sql': 'create table events (id integer primary key, kind text);',
    'db/mixed.sql': "create table things (id uuid primary key, at text default (datetime('now')));",
  });
  assert.deepEqual(tablesOf(f), ['db/mixed.sql:public.things', 'db/plain.sql:public.events'],
    'SQLite markers exclude a file only when nothing Postgres-only is in it');
});

test("a package that depends on Supabase makes its SQL relevant even when the root doesn't", async () => {
  const f = await rlsFindings({
    'package.json': JSON.stringify({ name: 'mono', private: true }),
    'packages/db/package.json': SUPABASE_PKG,
    'packages/db/sql/schema.sql': 'create table public.profiles (id uuid primary key, email text);',
  });
  assert.deepEqual(tablesOf(f), ['packages/db/sql/schema.sql:public.profiles']);
});

test('without any Postgres signal, SQL is still left alone', async () => {
  const f = await rlsFindings({
    'package.json': JSON.stringify({ name: 'x' }),
    'schema.sql': 'create table notes (id integer primary key, body text);',
  });
  assert.deepEqual(f, []);
});
