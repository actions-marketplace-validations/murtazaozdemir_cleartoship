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
