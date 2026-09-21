import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { scan } from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const VULNERABLE = join(here, 'fixtures', 'vulnerable-app');
const CLEAN = join(here, 'fixtures', 'clean-app');

// Unlike server-actions.test.js, these assertions never touch the generated
// .env / symlink state buildFixtures() produces (only the committed SQL
// migration and RLS-scanner-relevant fixture files), and skipping the call
// here avoids a symlink-creation race with server-actions.test.js when
// `node --test` runs multiple files concurrently.

const RLS_IDS = [
  'CTS010', 'CTS012', 'CTS013', 'CTS014', 'CTS015',
  'CTS016', 'CTS017', 'CTS018', 'CTS019', 'CTS050', 'CTS051', 'CTS052',
];

test('the RLS suite fires on the vulnerable migration', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const found = new Set(result.findings.map((f) => f.id));
  for (const id of RLS_IDS) assert.ok(found.has(id), `expected ${id} to be reported`);

  const byId = (id) => result.findings.find((f) => f.id === id);
  assert.equal(byId('CTS010').line, 16, 'CTS010 should point at the CREATE TABLE, not the closing paren');
  assert.equal(byId('CTS017').line, 50);
  const definerView = result.findings.find((f) => f.id === 'CTS016' && f.severity === 'medium');
  assert.equal(definerView.line, 47, 'the SECURITY DEFINER view is at line 47');
  const matview = result.findings.find((f) => f.id === 'CTS016' && f.severity === 'high');
  assert.equal(matview.line, 55, 'the materialized view is at line 55');
});

test('the clean fixture is silent on RLS', async () => {
  const result = await scan({ root: CLEAN, offline: true });
  const rls = result.findings.filter((f) => RLS_IDS.includes(f.id));
  assert.deepEqual(rls, []);
});

test('re-declaring a table with IF NOT EXISTS does not undo RLS enabled on it earlier', async () => {
  // Sampled from a real repository: a schema dump (`schema_check.sql`) re-declared every
  // table with CREATE TABLE IF NOT EXISTS after the migrations had enabled RLS on them.
  // In Postgres that statement does nothing to an existing table; the model treated it as
  // a fresh table with RLS off, and reported each one as unprotected.
  const { mkdtempSync, mkdirSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'cts-rls-dump-'));
  const put = (rel, body) => {
    mkdirSync(join(dir, rel, '..'), { recursive: true });
    writeFileSync(join(dir, rel), body);
  };
  put('package.json', JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { '@supabase/supabase-js': '2.0.0' } }));
  put('supabase/migrations/001_init.sql', [
    'create table public.admin_costs (id uuid primary key, amount numeric);',
    'alter table public.admin_costs enable row level security;',
    'create policy "own" on public.admin_costs for select using (auth.uid() = id);',
  ].join('\n'));
  // A dump that repeats the table, and one table that no migration ever protected.
  put('supabase/schema_check.sql', [
    'create table if not exists public.admin_costs (id uuid primary key, amount numeric);',
    'create table if not exists public.unprotected (id uuid primary key, note text);',
  ].join('\n'));

  const result = await scan({ root: dir, offline: true, noCommunity: true });
  const tables = result.findings.filter((f) => f.id === 'CTS010').map((f) => /`([^`]+)`/.exec(f.detail)[1]);
  assert.deepEqual(tables, ['public.unprotected'], 'only the table nothing ever protected is a finding');
});
