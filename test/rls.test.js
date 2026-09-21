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
