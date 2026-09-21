import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { scan } from '../dist/index.js';
import { buildFixtures } from './fixture-setup.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => join(here, 'fixtures', name);
const VULNERABLE = fixture('vulnerable-app');
const CLEAN = fixture('clean-app');
const INDIRECT = fixture('indirect-auth-app');

buildFixtures();

const SERVER_ACTIONS_IDS = ['CTS001', 'CTS002', 'CTS003', 'CTS004', 'CTS041', 'CTS042', 'CTS043', 'CTS044', 'CTS046'];

test('the Server Actions suite fires on the vulnerable fixture', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const found = new Set(result.findings.map((f) => f.id));
  for (const id of SERVER_ACTIONS_IDS) assert.ok(found.has(id), `expected ${id} to be reported`);
  assert.equal(
    result.findings.find((f) => f.id === 'CTS001').file,
    'app/actions/admin.ts',
  );
});

test('the correctly written action is not flagged', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const safe = result.findings.filter((f) => f.file === 'app/actions/safe.ts');
  assert.deepEqual(safe, [], `safe.ts should be clean, got ${safe.map((f) => f.id).join(', ')}`);
});

test('the clean fixture is silent on Server Actions', async () => {
  const result = await scan({ root: CLEAN, offline: true });
  const sa = result.findings.filter((f) => SERVER_ACTIONS_IDS.includes(f.id));
  assert.deepEqual(sa, []);
});

test('auth resolved in an imported helper counts as auth', async () => {
  const result = await scan({ root: INDIRECT, offline: true });
  const action = result.findings.filter((f) => f.file === 'app/actions/team.ts');
  assert.deepEqual(
    action.map((f) => f.id),
    [],
    `renameTeam authenticates via requireUser() from @/lib/auth, got ${action.map((f) => `${f.id}@${f.line}`).join(', ')}`,
  );
});

test('a shared-secret cron endpoint is authenticated, and its health check is not a finding', async () => {
  const result = await scan({ root: INDIRECT, offline: true });
  const route = result.findings.filter((f) => f.file === 'app/api/cron/digest/route.ts');
  assert.deepEqual(
    route.filter((f) => f.id === 'CTS001' || f.id === 'CTS046').map((f) => `${f.id}@${f.line}`),
    [],
    'the POST compares Authorization against CRON_SECRET; the GET returns a constant',
  );
  assert.equal(route.filter((f) => f.id === 'CTS002').length, 0);
});

test('mass assignment is the payload arriving whole, not any write of caller input', async () => {
  const bad = await scan({ root: VULNERABLE, offline: true });
  const flagged = bad.findings.filter((f) => f.file === 'app/actions/mass-assign.ts');

  assert.ok(flagged.some((f) => f.id === 'CTS002' && f.line === 10), 'a payload written whole is CTS002');
  assert.ok(flagged.some((f) => f.id === 'CTS043' && f.line === 18), 'a nested spread of the payload is CTS043');

  const clean = await scan({ root: CLEAN, offline: true });
  assert.deepEqual(clean.findings.map((f) => `${f.id} ${f.file}:${f.line}`), []);
});

test('getSession() does not satisfy the auth check, and replaces CTS001 there', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const settings = result.findings.filter((f) => f.file === 'app/actions/settings.ts');
  const found = new Set(settings.map((f) => f.id));
  assert.ok(found.has('CTS041'), 'supabase.auth.getSession() must be reported');
  assert.ok(!found.has('CTS001'), 'CTS041 is the precise diagnosis; the generic missing-auth rule should not double-report');
});

test('webhook that verifies via a framework helper or sig header is not flagged', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const cts042 = result.findings.filter((f) => f.id === 'CTS042').map((f) => f.file);
  assert.ok(cts042.includes('app/api/webhooks/stripe/route.ts'), 'the unverified webhook must still be flagged');
  assert.ok(
    !cts042.some((f) => f.includes('stripe-verified')),
    'a webhook that reads the signature header + verifies must not be flagged',
  );
});
