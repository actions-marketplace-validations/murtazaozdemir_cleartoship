import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import { scan } from '../dist/index.js';

// Found on a real app (aistoreaudit) while checking that a JWT-hardening fix actually took:
// pinning `algorithms: [ALG]` still got flagged, because VG105's "no algorithms option" branch
// ends on the first `)` after the second argument. When that argument is itself a call —
// `getJwtSecret()` — the regex backtracks onto ITS closing paren, matches only
// `jwt.verify(token, getJwtSecret()`, and never reaches the real options object two
// characters later. Confirmed against the pattern directly before writing the guard.

async function scanFile(name, body) {
  const dir = mkdtempSync(join(tmpdir(), 'vg105-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { next: '15.5.24', react: '19.0.0' } }),
  );
  mkdirSync(dirname(join(dir, name)), { recursive: true });
  writeFileSync(join(dir, name), body);
  const result = await scan({ root: dir, offline: true, noCommunity: false });
  return result.findings.filter((f) => f.id === 'VG105');
}

test('algorithms pinned through a nested call in the secret argument is not a finding', async () => {
  const found = await scanFile(
    'lib/jwt.ts',
    [
      "import jwt from 'jsonwebtoken';",
      "const JWT_ALGORITHM = 'HS256';",
      'function getJwtSecret() { return process.env.JWT_SECRET!; }',
      'export function verifyToken(token: string) {',
      '  return jwt.verify(token, getJwtSecret(), { algorithms: [JWT_ALGORITHM] });',
      '}',
    ].join('\n'),
  );
  assert.deepEqual(found, []);
});

test('algorithms pinned with a literal secret argument is not a finding (regression)', async () => {
  const found = await scanFile(
    'lib/jwt.ts',
    [
      "import jwt from 'jsonwebtoken';",
      'export function verifyToken(token: string, secret: string) {',
      "  return jwt.verify(token, secret, { algorithms: ['HS256'] });",
      '}',
    ].join('\n'),
  );
  assert.deepEqual(found, []);
});

test('no algorithms option, secret argument is a nested call: still a finding', async () => {
  const found = await scanFile(
    'lib/jwt.ts',
    [
      "import jwt from 'jsonwebtoken';",
      'function getJwtSecret() { return process.env.JWT_SECRET!; }',
      'export function verifyToken(token: string) {',
      '  return jwt.verify(token, getJwtSecret());',
      '}',
    ].join('\n'),
  );
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'medium');
});

test('an explicit alg:none allowlist is still reported wherever it appears', async () => {
  const found = await scanFile(
    'lib/jwt.ts',
    [
      "import jwt from 'jsonwebtoken';",
      'export function verifyToken(token: string, secret: string) {',
      "  return jwt.verify(token, secret, { algorithms: ['none'] });",
      '}',
    ].join('\n'),
  );
  assert.ok(found.length >= 1);
  assert.equal(found[0].severity, 'critical');
});
