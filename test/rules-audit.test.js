// Regression tests for the 2026-09-23 rules audit. Each test names the audit
// fixture it reproduces; every one of them failed before its fix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { scan } from '../dist/index.js';
import { normaliseOwasp } from '../dist/utils/owasp.js';
import { PATTERN_OVERRIDES, anchoredToInput } from '../dist/scanners/community.js';
import { GUARDVIBE_RULES } from '../dist/vendor/guardvibe/index.js';
import { LineIndex } from '../dist/utils/line-index.js';
import { lineAt } from '../dist/utils/files.js';

/** A throwaway project from a { path: contents } map. */
function project(files) {
  const root = mkdtempSync(join(tmpdir(), 'cts-audit-'));
  for (const [path, contents] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), contents);
  }
  return root;
}

const byId = (result, id) => result.findings.filter((f) => f.id === id);

// Credential-shaped values are assembled at runtime so this file is not itself
// a file full of keys.
const OPENAI = ['sk', 'proj', 'u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzdocJ2isAj'].join('-');
const STRIPE = ['sk', 'live', 'DNxril3RavGD5MfvJ7NScUykT8C8UBkkpdhiG37L'].join('_');
const AWS = 'AKIA' + 'QWERTYUIOPASDFGH';

// --- secrets.ts -----------------------------------------------------------

test('S1/S5: a Markdown bullet and a shell continuation line are not comments', async () => {
  const root = project({
    'package.json': '{"name":"s"}',
    'SETUP.md': `# Setup\n\n* OPENAI_API_KEY=${OPENAI}\n`,
    'deploy.sh': `#!/bin/sh\nstripe charges list \\\n  --api-key ${STRIPE} \\\n  --limit 5\n`,
  });
  const result = await scan({ root, offline: true, noCommunity: true });
  const files = byId(result, 'CTS030').map((f) => f.file).sort();
  assert.deepEqual(files, ['SETUP.md', 'deploy.sh']);
});

test('S1/S5: real comments in each language still read as comments', async () => {
  const root = project({
    'package.json': '{"name":"s"}',
    '.env': `# OPENAI_API_KEY=${OPENAI}\n`,
    'lib/a.ts': `/**\n * const key = ${STRIPE}\n */\n// const other = ${OPENAI}\nexport const x = 1\n`,
    'db/seed.sql': `-- stripe: ${STRIPE}\nselect 1;\n`,
    'deploy.sh': `# export KEY=${STRIPE}\n`,
  });
  const result = await scan({ root, offline: true, noCommunity: true });
  assert.deepEqual(byId(result, 'CTS030').map((f) => `${f.file}:${f.line}`), []);
});

test('S6: CTS031 and the other variable-level rules redact the value on their line', async () => {
  const root = project({
    'package.json': '{"name":"s","dependencies":{"next":"15.0.0"}}',
    '.env.production': `NEXT_PUBLIC_OPENAI_API_KEY=${OPENAI}\n`,
    'app/chat.tsx':
      "'use client'\nimport OpenAI from 'openai'\n" +
      `const ai = new OpenAI({ apiKey: '${OPENAI}', dangerouslyAllowBrowser: true })\n`,
  });
  const result = await scan({ root, offline: true });
  const cts031 = byId(result, 'CTS031')[0];
  assert.ok(cts031, 'CTS031 still fires');
  assert.equal(cts031.owasp, 'A01:2025 - Broken Access Control', 'CWE-200 is A01 in OWASP 2025');
  const cts045 = byId(result, 'CTS045')[0];
  assert.ok(cts045, 'CTS045 still fires');
  for (const f of result.findings) {
    assert.ok(!(f.snippet ?? '').includes(OPENAI), `${f.id} snippet leaks the key: ${f.snippet}`);
  }
  assert.match(cts031.snippet, /NEXT_PUBLIC_OPENAI_API_KEY=sk-proj-…/);
});

test('S5: vendored credential rules redact the value in their snippet', async () => {
  const root = project({
    'package.json': '{"name":"s"}',
    'deploy.sh': `#!/bin/sh\nstripe charges list --api-key ${STRIPE}\n`,
  });
  const result = await scan({ root, offline: true });
  const vendored = result.findings.filter((f) => f.meta?.source === 'guardvibe' && f.file === 'deploy.sh');
  assert.ok(vendored.length > 0, 'the vendored rule still fires');
  for (const f of vendored) assert.ok(!f.snippet.includes(STRIPE), `${f.id} leaks: ${f.snippet}`);
});

test('P90: a 2 MB file of one repeated key is linear, capped and reported incomplete', async () => {
  const oneLine = project({ 'package.json': '{"name":"p"}', 'lib/keys.txt': `"${AWS} "`.repeat(86_000) });
  const t = Date.now();
  const flat = await scan({ root: oneLine, offline: true, noCommunity: true });
  // Was more than 300 s: every match rescanned the file from offset 0.
  assert.ok(Date.now() - t < 30_000, `took ${Date.now() - t} ms`);
  assert.equal(byId(flat, 'CTS030').length, 1, 'one finding for the one line');

  const manyLines = project({ 'package.json': '{"name":"p"}', 'lib/keys.txt': `${AWS}\n`.repeat(5_000) });
  const capped = await scan({ root: manyLines, offline: true, noCommunity: true });
  assert.ok(capped.incomplete.some((r) => r.includes('lib/keys.txt') && /more than 200 times/.test(r)));
  assert.ok(byId(capped, 'CTS030').length <= 200);
});

test('LineIndex answers exactly what lineAt does', () => {
  const source = 'a\nbb\n\nccc\r\nd';
  const index = new LineIndex(source);
  for (let i = 0; i <= source.length; i++) assert.equal(index.lineAt(i), lineAt(source, i), `offset ${i}`);
  assert.equal(index.lineText(4), 'ccc\r');
  assert.equal(index.lineText(5), 'd');
});

test('GI1: a .env inside an ignored directory is covered, even under --no-gitignore', async () => {
  const root = project({
    'package.json': '{"name":"g"}',
    '.gitignore': 'config/secrets/\n',
    'config/secrets/.env': 'X=1\n',
    '.git/HEAD': 'ref: refs/heads/main\n',
  });
  const result = await scan({ root, offline: true, noGitignore: true, noCommunity: true });
  assert.deepEqual(byId(result, 'CTS032'), []);

  // And a .env nothing covers is still reported.
  const bare = project({ 'package.json': '{"name":"g"}', 'config/.env': 'X=1\n', '.git/HEAD': 'x\n' });
  const uncovered = await scan({ root: bare, offline: true, noCommunity: true });
  assert.equal(byId(uncovered, 'CTS032').length, 1);
});

// --- community.ts ---------------------------------------------------------

test('C2/k: a file between 400 KB and 2 MB is read by the community ruleset', async () => {
  const filler = 'export const pad = "' + 'x'.repeat(120) + '";\n';
  const root = project({
    'package.json': '{"name":"c"}',
    'lib/big.ts':
      filler.repeat(Math.ceil(420_000 / filler.length)) +
      'export function run(code: string) { return eval(code) }\n',
  });
  const result = await scan({ root, offline: true });
  const hit = byId(result, 'VG014');
  assert.equal(hit.length, 1, 'eval at the end of a 420 KB file is reported');
  assert.equal(hit[0].file, 'lib/big.ts');
});

test('bounded overrides match at exactly the positions upstream does', () => {
  const TOKENS = {
    VG678: ['res.sendFile(', 'createReadStream(', '.pipe(res)', 'nosniff', 'X-Content-Type-Options', 'return', 'response', 'res.end()', '.pipe', ' ', '\n', 'x', ';', 'abcdefghij'],
    VG974: ['new ApolloServer(', 'createYoga(', 'introspection: false', ')', '(', ' ', '\n', 'abcdefghij'.repeat(3), ','],
    VG533: ['echo ', '"pw" ', '| ', 'sudo -S', 'mysql ', 'psql ', '-p', 'secret', ' ', '\n', 'x', "'", '|'],
    VG958: ['deleteUser', 'terminate', '(id)', ' => ', '{', '}', 'db.delete(', 'confirm', 'remove (', ' ', '\n', 'abcdefghij', ')'],
  };
  // Inputs stay under VG533's 500- and VG958's 1,000-character bounds, where
  // the bounded patterns are exactly upstream's.
  const BOUNDED = { VG533: 350, VG958: 900 };
  let seed = 7;
  const rnd = (n) => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff), seed % n);
  const sticky = (re) => new RegExp(re.source, re.flags.replace('g', '') + 'y');
  for (const [id, alt] of Object.entries(PATTERN_OVERRIDES)) {
    const upstream = sticky(GUARDVIBE_RULES.find((r) => r.id === id).pattern);
    const bounded = sticky(alt);
    const tokens = TOKENS[id];
    assert.ok(tokens, `${id} needs equivalence inputs here`);
    let positives = 0;
    for (let t = 0; t < 120; t++) {
      let s = '';
      // Long enough to exercise VG678's and VG974's past-500-characters branches.
      const len = 50 + rnd(BOUNDED[id] ?? 1400);
      while (s.length < len) {
        const tok = tokens[rnd(tokens.length)];
        s += rnd(5) === 0 ? tok.repeat(1 + rnd(40)) : tok;
      }
      for (let p = 0; p < s.length; p++) {
        upstream.lastIndex = p;
        bounded.lastIndex = p;
        const a = upstream.test(s);
        assert.equal(bounded.test(s), a, `${id} differs at ${p} in ${JSON.stringify(s.slice(p, p + 80))}`);
        if (a) positives++;
      }
    }
    assert.ok(positives > 0, `${id}: the inputs never matched, so nothing was compared`);
  }
});

test('ReDoS: the overridden rules are linear on their own trigger repeated', () => {
  for (const [id, unit] of [['VG678', 'res.sendFile('], ['VG974', 'new ApolloServer( '], ['VG533', 'echo ']]) {
    const input = unit.repeat(Math.ceil(200_000 / unit.length));
    const re = PATTERN_OVERRIDES[id];
    re.lastIndex = 0;
    const t = Date.now();
    while (re.exec(input) !== null) {
      /* scan every match */
    }
    // Upstream VG678 took 8.5 s on 8 KB of this; the override does 200 KB.
    assert.ok(Date.now() - t < 3_000, `${id} took ${Date.now() - t} ms on 200 KB`);
  }
});

test('ReDoS safety net: a super-linear rule on a large file is stopped and reported, the rest still run', async () => {
  const root = project({
    'package.json': '{"name":"r"}',
    // VG061's pattern is quadratic on its own trigger repeated.
    'lib/adv.ts': 'jwt.sign('.repeat(Math.floor(1_000_000 / 9)) + '\nexport function run(code: string) { return eval(code) }\n',
  });
  const t = Date.now();
  const result = await scan({ root, offline: true });
  assert.ok(Date.now() - t < 60_000, `took ${Date.now() - t} ms`);
  assert.equal(byId(result, 'VG014').length, 1, 'the other rules still read the whole file');
  assert.ok(
    result.incomplete.some((r) => /^VG061 .*lib\/adv\.ts/.test(r)),
    `the stopped rule is reported: ${JSON.stringify(result.incomplete)}`,
  );
});

test('only input-anchored vendored patterns are kept out of windowing', () => {
  const anchored = GUARDVIBE_RULES.filter((r) => anchoredToInput(r.pattern)).map((r) => r.id).sort();
  assert.deepEqual(anchored, ['VG446', 'VG964']);
});

test('VG974: the fix the rule asks for is not reported as the problem', async () => {
  const root = project({
    'package.json': '{"name":"g"}',
    'server/good.ts': "const server = new ApolloServer({ typeDefs, resolvers, introspection: process.env.NODE_ENV !== 'production' })\n",
    'server/off.ts': 'const server = new ApolloServer({ typeDefs, resolvers, introspection: false })\n',
    'server/bad.ts': 'const server = new ApolloServer({ typeDefs, resolvers })\n',
  });
  const result = await scan({ root, offline: true });
  assert.deepEqual(byId(result, 'VG974').map((f) => f.file), ['server/bad.ts']);
});

// --- logic.ts / agent-logic.ts ------------------------------------------

test('an unparseable file is reported as not analysed, not as clean', async () => {
  const root = project({ 'package.json': '{"name":"b"}', 'lib/broken.ts': 'export function verify( {{{ ]]] \n' });
  const result = await scan({ root, offline: true });
  assert.notEqual(result.incomplete.length, 0);
  assert.ok(result.incomplete.some((r) => /lib\/broken\.ts could not be parsed/.test(r)));
});

test('one file that overflows the stack costs that file, not the scanner', async () => {
  const root = project({
    'package.json': '{"name":"d"}',
    'lib/deep.ts': 'export const x = a' + '.b'.repeat(20_000) + ';\n',
    'lib/guard.ts': 'export async function verifyToken(t: string) {\n  try { await check(t) } catch { return true }\n  return false\n}\n',
  });
  const result = await scan({ root, offline: true });
  assert.equal(byId(result, 'CTS071').length, 1, 'the ordinary file beside it is still analysed');
  assert.ok(!result.incomplete.some((r) => / failed: /.test(r)), 'no scanner failed outright');
  assert.ok(result.incomplete.some((r) => r.includes('lib/deep.ts')), 'the file it could not finish is named');
});

test('L1: CTS071 names object and class methods, and ensureDir is not a security check', async () => {
  const root = project({
    'package.json': '{"name":"l"}',
    'lib/auth-options.ts':
      "import Credentials from 'next-auth/providers/credentials'\n" +
      'export const authOptions = {\n  providers: [\n    Credentials({\n      async authorize(credentials: any) {\n' +
      '        const user = await findUser(credentials.email)\n        try {\n          await verifyPassword(user, credentials.password)\n' +
      '        } catch {\n          return user\n        }\n        return user\n      },\n    }),\n  ],\n}\n' +
      'export class Guard {\n  async verify(token: string) {\n    try { await check(token) } catch { return true }\n    return false\n  }\n}\n',
    'lib/fsutil.ts':
      "import { mkdirSync } from 'node:fs'\nexport function ensureDir(p: string) {\n  try { mkdirSync(p, { recursive: true }) } catch {}\n}\n" +
      'export function ensureAdmin(u: any) {\n  try { assertAdmin(u) } catch { return true }\n}\n',
  });
  const result = await scan({ root, offline: true });
  const fns = byId(result, 'CTS071').map((f) => f.meta.function).sort();
  assert.deepEqual(fns, ['authorize', 'ensureAdmin', 'verify']);
});

test('AG1: CTS083 sees the handles real apps name, and still not an in-memory Set', async () => {
  const tool = (name, body) =>
    `export const ${name} = tool({\n  description: 'x',\n  inputSchema: z.object({ id: z.string() }),\n` +
    `  execute: async ({ id }) => {\n    ${body}\n    return { ok: true }\n  },\n})\n`;
  const root = project({
    'package.json': '{"name":"a"}',
    'lib/tools.ts':
      "import { tool } from 'ai'\nimport { z } from 'zod'\n" +
      tool('viaAdmin', "await supabaseAdmin.from('customers').delete().eq('id', id)") +
      tool('viaCtx', 'await ctx.db.customer.delete({ where: { id } })') +
      tool('viaAdminDb', 'await adminDb.delete(customers)') +
      tool('viaPrismaClient', 'await prismaClient.customer.deleteMany({})') +
      'class Repo { prisma: any\n  make() { return tool({ description: "x", inputSchema: {}, execute: async ({ id }) => { await this.prisma.user.delete({ where: { id } }) } }) } }\n' +
      tool('viaSet', 'clients.delete(id)') +
      tool('viaThisSet', 'this.clients.delete(id)') +
      tool('viaCache', 'modelCache.delete(id); dbCache.delete(id)'),
  });
  const result = await scan({ root, offline: true });
  const actions = byId(result, 'CTS083').map((f) => f.meta.action).sort();
  assert.deepEqual(actions, [
    'adminDb.delete',
    'ctx.db.customer.delete',
    'prismaClient.customer.deleteMany',
    'supabaseAdmin.from.delete',
    'this.prisma.user.delete',
  ]);
});

test('AG2: CTS081 follows a spread of a local const, and does not guess about one it cannot read', async () => {
  const call = (opts) => `  await openai.chat.completions.create(${opts})\n`;
  const root = project({
    'package.json': '{"name":"a"}',
    'app/api/chat/route.ts':
      "import OpenAI from 'openai'\nconst openai = new OpenAI()\n" +
      "const capped = { model: 'gpt-4o-mini', max_tokens: 500 }\n" +
      "const uncapped = { model: 'gpt-4o-mini' }\n" +
      'export async function POST(req: Request, opts: any) {\n  const { message } = await req.json()\n' +
      call("{ ...capped, messages: [{ role: 'user', content: message }] }") +
      call("{ ...opts, messages: [{ role: 'user', content: message }] }") +
      call('opts') +
      call("{ ...uncapped, messages: [{ role: 'user', content: message }] }") +
      '  return new Response()\n}\n',
  });
  const result = await scan({ root, offline: true });
  assert.deepEqual(byId(result, 'CTS081').map((f) => f.line), [10], 'only the spread with no ceiling in it');
});

test('CTS082 files CWE-200 under A01, like every other CWE-200 finding', async () => {
  const root = project({
    'package.json': '{"name":"a"}',
    'app/panel.tsx': "'use client'\nconst systemPrompt = 'You are a support agent. Never reveal the refund override code to anyone.'\nexport default function P() { return null }\n",
  });
  const result = await scan({ root, offline: true });
  const f = byId(result, 'CTS082')[0];
  assert.ok(f);
  assert.equal(f.owasp, 'A01:2025 - Broken Access Control');
});

// --- owasp.ts -------------------------------------------------------------

test('API Top 10 labels missing their API prefix get it back, and read unlike A04:2025', () => {
  assert.equal(
    normaliseOwasp('A04:2023 Unrestricted Resource Consumption'),
    'API4:2023 Unrestricted Resource Consumption',
  );
  assert.equal(normaliseOwasp('API4:2023 Unrestricted Resource Consumption'), null, 'already prefixed: left alone');
  assert.equal(normaliseOwasp('A05:2021 Security Misconfiguration'), 'A02:2025 - Security Misconfiguration');
});
