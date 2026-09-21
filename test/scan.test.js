import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { buildFixtures } from './fixture-setup.js';
import { scan } from '../dist/index.js';
import { splitStatements, normaliseTable, isAlwaysTrue, clauseAfter } from '../dist/utils/sql.js';
import { editDistance, nearestPopular, POPULAR_NPM } from '../dist/data/popular.js';
import { Suppressions } from '../dist/utils/suppress.js';
import { Gitignore } from '../dist/utils/gitignore.js';
import { pathClass } from '../dist/utils/paths.js';

const here = dirname(fileURLToPath(import.meta.url));
const VULNERABLE = join(here, 'fixtures', 'vulnerable-app');
const CLEAN = join(here, 'fixtures', 'clean-app');
const INDIRECT = join(here, 'fixtures', 'indirect-auth-app');
const CLI = join(here, '..', 'dist', 'cli.js');

// Credential-shaped fixture state is generated, never committed.
buildFixtures();

const ids = (result) => new Set(result.findings.map((f) => f.id));

test('vulnerable fixture: reports every free-tier rule it is built to trigger', async () => {
  // The Server Actions, RLS and LLM/agent suites (CTS001-004, 010-019, 041-046,
  // 050-052, 080-085) are asserted in rls.test.js, server-actions.test.js and
  // agent-logic.test.js. This list is the dependency and secrets surface. CTS040
  // and CTS045 belong here despite the numbering: they are implemented in the
  // secrets scanner, not the Server Actions scanner.
  const result = await scan({ root: VULNERABLE, offline: true });
  const found = ids(result);
  for (const expected of [
    'CTS028', // install hook runs network/shell code
    'CTS030', // hardcoded secret
    'CTS031', // secret behind NEXT_PUBLIC_
    'CTS032', // .env not gitignored
    'CTS033', // client component reads a server secret
    'CTS040', // client component reads a server env var
    'CTS045', // AI client allowed to run in the browser
  ]) {
    assert.ok(found.has(expected), `expected ${expected} to be reported`);
  }
});

test('vulnerable fixture: secrets are redacted in the reported snippet', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  for (const f of result.findings.filter((f) => f.id === 'CTS030')) {
    assert.ok(f.snippet.includes('…'), `snippet should be redacted: ${f.snippet}`);
    assert.ok(f.snippet.length <= 160);
  }
});

test('clean fixture: no findings at all', async () => {
  const result = await scan({ root: CLEAN, offline: true });
  assert.deepEqual(
    result.findings.map((f) => `${f.id} ${f.file}:${f.line}`),
    [],
  );
  assert.ok(result.checks.every((c) => c.passed));
});

test('lockfile entries are judged as lockfile entries', async () => {
  const result = await scan({ root: INDIRECT, offline: true });
  const lock = result.findings.filter((f) => f.file === 'package-lock.json');

  // A workspace link resolves to a directory, so it has no integrity hash by
  // design; a tarball entry without one is the real finding.
  const integrity = lock.filter((f) => f.id === 'VG870');
  assert.equal(integrity.length, 1, 'only the tampered tarball entry should fire');
  assert.equal(integrity[0].snippet.includes('tampered-pkg'), true);

  // Name heuristics belong to a hand-written manifest: every one of these
  // matched a transitive dependency nobody in the project chose.
  for (const id of ['VG872', 'VG873', 'VG020']) {
    assert.equal(lock.some((f) => f.id === id), false, `${id} should not run over a lockfile`);
  }
});

test('where a file lives changes what a finding in it costs', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });

  // Build tooling: real finding, one step down, and the report says why.
  const seed = result.findings.filter((f) => f.file === 'scripts/seed.mjs');
  assert.ok(seed.length > 0, 'an interpolated query in a script is still reported');
  for (const f of seed) {
    assert.equal(f.severity, 'high', `${f.id} should be demoted from critical, not dropped`);
    assert.match(f.detail, /build or maintenance tooling/);
  }

  // The same shape in the app itself keeps its full severity.
  const app = result.findings.filter(
    (f) => f.id === 'VG010' && !f.file.startsWith('scripts/'),
  );
  assert.ok(
    app.every((f) => !/build or maintenance tooling/.test(f.detail)),
    'application code is not demoted',
  );
});

test('raw-SQL helpers are judged on whether the values are bound', async () => {
  const bad = await scan({ root: VULNERABLE, offline: true });
  assert.ok(
    bad.findings.some((f) => f.file === 'app/actions/raw-sql.ts' && f.id === 'VG433'),
    "`$executeRawUnsafe` with the caller's value inside the SQL text is reported",
  );

  // The same call, with the placeholder skeleton built in code and every value
  // passed after the query, is the documented safe form.
  const clean = await scan({ root: CLEAN, offline: true });
  assert.deepEqual(clean.findings.map((f) => `${f.id} ${f.file}`), []);
});

test('a CVE in a build-time dependency is not a shipping vulnerability', async () => {
  const result = await scan({ root: INDIRECT, offline: true });
  const cve = result.findings.filter((f) => f.id === 'VG903');
  assert.equal(cve.length, 2, 'the same rule matches both declarations');

  const shipped = cve.find((f) => f.snippet.includes('17.0.2'));
  const build = cve.find((f) => f.snippet.includes('16.14.0'));
  assert.equal(shipped.severity, 'high', 'a dependency your users run keeps its severity');
  assert.equal(build.severity, 'low', 'one under devDependencies does not');
  assert.match(build.detail, /devDependencies/);
});

test('a bound parameter is not an injection; a raw interpolation still is', async () => {
  const clean = await scan({ root: CLEAN, offline: true });
  assert.deepEqual(
    clean.findings.map((f) => `${f.id} ${f.file}:${f.line}`),
    [],
    'binding the values and interpolating only the table name is the correct pattern',
  );

  // The same rule still fires where nothing is bound at all.
  const bad = await scan({ root: VULNERABLE, offline: true });
  assert.ok(
    bad.findings.some((f) => f.file === 'scripts/seed.mjs' && f.id === 'VG010'),
    'an interpolated query with no binds is still reported',
  );
});

test('path classification reads directories, not filenames', () => {
  assert.equal(pathClass('transfer-tests/errormonitor-tests.mjs'), 'non-production');
  assert.equal(pathClass('app/e2e-tests/login.ts'), 'non-production');
  assert.equal(pathClass('scripts/seed.mjs'), 'dev-tooling');
  assert.equal(pathClass('next.config.ts'), 'dev-tooling');
  // A file that merely contains one of the words is production code.
  assert.equal(pathClass('src/lib/spec-parser.ts'), 'production');
  assert.equal(pathClass('src/app/api/document-samples/route.ts'), 'production');
  assert.equal(pathClass('src/features/demo-billing/index.ts'), 'production');
  assert.equal(pathClass('src/app/page.tsx'), 'production');
  // bin/ is a published CLI's entry point; migrations are production schema.
  assert.equal(pathClass('bin/cli.js'), 'production');
  assert.equal(pathClass('migrations/001_init.sql'), 'production');
});

test('rules naming a platform the project does not use are not run', async () => {
  // The fixture has no Supabase or Firebase dependency. "Supabase Auth Missing
  // Middleware" was being reported against a real app with neither.
  const result = await scan({ root: INDIRECT, offline: true });
  const note = result.checks.find((c) => c.label.startsWith('Community ruleset'))?.note ?? '';
  assert.match(note, /Supabase rules \(no Supabase dependency\)/);
  assert.match(note, /Firebase rules \(no Firebase dependency\)/);
  assert.equal(
    result.findings.some((f) => /supabase|firebase/i.test(f.title)),
    false,
  );

  // The clean fixture does depend on Supabase, so those rules stay switched on.
  const withSupabase = await scan({ root: CLEAN, offline: true });
  const cleanNote =
    withSupabase.checks.find((c) => c.label.startsWith('Community ruleset'))?.note ?? '';
  assert.equal(/Supabase rules/.test(cleanNote), false, 'not skipped where it applies');
});

test('scanning a repo by absolute path reports paths relative to that repo', () => {
  // Found by scanning somebody else's repository rather than my own: `root` was
  // always the shell's cwd, so `cleartoship /path/to/their/repo` reported every
  // finding as `../../../private/tmp/.../app/page.tsx`. Accurate, unreadable,
  // and impossible to match against a file in an editor.
  const out = execFileSync(process.execPath, [CLI, VULNERABLE, '--offline', '--json', '--no-community', '--fail-on=none'], {
    cwd: join(here, '..', 'src'),   // deliberately not inside the scanned tree
    encoding: 'utf8',
  });
  const files = JSON.parse(out).findings.map((f) => f.file).filter(Boolean);
  assert.ok(files.length > 0, 'the fixture should still produce findings');
  const escaping = files.filter((f) => f.startsWith('..'));
  assert.deepEqual(escaping, [], 'no finding may be reported with a path that climbs out of the repo');
  assert.ok(
    // logging.ts's CTS070 is a reliable proxy for "was this directory read".
    files.some((f) => f === 'app/actions/logging.ts'),
    `expected a repo-relative path, got ${files.slice(0, 3).join(', ')}`,
  );
});

test('a subdirectory argument still scans as part of the surrounding project', () => {
  // The other half of the same decision: `cleartoship app` must NOT re-root at
  // app/, because framework detection and .gitignore hang off the project's own
  // package.json one level up.
  const out = execFileSync(process.execPath, [CLI, 'app', '--offline', '--json', '--no-community', '--fail-on=none'], {
    cwd: VULNERABLE,
    encoding: 'utf8',
  });
  const files = JSON.parse(out).findings.map((f) => f.file).filter(Boolean);
  assert.ok(
    files.every((f) => f.startsWith('app/')),
    'paths stay relative to the project root, not the subdirectory',
  );
});

test('findings carry one OWASP taxonomy, plus an LLM category where it applies', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });

  // The vendored ruleset labels Injection as both A02:2025 and A03:2025, and
  // Security Misconfiguration as A05:2025 and A05:2021. Whatever went in, one
  // spelling comes out.
  const categories = new Set(result.findings.map((f) => f.owasp).filter(Boolean));
  for (const c of categories) {
    assert.match(
      c,
      /^(A\d{2}:2025 - |API\d:2023)/,
      `${c} is neither the 2025 web list nor an API Top 10 label`,
    );
  }
  assert.equal([...categories].filter((c) => /Injection/.test(c)).length, 1, 'one Injection');

  // A hardcoded provider key is an LLM finding as well as a web one; an npm
  // install hook that shells out is not, however much it looks like a "hook".
  const key = result.findings.find((f) => f.id === 'CTS030' && /OpenAI/.test(f.title));
  assert.equal(key.meta.llm, 'LLM02:2026 - Sensitive Information Disclosure');
  const hook = result.findings.find((f) => f.id === 'CTS028');
  assert.equal(hook.meta?.llm, undefined, 'a postinstall hook is supply chain, not excessive agency');
});

test('the scan stays inside the directory it was given', async () => {
  const result = await scan({ root: INDIRECT, offline: true });

  // `escape` points at the vulnerable fixture, which is full of findings.
  assert.equal(
    result.findings.some((f) => f.file?.startsWith('escape/')),
    false,
    'a symlink out of the tree is not followed — its contents are not this project',
  );
  // `self` points at the fixture root: walking it again would report every
  // file twice, at two different paths.
  assert.equal(
    result.findings.some((f) => f.file?.startsWith('self/')),
    false,
    'and a symlink loop is walked once',
  );
  assert.ok(result.escapingSymlinkCount >= 1, 'the report says how many were refused');
});

test('what git ignores is not part of the project', async () => {
  const result = await scan({ root: INDIRECT, offline: true });
  const files = result.findings.map((f) => f.file);

  assert.equal(
    files.some((f) => f.startsWith('vendored/')),
    false,
    'vendored/ is gitignored, so its hardcoded key and eval() are somebody else\'s problem',
  );
  assert.equal(
    files.includes('settings.local.json'),
    false,
    '*.local.json is gitignored too',
  );
  assert.ok(result.gitIgnoredCount >= 2, 'and the report says how many paths were skipped');

  // An ignored `.env` is the exception: the secret is on disk either way, and
  // CTS032 exists precisely to reason about whether the file is ignored.
  const env = result.findings.filter((f) => f.file === '.env');
  assert.equal(env.length, 1, `expected the .env secret, got ${env.map((f) => f.id).join(', ')}`);
  assert.equal(env[0].id, 'CTS030');
  assert.equal(
    result.findings.some((f) => f.id === 'CTS032'),
    false,
    '.env IS covered by .gitignore here, so CTS032 must stay quiet',
  );
});

test('--no-gitignore scans them anyway', async () => {
  const result = await scan({ root: INDIRECT, offline: true, noGitignore: true });
  const vendored = result.findings.filter((f) => f.file?.startsWith('vendored/'));
  assert.ok(vendored.length > 0, 'the opt-out has to actually opt out');
  assert.equal(result.gitIgnoredCount, 0);
});

test('gitignore patterns follow git, not glob intuition', () => {
  const rules = Gitignore.empty().extend('/repo', [
    'logs',            // bare name, any depth, file or directory
    '/build',          // anchored to the root only
    '*.log',           // suffix, any depth
    'tmp/',            // directories only
    'docs/**/draft',   // ** spans directories
    'keep/*.txt',      // anchored by the embedded slash
    '!keep/README.txt',// re-included
  ].join('\n'));

  assert.equal(rules.ignores('/repo/logs', true), true);
  assert.equal(rules.ignores('/repo/src/logs', true), true, 'a bare name matches at any depth');
  assert.equal(rules.ignores('/repo/build', true), true);
  assert.equal(rules.ignores('/repo/src/build', true), false, 'a leading slash anchors');
  assert.equal(rules.ignores('/repo/a/b/c.log', false), true);
  assert.equal(rules.ignores('/repo/tmp', false), false, 'trailing slash means directories only');
  assert.equal(rules.ignores('/repo/tmp', true), true);
  assert.equal(rules.ignores('/repo/docs/a/b/draft', true), true);
  assert.equal(rules.ignores('/repo/keep/notes.txt', false), true);
  assert.equal(rules.ignores('/repo/keep/README.txt', false), false, 'a later ! re-includes');
  assert.equal(rules.ignores('/elsewhere/logs', true), false, 'rules stop at their own tree');
});

test('an ignored directory can have a re-included subdirectory', () => {
  // The shape that exposed the bug, from a real repository: everything under
  // logos/ is ignored except one subdirectory, whose files are tracked.
  const rules = Gitignore.empty().extend('/repo', ['logos/*', '!logos/logos-in-app/'].join('\n'));

  assert.equal(rules.ignores('/repo/logos/scratch.svg', false), true);
  assert.equal(rules.ignores('/repo/logos/logos-in-app', true), false, 're-included');
  assert.equal(
    rules.ignores('/repo/logos/logos-in-app/anim-pulse-24.svg', false),
    false,
    'a pattern matches a path, not everything beneath it — the walk prunes directories instead',
  );
});

test('a pattern that will not compile does not end the scan', () => {
  // `[z-a]` is a reversed range. This used to throw out of walk(), before any
  // scanner error handling, and kill the run on one line of somebody's file.
  const rules = Gitignore.empty().extend(
    '/repo',
    ['**/[z-a]/**', '[unclosed', 'node_modules', 'x'.repeat(900)].join('\n'),
  );
  assert.equal(rules.ignores('/repo/node_modules', true), true, 'the valid rules still apply');
  assert.equal(rules.ignores('/repo/src/index.ts', false), false);
});

test('a nested .gitignore overrides the one above it', () => {
  const rules = Gitignore.empty()
    .extend('/repo', '*.json')
    .extend('/repo/config', '!*.json');
  assert.equal(rules.ignores('/repo/a.json', false), true);
  assert.equal(rules.ignores('/repo/config/a.json', false), false);
});

test('scan honours --ignore, --only and --min-severity equivalents', async () => {
  const all = await scan({ root: VULNERABLE, offline: true });
  const ignored = await scan({ root: VULNERABLE, offline: true, ignore: ['CTS030'] });
  assert.ok(all.findings.length > ignored.findings.length);
  assert.ok(!ids(ignored).has('CTS030'));

  const only = await scan({ root: VULNERABLE, offline: true, only: ['CTS030'] });
  assert.ok([...ids(only)].every((id) => id === 'CTS030'));
  assert.ok(ids(only).has('CTS030'));

  const criticals = await scan({ root: VULNERABLE, offline: true, minSeverity: 'critical' });
  assert.ok(criticals.findings.every((f) => f.severity === 'critical'));
});

test('inline suppression comments silence a rule', () => {
  const sup = new Suppressions(
    ['const a = 1', '// cleartoship-ignore CTS001', 'const b = 2', 'const c = 3 // cts-ignore'].join('\n'),
  );
  assert.equal(sup.suppressed(3, 'CTS001'), true);
  assert.equal(sup.suppressed(3, 'CTS002'), false);
  assert.equal(sup.suppressed(4, 'CTS999'), true, 'bare cts-ignore suppresses everything on the line');
});

test('SQL splitter records the first token line, not trailing whitespace', () => {
  const sql = ['-- a comment', '', 'create table a (id int);', '', '', 'create table b (id int);'].join('\n');
  const statements = splitStatements(sql);
  assert.equal(statements.length, 2);
  assert.equal(statements[0].line, 3);
  assert.equal(statements[1].line, 6);
});

test('SQL splitter does not break inside dollar-quoted bodies', () => {
  const sql = "create function f() returns void as $$ begin raise notice 'a; b'; end; $$ language plpgsql;\nselect 1;";
  const statements = splitStatements(sql);
  assert.equal(statements.length, 2);
  assert.ok(statements[0].text.includes('raise notice'));
});

test('SQL helpers normalise names and detect permissive predicates', () => {
  assert.equal(normaliseTable('"public"."posts"'), 'public.posts');
  assert.equal(normaliseTable('posts'), 'public.posts');
  assert.equal(isAlwaysTrue('true'), true);
  assert.equal(isAlwaysTrue('(true)'), true);
  assert.equal(isAlwaysTrue('user_id = auth.uid()'), false);
  assert.equal(clauseAfter('using (a = (b))', /\busing\s*(?=\()/i), 'a = (b)');
});

test('edit distance handles transposition and caps out', () => {
  assert.equal(editDistance('express', 'express'), 0);
  assert.equal(editDistance('expres', 'express'), 1);
  assert.equal(editDistance('exprses', 'express'), 1, 'transposition costs one');
  assert.equal(editDistance('completely', 'different', 2), 3);
});

test('typosquat matching skips exact names and very short names', () => {
  assert.equal(nearestPopular('express', POPULAR_NPM), null, 'a popular package is not its own squat');
  assert.equal(nearestPopular('next', POPULAR_NPM), null, 'next must not match nest');
  assert.equal(nearestPopular('ms', POPULAR_NPM), null, 'short names produce noise, not signal');
  assert.equal(nearestPopular('expres', POPULAR_NPM), 'express');
  assert.equal(nearestPopular('@types/react', POPULAR_NPM), null);
});

const runCli = (args) => {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return { code: 0, stdout };
  } catch (err) {
    return { code: err.status, stdout: err.stdout ?? '' };
  }
};

test('CLI exits 1 on the vulnerable fixture and 0 on the clean one', () => {
  assert.equal(runCli(['-C', VULNERABLE, '--offline', '--no-banner']).code, 1);
  assert.equal(runCli(['-C', CLEAN, '--offline', '--no-banner']).code, 0);
});

test('CLI --fail-on=none never fails the build', () => {
  assert.equal(runCli(['-C', VULNERABLE, '--offline', '--no-banner', '--fail-on', 'none']).code, 0);
});

test('CLI emits valid JSON, SARIF, a fix prompt and a badge', () => {
  const json = JSON.parse(runCli(['-C', VULNERABLE, '--offline', '--json']).stdout);
  assert.equal(json.tool, 'cleartoship');
  assert.equal(json.verdict, 'hold');
  assert.ok(json.findings.length > 10);

  const sarif = JSON.parse(runCli(['-C', VULNERABLE, '--offline', '--sarif']).stdout);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].tool.driver.name, 'ClearToShip');
  assert.equal(sarif.runs[0].results.length, json.findings.length);
  for (const r of sarif.runs[0].results) {
    assert.ok(r.locations[0].physicalLocation.region.startLine >= 1);
  }

  const prompt = runCli(['-C', VULNERABLE, '--offline', '--fix-prompt']).stdout;
  assert.match(prompt, /# ClearToShip — security fixes to apply/);
  assert.match(prompt, /CTS030/);

  const badge = runCli(['-C', CLEAN, '--offline', '--badge']).stdout;
  assert.match(badge, /img\.shields\.io.*10b981/);
});

test('hardcoded keys are not swallowed by placeholder heuristics', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const lines = result.findings.filter((f) => f.id === 'CTS030' && f.file === '.env').map((f) => f.line);
  // service-role JWT, Stripe live key, OpenAI key — one finding each.
  assert.deepEqual(lines.sort((a, b) => a - b), [2, 3, 4]);
});

test('install commands in prose are resolved like manifest dependencies', async () => {
  const { collectProseForTest } = await import('../dist/scanners/dependencies.js');
  const found = collectProseForTest(
    [
      '```bash',
      'npm install next react',
      'npm i -D typescript',
      'npx create-vibe-dashboard --template saas',
      'npm install ./local-package',
      'pip install supabase-py-async',
      '```',
    ].join('\n'),
    'AGENTS.md',
  ).map((d) => `${d.ecosystem}:${d.name}`);

  assert.ok(found.includes('npm:next'));
  assert.ok(found.includes('npm:create-vibe-dashboard'));
  assert.ok(found.includes('pypi:supabase-py-async'));
  assert.ok(!found.some((n) => n.includes('local-package')), 'local paths are not packages');
  assert.ok(!found.some((n) => n.includes('-D')), 'flags are not packages');
});

test('quoted or commented mentions of a risky flag are not findings', async () => {
  const result = await scan({ root: CLEAN, offline: true });
  assert.ok(!result.findings.some((f) => f.id === 'CTS045'));
});

// Registry-dependent rules can only be exercised with network access, so this
// test skips itself rather than turning a flaky connection into a red build.
const online = await fetch('https://registry.npmjs.org/zod', {
  headers: { accept: 'application/vnd.npm.install-v1+json' },
  signal: AbortSignal.timeout(5000),
}).then((r) => r.ok, () => false);

test('registry rules resolve hallucinated and lookalike packages', { skip: !online && 'offline' }, async () => {
  const result = await scan({ root: VULNERABLE });
  const found = ids(result);
  assert.ok(found.has('CTS020'), 'non-existent packages must be reported');
  assert.ok(found.has('CTS023'), 'expres must be matched against express');

  const hallucinated = result.findings
    .filter((f) => f.id === 'CTS020')
    .map((f) => f.meta.package);
  assert.ok(hallucinated.includes('tailwind-modal-components'));
  assert.ok(hallucinated.includes('create-vibe-dashboard'), 'names in AGENTS.md count too');

  // Real packages must never be reported as missing.
  assert.ok(!hallucinated.includes('next') && !hallucinated.includes('react'));
});

test('--no-community leaves only ClearToShip rules', async () => {
  const withCommunity = await scan({ root: VULNERABLE, offline: true });
  const withoutCommunity = await scan({ root: VULNERABLE, offline: true, noCommunity: true });

  assert.ok(withCommunity.findings.some((f) => f.id.startsWith('VG')));
  assert.ok(!withoutCommunity.findings.some((f) => f.id.startsWith('VG')));
  assert.ok(withCommunity.findings.length > withoutCommunity.findings.length);
});

test('vendored rules add coverage without duplicating our own', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const community = result.findings.filter((f) => f.id.startsWith('VG'));
  assert.ok(community.length > 0, 'the community ruleset should contribute findings');

  // Every vendored finding must carry its attribution.
  for (const f of community) {
    assert.equal(f.meta.source, 'guardvibe');
    assert.match(f.meta.attribution, /Apache-2\.0/);
  }

  // A superseded rule must never appear beside the rule that replaced it —
  // including VG401/VG402/VG427/VG952/VG1007, superseded by the Server Actions
  // suite. Standing these vendored ids back up as fallback coverage reported
  // VG1010 as "critical" on clean-app's deliberately-safe updateProfile action
  // (see community.ts's SUPERSEDED doc comment) — the first-party result is the
  // precise one.
  const ids = new Set(community.map((f) => f.id));
  for (const superseded of ['VG400', 'VG401', 'VG402', 'VG427', 'VG952', 'VG1007']) {
    assert.ok(!ids.has(superseded), `${superseded} is superseded and must not fire`);
  }
});

test('a NEXT_PUBLIC_ variable named for an AI provider is reported as that provider\'s key', async () => {
  // Same finding, named for what it is: an OpenAI key in the bundle is a spendable
  // credential, not just "a secret". A variable with no provider in its name keeps
  // the generic wording, so the specific title is never guessed.
  const { mkdtempSync, mkdirSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'cts-pub-'));
  mkdirSync(join(dir, 'app'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 't', version: '1.0.0', dependencies: { next: '15.5.24', react: '19.0.0' } }),
  );
  writeFileSync(join(dir, '.gitignore'), '.env*\n');
  writeFileSync(
    join(dir, '.env.local'),
    'NEXT_PUBLIC_OPENAI_API_KEY=abc123\nNEXT_PUBLIC_MAPS_SECRET_TOKEN=abc123\n',
  );
  writeFileSync(
    join(dir, 'app', 'page.tsx'),
    "'use client'\nexport default function P() {\n  return <div>{process.env.NEXT_PUBLIC_OPENAI_API_KEY}{process.env.NEXT_PUBLIC_MAPS_SECRET_TOKEN}</div>;\n}\n",
  );

  const result = await scan({ root: dir, offline: true });
  const cts031 = result.findings.filter((f) => f.id === 'CTS031');

  const ai = cts031.find((f) => f.detail.includes('NEXT_PUBLIC_OPENAI_API_KEY'));
  assert.ok(ai, 'the OpenAI-named variable should be reported');
  assert.equal(ai.title, 'OpenAI API key exposed through a NEXT_PUBLIC_ variable');
  assert.equal(ai.meta.llm, 'LLM02:2026 - Sensitive Information Disclosure');

  const generic = cts031.find((f) => f.detail.includes('NEXT_PUBLIC_MAPS_SECRET_TOKEN'));
  assert.ok(generic, 'the provider-less secret should still be reported');
  assert.equal(generic.title, 'Server secret exposed through a NEXT_PUBLIC_ variable');
});

test('a rule whose match opens with a newline is reported on its own line, not the one before', async () => {
  // VG1070 opens with `(?:^|\n)\s*`, so the match starts on the newline that
  // ends the previous line. It used to be reported one line early — here, on
  // the `echo` step rather than the `npm ci` step under it.
  const { mkdtempSync, mkdirSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'cts-line-'));
  mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
  writeFileSync(
    join(dir, '.github', 'workflows', 'ci.yml'),
    ['name: ci', 'on: push', 'jobs:', '  x:', '    runs-on: ubuntu-latest', '    steps:',
      '      - run: echo hello', '      - run: npm ci', ''].join('\n'),
  );
  const result = await scan({ root: dir, offline: true });
  const finding = result.findings.find((f) => f.id === 'VG1070');
  assert.ok(finding, 'the unhardened npm ci should be reported');
  assert.equal(finding.line, 8, 'the finding belongs on the npm ci line');
  assert.match(finding.snippet, /npm ci/);
});

test('suppression directives work from the top of a comment block', () => {
  const sup = new Suppressions(
    [
      'const a = 1',
      '// cleartoship-ignore VG010 — this is why,',
      '// and here is the second line of the reason.',
      'const b = 2',
    ].join('\n'),
  );
  assert.equal(sup.suppressed(4, 'VG010'), true, 'directive may start the comment block');
  assert.equal(sup.suppressed(4, 'VG999'), false, 'other rules are unaffected');
  assert.equal(sup.suppressed(1, 'VG010'), false, 'code above the block is unaffected');
});

test('vendored gitleaks rules cover providers the built-in patterns do not', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const gl = result.findings.filter((f) => f.id.startsWith('GL-'));
  assert.ok(gl.length > 0, 'the gitleaks ruleset should contribute findings');

  for (const f of gl) {
    assert.equal(f.meta.source, 'gitleaks');
    assert.match(f.meta.attribution, /MIT/);
    assert.ok(typeof f.meta.entropy === 'number');
    assert.ok(f.snippet.includes('…'), `snippet must be redacted: ${f.snippet}`);
  }

  const rules = new Set(gl.map((f) => f.id));
  assert.ok(rules.has('GL-npm-access-token'), 'npm token should be detected');
});

test('noisy gitleaks rules are withheld', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const ids = new Set(result.findings.map((f) => f.id));
  assert.ok(!ids.has('GL-generic-api-key'), "gitleaks' catch-all is too noisy to ship");
  assert.ok(!ids.has('GL-sourcegraph-access-token'), 'it matches any 40-char hex, i.e. every SHA');
});

test('a built-in pattern is not double-reported by a gitleaks rule', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const byLocation = new Map();
  for (const f of result.findings.filter((f) => f.id === 'CTS030' || f.id.startsWith('GL-'))) {
    const key = `${f.file}:${f.line}`;
    byLocation.set(key, (byLocation.get(key) ?? 0) + 1);
  }
  for (const [where, count] of byLocation) {
    assert.equal(count, 1, `${where} reported ${count} times by overlapping credential rules`);
  }
});

test('entropy scoring separates real keys from filler', async () => {
  const { shannonEntropy } = await import('../dist/utils/entropy.js');
  assert.ok(shannonEntropy('npm_7Kq2Xw9ZbR4tYn6Vm1Pj8Ld3Hs5Gf0Ec7Ua2') > 4);
  assert.ok(shannonEntropy('aaaaaaaaaaaaaaaaaaaaaaaa') < 1);
  assert.ok(shannonEntropy('your_api_key_here') < 4);
  assert.equal(shannonEntropy(''), 0);
});

test('lockfile-free projects still resolve a version for OSV', async () => {
  // The vulnerable fixture has no lockfile, so `next: "14.2.3"` must resolve
  // from the manifest range floor for the CVE check to run at all.
  const result = await scan({ root: VULNERABLE, offline: true });
  assert.ok(
    !result.checks.some((c) => c.label.startsWith('Known vulnerabilities')),
    'OSV must not run offline',
  );
});

test('OSV reports real advisories for a known-vulnerable version', { skip: !online && 'offline' }, async () => {
  const result = await scan({ root: VULNERABLE });
  const cves = result.findings.filter((f) => f.id === 'CTS024');
  assert.ok(cves.length > 0, 'next@14.2.3 has published advisories');

  const next = cves.find((f) => f.meta.package === 'next');
  assert.ok(next, 'the vulnerable next version should be flagged');
  assert.equal(next.meta.version, '14.2.3');
  assert.ok(next.meta.advisories.length > 1);
  assert.match(next.title, /CVE-|GHSA-/);

  // With live data available, the hand-written CVE regexes must stand down.
  const { GUARDVIBE_CVE_RULE_IDS } = await import('../dist/vendor/guardvibe/index.js');
  assert.ok(
    !result.findings.some((f) => GUARDVIBE_CVE_RULE_IDS.has(f.id)),
    'vendored CVE-version rules should defer to OSV when it answered',
  );
});

test('yarn.lock is parsed without a backtracking-prone regex', async () => {
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');

  const dir = mkdtempSync(join(tmpdir(), 'cts-yarn-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'x', dependencies: { next: '^14.0.0', zod: '^3.0.0' } }),
  );
  writeFileSync(
    join(dir, 'yarn.lock'),
    [
      '# yarn lockfile v1',
      '',
      '"next@npm:^14.0.0", next@^14.0.0:',
      '  version "14.2.3"',
      '  resolved "https://registry.yarnpkg.com/next/-/next-14.2.3.tgz"',
      '',
      'zod@^3.0.0:',
      '  version: 3.23.8',
      '',
    ].join('\n'),
  );

  const { scan: run } = await import('../dist/index.js');
  const started = Date.now();
  const result = await run({ root: dir, offline: true });
  // A catastrophic-backtracking parser would not return promptly.
  assert.ok(Date.now() - started < 5000);
  assert.ok(Array.isArray(result.findings));
});

test('markdown report is well-formed for both verdicts', async () => {
  const { renderMarkdown } = await import('../dist/index.js');

  const vuln = renderMarkdown(await scan({ root: VULNERABLE, offline: true }));
  assert.match(vuln, /## 🔴 ClearToShip — hold before shipping/);
  assert.match(vuln, /\| Severity \| Rule \| Finding \| Location \|/);
  assert.match(vuln, /`CTS030`/);
  assert.match(vuln, /<details><summary>/, 'lower-severity findings should be collapsible');
  // A GitHub comment must not exceed 65536 bytes.
  assert.ok(Buffer.byteLength(vuln) < 65536, 'comment body must fit GitHub limit');

  const clean = renderMarkdown(await scan({ root: CLEAN, offline: true }));
  assert.match(clean, /clear to ship/);
  assert.match(clean, /No security findings/);
  assert.ok(!clean.includes('| Severity |'), 'no table when there is nothing to report');
});

test('the shipped GitHub Action is structurally sound', () => {
  const yml = readFileSync(join(here, '..', 'action.yml'), 'utf8');
  assert.ok(!/\t/.test(yml), 'YAML must not contain tabs');
  assert.match(yml, /using: composite/);
  // The two runner paths the action can take: the release bundle, then a local build.
  assert.match(yml, /releases\/download\/v\$\{ver\}\/cleartoship\.mjs/, 'should prefer the release bundle');
  assert.match(yml, /releases\/latest\/download\/cleartoship\.mjs/, '`latest` resolves through GitHub releases');
  assert.match(yml, /node \$\{GITHUB_ACTION_PATH\}\/dist\/cli\.js/, 'should fall back to a local build');
  // ClearToShip is not published on npm, so a package by its name on the registry
  // is not ours. The action must never fetch or run one: with `version: latest`
  // and an unclaimed name, that would be code execution for whoever registers it.
  const code = yml.replace(/^\s*#.*$/gm, '');
  assert.ok(!/npx\s+(--yes\s+)?cleartoship/.test(code), 'the action must not npx the cleartoship package');
  assert.ok(!/npm\s+(view|install|i)\s+\S*cleartoship/.test(code), 'the action must not resolve cleartoship from npm');
  // Balanced GitHub expression braces.
  const opens = (yml.match(/\$\{\{/g) || []).length;
  const closes = (yml.match(/\}\}/g) || []).length;
  assert.equal(opens, closes, 'unbalanced ${{ }} expressions');
  // Every declared output must be produced by the scan step. The list is read
  // out of the outputs: block rather than hard-coded, so a newly declared
  // output cannot ship without something actually writing it.
  const outputsBlock = yml.slice(yml.indexOf('\noutputs:'), yml.indexOf('\nruns:'));
  const declared = [...outputsBlock.matchAll(/^  ([a-z][a-z-]*):$/gm)].map((m) => m[1]);
  assert.ok(declared.length >= 5, 'the action should declare its outputs');
  for (const out of declared) {
    assert.match(yml, new RegExp(`\\b${out}=`), `output ${out} must be written`);
  }

  // Shell-quoting guard. The inline script is fed to node over a quoted
  // heredoc, never `node -e '...'`, where a single apostrophe in a comment
  // truncates the script and every output silently comes back empty.
  assert.ok(!/node -e '/.test(yml), "inline node must not be passed via node -e '...'");
  assert.match(yml, /node <<'NODE'/, 'inline node should be fed over a quoted heredoc');
  // After YAML strips the block indentation the terminator must land in column
  // 0, or the heredoc never closes.
  const runIndent = /^(\s*)node <<'NODE'/m.exec(yml)[1];
  assert.match(
    yml,
    new RegExp(`^${runIndent}NODE$`, 'm'),
    'heredoc terminator must sit at the run body indentation',
  );

  // The gate must be counted off every finding's severity. Rebuilding it from
  // the critical/high outputs alone is the bug that made fail-on=medium and
  // fail-on=low silently behave like fail-on=high.
  assert.match(
    yml,
    /rank\[f\.severity\] >= rank\[gate\]/,
    'the severity gate must count findings at every severity',
  );
});

test('CVEs distinguish shipping deps from dev/build deps', { skip: !online && 'offline' }, async () => {
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'cts-devprod-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({
      name: 'x',
      dependencies: { next: '14.2.3' },     // ships — known CVE cluster
      devDependencies: { postcss: '8.4.30' }, // build-only — known CVE
    }),
  );
  const { scan: run } = await import('../dist/index.js');
  const r = await run({ root: dir });
  const cves = r.findings.filter((f) => f.id === 'CTS024');

  const prod = cves.find((f) => f.meta.package === 'next');
  const dev = cves.find((f) => f.meta.package === 'postcss');
  assert.ok(prod && dev, 'both packages should have advisories');

  assert.equal(prod.meta.production, true);
  assert.notEqual(prod.severity, 'low', 'a shipping CVE keeps its CVSS severity');

  // `notEqual(…, 'low')` passed for a year while every advisory was reported
  // `high` because the CVSS vector was never parsed. Assert the score itself.
  assert.ok(
    prod.meta.advisories.some((a) => typeof a.cvss === 'number'),
    'a real CVSS score must be read off the record, not defaulted',
  );
  const { severityFromCvss } = await import('../dist/utils/osv.js');
  const worst = prod.meta.advisories
    .filter((a) => typeof a.cvss === 'number')
    .reduce((a, b) => (b.cvss > a.cvss ? b : a));
  assert.equal(
    prod.severity,
    severityFromCvss(worst.cvss),
    'the severity reported is the one the worst score maps to',
  );

  assert.equal(dev.meta.production, false);
  assert.equal(dev.severity, 'low', 'a dev/build CVE is held below the gate');
  assert.match(dev.title, /Dev dependency/);

  // The known-vulnerabilities check fails on shipping deps, not dev ones.
  const check = r.checks.find((c) => c.label.startsWith('Known vulnerabilities'));
  assert.equal(check.passed, false);
  assert.match(check.note, /1 shipping/);
});

test('generated code (Prisma client, *.generated.*) is skipped', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const inGenerated = result.findings.filter((f) => (f.file || '').includes('generated/prisma'));
  assert.deepEqual(inGenerated, [], 'vendor/generated code must not produce findings');
});

test('A09/A10/A08 logic rules fire precisely and skip the safe cases', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const ids = (id) => result.findings.filter((f) => f.id === id);

  // A09 — secrets/PII in logs, but NOT a non-sensitive object or a string message.
  const logs = ids('CTS070');
  assert.ok(logs.length >= 3, 'should catch logged password, token, and request body');
  assert.ok(logs.some((f) => f.title.includes('Request body')), 'whole-body log flagged');
  assert.ok(!logs.some((f) => f.line === 8), 'console.log("user", user) must not fire');

  // A10 — fails-open flagged, fail-closed not.
  const failOpen = ids('CTS071');
  assert.ok(failOpen.some((f) => f.severity === 'high'), 'catch { return true } in a verify fn is high');
  assert.ok(
    !failOpen.some((f) => f.meta?.function === 'safeVerify'),
    'catch { return false } must not be flagged',
  );

  // A08 — insecure deserialization in both JS and Python.
  const deser = ids('CTS072');
  assert.ok(deser.some((f) => f.file.endsWith('.ts')), 'node-serialize unserialize flagged');
  assert.ok(deser.some((f) => f.file.endsWith('.py')), 'pickle/yaml.load flagged');

  for (const f of [...logs, ...failOpen, ...deser]) {
    assert.match(f.owasp, /A0[89]|A10/, 'maps to A08/A09/A10');
  }
});

test('logic rules do not fire on the clean fixture', async () => {
  const result = await scan({ root: CLEAN, offline: true });
  assert.ok(!result.findings.some((f) => ['CTS070', 'CTS071', 'CTS072'].includes(f.id)));
});

// ---------------------------------------------------------------------------
// Regressions from the 0.13.4 audit. Every test below reproduces a defect that
// shipped, so the fix stays fixed.
// ---------------------------------------------------------------------------

/** A throwaway project directory, populated from a {path: contents} map. */
async function tempProject(files) {
  const { mkdtempSync, writeFileSync, mkdirSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { dirname: dir } = await import('node:path');
  const root = mkdtempSync(join(tmpdir(), 'cts-audit-'));
  for (const [name, contents] of Object.entries(files)) {
    const full = join(root, name);
    mkdirSync(dir(full), { recursive: true });
    writeFileSync(full, contents);
  }
  return root;
}

const VULNERABLE_ROUTE = [
  "import { createClient } from '@supabase/supabase-js';",
  // A hardcoded secret (CTS030) rather than the missing auth check itself
  // (CTS001) — this fixture is a proxy for "was this file/directory actually
  // opened", not a test of the Server Actions suite.
  "const STRIPE_KEY = 'sk_live_51NqAbCdEfGhIjKlMnOpQrStU';",
  'export async function POST(req: Request) {',
  '  const body = await req.json();',
  '  const db = createClient(process.env.URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);',
  "  await db.from('users').delete().eq('id', body.id);",
  '  return Response.json({ ok: true, key: STRIPE_KEY });',
  '}',
  '',
].join('\n');

test('a directory named site/ is read, not skipped', async () => {
  // `site` and `_reference` were on the skip list because they are this
  // project's own layout. Every user with a site/ directory had that whole
  // subtree reported clean without a single file being opened.
  const root = await tempProject({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0"}}\n',
    'site/app/api/admin/route.ts': VULNERABLE_ROUTE,
  });
  const result = await scan({ root, offline: true, noCommunity: true });
  assert.ok(ids(result).has('CTS030'), 'a hardcoded secret under site/ must still be reported');
});

test('naming a single file scans that file', async () => {
  // `cleartoship path/to/file.ts` is documented, and used to walk nothing:
  // readdirSync on a file throws, the walk returned empty, and the run reported
  // CLEAR TO SHIP having opened no files at all.
  const root = await tempProject({
    'package.json': '{"name":"x"}\n',
    'app/api/admin/route.ts': VULNERABLE_ROUTE,
  });
  const result = await scan({
    root,
    paths: ['app/api/admin/route.ts'],
    offline: true,
    noCommunity: true,
  });
  assert.equal(result.fileCount, 1, 'the named file is the one file scanned');
  assert.ok(ids(result).has('CTS030'));
});

test('a path that does not exist is reported, not silently empty', async () => {
  const root = await tempProject({ 'package.json': '{"name":"x"}\n' });
  const result = await scan({ root, paths: ['nope'], offline: true, noCommunity: true });
  assert.ok(
    result.warnings.some((w) => w.includes('does not exist')),
    'a missing path must not read as a clean scan',
  );
  // A warning is not enough: the verdict is what a CI gate and a badge read.
  const { verdictOf } = await import('../dist/report.js');
  assert.equal(verdictOf(result), 'conditional', 'nothing was scanned, so it cannot be "clear"');
});

test('the verdict is decided in one place, and an incomplete run is never clear', async () => {
  const { verdictOf } = await import('../dist/report.js');
  const counts = (over = {}) => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0, ...over });

  assert.equal(verdictOf({ counts: counts(), incomplete: [] }), 'clear');
  assert.equal(verdictOf({ counts: counts({ low: 4, medium: 2 }), incomplete: [] }), 'clear');
  assert.equal(verdictOf({ counts: counts({ high: 1 }), incomplete: [] }), 'conditional');
  assert.equal(verdictOf({ counts: counts({ critical: 1 }), incomplete: [] }), 'hold');
  // Nothing found, but something could not be looked at: not clear.
  assert.equal(verdictOf({ counts: counts(), incomplete: ['registry did not answer'] }), 'conditional');
  // A finding always outranks an incomplete run.
  assert.equal(verdictOf({ counts: counts({ critical: 1 }), incomplete: ['x'] }), 'hold');
  // A result from before the field existed still reads correctly.
  assert.equal(verdictOf({ counts: counts() }), 'clear');
});

test('when the registry does not answer, the run says it did not check — it does not say "all checks passed"', async () => {
  // The real failure: with npmjs.com unreachable, a project depending on two
  // packages that do not exist scanned "clear to ship — all checks passed", and the
  // dependency check still read "2 packages checked". Fail-open stays (a network
  // blip must never be reported as a hallucinated package); claiming it checked
  // does not.
  const { verdictOf, renderTerminal, renderJson, renderMarkdown } = await import('../dist/report.js');
  const root = await tempProject({
    'package.json': JSON.stringify({
      name: 'x',
      version: '1.0.0',
      dependencies: { 'react-hot-toast-notifications': '1.0.0', 'tailwind-modal-components': '1.0.0' },
    }),
  });
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const cache = mkdtempSync(join(tmpdir(), 'cts-cache-'));

  const realFetch = globalThis.fetch;
  const realCache = process.env.CLEARTOSHIP_CACHE;
  globalThis.fetch = () => Promise.reject(new TypeError('fetch failed (simulated: registry unreachable)'));
  process.env.CLEARTOSHIP_CACHE = cache; // an earlier real answer must not mask the outage
  let result;
  try {
    result = await scan({ root, noCommunity: true });
  } finally {
    globalThis.fetch = realFetch;
    if (realCache === undefined) delete process.env.CLEARTOSHIP_CACHE;
    else process.env.CLEARTOSHIP_CACHE = realCache;
  }

  // Still fail-open: an unreachable registry is not evidence the packages are fake.
  assert.equal(result.findings.filter((f) => f.id === 'CTS020').length, 0);

  const reason = result.incomplete.find((r) => /looked up on npm\/PyPI/.test(r));
  assert.ok(reason, 'the outage must be recorded as an incomplete check');
  assert.match(reason, /^2 of 2 packages/);
  assert.ok(result.warnings.includes(reason), 'and still shown as a warning');

  const check = result.checks.find((c) => c.label.startsWith('Dependency verification'));
  assert.equal(check.label, 'Dependency verification (0 of 2 packages checked against npm/PyPI)');
  assert.equal(check.passed, false, 'a check that looked at nothing has not passed');

  assert.equal(verdictOf(result), 'conditional');
  const text = renderTerminal(result);
  assert.ok(!text.includes('all checks passed'), 'the terminal verdict must not claim a clean run');
  assert.ok(!/✔ PASS\s+Dependency verification/.test(text), 'and must not list the check as passed');
  assert.match(text, /could not complete/);
  assert.equal(JSON.parse(renderJson(result)).verdict, 'conditional');
  assert.match(renderMarkdown(result), /Not everything could be checked/);
});

test('the walk says what it left unread', async () => {
  const root = await tempProject({
    'package.json': '{"name":"x"}\n',
    'node_modules/pkg/index.js': 'export const a = 1;\n',
    'huge.ts': `// ${'x'.repeat(2_100_000)}\n`,
  });
  const result = await scan({ root, offline: true, noCommunity: true });
  assert.ok(result.skippedDirs.includes('node_modules'), 'skipped directories are named');
  assert.equal(result.oversizeCount, 1, 'a file too large to read is counted');
  assert.ok(
    result.checks.some((c) => /too large to read/.test(c.label)),
    'and both appear in the report rather than only in the walk',
  );
});

test('a package this repository defines itself is not a hallucinated dependency', async () => {
  // A library whose README says `npm install <its own name>` before the first
  // publish was reported CTS020 critical — blocking the default gate, on
  // entirely correct code. Runs online: the point is that no lookup happens.
  const root = await tempProject({
    'package.json': '{"name":"a-package-that-is-not-published-xyz9","version":"0.1.0"}\n',
    'README.md': '# x\n\n```bash\nnpm install a-package-that-is-not-published-xyz9\n```\n',
    'packages/ui/package.json': '{"name":"@acme-private/ui","version":"1.0.0"}\n',
    'packages/app/package.json':
      '{"name":"@acme-private/app","dependencies":{"@acme-private/ui":"^1.0.0"}}\n',
  });
  const result = await scan({ root, offline: true, noCommunity: true });
  const named = result.findings
    .filter((f) => ['CTS020', 'CTS021', 'CTS022', 'CTS023'].includes(f.id))
    .map((f) => f.meta.package);
  assert.deepEqual(named, [], 'neither the root package nor a sibling workspace is third-party');

  const check = result.checks.find((c) => c.label.startsWith('Dependency verification'));
  assert.match(check.note ?? '', /defined by this repository itself/, 'and the report says so');
});

test('CTS032 asks the gitignore matcher, not a list of literal strings', async () => {
  // `/.env` and `.env.local` both genuinely cover the file beside them. Both
  // were reported as uncovered — a high-severity finding on a correct repo.
  const covered = [
    ['/.env', '.env'],
    ['.env.local', '.env.local'],
    ['**/.env', '.env'],
    ['.env*', '.env'],
  ];
  for (const [rule, envFile] of covered) {
    const root = await tempProject({
      'package.json': '{"name":"x"}\n',
      '.gitignore': `${rule}\n`,
      [envFile]: 'API_SECRET=abc\n',
      '.git/HEAD': 'ref: refs/heads/main\n',
    });
    const result = await scan({ root, offline: true, noCommunity: true });
    assert.ok(
      !ids(result).has('CTS032'),
      `.gitignore rule "${rule}" does cover ${envFile}; CTS032 must stay quiet`,
    );
  }

  // A nested .gitignore counts too — git reads those, so this must.
  const nested = await tempProject({
    'package.json': '{"name":"x"}\n',
    '.gitignore': 'node_modules\n',
    'web/.gitignore': '.env\n',
    'web/.env': 'API_SECRET=abc\n',
    '.git/HEAD': 'ref: refs/heads/main\n',
  });
  assert.ok(!ids(await scan({ root: nested, offline: true, noCommunity: true })).has('CTS032'));

  // And the real case still fires.
  const uncovered = await tempProject({
    'package.json': '{"name":"x"}\n',
    '.gitignore': 'node_modules\n',
    '.env': 'API_SECRET=abc\n',
    '.git/HEAD': 'ref: refs/heads/main\n',
  });
  assert.ok(ids(await scan({ root: uncovered, offline: true, noCommunity: true })).has('CTS032'));
});

test('CVSS base scores are computed from the vector OSV actually publishes', async () => {
  // OSV publishes `severity[].score` as a vector string, not a number. Reading
  // it with Number() produced NaN on every GitHub-sourced advisory, so every
  // CVE fell through to the null default and a 9.8 and a 5.3 both reported high.
  const { cvssFromVector, severityFromCvss, severityForVulnerability } = await import(
    '../dist/utils/osv.js'
  );
  const published = [
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0, 'critical'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'critical'],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 8.1, 'high'],
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8, 'high'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5, 'high'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1, 'medium'],
    ['CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 6.5, 'medium'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L', 5.3, 'medium'],
    ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N', 0.0, 'low'],
  ];
  for (const [vector, score, severity] of published) {
    assert.equal(cvssFromVector(vector), score, vector);
    assert.equal(severityFromCvss(score), severity, vector);
  }

  // v2 and v4 vectors are not computed; those records fall back to the rating
  // the database publishes rather than defaulting everything to high.
  assert.equal(cvssFromVector('CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P'), null);
  assert.equal(cvssFromVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H'), null);
  assert.equal(
    severityForVulnerability({ cvss: null, rating: 'MODERATE' }),
    'medium',
    'a scoreless record uses the database rating',
  );
  assert.equal(severityForVulnerability({ cvss: null, rating: null }), 'high');
  assert.equal(severityForVulnerability({ cvss: 9.4, rating: 'MODERATE' }), 'critical');
});

test('a secret in a client component is worse than the same secret on the server', async () => {
  // The branch that was supposed to do this read
  // `clientComponent && severity === 'critical' ? 'critical' : severity`,
  // whose two arms are the same value, so it never raised anything.
  const key = 'AIzaSyD9fT2kQ7pLm4Rv8XcW1nB3hJ6yU0oE5aZ';
  const root = await tempProject({
    'package.json': '{"name":"x"}\n',
    'app/Widget.tsx': `'use client';\nconst k = "${key}";\nexport default () => k;\n`,
    'app/server.ts': `const k = "${key}";\nexport const keys = k;\n`,
  });
  const result = await scan({ root, offline: true, noCommunity: true });
  const byFile = Object.fromEntries(
    result.findings.filter((f) => f.id === 'CTS030').map((f) => [f.file, f.severity]),
  );
  assert.equal(byFile['app/server.ts'], 'high', 'a Google key on the server keeps its severity');
  assert.equal(byFile['app/Widget.tsx'], 'critical', 'and is one step worse in the bundle');
});

test('a real key containing filler digits is still reported', async () => {
  // `1234567`, `xxx` and friends sat in the same list as `changeme` and
  // `your_api_key`, so a live credential that happened to contain one was
  // dropped — the one failure a secret scanner cannot afford.
  const root = await tempProject({
    'package.json': '{"name":"x"}\n',
    'config.ts': [
      // The second value is *defined* as a run of sixteen identical characters,
      // and `'X'.repeat(16)` says so where counting X's in a literal does not.
      `export const live = "AKIA${'Q1234567RSTUVWXY'}";`,
      `export const filler = "AKIA${'X'.repeat(16)}";`,
      '',
    ].join('\n'),
  });
  const result = await scan({ root, offline: true, noCommunity: true });
  const aws = result.findings.filter((f) => f.id === 'CTS030' && f.meta.kind === 'aws');
  assert.equal(aws.length, 1, 'exactly one of the two is a credential');
  assert.equal(aws[0].line, 1, 'the high-entropy one, not the run of X');
});

test('--min-severity cannot hide a finding the gate would fail on', async () => {
  // It is documented as a display control, but the exit code was computed from
  // the findings that survived it, so `--min-severity high --fail-on low` exited 0.
  const out = runCli([
    '-C', VULNERABLE, '--offline', '--no-banner', '--no-community',
    '--min-severity', 'critical', '--fail-on', 'low',
  ]);
  assert.equal(out.code, 1, 'a low-severity gate still fails, however quiet the report');
});

test('repository text going into a PR comment cannot close the block it sits in', async () => {
  const { renderMarkdown } = await import('../dist/report.js');
  const hostile = {
    id: 'CTS028',
    severity: 'critical',
    title: 'Install hook</summary><img src=x onerror=alert(1)>',
    detail: 'The `postinstall` script (`</details><script>x</script>`) runs on every install.',
    fix: 'Remove it.\n```\nnot a fence break\n```',
    file: 'package.json',
    line: 3,
  };
  const md = renderMarkdown({
    root: '/x', framework: 'node', fileCount: 1, gitIgnoredCount: 0, escapingSymlinkCount: 0,
    oversizeCount: 0, skippedDirs: [], findings: [hostile], checks: [], warnings: [],
    counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }, durationMs: 1,
  });
  assert.ok(!md.includes('<script>'), 'no raw script tag reaches the comment');
  assert.ok(!md.includes('<img'), 'no raw img tag reaches the comment');
  assert.ok(!md.includes('</details><'), 'the details block cannot be closed early');
  assert.equal(md.match(/^```$/gm).length, 2, 'exactly one balanced fence');
  assert.ok(md.includes('&lt;'), 'the text is escaped rather than dropped, so it stays readable');
});

test('a scan never runs code from a package it finds beside it', async () => {
  // The bundle is meant to be downloaded into the project being scanned, and that
  // project's package.json can declare any dependency at all — including one named
  // for a companion package nobody owns. An earlier build did a runtime
  // `import('cleartoship-rules-pro')` to load optional scanners, so a scan of a
  // project holding such a package executed that package's code. Plant one, run
  // the real bundle next to it, and require that nothing of it ever ran.
  const { execFileSync } = await import('node:child_process');
  const { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, existsSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const root = join(here, '..');
  execFileSync(process.execPath, [join(root, 'scripts', 'bundle.mjs')], { stdio: 'pipe' });

  const dir = mkdtempSync(join(tmpdir(), 'cts-plant-'));
  const marker = join(dir, 'PLANTED_CODE_RAN');
  for (const name of ['cleartoship-rules-pro']) {
    const pkg = join(dir, 'node_modules', name);
    mkdirSync(pkg, { recursive: true });
    writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name, version: '1.0.0', type: 'module', main: 'index.js' }));
    writeFileSync(
      join(pkg, 'index.js'),
      `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(marker)}, 'ran');\nexport async function getScanners() { return []; }\n`,
    );
  }
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'victim', version: '1.0.0', dependencies: { 'cleartoship-rules-pro': '1.0.0' } }),
  );
  const bundled = join(dir, 'cleartoship.mjs');
  copyFileSync(join(root, 'standalone', 'bin', 'cleartoship.mjs'), bundled);

  execFileSync(process.execPath, [bundled, dir, '--offline', '--json', '--fail-on=none'], {
    stdio: ['pipe', 'pipe', 'ignore'],
  });
  assert.ok(!existsSync(marker), 'a package found beside the bundle must never be loaded or run');

  // And the same for the unbundled CLI, which resolves from this repository.
  const help = execFileSync(process.execPath, [CLI, '--help'], { encoding: 'utf8' });
  assert.ok(!/\bpro\b.*license/i.test(help), 'there is no `pro` command that reaches for a companion package');
});

test('the zero-dependency bundle behaves exactly like the package it stands in for', async () => {
  // The standalone artifact exists so a registry outage cannot take the tool
  // offline. A fallback that behaves differently from the thing you tested is
  // not a fallback, so this asserts they agree finding-for-finding rather than
  // merely that the bundle starts. Built here rather than skipped when absent:
  // a test that quietly skips is how the network-gated ones went unrun for
  // months.
  const { execFileSync } = await import('node:child_process');
  const root = join(here, '..');
  execFileSync(process.execPath, [join(root, 'scripts', 'bundle.mjs')], { stdio: 'pipe' });

  const bundled = join(root, 'standalone', 'bin', 'cleartoship.mjs');
  const args = [VULNERABLE, '--offline', '--json', '--fail-on=none'];
  const run = (entry) =>
    JSON.parse(execFileSync(process.execPath, [entry, ...args], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }));

  const normal = run(CLI);
  const standalone = run(bundled);

  const shape = (r) => r.findings.map((f) => `${f.id}|${f.severity}|${f.file}|${f.line}`).sort();
  assert.ok(shape(normal).length > 30, 'the fixture should produce a substantial report');
  assert.deepEqual(shape(standalone), shape(normal), 'every finding must match');
  assert.equal(standalone.verdict, normal.verdict);
  assert.equal(standalone.version, normal.version);

  // The point of the artifact: nothing left to resolve.
  const manifest = JSON.parse(readFileSync(join(root, 'standalone', 'package.json'), 'utf8'));
  assert.deepEqual(manifest.dependencies, {}, 'the standalone package declares no dependencies');
  assert.equal(manifest.version, JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version);
});
