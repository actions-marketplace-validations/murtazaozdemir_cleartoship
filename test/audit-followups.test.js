// Regression tests for the three self-scan false positives left after the
// 2026-09-23 audit merge. Each failed before its fix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { scan } from '../dist/index.js';
import { lexSpans, commentStyleFor, isInside } from '../dist/utils/spans.js';
import { collectProseForTest } from '../dist/scanners/dependencies.js';

function project(files) {
  const root = mkdtempSync(join(tmpdir(), 'cts-followup-'));
  for (const [path, contents] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), contents);
  }
  return root;
}

const TS = commentStyleFor(['typescript']);

test('a backtick inside a regex literal does not open a template string', () => {
  const source = [
    'if (/`\\s*,\\s*[^)\\s]/.test(statement)) return true;',
    '// a comment after it',
    'const q = "it\'s";',
  ].join('\n');
  const spans = lexSpans(source, TS);
  assert.ok(isInside(spans, source.indexOf('// a comment') + 3, 'comment'));
  assert.ok(isInside(spans, source.indexOf('"it') + 1, 'string'));
});

test('division and JSX closing tags are not read as regex literals', () => {
  const division = 'const r = total / count; // "quoted" in a comment';
  const spans = lexSpans(division, TS);
  assert.ok(isInside(spans, division.indexOf('"quoted"'), 'comment'));

  const jsx = 'const el = <b>bold</b>; const s = "x";';
  const jsxSpans = lexSpans(jsx, TS);
  assert.ok(isInside(jsxSpans, jsx.indexOf('"x"') + 1, 'string'));
});

test('a vendored rule no longer fires on a comment below a regex containing a backtick', async () => {
  const root = project({
    'package.json': '{"name":"lexer-fixture"}',
    'lib/sql.ts': [
      'export function isParameterized(statement: string): boolean {',
      '  if (/`\\s*,\\s*[^)\\s]/.test(statement)) return true;',
      '  return false;',
      '}',
      '// Merely calling `jwt.verify(token, secret)` is not the bug; `verifyToken(`',
      '// matching its own declaration was.',
      '',
    ].join('\n'),
  });
  const result = await scan({ root, offline: true });
  assert.deepEqual(
    result.findings.filter((f) => f.file === 'lib/sql.ts').map((f) => f.id),
    [],
  );
});

test('a placeholder written in words is not harvested as packages', () => {
  const md = 'a library whose README says `npm install <its own name>` before the first publish';
  assert.deepEqual(collectProseForTest(md, 'TODO.md').map((d) => d.name), []);
  // An ordinary install command is still read.
  const plain = '```\nnpm install zod\n```';
  assert.deepEqual(collectProseForTest(plain, 'README.md').map((d) => d.name), ['zod']);
});

test('a 396 KB file of one identifier does not stall the gitleaks rules', async () => {
  // gitleaks' cohere and private_ai patterns nest `[\w.-]{0,50}?` twice; on V8
  // this file took ~10.8 s with the community ruleset off.
  const root = project({ 'package.json': '{"name":"ident"}', 'lib/x.ts': 'a'.repeat(396_000) + '\n' });
  const t = Date.now();
  const result = await scan({ root, offline: true, noCommunity: true });
  assert.ok(Date.now() - t < 3_000, `took ${Date.now() - t} ms`);
  assert.deepEqual(result.incomplete, []);
});

test('two files with identical content both get their community and gitleaks findings', async () => {
  // The linear matcher reused per-text state when the same text was searched
  // again from the start, and found nothing the second time.
  const body = "export function run(req: any) { return eval(req.query.code) }\n" +
    'const t = "' + ['npm', '7Kq2Xv9Lp3Rt8Wm1Zb6Nc4Hd0Jf5Gs2Qy7Ua'].join('_') + '"\n';
  const root = project({ 'package.json': '{"name":"twins"}', 'a/x.ts': body, 'b/x.ts': body });
  for (let i = 0; i < 2; i++) {
    const result = await scan({ root, offline: true });
    for (const id of ['VG014', 'GL-npm-access-token']) {
      assert.deepEqual(
        result.findings.filter((f) => f.id === id).map((f) => f.file).sort(),
        ['a/x.ts', 'b/x.ts'],
        `${id} on scan ${i + 1}`,
      );
    }
  }
});
