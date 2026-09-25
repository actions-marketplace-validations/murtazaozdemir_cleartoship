// The linear-time matcher in community.ts runs about 380 vendored patterns in
// place of V8's own engine. These tests hold it to two promises: it finds
// exactly what V8 finds, match for match; and its cost grows linearly with the
// text on the inputs that made V8's grow with the square of it (or worse).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, lstatSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { scan } from '../dist/index.js';
import { LinearMatcher, matcherFor, linearInIrregexp, PATTERN_OVERRIDES } from '../dist/scanners/community.js';
import { GUARDVIBE_RULES } from '../dist/vendor/guardvibe/index.js';

const byId = new Map(GUARDVIBE_RULES.map((r) => [r.id, r]));
const effective = (id) => PATTERN_OVERRIDES[id] ?? byId.get(id).pattern;

/** Every match `re` reports from `from` on, as `start:end`, stepping past empty ones as the scanner does. */
function matches(re, text, from = 0) {
  const out = [];
  re.lastIndex = from;
  for (let guard = 0; guard < 100_000; guard++) {
    const m = re.exec(text);
    if (m === null) break;
    out.push(`${m.index}:${m.index + m[0].length}`);
    if (m[0].length === 0) re.lastIndex++;
    if (!re.global) break;
  }
  return out.join(',');
}

/** The literal runs in a pattern's source: its trigger words, roughly. */
function fragments(source) {
  const out = new Set();
  let run = '';
  const close = () => {
    if (run.length >= 2) out.add(run);
    run = '';
  };
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === '\\') {
      const d = source[i + 1] ?? '';
      i++;
      if (/[dDsSwWbBnrtvf0-9xuck]/.test(d)) close();
      else run += d;
    } else if (c === '[') {
      close();
      while (i < source.length && source[i] !== ']') i += source[i] === '\\' ? 2 : 1;
    } else if ('()|?*+{}^$.'.includes(c)) {
      // A quantifier makes the last character optional; keep the run anyway.
      close();
    } else run += c;
  }
  close();
  return [...out];
}

let seed = 20260923;
const rnd = (n) => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff), seed % n);
const SEPARATORS = [' ', '\n', '\t', '(', ')', '{', '}', '"', "'", '`', ',', ';', ':', '=', '.', 'a', 'x', '_', '0', '${', '/', '\\', '[', ']', '<', '>', '|', '-', '*', '  '];

const CANDIDATE_CHARS = [...'ax_0 \n\t.(){}[]"\'`=:;,/-$@<>*+?!#%&|\\~AZz9'];

/**
 * A random string the pattern would read as (most of) a match: each atom
 * replaced by a character it accepts, each quantifier by a small count, one
 * alternative chosen at random. Lookarounds and backreferences are skipped,
 * so some samples do not match; those are near misses, which is also useful.
 */
function sample(source, flags) {
  let i = 0;
  const cflags = flags.replace(/[gy]/g, '');
  const pick = (raw) => {
    const re = new RegExp('^(?:' + raw + ')$', cflags);
    let ok = CANDIDATE_CHARS.filter((c) => re.test(c));
    if (ok.length === 0) {
      for (let c = 32; c < 127; c++) if (re.test(String.fromCharCode(c))) ok.push(String.fromCharCode(c));
    }
    return ok.length ? ok[rnd(ok.length)] : '';
  };
  function alt() {
    const options = [seq()];
    while (source[i] === '|') {
      i++;
      options.push(seq());
    }
    return () => options[rnd(options.length)]();
  }
  function seq() {
    const items = [];
    while (i < source.length && source[i] !== '|' && source[i] !== ')') items.push(term());
    return () => items.map((f) => f()).join('');
  }
  function term() {
    const start = i;
    const c = source[i];
    let atom;
    if (c === '^' || c === '$') {
      i++;
      atom = () => '';
    } else if (c === '(') {
      const look = /^\(\?<?[=!]/.test(source.slice(i, i + 4));
      if (source.startsWith('(?:', i)) i += 3;
      else if (look) i += source[i + 2] === '<' ? 4 : 3;
      else if (source.startsWith('(?<', i)) i = source.indexOf('>', i) + 1;
      else i++;
      const body = alt();
      i++; // the closing paren
      atom = look ? () => '' : body;
    } else if (c === '[') {
      let j = i + 1;
      if (source[j] === '^') j++;
      while (source[j] !== ']') j += source[j] === '\\' ? 2 : 1;
      i = j + 1;
      const raw = source.slice(start, i);
      atom = () => pick(raw);
    } else if (c === '\\') {
      const d = source[i + 1];
      i += d === 'x' ? 4 : d === 'u' ? 6 : 2;
      const raw = source.slice(start, i);
      atom = d === 'b' || d === 'B' || /[1-9]/.test(d) ? () => '' : () => pick(raw);
    } else {
      i++;
      atom = () => c;
    }
    const q = /^(?:\*|\+|\?|\{(\d+)(?:(,)(\d*))?\})\??/.exec(source.slice(i));
    if (!q) return atom;
    i += q[0].length;
    const min = q[0][0] === '+' ? 1 : q[1] !== undefined ? Number(q[1]) : 0;
    const max =
      q[0][0] === '?' ? 1 : q[1] === undefined ? Infinity : q[2] === undefined ? min : q[3] === '' ? Infinity : Number(q[3]);
    return () => {
      const k = Math.min(max, min + rnd(3));
      let s = '';
      for (let j = 0; j < k; j++) s += atom();
      return s;
    };
  }
  return alt()();
}

function randomText(pieces, length) {
  let s = '';
  while (s.length < length) {
    if (pieces.length > 0 && rnd(10) < 6) {
      let p = pieces[rnd(pieces.length)];
      if (rnd(4) === 0) p = p.slice(0, 1 + rnd(p.length));
      s += rnd(6) === 0 ? p.repeat(1 + rnd(6)) : p;
    } else s += SEPARATORS[rnd(SEPARATORS.length)].repeat(rnd(8) === 0 ? 1 + rnd(30) : 1);
  }
  return s;
}

// Superseded and withheld rules never run; everything else can.
const excluded = new Set();
{
  const src = readFileSync(fileURLToPath(new URL('../src/scanners/community.ts', import.meta.url)), 'utf8');
  for (const block of [/const SUPERSEDED[\s\S]*?\]\);/, /const WITHHELD[\s\S]*?\]\);/]) {
    for (const m of block.exec(src)[0].matchAll(/\[\s*'(VG\d+)'/g)) excluded.add(m[1]);
  }
}
const active = GUARDVIBE_RULES.filter((r) => !excluded.has(r.id));

test('every active rule is either linear in V8 already or runs on the linear matcher; one exception', () => {
  const unsupported = [];
  let linear = 0;
  for (const r of active) {
    const m = matcherFor(effective(r.id));
    if (m instanceof LinearMatcher) linear++;
    else if (!linearInIrregexp(effective(r.id))) unsupported.push(r.id);
  }
  // VG1094's `\(\s*(\w+)\s*\)\s*=>\s*\1` needs a backreference, which the
  // matcher does not do. Its gaps are bounded ({0,400}), so V8 stays polynomial
  // with a small constant on it; the time budget covers the rest.
  assert.deepEqual(unsupported, ['VG1094']);
  assert.ok(linear > 300, `${linear} rules on the linear matcher`);
});

test('the linear matcher finds exactly what V8 finds, on generated text, for every rule it accepts', () => {
  let compared = 0;
  let withMatches = 0;
  for (const r of active) {
    const re = effective(r.id);
    let lm;
    try {
      lm = new LinearMatcher(re);
    } catch {
      continue; // VG1094, checked above
    }
    const pieces = fragments(re.source);
    for (let k = 0; k < 6; k++) {
      const whole = sample(re.source, re.flags);
      pieces.push(whole, whole.slice(0, rnd(whole.length + 1)));
    }
    for (let t = 0; t < 24; t++) {
      const text = randomText(pieces, 20 + rnd(t % 4 === 0 ? 2000 : 400));
      const from = rnd(3) === 0 ? rnd(text.length) : 0;
      const expected = matches(re, text, from);
      assert.equal(matches(lm, text, from), expected, `${r.id} differs from V8 on ${JSON.stringify(text.slice(0, 200))}`);
      compared++;
      if (expected !== '') withMatches++;
    }
  }
  assert.ok(withMatches > 500, `only ${withMatches} of ${compared} inputs matched anything`);
});

test('the linear matcher finds exactly what V8 finds on the fixture projects', () => {
  const root = fileURLToPath(new URL('./fixtures/', import.meta.url));
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const st = lstatSync(p);
      if (st.isDirectory()) walk(p);
      else if (st.isFile() && st.size < 400_000) files.push(p);
    }
  };
  walk(root);
  assert.ok(files.length > 20);
  let found = 0;
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    for (const r of active) {
      const m = matcherFor(effective(r.id));
      if (!(m instanceof LinearMatcher)) continue;
      const expected = matches(effective(r.id), text);
      assert.equal(matches(m, text), expected, `${r.id} on ${file}`);
      if (expected !== '') found++;
    }
  }
  assert.ok(found > 0, 'the fixtures matched nothing, so nothing was compared');
});

// Rules the 2026-09-23 audit named as super-linear, and the worst the whole-
// ruleset fuzz found afterwards, each with a real positive and negative.
const SNIPPETS = {
  VG061: ['jwt.sign(payload, secret)', "jwt.sign(payload, secret, { expiresIn: '1h' })"],
  VG102: ['fs.readFile(path.join(dir, req.query.name))', 'fs.readFile(path.join(dir, "static.txt"))'],
  VG103: ['Object.assign(target, req.body)', 'Object.assign(target, defaults)'],
  VG105: ['jwt.verify(token, secret)', "jwt.verify(token, secret, { algorithms: ['HS256'] })"],
  VG125: [
    'async function login(req, res) {\n  req.session.userId = user.id;\n  return res.json({ ok: true })\n}',
    'async function login(req, res) {\n  req.session.regenerate(() => {});\n  req.session.userId = user.id;\n}',
  ],
  VG140: ['xml2js.parseString(rawXml + req.body.xml)', 'parseString(xml, { noent: false }, cb)'],
  VG851: [
    'catch (e) {\n  return Response.json({ error: e.message, systemPrompt })\n}',
    'catch (e) {\n  return Response.json({ error: "internal" })\n}',
  ],
  VG1011: ['sql.identifier(req.query.column)', 'sql.identifier("created_at")'],
  VG1082: ['Handlebars.compile(req.body.template)', 'Handlebars.compile(TEMPLATE)'],
  VG133: [
    'const u = await db.user.findUnique({ where: { id } });\nif (u.balance > 0) {\n  await db.user.update({ where: { id } })\n}',
    'await db.$transaction(async (tx) => { const u = await tx.user.findUnique({ where: { id } }) })',
  ],
  VG981: ['.middleware(async ({ req }) => {\n  return { files: [] }\n})', '.middleware(async ({ req }) => {\n  const user = await auth(req)\n  return { userId: user.id }\n})'],
  VG1070: ['- run: npm install\n', '- run: npm ci --ignore-scripts\n'],
};

test('the audit-named rules: same verdict as V8 on a real positive and negative', () => {
  for (const [id, [positive, negative]] of Object.entries(SNIPPETS)) {
    const re = effective(id);
    const m = matcherFor(re);
    assert.ok(m instanceof LinearMatcher, `${id} runs on the linear matcher`);
    assert.notEqual(matches(re, positive), '', `${id}: the positive does match upstream`);
    assert.equal(matches(m, positive), matches(re, positive), `${id} positive`);
    assert.equal(matches(m, negative), matches(re, negative), `${id} negative`);
  }
});

/** Milliseconds to run `m` over `text` to the end, the best of three. */
function cost(m, text) {
  let best = Infinity;
  for (let k = 0; k < 3; k++) {
    const t = performance.now();
    matches(m, text);
    best = Math.min(best, performance.now() - t);
  }
  return best;
}

/** Inputs of the shapes that stalled V8: a trigger repeated, or a trigger and then one long run. */
function adversarial(source, size) {
  const pieces = fragments(source);
  const trigger = pieces[0] ?? 'a';
  const near = pieces.join(' ');
  return [
    trigger.repeat(Math.ceil(size / trigger.length)),
    (trigger + ' ').repeat(Math.ceil(size / (trigger.length + 1))),
    trigger + '(' + ' '.repeat(size),
    trigger + '\n'.repeat(size),
    (near + '\n').repeat(Math.ceil(size / (near.length + 1))),
  ].map((s) => s.slice(0, size));
}

test('ReDoS: the audit-named rules grow linearly, not with the square of the input', () => {
  // V8 on the first of these took from 2 s (VG061 at 400 KB) to minutes. A
  // quadratic cost quadruples per doubling, so 32 KB -> 128 KB would be 16x;
  // linear is 4x. 8x leaves room for timer noise and GC without letting a
  // quadratic one through.
  for (const id of Object.keys(SNIPPETS)) {
    const m = matcherFor(effective(id));
    const larges = adversarial(effective(id).source, 128_000);
    for (const [small, large] of adversarial(effective(id).source, 32_000).map((s, i) => [s, larges[i]])) {
      const a = cost(m, small);
      const b = cost(m, large);
      assert.ok(b < 8 * a + 20, `${id}: ${a.toFixed(1)} ms at 32 KB, ${b.toFixed(1)} ms at 128 KB`);
      assert.ok(b < 1_000, `${id}: ${b.toFixed(1)} ms at 128 KB`);
    }
  }
});

test('ReDoS: every rule stays fast on its own trigger words at 32 KB', () => {
  // A sweep, not a proof: the whole-ruleset fuzz behind these numbers pumped
  // every rule's prefixes and quantifiers up to 400 KB. This keeps the cheap
  // part of it in the suite so a regression cannot pass unnoticed.
  const slow = [];
  for (const r of active) {
    const m = matcherFor(effective(r.id));
    for (const text of adversarial(effective(r.id).source, 32_000)) {
      const t = performance.now();
      matches(m, text);
      const ms = performance.now() - t;
      if (ms > 400) slow.push(`${r.id} ${ms.toFixed(0)} ms on ${JSON.stringify(text.slice(0, 40))}`);
    }
  }
  assert.deepEqual(slow, []);
});

function project(files) {
  const root = mkdtempSync(join(tmpdir(), 'cts-redos-'));
  for (const [path, contents] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), contents);
  }
  return root;
}

test('ReDoS: a hostile file does not make the scan incomplete, and what it hides is still found', async () => {
  // Triggers of the rules that were slowest, each followed by the kind of run
  // that stalled them: 1.2 MB in all, so it is searched in windows, plus a
  // 200 KB file that is searched whole (small enough that a slow CI runner has
  // headroom under the fixed 250 ms minimum budget).
  const hostile =
    'jwt.sign('.repeat(40_000) +
    '\n.middleware( async (' + ' '.repeat(200_000) +
    '\n- cmd:' + '\t'.repeat(200_000) +
    '\nfindOne()\nif(){.update(' + '\n'.repeat(200_000) +
    '\n' + 'eval'.repeat(100_000) +
    '\nexport function run(code: string) { return eval(code) }\n';
  const root = project({
    'package.json': '{"name":"r"}',
    'lib/hostile.ts': hostile,
    'lib/whole.ts': '/' + '|(*)*|('.repeat(28_000) + '\nexport function go(code: string) { return eval(code) }\n',
  });
  const t = Date.now();
  const result = await scan({ root, offline: true });
  const took = Date.now() - t;
  assert.deepEqual(
    result.incomplete.filter((r) => /time budget/.test(r)),
    [],
    `a rule ran out of time budget (${took} ms)`,
  );
  const evals = result.findings.filter((f) => f.id === 'VG014').map((f) => f.file).sort();
  assert.deepEqual(evals, ['lib/hostile.ts', 'lib/whole.ts']);
  assert.ok(took < 120_000, `took ${took} ms`);
});

test('ReDoS safety net: a pattern V8 backtracks on is still stopped by the time budget', async () => {
  // No vendored rule is super-linear any more, so borrow one: a backreference
  // keeps this pattern off the linear matcher, and it is quadratic on its own
  // trigger repeated, as VG061's upstream pattern was.
  const original = PATTERN_OVERRIDES.VG061;
  PATTERN_OVERRIDES.VG061 = /(jwt)\.sign\s*\((?:(?!\bexpiresIn\b|\1x)[^)])*\)/gi;
  try {
    assert.ok(!(matcherFor(PATTERN_OVERRIDES.VG061) instanceof LinearMatcher));
    const root = project({
      'package.json': '{"name":"r"}',
      'lib/adv.ts': 'jwt.sign('.repeat(Math.floor(1_000_000 / 9)) + '\nexport function run(code: string) { return eval(code) }\n',
    });
    const result = await scan({ root, offline: true });
    assert.equal(result.findings.filter((f) => f.id === 'VG014').length, 1, 'the other rules still read the whole file');
    assert.ok(
      result.incomplete.some((r) => /^VG061 .*lib\/adv\.ts/.test(r)),
      `the stopped rule is reported: ${JSON.stringify(result.incomplete)}`,
    );
  } finally {
    if (original === undefined) delete PATTERN_OVERRIDES.VG061;
    else PATTERN_OVERRIDES.VG061 = original;
  }
});
