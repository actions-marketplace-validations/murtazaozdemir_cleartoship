// Regression tests for the 2026-10-13 audit. Two themes: files and rules that
// were never read at all (a generated-looking name, an HTML page, a `.toml`,
// a `firestore.rules`), and vendored rules reporting critical on correct code.
// Every test here failed before its fix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { scan } from '../dist/index.js';
import { languagesFor } from '../dist/utils/files.js';
import { Suppressions } from '../dist/utils/suppress.js';
import { GUARDVIBE_RULES } from '../dist/vendor/guardvibe/index.js';
import { RULE_COUNTS } from '../dist/scanners/community.js';
import { Registry } from '../dist/utils/registry.js';

/** A throwaway project from a { path: contents } map. */
function project(files) {
  const root = mkdtempSync(join(tmpdir(), 'cts-cover-'));
  for (const [path, contents] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), contents);
  }
  return root;
}

const byId = (result, id) => result.findings.filter((f) => f.id === id);
const run = (root, options = {}) => scan({ root, offline: true, ...options });

// Credential-shaped values are assembled at runtime so this file is not itself
// a file full of keys.
const SERVICE_ROLE_JWT = [
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  Buffer.from(JSON.stringify({ iss: 'supabase', role: 'service_role', exp: 2000000000 })).toString(
    'base64url',
  ),
  'dGhpc19pc19hX2Zha2Vfc2lnbmF0dXJlXzEyMw',
].join('.');
const STRIPE_LIVE = ['sk', 'live', '51NqAbCdEfGhIjKlMnOpQrStU'].join('_');

const ADMIN_ACTION = `'use server'
import { db } from '@/lib/db'

export async function grantAdmin(email: string) {
  await db.from('profiles').update({ is_admin: true }).eq('email', email)
}
`;

// --- files the walk declined, silently --------------------------------------

test('a generated-looking file is skipped, and the report names the skip', async () => {
  const root = project({
    'package.json': '{"name":"g","dependencies":{"next":"15.0.0"}}',
    'app/actions/admin.ts': ADMIN_ACTION,
    'app/actions/admin.gen.ts': ADMIN_ACTION,
    'src/generated/client/admin.ts': ADMIN_ACTION,
  });
  const result = await run(root);

  // The skip itself is deliberate: a Prisma client ships its own credentials.
  assert.equal(result.generatedCount, 2);
  const files = byId(result, 'CTS001').map((f) => f.file);
  assert.deepEqual(files, ['app/actions/admin.ts']);

  // What was not deliberate: saying nothing. Two files byte-identical to one
  // reported critical beside them were left out of the report entirely.
  const row = result.checks.find((c) => c.label.startsWith('Generated files skipped'));
  assert.ok(row, 'expected a check row for the generated files');
  assert.match(row.label, /\(2\)/);
  assert.match(row.note, /app\/actions\/admin\.gen\.ts/);
  assert.match(row.note, /src\/generated\/client\/admin\.ts/);
  assert.match(row.note, /nothing in them was checked/i);
});

test('a static HTML page is read: a key in an inline script is a finding', async () => {
  const root = project({
    'package.json': '{"name":"h"}',
    'public/index.html':
      '<!doctype html><html><body><script>\n' +
      `const supabase = createClient("https://x.supabase.co", "${SERVICE_ROLE_JWT}");\n` +
      `const stripe = "${STRIPE_LIVE}";\n` +
      '</script></body></html>\n',
  });
  const result = await run(root);
  const secrets = byId(result, 'CTS030');
  assert.equal(secrets.length, 2, JSON.stringify(secrets.map((f) => f.title)));
  assert.ok(secrets.every((f) => f.file === 'public/index.html'));
  assert.ok(secrets.every((f) => f.severity === 'critical'));
  // Redacted like every other finding, whatever file type it came out of.
  assert.ok(secrets.every((f) => !f.snippet.includes(STRIPE_LIVE)));
});

test('every vendored rule can be reached by some file the walk reads', async () => {
  // VG517/518/520 (TOML platform config) and VG750/753 (Firebase rules) were
  // vendored, counted as active in the report's rule count, and could never
  // match: `languagesFor` answered nothing for a `.toml`, and no `.rules` file
  // was read at all.
  const produced = new Set([
    ...languagesFor('a.ts'), ...languagesFor('a.tsx'), ...languagesFor('a.js'),
    ...languagesFor('a.json'), ...languagesFor('vercel.json'), ...languagesFor('a.sql'),
    ...languagesFor('a.yml'), ...languagesFor('docker-compose.yml'), ...languagesFor('render.yaml'),
    ...languagesFor('a.py'), ...languagesFor('a.go'), ...languagesFor('a.sh'),
    ...languagesFor('a.tf'), ...languagesFor('a.rb'), ...languagesFor('a.php'),
    ...languagesFor('Dockerfile'), ...languagesFor('a.html'), ...languagesFor('fly.toml'),
    ...languagesFor('netlify.toml'), ...languagesFor('a.toml'),
    ...languagesFor('firestore.rules'), ...languagesFor('database.rules.json'),
  ]);
  const unreachable = GUARDVIBE_RULES.filter((r) => !r.languages.some((l) => produced.has(l)));
  assert.deepEqual(unreachable.map((r) => r.id), []);
});

test('the TOML and Firebase-rules rules that could never run now fire', async () => {
  const root = project({
    'package.json': '{"name":"p"}',
    'fly.toml': '[env]\n  SESSION_SECRET = "Hv8wQ2ltYmFsYmFs9921xZ"\n  force_https = false\n',
    'firestore.rules':
      'service cloud.firestore {\n  match /databases/{db}/documents {\n' +
      '    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}\n',
  });
  const result = await run(root);
  const ids = new Set(result.findings.map((f) => f.id));
  assert.ok(ids.has('VG517'), `fly.toml [env] secret: ${[...ids]}`);
  assert.ok(ids.has('VG750'), `firestore allow if true: ${[...ids]}`);
});

// --- vendored rules reporting critical on correct code ----------------------

const GATED_PROMOTION = `import { auth } from '@/auth'
import { db } from '@/lib/db'

export async function POST(req: Request) {
  const session = await auth()
  if (!session?.user) return new Response('Unauthorized', { status: 401 })
  const caller = await db.from('profiles').select('is_admin').eq('id', session.user.id).single()
  if (!caller.data?.is_admin) return new Response('Forbidden', { status: 403 })

  const { email } = await req.json()
  await db.from('profiles').update({ is_admin: true }).eq('email', email)
  return Response.json({ ok: true })
}
`;

test('VG1008/VG154: an admin route that checks the caller is an admin is not a finding', async () => {
  const root = project({
    'package.json': '{"name":"a","dependencies":{"@supabase/supabase-js":"2.45.0"}}',
    'app/api/promote/route.ts': GATED_PROMOTION,
  });
  const result = await run(root);
  // Both fired critical on this file: VG1008 because its pattern has no notion
  // of the authorization check its own name is about, VG154 because an access
  // -control gate has the same read-check-write shape as a credits race.
  assert.deepEqual(byId(result, 'VG1008'), []);
  assert.deepEqual(byId(result, 'VG154'), []);
  // And the AST rule that reads the same function agrees it is authorized.
  assert.deepEqual(byId(result, 'CTS001'), []);
});

test('VG1008: the same write with nothing checking the caller is still critical', async () => {
  const root = project({
    'package.json': '{"name":"a","dependencies":{"next":"15.0.0"}}',
    'app/actions/admin.ts': ADMIN_ACTION,
  });
  const result = await run(root);
  const found = byId(result, 'VG1008');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'critical');
});

test('VG154: a credits balance read, checked, then written is still reported', async () => {
  const root = project({
    'package.json': '{"name":"c","dependencies":{"@supabase/supabase-js":"2.45.0"}}',
    'lib/spend.ts': `import { supabase } from './client'

export async function spend(id: string, cost: number) {
  const { data } = await supabase.from('users').select('credits').eq('id', id).single()
  if (data.credits >= cost) {
    await supabase.from('users').update({ credits: data.credits - cost }).eq('id', id)
  }
}
`,
  });
  const result = await run(root);
  assert.equal(byId(result, 'VG154').length, 1);
});

test('VG999 is superseded by CTS081: one finding for one uncapped model call', async () => {
  const root = project({
    'package.json': '{"name":"ai","dependencies":{"ai":"5.0.0","next":"15.5.0"}}',
    'app/api/chat/route.ts': `import { generateText } from 'ai'
import { openai } from '@ai-sdk/openai'

export async function POST(req: Request) {
  const { prompt } = await req.json()
  const { text } = await generateText({ model: openai('gpt-5'), prompt })
  return Response.json({ text })
}
`,
  });
  const result = await run(root);
  assert.equal(byId(result, 'CTS081').length, 1);
  assert.deepEqual(byId(result, 'VG999'), []);
});

test('VG012: innerHTML from a constant, escaped on the way in, is not XSS', async () => {
  const root = project({
    'package.json': '{"name":"x"}',
    'public/page.html': `<script>
var out = document.getElementById('o');
function esc(s){ return s.replace(/</g,'&lt;'); }
out.innerHTML = LINES.map(function(l){ return '<span>' + esc(l) + '</span>'; }).join('\\n');
out.innerHTML = '<b>static</b>';
</script>
`,
    'public/bad.html': `<script>
var out = document.getElementById('o');
out.innerHTML = location.hash;
out.innerHTML = '<b>' + data.name + '</b>';
</script>
`,
  });
  const result = await run(root);
  const xss = byId(result, 'VG012');
  assert.deepEqual([...new Set(xss.map((f) => f.file))], ['public/bad.html']);
  assert.equal(xss.length, 2);
});

// --- RLS wording and severity ----------------------------------------------

const TABLES = `create table public.events ( id bigserial primary key, note text );
alter table public.events enable row level security;
create table public.posts ( id uuid primary key, user_id uuid not null, body text );
alter table public.posts enable row level security;
`;

test('CTS012: an always-true INSERT policy is not described as overwriting rows', async () => {
  const root = project({
    'package.json': '{"name":"r","dependencies":{"@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/1_init.sql':
      TABLES +
      "create policy events_insert on public.events for insert to authenticated with check (true);\n" +
      "create policy posts_update on public.posts for update to authenticated using (true);\n" +
      "create policy posts_insert on public.posts for insert to authenticated with check (true);\n",
  });
  const result = await run(root);
  const byPolicy = new Map(byId(result, 'CTS012').map((f) => [f.meta.policy, f]));

  // Append-only, no ownership column: a real gap, but it cannot overwrite or
  // delete anything — PostgreSQL needs an UPDATE or DELETE policy for that.
  const events = byPolicy.get('events_insert');
  assert.ok(events, [...byPolicy.keys()].join(','));
  assert.equal(events.severity, 'high');
  assert.match(events.title, /unrestricted inserts/);
  assert.match(events.detail, /Nothing here can overwrite or delete an existing row/);
  assert.doesNotMatch(events.detail, /can overwrite or delete every other/);

  // An ownership column makes the same policy forgeable: critical again.
  const posts = byPolicy.get('posts_insert');
  assert.equal(posts.severity, 'critical');
  assert.match(posts.detail, /user_id/);

  // UPDATE is unchanged: still critical, still the destructive wording.
  const update = byPolicy.get('posts_update');
  assert.equal(update.severity, 'critical');
  assert.match(update.detail, /overwrite or delete/);
});

test('CTS050: two policies with the same predicate are not a widening', async () => {
  const same = `create table public.docs ( id uuid primary key, owner_id uuid not null );
alter table public.docs enable row level security;
create policy docs_select on public.docs for select to authenticated using ( owner_id = auth.uid() );
create policy docs_all on public.docs for all to authenticated
  using ( owner_id = auth.uid() ) with check ( owner_id = auth.uid() );
`;
  const widened = `create table public.notes ( id uuid primary key, owner_id uuid not null );
alter table public.notes enable row level security;
create policy notes_own on public.notes for select to authenticated using ( owner_id = auth.uid() );
create policy notes_shared on public.notes for select to authenticated using ( is_public );
`;
  const root = project({
    'package.json': '{"name":"r","dependencies":{"@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/1_same.sql': same,
  });
  assert.deepEqual(byId(await run(root), 'CTS050'), []);

  const other = project({
    'package.json': '{"name":"r","dependencies":{"@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/1_widened.sql': widened,
  });
  // A genuinely broader policy beside a scoped one still is one.
  assert.equal(byId(await run(other), 'CTS050').length, 1);
});

// --- suppression comments, per language -------------------------------------

test('a suppression directive is only honoured in that language’s comment syntax', () => {
  // Every scanner used to build this with the source alone, so the fallback ran
  // everywhere: `//`, `#` and `--` all opened a comment whatever the file was.
  const shell = 'curl https://example.com/x cts-ignore\n';
  assert.equal(new Suppressions(shell, 'deploy.sh').suppressed(1, 'CTS030'), false);
  assert.equal(new Suppressions(shell).suppressed(1, 'CTS030'), true, 'the old fallback');

  // And a `#` is not a comment in TypeScript.
  const ts = 'const key = load() # cts-ignore\n';
  assert.equal(new Suppressions(ts, 'a.ts').suppressed(1, 'CTS030'), false);

  // What must keep working: the real comment syntax of each language, including
  // JSON-with-comments, which commentStyleFor did not know about.
  assert.equal(new Suppressions('// cts-ignore\nkey\n', 'a.ts').suppressed(2, 'CTS030'), true);
  assert.equal(
    new Suppressions('{\n  // cleartoship-ignore CTS030\n  "key": "x"\n}\n', 'tsconfig.json').suppressed(3, 'CTS030'),
    true,
  );
  assert.equal(new Suppressions('# cts-ignore\nKEY=x\n', 'fly.toml').suppressed(2, 'CTS030'), true);
  assert.equal(new Suppressions('-- cts-ignore\nselect 1;\n', 'a.sql').suppressed(2, 'CTS030'), true);
  assert.equal(new Suppressions('<!-- cts-ignore -->\n', 'README.md').suppressed(1, 'CTS030'), true);
});

// --- claims about the ruleset, asserted rather than remembered --------------

test('the README\u2019s rule counts are the counts in the code', async () => {
  const readme = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'README.md'), 'utf8');
  const claim = (re, what) => {
    const m = re.exec(readme);
    assert.ok(m, `README no longer states ${what} in a form this test can read`);
    return Number(m[1]);
  };
  // "435 additional rules vendored" was the active count written as the
  // vendored one, and the same README's own per-category table counts all 468.
  assert.equal(claim(/\*\*Community ruleset\*\* \u2014 (\d+) rules vendored from/, 'the vendored total'), RULE_COUNTS.vendored);
  assert.equal(claim(/of which \*\*(\d+)\*\* run/, 'how many run'), RULE_COUNTS.active);
  assert.equal(claim(/the (\d+) vendored GuardVibe rules that remain/, 'how many remain'), RULE_COUNTS.active);
  assert.equal(claim(/(\d+) upstream rules are \*\*superseded\*\*/, 'the superseded count'), RULE_COUNTS.superseded);
  assert.equal(claim(/(\d+) are \*\*withheld\*\*/, 'the withheld count'), RULE_COUNTS.withheld);
  assert.equal(claim(/(\d+) carry a\n\*\*match guard\*\*/, 'the match-guard count'), RULE_COUNTS.guarded);
  assert.equal(claim(/(\d+) name-heuristic rules are\n\*\*manifest-only\*\*/, 'the manifest-only count'), RULE_COUNTS.manifestOnly);
});

// --- the registry answer that looks healthy ---------------------------------

test('a name whose versions were all unpublished is not a package that exists', async () => {
  // npm answers **200** for a fully unpublished name, with an empty `versions`
  // map and a `time.unpublished` record. Reading the status instead of the
  // content made it a package that exists, and `time.created` then made it a
  // recent one — so the scanner reported `cleartoship` (unpublished 2026-09-03)
  // as a "newly published, barely used dependency" of this repository, off the
  // README sentence that warns people not to install that very name.
  const packument = {
    _id: 'ghost-pkg',
    name: 'ghost-pkg',
    time: {
      created: new Date(Date.now() - 42 * 86400_000).toISOString(),
      unpublished: { time: new Date().toISOString(), versions: ['1.0.0'] },
    },
  };
  const real = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url) => {
    seen.push(String(url));
    if (String(url).includes('api.npmjs.org/downloads')) {
      return new Response(JSON.stringify({ downloads: 0 }), { status: 200 });
    }
    return new Response(JSON.stringify(packument), { status: 200 });
  };
  try {
    const registry = new Registry(mkdtempSync(join(tmpdir(), 'cts-reg-')));
    const facts = await registry.lookup('ghost-pkg', 'npm');
    assert.equal(facts.exists, false, 'an empty version list is not a package');
    assert.equal(facts.unpublished, true, 'and it is the takeover shape CTS027 reports');
  } finally {
    globalThis.fetch = real;
  }
  assert.ok(seen.some((u) => u.includes('registry.npmjs.org')));
});
