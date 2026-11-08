// Regression tests for the 2026-10-28 audit. This pass went where the last one
// said it had not looked: the ~180 untriaged `high` findings on the corpus, and
// the report renderers. The theme that came back is a guarded rule standing
// beside an unguarded copy of itself, and rules whose name describes a problem
// their pattern cannot see — VG120 matching any `fetch(name)` under the title
// "SSRF via User-Controlled URL", VG1021 reading `case "enum":` as a tool
// schema, VG964 asking a route handler to import `server-only`, VG1006 calling
// a head-only count "Exposes All Columns". Every test here failed before its
// fix except the marked keep-cases, which pin the true positives each fix had
// to preserve.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { scan } from '../dist/index.js';
import { renderMarkdown, renderFixPrompt, renderSarif } from '../dist/report.js';

/** A throwaway project from a { path: contents } map. */
function project(files) {
  const root = mkdtempSync(join(tmpdir(), 'cts-oct28-'));
  for (const [path, contents] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), contents);
  }
  return root;
}

const byId = (result, id) => result.findings.filter((f) => f.id === id);
const run = (root, options = {}) => scan({ root, offline: true, ...options });

const PKG = JSON.stringify({ name: 'app', dependencies: { next: '16.2.2', react: '19.2.4' } });

// --- a guarded rule beside an unguarded copy of itself ----------------------

test('a <style> element’s CSS text is not an HTML sink under VG408 either', async () => {
  // The 2026-10-13 audit taught VG012 that `<style dangerouslySetInnerHTML={{
  // __html: css }} />` is a stylesheet, not XSS. VG408 matched the same
  // construct with no guard at all, so all eight of app C's were reported
  // again under the other id — the guard did nothing while its twin ran.
  const root = project({
    'package.json': PKG,
    'app/themed.tsx': [
      'export function Themed({ css }: { css: string }) {',
      '  return <style dangerouslySetInnerHTML={{ __html: css }} />;',
      '}',
    ].join('\n'),
  });
  const result = await run(root);
  assert.equal(byId(result, 'VG408').length, 0);
  assert.equal(byId(result, 'VG012').length, 0);
});

test('VG408 never reports on its own: every match of it is a VG012 match', async () => {
  const root = project({
    'package.json': PKG,
    // A bare identifier is the case VG012 deliberately keeps reporting, because
    // proving `userHtml` holds a constant is dataflow. It must be reported once,
    // by VG012, not twice.
    'app/post.tsx': [
      'export function Post({ userHtml }: { userHtml: string }) {',
      '  return <div dangerouslySetInnerHTML={{ __html: userHtml }} />;',
      '}',
    ].join('\n'),
  });
  const result = await run(root);
  assert.equal(byId(result, 'VG408').length, 0, 'VG408 is superseded');
  assert.equal(byId(result, 'VG012').length, 1, 'keep-case: VG012 still reports the bare identifier');
});

// --- "SSRF via User-Controlled URL" on URLs no caller can move --------------

test('a Workers fetch handler is a definition, not an outbound request', async () => {
  // `export default { fetch(request, env, ctx) { … } }` is the Cloudflare
  // Workers entry point. VG120 matched the parameter list and reported high
  // SSRF on it, and again on the delegation one line below — the same
  // declaration-read-as-a-call mistake VG105 was fixed for in 0.13.10.
  const root = project({
    'package.json': PKG,
    'worker-entry.js': [
      "import nextWorker from './.open-next/worker.js';",
      'const worker = {',
      '  fetch(request, env, ctx) {',
      '    return nextWorker.fetch(request, env, ctx);',
      '  },',
      '};',
      'export default worker;',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG120').length, 0);
});

test('a URL built on a literal origin is not a URL an attacker can point anywhere', async () => {
  // The pattern already refuses `fetch("https://…")` written inline; one
  // `const` in between defeated it, which is how it is normally written.
  const root = project({
    'package.json': PKG,
    'lib/cron.ts': [
      'export async function runSchedules(env: { CRON_SECRET: string }) {',
      '  const endpoint = "https://cron.example.com/api/run";',
      '  const res = await fetch(endpoint, { method: "POST", headers: { "X-Cron-Secret": env.CRON_SECRET } });',
      '  return res.json();',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG120').length, 0);
});

test('a constant base reached through a ternary of two literals still fixes the origin', async () => {
  // `const base = sandbox ? A : B` then `` `${base}/v3/…` `` — three lines of
  // one idiom, and six of app C's QuickBooks callers. The first version of
  // this guard missed it twice: once for running out of hops, once because
  // both branches of the ternary contain the `:` of their own scheme.
  const root = project({
    'package.json': PKG,
    'lib/qb.ts': [
      'const SANDBOX = "https://sandbox-quickbooks.api.intuit.com";',
      'const PRODUCTION = "https://quickbooks.api.intuit.com";',
      'export async function qbQuery(realmId: string, query: string, useSandbox = true) {',
      '  const base = useSandbox ? SANDBOX : PRODUCTION;',
      '  const url = `${base}/v3/company/${realmId}/query?query=${encodeURIComponent(query)}`;',
      '  const res = await fetch(url, { headers: { Accept: "application/json" } });',
      '  return res.json();',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG120').length, 0);
});

test('a literal hostname interpolated under a literal scheme fixes the origin', async () => {
  const root = project({
    'package.json': PKG,
    'scripts/sync.mjs': [
      'const SHOP = "example-store.myshopify.com";',
      'const API = `https://${SHOP}/admin/api/2026-04`;',
      'export async function pull(token) {',
      '  const url = `${API}/orders.json`;',
      '  const res = await fetch(url, { headers: { "X-Shopify-Access-Token": token } });',
      '  return res.json();',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG120').length, 0);
});

test('keep-case: a host that comes from a database row is still reported', async () => {
  // This is the line the guard draws, and the asymmetry that proves it works:
  // the same file shape as the QuickBooks callers above, except the host is a
  // value read out of a row. `https://${shop}/…` is not a fixed origin — the
  // host is the whole of SSRF.
  const root = project({
    'package.json': PKG,
    'lib/shopify.ts': [
      'export async function run(connection: { platform_account_id: string; access_token: string }) {',
      '  const shop = connection.platform_account_id;',
      '  const url = `https://${shop}/admin/api/2024-01/graphql.json`;',
      '  const res = await fetch(url, { method: "POST", headers: { "X-Shopify-Access-Token": connection.access_token } });',
      '  return res.json();',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG120').length, 1);
});

test('keep-case: a URL that arrives as a parameter is still reported', async () => {
  const root = project({
    'package.json': PKG,
    'lib/download.ts': [
      'export async function downloadAndParse(url: string): Promise<unknown> {',
      '  const response = await fetch(url);',
      '  return response.json();',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG120').length, 1);
});

test('a URL through an SSRF validator is the fix, not the finding', async () => {
  // app E's `fetchNoOpenRedirect` does exactly what this rule's own `fix`
  // text asks for — validate the host, `redirect: 'manual'`, bound the chain,
  // re-check every hop — and was reported high for it.
  const root = project({
    'package.json': PKG,
    'lib/image.ts': [
      'import { assertFetchableImageUrl } from "./guard";',
      'export async function fetchNoOpenRedirect(startUrl: string) {',
      '  let url = assertFetchableImageUrl(startUrl).toString();',
      '  const res = await fetch(url, { redirect: "manual" });',
      '  return res;',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG120').length, 0);
});

test('a function that returns when there is no window fetches only in a browser', async () => {
  const root = project({
    'package.json': PKG,
    'utils/docExport.js': [
      'export async function inlineImages(html) {',
      "  if (typeof window === 'undefined') return html;",
      '  const srcs = [...String(html).matchAll(/<img[^>]+src="([^"]+)"/g)].map((m) => m[1]);',
      '  return Promise.all(srcs.map(async (url) => {',
      '    const res = await fetch(url);',
      '    return res.blob();',
      '  }));',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG120').length, 0);
});

// --- a switch label read as a tool schema -----------------------------------

test('`case "enum":` is a switch label, not an AI tool schema built from user input', async () => {
  // Seven findings across app C's query builder and type-colour table, all
  // of this shape: a switch over a JSON-Schema type name picking an icon.
  const root = project({
    'package.json': PKG,
    'lib/type-colors.ts': [
      'export function icon(kind: string): string {',
      '  switch (kind) {',
      '    case "enum": return "\\u2261";',
      '    case "string": return "S";',
      '    default: return "?";',
      '  }',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG1021').length, 0);
});

test('keep-case: a schema enum really built from a runtime variable is still reported', async () => {
  const root = project({
    'package.json': PKG,
    'lib/tool.ts': [
      'export function makeTool(allowedActions: string[]) {',
      '  return { parameters: { type: "object", properties: { action: { "enum": allowedActions } } } };',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG1021').length, 1);
});

// --- `server-only` asked of a file that cannot reach the client -------------

test('a route handler cannot be imported by a client component, so server-only guards nothing', async () => {
  const root = project({
    'package.json': PKG,
    'app/api/cron/run-schedules/route.ts': [
      'import { NextRequest, NextResponse } from "next/server";',
      'import { createAdminClient } from "@/lib/supabase/admin";',
      'export async function POST(req: NextRequest) {',
      '  if (req.headers.get("x-cron-secret") !== process.env.CRON_SECRET) {',
      '    return NextResponse.json({ error: "no" }, { status: 401 });',
      '  }',
      '  const db = createAdminClient();',
      '  const { data } = await db.from("schedules").select("id");',
      '  return NextResponse.json({ data });',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG964').length, 0);
});

test('keep-case: a shared lib that reads a secret and imports from next is still reported', async () => {
  const root = project({
    'package.json': PKG,
    'src/lib/session.ts': [
      'import { cookies } from "next/headers";',
      'export async function sign(payload: object) {',
      '  const secret = process.env.SESSION_SECRET;',
      '  const store = await cookies();',
      '  const db = await supabase.from("sessions").select("id");',
      '  return { secret, store, db };',
      '}',
    ].join('\n'),
  });
  assert.ok(byId(await run(root), 'VG964').length >= 1);
});

// --- a count that returns no rows called "Exposes All Columns" --------------

test('select(‘*’) with head: true returns a count, not columns', async () => {
  // Supabase's own documented way to count rows: `head: true` sends the request
  // with no row payload at all. The rule's pattern stops at the `'*'` and never
  // reads the second argument.
  const root = project({
    'package.json': JSON.stringify({ name: 'app', dependencies: { '@supabase/supabase-js': '2.45.0' } }),
    'functions/report-error/index.ts': [
      'export async function throttled(admin: any, ip: string) {',
      "  const { count } = await admin.from('client_errors')",
      "    .select('*', { count: 'exact', head: true })",
      "    .eq('ip_address', ip);",
      '  return (count ?? 0) >= 5;',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG1006').length, 0);
});

test('keep-case: a select(‘*’) that really returns rows is still reported', async () => {
  const root = project({
    'package.json': JSON.stringify({ name: 'app', dependencies: { '@supabase/supabase-js': '2.45.0' } }),
    'functions/notify/index.ts': [
      'export async function post(supabase: any, post_id: string) {',
      "  const { data } = await supabase.from('forum_posts').select('*').eq('id', post_id).single();",
      '  return data;',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG1006').length, 1);
});

test('a count query that also returns its rows is still reported', async () => {
  // Without `head: true` the rows come back alongside the count, so the rule is
  // right about that one — the guard has to key on `head`, not on `count`.
  const root = project({
    'package.json': JSON.stringify({ name: 'app', dependencies: { '@supabase/supabase-js': '2.45.0' } }),
    'functions/list/index.ts': [
      'export async function page(admin: any) {',
      "  const { data, count } = await admin.from('rows').select('*', { count: 'exact' });",
      '  return { data, count };',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG1006').length, 1);
});

// --- the renderers: a finding the report was given and did not show ---------

const scanWith = (findings, counts, extra = {}) => ({
  root: '/repo',
  framework: 'Next.js',
  fileCount: 3,
  durationMs: 1000,
  gitIgnoredCount: 0,
  escapingSymlinkCount: 0,
  oversizeCount: 0,
  generatedCount: 0,
  skippedDirs: [],
  unreadable: [],
  warnings: [],
  incomplete: [],
  checks: [],
  counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, ...counts },
  findings,
  ...extra,
});

test('an info finding reaches the PR comment and the fix prompt', async () => {
  // `--min-severity info` asks for them, the terminal prints them, the JSON
  // carries them — and the Markdown partitioned findings into critical|high and
  // medium|low, so an info finding appeared in neither table while the
  // lower-severity count said one fewer than it had.
  const scan = scanWith(
    [
      { id: 'CTS031', severity: 'medium', title: 'Stripe test key', detail: 'd', fix: 'f', file: 'a.ts', line: 1 },
      { id: 'CTS030', severity: 'info', title: 'Supabase anon key', detail: 'public by design', fix: 'nothing', file: 'b.ts', line: 2 },
    ],
    { medium: 1, info: 1 },
  );
  const md = renderMarkdown(scan);
  assert.match(md, /Supabase anon key/, 'the info finding is in the comment');
  assert.match(md, /2 lower-severity findings/, 'and is counted');
  assert.match(renderFixPrompt(scan), /Supabase anon key/, 'and in the fix prompt');
});

test('SARIF says the run did not complete when checks could not finish', async () => {
  // An incomplete scan uploaded to code scanning as an ordinary successful
  // analysis: the alerts page showed what was found and nothing about what was
  // never read. With `allow-incomplete` or `fail-on: none` the job is green
  // too, so this was the only surface left that could have said so.
  const scan = scanWith([], {}, { incomplete: ['OSV did not answer; dependency CVEs were not checked.'] });
  const sarif = JSON.parse(renderSarif(scan, '0.13.13'));
  const invocation = sarif.runs[0].invocations?.[0];
  assert.ok(invocation, 'the run carries an invocation');
  assert.equal(invocation.executionSuccessful, false);
  assert.match(JSON.stringify(invocation), /OSV did not answer/);
});

test('SARIF on a complete run says so', async () => {
  const sarif = JSON.parse(renderSarif(scanWith([], {}), '0.13.13'));
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true);
});

test('a report too large for a GitHub comment is trimmed, not refused', async () => {
  // 732 findings off a large lockfile is a size the corpus actually reached.
  // At ~125 characters a row the body passed GitHub's 65,536-character limit,
  // the POST came back 422, and the Action's `|| echo "::warning::…"` reported
  // it as a missing `pull-requests: write` permission.
  const findings = Array.from({ length: 732 }, (_, i) => ({
    id: 'CTS024',
    severity: i === 0 ? 'critical' : 'high',
    title: 'Vulnerable dependency version in lockfile',
    detail: 'd',
    fix: 'f',
    file: `node_modules/pkg-${i}/package.json`,
    line: i + 1,
  }));
  const md = renderMarkdown(scanWith(findings, { critical: 1, high: 731 }));
  assert.ok(md.length <= 65536, `body is ${md.length} characters`);
  assert.match(md, /more findings not shown here/);
  assert.match(md, /ClearToShip — hold before shipping/, 'the verdict survives the trim');
  // The most severe findings are the ones kept.
  assert.match(md, /pkg\\?-0\/package\.json/);
});

test('a report that fits is not trimmed', async () => {
  const findings = Array.from({ length: 20 }, (_, i) => ({
    id: 'CTS024', severity: 'medium', title: 't', detail: 'd', fix: 'f', file: `a-${i}.ts`, line: 1,
  }));
  const md = renderMarkdown(scanWith(findings, { medium: 20 }));
  assert.doesNotMatch(md, /not shown here/);
  assert.match(md, /a\\?-19\.ts/);
});

test('keep-case: an options object with two keys is not a three-argument fetch', async () => {
  // The first version of the Workers-handler check counted arguments with
  // `[^(),]{1,40},` twice, and a character class does not stop at an object
  // literal — so `fetch(url, { ...opts, signal })` read as three arguments and
  // cleared a `url` that is a bare parameter. The commonest fetch shape there
  // is would have silently stopped being reported.
  const root = project({
    'package.json': PKG,
    'src/worker.js': [
      'async function fetchTimeout(url, opts = {}, ms = 8000) {',
      '  const controller = new AbortController();',
      '  const id = setTimeout(() => controller.abort(), ms);',
      '  try {',
      '    const res = await fetch(url, { ...opts, signal: controller.signal });',
      '    return res;',
      '  } finally {',
      '    clearTimeout(id);',
      '  }',
      '}',
      'export default { fetchTimeout };',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG120').length, 1);
});

test('keep-case: a later local of the same name does not vouch for an earlier fetch', async () => {
  // The forward lookup exists for a module-level const declared below its use.
  // Unanchored, it also found a `const url = …` inside a different function
  // further down the file and credited this one's bare parameter with it.
  const root = project({
    'package.json': PKG,
    'src/api.js': [
      'export async function proxy(target) {',
      '  const res = await fetch(target);',
      '  return res.text();',
      '}',
      'export function route(request) {',
      '  const target = "https://api.example.com/v1";',
      '  return target + new URL(request.url).pathname;',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG120').length, 1);
});

test('keep-case: an `if (…) {` after a call does not make the call a definition', async () => {
  // The Workers-handler check asked whether a `) {` followed within 120
  // characters, which an ordinary `if (!response.ok) {` on the next line
  // satisfies. An app B edge function's `fetch(imageUrl)` — on a value
  // straight out of `searchParams` — was cleared by it.
  const root = project({
    'package.json': PKG,
    'functions/thumbnail/index.ts': [
      'export async function handler(req: Request) {',
      '  const url = new URL(req.url);',
      '  const imageUrl = url.searchParams.get("url")!;',
      '  const response = await fetch(imageUrl);',
      '  if (!response.ok) {',
      '    return new Response("bad", { status: 502 });',
      '  }',
      '  return new Response(await response.arrayBuffer());',
      '}',
    ].join('\n'),
  });
  assert.equal(byId(await run(root), 'VG120').length, 1);
});
