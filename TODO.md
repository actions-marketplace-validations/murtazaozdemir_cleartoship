# ClearToShip — roadmap

Public backlog. Working notes, positioning and anything about other projects
live in `NOTES.private.md`, which is gitignored and stays on my machine.

_Current release: **v0.13.13** — linear-time matching for the vendored rules, one
RLS schema per project, CTS014 per command, auth wrappers judged by behaviour.
**v0.13.12** fixed a sticky-PR-comment regression in
0.13.11's Action (a new comment on every run). **v0.13.11** shipped the
2026-09-23 audit: incomplete scans exit 3, tracked files can no longer be hidden
by `.gitignore`, and it is the first release with build-provenance attestations,
which the Action verifies before it runs a downloaded bundle.
[The Action is on the GitHub Marketplace](https://github.com/marketplace/actions/cleartoship)
(since 2026-09-22), under Security / Code Scanning Ready. Every check is in the one free download,
including the RLS, Server Actions and LLM/agent suites, as of v0.13.9.
(They were split into a private package for v0.13.6–0.13.8, which left them in no
downloadable build; v0.13.8 also closed a hole where a scan would run a package of
that name found beside it.) v0.13.6's own release run is red — it ran the old
workflow, which still tried npm, and a re-run uses the workflow as it was at the
tag. The release itself is fine.
Install from
[cleartoship.app](https://cleartoship.app/cleartoship.mjs)
(`curl -fsSL https://cleartoship.app/cleartoship.mjs -o cleartoship.mjs && node cleartoship.mjs`);
the same file is on [the GitHub release](https://github.com/murtazaozdemir/cleartoship/releases/latest).
**Not distributed through npm, by decision (2026-09-21):** the maintainer can no
longer use npmjs.com. The package was unpublished on 2026-09-03 and the name is
unclaimed, so anything on the registry under it is **not from this project**:
the docs say so, and the Action and CI no longer run or recommend it.
`release.yml` has no npm publish steps any more (removed 2026-09-21); the
`NPM_TOKEN` secret it used is dead and can be deleted from the repository.
`release.yml` verifies that the release carries a bundle that runs and reports
its version, and `deploy-site.yml` serves that build from the domain and compares
its hash with the release asset after every deploy._
_v0.13.0 and earlier published **unsigned** — npm's registry refuses provenance
from a private source repo. The repository is public now, and `release.yml`
reads its visibility, so 0.13.1 is the first release signed with provenance._

## Where this stands

Twenty-one releases, 0.8.0 → 0.13.10. The calibration work is the point of the project
so far: across a five-repo corpus the tool went from 2,290 findings to a few
hundred, and from 157 criticals to a handful — **every removal verified by
reading the code it was about**, never by adjusting a threshold. Reports that
name a real problem are worth more than reports that cover a table.

0.13.0 added the three agent rules (CTS083/084/085) and made the LLM/agent
surface the headline rather than the fifth section. 0.13.1 was the first signed
release. 0.13.2 raised the Node floor onto Babel 8.

**0.13.3 is the first release fixed by code I did not write.** Scanning
vercel/ai-chatbot, modelcontextprotocol/servers and assistant-ui turned up two
real defects in one afternoon that six repositories of my own never showed: paths
were reported relative to the shell's cwd rather than the scanned repo, and
CTS083 matched `clients.delete(id)` on an in-memory `Set` because the root
pattern accepted a prefix instead of a whole segment. Both were exactly the kind
of thing dogfooding structurally cannot find — my repos all sit beside this one,
and I would never have written `clients` for a Set.

**0.13.5 is a full self-audit, and the self-scan is why most of it was found.**
Ten defects, every one reproduced before it was fixed and covered by a test
after. Three of them fired on other people's correct code — a repository with a
`site/` directory had that whole subtree reported clean without a file being
opened; a library whose README says `npm install <its own name>` before the
first publish got a *critical* hallucinated-dependency finding; and `/.env` or
`.env.local` in a `.gitignore` were both reported as failing to cover the file
sitting next to them, because CTS032 compared the text against five literal
strings instead of asking the matcher this repo already ships. A fourth was
quieter and worse: OSV publishes `severity[].score` as a CVSS *vector*, so
`Number()` returned `NaN` on every GitHub-sourced advisory and a 9.8 and a 5.3
were both reported `high` — the "by CVSS" column was not what happened.

The pattern worth keeping: the CI self-scan read `src` and nothing else, so the
README, the manifests, the shipped Action and the landing page were never
scanned by the tool that scans them for everyone else. Pointing it at all of
them found a credential-shaped literal in a comment written the same afternoon.

**0.13.9 re-ran the calibration on a fresh, seeded sample of 155 public repos**
(the prior corpus was lost when the machine crashed mid-session; nothing
committed was lost, only the scratch data). Hardcoded credentials (CTS030):
of 96 critical PostgreSQL connection-string findings, 63 were a default
password on localhost and 18 were templates — only 5, across 2 repos, were a
real password to a remote host; 222 → 51 findings. CTS001 (missing auth on a
Server Action or route handler that writes) got the same treatment: one
finding read per repo, 60 of 77 wrong. Fixed at the cause — a helper that
provably does nothing outside the process (new `src/scanners/effects.ts`),
signature and credential-header checks recognised more widely, an
authorization helper credited when its result gates the write before it
happens. **Verified by reading what the fix removed, not just what it kept**:
of 60 sampled removals, 2 were real bugs the first version of the fix had
hidden along with the noise (a caller-set `x-actor-role` header read as
authorization; an approval flag read from a row the caller's own request body
selected) — both restored, both have regression tests now. 732 → 603
findings on the full corpus, all 17 confirmed real findings still reported.
Also found and fixed in the same pass: the three registry/OSV-dependent
tests had been silently skipping on every run, local and in CI, since at
least 73abec9 — the probe that decides `online` sat below other tests in the
file and starved on the event loop before its own timeout fired.

**0.13.10 is the first release found by dogfooding a sibling project.**
Scanning `aistoreaudit` (live on the Shopify App Store) with the newly
calibrated tool, then verifying its maintainer's fixes actually landed,
turned up two more scanner bugs that the 155-repo corpus never surfaced: a
`cleartoship-ignore` comment that silently didn't apply because a real
statement sat between it and the line it was suppressing, and a regex false
positive in the vendored "JWT algorithm none" rule (VG105) — it matched a
function's own declaration as a call when a helper shared the wrapped
function's name, and separately backtracked across nested parens in a
`jwt.verify` call's secret argument and missed the real options object.
Fixed with a `MATCH_GUARDS` entry rather than touching the vendored file,
verified against both the fixed code and the actual pre-fix vulnerable
version pulled from that repo's own git history. Also listed [the Action on
the GitHub Marketplace](https://github.com/marketplace/actions/cleartoship)
this release — the Developer Agreement acceptance was the last blocker, and
`action.yml`'s description turned out to be 83 characters over the
Marketplace's limit. The first attempted fix broke `action.yml` outright (an
unquoted colon reads as a YAML mapping key); the `Action integration test`
workflow caught it within a minute, before it reached a tag.

**The 2026-09-23 full audit (shipped as 0.13.11) found the
worst failure class this project exists to prevent — "clear" on code it never
read — in eight separate places, in this tool itself.** A committed `.gitignore`
could hide a tracked file (a PR adds `app/backdoor.ts` to `.gitignore` and the
scan is 🟢, exit 0); a `test/fixtures/x/package.json` named `minimist` switched
off the CVE and registry checks for the root's real `minimist@1.2.0`; a 40 KB
`a.b.b.b…` chain overflowed the stack and killed three whole scanners, taking a
real CTS001 in another file with it, and still exited 0; `.ts` files were
parsed with JSX on, so a `<string>x` cast made the file unparsed and the run
clear; unreadable files, files over the 2 MB cap and files the community ruleset
thought too big (400 KB–2 MB) were all silently skipped. Now every one of those
is `incomplete`, and **an incomplete run exits 3** unless `--allow-incomplete`
is passed; the Action fails on it by default. `.git/index` is parsed (v2–v4, no
child process) so a tracked file is always scanned. Detection gaps found in the
same pass and fixed: Pages Router API routes, `export { fn }` / `export default
fn` / `cache(async …)` / NextAuth `export { handler as POST }` were never
analysed; an auth call counted wherever it sat — after the write, in a
`NODE_ENV === 'test'` branch, in a closure never called, or as `if (session)
return`; Supabase's own default policy name "Enable read access **for all**
users" was parsed as `FOR ALL` (critical false positive) and a name containing
" to " swallowed the role list (missed critical); FORCE was read as ENABLE;
restrictive policies were judged as grants. The untrusted-input side: CTS031 and
vendored rules printed full secrets beside CTS030's redacted copy (now one
redaction pass over every finding); filenames and install scripts could inject
links, images and @-mentions into the PR comment and ANSI into the terminal;
lockfiles and `.gitignore` were read through symlinks (a `.gitignore ->
/dev/zero` ate 2 GB in two seconds); VG678 went 8 KB → 8.5 s (bounded override,
now 8 ms, same match positions on ~1.5M checked); a hostile `.gitignore` glob
spun past two minutes (linear matcher, 0 differences from the old one over 200k
fuzzed cases). Supply chain: releases now carry build-provenance attestations
from a publish job that never runs `npm ci`, the Action verifies the bundle's
attestation and version before running it, every action is SHA-pinned, and the
Cloudflare token no longer sits in the env of `npm ci`. And the landing page had
said `@v0.8.0` since 0.8.0 — the version-pin check only read the README; it now
reads `site/public/*.html` too. **Verification:** 101 → 205 tests, every new one
failing before its fix; each audit PoC re-run against the merged build; the
Server Actions changes run before/after on ten real Next.js repos here, which
caught and fixed two CTS004 false positives the first version introduced in
aistoreaudit. Self-scan down to five lows; the self-scan also found the last
bug of the pass — the comment lexer did not know regex literals, so a backtick
in `/`\s*,/` opened a phantom template string in `community.ts` and VG105
fired on a sentence a hundred lines later.

**Shipping 0.13.11 was its own lesson in the rule the release skill opens
with.** Every run was green, and the release still had nothing on it as far as
two consumers could tell: for about two minutes after the draft was published,
GitHub served the release's embedded asset list empty while the assets endpoint
and the download URLs already had all three files. The site redeploy that
release.yml dispatches landed inside that window, failed with "no assets to
download", and left cleartoship.app on 0.13.10; the release job's own verify
step read the same list and passed only by timing. Both now read the assets
endpoint or the download URL, with retries (90a8d96), and a redeploy was
checked by hash against the attested asset, not by exit code. Then the Action
integration test on an open Dependabot PR found a second 0.13.11 bug: the sticky
PR comment's author lookup ran `me=$(gh api user --jq .login || true)`, and on
an HTTP error `gh api` prints the error body to stdout, `--jq` or not — so the
default token's 403 left `me` holding a JSON blob, no comment matched, and every
run posted a new one. 0.13.12 tests the exit status instead. The test that
caught it asserts exactly one comment, which is the assertion that could fail.

**0.13.13 closed the limits the audit had left open on purpose, and the
biggest one turned out to be six times larger than the audit thought.** The
audit counted ~35 super-linear vendored patterns; fuzzing all 435 active rules
on their own trigger words found 209 over 50 ms at 400 KB and 125 over 8 s —
`eval.*\(` alone spent 50 s in one uninterruptible `exec`, and a 396 KB file of
`eval` repeated kept 0.13.12 busy for more than 15 minutes. Rewriting 200
patterns by hand was not credible, so the vendored patterns V8 backtracks on
(382 of 435) now run on a memoizing matcher that takes V8's paths in V8's order
and remembers every (state, position) that failed: same matches, linear time.
Worst rule now 126 ms at 400 KB, all growing linearly; 0 differences from V8
over 27,391 matches in 129 MB of real code. Pointing the same matcher at the
gitleaks rules took a 396 KB one-identifier file from 10.8 s to 133 ms (two
patterns nest `[\w.-]{0,50}?` inside itself) — and running the existing suite
over it found a bug in the matcher before it shipped: it cached where the next
required text sat and reused that cache when the same text was searched again
from the start, so the **second of two files with identical content got no
community or gitleaks findings at all**. Proven by a test that fails without
the fix. The other limits: the RLS model is now one schema per project (a
whole-repo scan had mixed this repo's two fixtures, inventing a CTS050 on one
and dropping a CTS014 on the other), and CTS014 is judged per command, so an
`auth.role() = 'authenticated'` policy OR'd beside an `auth.uid()` one is
reported; Prisma's `migration_lock.toml` now marks non-Postgres migrations,
which removed 11 false CTS010 criticals from BizDataly's SQLite app. Auth
wrappers are judged by what their definition does — iron-session and next-auth
v5 `auth()` attach a session without requiring one, so they no longer count as
auth on their own — and unknown package wrappers still credited by name are
now named in a warning. A guest-only action (`if (session) redirect(...)`) is
low only while everything it does is what a sign-up does; the two bugs a name
list once hid, `register` hardcoding an Admin role and `leads` running paid
enrichment, stay critical and are pinned by tests. **Verified:** 205 → 238
tests; before/after on 11 real repos differs only by BizDataly's 11 removed
false criticals, with scan times unchanged.

**The 2026-10-13 full audit: eleven defects, and the worst class was again a
file or a rule that was never read at all.** Four of them were silent coverage holes,
every one reachable by naming a file. `looksGenerated` skips machine-generated
code on purpose — a Prisma client ships its own credentials and its own
`queryRawUnsafe` — and it skipped it *silently*: `app/actions/admin.gen.ts` and
`src/generated/client/admin.ts`, byte-identical to an `app/actions/admin.ts`
reported critical beside them, were left out of a 🟢 report that named neither.
There is a `Generated files skipped (n)` line now that names them, passing like
the skipped build directories rather than incomplete, since making it
incomplete would fail every Prisma project's CI. **HTML was not read at all**:
`.html` was not in `SCAN_EXTS`, so a `public/index.html` with a Supabase
service-role JWT and an `sk_live_` key in an inline `<script>` produced nothing
and said nothing — and this project's own self-scan has listed `site` since
0.13.5 while opening none of its four landing pages. **Five vendored rules
could never match any file**: VG517/518/520 are registered for `toml` and
VG750/753 for `firestore`, and `languagesFor` answered neither, so `.toml` files
were read by the walk and then skipped by the community scanner for having no
language, and no `.rules` file was read at all — all five counted as active in
the rule count the report prints, two of them critical. A test now asserts that
no vendored rule's language set is unreachable, and `firestore.rules` /
`storage.rules` make a repository a Firebase one, because the two rules that
read them are otherwise skipped as "not a Firebase project".

**Then four rules reporting on correct code, two of them critical.** A route
that calls `auth()`, returns 401, reads the caller's own `is_admin`, returns 403
and only then promotes somebody — the shape VG1008's own `fixCode` asks for —
got **two criticals**: VG1008, whose name is "Admin Role Elevation Without
Authorization Check" and whose pattern contains no notion of one, and VG154,
because an access-control gate has the same read-check-write shape as a credits
race. CTS001 read the same function and correctly said nothing, so the report
contradicted itself and would have failed the user's build at the default
`--fail-on=critical`. Both are guarded now, on VG1025's precedent; upstream's own
benchmark has a test named *"skips when requireAdmin guard is present"* that the
rule failed, and it passes. VG012 ("XSS via innerHTML") fired on 17 of 23 real
sites across eleven repositories: ten were `<style dangerouslySetInnerHTML={{
__html: css }}>` (shadcn's own `chart.tsx` among them), others a concatenation of
nothing but string literals, a value already through `sanitizeHTML` / `escHtml` /
DOMPurify — including guardvibe's own `fixCode` string demonstrating the fix —
and `showing ? '<path …/>' : '<path …/>'`, whose condition is a name and whose
two values cannot be anything else. A `<style>` element's CSS text, an
all-literal expression and one passed through an escaper are not HTML sinks; a
bare identifier still is, because proving that `userHtml` holds a module
constant is dataflow, and assuming it would drop the finding. VG999 duplicated
CTS081 line for line (13 times in the sweep) and is superseded.

**And two rules that described a different problem than the one they found.**
CTS012 told an always-true INSERT policy that "any signed-up user can overwrite
or delete every other user's rows" — an INSERT policy cannot, PostgreSQL needs
an UPDATE or DELETE policy for that. It is split per command now: critical when
anon-facing, or when an ownership column means the caller can attribute the row
to somebody else, and high for an append-only table with no such column, which
is the common correct shape of exactly that policy. CTS050 reported a widening
between two policies whose predicates are the same text — StorageVisual's
`uploads_own_prefix_insert` and `uploads_user_folder_insert`, identical `with
check`, one superseding the other across migrations — when the OR of a predicate
with itself is that predicate; it was also comparing clauses PostgreSQL does not
apply to the command in hand (a `FOR ALL` policy's `WITH CHECK` under SELECT).
The last two defects were quieter: every scanner built `Suppressions` from the
source alone, though the class takes the file path and its own comment says
scanners pass it — so the per-language path was dead outside its unit tests and
every check ran the fallback, where `//`, `#` and `--` all open a comment
whatever the file is, and `curl https://x cts-ignore` in a shell script
suppressed that line. All six call sites pass the path, and `commentStyleFor`
learned JSON-with-comments, TOML and HCL, which `secrets.ts` had been
compensating for on its own. Finally two README counts were wrong — "435
additional rules vendored" is the count that *runs* (468 are vendored, and the
same README's own per-category table counts all 468) and "21 carry a match
guard" was 22 — so `RULE_COUNTS` is exported and a test asserts the prose
against the code, the same move `check-version-pins.sh` makes for versions.

**The eleventh was the registry answering in a way that looks healthy**, which
is the failure the release skill opens with, in the one place it had not been
looked for. npm serves **HTTP 200** for a fully unpublished name — the packument
carries `time.unpublished` and an empty `versions` map — and `lookupNpm` read
the status rather than the content: `exists: true`, zero versions, and
`time.created` then made it *recent*, so the verdict was CTS021, "newly
published, barely used". The example is this project's own name, unpublished
2026-09-03, which is how the audit found it: scanning `README.md` on its own
reported the sentence that warns people off installing `cleartoship` as a
barely-used dependency of this repository. The truth is CTS027, critical, and it
already existed — an install of such a name fails, and the name is free for
anyone to claim and inherit the installs that still ask for it. The 404-plus-
traffic path had always said so; the 200 path never reached it. (The full
self-scan was never affected: `package.json` declares the name, so it is "defined
by this repository itself, so not looked up" — verified again with a cold cache.)

**Verification:** 238 → 252 tests; 12 of the 14 new ones fail against the
pre-fix build, and the other two are the true positives each fix had to keep
(VG1008 on an ungated `update({ is_admin: true })`, VG154 on the credits
race). Before/after over eleven real repositories (aistoreaudit,
BizDataly, Cherrly, AppVitrine, StorageVisual, datavot, SysXray, guardvibe,
splinter, dep-hallucinator, gitleaks): −17 VG012, −13 VG999, −1 VG1008, −1
CTS050, +6 VG012 on SysXray's HTML dashboards, which are newly read and really
do write `innerHTML=cpuTopHtml` built by concatenating scan data. **Every
removal was verified by reading the code it fired on**, and 2,291 → 2,313 files
scanned with the times unchanged. That sweep ran `--offline`, so the registry
fix is covered by a test that stubs `fetch` and asserts the facts rather than by
the corpus. The self-scan went 64 → 68 files — it reads
the landing pages now — and stayed 🟢 on the same five lows, after the first
HTML-reading run reported a `high` on `site/public/index.html`'s own
`innerHTML`, which was the escaped-constant false positive above. Not released
yet: the work sits on the branch `audit-2026-10-13`, unpushed, and reaches
users only once it is merged and a tag ships it.

**The 2026-10-21 full audit: the same two failure classes, one layer further
out — text the scanner decoded into mojibake, and ecosystems whose conventions
it did not know.** Every read in the tool was `utf8`, so a UTF-16LE `.env` —
what PowerShell's `>` redirect writes — decoded to NUL-riddled garbage no
pattern can match, counted as scanned, and said nothing; and a UTF-8 BOM in
front of `package.json` made `JSON.parse` throw inside collectors that swallow
the error, which switched off the entire dependency surface — hallucination,
typosquat, CVE and install-hook checks — while the report said "no dependencies
declared", passed, complete. Every read now goes through one BOM-aware decoder
(UTF-16LE/BE decoded, UTF-8 BOM stripped), and a manifest that exists but
cannot be parsed makes the run incomplete rather than clean. The other
never-read files: `.svelte`, `.vue` and `.astro` were not in `SCAN_EXTS` at all
— `SKIP_DIRS` has named `.svelte-kit` and `.nuxt` since it existed, so those
users were always expected while every line of their components went unread;
the same `sk_live_` key that was a critical in a `.ts` file produced nothing in
all three. They are read now as the HTML-shaped documents they are (secrets
plus the 7 html rules; the AST scanners skip them like inline `<script>` in
`.html`, the same documented limit). A `.env` whose *parent directory* is
gitignored was never reached although `SCAN_EVEN_IF_IGNORED` exists for exactly
ignored `.env` files — the walk now peeks one level into each directory the
ignore rules skip. And the manifests the tool read but asked nothing about:
`requirements-dev.txt` and `requirements/*.txt` were never collected (only the
exact name was), `[tool.poetry.group.*.dependencies]` and PEP 735
`[dependency-groups]` never matched the pyproject parser, and pnpm v9's quoted
scoped entries (`'@babel/core@7.24.0':`) resolved to nothing, so OSV was asked
about range floors instead of the versions actually installed.

**Rules on correct code, the sweep's second half.** The biggest cluster was
VG010/VG123 ("SQL injection"): three criticals on a QuickBooks integration
whose query strings are QBQL sent URL-encoded to Intuit's HTTP API —
`MAXRESULTS`/`STARTPOSITION` are keywords no SQL driver parses, and that API
has no parameterized form to recommend instead; two more on
`PRAGMA table_info(${quoteIdent(table)})`, where the interpolation *is* the
escaping — credited now when every hole is a SQL quoting call, with HTML
escapers deliberately excluded and bare identifiers still reported, the line
VG012 drew; and two on a rule-definition file's own `description:` strings,
cleared by refusing matches that sit inside a string literal. VG123 duplicated
VG010 on all 24 of its findings — upstream's own tests call VG010 "the concat
rule (which dedup-takes-over)" — and is superseded. VG001/VG062 ("hardcoded
credentials") reported a redaction helper's own replacement string
(`password="[REDACTED]"`), a docs sample whose body is `1234567890abcdef`
twice, a value ending in the ellipsis its author cut it with, and — on a login
route — `DUMMY_PASSWORD_HASH = '$2b$12$…'`, the standard timing-equalization
idiom: a PHC-format hash is a verifier, not a credential anyone can present.
VG060 ("weak *password* hashing") fired on `hashlib.md5(hostname + mac)`
deriving a stable device id; it now requires a password within sight of the
call. VG154 ("check-then-act race") hit four times, none a race worth the
word: count-based rate limiters that reject at the limit and append the row
being counted (overshoot bounded by in-flight requests is the accepted
property of every soft limiter), and pages that count one table and save
another, which is load-then-save. Same table with an update — the credits
race — stays reported, pinned by the 0.13.13 test. And an `sk-ant-…` key was
reported twice on its line, once correctly and once as "Hardcoded OpenAI API
key", because the OpenAI pattern had no exclusion in front of 24 free-form
characters.

**Third: test conventions from outside the JavaScript world.** `_test.go`,
`testdata/`, `test_*.py` and `conftest.py` were in neither of the two
non-production path definitions (secrets.ts's and paths.ts's — which had
drifted identically, the cost of one idea living in two places), so 187 of
gitleaks' own fixture keys were criticals while the identical string in a
`.test.ts` would have been low. Both lists know them now. And the RLS scanner
never placed findings by path at all, though community, logic and agent all
do: supabase/splinter's `test/sql/` lint fixtures — SQL whose *job* is to
contain the defect — carried 18 criticals and a HOLD verdict; they are low
with a stated reason now, and splinter scans CLEAR. `migrations/` remains
deliberately absent from the path classes: migrations are the production
schema.

**Verification:** 252 → 274 tests; 18 of the 20 behavioural tests fail against
the pre-fix build, and the two that pass are the keep-cases each fix had to
preserve (VG010 on a bare interpolated identifier, VG001 on an opaque value
under a credential name). Before/after over the same eleven repositories:
2,159 → 2,067 findings, criticals 401 → 151, **zero findings added**, and
every removal read: −24 VG123 (each a duplicate of a VG010 on the same line,
which stays), −28 VG010, −13 VG001, −10 VG062, −4 VG154, −4 VG060, with 187
CTS030 and 18 splinter RLS findings demoted to low on test paths. splinter
went HOLD → CLEAR, dep-hallucinator HOLD → CONDITIONAL; what stays is real or
honestly undecidable — gitleaks' `cmd/generate` keys are realistic by
construction, and BizDataly's one remaining VG010 interpolates variables whose
QBQL markers the match cannot see, the bare-identifier line again. Self-scan
🟢 on the same five lows, 68 files. Not released: the work sits on
`audit-2026-10-21`, stacked on the unreleased `audit-2026-10-13`; one 0.13.14
release ships both.

**The 2026-10-28 full audit went where the last one said it had not looked —
the ~180 untriaged corpus `high` findings and `report.ts` — and the worst thing
it found was a guarded rule standing beside an unguarded copy of itself.**
VG408 ("Unsafe innerHTML Usage") matches `dangerouslySetInnerHTML={{ __html:`;
VG012 ("XSS via innerHTML") matches `innerHTML` followed by `=` or `:`, and
`dangerouslySetInnerHTML` *ends* in `InnerHTML`. So every VG408 match is a
VG012 match at the same position — 15 of 15 across the seven dogfooding repos,
and by construction, since VG408 requires a `{` after the `=`, which is exactly
what VG012's `(?!['"]<)` lookahead lets through. The 2026-10-13 audit spent a
whole pass teaching VG012 the difference between an HTML sink and a `<style>`
element's CSS text, an all-literal expression and a value already through an
escaper. VG408 carried no guard, so it reported all of it again under a
different id: **eight `<style dangerouslySetInnerHTML={{ __html: css }} />` on
BizDataly and shadcn's own `chart.tsx` on AppVitrine — the exact findings that
audit cleared** — plus three `sanitizeJsonLd(…)` calls and three lines where it
only repeated what VG012 had already said. Fourteen findings, not one of them a
true positive VG012 does not already report. A guard beside an unguarded copy
of itself does nothing, and nothing in the build said so; it is superseded now,
the third instance of that shape after VG999→CTS081 and VG123→VG010.

**Then four rules whose name describes a problem their pattern cannot see** —
the VG1008 gap again, in four more places. VG120 is titled "SSRF via
User-Controlled URL" and its description says "user-controlled input is passed
directly to fetch()", but what it matches is `fetch(` plus any bare identifier.
That made `export default { fetch(request, env, ctx) { … } }` — the Cloudflare
Workers entry point, the most common shape there is — a high-severity SSRF
finding on a *method definition*, and the delegation one line below it too; a
three-argument `fetch` is never WHATWG `fetch`, which takes two. It reported
datavot's `fetchNoOpenRedirect`, which calls `assertFetchableImageUrl`, sets
`redirect: 'manual'`, bounds the chain at three hops and re-validates every
`Location` — code that implements what the rule's own `fix` text asks for. And
it reported a URL built on an origin no caller can move: the pattern already
refuses `fetch("https://…")` written inline, and one `const` in between defeats
it, which is how it is normally written (`const endpoint =
"https://…/api/run"`, or `` `${base}/v3/company/${realmId}/query` `` over a
literal base). The origin is resolved up to four assignments back now, through
ternaries and concatenations, crediting a literal or env-derived scheme+host —
**and the host specifically, not the scheme**, which is the line that matters:
`https://${shop}/admin/api/…` where `shop` is a column from a database row
stays reported, and in `run-saved-query.ts` line 133 clears while line 167, six
lines of near-identical code away, does not. VG1021 ("AI Tool Schema Enum Built
From User Input") fired seven times on `case "enum": return "≡";` — a switch
over a JSON-Schema type name picking an icon, where the `"enum":` is a case
label and the lowercase identifier the pattern wants is the keyword `return`.
VG964 asked six Next.js **route handlers** to `import 'server-only'`; a
`route.ts` cannot be imported by a client component, which is the entire hazard
that rule exists for, so the import would guard nothing — the seventh finding,
a shared `src/lib/session.js` that really is importable from both sides, stays.
VG1006 ("Supabase select('*') Exposes All Columns") reported eight
`select('*', { count: 'exact', head: true })` — Supabase's documented way to
count rows, which returns **no rows at all**; the pattern stops at the `'*'`
and never reads the second argument. The eight real `select('*')` fetches
beside them are untouched.

**The renderers dropped findings they were handed, and told GitHub a run had
succeeded when it had not.** `renderMarkdown` partitioned findings into
critical|high and medium|low by naming the severities, so an `info` finding —
the Supabase anon key, asked for with `--min-severity info` — appeared in
neither table while the "lower-severity findings" count said one fewer than it
had; `renderFixPrompt` dropped them outright. Both are partitioned by what is
*not* blocking now, so a renderer can rank a finding last but cannot lose one.
Worse, the SARIF had no `invocations` block at all: an incomplete scan uploaded
to code scanning as an ordinary successful analysis, showing what was found and
nothing about what was never read — and with `allow-incomplete` or
`fail-on: none` the job is green too, so this was the last surface that could
have said so. It carries `executionSuccessful` and a notification per reason
now. And the Markdown had no size bound while the Action posts it as a PR
comment: GitHub refuses a body over 65,536 characters with a 422, which at
~125 characters a row is about 535 findings — a number the 155-repo corpus
reached twice (603 and 732) off nothing stranger than a large lockfile matched
against OSV. The 422 landed in `|| echo "::warning::Could not post… (does the
token have pull-requests: write?)"`, so the one surface a reviewer reads showed
nothing and blamed the wrong cause. It bisects down to a row count that fits
and says how many are not shown, keeping the heading, the counts and the
incomplete warning always.

**Three of this audit's own fixes were wrong first, and the corpus caught all
three** — worth recording, because each was an over-credit, the direction that
hides real findings rather than adding noise. The Workers-handler check asked
whether a `) {` followed within 120 characters, which an ordinary
`if (!response.ok) {` on the next line satisfies — that cleared an AppVitrine
edge function's `fetch(imageUrl)` on a value straight out of `searchParams`.
The arity check counted arguments with `[^(),]{1,40},` twice, and a character
class does not stop at an object literal, so `fetch(url, { ...opts, signal })`
read as three arguments — SysXray's `fetchTimeout`, on a bare parameter. Both
are read off the matching close paren now. And the forward lookup for a
module-level const declared below its use was unanchored, so a `const url =
new URL(request.url)` in a later function vouched for an earlier function's
`fetch(url)`; it is `^`-anchored to column 0. The first version of the origin
resolver also credited `` `https://${host}/path` `` on the literal `https://`
prefix alone, which would have hidden exactly the database-row host above. All
four are pinned by keep-case tests.

**Verification:** 274 → 299 tests; **15 of the 25 new ones fail against the
pre-fix build, and all 10 that pass are keep-cases** — the true positives each
fix had to preserve, three of them pinning the over-credits above. Before/after
over seven real repositories (BizDataly, StorageVisual, datavot, aistoreaudit,
Cherrly, AppVitrine, SysXray), 1,638 files, run back-to-back on the same
checkouts: **452 → 385 findings, criticals 9 → 9, highs 194 → 148, zero
findings added**, scan times unchanged (−31 VG120, −15 VG408, −8 VG1006,
−7 VG1021, −6 VG964). **Every removal was read**, and what stays is real or
honestly undecidable: BizDataly's `downloadAndParseJSONL(url)` and datavot's
LinkedIn `uploadUrl` take a URL from an external API's response, StorageVisual's
bridge follows a `Location` header to an arbitrary host and writes the result
into its own install directory, and the database-row host stays critical to the
rule's purpose. No verdict changed on any repo — these were noise, not
verdict-flipping bugs, which is the honest summary. Self-scan 🟢 on the same
five lows, 68 files — after the first build added a sixth: the tool reported
**this audit's own new code**, a `[\w-]+(?:\.[\w-]+)+` hostname pattern, as
VG153 ReDoS. It was bounded in practice (it only ever sees ≤400 characters) but
rewritten without the nesting rather than suppressed, since running the vendored
patterns through a linear matcher is the thing 0.13.13 exists for. The
identifiers this audit interpolates into dynamically built patterns are also
re-checked against `^[A-Za-z_$][\w$]*$` at the point of use rather than trusting
every caller. One live-corpus lesson: a first before/after showed "+1 finding"
that turned out to be `datavot/scripts/invariants-test.mjs` being **edited by
another session while the scan ran** (mtime four minutes old, a VG153 line
moving 5434 → 5443 → 5540), which is why the final sweep was run with both
builds back-to-back. Not released: the work sits on top of `audit-2026-10-21`,
itself stacked on the unreleased `audit-2026-10-13`; one 0.13.14 ships all
three.

**0.13.14 ships all three audits (2026-10-29).** `main` fast-forwarded onto
`audit-2026-10-28` — six commits, 22 files, +2,853/−54 — so the 2026-10-13,
2026-10-21 and 2026-10-28 audits all go out under one version instead of
accumulating further; the three audit branches were ancestors of the tip, so
nothing had to be merged by hand. Bumped `package.json`, both root `version`
fields in `package-lock.json`, and the six doc literals the pin check asserts.
One version literal that the check deliberately *does not* match was stale
anyway — README prose reading "so `@v0.13.13` runs ClearToShip 0.13.13" as a
generic illustration of ref pinning — and it is version-free now (`@vX.Y.Z`)
rather than bumped, which is the drift the check exists to catch, one line
outside its reach.

**The whole release gate was run locally before the tag, not just at the end.**
Version pins 6/6 at v0.13.14; `npm ci` 0 vulnerabilities; **299 tests pass, 0
fail, and — run file by file — 0 skipped in all 17 files**, which is the check
worth naming here, because three network-gated tests once skipped silently on
this machine for months; the three new audit files contribute 61 of the 299
(audit-coverage 14, audit-oct21 22, audit-oct28 25). Self-scan run with CI's
exact argument list, online and without `--allow-incomplete`: **exit 0, 🟢 CLEAR
TO SHIP, 68 files, the same 5 low-priority notes**, reaching OSV.dev (12
resolved versions) and npm (12 packages), so it was complete rather than exit-3
incomplete. All three release assets built and all four of `release.yml`'s
pre-signing assertions reproduced by hand: the bundle reports `0.13.14`, it
carries its Apache licence text, `cleartoship-standalone.tgz` ships
`package/LICENSES/`, and `cleartoship-0.13.14.tgz` exists. Also checked a
stale-file trap that the workflow's `cp standalone/cleartoship.mjs` would not
have caught on its own: `bundle.mjs` writes `bin/cleartoship.mjs` and copies it
up (line 121), and the two hashes are identical, so the bare file cannot be a
leftover from an earlier build.

**Shipped and verified, 2026-10-29 09:15 UTC.** `v0.13.14` is published,
not draft, with all three assets at the byte sizes the local build produced
(428,670 / 557,032 / 2,377,500). All four rows of the release skill's table
were checked rather than read off a green run, and two of them independently:
`gh release view` lists the assets; the downloaded bundle runs and reports
`0.13.14`; `gh attestation verify` exits 0 and its predicate names
`.github/workflows/release.yml` at `refs/tags/v0.13.14` with source digest
`cfef22a`, so the signature is tied to this workflow and this tag rather than
merely existing; `curl https://cleartoship.app/cleartoship.mjs | shasum -a 256`
is `0c4c2ad…871c`, which is the release asset's hash, and `deploy-site.yml`'s
own post-deploy comparison reported the same sha256 from the runner. The Worker
moved to version `b5f53e42-4293-495b-a8f1-6d81424f6dd5`, confirmed by the
workflow's `wrangler deployments list` read-back rather than by the deploy step
exiting 0, and the live footer pill reads `v0.13.14`. **The release bundle is
byte-identical to the one built here** — same `0c4c2ad…871c` — so the tag
reproduced the local build exactly. And it was run, not just version-checked:
the downloaded bundle scans this repo to the same 🟢, same 68 files, same 5
low-priority notes, same 402 community rules.

**One coordination note worth keeping.** A second session was working in this
repo at the same time and committed the version bump out from under this one —
`e597239`, at 05:08:47 local, while the self-scan was still running. Its
content was byte-for-byte the working tree this session had already gated
(including the version-free `@vX.Y.Z` README line), and its message is
accurate, so it was kept rather than rewritten; this session's own commit was
reworded, since it then held only `TODO.md` while still claiming the bump. The
check that caught it was reading `git status` after `git add -A` and seeing one
file where seven were expected — not something a test would have failed on.
Worth remembering with the audit's other concurrency surprise: the same
overlap produced the phantom "+1 finding" from a file edited mid-scan.

## Open

- [ ] **Four findings reported from the jobcopilot audit, 2026-10-28/29** (an outside app —
      MV3 Chrome extension + local Node bridge + a Cloudflare Worker — run as
      `node dist/cli.js --offline bridge extension d1`, 99 files, 2.7s, 47 findings:
      3 critical, 27 high, 3 medium, 14 low. **All 47 were checked by hand against the source
      and all 47 are false positives for that app**, which is the context for the first item):
      - **The XSS family is 19 of the 27 HIGHs, and they are all one correctly-escaped file.**
        `VG852` (9), `VG012` (8) and `VG121` (2) all land on the same six-file side panel, which
        has exactly one `escapeHtml` (escaping `& < > " '`) applied to every attacker-reachable
        value; the remaining interpolations are numbers, literal ternaries, or fragments already
        escaped when built. This is the **sink-level** limitation already filed above from the
        SysXray audit, but the proportion is the new information: a 🔴 HOLD verdict in which
        70% of the high findings are one correct file is a verdict a reader learns to discount,
        and the documented next step (`--fix-prompt`, "hand the fixes to your AI editor") would
        point an agent at correct code and invite it to change it. Worth considering whether a
        sink whose inputs all pass through a single-argument escaper in the same file can be
        downgraded, or at least counted once per file rather than once per sink.
      - **`VG020` "wildcard dependency" reads `engines`.** Two findings, both
        `bridge/package.json:8`, which is `"engines": { "node": ">=20" }` — a runtime constraint,
        not a dependency range. A `>=` in `engines` is the normal way to write that field, so
        this will fire on a large share of Node projects. Probably wants scoping to
        `dependencies` / `devDependencies` / `peerDependencies`.
      - **`VG010` SQL injection reads a CSS selector.** `extension/adapters/base.js:157` builds a
        `querySelectorAll('select, textarea, …')` string. The word `select` plus string
        concatenation is enough to return CRITICAL, and CRITICAL is what sets the HOLD — so a
        DOM query in a browser extension with no database anywhere in it decides the verdict.
        The other `VG010` is `d1/worker.js:66`, which interpolates a frozen `COLUMNS` literal and
        never input; that one is at least a real SQL string.
      - **`dist/` has to be built before the documented command works.** The published
        instruction is `node dist/cli.js`, and on a fresh checkout `dist/` does not exist, so the
        first run fails. `npm run build` first. Either the docs should say so or the CLI should
        say it when `dist/` is missing.

      Two things that worked well and are worth not losing: scoping by path
      (`cleartoship bridge extension d1`) cleanly excluded a vendored upstream that the project
      does not patch — which took 474 findings down to 47 — and the PASS lines that say what was
      skipped and why (`.gitignore` entries, build dirs) are the reason it was obvious the run
      had not quietly missed anything.

- [ ] **Three findings reported from the SysXray audit, 2026-10-28** (an outside
      app, run as `node dist/cli.js --offline` over 44 files, 2.8s):
      - **`VG120` SSRF — two false positives on a Cloudflare Worker.**
        `src/worker.js:10` is a generic `fetchTimeout(url, opts)` helper whose
        every caller passes `` `${env.SUPABASE_URL}` `` plus a fixed path, so the
        host is never user-controlled; a taint check would clear it. Worse,
        `src/worker.js:262` is `async fetch(request, env)` — the **Worker's own
        default export handler**, not an outbound request at all. Matching the
        method name `fetch` on a Workers entry point will fire on every Worker
        ever written, so this one is likely to recur across the portfolio.
      - **`VG146` "Unquoted .env Value" fires on shell scripts.**
        `macos/release.sh:17,19,26` and `public/install.sh:39,49,54`. These are
        `.sh` files assigning shell variables, not env files. Probably wants
        scoping to `.env*`.
      - **`VG012` is sink-level, so it cannot confirm a fix.** It flags
        `X.innerHTML = <non-literal>`, which stays flagged whether or not the
        inputs are escaped — the count was 7 before that app's XSS fix and 7
        after. The real defect was 9 unescaped interpolations feeding those
        sinks, which the scanner did not enumerate. It worked well as a pointer
        to *where to read*; it is not a signal of whether the taint is handled.
        Worth considering whether the finding can say "sink reached by a
        non-literal; check the inputs" rather than "XSS via innerHTML".
      - **Severity note on `CTS030`.** It returned CRITICAL, and so 🔴 HOLD, for a
        real secret in a `.env` that is gitignored, untracked and absent from
        every commit in every branch — the documented way that app's
        `wrangler dev` gets real secrets. The finding is correct; the severity
        cannot currently distinguish "secret in a committed file" from "secret in
        a gitignored local dev file", which is the difference between an incident
        and normal practice.
- [ ] **Maintainer-only settings the audit turned up** (not doable from the
      repo): **enable immutable releases** (release.yml publishes via a draft,
      so it is compatible), **delete the dead `NPM_TOKEN` secret**, and add a
      **Cloudflare rate-limit rule** on `/license/*` and `/webhooks/*`.
- [ ] **Found in the 2026-10-13 audit, deliberately not fixed yet.** CTS004
      ("authenticated but not owner-scoped", medium) says "any logged-in user can
      pass another tenant's id" about a route gated on `requireAdmin()`, where
      acting on someone else's row is the point. Fixing it properly needs the
      auth model to distinguish *authorization* from *authentication*, not a
      vocabulary match — a name list in this exact area has already hidden two
      real bugs — so it is recorded rather than patched. VG1008 still reports
      alongside CTS001 on an ungated admin write (same line, two criticals);
      kept because it also covers the authenticated-but-not-admin case CTS001
      rates lower. VG012 cannot prove `safeHtml` or `buildHTML()` is sanitised,
      so those stay reported. And an HTML file is read for credentials and by the
      7 HTML-language vendored rules, not by the JS AST scanners: an inline
      `<script>` in a `.html` is not analysed for CTS001/CTS070/CTS080-085.
      Since 2026-10-21 the same applies to `.svelte` / `.vue` / `.astro`
      single-file components: read for secrets and the html rules, their
      script blocks not AST-analysed.
- [ ] **Known limits still open after 0.13.13.** SQL inside a `DO $$ … $$`
      block is not parsed, so policies created there are invisible (a false
      CTS014 on StorageVisual's `forum_comment_likes`). A gate-only SELECT
      (`auth.role() = 'authenticated'`) on a table that is really private is not
      reported unless a scoped SELECT policy sits beside it — deliberate, to
      stay quiet on member-readable tables. Custom roles (`to
      supabase_auth_admin using (true)`) still trip the whole-table CTS014.
      Unknown package auth wrappers are credited by name, with a warning. The
      per-rule time budget has a ~2× margin on this machine (worst rule 126 ms
      per 400 KB vs 250 ms), so a slow runner could still see it fire.
- [ ] **Billing stays dormant (free in beta).** The Worker's webhook, key-id and
      missing-secret bugs were fixed in the audit, and migration
      `0002_license_per_subscription.sql` must be applied remotely
      (`wrangler d1 migrations apply cleartoship-licenses --remote`) before any
      payment is taken. There is no `/admin/license/issue` route and no
      client-side license verifier; both would have to be written first.
      `currentPeriodEnd()`'s field-name fallback still needs checking against
      whatever Stripe API version a real account is pinned to.
- [ ] **Get it in front of people, as early as possible.** Publish and publicize
      now; there is no minimum number of users to reach first (decided 2026-09-21).
      Every calibration decision so far was made against my own six repositories,
      which remains the biggest weakness in the tool's judgement, but the way to
      fix it is more people running it and reporting what comes back wrong, not
      recruiting a set number of testers before launching.
      **In progress 2026-09-22:** a Show HN post and a dev.to writeup are drafted
      (the CTS001 calibration story — 60 of 77 sampled findings were wrong, two
      real bugs hidden by the first version of the fix, both caught by reading
      what the fix removed). Neither is posted yet — blocked on logging into
      Hacker News and dev.to in the browser; nothing else is stopping it.
- [ ] **CTS001 still has real false-positive classes left, found but not fixed
      2026-09-22.** Of 60 sampled false positives from the 155-repo corpus, 24
      cleared with the false-positive fix that shipped (v0.13.9); the other 36
      are left on purpose, not by oversight:
      - **Name-based "public by design" cases** (analytics beacons, apps with no
        auth model at all, intake/lead forms) — only separable by route name
        today, and a name-list heuristic already hid two real bugs in this same
        pass (`register` hardcoding an Admin role, `leads` running paid
        enrichment), so widening it needs care, not just more names.
      - **Clerk middleware that already protects `/api`** — needs the
        `middleware.ts` matcher and `createRouteMatcher` public-route list
        actually parsed, not guessed at.
      - **Signature/auth checks delegated to a helper that itself calls an
        external service** (a Supabase REST call, a DB-backed API-key lookup)
        — not credited today because the scanner only follows first-party
        helpers, never into what they call out to.
- [ ] **New rule candidate, found during the same pass, not CTS001's job.**
      Unauthenticated `execa.command(\`...${formField}\`, { shell: true })` —
      direct shell-command injection from a request field, seen on a real public
      playground repo. Worth its own rule rather than folding into an existing
      one; not scoped yet.
- [ ] **Lockfile-vulnerability false positives, not yet triaged.** 148 of 154
      repos in the corpus still get a HOLD verdict, almost entirely from real
      `package-lock.json` / `pnpm-lock.yaml` versions matched against OSV — the
      overall verdict barely moved across the whole CTS001/CTS030 calibration
      pass. Unknown yet how much of that 148 is genuine (most likely) versus a
      severity-mapping or dev-dependency-splitting bug like the ones CTS024
      already exists to fix. Needs the same read-the-code treatment the other
      rules got; hasn't started.

- [ ] **Where the 2026-10-21 audit did not look — scope for the next one.**
      That pass went where the yield was (the walk/read layer, the dependency
      collectors, the vendored-rule guards, corpus triage of every critical on
      the seven real apps plus sampled removals on the fixture repos). It did
      NOT re-read `report.ts`'s five renderers beyond a skim, the
      `server-actions.ts` / `auth-helpers.ts` pair, the site Worker, or
      `action.yml` and the workflows — all last audited 2026-10-13 or
      2026-09-23 — and it triaged highs only where a critical led there, so
      the ~180 corpus highs (BizDataly 59, StorageVisual 45, datavot 39) have
      never had the read-the-code pass the criticals got. The next audit
      should start from one of those rather than re-walking this one's ground.
      **Done 2026-10-28** — see the entry above: the renderers and the ~180
      highs were the two it took. `server-actions.ts` / `auth-helpers.ts`
      (3,286 lines) is still the one nobody has re-read since 2026-10-13.
- [ ] **Three things the 2026-10-13 audit noticed and did not act on.**
      (The first sentence of this item was lost when `fb24b85` wrote over its
      opening line; restored here from the commit that introduced it.) 8
      vendored rules
      carry an `API:`-prefixed OWASP label (the API Security Top 10, a
      different list) that the README's OWASP table does not mention, so those
      rules' category reads as unmapped. Now that `site/public` HTML is
      actually read, static-site rules like VG142 (missing Subresource
      Integrity on a CDN `<script>`) can fire on landing pages where the CDN is
      a deliberate choice — no noise on this repo's four pages, but worth
      watching on the first user who scans a marketing site. And
      `/license/verify` on the Worker is unauthenticated by design (anyone can
      ask whether a key is valid); the mitigation is the Cloudflare rate-limit
      rule already listed in the maintainer-settings item above, not a code
      change.
- [ ] **Noticed in the 2026-10-21 audit, deliberately not acted on.**
      `bun.lock` / `bun.lockb` and `uv.lock` are not read by `resolveVersions`,
      so bun- and uv-only projects have their OSV queries made with range
      floors rather than installed versions — checked, but imprecise. A `.env`
      nested *deeper* than one level inside a gitignored directory is still
      never read (the peek is one `readdir` per skipped directory, by design).
      A UTF-16 file *without* a BOM still decodes as mojibake — PowerShell
      writes the BOM, so the no-BOM case was left. The non-production path idea
      lives in two places (`secrets.ts` `NON_PRODUCTION_PATH` and `paths.ts`
      `NON_PRODUCTION`) and they drifted identically once already; folding
      secrets onto `pathClass()` changes which secrets findings get demoted
      (paths.ts accepts affixed names like `transfer-tests/`), so it needs its
      own read-the-removals pass, not a refactor commit. `meta.resolvedFrom`
      on CTS024 always says `lockfile-or-range` — the ternary that was meant to
      distinguish them is decided after the lookup it reports on. And
      gitleaks' `cmd/generate/config/rules/*.go` keeps ~90 criticals: those
      sample keys are realistic by construction (that is their job), no path
      convention marks them, and a scanner that special-cases one repo's layout
      is shaping itself around its corpus.
- [ ] **Noticed in the 2026-10-28 audit, deliberately not acted on.**
      **`action.yml` runs the whole scan two or three times** — once for
      `--json`, once for `--markdown`, and again for `--sarif` when it is
      asked for. That is 2–3× the wall clock and 2–3× the registry and OSV
      traffic on every CI run, and worse than the cost: **the severity gate is
      computed from the JSON run and the PR comment is rendered from a
      different one**, so if the two disagree — a registry that answers once
      and times out the next — the comment and the verdict are from different
      scans. The fix is a CLI that writes several formats from one scan (a
      `--write <format>:<path>` option), then one invocation in the Action;
      that is a feature, not an audit patch, so it is recorded rather than
      half-built at the end of a pass.
      **VG926's name does not match what it matches.** "Next.js / React Server
      Components DoS" fires on `"react": "^19.2.4"` with no requirement that
      the project has Next.js or RSC at all — StorageVisual is a Vite SPA with
      no `next` dependency and no Server Functions, and got 5 highs, 3 of them
      on `package-lock.json` and 2 on the `package.json` beside it, so the
      same dependency is reported twice. The version range is correct and
      reachability analysis is deliberately out of scope, so this is a
      severity-and-wording problem rather than a false positive; it also only
      appears with `--offline`, since `GUARDVIBE_CVE_RULE_IDS` stand down once
      OSV has answered. Both halves (framework-gating a CVE rule, and
      de-duplicating a version rule across a manifest and its lockfile) need
      their own read-the-removals pass across the whole CVE ruleset.
      **`verdictOf` is documented as "the one place the verdict is decided"
      and `renderTerminal` still decides it again** from `scan.counts` inline.
      The two agree today, checked case by case; it is one idea in two places,
      which is how `NON_PRODUCTION` drifted.
- [ ] **Six new VG012 findings on SysXray, nothing written down yet.** The
      sweep read SysXray's HTML dashboards for the first time and they really
      do assign `innerHTML` from strings concatenated out of scan data
      (`innerHTML=cpuTopHtml`). Per the convention, new findings on one of my
      own apps belong in `security-scans/<date>-<time>.md` in *that* repo, not
      here — decide whether these are worth a report (the data is local machine
      telemetry, not attacker-controlled input) and write it there if so.
- [ ] **Where the 2026-10-28 audit did not look — scope for the next one.**
      That pass took the renderers and the corpus highs, which is what the last
      one left. What is still unread: **`server-actions.ts` /
      `auth-helpers.ts`, 3,286 lines between them, last audited 2026-10-13**
      and skipped by two audits running — the largest unexamined surface in the
      tool, and the one behind CTS001/CTS004, whose known false-positive
      classes are still open above. The site Worker and the workflows *were*
      re-read this time and nothing new came out of them: the Worker verifies
      Stripe signatures with SubtleCrypto, ignores stale events by `created`,
      re-reads the subscription rather than trusting the payload, and repeats
      the age check at the write; every third-party action is SHA-pinned, there
      is no `pull_request_target`, and `release.yml` is default-deny with
      per-job grants. Also untouched: the **~150 remaining highs** after this
      pass (BizDataly 42, StorageVisual 38, datavot 30) — this audit read every
      *cluster* of three or more and the singletons are unexamined — and the
      **mediums have never been triaged at all** on any repo.
- [x] **BizDataly's hardcoded Shopify token is written up.** Reported at
      `/Users/Shared/BizDataly/security-scans/2026-10-28-1841.md` per the
      convention: a live `shpat_…` Admin API token for a development store,
      hardcoded as a `process.env.X || "shpat_…"` fallback in two server
      modules and a bare `const` in three scripts, duplicated across the
      `Shopify/ShopifyApp/` copy (10 source locations), plus two
      `.claude/settings.local.json` permission entries that embed it in an
      allowlisted `curl`. Not in any git history today — the BizDataly root is
      not a repo and `saas/.env.local` is correctly ignored — which is exactly
      why it is worth fixing before either folder becomes one.

## Later — recorded, not being worked on

- **Trademark "ClearToShip".** The code is MIT and the package is public, so the
  licence deliberately lets anyone copy, modify and sell it — that is the trade,
  and it is the same one gitleaks and GuardVibe made with this project. What MIT
  does *not* grant is the name, and a trademark is the only protection here that
  actually works: a fork may take every line and still cannot call itself
  ClearToShip, which leaves the discoverability with the original.
  **Parked deliberately, not forgotten.** At zero users there is nothing to pass
  off and nobody to confuse, which is what a trademark protects against. The
  moment to file is when the name starts carrying weight — real users, a
  Marketplace listing, or the first time somebody else ships something built on
  this. Revisit then rather than on a date.

## Settled

- **No npm distribution, as of 2026-09-21.** ClearToShip ships as a GitHub Release
  plus `cleartoship.app/cleartoship.mjs`. The Action resolves the release bundle,
  then a checkout build, and never `npx`es the name — with the name unclaimed, that
  would be code execution for whoever registered it. The scanner still *queries*
  the npm registry, because checking a user's dependencies against it is the
  feature; when it cannot, the run says so and is never "clear".

- **Node floor: `^22.18.0 || >=24.11.0`,** as of 0.13.2. That is Babel 8's own
  range copied exactly rather than approximated — a looser `>=22.18` would claim
  Node 23 and 24.0–24.10 work, and Babel 8 does not support them. Node 18 and 20
  are dropped. CI tests the declared floor (`22.18.0`) alongside the latest 22
  and 24, so a claim the code cannot meet fails the build rather than a user's.
  Worth being clear why the exactness matters here rather than being pedantry:
  had the range been wrong, the tool would have installed happily and then failed
  at *parse* time — and an unparsed file produces **no findings**, not an error.
  A scanner's worst failure is reporting clean on code it never read.
  ⚠️ **Local dev needs a newer Node than this machine's default.** `node` on the
  PATH here is v22.14, below the floor. **Homebrew's v26 no longer runs** (as of
  2026-10-29): the bottle links `libada.3` and `libsimdjson.33`, the Cellar has
  ada-url 4 and simdjson 5, and it dies in dyld before printing a version — so
  `export PATH="/usr/local/opt/node/bin:$PATH"` now buys a broken interpreter
  rather than a newer one. `brew reinstall node` builds from source on this
  macOS/Intel pair (no bottle), which takes long enough that it is not the
  unblocking move. What 0.13.14 was built with instead: the official
  `node-v22.23.4-darwin-x64` tarball, checksum-verified against nodejs.org's
  `SHASUMS256.txt`, unpacked outside the repo and put on the PATH for the
  build — and v22 is what `ci.yml` and `release.yml` set anyway, so it matches
  the release runner more closely than v26 did.

## Deliberately not covered, and why

These are decisions, not gaps waiting to be filled. Adding a rule for any of
them would be box-checking, which is the failure mode this project exists to
avoid.

- **OWASP A06 (Insecure Design).** Missing threat modelling is an architecture
  concern that no static read detects. Revisit only if a genuinely high-signal
  design-flaw pattern turns up.
- **OWASP LLM05 (Data & Model Poisoning).** Needs training-pipeline and dataset
  provenance. Nothing in a web app's source tree answers it.
- **Strengthening A04 / A02 first-party.** Parked on purpose rather than by
  neglect: five repos were triaged and no real gap showed up. Speculative rules
  are how a scanner becomes noise.

## Deliberately not built

- **A cross-finding risk graph** correlating web findings with LLM findings.
  It is an existing category, and a *Critical* assembled out of two mediums is
  exactly the false-positive behaviour that eight releases went into removing.
- **An auto-fix PR bot.** `--fix-prompt` and SARIF already cover the useful part
  at none of the cost.
- **Broader generic SAST/SCA.** Saturated, free at the entry point, and not a
  reason anyone would choose this tool.

## Pricing

**Everything is free while ClearToShip is in beta (decided 2026-09-21).** The
RLS, Server Actions and LLM/agent suites had been split into a private
`cleartoship-rules-pro` repository for a planned $5/month Pro tier. They are back
in this repository, MIT licensed, and ship in the free bundle. Why: a separate
package cannot be installed now that npm is out, so an unpublished paid tier
delivered nothing; the tool's headline features (the agent surface) were missing
from the download; and the same rules had been public under MIT since v0.4.

The private repository and the license-issuing Worker under `site/` (D1 database,
Ed25519 token signing, Stripe webhook code) remain, dormant, in case a paid tier
is ever wanted. Nothing charges anyone. No price is set — $5/month was only ever a
plan — and what is free now stays free.

## Contributing

The most useful bug report here is a **false positive, with the code that caused
it**. A rule that fires on correct code is a worse bug than a rule that misses
something: one wastes your afternoon and teaches you to ignore the tool, the
other you never knew about. Removing false positives is what most of this
project's history is actually made of, and every removal so far was verified by
reading the code it was about rather than by loosening a threshold.

Second most useful: a **missed finding**, with the code it should have caught.

New rules are welcome, but the bar is deliberately high — a rule that cannot
name a specific wrong thing a developer would act on does not go in, however
well it maps to a compliance table.
