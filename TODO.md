# ClearToShip — roadmap

Public backlog. Working notes, positioning and anything about other projects
live in `NOTES.private.md`, which is gitignored and stays on my machine.

_Current release: **v0.13.10** — trims `action.yml`'s description under the GitHub
Marketplace's 125-character limit, which was blocking the Marketplace listing;
[the Action is now live there](https://github.com/marketplace/actions/cleartoship)
(2026-09-22), under Security / Code Scanning Ready. The first fix for the limit
broke `action.yml` outright — an unquoted colon in the trimmed description reads
as a YAML mapping key, and the `Action integration test` workflow caught it within
a minute, before it reached a tag. Every check is in the one free download,
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

**The 2026-09-23 full audit (unreleased; on branch `audit-fixes`) found the
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

## Open

- [ ] **Ship the audit fixes.** Merge `audit-fixes` to `main`, bump to 0.13.11
      and release — the first release with build-provenance attestations. Until
      0.13.11 exists, README and `examples/security-cli.yml` show `gh attestation
      verify` against v0.13.10, which has no attestation and fails; the Action
      handles pre-attestation versions by building its own checkout.
      Maintainer-only, not doable from the repo: **enable immutable releases**
      (release.yml already publishes via a draft, so it is compatible), **delete
      the dead `NPM_TOKEN` secret**, and add a **Cloudflare rate-limit rule** on
      `/license/*` and `/webhooks/*`.
- [ ] **Known limits left by the audit, on purpose.** A whole-repo scan builds
      one SQL schema from every `.sql` file, so separate projects' migrations
      mix (visible on this repo's own fixtures). CTS014 still counts a table
      isolated if any one policy uses `auth.uid()`, even when an OR'd
      `auth.role() = 'authenticated'` policy leaks. ~35 vendored patterns are
      still super-linear on adversarial input; 64 KB windows plus a per-rule time
      budget cap them (a budget overrun is `incomplete`), but files ≤400 KB are
      searched whole. Auth wrappers are credited by name
      (`withIronSessionApiRoute` counts), and an action that reads the session
      only to turn signed-in users away (`if (session) redirect('/')`) is now a
      CTS001.
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
  PATH here is v22.14, below the floor. Homebrew's v26 satisfies it:
  `export PATH="/usr/local/opt/node/bin:$PATH"` before `npm install` or `npm test`.

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
