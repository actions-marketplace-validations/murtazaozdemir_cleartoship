# ClearToShip

> The 30-second pre-launch security clearance for AI-built apps — including the agent
> surface a runtime scanner cannot reach until after you have already deployed it.

![ClearToShip scanning a deliberately vulnerable Next.js and Supabase app: a hallucinated package, a Server Action with no auth check, and a table with Row Level Security disabled](docs/demo.svg)

<sub>Real output from a scan of this repository's deliberately vulnerable test fixture, trimmed to three findings.</sub>

AI coding assistants write code fast, but they optimise for *"runs without errors"*, not
*"runs without leaks"*. The failure mode is almost never a dangerous line of code — it's an
**absent** one: the session check that was never written, the RLS policy that was never
enabled, the package name the model invented, the approval step the agent tool never had.

`cleartoship` is a static pre-flight check for exactly those gaps. No database connection, no
account, no upload — it reads your repo and exits non-zero if you shouldn't deploy.

### Where this is not like the other scanners

The serious LLM security tools are **runtime**: they probe a deployed endpoint and report how
it answered. That is a real and different job, and this does not compete with it. What none of
them does is read your *source*, before it ships, and tell you that the system prompt is
compiled into the client bundle, that the model call has no token ceiling, that the agent tool
which deletes rows has nothing asking a person first, or that an answer is being used as the
access check.

Six first-party rules read that surface directly, mapped to the **2026** OWASP LLM Top 10 —
and the coverage table below names the one category this refuses to fake. Everything else here
is the ordinary web surface, which is table stakes: you still ship on the same day that a
missing RLS policy would have leaked the table.

Those six, the RLS and Server Actions suites alongside them, and everything else on
this page (dependencies, secrets, logging/exception handling) are free while
ClearToShip is in beta — no account, no key. See [What's free](#whats-free).

```bash
curl -fsSL https://cleartoship.app/cleartoship.mjs -o cleartoship.mjs
node cleartoship.mjs
```

**Every check is free while ClearToShip is in beta — no account, no key.** It
runs on your machine and reports to your terminal; your code never leaves it.

That is one bundled file with zero dependencies: no package manager in the path
and nothing for a registry to resolve. **ClearToShip is not distributed through
npm.** There is no `npx cleartoship`, and a package by that name on the registry is
not from this project — do not run it. The same file is attached to every
[GitHub release](https://github.com/murtazaozdemir/cleartoship/releases/latest)
if you would rather not fetch it from this domain
(`https://github.com/murtazaozdemir/cleartoship/releases/latest/download/cleartoship.mjs`),
and `https://cleartoship.app/SHA256SUMS` lists its checksum.

This is the most robust way to run it, and deliberately so: npm 12
ships with `allow-remote` and `allow-git` set to `none`, so *any* install from a
URL or a git ref now needs an explicit flag from the user. A file you fetch and
hand to `node` needs nothing to cooperate.

Requires **Node ^22.18 or >=24.11** — the range Babel 8 supports, mirrored exactly
rather than approximated, since a looser `>=22.18` would claim Node 23 and early
24 work when they do not.

<details>
<summary>Other ways to install</summary>

None of these fetches ClearToShip itself from the npm registry. Ranked by how
little has to work for them to work:

```bash
# 1. nothing but node. No package manager, no registry, no install step.
#    (The same file is at https://github.com/murtazaozdemir/cleartoship/releases/latest/download/cleartoship.mjs)
curl -fsSL https://cleartoship.app/cleartoship.mjs -o cleartoship.mjs
node cleartoship.mjs

# 2. the same bundle as an installable package. npm 12 defaults allow-remote to
#    "none", so it has to be told this is wanted.
npm i -D https://github.com/murtazaozdemir/cleartoship/releases/latest/download/cleartoship-standalone.tgz --allow-remote=all

# 3. from the repository, building on install. npm 12 defaults allow-git to
#    "none" too, and the build is a lifecycle script, so both need allowing.
npm i -D github:murtazaozdemir/cleartoship --allow-git=all --allow-scripts=cleartoship
```

1 and 2 are the same bundled file, and the test suite asserts it produces
identical findings to the full package — a fallback that behaves differently from
the tool you tested is not a fallback. 3 still resolves the five runtime
dependencies from npm; what it removes is any need for *this package* to be
published there.

The GitHub Action needs none of them: `action.yml` downloads the release bundle
for the version its ref declares, verifies its build-provenance attestation
before running it, and builds from its own checkout when that version has no
verifiable release.

</details>

## What's free

Everything on this page is free while ClearToShip is in beta: the
**dependency/supply-chain**, **secrets & client bundle** and **logging,
error-handling & deserialization** checks, the full vendored community ruleset,
**and** the Row Level Security, Server Actions and LLM/agent suites. No account,
no key, nothing to install beyond the one file above.

A paid tier may come later, once people are using the tool and it is clear what
they would pay for. Nothing is for sale today, and no price is set. If it comes,
what is free now stays free and MIT licensed: a paid tier would be new rules on
top, announced first, never something taken out of the tier you already have.

The vendored community rules that overlap the first-party RLS, Server Actions and
LLM/agent checks are switched off in their favour (see `SUPERSEDED` in
`src/scanners/community.ts`): they were measurably noisier than the checks they
were built to replace, and this project's whole premise is that a scanner which
cries wolf gets ignored.

## What it checks

**Next.js server surface** — Server Actions, Route Handlers, client boundary

| Rule | Severity | What it catches |
| --- | --- | --- |
| **CTS001** | critical/high/low | Server Action / Route Handler with no session check: **critical** when it visibly writes to the database, **high** when it accepts a mutating method but no write is visible in the handler, **low** on a route that is unauthenticated by design (sign-in, sign-up, password reset, contact/waitlist forms, a logout that reads nothing from the request) |
| **CTS002** | high | Caller's payload written to the database as an object — every key they sent becomes a column |
| **CTS003** | critical | `SUPABASE_SERVICE_ROLE_KEY` client built inside a user-reachable action |
| **CTS004** | medium | Authenticated mutation keyed only on a caller-supplied id (IDOR) |
| **CTS040** | high | Client component reads a server-side `process.env` variable |
| **CTS041** | high | `supabase.auth.getSession()` used as a server-side auth check — it does not revalidate the JWT |
| **CTS042** | critical | Webhook endpoint accepts an unsigned, unverified payload |
| **CTS043** | high | Request body spread straight into a database write (mass assignment) |
| **CTS044** | medium | `.passthrough()` / `z.any()` makes the schema decorative |
| **CTS045** | critical | AI SDK client set to `dangerouslyAllowBrowser: true` |
| **CTS046** | high | Cron route with neither `CRON_SECRET` nor a session check |

CTS040 and CTS045 are implemented in the secrets scanner rather than the Server
Actions suite.

**Supabase / PostgreSQL** — schema, RLS, storage

| Rule | Severity | What it catches |
| --- | --- | --- |
| **CTS010** | critical | Public table with Row Level Security never enabled |
| **CTS011** | low | RLS on with no policies — fail-closed, but the feature is probably broken |
| **CTS012** | critical | Policy grants writes with an always-true predicate |
| **CTS013** | high | Anonymous `SELECT` over a table holding emails, tokens or billing ids |
| **CTS014** | high | Table has a `user_id` column but no policy compares it to `auth.uid()` |
| **CTS015** | medium | `SECURITY DEFINER` function without a pinned `search_path` |
| **CTS016** | medium/high | View with definer rights, or a materialized view, exposed over the Data API |
| **CTS017** | critical | `GRANT INSERT/UPDATE/DELETE … TO anon` |
| **CTS018** | critical | Policy trusts `user_metadata`, which the user can edit themselves |
| **CTS019** | critical | `auth.users` republished through a view in the public schema |
| **CTS050** | medium | Overlapping permissive policies — they OR together and only widen access |
| **CTS051** | high | Storage policy lets anyone list every object in every bucket |
| **CTS052** | high | `SECURITY DEFINER` function executable by `anon` |

**Supply chain** — hallucinated and hostile dependencies

| Rule | Severity | What it catches |
| --- | --- | --- |
| **CTS020** | critical | Dependency that **does not exist** on npm/PyPI — a hallucinated import |
| **CTS021** | high | Dependency registered days ago with near-zero downloads (slopsquat shape) |
| **CTS022** | low | Runtime dependency with almost no users |
| **CTS023** | high/medium | Name is one edit from a popular package (`expres` → `express`) |
| **CTS024** | by CVSS | Dependency version has a **published advisory**, resolved live from [OSV.dev](https://osv.dev). Vulns in `devDependencies` are labeled and held below the gate — a linter CVE never blocks a deploy the way a shipping one does. |
| **CTS025** | low | Dependency deprecated upstream |
| **CTS026** | critical | Registry serves HTTP 451 — the package was pulled for malware |
| **CTS027** | critical | Package was unpublished but still has installs; the name is open to takeover |
| **CTS028** | critical | `postinstall` hook that curls, evals or shells out |

Dependency rules read `package.json`, `requirements.txt` and `pyproject.toml` — **and**
`README.md`, `AGENTS.md`, `CLAUDE.md` and `.cursorrules`, because a hallucinated
`npm install` line gets copy-pasted out of an agent instruction file long before it
reaches a manifest.

**Secrets & client bundle**

| Rule | Severity | What it catches |
| --- | --- | --- |
| **CTS030** | critical | Hardcoded provider key — Supabase service-role, Stripe live, OpenAI, AWS, GitHub … |
| **CTS031** | critical | Server secret routed through a `NEXT_PUBLIC_` variable |
| **CTS032** | high | `.env` in a git repo with no matching `.gitignore` rule |
| **CTS033** | critical | `'use client'` component reaching for a server-only secret |
| **GL-\*** | high/critical | 219 further credential providers, vendored from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT), gated on Shannon entropy |

**LLM & agent risks** — the detectable slices of the OWASP Top 10 for LLM Apps

| Rule | Severity | What it catches |
| --- | --- | --- |
| **CTS080** | high | Caller-supplied text interpolated into the instruction text itself — prompt injection by construction, not by filter (LLM01) |
| **CTS081** | medium | A request-reachable model call with no `max_tokens` ceiling: the answer's length, and its bill, chosen by whoever wrote the input (LLM06) |
| **CTS082** | medium | A system prompt in a `'use client'` module — compiled into the bundle, readable in devtools (LLM08) |
| **CTS083** | high | An agent tool the model may call on its own whose body **cannot be taken back** — deletes rows, moves money, sends mail, runs a shell — with nothing asking a person first (LLM03) |
| **CTS084** | critical/high | The model's own answer traced into a sink that *runs* it: `eval`, `new Function`, a shell, raw SQL, `innerHTML`, `dangerouslySetInnerHTML` (LLM10) |
| **CTS085** | high | A branch or a check that turns on what the model returned — the guess decides access (LLM07) |

**Logging, error-handling & deserialization** — the detectable slices of A08/A09/A10

| Rule | Severity | What it catches |
| --- | --- | --- |
| **CTS070** | high/medium | Secret, token or PII (or a whole request body) written to a log (A09) |
| **CTS071** | high/medium | A security check that **fails open** — `catch { return true }` — or swallows its error (A10) |
| **CTS072** | high | Insecure deserialization of untrusted data — `unserialize`, `pickle.loads`, unsafe `yaml.load` (A08) |

**Community ruleset** — 435 additional rules vendored from
[GuardVibe](https://github.com/goklab/guardvibe) (Apache-2.0)

Reported under their upstream `VG###` ids. These cover ground the AST scanners
don't: known-vulnerable framework versions (`next` 14.2.3 is still shipped by a
lot of AI scaffolds and carries CVE-2025-29927, a middleware auth bypass),
Dockerfiles, Terraform, GitHub Actions pinning, prompt injection and MCP tool
runtimes, React Native, Go and shell.

27 upstream rules are **superseded** where ClearToShip's own AST check is more
precise — permanently, since the vendored version was the noisier of the two —
6 are **withheld** as measurably noisy, 10 React Native rules are
**skipped as inapplicable** on a project that is not React Native, 21 carry a
**match guard** for a
shape their regex cannot exclude (a `"link": true` lockfile entry has no
integrity hash by design; `querySelectorAll` is not a SQL call; `eval()` inside
a sentence about eval is prose; a bounded agent loop written with the AI SDK's
current `stopWhen` is not an unbounded one), and 3 name-heuristic rules are
**manifest-only** — they never run over a `package-lock.json`, where they matched
ordinary transitive packages (`fast-glob`, `core-js`) and named nothing anyone
could act on. Each list carries a reason per rule in
`src/scanners/community.ts`. Run `--no-community` to use only ClearToShip's
rules. See [ATTRIBUTION.md](ATTRIBUTION.md).

Findings map to **OWASP Top 10:2025**, and the ones that are about an LLM or an
agent carry an **OWASP Top 10 for LLM Applications** category as well (in
`meta.llm`). ClearToShip's own rules and the gitleaks-derived credential rules
also name a **CWE**; the vendored GuardVibe rules do not, because upstream
publishes none and inventing one per rule would be a guess presented as a fact. The vendored ruleset labels categories inconsistently —
Injection arrives as both `A02:2025` and `A03:2025`, Security Misconfiguration
as `A05:2025` and `A05:2021` — so labels are normalised to one taxonomy on the
way out, with the original kept in `meta.owaspUpstream`.

New to these lists, or want a plain-language description of each category, who
publishes them, and a link to the source? See [docs/OWASP.md](docs/OWASP.md).
The two tables below are about what `cleartoship` detects, not what the
categories mean.

## OWASP Top 10:2025 coverage — honest version

ClearToShip is not an even, "100% coverage" scanner and does not claim to be —
it is strongest exactly where AI-generated code fails. Coverage by category:

| Category | Coverage | What we detect |
| --- | --- | --- |
| **A01** Broken Access Control | 🟢 Strong | Missing Server Action / route auth, RLS holes, IDOR, definer bypasses |
| **A03** Supply Chain Failures | 🟢 Strong | Hallucinated / slopsquat / typosquat packages, live CVEs (OSV), install hooks |
| **A07** Authentication Failures | 🟢 Strong | `getSession` misuse, weak sessions, JWT (mostly vendored) |
| **A02** Security Misconfiguration | 🟢 Strong | Docker, Terraform, headers, CORS — via the vendored pack |
| **A05** Injection | 🟢 Strong | SQLi, XSS, command injection |
| **A04** Cryptographic Failures | 🟡 Moderate | Hardcoded keys (234 credential patterns), weak hashing |
| **A09** Logging & Alerting Failures | 🟡 Targeted | **Secrets / PII written to logs** (CTS070) — the statically knowable slice |
| **A10** Mishandling Exceptions | 🟡 Targeted | **Fail-open / swallowed error on a security check** (CTS071) |
| **A08** Data & Integrity Failures | 🟡 Targeted | Unverified webhooks (CTS042), **insecure deserialization** (CTS072) |
| **A06** Insecure Design | 🔴 Not detectable first-party | Missing threat modeling is an architecture concern. 13 vendored rules carry the label; none of ClearToShip's own do, deliberately |

Counts, measured across the vendored ruleset after normalisation: A01 121,
A05 112, A04 78, A02 59, A03 32, A07 17, A06 13, A08 11, A09 2. ClearToShip's
own 46 rules add A01 23, A03 9, A04 5, A08 3, A05 3, and one each for A07, A09
and A10 — which is the category no vendored rule reaches.

## OWASP Top 10 for LLM Applications (2026) — coverage

Worth stating separately, because "we cover the OWASP Top 10" and "we cover the
LLM Top 10" are different claims and only one of them is usually meant. Mapped
against the **2026 edition**, published 4 August 2026 — which renumbered eight
of the ten: Excessive Agency moved 06 → 03, Unbounded Consumption 10 → 06,
Improper Output Handling 05 → 10, and System Prompt Leakage was renamed and
broadened into **Hidden Context Exposure**.

| Category | Rules | What we detect |
| --- | --- | --- |
| **LLM01** Prompt Injection | 12 + **CTS080** | Caller text interpolated into the instruction text itself; fetched pages and query results reaching a prompt unbounded; instructions hidden in a tool description |
| **LLM02** Sensitive Information Disclosure | 8 (+ CTS030, CTS031, CTS045) | Provider keys in client code or a `NEXT_PUBLIC_` variable, `dangerouslyAllowBrowser`, a base URL pointed at somebody else's endpoint |
| **LLM03** Excessive Agency | 9 + **CTS083** | MCP servers with permissive tool access, `allowedTools` wildcards, auto-approve bypassing the permission prompt, settings hooks that fetch or pipe; and a tool handed to a model whose body takes an action nobody can undo, with no approval step in it |
| **LLM04** Supply Chain | 1 | MCP server pinned to `@latest` |
| **LLM06** Unbounded Consumption | **CTS081** | A request-reachable model call with no `max_tokens` ceiling — the answer's length, and its cost, decided by whoever wrote the input |
| **LLM07** Misinformation | **CTS085** | Whether an answer is *true* is not a property of the source. What is in the source is the answer being **believed**: a branch, or a function that reads as a check, turning on what the model returned |
| **LLM08** Hidden Context Exposure | 1 + **CTS082** | A system prompt held in a `'use client'` module, so it ships in the bundle; a prompt returned in an error response |
| **LLM09** Vector & Embedding Weaknesses | 3 | Retrieval results interpolated into a prompt, unauthenticated vector upserts |
| **LLM10** Improper Output Handling | 4 + **CTS084** | Model output rendered as raw HTML or markdown images, or used in a dangerous sink — and, first-party, the answer followed from the call that produced it into `eval`, `new Function`, a shell, raw SQL or the DOM |
| **LLM05** Data & Model Poisoning | — | Needs training-pipeline and dataset provenance. Nothing in a web app's source tree answers it, and a rule that pretended otherwise would be box-checking |

The mapping is derived from each rule's own text rather than a hand-kept list of
ids, so re-vendoring upstream cannot silently drop it, and it is deliberately
conservative: a rule that does not clearly belong to a category gets none.

**Nine of ten have first-party or vendored detection. One does not, and will not
get a rule for the sake of the table** — LLM05 needs training-pipeline and dataset
provenance, and nothing in a web app's source tree answers it. A tool that claimed
it would be lying about what it checked, which is the failure mode this project
exists to avoid.

LLM07 left that group in 0.13.0, and it is worth being exact about how. Nothing here
judges whether an answer is true; that is still not a property of the source. What
the source does show is the answer being *trusted* — `if (verdict === 'safe')`, or a
function named like a check handing back whatever the model said. That is the
detectable half, it was named as missing in this table for two releases, and it is
now CTS085.

## Usage

Every command below runs the standalone file from the install step above.

```bash
node cleartoship.mjs                     # scan the whole project
node cleartoship.mjs app supabase        # scan specific paths
node cleartoship.mjs --offline           # no registry lookups
node cleartoship.mjs --fix-prompt        # prompt to paste into Cursor / Claude Code
node cleartoship.mjs --json -o report.json # machine-readable
node cleartoship.mjs --sarif -o results.sarif # GitHub code scanning
node cleartoship.mjs --fail-on high      # stricter CI gate (default: critical)
node cleartoship.mjs --ignore CTS004,CTS022 # skip rules
node cleartoship.mjs --no-community      # ClearToShip rules only
node cleartoship.mjs --no-gitignore      # also scan what .gitignore excludes
node cleartoship.mjs --markdown          # markdown report (PR comments / summaries)
```

Every flag:

| Flag | Default | What it does |
| --- | --- | --- |
| `[paths...]` | whole project | Files or directories to scan. A single directory outside the current one is treated as the project root. |
| `-C, --cwd <dir>` | current directory | Project root: framework detection, `.gitignore` and reported paths all hang off it. |
| `--fail-on <severity>` | `critical` | Exit 1 when any finding is at or above `critical`, `high`, `medium` or `low`. `none` always exits 0. |
| `--allow-incomplete` | off | Exit 0 instead of 3 when a check could not finish (see [Exit codes](#exit-codes)). |
| `--min-severity <severity>` | `low` | Hide findings below `critical`, `high`, `medium`, `low` or `info`. Display only: it is clamped to `--fail-on`, so it can quieten a report but never hide what fails the build. |
| `--only <ids>` | all | Comma-separated rule ids to report exclusively, e.g. `CTS001,CTS010`. |
| `--ignore <ids>` | none | Comma-separated rule ids to skip. |
| `--offline` | off | No network at all: no registry or OSV lookups. |
| `--no-community` | off | Only ClearToShip's own rules; skip the vendored community ruleset. |
| `--no-gitignore` | off | Also scan what `.gitignore` excludes. |
| `--json` / `--sarif` / `--markdown` | terminal report | Machine-readable JSON, SARIF 2.1.0, or a markdown report. |
| `--fix-prompt` | — | A ready-to-paste prompt for Cursor / Claude Code instead of the report. |
| `--badge` | — | Print the markdown status badge for your README. |
| `-o, --output <file>` | stdout | Write the chosen output to a file. |
| `--no-banner` | banner shown | Suppress the ASCII header. |
| `--quiet` | off | Terminal report lists findings only, not the checks that passed. |
| `--verbose` | off | Extra diagnostic output. |
| `-v, --version` | — | Print the version. |

Suppress a single finding inline:

```ts
// cleartoship-ignore CTS001 — invoked only by a cron job, never by a request
export async function reconcileBilling() { … }
```

`// cts-ignore` on its own suppresses every rule at that location. The directive
may sit at the top of a multi-line comment block, so a real justification has
room to be written out.

## Continuous integration

### The CLI (works anywhere, today)

Two lines in any workflow, on any CI — no package manager and no registry:

```yaml
      - run: curl -fsSL https://cleartoship.app/cleartoship.mjs -o cleartoship.mjs
      - run: node cleartoship.mjs --fail-on=critical
```

In CI you usually want the pinned, verified form: a versioned release URL, so
the build does not change under you, and the file's GitHub build-provenance
attestation checked before it runs (every release after 0.13.10 carries one):

```yaml
      - run: |
          curl -fsSL https://github.com/murtazaozdemir/cleartoship/releases/download/v0.13.13/cleartoship.mjs -o cleartoship.mjs
          gh attestation verify cleartoship.mjs --repo murtazaozdemir/cleartoship
        env: { GH_TOKEN: "${{ github.token }}" }
      - run: node cleartoship.mjs --fail-on=critical
```

The gate exits 1 on findings at or above `--fail-on`, and 3 when the scan could
not finish (a registry outage, a file that would not parse) — add
`--allow-incomplete` if an incomplete scan should pass. See
[Exit codes](#exit-codes).

To feed findings into GitHub's Security tab:

```yaml
      - run: node cleartoship.mjs --sarif -o results.sarif --fail-on=none
      - uses: github/codeql-action/upload-sarif@v4
        with: { sarif_file: results.sarif }
```

A copyable workflow is in [`examples/security-cli.yml`](examples/security-cli.yml).

### GitHub Action

Posts a summary comment on every pull request, blocks the merge on critical
findings, and optionally uploads to the Security tab. Copy
[`examples/security.yml`](examples/security.yml) into `.github/workflows/`:

```yaml
name: ClearToShip
on: [pull_request]
permissions:
  contents: read
  pull-requests: write
jobs:
  preflight:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: murtazaozdemir/cleartoship@v0.13.13
        with:
          fail-on: critical
          comment: true
```

| Input | Default | Purpose |
| --- | --- | --- |
| `paths` | *(whole project)* | Files or directories to scan |
| `fail-on` | `critical` | Fail the job at or above this severity (`critical`/`high`/`medium`/`low`/`none`) |
| `comment` | `true` | Post/update a sticky summary comment on the PR |
| `sarif` | `false` | Upload results to GitHub code scanning |
| `offline` | `false` | Skip registry and OSV lookups |
| `working-directory` | `.` | Directory to scan from |
| `version` | *(matches the action ref)* | Release to run: a version number, `latest` for the newest release, or `local` to build from the checkout |
| `allow-incomplete` | `false` | Pass the job even when a check could not finish. By default an incomplete scan fails the job, like the CLI's exit 3 |
| `github-token` | `${{ github.token }}` | Token for verifying the release bundle's attestation and posting the PR comment |

Outputs `resolved` (`release` — the attested release bundle ran — or `checkout`
— the action built its own source), `verdict` (`clear`/`conditional`/`hold`;
`conditional` is also what a run gets when a check could not complete, even
with no findings), the per-severity counts `critical`, `high`, `medium`, `low`,
plus `total`, `blocking` (findings at or above `fail-on`) and `incomplete`
(checks that could not finish), and the paths `report-json`,
`report-markdown` and `sarif-file`. Reports are written under `$RUNNER_TEMP`,
never into your checkout. The comment is *sticky* — re-runs edit the same
comment instead of piling up — and is skipped on pull requests from forks,
whose token cannot write one; the report is in the job summary either way.

The job fails with findings at or above `fail-on`, or — when nothing blocks —
if the scan was incomplete and `allow-incomplete` is not set. `fail-on: none`
turns both off.

By default the action runs the release bundle for the version its own ref
declares, so `@v0.13.13` runs ClearToShip 0.13.13 and pinning the ref pins the
behaviour. Before running a downloaded bundle it verifies the bundle's GitHub
build-provenance attestation (`gh attestation verify`: built by this
repository's release workflow, from that version's tag) and that it reports
the expected version; a bundle that fails either check fails the job rather
than being swapped for something else. Releases from before attestations
existed (0.13.10 and earlier) are never downloaded — the action builds its own
checkout of that version instead. If the version has no release yet, it builds
from its own checkout too, so `uses: …@ref` works against an unreleased commit.
It never fetches or runs anything from the npm registry under ClearToShip's
name.

## How it works

Seven scanners, all static: your source is read and parsed, never executed, never
uploaded, and no database is connected to. They run in this order, and each
only when it applies to the project (a repo with no Next.js or SQL skips those).

1. **Dependencies** — resolves every declared dependency against npm and PyPI,
   flagging names that do not exist at all, names registered days ago with no users, and names
   one edit away from a popular package. Registry answers are cached for 24h under
   `~/.cache/cleartoship`. Then **known vulnerabilities**: dependency versions are resolved from
   `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` (falling back to the range floor)
   and queried against OSV.dev, the database behind Google's `osv-scanner` — live, never
   cached. Live data beats hand-written version regexes, which go stale the week they are
   written — so when OSV answers, the vendored CVE rules stand down. `--offline` reverses that.
2. **Server Actions & Route Handlers** — parses TS/TSX with Babel, finds every exported
   function reachable over HTTP (`'use server'` modules, inline directives, `app/**/route.ts`
   method exports), then asks whether it authenticates, validates and scopes its writes.
   Recognises `next-safe-action` / `zsa` style wrappers so wrapped actions are not
   double-reported.
3. **Row Level Security** — replays your `.sql` migrations in filename order to build a model
   of the resulting schema (tables, columns, RLS state, policies, grants, views, functions),
   then judges the end state. This is the same class of check as Supabase's own `splinter`
   linter, but static, so it runs on a pull request with no live database.
4. **Secrets & client boundary** — pattern plus verification: candidate JWTs are decoded and
   only reported when the payload actually says `role: service_role`. 15 hand-tuned patterns
   cover the providers that matter most; 219 more come from the vendored gitleaks ruleset,
   each gated on a keyword prefilter and a Shannon entropy threshold so that
   `your_api_key_here` never reads as a breach. Values in test fixtures, docs and
   commented-out counter-examples are downgraded rather than reported.
5. **Logging, exception-handling & deserialization** — CTS070–072: secrets, PII or a whole
   request body written to a log; a security check that fails open or swallows its error;
   untrusted data handed to `pickle.loads`, `unserialize` or an unsafe YAML loader.
6. **LLM & agent risk** — CTS080–085: collects every binding that holds what a model
   returned and follows it into the sinks that would run or trust it, and reads each agent
   tool's body for an irreversible action with no approval step. See the design notes below.
7. **Community ruleset** — the 435 vendored GuardVibe rules that remain after the
   superseded and withheld ones are taken out, over the ground the AST scanners do not
   cover (Dockerfiles, Terraform, GitHub Actions, MCP runtimes, Go, shell).

### Design notes

- **Fail open on uncertainty — and say so.** If a registry lookup fails, the package is treated
  as valid: a network blip must never be reported as a hallucinated dependency. But a lookup that
  failed is not a check that passed. The report counts what was actually looked up ("0 of 3
  packages checked"), says why as a warning, and the verdict is `conditional` — never `clear` —
  for any run in which a check could not complete (npm/PyPI or OSV unreachable, a scanner that
  threw, a path that was not there, a file that could not be parsed or read). The JSON
  `incomplete` array lists the reasons, and the exit code is **3** unless `--allow-incomplete`
  is passed: a build that was gated on "no findings" should not pass on a scan that did not
  finish. Findings at or above `--fail-on` still exit 1 first, and `--fail-on none` exits 0.
  If you would rather an npm or OSV outage never blocks a deploy, pass `--allow-incomplete`
  (the report still says what was not checked) or run `--offline`.
- **Test fixtures are not breaches.** Credentials under `tests/`, `fixtures/`, `docs/` or in a
  commented-out line are reported at `low`, never as blocking criticals.
- **Where a file lives changes what a finding costs.** CTS024 already separated a
  CVE that ships from one that only ever runs on your machine; the same reasoning
  now covers the rules that read code. An interpolated query in `scripts/`, a
  swallowed error in a `*.config.ts` — build and maintenance tooling runs with
  credentials its author already holds and never answers a request from the
  internet, so those drop one severity step, with the reason attached to the
  finding rather than applied silently. `bin/` and `migrations/` are deliberately
  excluded: one is a published CLI's entry point, the other is production schema.
  Across five dogfooded repos this moved 21 findings out of `critical` without
  hiding one of them.
- **A CVE that only runs on a build machine is not a shipping vulnerability.**
  CTS024 already split those when OSV answers; the vendored CVE rules — what
  runs under `--offline` — now make the same split, dropping a match under
  `devDependencies` (or a lockfile entry marked `"dev": true`) to `low` with the
  reason attached. The same advisory against a dependency your users run keeps
  its full severity.
- **A bound parameter is not an injection.** `db.prepare(\`UPDATE ${table} SET
  csv = ? WHERE id = ?\`).bind(...)` interpolates an identifier while its values
  go through placeholders — the correct pattern, and the one a SQL-injection
  regex reads as the bug. Both SQL rules now read the whole statement and the
  call chained to it, and stand down when the values are bound. They still fire
  when any interpolation reads from the request, so a query that binds one value
  and concatenates another is reported.
- **The scan stays inside the directory you pointed at.** A symlink that
  resolves outside the scan root is not followed. It sounds academic until you
  run this in CI on a pull request: `vendor-config -> /home/runner/.ssh` would
  otherwise be read, and quoted, into a public comment. Every read is checked
  the same way — the file's real path must sit under the scan root — so a link
  the walk did not see (a manifest, an ignore file) cannot escape either.
  Symlink loops are walked once rather than a dozen times, and the report says
  how many links were refused.
- **A report is safe to post.** Anything that looks like a secret is redacted
  in every snippet, whichever rule found it, and text that came from the
  repository (file names, matched lines) is escaped in the markdown and
  terminal output, so a file named to look like markup or a terminal escape
  sequence cannot rewrite the PR comment or your terminal.
- **A match in a comment is prose about code, not code.** The scanner lexes each
  file once for strings and comments — properly, tracking quotes, so a URL
  inside a string is not mistaken for the start of one — and a community rule
  that matched inside a comment is dropped. Our own source found this: a comment
  reading *"merely calling `jwt.verify(token, secret)`"* was reported as a JWT
  vulnerability.
- **A rule that cannot apply here is not run.** The vendored ruleset covers
  ground this project may not stand on: certificate pinning and WebView
  hardening are React Native concerns, and a browser will not let a page pin a
  certificate at all, so those rules are skipped unless the project actually is
  React Native. Likewise the "no request-body size limit" rule, whose own text
  says Next.js already imposes one. The report names what it skipped and why.
- **Mass assignment means the payload arrives whole.** CTS002 and CTS043 fire when
  the object the caller sent reaches the columns — `update(body)`,
  `data: { ...input }`, including one level down where Prisma and Drizzle put it.
  Reading named fields into an explicit column list is the safe pattern and is
  never reported, whether or not a schema library was involved: of 102 findings
  the old, broader rule produced on one dogfooded app, all 102 were that shape.
- **Precision over recall on the noisy rules.** Typosquat matching skips exact matches and
  names shorter than five characters, where one-edit neighbours are meaningless.
- **Your `.gitignore` decides what counts as your project.** Ignored paths are
  not scanned: they never reach a CI checkout, so a finding there is one nobody
  can act on and nobody's pipeline would reproduce. This is usually the
  difference between a usable report and an unreadable one — a repo with a
  gitignored folder of reference apps went from 1,487 findings to 235, and from
  84 seconds to 2. `.env` files are the deliberate exception, since a secret on
  your disk is a secret either way and CTS032 exists to check that the file *is*
  ignored. `--no-gitignore` scans everything, and the report always says how many
  paths were skipped. A file git already tracks is scanned whatever `.gitignore`
  says: the scanner reads `.git/index`, so a pull request cannot hide a
  committed file from the scan by adding an ignore rule for it.
- **Auth is followed into the helper it lives in.** Almost no real app repeats the
  session check inside every action — it resolves in `lib/auth.ts`, or in a
  framework helper such as Shopify's `handleSessionToken`, and each action calls
  that. ClearToShip resolves first-party imports (relative paths and `@/`-style
  aliases) and credits a call whose helper authenticates, directly or through
  another helper. Third-party packages are never followed, so a call into
  `node_modules` still proves nothing on its own.
- **A rule about model output has to prove the output came from a model.**
  `dangerouslySetInnerHTML` is everywhere — theme scripts, chart CSS, sanitized
  markdown — and reporting all of it would be a regex, not a finding. CTS084 and
  CTS085 first collect every binding in the file that holds what a model
  returned, following it through the shapes the SDKs actually produce
  (`const { text } = await generateText(...)`, `message.content[0].text`,
  `completion.choices[0].message.content`) and one hop onward, then ask whether
  *that* value reaches the sink. Across five dogfooded repos the rules fired
  zero times; on a probe corpus written to break them, `SLUG.exec(slug)` and
  `seen.delete(key)` on a `Map` stayed silent while a Supabase delete, a Drizzle
  delete and a two-hop Anthropic answer reaching `execSync` all fired.
- **An approval gate is code, not a description.** CTS083 stands down when
  something in the tool puts a person in front of the effect — a confirmation, a
  permission check, `needsApproval: true`. That test reads identifiers and
  property keys only, never string values: a tool whose `description` says
  "review this before approving" has written prose, and prose must not be able
  to talk the rule out of firing.
- **Writing a row is not excessive agency.** An agent that inserts and updates is
  the ordinary case, and reporting it would bury CTS083 in its own output. What
  it reports is the subset a wrong answer cannot be undone from: rows deleted,
  money moved, mail sent to somebody, a shell command, a file removed.
- **A machine endpoint authenticates differently.** Comparing an `Authorization`
  header against a server-side secret is the auth check for a cron or
  webhook route, and a verified provider signature *is* the caller's identity —
  neither is reported as missing authorization.

## Trust

A security tool earns its place by being auditable, so the guarantees are stated
plainly and each one is checkable in a few seconds. `SECURITY.md` has the full
version, including how to report a vulnerability.

- **Read-only on your code.** The only files ClearToShip writes are the report
  you ask for with `--output` and its 24-hour registry cache under
  `~/.cache/cleartoship`. Nothing under the scan root is ever modified.
- **Your code is never executed.** No `child_process`, no `eval`, no dynamic
  import of a scanned file. Everything is text, an AST and regexes — which is
  also why it is safe to point at a repository you have not read yet.
- **No source leaves the machine.** Online, four hosts are contacted:
  `registry.npmjs.org`, `api.npmjs.org` and `pypi.org` receive package
  **names**, and `api.osv.dev` receives package **names and versions**. No file
  contents, no paths, no project name. `--offline` disables all four and makes a
  run a pure local computation.
- **Nothing is loaded by name at run time.** Every scanner is compiled into the
  build you run. ClearToShip never imports a module it finds next to it or in the
  project's `node_modules`, so scanning a repository cannot run that repository's
  code — including a package that happens to be named after this project.
- **No database connection.** The RLS checks read your migration files.
  There is no database driver in the dependency tree.
- **Five runtime dependencies.** Three Babel packages, `commander`,
  `picocolors`. The GuardVibe and gitleaks rulesets are vendored into
  `src/vendor/`, not installed, so they are visible in every diff and pinned by
  construction.

## Programmatic use

The library API needs the package itself, which is attached to each GitHub
release as `cleartoship-<version>.tgz` (the standalone bundle above is the CLI
only). Install that file with `npm i -D ./cleartoship-<version>.tgz`; its five
runtime dependencies still come from npm.

```ts
import { scan, renderJson } from 'cleartoship';

const result = await scan({ root: process.cwd(), offline: true });
console.log(result.counts); // { critical: 0, high: 2, medium: 1, low: 0, info: 0 }
```

Findings come back in `result.findings`, each in the same `Finding` shape as in
the CLI's JSON output.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clear to ship at the configured `--fail-on` threshold, and every check finished (or `--allow-incomplete` was passed). `--fail-on none` always exits 0. |
| `1` | Findings at or above the threshold. Takes precedence over 3. |
| `2` | The scanner itself crashed (bad arguments, an unexpected error) |
| `3` | Nothing at or above the threshold, but the scan is incomplete: a check could not finish — a file that failed to parse or could not be read, a registry or OSV outage, a scanner that threw, a file too large for a ruleset. The report's `incomplete` list says what. `--allow-incomplete` turns this into 0. |

## Prior art, and what was taken from where

ClearToShip occupies the gap between general-purpose scanners and the modern AI-assisted
stack. It is not a replacement for [Semgrep](https://github.com/semgrep/semgrep),
[Trivy](https://github.com/aquasecurity/trivy), [OSV-Scanner](https://github.com/google/osv-scanner)
or [TruffleHog](https://github.com/trufflesecurity/trufflehog) — run those too. It answers a
narrower question they don't: *given that an LLM wrote this, what did it forget?*

The rule set was designed after surveying the field. What each source contributed:

| Source | License | What was taken |
| --- | --- | --- |
| [supabase/splinter](https://github.com/supabase/splinter) | none stated | The vulnerability classes behind CTS010–019 and CTS050–052. Splinter runs SQL against a live database; these are static reimplementations against migration files. Verified by pointing ClearToShip at splinter's own `test/sql/` fixtures. |
| [slopcheck](https://github.com/mattschaller/slopcheck) | MIT | Three distinctions worth making: HTTP 451 (pulled for malware) ≠ 404 (never existed) ≠ unpublished-with-installs (open to takeover) — CTS026/CTS027. And the idea of reading install commands out of prose and agent instruction files. |
| [guardvibe](https://github.com/goklab/guardvibe) | Apache-2.0 | Coverage gaps: webhook signature verification, cron secrets, mass assignment, `dangerouslyAllowBrowser`, schema escape hatches, `getSession` vs `getUser` — CTS040–046. |

**No rule content was copied.** Every check here is an independent implementation, and the
detection engine is different in kind: ClearToShip parses TypeScript to an AST and replays SQL
migrations into a schema model, where the regex-and-window approach used by several of these
tools cannot express "this function has no auth check anywhere in its body".

That distinction is not just technical pride — it is a licensing constraint. Two of the most
tempting corpora, **TruffleHog** (800+ verified credential detectors) and
**RouteWarden**, are **AGPL-3.0**; lifting their detectors into a commercial product carries
the AGPL's network-use obligations. **semgrep-rules** ships under the bespoke *Semgrep Rules
License v1.0*, which needs reading before any rule is reused. **splinter** and
**supabase-exposure-check** publish no license at all, which means default copyright — ideas
are free, expression is not. Vulnerability classes are facts and cannot be owned; regexes,
queries and rule text can be.

## License

MIT — this package (`cleartoship`), always, including every rule listed above.
Any paid tier added later would be new rules in a separate package under its own
license; it would not change what is MIT here, the same way vendoring GuardVibe
and gitleaks under their own licenses (`ATTRIBUTION.md`, `LICENSES/`) doesn't
either.
