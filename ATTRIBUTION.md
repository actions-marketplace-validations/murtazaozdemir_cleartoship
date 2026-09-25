# Attribution

ClearToShip vendors and adapts work from other projects. This file records what,
from where, and under which licence.

## Vendored code

### GuardVibe — `src/vendor/guardvibe/`

- Source: https://github.com/goklab/guardvibe
- Copyright 2026 GokLab
- Licence: Apache License 2.0 — full text in `LICENSES/guardvibe-Apache-2.0.txt`,
  upstream NOTICE in `LICENSES/guardvibe-NOTICE.txt`

468 security rules are vendored under `src/vendor/guardvibe/rules/`. Rule
content — ids, patterns, names, descriptions, fixes — is **unmodified** in those
files. The changes to the files themselves are: a provenance header added to
each, **import paths rewritten** for this package's layout (e.g. `./types.js`),
and an aggregating `index.ts` written by this project.

Modifications to how the rules behave, stated here as Apache-2.0 §4(b)
requires, are all made at runtime in `src/scanners/community.ts` (and, for
the CVE rules, `src/scan.ts`) rather than in the vendored files:

- **27 rules are superseded** by ClearToShip's own AST and schema checks, which
  reason over a whole function body or a replayed migration rather than a fixed
  character window. Running both would double-report the same defect and import
  the less precise location. Each is listed with the rule that replaces it
  (`SUPERSEDED`).
- **6 rules are withheld** as measurably noisy in this tool's context — for
  example `VG543`, which matches `; DROP|DELETE|INSERT …` anywhere in a `.sql`
  file and therefore fires on the normal shape of every migration. Each is
  listed with its reason (`WITHHELD`).
- **Rules for a platform the project does not use are skipped**: the 10 React
  Native rules unless the project is React Native; rules naming Supabase or
  Firebase unless that is a dependency; and `VG132` (request-body size limit)
  on Next.js, which already imposes one. The report names what was skipped.
- **21 rules carry a match guard** (`MATCH_GUARDS`): an extra test a match must
  pass, for a shape the upstream regex cannot exclude — a `"link": true`
  lockfile entry has no integrity hash by design, `querySelectorAll` is not a
  SQL call, `eval()` inside a sentence is prose, a bounded agent loop written
  with the AI SDK's `stopWhen` is not unbounded.
- **3 rules are manifest-only** (`MANIFEST_ONLY`): they are not run over
  lockfiles, where they matched ordinary transitive package names.
- **Most rule patterns run on a linear-time matcher, not V8's regex engine.**
  209 of the 435 active upstream patterns took over 50 ms on 400 KB of hostile
  input and 125 over 8 s (`eval.*\(` alone: 50 s in one `exec`), so one crafted
  file in a pull request could stall a scan. 382 of the 435 now run their
  unchanged pattern through a memoizing matcher in `src/scanners/community.ts`
  that returns the same matches, in the same order, as V8 would — verified with
  0 differences over 27,391 matches in 129 MB of real code. 52 stay on V8
  because they are provably linear there, and 1 (`VG1094`) because it needs a
  backreference. 4 patterns (VG678, VG974, VG533, VG958) are additionally
  replaced by bounded equivalents, each listed with its reason. The same
  matcher runs the vendored gitleaks rules, two of which (`cohere`,
  `private_ai`) nest bounded lazy repeats. The vendored files keep the original
  patterns; a per-rule time budget remains as a last line of defence.
- **A match inside a comment is dropped.** Nothing in the ruleset targets
  comment content, and a commented-out call is not a call.
- **Severity adjustments**: a vendored CVE rule matching a package under
  `devDependencies` (or a lockfile entry marked `"dev": true`) is reported at
  `low`; `VG105` is reported at `medium` unless the match actually accepts
  `alg: none`; findings in test, fixture and documentation paths are reported
  at `low`, and in build and maintenance tooling (`scripts/`, `*.config.*`) one
  severity step lower. Each adjusted finding says why in its text.
- **The vendored CVE-version rules stand down when OSV answers**, since live
  advisory data supersedes a hard-coded version range; with `--offline` they
  are the fallback.
- **OWASP labels are normalised** onto one 2025 taxonomy (upstream mixes
  editions); the original label is kept in `meta.owaspUpstream`.
- At most three matches per rule per file are reported, and files over 400 KB
  are not run through the ruleset; the scan is then reported as incomplete for
  them rather than clean.

Every vendored finding carries `meta.source: "guardvibe"` and its attribution
string, so provenance survives into JSON and SARIF output.

### gitleaks — `src/vendor/gitleaks/rules.ts`

- Source: https://github.com/gitleaks/gitleaks (`config/gitleaks.toml`)
- Copyright (c) 2019 Zachary Rice
- Licence: MIT — full text in `LICENSES/gitleaks-MIT.txt`

221 of 222 credential detection rules are converted from the upstream TOML into
a generated TypeScript module by `scripts/vendor-gitleaks.mjs`. Rule ids,
descriptions, entropy thresholds and keyword prefilters are carried over
unchanged.

Modifications:

- **Regex dialect.** Upstream patterns are Go RE2. A leading `(?i)` becomes the
  JavaScript `i` flag and `(?P<n>)` becomes `(?<n>)`. 37 rules use *scoped*
  inline flags — `(?i:…)`, `(?-i:…)` — which JavaScript has no equivalent for;
  rather than drop them, the flag is hoisted to the whole pattern. The cost is
  precision, not safety: a prefix upstream matched case-sensitively now matches
  either way, and every match still has to clear the entropy threshold. One rule
  could not be converted and is omitted.
- **2 rules are withheld** as noisy, each with its reason in
  `src/scanners/secrets.ts`: `generic-api-key` (gitleaks' own catch-all — 97 of 118 hits across the
  reference corpus were false, including ordinary arrays of method names) and
  `sourcegraph-access-token` (matches any 40-character hex string, so every
  SHA-pinned GitHub Action reads as a leaked token).
- Per-rule allowlists are not carried over; ClearToShip applies its own
  placeholder, entropy, hex-digest and fixture-path filters instead.

Findings carry `meta.source: "gitleaks"` and the attribution string.

## Services queried

### OSV.dev

Known-vulnerability data comes from https://osv.dev via its public HTTP API —
the same database behind Google's `osv-scanner` (Apache-2.0). Nothing is
vendored and no licence attaches; ClearToShip queries the API at scan time.

This is why the vendored CVE-version rules stand down whenever OSV answers: a
rule that hard-codes "next before 14.1.1" is stale the week after it is written,
while OSV is current. Offline (`--offline`), the vendored rules are the fallback.

## Ideas adopted, code not copied

These informed the rule set. No code, regex or rule text was taken.

| Project | Licence | What it informed |
| --- | --- | --- |
| [supabase/splinter](https://github.com/supabase/splinter) | none stated | The vulnerability classes behind CTS010–019 and CTS050–052. Splinter queries a live database; ClearToShip reimplements these statically against migration files. |
| [slopcheck](https://github.com/mattschaller/slopcheck) | MIT | Distinguishing HTTP 451 (pulled for malware) from 404 (never existed) from unpublished-with-installs (open to takeover) — CTS026/CTS027 — and reading install commands out of prose and agent instruction files. |

## Licence status of every candidate considered

Verified against the GitHub API and the repositories' own LICENSE files, because
second-hand licence claims about these projects are frequently wrong.

| Project | Actual licence | Usable in a commercial SaaS? |
| --- | --- | --- |
| gitleaks | MIT | **Yes** — vendored above |
| google/osv-scanner | Apache-2.0 | Yes (we use the OSV API rather than the binary) |
| aquasecurity/trivy | Apache-2.0 | Yes |
| dependency-check/DependencyCheck | Apache-2.0 | Yes |
| projectdiscovery/nuclei + templates | MIT | Yes (DAST — needs a running app, out of scope here) |
| zaproxy/zaproxy | Apache-2.0 | Yes (DAST) |
| OWASP/Nettacker | Apache-2.0 | Yes (recon) |
| goklab/guardvibe | Apache-2.0 | **Yes** — vendored above |
| octokit, probot, babel, zod, shadcn/ui | MIT / ISC | Yes |
| semgrep/semgrep | **LGPL-2.1**, not Apache | Only as a subprocess. LGPL is copyleft; invoking the CLI is fine, linking it into the product is not. Its *rules* are separately under the Semgrep Rules License. |
| trufflesecurity/trufflehog | **AGPL-3.0** | No, unless ClearToShip itself ships under AGPL. gitleaks is the permissive equivalent and is what we used. |
| elicosilva/RouteWarden | AGPL-3.0 | Same. |
| wapiti | GPL-2.0 | Subprocess only. |
| sqlmap, nikto | GPL-2.0 | Subprocess only. |
| **Bearer/bearer** | **Elastic License 2.0** | **No.** ELv2 specifically prohibits providing the software to third parties as a hosted or managed service — which is precisely what a ClearToShip SaaS would be. It is not an open-source licence. |
| supabase/splinter | **none** | No licence file means no licence granted. Ideas only. |
| bscript/supabase-exposure-check | none | Same. |

Taking a part rather than the whole does not change any of this: copyright and
the AGPL both apply to substantial portions, not only to entire programs. What
is genuinely free to take is the *idea* — the class of vulnerability, the fact
that a check is worth making. Expression (regexes, queries, rule prose) is not.
