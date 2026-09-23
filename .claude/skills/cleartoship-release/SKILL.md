---
name: cleartoship-release
description: How to ship ClearToShip and verify that it actually shipped — releases, tags, the Cloudflare-hosted download, the landing page, version pins in the docs, self-scan coverage, and the rule-calibration bar. Use this whenever the work touches releasing, publishing, tagging, bumping a version, a failing or suspicious CI run, `release.yml` / `ci.yml` / `deploy-site.yml` / `action.yml`, the GitHub Action, the site/ Worker, or adding or loosening a scanner rule — and also when a run looks green but you have not yet seen the artifact it was supposed to produce, which is the case this exists for.
---

# Shipping ClearToShip

The governing idea, and the reason for everything below: **a green step is not a
shipped artifact.** Every outage this project and its sibling `aistoreaudit`
have had looked like success from inside CI. Nothing here is theoretical — each
rule is followed by the incident that produced it.

So the habit to build is: after anything meant to ship, go and look at the thing
that was supposed to change. Not the exit code, not the checkmark — the artifact.

## Verify the artifact, not the step

| What you did | What proves it worked |
| --- | --- |
| Served the bundle from the domain | `curl -fsSL https://cleartoship.app/cleartoship.mjs \| shasum -a 256` equals the hash of the release's `cleartoship.mjs` — `deploy-site.yml` compares them itself after every deploy |
| Deployed the landing page | `npx wrangler deployments list --name cleartoship` shows a *new* version id |
| Cut a GitHub release | `gh release view v<version>` lists the expected assets, and one downloads and runs |
| Attested the release | `gh release download v<version> -p cleartoship.mjs -R murtazaozdemir/cleartoship && gh attestation verify cleartoship.mjs -R murtazaozdemir/cleartoship` passes — the Action refuses to run a bundle for which this fails |

If you cannot state which command you ran to confirm it, it is not confirmed.

This table is for ClearToShip only. The sibling app `aistoreaudit` has the same
rule and its own commands, and `/Users/Shared/CLAUDE.md` is where those live —
read them there rather than copying them here. One operational fact in two
places is how the stale one survives, which is the same failure this repo keeps
fixing in its own docs.

**Why.** On 2026-09-03 the `v0.13.4` release run reached `Check the npm token`,
failed 401, and skipped publish, registry-verify and the GitHub Release. The job
was red, but the more dangerous shape is the quiet one: `aistoreaudit` twice ran
stale code in production for days — once because GitHub billing killed runs in
~2 seconds *before the job started*, swallowing two releases whole, and once
because a missing `CLOUDFLARE_API_TOKEN` failed in ~8 seconds while four commits
piled up undeployed. Both looked fine from the commit list.

A registry answer can lie by looking healthy, too. When `cleartoship` was
unpublished, `https://registry.npmjs.org/cleartoship` still returned **HTTP 200**
— with `versions: {}` and empty `dist-tags`. Check the content, not the status.

## Releasing

The tag is the release. `release.yml` fires on `push: tags: ['v*']` and nothing
else — merging to `main` publishes nothing.

**ClearToShip is not published on npm.** The maintainer cannot use npmjs.com, and
the package name is unclaimed, so a package by that name on the registry is not
ours. A release is a GitHub Release with the bundle attached, and
`cleartoship.app` serving that same file. Nothing in a release talks to the
registry to publish.

1. Bump `package.json` and the two root `version` fields at the top of
   `package-lock.json`.
2. Update every version literal in the docs — see below.
3. Commit and push; let CI go green on `main`. Then tag and push the tag.
4. Watch the run, then **verify the artifact** per the table above.

`release.yml` is two jobs, split by trust. `build` has a read-only token and no
persisted credentials: it checks the tag against `package.json`, runs
`scripts/check-version-pins.sh`, `npm ci`, build, test and the self-scan, builds
the three assets, checks the bundle reports this version and carries its licence
texts, and uploads them as an artifact. `publish` never checks out or installs
the repository: it downloads the assets, signs **build-provenance attestations**
for all three (`actions/attest-build-provenance`), attaches them to a **draft**
release, publishes it, then re-downloads `cleartoship.mjs` and runs
`gh attestation verify` and `--version` on it the way a consumer would, and
dispatches a site redeploy.

The Action depends on those attestations: it verifies a downloaded bundle
against `release.yml` and the version's tag before running it, and fails closed
if that does not pass. Releases up to 0.13.10 have no attestation, so the Action
builds those from its own checkout instead.

`deploy-site.yml` fetches the release for the exact version in `package.json`,
so the download matches the source that deployed it, and compares the served
file's hash with the release asset. With no release for that version yet (a
bump merged before its tag), it serves the **latest** release's bundle rather
than deploying the site without its primary download, and `release.yml`'s
dispatch replaces it with the exact version once the tag ships. Attested
bundles are verified before they are served.

Re-running a tag: a release still in **draft** (a run that died part way) gets
its assets re-uploaded with `--clobber` and is then published. A release that is
already **published** is never overwritten; the re-run passes only if its assets
are byte-identical to the new build. A different build ships as a new version.
That also keeps the workflow working with immutable releases turned on. A re-run
uses the workflow file as it was **at that tag**, so it cannot pick up a fix made
afterwards: `v0.13.6` is red for that reason and stays red.

### Distribution

- `curl -fsSL https://cleartoship.app/cleartoship.mjs -o cleartoship.mjs && node cleartoship.mjs`
  — the primary path: one bundled file, no dependencies.
- The same file at `…/releases/latest/download/cleartoship.mjs`, and
  `cleartoship-standalone.tgz` (the same bundle as an installable package).
- `npm i -D github:murtazaozdemir/cleartoship --allow-git=all --allow-scripts=cleartoship`
  — builds on install via the `prepare` script. Still needs the registry for the
  five runtime dependencies, but not for this package. `prepare`, not
  `prepublishOnly`: npm runs `prepare` on git installs.
- `cleartoship-X.Y.Z.tgz` — the full package, for the library API.
- The GitHub Action: the attestation-verified release bundle, or a build of its
  own checkout when that version has no verifiable release. It never runs
  `npx cleartoship`: with the name unclaimed, that executes whatever a stranger
  registered under it. `package.json` is `"private": true` so an accidental
  `npm publish` is refused; `npm pack` is unaffected.

The standalone artifact must stay behaviourally identical to the package it
stands in for; the suite asserts they produce the same findings. A fallback that
behaves differently from the tool you tested is not a fallback.

## Version literals in the docs

`action.yml` resolves its own version at runtime rather than naming one, because
that line was twice left stating the previous release during a bump. Prose
cannot do that, so `scripts/check-version-pins.sh` asserts it, run by both
`ci.yml` and `release.yml`: every `cleartoship@vX.Y.Z`,
`cleartoship/releases/download/vX.Y.Z` and footer `class="pill">vX.Y.Z` in
`README.md`, `examples/*.yml` and `site/public/*.html` must equal
`package.json`.

**Why the site is in it.** The landing page said `v0.8.0` — in its Action
snippet and its footer — through five minor releases, live, because the check
only read the README and one example.

When adding a new versioned string to the docs, extend that script's pattern or
— better — use a version-free URL, which is why the standalone asset is named
without a version so `/releases/latest/download/` works forever.

## Self-scan coverage

CI scans `src site examples scripts .github` plus the manifests and docs, not
`src` alone. That matters because the README, `package.json`, `action.yml` and
the landing page are all part of what this publishes.

**Why.** While CI scanned only `src`, the tool reported a false positive on its
own README — `npx cleartoship` read as a suspicious new dependency — through a
whole release, because the file was never scanned. Widening the scan immediately
caught a credential-shaped literal in a source comment written that same
afternoon.

Never add a project-specific directory name to `SKIP_DIRS` in
`src/utils/files.ts`. `site` and `_reference` were once on that list, which meant
every user with a `site/` directory had that entire subtree reported clean
without a single file being opened. Everything on that list must be regenerable
in *any* repository, not just this one.

The self-scan runs online and without `--allow-incomplete`, in CI and in the
release build. An npm or OSV outage therefore makes it exit 3 (incomplete).
Re-run it; do not add `--offline` or `--allow-incomplete` to get a green check,
because a scan that did not finish is exactly what this tool refuses to call
clear.

More generally: when the scanner declines to read something, say so in the
report. Gitignored paths, skipped directories, oversize files and truncated
match lists are all counted and surfaced, because "no findings" must never be
silently indistinguishable from "nothing was read".

## Changing a rule

The bar for this project is unusual and worth respecting.

**Removing a false positive: read the code it fired on.** Never loosen a
threshold to make a finding go away. Every removal in this project's history was
verified by reading the actual code that triggered it, and that is what makes
the report trustworthy. A rule that fires on correct code is a worse bug than a
rule that misses something — one wastes an afternoon and teaches people to
ignore the tool.

**Adding a rule: it must name a specific wrong thing a developer would act on.**
Mapping neatly onto a compliance table is not sufficient. Several categories are
*deliberately* uncovered (`TODO.md` lists them with reasons); adding rules for
them would be box-checking, which is the failure mode this project exists to
avoid.

**Write the assertion that could fail.** The CVSS severity mapping was dead for
a year — OSV publishes `severity[].score` as a vector string, so `Number()`
returned `NaN` and every advisory defaulted to `high`. The test meant to catch
that asserted `notEqual(severity, 'low')`, which passes whether the mapping works
or not. Assert the value, not the absence of the worst case.

**A test that skips is a test that is not running.** Three network-gated tests
skipped silently on the maintainer's machine for months and were only observed
passing when a CI run happened to surface them. If a test can skip, know what
makes it skip and confirm it runs somewhere.

## Local environment

`node` on the PATH is below this project's floor (`^22.18.0 || >=24.11.0`, which
is Babel 8's own range copied exactly). Use Homebrew's:

```bash
export PATH="/usr/local/opt/node/bin:$PATH"
```

This is not pedantry. Below the floor, Babel fails at *parse* time — and an
unparsed file produces no findings, not an error. The worst failure available to
a scanner is reporting clean on code it never read.
