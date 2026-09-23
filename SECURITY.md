# Security

ClearToShip is a security tool, so it asks for the same scrutiny it applies. This
document states exactly what it does on your machine, what leaves it, and how to
check both for yourself rather than take it on faith.

## Reporting a vulnerability

Report privately through the repository's **Security → Report a vulnerability**
tab (GitHub private vulnerability reporting). Please include the version
(`cleartoship --version`), the smallest input that reproduces the problem, and
what you expected instead. Non-sensitive bugs — a false positive, a crash on a
weird file — belong in a normal issue.

Fixes ship in a patch release. The `latest` published version is the only
supported one; older versions are not backported.

## Where to get it — and where not to

ClearToShip is distributed through [cleartoship.app](https://cleartoship.app) and
the [GitHub releases](https://github.com/murtazaozdemir/cleartoship/releases) of
this repository, and nowhere else. **It is not published on npm.** A package named
`cleartoship` (or `cleartoship-rules-pro`) on the npm registry did not come from
this project: do not `npx` it or install it, and report it through the private
vulnerability reporting above. `SHA256SUMS` on cleartoship.app lists the checksum
of the downloadable file — which catches a corrupted download, not a compromised
host, since it comes from the same place.

The check that does not depend on trusting a host: every release after 0.13.10
carries a GitHub **build-provenance attestation** for `cleartoship.mjs` and both
tarballs, signed by this repository's `release.yml` from the release tag.

```bash
gh attestation verify cleartoship.mjs --repo murtazaozdemir/cleartoship
```

The GitHub Action runs that verification itself (pinned to `release.yml` and the
version's tag) before it runs a downloaded bundle, and fails rather than running
one that does not verify. Releases up to and including 0.13.10 predate
attestations; the Action builds those from its own checkout instead of
downloading them.

## cleartoship.app

The site is static pages served by a Cloudflare Worker, with a Content Security
Policy that allows no third-party origin, HSTS, `nosniff`, `frame-ancestors
'none'` and `Referrer-Policy: no-referrer` (`site/public/_headers`). The only
dynamic routes are the dormant licensing endpoints under `/webhooks/*` and
`/license/*`; while billing is unconfigured, the Stripe webhook and
`/license/issue` answer 503. Rate limiting for those
routes is a Cloudflare dashboard rule (WAF → Rate limiting rules on
`/license/*`), not code in this repository.

## What it does to your project

**You do not need access to the source repository to check any of this.** The
package tarball attached to each GitHub release contains the code that actually
runs:

```bash
gh release download -R murtazaozdemir/cleartoship -p 'cleartoship-[0-9]*.tgz' \
  && tar xzf cleartoship-[0-9]*.tgz   # gives you package/dist
```

The greps in the table below are written against `src/` and match *call and
import syntax*, not bare words, because a scanner that looks for `eval`
necessarily contains the word `eval` in its rules and comments — the difference
between naming a dangerous call and making one is the whole claim. Run them
exactly as written (from the repository root, or with `src/` replaced by
`package/dist` in the tarball; the counts are the same) and compare the number
of lines with the number stated.

| Guarantee | Why it holds |
| --- | --- |
| **Never writes to the scanned project** | The only writes in the codebase are the report file you ask for with `--output <path>` and the registry cache. Verify: `grep -rnE "\b(writeFileSync\|appendFileSync\|mkdirSync\|rmSync\|unlinkSync\|renameSync\|copyFileSync\|cpSync\|createWriteStream)\(" src/ --exclude-dir=vendor` — exactly **3** lines: the `--output` write in `cli.ts`, and the cache directory's `mkdirSync` and the cache file's `writeFileSync` in `utils/registry.ts`. Neither path is derived from the scan root. |
| **Never executes your code** | The scanner has no `child_process`, `vm` or `worker_threads`, no `eval`, no `new Function`, and no dynamic `import()`. Your code is read as text, parsed by Babel into an AST, and matched against regexes. Verify the imports: `grep -rnE "^\s*import\b.*['\"](node:)?(child_process\|vm\|worker_threads)['\"]\|\brequire\(\s*['\"](node:)?(child_process\|vm\|worker_threads)['\"]\|\bimport\(" src/ --exclude-dir=vendor` — **0** lines. And the calls: `` grep -rnE "^[^/'\"\`]*\b(eval\|new Function)\(" src/ --exclude-dir=vendor `` — **0** lines (it only counts an `eval(` or `new Function(` that is not preceded on its line by a comment or a quote, i.e. one that could be code). Drop `--exclude-dir=vendor` and the first grep finds 1 line, an `import("./Chart")` inside the *example text* of a vendored rule — a string shown to you, never run. |
| **Never connects to your database** | The Row Level Security scanner replays your `.sql` migration files to model the resulting schema. There is no database driver in the dependency tree and no connection string is ever read. |
| **Reads only what it scans** | Files are gathered by walking the scan root, skipping `node_modules`, build output, virtualenvs and anything your own `.gitignore` excludes — except files git already tracks, which are read from `.git/index` so a committed `.gitignore` cannot hide them. Ignore rules are read from the scan root downwards only — never from a parent directory. **Every read is contained:** a file is opened only if its real path (symlinks resolved) is inside the scan root, so a repository cannot make the scanner read `~/.ssh` and quote it back into a report, whether through a symlinked directory the walk would enter or a symlinked manifest or ignore file it reads directly; the count of refused links appears in the output. Nothing outside the root is read except the registry cache directory. |
| **Reports are safe to post** | Anything shaped like a secret is redacted in every snippet, whichever rule matched it, and repository-derived text (file names, matched lines) is escaped in the markdown and terminal output, so the report can go into a PR comment or a CI log without re-publishing a key or letting a crafted file name inject markup or terminal escape sequences. |
| **Says when it did not finish** | A check that could not complete — a file that failed to parse or could not be read, a file too large for a ruleset, an npm/PyPI/OSV outage, a scanner that threw — is listed in the report's `incomplete` array, the verdict is never `clear`, and the CLI exits **3** unless `--allow-incomplete` is passed (findings at or above `--fail-on` still exit 1 first). "Nothing found" is never reported for something that was not read. |

## What leaves your machine

Four hosts, and only when a scan runs online:

| Host | Sent | Purpose |
| --- | --- | --- |
| `registry.npmjs.org`, `api.npmjs.org` | package **name** (in the URL), nothing else | does this package exist, when was it published, how many weekly downloads, is it deprecated |
| `pypi.org` | package **name** (in the URL) | the same, for Python dependencies declared in `requirements.txt` or `pyproject.toml` |
| `api.osv.dev` | package **name** + resolved **version** (in a JSON body) | known-vulnerability lookup |

No file contents, no paths, no repository name, no identifier of you or your
project is ever transmitted. Requests to npm and PyPI identify the tool, not
you, with `User-Agent: cleartoship (+https://cleartoship.app)`; requests to OSV
carry Node's default `fetch` user agent. Like any HTTPS request, each host sees
the IP address it came from.

npm and PyPI answers are cached for 24 hours under `~/.cache/cleartoship`
(override with `CLEARTOSHIP_CACHE`), so a second run within a day asks the
registries nothing new. OSV answers are **not** cached: vulnerability data is
the one answer that should be current on every run, so each online scan queries
OSV again. If any of these hosts cannot be reached, the scan says so, is
reported as incomplete, and exits 3 unless `--allow-incomplete` is passed.

**`--offline` stops even that.** Every network path is behind the same flag: the
dependency scanner returns early, and the registry client refuses to fetch. An
offline run is a pure local computation, and it is the right default in CI on a
private codebase.

## Dependency surface

Five runtime dependencies, all first-party Babel or long-established
single-purpose packages:

- `@babel/parser`, `@babel/traverse`, `@babel/types` — the TS/TSX parser and AST walker
- `commander` — argument parsing
- `picocolors` — terminal colour, zero dependencies

Two rulesets are **vendored** into `src/vendor/` rather than installed, so they
are visible in the diff and cannot change under you between releases:
[GuardVibe](https://github.com/goklab/guardvibe) (Apache-2.0) and
[gitleaks](https://github.com/gitleaks/gitleaks) (MIT). See `ATTRIBUTION.md`.

## What this tool is not

- **Not a proof of security.** It finds specific, well-defined classes of
  mistake. A clean run means those classes are absent, not that the app is safe.
  The OWASP coverage matrix in `README.md` is deliberately honest about the
  categories no static scanner can reach.
- **Not a sandbox.** It reads whatever you point it at. Pointing it at a
  repository you do not trust is as safe as opening that repository in an
  editor — no more, and no less. What it will not do is read *beyond* what you
  pointed it at: reads whose real path leaves the tree are refused, and a malformed pattern
  in the repository's own `.gitignore` is skipped rather than allowed to end
  the scan.
- **Not a secret scanner of record.** Secrets already committed to git history
  are out of scope; ClearToShip reads the working tree, not past commits.
