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

## What it does to your project

**You do not need access to the source repository to check any of this.** The
package tarball attached to each GitHub release contains the code that actually
runs (once the package is on npm, `npm pack cleartoship` gives you the same
thing):

```bash
gh release download -R murtazaozdemir/cleartoship -p 'cleartoship-[0-9]*.tgz' \
  && tar xzf cleartoship-[0-9]*.tgz   # gives you package/dist
```

The greps in the table below are written against `src/`. Run the same greps
against `package/dist` and they answer the same question — every hit that comes
back is a comment, a regex pattern string or the text of a rule that is *matched
against your code*, never a call site. That is worth checking rather than
believing: a scanner that looks for `eval` necessarily contains the word `eval`,
and the difference between naming a dangerous call and making one is the whole
claim.

| Guarantee | Why it holds |
| --- | --- |
| **Never writes to the scanned project** | The only writes in the codebase are the report file you ask for with `--output <path>` and the registry cache. Verify: `grep -rn "writeFileSync\|mkdirSync\|rmSync\|unlink" src/ --exclude-dir=vendor` — five lines, of which two are imports and three are those call sites. Neither path is derived from the scan root. |
| **Never executes your code** | The scanner has no `child_process`, `exec`, `spawn`, `eval`, `new Function`, or dynamic `import()` of scanned files. Your code is read as text, parsed by Babel into an AST, and matched against regexes. Verify: `grep -rn "child_process\|execSync\|spawn\|eval(\|new Function" src/ --exclude-dir=vendor` — one hit, and it is a *pattern string* in the rule that detects those calls in **your** install hooks. (Drop `--exclude-dir=vendor` and the extra hits are rule text in the vendored ruleset, matched against your code, never run.) |
| **Never connects to your database** | The Row Level Security scanner replays your `.sql` migration files to model the resulting schema. There is no database driver in the dependency tree and no connection string is ever read. |
| **Reads only what it scans** | Files are gathered by walking the scan root, skipping `node_modules`, build output, virtualenvs and anything your own `.gitignore` excludes. Ignore rules are read from the scan root downwards only — never from a parent directory. **A symlink that resolves outside the root is not followed**, so a repository cannot make the scanner read `~/.ssh` and quote it back into a report; the count of refused links appears in the output. Nothing outside the root is read except the cache directory. |

## What leaves your machine

Three hosts, and only when a scan runs online:

| Host | Sent | Purpose |
| --- | --- | --- |
| `registry.npmjs.org`, `api.npmjs.org` | package **name** (in the URL), nothing else | does this package exist, when was it published, how many weekly downloads, is it deprecated |
| `pypi.org` | package **name** | the same, for `requirements.txt` |
| `api.osv.dev` | package **name** + resolved **version** | known-vulnerability lookup |

No file contents, no paths, no repository name, no identifier of you or your
project is ever transmitted. Responses are cached for 24 hours under
`~/.cache/cleartoship` (override with `CLEARTOSHIP_CACHE`).

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
  pointed it at: symlinks out of the tree are refused, and a malformed pattern
  in the repository's own `.gitignore` is skipped rather than allowed to end
  the scan.
- **Not a secret scanner of record.** Secrets already committed to git history
  are out of scope; ClearToShip reads the working tree, not past commits.
