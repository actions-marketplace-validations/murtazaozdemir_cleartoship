import { basename, join } from 'node:path';
import { readFileSync } from 'node:fs';
import { read, rel, isProse, lineAt } from '../utils/files.js';
import { Registry, pool } from '../utils/registry.js';
import { queryOsv, severityForVulnerability } from '../utils/osv.js';
import type { OsvQuery } from '../utils/osv.js';
import { POPULAR_NPM, POPULAR_PYPI, nearestPopular } from '../data/popular.js';
import { emptyResult } from '../types.js';
import type { Finding, ProjectContext, ScanResult, Scanner } from '../types.js';

const NEW_PACKAGE_DAYS = 60;
const LOW_DOWNLOADS = 250;
const VERY_LOW_DOWNLOADS = 50;

interface Declared {
  name: string;
  range: string;
  ecosystem: 'npm' | 'pypi';
  file: string;
  line: number;
  dev: boolean;
  /** Harvested from an install command in prose rather than a manifest. */
  fromProse?: boolean;
}

function collectFromPackageJson(source: string, relPath: string): Declared[] {
  let pkg: any;
  try {
    pkg = JSON.parse(source);
  } catch {
    return [];
  }
  const lines = source.split('\n');
  const lineOf = (name: string): number => {
    const needle = `"${name}"`;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i]!.includes(needle)) return i + 1;
    }
    return 1;
  };
  const out: Declared[] = [];
  for (const [field, dev] of [
    ['dependencies', false],
    ['devDependencies', true],
    ['optionalDependencies', true],
    ['peerDependencies', true],
  ] as const) {
    const block = pkg?.[field];
    if (!block || typeof block !== 'object') continue;
    for (const [name, range] of Object.entries(block)) {
      if (typeof range !== 'string') continue;
      out.push({ name, range, ecosystem: 'npm', file: relPath, line: lineOf(name), dev });
    }
  }
  return out;
}

function collectFromRequirements(source: string, relPath: string): Declared[] {
  const out: Declared[] = [];
  source.split('\n').forEach((raw, i) => {
    const line = raw.split('#')[0]!.trim();
    if (!line || line.startsWith('-')) return;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/.exec(line);
    if (!m) return;
    out.push({
      name: m[1]!,
      range: (m[3] ?? '').trim(),
      ecosystem: 'pypi',
      file: relPath,
      line: i + 1,
      dev: false,
    });
  });
  return out;
}

function collectFromPyproject(source: string, relPath: string): Declared[] {
  const out: Declared[] = [];
  const lines = source.split('\n');
  let inDeps = false;
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (/^\[/.test(line)) {
      inDeps = /\[(tool\.poetry\.(dev-)?dependencies|project\.optional-dependencies)\]/.test(line);
      return;
    }
    if (/^dependencies\s*=\s*\[/.test(line)) inDeps = true;
    if (!inDeps) return;
    const quoted = /^["']([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(line.replace(/^\s*["']?/, (m0) => m0));
    const poetry = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/.exec(line);
    const strItem = /["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*[<>=!~ ]*[^"']*["']/.exec(line);
    const name = poetry?.[1] ?? strItem?.[1] ?? quoted?.[1];
    if (!name || name === 'python') return;
    out.push({ name, range: '', ecosystem: 'pypi', file: relPath, line: i + 1, dev: false });
  });
  return out;
}

/**
 * The `name` this manifest publishes under, if any.
 *
 * A package the repository itself defines is not a third-party dependency, and
 * asking a registry about it produces exactly the wrong answer: a library whose
 * README says `npm install <its own name>` before the first publish was reported
 * as a hallucinated package — a *critical*, blocking the default gate, on
 * completely correct code. The same applies across a monorepo, where one
 * workspace depends on another by name.
 */
function packageJsonName(source: string): string | null {
  try {
    const name = JSON.parse(source)?.name;
    return typeof name === 'string' && name ? name : null;
  } catch {
    return null;
  }
}

/** `[project] name` / `[tool.poetry] name` from a pyproject.toml. */
function pyprojectName(source: string): string | null {
  let inProject = false;
  for (const raw of source.split('\n')) {
    const line = raw.trim();
    if (/^\[/.test(line)) {
      inProject = /^\[(project|tool\.poetry)\]/.test(line);
      continue;
    }
    if (!inProject) continue;
    const m = /^name\s*=\s*["']([^"']+)["']/.exec(line);
    if (m) return m[1]!;
  }
  return null;
}

/**
 * Scopes an `.npmrc` points at a registry other than npmjs.org. A package in one
 * of those resolves from somewhere this tool cannot see, so a 404 on the public
 * registry says nothing about whether it exists — and CTS020 is a critical.
 */
function privateScopes(root: string): Set<string> {
  const scopes = new Set<string>();
  for (const name of ['.npmrc', '.yarnrc.yml']) {
    let source: string;
    try {
      source = readFileSync(join(root, name), 'utf8');
    } catch {
      continue;
    }
    const re = /(@[a-z0-9-~][a-z0-9-._~]*)\s*:\s*registry\s*[=:]/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(source)) !== null) scopes.add(m[1]!.toLowerCase());
  }
  return scopes;
}

/** Valid npm package name, optionally scoped. */
const NPM_NAME = String.raw`(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*`;

const INSTALL_COMMAND = new RegExp(
  String.raw`\b(?:npm\s+(?:i|install|add)|yarn\s+add|pnpm\s+(?:i|install|add)|bun\s+(?:i|install|add))\s+([^\n\`|;&>]+)`,
  'gi',
);
const RUNNER_COMMAND = new RegExp(
  String.raw`\b(?:npx|pnpm\s+dlx|bunx)\s+([^\n\`|;&>]+)`,
  'gi',
);
const PIP_COMMAND =
  /\b(?:pip3?\s+install|uv\s+pip\s+install|poetry\s+add|uv\s+add)\s+([^\n`|;&>]+)/gi;

/**
 * Pulls package names out of install commands written in prose. Agent
 * instruction files and READMEs are where a hallucinated name is copy-pasted
 * from long before anyone adds it to a manifest, so they are worth reading.
 */
function collectFromProse(source: string, relPath: string): Declared[] {
  const out: Declared[] = [];
  const npmName = new RegExp(`^${NPM_NAME}$`);

  const harvest = (re: RegExp, ecosystem: 'npm' | 'pypi', firstArgOnly: boolean) => {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(source)) !== null) {
      const args = m[1]!.trim().split(/\s+/);
      const line = lineAt(source, m.index);
      for (const arg of args) {
        if (arg.startsWith('-')) continue; // flag
        // Strip a version spec, but not a scope: `@types/node` vs `react@18`.
        const bare = arg.replace(/(?!^)@[^@/]*$/, '').replace(/\[.*\]$/, '');
        if (!bare || bare.includes('/') && !bare.startsWith('@')) continue; // path or URL
        if (/^[.~/]|:/.test(bare)) continue;
        const ok = ecosystem === 'npm' ? npmName.test(bare) : /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(bare);
        // A real package name contains letters; reject list bullets, ports and
        // version-ish tokens ("3003", "1.", "2") that show up in prose.
        if (!ok || !/[a-z]/i.test(bare) || bare.length < 2) continue;
        out.push({ name: bare, range: '', ecosystem, file: relPath, line, dev: false, fromProse: true });
        if (firstArgOnly) break;
      }
    }
  };

  // For `npx pkg <args>` / `pnpm dlx` / `bunx`, only the first token is a
  // package — the rest are that command's arguments (so `wrangler d1 create
  // my-db` must not read `d1`, `create`, `my-db` as packages).
  harvest(RUNNER_COMMAND, 'npm', true);
  harvest(INSTALL_COMMAND, 'npm', false);
  harvest(PIP_COMMAND, 'pypi', false);
  return out;
}

/** Lifecycle scripts that run automatically on `npm install`. */
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];
const DANGEROUS_SCRIPT =
  /\b(curl|wget|https?:\/\/|base64\s+(-d|--decode)|eval\s|node\s+-e|child_process|\|\s*(sh|bash)\b|chmod\s+\+x)/i;

function collectInstallScriptFindings(source: string, relPath: string): Finding[] {
  let pkg: any;
  try {
    pkg = JSON.parse(source);
  } catch {
    return [];
  }
  const findings: Finding[] = [];
  const lines = source.split('\n');
  for (const hook of INSTALL_HOOKS) {
    const script = pkg?.scripts?.[hook];
    if (typeof script !== 'string' || !DANGEROUS_SCRIPT.test(script)) continue;
    const line = Math.max(1, lines.findIndex((l) => l.includes(`"${hook}"`)) + 1);
    findings.push({
      id: 'CTS028',
      severity: 'critical',
      title: `Install hook \`${hook}\` runs network or shell code`,
      detail:
        `The \`${hook}\` script (\`${script.length > 120 ? script.slice(0, 117) + '...' : script}\`) executes ` +
        'automatically on every `npm install`, including in CI and on every contributor’s machine, ' +
        'before any code review happens. Fetching or evaluating code there is the standard ' +
        'supply-chain execution path.',
      fix:
        'Move the work into an explicit script the developer opts into (`npm run setup`), or vendor ' +
        'the artefact and verify its checksum instead of fetching it at install time.',
      file: relPath,
      line,
      cwe: 'CWE-829: Inclusion of Functionality from Untrusted Control Sphere',
      owasp: 'A03:2025 - Software Supply Chain Failures',
      meta: { hook, script },
    });
  }
  return findings;
}

/**
 * Resolves the version actually installed for each declared dependency.
 *
 * A manifest only carries a range, and OSV needs an exact version. Lockfiles
 * are the truth, so they are read directly (bypassing the walker's size cap,
 * since a lockfile is routinely megabytes). Where no lockfile exists, the
 * range's floor is used: `^14.2.3` resolves to `14.2.3`, which is the oldest
 * version the range permits and therefore the one worth checking.
 *
 * Keyed by ecosystem as well as name: `npm` and PyPI both publish a `click`, and
 * a shared key handed the Python package the JavaScript one's lockfile version
 * to query OSV with.
 */
function resolveVersions(root: string, declared: Declared[]): Map<string, string> {
  const resolved = new Map<string, string>();
  const setNpm = (name: string, version: string) => {
    const key = `npm:${name}`;
    if (!resolved.has(key)) resolved.set(key, version);
  };

  const readIfPresent = (name: string): string | null => {
    try {
      return readFileSync(join(root, name), 'utf8');
    } catch {
      return null;
    }
  };

  const npmLock = readIfPresent('package-lock.json');
  if (npmLock) {
    try {
      const doc = JSON.parse(npmLock);
      for (const [path, entry] of Object.entries<any>(doc.packages ?? {})) {
        if (!path.startsWith('node_modules/')) continue;
        const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
        if (entry?.version) setNpm(name, String(entry.version));
      }
      for (const [name, entry] of Object.entries<any>(doc.dependencies ?? {})) {
        if (entry?.version) setNpm(name, String(entry.version));
      }
    } catch {
      /* a malformed lockfile just means we fall back to the range floor */
    }
  }

  const pnpmLock = readIfPresent('pnpm-lock.yaml');
  if (pnpmLock) {
    // Entries look like `/next@14.2.3:` (v6/v9) or `/next/14.2.3:` (v5).
    const re = /^\s{2}\/?((?:@[^/\s]+\/)?[^/@\s]+)[@/](\d+\.\d+\.\d+[^\s:(]*)/gm;
    let m: RegExpExecArray | null;
    while ((m = re.exec(pnpmLock)) !== null) {
      setNpm(m[1]!, m[2]!);
    }
  }

  const yarnLock = readIfPresent('yarn.lock');
  if (yarnLock) {
    // Parsed line by line rather than with a regex: matching an entry header
    // and its indented `version` line in one pattern needs a nested quantifier,
    // which backtracks catastrophically on a crafted lockfile — and a lockfile
    // is exactly the attacker-influenced input this tool reads in CI.
    let pendingNames: string[] = [];
    for (const rawLine of yarnLock.split('\n')) {
      if (rawLine.length === 0 || rawLine.startsWith('#')) continue;

      if (!/^\s/.test(rawLine)) {
        // Entry header: `"next@npm:^14.2.3", next@^14.0.0:`
        pendingNames = rawLine
          .replace(/:\s*$/, '')
          .split(',')
          .map((part) => part.trim().replace(/^"|"$/g, ''))
          .map((spec) => {
            const at = spec.lastIndexOf('@');
            return at > 0 ? spec.slice(0, at) : spec;
          })
          .filter(Boolean);
        continue;
      }

      const version = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(rawLine)?.[1];
      if (version && pendingNames.length > 0) {
        for (const name of pendingNames) {
          setNpm(name, version);
        }
        pendingNames = [];
      }
    }
  }

  // Fall back to the floor of each declared range.
  for (const d of declared) {
    const key = `${d.ecosystem}:${d.name}`;
    if (resolved.has(key)) continue;
    const floor = /(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)/.exec(d.range)?.[1];
    if (floor) resolved.set(key, floor);
  }
  return resolved;
}

export const dependencyScanner: Scanner = {
  name: 'Dependency hallucination & slopsquatting',

  applies(ctx) {
    return ctx.files.some((f) => {
      const b = basename(f);
      return (
        b === 'package.json' || b === 'requirements.txt' || b === 'pyproject.toml' || isProse(f)
      );
    });
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    const declared: Declared[] = [];
    // Every package this repository defines itself — the root one and, in a
    // monorepo, each workspace. None of them is a third-party dependency.
    const local = new Set<string>();

    for (const file of ctx.files) {
      const b = basename(file);
      const source = read(file);
      if (source === null) continue;
      const relPath = rel(ctx.root, file);
      if (b === 'package.json') {
        const own = packageJsonName(source);
        if (own) local.add(`npm:${own}`);
        declared.push(...collectFromPackageJson(source, relPath));
        result.findings.push(...collectInstallScriptFindings(source, relPath));
      } else if (b === 'requirements.txt') declared.push(...collectFromRequirements(source, relPath));
      else if (b === 'pyproject.toml') {
        const own = pyprojectName(source);
        if (own) local.add(`pypi:${own}`);
        declared.push(...collectFromPyproject(source, relPath));
      } else if (isProse(file)) declared.push(...collectFromProse(source, relPath));
    }

    // Local workspace references never hit a registry.
    const scopes = privateScopes(ctx.root);
    let skippedLocal = 0;
    let skippedPrivate = 0;
    const checkable = declared.filter((d) => {
      if (/^(file:|link:|workspace:|portal:|git\+|https?:|github:|npm:)/.test(d.range)) return false;
      // Defined right here — by the root manifest or a sibling workspace.
      if (local.has(`${d.ecosystem}:${d.name}`)) {
        skippedLocal++;
        return false;
      }
      // Resolved from a registry this tool was never pointed at, so the public
      // registry's answer about it is not evidence either way.
      const scope = d.ecosystem === 'npm' ? /^(@[^/]+)\//.exec(d.name)?.[1]?.toLowerCase() : undefined;
      if (scope && scopes.has(scope)) {
        skippedPrivate++;
        return false;
      }
      return true;
    });
    // Dedupe by package, but let a manifest entry win over a mention in prose.
    // Files are walked alphabetically, so AGENTS.md is seen before package.json;
    // without this, a real dependency is recorded as a prose reference, which
    // both mislocates the finding and skips version resolution for it.
    const unique = new Map<string, Declared>();
    for (const d of checkable) {
      const key = `${d.ecosystem}:${d.name}`;
      const existing = unique.get(key);
      if (!existing || (existing.fromProse && !d.fromProse)) unique.set(key, d);
    }
    const list = [...unique.values()];

    // Said once, and said on both paths: a project whose every dependency was
    // skipped as local is not a project with no dependencies.
    const skipNotes: string[] = [];
    if (skippedLocal > 0) {
      skipNotes.push(`${skippedLocal} defined by this repository itself, so not looked up`);
    }
    if (skippedPrivate > 0) {
      skipNotes.push(
        `${skippedPrivate} in a scope your .npmrc points at a private registry, which this cannot read`,
      );
    }

    if (list.length === 0) {
      result.checks.push({
        label: 'Dependency verification',
        passed: true,
        note: skipNotes.length > 0 ? skipNotes.join('; ') : 'no dependencies declared',
      });
      return result;
    }

    if (ctx.offline) {
      result.checks.push({
        label: `Dependency verification (${list.length} packages)`,
        passed: true,
        note: 'skipped — running with --offline',
      });
      return result;
    }

    const registry = new Registry(ctx.cacheDir, ctx.offline);
    const facts = await pool(list, 8, (d) => registry.lookup(d.name, d.ecosystem));

    // A lookup that failed is not a package that exists. This stays fail-open, so a
    // network blip is never reported as a hallucinated dependency, but it must not
    // be reported as *checked* either: a run where the registry never answered used
    // to end "all checks passed" with a one-line warning above it.
    const unverified = facts.filter((f) => f.error && f.error !== 'offline').length;
    if (unverified > 0) {
      result.incomplete = [
        ...(result.incomplete ?? []),
        `${unverified} of ${list.length} package${list.length === 1 ? '' : 's'} could not be looked up ` +
          'on npm/PyPI (the registry did not answer), so they were NOT checked — a hallucinated, ' +
          'typosquatted or newly registered name among them would not be reported.',
      ];
    }

    list.forEach((d, i) => {
      const f = facts[i]!;
      const popular = d.ecosystem === 'npm' ? POPULAR_NPM : POPULAR_PYPI;
      const registryName = d.ecosystem === 'npm' ? 'npm' : 'PyPI';

      const origin = d.fromProse
        ? `referenced by an install command in ${d.file}`
        : `declared in ${d.file}`;

      if (!f.exists && f.securityHold) {
        result.findings.push({
          id: 'CTS026',
          severity: 'critical',
          title: 'Dependency was removed by the registry for malware',
          detail:
            `\`${d.name}\` is ${origin}, and ${registryName} serves HTTP 451 for it — the response ` +
            'reserved for a package taken down on legal or security grounds. This name was not merely ' +
            'invented; it was published, weaponised and pulled.',
          fix:
            `Remove \`${d.name}\` everywhere it appears and treat any machine that installed it as ` +
            'compromised: rotate the credentials that were present in that environment and audit the lockfile history.',
          file: d.file,
          line: d.line,
          cwe: 'CWE-1357: Reliance on Insufficiently Trustworthy Component',
          owasp: 'A03:2025 - Software Supply Chain Failures',
          meta: { package: d.name, ecosystem: d.ecosystem, securityHold: true },
        });
        return;
      }

      if (!f.exists && f.unpublished) {
        result.findings.push({
          id: 'CTS027',
          severity: 'critical',
          title: 'Dependency was unpublished and its name is open to takeover',
          detail:
            `\`${d.name}\` is ${origin} but no longer exists on ${registryName}, yet it still records ` +
            `${f.weeklyDownloads} weekly downloads. It was published and then withdrawn, so the name is ` +
            'free for anyone to claim — and whoever claims it inherits every one of those installs.',
          fix:
            `Remove \`${d.name}\` and replace it with a maintained package. Your install is already ` +
            'failing or falling back to a cache; the risk is the day someone republishes the name.',
          file: d.file,
          line: d.line,
          cwe: 'CWE-1357: Reliance on Insufficiently Trustworthy Component',
          owasp: 'A03:2025 - Software Supply Chain Failures',
          meta: { package: d.name, ecosystem: d.ecosystem, unpublished: true, weeklyDownloads: f.weeklyDownloads },
        });
        return;
      }

      if (!f.exists) {
        const near = nearestPopular(d.name, popular, 2);
        result.findings.push({
          id: 'CTS020',
          severity: 'critical',
          title: 'Dependency does not exist on the registry',
          detail:
            `\`${d.name}\` is ${origin} but no such package is published on ${registryName}. ` +
            'This is the classic signature of an AI-hallucinated import. The name is unclaimed, so an ' +
            'attacker can register it and have their code execute in every install and CI run from then on.' +
            (near ? ` Did you mean \`${near}\`?` : ''),
          fix: near
            ? `Replace \`${d.name}\` with \`${near}\`, or remove the dependency and the code importing it.`
            : `Remove \`${d.name}\` and the code that imports it, or publish the package yourself to claim the name.`,
          file: d.file,
          line: d.line,
          cwe: 'CWE-1357: Reliance on Insufficiently Trustworthy Component',
          owasp: 'A03:2025 - Software Supply Chain Failures',
          meta: { package: d.name, ecosystem: d.ecosystem, suggestion: near, fromProse: d.fromProse },
        });
        return;
      }

      if (f.error) return; // lookup failed; already reported as a warning

      const ageDays = f.created
        ? Math.floor((Date.now() - Date.parse(f.created)) / 86_400_000)
        : null;
      const downloads = f.weeklyDownloads;
      const near = nearestPopular(d.name, popular, 1);

      if (near) {
        // Squats of very popular names still rack up thousands of installs from
        // people making the same mistake, so download volume tunes the severity
        // rather than gating the finding.
        const busy = downloads !== undefined && downloads >= 10_000;
        result.findings.push({
          id: 'CTS023',
          severity: busy ? 'medium' : 'high',
          title: 'Dependency name is one edit away from a popular package',
          detail:
            `\`${d.name}\` differs from the widely-used \`${near}\` by a single character` +
            (downloads !== undefined ? ` and has ${downloads.toLocaleString()} weekly downloads` : '') +
            '. Typosquats and slopsquats are published precisely to catch this substitution — and a ' +
            'squat of a popular name still collects real install traffic, so a download count is not ' +
            'on its own reassuring.',
          fix:
            `Confirm you meant \`${d.name}\` and not \`${near}\`. Check the package's repository, ` +
            'maintainer and install scripts before trusting it.',
          file: d.file,
          line: d.line,
          cwe: 'CWE-1357: Reliance on Insufficiently Trustworthy Component',
          owasp: 'A03:2025 - Software Supply Chain Failures',
          meta: { package: d.name, lookalike: near, weeklyDownloads: downloads },
        });
      }

      if (ageDays !== null && ageDays <= NEW_PACKAGE_DAYS && (downloads === undefined || downloads < LOW_DOWNLOADS)) {
        result.findings.push({
          id: 'CTS021',
          severity: 'high',
          title: 'Newly published, barely used dependency',
          detail:
            `\`${d.name}\` was first published ${ageDays} day${ageDays === 1 ? '' : 's'} ago` +
            (downloads !== undefined ? ` and has ${downloads} weekly downloads` : '') +
            '. A package that appears in an AI-written manifest and was registered days ago is the ' +
            'expected shape of a slopsquat: the model invents the name, an attacker registers it.',
          fix:
            `Open https://www.npmjs.com/package/${d.name} and check the repository, the maintainer and the ` +
            'install scripts before trusting it. Pin an exact version if you keep it.',
          file: d.file,
          line: d.line,
          cwe: 'CWE-1357: Reliance on Insufficiently Trustworthy Component',
          owasp: 'A03:2025 - Software Supply Chain Failures',
          meta: { package: d.name, ageDays, weeklyDownloads: downloads },
        });
      } else if (
        downloads !== undefined &&
        downloads < VERY_LOW_DOWNLOADS &&
        !d.dev &&
        !near
      ) {
        result.findings.push({
          id: 'CTS022',
          severity: 'low',
          title: 'Runtime dependency with almost no users',
          detail:
            `\`${d.name}\` has ${downloads} weekly downloads. That is not a vulnerability by itself, but ` +
            'an unmaintained single-author package in your runtime path is worth a deliberate decision ' +
            'rather than an accidental one.',
          fix: 'Confirm the package is maintained and actually needed, or vendor the few functions you use.',
          file: d.file,
          line: d.line,
          owasp: 'A03:2025 - Software Supply Chain Failures',
          meta: { package: d.name, weeklyDownloads: downloads },
        });
      }

      if (f.deprecated) {
        result.findings.push({
          id: 'CTS025',
          severity: 'low',
          title: 'Dependency is deprecated upstream',
          detail: `The latest published version of \`${d.name}\` is marked deprecated by its maintainer.`,
          fix: 'Check the deprecation notice on the registry page and migrate to the successor package.',
          file: d.file,
          line: d.line,
          owasp: 'A03:2025 - Software Supply Chain Failures',
          meta: { package: d.name },
        });
      }
    });

    // Known vulnerabilities, from OSV.dev rather than hand-maintained version
    // patterns. Only packages that exist and resolve to a concrete version can
    // be queried.
    const versions = resolveVersions(ctx.root, declared);
    const osvQueries: OsvQuery[] = [];
    const osvSubjects: Declared[] = [];
    list.forEach((d, i) => {
      if (!facts[i]!.exists || facts[i]!.error) return;
      if (d.fromProse) return; // a mention in prose is not an installed version
      const version = versions.get(`${d.ecosystem}:${d.name}`);
      if (!version) return;
      osvQueries.push({
        name: d.name,
        version,
        ecosystem: d.ecosystem === 'npm' ? 'npm' : 'PyPI',
      });
      osvSubjects.push(d);
    });

    let osvChecked = 0;
    if (osvQueries.length > 0) {
      const { results: vulnResults, failed } = await queryOsv(osvQueries);
      if (failed) {
        result.incomplete = [
          ...(result.incomplete ?? []),
          'OSV.dev did not answer, so the versions you depend on were NOT checked for known ' +
            'vulnerabilities in this run.',
        ];
      } else {
        osvChecked = osvQueries.length;
      }

      vulnResults.forEach((vulns, i) => {
        if (vulns.length === 0) return;
        const d = osvSubjects[i]!;
        const q = osvQueries[i]!;
        // Report the worst one per package; the rest are listed in meta. Ranked
        // by the severity actually reported, so a record that only publishes a
        // qualitative rating still competes with one that publishes a score.
        const rank = { critical: 4, high: 3, medium: 2, low: 1 } as const;
        const worst = vulns.reduce((a, b) => {
          const byRank = rank[severityForVulnerability(b)] - rank[severityForVulnerability(a)];
          if (byRank !== 0) return byRank > 0 ? b : a;
          return (b.cvss ?? 0) > (a.cvss ?? 0) ? b : a;
        });
        const cve = worst.aliases.find((a) => a.startsWith('CVE-')) ?? worst.id;
        const others = vulns.length - 1;

        // A devDependency's vulnerability lives in your build/CI toolchain, not
        // in what your users run — a real concern, but not the same class as a
        // CVE in a package that ships. Label it and hold its severity below the
        // gate so a linter CVE never blocks a deploy the way a runtime one does.
        const shipsToProd = !d.dev;
        const severity: typeof result.findings[number]['severity'] = shipsToProd
          ? severityForVulnerability(worst)
          : 'low';

        result.findings.push({
          id: 'CTS024',
          severity,
          title: shipsToProd
            ? `Dependency has a known vulnerability (${cve})`
            : `Dev dependency has a known vulnerability (${cve})`,
          detail:
            // The summary is upstream prose and often ends without punctuation,
            // so the sentence break is added here rather than assumed — the
            // clauses after it used to run straight on from the last word.
            `\`${d.name}@${q.version}\` is affected by ${cve}: ` +
            worst.summary.replace(/\s*$/, '').replace(/([^.!?])$/, '$1.') +
            (worst.cvss !== null
              ? ` CVSS ${worst.cvss.toFixed(1)}.`
              : worst.rating
                ? ` Rated ${worst.rating.toLowerCase()} by the advisory database, which publishes no score for it.`
                : '') +
            (others > 0
              ? ` ${others} further advisor${others === 1 ? 'y' : 'ies'} also affect this version.`
              : '') +
            (shipsToProd
              ? ''
              : ' It is a dev/build dependency, so it does not ship to production — fix it, but it does not gate a deploy.'),
          fix: worst.fixedIn
            ? `Upgrade \`${d.name}\` to ${worst.fixedIn} or later.`
            : `No fixed version is published yet. Check https://osv.dev/vulnerability/${worst.id} for mitigations.`,
          file: d.file,
          line: d.line,
          cwe: 'CWE-1395: Dependency on Vulnerable Third-Party Component',
          owasp: 'A03:2025 - Software Supply Chain Failures',
          meta: {
            package: d.name,
            version: q.version,
            production: shipsToProd,
            resolvedFrom: versions.has(`${d.ecosystem}:${d.name}`) ? 'lockfile-or-range' : 'range',
            advisories: vulns.map((v) => ({
              id: v.id,
              aliases: v.aliases,
              cvss: v.cvss,
              rating: v.rating,
              severity: severityForVulnerability(v),
              fixedIn: v.fixedIn,
            })),
          },
        });
      });

      if (osvChecked > 0) {
        const cts024 = result.findings.filter((f) => f.id === 'CTS024');
        const shipping = cts024.filter((f) => f.meta?.production === true).length;
        const devOnly = cts024.length - shipping;
        result.checks.push({
          label: `Known vulnerabilities (${osvChecked} resolved versions checked against OSV.dev)`,
          // Only shipping vulnerabilities fail the check; dev/build ones are noted.
          passed: shipping === 0,
          note:
            cts024.length === 0
              ? undefined
              : `${shipping} shipping` + (devOnly > 0 ? `, ${devOnly} dev/build (non-blocking)` : ''),
        });
      }
    }

    const missing = result.findings.filter((f) =>
      ['CTS020', 'CTS026', 'CTS027'].includes(f.id),
    ).length;
    const notes = missing > 0 ? [`${missing} could not be resolved`, ...skipNotes] : [...skipNotes];
    if (unverified > 0) notes.push(`${unverified} not verified — registry did not answer`);
    const checked = list.length - unverified;
    result.checks.push({
      // Says how many were actually looked up, not how many were asked about.
      label:
        unverified > 0
          ? `Dependency verification (${checked} of ${list.length} package${list.length === 1 ? '' : 's'} checked against npm/PyPI)`
          : `Dependency verification (${list.length} package${list.length === 1 ? '' : 's'} checked against npm/PyPI)`,
      passed: missing === 0 && unverified === 0,
      note: notes.length > 0 ? notes.join('; ') : undefined,
    });
    return result;
  },
};

/** Exposed for tests: harvest package names from prose install commands. */
export const collectProseForTest = collectFromProse;
