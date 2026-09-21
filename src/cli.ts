#!/usr/bin/env node
import { Command, Option } from 'commander';
import { writeFileSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve, relative, isAbsolute } from 'node:path';
import pc from 'picocolors';
import { scan } from './scan.js';
import { banner } from './banner.js';
import {
  renderTerminal,
  renderJson,
  renderSarif,
  renderFixPrompt,
  renderBadge,
  renderMarkdown,
} from './report.js';
import { SEVERITY_ORDER } from './types.js';
import type { Severity } from './types.js';

const here = dirname(fileURLToPath(import.meta.url));
// The standalone bundle is a single file with no sibling manifest to read, so
// the build stamps the version in. Undefined in the normal build, which falls
// through to the manifest exactly as before.
let version = process.env.CLEARTOSHIP_VERSION ?? '0.0.0';
if (version === '0.0.0') {
  try {
    version = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8')).version;
  } catch {
    /* running from an unusual layout; version is cosmetic */
  }
}

/**
 * Decide what the project root is, given the cwd and whatever paths were typed.
 *
 * `cleartoship /path/to/some/repo` means "scan that project". Rooting the scan
 * at the shell's cwd instead reports every finding as
 * `../../../tmp/x/app/page.tsx` — accurate, unreadable, and impossible to click
 * in an editor.
 *
 * Only a lone directory argument that lies outside the cwd is promoted. Several
 * paths, a file, or a path inside the current project all keep the cwd as root:
 * `cleartoship app supabase` must not re-root at `app/`, because framework
 * detection and `.gitignore` resolution both hang off the project's own
 * `package.json`. An explicit `--cwd` always wins.
 */
export function resolveRoot(
  cwd: string,
  paths: string[],
  cwdWasExplicit: boolean,
): { root: string; paths: string[] } {
  const only = paths.length === 1 ? paths[0] : undefined;
  if (cwdWasExplicit || only === undefined) return { root: cwd, paths };

  const candidate = resolve(cwd, only);
  const inside = !relative(cwd, candidate).startsWith('..') && !isAbsolute(relative(cwd, candidate));
  if (inside) return { root: cwd, paths };

  try {
    if (!statSync(candidate).isDirectory()) return { root: cwd, paths };
  } catch {
    // Unreadable or missing: leave it alone and let the scanner report it.
    return { root: cwd, paths };
  }
  return { root: candidate, paths: [] };
}

const program = new Command();

program
  .name('cleartoship')
  .description(
    'Pre-flight security check for AI-built apps, agents included.\n' +
      'Finds missing Server Action auth, Supabase RLS holes, hallucinated npm\n' +
      'packages and leaked keys before you deploy.',
  )
  .version(version, '-v, --version')
  .argument('[paths...]', 'files or directories to scan (default: the whole project)')
  .option('-C, --cwd <dir>', 'project root', process.cwd())
  .addOption(
    new Option('--fail-on <severity>', 'exit non-zero at or above this severity')
      .choices(['critical', 'high', 'medium', 'low', 'none'])
      .default('critical'),
  )
  .addOption(
    new Option('--min-severity <severity>', 'hide findings below this severity')
      .choices(['critical', 'high', 'medium', 'low', 'info'])
      .default('low'),
  )
  .option('--json', 'emit machine-readable JSON instead of the report')
  .option('--sarif', 'emit SARIF 2.1.0 (upload to GitHub code scanning)')
  .option('--fix-prompt', 'emit a ready-to-paste prompt for Cursor / Claude Code')
  .option('--badge', 'print the markdown status badge for your README')
  .option('--markdown', 'emit a markdown report (for PR comments / job summaries)')
  .option('-o, --output <file>', 'write the chosen output to a file instead of stdout')
  .option('--offline', 'skip registry lookups (no network)')
  .option('--no-community', 'run only ClearToShip rules, skipping the vendored community ruleset')
  .option('--no-gitignore', 'also scan files your .gitignore excludes')
  .option('--ignore <ids>', 'comma-separated rule ids to skip, e.g. CTS004,CTS022')
  .option('--only <ids>', 'comma-separated rule ids to report exclusively')
  .option('--no-banner', 'suppress the ASCII header')
  .option('--quiet', 'only print findings, no passed checks')
  .option('--verbose', 'extra diagnostic output')
  .action(async (paths: string[], opts) => {
    const machineReadable = Boolean(
      opts.json || opts.sarif || opts.fixPrompt || opts.badge || opts.markdown,
    );
    const interactive = !machineReadable && !opts.output;

    if (interactive && opts.banner !== false) {
      process.stderr.write(banner(version) + '\n');
    }

    const list = (value?: string) =>
      value ? value.split(',').map((s) => s.trim()).filter(Boolean) : undefined;

    // `cleartoship /path/to/some/repo` means "scan that project", not "scan that
    // path as part of the one I happen to be standing in". Without this, every
    // reported path is relative to the shell's cwd, so scanning a repo from
    // anywhere else produces `../../../private/tmp/.../app/page.tsx` — accurate,
    // unreadable, and impossible to match against a file in an editor.
    //
    // Only a single directory argument that sits outside the cwd is treated this
    // way. `cleartoship app supabase` still scans subtrees of the current
    // project, because rooting at `app/` would move the project root away from
    // the `package.json` that framework detection and .gitignore depend on.
    // `--cwd` carries a default, so it is always "set"; only the source says
    // whether the user actually passed it.
    const cwdWasExplicit = program.getOptionValueSource('cwd') === 'cli';
    const { root, paths: scanPaths } = resolveRoot(opts.cwd, paths, cwdWasExplicit);

    // `--min-severity` is a display control, but the exit code is computed from
    // the findings that survive it — so `--min-severity high --fail-on low` used
    // to hide the very findings it was told to fail on, and exit 0. The floor is
    // clamped to the gate instead: you can quieten a report, never the build.
    const minSeverity: Severity =
      opts.failOn !== 'none' &&
      SEVERITY_ORDER[opts.minSeverity as Severity] > SEVERITY_ORDER[opts.failOn as Severity]
        ? (opts.failOn as Severity)
        : (opts.minSeverity as Severity);

    const result = await scan({
      root,
      paths: scanPaths,
      offline: opts.offline,
      // commander maps --no-gitignore to `gitignore: false`.
      noGitignore: opts.gitignore === false,
      noCommunity: opts.community === false,
      ignore: list(opts.ignore),
      only: list(opts.only),
      minSeverity,
      verbose: opts.verbose,
      onProgress: interactive
        ? (step, total, name) => {
            process.stderr.write(pc.dim(`  [${step}/${total}] ${name}…\n`));
          }
        : undefined,
    });

    if (interactive) {
      process.stderr.write(
        `\n  ${pc.dim('root')}      ${result.root}\n` +
          `  ${pc.dim('stack')}     ${result.framework}\n`,
      );
    }

    let output: string;
    if (opts.json) output = renderJson(result);
    else if (opts.sarif) output = renderSarif(result, version);
    else if (opts.fixPrompt) output = renderFixPrompt(result);
    else if (opts.badge) output = renderBadge(result);
    else if (opts.markdown) output = renderMarkdown(result);
    else output = renderTerminal(result, { showPassed: !opts.quiet });

    if (opts.output) {
      writeFileSync(opts.output, output.endsWith('\n') ? output : output + '\n');
      process.stderr.write(pc.dim(`\n  wrote ${opts.output}\n`));
    } else {
      process.stdout.write(output.endsWith('\n') ? output : output + '\n');
    }

    if (opts.failOn === 'none') return;
    const floor = SEVERITY_ORDER[opts.failOn as Severity];
    const blocking = result.findings.filter((f) => SEVERITY_ORDER[f.severity] >= floor).length;
    if (blocking > 0) process.exitCode = 1;
  });

program.parseAsync(process.argv).catch((err) => {
  process.stderr.write(pc.red(`cleartoship: ${err instanceof Error ? err.message : String(err)}\n`));
  process.exitCode = 2;
});
