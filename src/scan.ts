import { resolve } from 'node:path';
import { statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { walk } from './utils/files.js';
import { detectFramework } from './utils/detect.js';
import { SCANNERS, communityScanner } from './scanners/index.js';
import { GUARDVIBE_CVE_RULE_IDS } from './vendor/guardvibe/index.js';
import { SEVERITY_ORDER } from './types.js';
import { normaliseOwasp, llmCategory } from './utils/owasp.js';
import type { CheckSummary, Finding, ProjectContext, Severity } from './types.js';

export interface ScanOptions {
  root: string;
  paths?: string[];
  offline?: boolean;
  ignore?: string[];
  only?: string[];
  minSeverity?: Severity;
  /** Skip the vendored community ruleset, leaving only ClearToShip's own checks. */
  noCommunity?: boolean;
  /** Scan files the repository ignores too. Off by default — see `walk`. */
  noGitignore?: boolean;
  verbose?: boolean;
  onProgress?: (step: number, total: number, name: string) => void;
}

export interface FullScan {
  root: string;
  framework: string;
  fileCount: number;
  /** Paths left unscanned because the repository's own ignore rules exclude them. */
  gitIgnoredCount: number;
  /** Symlinks that pointed outside the scan root and were not followed. */
  escapingSymlinkCount: number;
  /** Files left unread because they exceed the walker's size cap. */
  oversizeCount: number;
  /** Build and dependency directories skipped whole, by name. */
  skippedDirs: string[];
  findings: Finding[];
  checks: CheckSummary[];
  warnings: string[];
  /**
   * Checks that could not finish (registry unreachable, a scanner that threw, a
   * path that was not there). Each is also in `warnings`. Any entry means the
   * result is incomplete, so the verdict is never "clear".
   */
  incomplete: string[];
  counts: Record<Severity, number>;
  durationMs: number;
}

export async function scan(options: ScanOptions): Promise<FullScan> {
  const started = Date.now();
  const root = resolve(options.root);
  const roots = options.paths?.length ? options.paths.map((p) => resolve(root, p)) : [root];

  // A path that is not there scans nothing and finds nothing, which is
  // indistinguishable from a clean result unless it is said out loud. A typo in
  // a CI invocation is exactly how a check silently stops checking.
  const missingRoots = roots.filter((r) => {
    try {
      statSync(r);
      return false;
    } catch {
      return true;
    }
  });

  const walked = roots.map((r) => walk(r, { respectGitignore: !options.noGitignore }));
  const files = [...new Set(walked.flatMap((w) => w.files))];
  const gitIgnoredCount = walked.reduce((n, w) => n + w.gitIgnored, 0);
  const escapingSymlinkCount = walked.reduce((n, w) => n + w.escapingSymlinks, 0);
  const oversizeCount = walked.reduce((n, w) => n + w.oversize, 0);
  const skippedDirs = [...new Set(walked.flatMap((w) => w.skippedDirs))].sort();
  const framework = detectFramework(root, files);

  const ctx: ProjectContext = {
    root,
    files,
    framework,
    offline: Boolean(options.offline),
    cacheDir: process.env.CLEARTOSHIP_CACHE ?? join(homedir(), '.cache', 'cleartoship'),
    verbose: Boolean(options.verbose),
  };

  const active = SCANNERS.filter(
    (s) => s.applies(ctx) && !(options.noCommunity && s === communityScanner),
  );
  // Exactly the scanners compiled into this build. Nothing is loaded by package
  // name at run time: a scan that imports whatever module of a given name it finds
  // beside it runs a stranger's code, and the project being scanned is where that
  // module would come from.
  const activeAll = active;

  const findings: Finding[] = [];
  const checks: CheckSummary[] = [];
  const missingRootNotes = missingRoots.map(
    (r) => `${r} does not exist; nothing there was scanned.`,
  );
  const warnings: string[] = [...missingRootNotes];
  const incomplete: string[] = [...missingRootNotes];

  for (let i = 0; i < activeAll.length; i++) {
    const scanner = activeAll[i]!;
    options.onProgress?.(i + 1, activeAll.length, scanner.name);
    try {
      const result = await scanner.run(ctx);
      findings.push(...result.findings);
      checks.push(...result.checks);
      warnings.push(...result.warnings);
      // Reported once as a warning and once as a reason the verdict is not clear.
      const notVerified = result.incomplete ?? [];
      warnings.push(...notVerified);
      incomplete.push(...notVerified);
    } catch (err) {
      // A scanner that threw produced no findings, which is not the same thing as
      // finding nothing.
      const reason = `${scanner.name} failed: ${err instanceof Error ? err.message : String(err)}`;
      warnings.push(reason);
      incomplete.push(reason);
    }
  }

  // OSV.dev is authoritative and current; the vendored CVE-version regexes are
  // neither. If OSV answered for this project, stand them down rather than
  // report the same advisory twice from two sources of differing freshness.
  const osvAnswered = checks.some((c) => c.label.startsWith('Known vulnerabilities'));
  let filtered = osvAnswered
    ? findings.filter((f) => !GUARDVIBE_CVE_RULE_IDS.has(f.id))
    : findings;
  if (options.ignore?.length) {
    const ignored = new Set(options.ignore.map((s) => s.toUpperCase()));
    filtered = filtered.filter((f) => !ignored.has(f.id.toUpperCase()));
  }
  if (options.only?.length) {
    const only = new Set(options.only.map((s) => s.toUpperCase()));
    filtered = filtered.filter((f) => only.has(f.id.toUpperCase()));
  }
  if (options.minSeverity) {
    const floor = SEVERITY_ORDER[options.minSeverity];
    filtered = filtered.filter((f) => SEVERITY_ORDER[f.severity] >= floor);
  }

  // One taxonomy on the way out, and a second label for the findings that are
  // about an LLM or an agent rather than a web app. Both are applied here, so
  // every scanner's output is consistent without each one having to know.
  filtered = filtered.map((f) => {
    const canonical = normaliseOwasp(f.owasp);
    const llm = llmCategory(`${f.title} ${f.detail}`);
    if (!canonical && !llm) return f;
    return {
      ...f,
      owasp: canonical ?? f.owasp,
      meta: {
        ...f.meta,
        ...(canonical && canonical !== f.owasp ? { owaspUpstream: f.owasp } : {}),
        ...(llm ? { llm } : {}),
      },
    };
  });

  filtered.sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (bySeverity !== 0) return bySeverity;
    const byFile = (a.file ?? '').localeCompare(b.file ?? '');
    if (byFile !== 0) return byFile;
    return (a.line ?? 0) - (b.line ?? 0);
  });

  if (gitIgnoredCount > 0) {
    checks.push({
      label: `Ignored paths skipped (${gitIgnoredCount} ${gitIgnoredCount === 1 ? 'entry' : 'entries'})`,
      passed: true,
      note:
        'excluded by your own .gitignore, and a skipped directory takes its whole ' +
        'subtree with it. They are not part of the project and never reach a CI ' +
        'checkout. Use --no-gitignore to scan them anyway.',
    });
  }

  if (skippedDirs.length > 0) {
    checks.push({
      label: `Build and dependency directories skipped (${skippedDirs.join(', ')})`,
      passed: true,
      note:
        'dependency trees and build output, regenerated from source rather than written ' +
        'by hand. Nothing in them was read, so nothing in them was checked.',
    });
  }

  if (oversizeCount > 0) {
    checks.push({
      label: `Files too large to read (${oversizeCount})`,
      passed: true,
      note:
        'over the 2 MB cap, which is bundles and generated data rather than source. ' +
        'They produced no findings because they were never opened — not because they are clean.',
    });
  }

  if (escapingSymlinkCount > 0) {
    checks.push({
      label: `Symlinks leaving the scan root not followed (${escapingSymlinkCount})`,
      passed: true,
      note:
        'they point outside the directory you asked about, so their contents are not ' +
        'this project and are never read or quoted in this report',
    });
  }

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of filtered) counts[f.severity]++;

  return {
    root,
    framework: framework.describe(),
    fileCount: files.length,
    gitIgnoredCount,
    escapingSymlinkCount,
    oversizeCount,
    skippedDirs,
    findings: filtered,
    checks,
    warnings,
    incomplete,
    counts,
    durationMs: Date.now() - started,
  };
}
