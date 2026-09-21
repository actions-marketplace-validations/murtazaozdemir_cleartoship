import pc from 'picocolors';
import { SEVERITY_ORDER } from './types.js';
import type { Finding, Severity } from './types.js';
import type { FullScan } from './scan.js';

const RULE = '─'.repeat(74);

export type Verdict = 'hold' | 'conditional' | 'clear';

/**
 * The one place the verdict is decided. The terminal report, the JSON, the
 * Markdown comment and the badge each used to work it out from the counts alone,
 * so a run in which a check never finished — the registry did not answer, a
 * scanner threw — came out "clear", because nothing was found. Finding nothing
 * and not being able to look are different results; only the first is clear.
 */
export function verdictOf(scan: Pick<FullScan, 'counts'> & { incomplete?: string[] }): Verdict {
  if (scan.counts.critical > 0) return 'hold';
  if (scan.counts.high > 0) return 'conditional';
  if ((scan.incomplete ?? []).length > 0) return 'conditional';
  return 'clear';
}

const SEVERITY_STYLE: Record<Severity, { label: string; paint: (s: string) => string }> = {
  critical: { label: 'CRITICAL', paint: (s) => pc.bold(pc.red(s)) },
  high: { label: 'HIGH    ', paint: pc.red },
  medium: { label: 'MEDIUM  ', paint: pc.yellow },
  low: { label: 'LOW     ', paint: pc.blue },
  info: { label: 'INFO    ', paint: pc.dim },
};

function indent(text: string, prefix: string): string {
  return text
    .split('\n')
    .map((l) => prefix + l)
    .join('\n');
}

function wrap(text: string, width: number): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = '';
  for (const word of words) {
    if (line.length + word.length + 1 > width && line) {
      lines.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(line);
  return lines.join('\n');
}

/**
 * Wraps the prose lines of a fix while leaving indented lines — SQL and code
 * snippets — exactly as written, since reflowing those would break them.
 */
function renderFix(fix: string): string {
  return fix
    .split('\n')
    .map((line, i) => {
      if (/^\s/.test(line)) return line;
      const prefixed = i === 0 ? `\u2192 ${line}` : line;
      return wrap(prefixed, 68);
    })
    .join('\n');
}

export function renderTerminal(scan: FullScan, opts: { showPassed: boolean } = { showPassed: true }): string {
  const out: string[] = [];
  const total = scan.findings.length;

  if (total > 0) {
    out.push('');
    out.push(pc.dim(RULE));
    const summary = (['critical', 'high', 'medium', 'low', 'info'] as Severity[])
      .filter((s) => scan.counts[s] > 0)
      .map((s) => SEVERITY_STYLE[s].paint(`${scan.counts[s]} ${s}`))
      .join(pc.dim(' · '));
    out.push(`  ${pc.bold('SCAN FINDINGS')}  ${pc.dim('(')}${summary}${pc.dim(')')}`);
    out.push(pc.dim(RULE));
    out.push('');

    for (const f of scan.findings) {
      const style = SEVERITY_STYLE[f.severity];
      const location = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : scan.root;
      out.push(`  ${style.paint('✖ ' + style.label)}  ${pc.bold(f.title)}  ${pc.dim(f.id)}`);
      out.push(`    ${pc.dim('at')} ${pc.cyan(location)}`);
      if (f.snippet) out.push(`    ${pc.dim('│')} ${pc.dim(f.snippet)}`);
      out.push(indent(wrap(f.detail, 68), '    '));
      out.push(indent(pc.green(renderFix(f.fix)), '    '));
      if (f.owasp) out.push(`    ${pc.dim(f.owasp)}${f.cwe ? pc.dim(' · ' + f.cwe) : ''}`);
      out.push('');
    }
  }

  if (opts.showPassed) {
    const passed = scan.checks.filter((c) => c.passed);
    if (passed.length) {
      for (const c of passed) {
        out.push(`  ${pc.green('✔ PASS')}      ${c.label}${c.note ? pc.dim(` — ${c.note}`) : ''}`);
      }
      out.push('');
    }
  }

  if (scan.warnings.length) {
    for (const w of scan.warnings) out.push(`  ${pc.yellow('! WARN')}      ${w}`);
    out.push('');
  }

  out.push(pc.dim(RULE));
  const blocking = scan.counts.critical + scan.counts.high;
  if (scan.counts.critical > 0) {
    out.push(`  ${pc.bold(pc.red('VERDICT: 🔴 HOLD — resolve the critical findings before deploying'))}`);
  } else if (blocking > 0) {
    out.push(`  ${pc.bold(pc.yellow('VERDICT: 🟡 CONDITIONAL — no criticals, but high-severity gaps remain'))}`);
  } else if ((scan.incomplete ?? []).length > 0) {
    const n = scan.incomplete.length;
    out.push(
      `  ${pc.bold(pc.yellow(`VERDICT: 🟡 CONDITIONAL — nothing blocking found, but ${n} check${n === 1 ? '' : 's'} could not complete`))}`,
    );
    out.push(pc.dim('  This result is incomplete, not clear: see the WARN lines above for what was not checked.'));
  } else if (total > 0) {
    // Mediums are not "low-priority notes". Saying so about a finding the
    // reader can see is rated medium is the small dishonesty that teaches
    // people to stop reading the verdict line.
    const tail =
      scan.counts.medium > 0
        ? `— ${total} non-blocking finding${total === 1 ? '' : 's'}, ${scan.counts.medium} medium`
        : `— ${total} low-priority note${total === 1 ? '' : 's'}`;
    out.push(`  ${pc.bold(pc.green('VERDICT: 🟢 CLEAR TO SHIP'))} ${pc.dim(tail)}`);
  } else {
    out.push(`  ${pc.bold(pc.green('VERDICT: 🟢 CLEAR TO SHIP — all checks passed'))}`);
  }
  out.push(pc.dim(RULE));
  out.push(
    pc.dim(`  ${scan.fileCount} files · ${(scan.durationMs / 1000).toFixed(1)}s`),
  );

  if (total > 0) {
    out.push('');
    out.push(`  ${pc.dim('Hand the fixes to your AI editor:')}  ${pc.cyan('npx cleartoship --fix-prompt')}`);
  }
  out.push('');
  return out.join('\n');
}

export function renderJson(scan: FullScan): string {
  return JSON.stringify(
    {
      version: 1,
      tool: 'cleartoship',
      root: scan.root,
      framework: scan.framework,
      fileCount: scan.fileCount,
      gitIgnoredCount: scan.gitIgnoredCount,
      escapingSymlinkCount: scan.escapingSymlinkCount,
      oversizeCount: scan.oversizeCount,
      skippedDirs: scan.skippedDirs,
      durationMs: scan.durationMs,
      verdict: verdictOf(scan),
      counts: scan.counts,
      findings: scan.findings,
      checks: scan.checks,
      warnings: scan.warnings,
      incomplete: scan.incomplete ?? [],
    },
    null,
    2,
  );
}

const SARIF_LEVEL: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

export function renderSarif(scan: FullScan, version: string): string {
  const rules = new Map<string, any>();
  for (const f of scan.findings) {
    if (rules.has(f.id)) continue;
    rules.set(f.id, {
      id: f.id,
      name: f.title.replace(/\s+/g, ''),
      shortDescription: { text: f.title },
      fullDescription: { text: f.detail },
      help: { text: f.fix },
      defaultConfiguration: { level: SARIF_LEVEL[f.severity] },
      properties: {
        tags: [f.owasp, f.cwe].filter(Boolean),
        'security-severity': String(SEVERITY_ORDER[f.severity] * 2.4),
      },
    });
  }
  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'ClearToShip',
              version,
              informationUri: 'https://cleartoship.app',
              rules: [...rules.values()],
            },
          },
          results: scan.findings.map((f) => ({
            ruleId: f.id,
            level: SARIF_LEVEL[f.severity],
            message: { text: `${f.title}. ${f.detail}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file ?? '.' },
                  region: { startLine: Math.max(1, f.line ?? 1) },
                },
              },
            ],
          })),
        },
      ],
    },
    null,
    2,
  );
}

export function renderFixPrompt(scan: FullScan): string {
  if (scan.findings.length === 0) {
    return 'ClearToShip found no issues to fix.\n';
  }
  const lines: string[] = [];
  lines.push('# ClearToShip — security fixes to apply');
  lines.push('');
  lines.push(
    'You are fixing security findings in this repository. Apply every fix below. ' +
      'Do not change unrelated behaviour, do not weaken any existing check, and keep the ' +
      'project’s existing conventions and helper functions. After each fix, briefly state ' +
      'what you changed.',
  );
  lines.push('');
  lines.push(`Project: ${scan.framework}`);
  lines.push('');

  const bySeverity = ['critical', 'high', 'medium', 'low'] as const;
  for (const sev of bySeverity) {
    const group = scan.findings.filter((f) => f.severity === sev);
    if (!group.length) continue;
    lines.push(`## ${sev.toUpperCase()} (${group.length})`);
    lines.push('');
    group.forEach((f, i) => {
      lines.push(`### ${i + 1}. ${f.title} \`${f.id}\``);
      lines.push('');
      if (f.file) lines.push(`**Location:** \`${f.file}${f.line ? `:${f.line}` : ''}\``);
      if (f.snippet) lines.push(`**Offending line:** \`${fenceSafe(f.snippet)}\``);
      lines.push('');
      lines.push(`**Problem:** ${fenceSafe(f.detail)}`);
      lines.push('');
      lines.push('**Required fix:**');
      lines.push('');
      lines.push('```');
      lines.push(fenceSafe(f.fix));
      lines.push('```');
      lines.push('');
    });
  }
  lines.push('---');
  lines.push('');
  lines.push(
    'When you are done, re-run `npx cleartoship` and confirm the findings above are gone ' +
      'and no new ones appeared.',
  );
  lines.push('');
  return lines.join('\n');
}

/**
 * Text that came out of the scanned repository, on its way into a pull-request
 * comment. A finding's detail quotes what it found — a package name, an install
 * script, a source line — and the Action posts that to GitHub, where raw HTML
 * renders. `</details>` in a package.json script would close the block it was
 * supposed to sit inside; an `<img>` would fetch on view. Escaped rather than
 * stripped, so the reader still sees exactly what is in their repo.
 */
function mdSafe(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/```/g, '`\u200b``');
}

/** The same, for text going inside a fenced block: only the fence can break out. */
function fenceSafe(text: string): string {
  return text.replace(/```/g, '`\u200b``');
}

const MD_SEVERITY: Record<Severity, string> = {
  critical: '🔴 Critical',
  high: '🟠 High',
  medium: '🟡 Medium',
  low: '🔵 Low',
  info: '⚪ Info',
};

/**
 * Markdown for a GitHub pull-request comment or an Actions job summary. Kept
 * compact: the verdict and counts up top, findings grouped by severity in a
 * collapsible block, so a passing PR shows one green line and a failing one puts
 * the blocking issues first without burying the diff.
 */
export function renderMarkdown(scan: FullScan): string {
  const out: string[] = [];
  const total = scan.findings.length;
  const verdict = verdictOf(scan);
  const notChecked = scan.incomplete ?? [];

  const heading =
    verdict === 'hold'
      ? '## 🔴 ClearToShip — hold before shipping'
      : verdict === 'conditional'
        ? scan.counts.high > 0
          ? '## 🟡 ClearToShip — clear, with high-severity gaps'
          : '## 🟡 ClearToShip — nothing blocking found, but the run is incomplete'
        : total > 0
          ? '## 🟢 ClearToShip — clear to ship'
          : '## 🟢 ClearToShip — clear to ship, all checks passed';
  out.push(heading);
  out.push('');

  const counts = (['critical', 'high', 'medium', 'low'] as Severity[])
    .filter((sev) => scan.counts[sev] > 0)
    .map((sev) => `**${scan.counts[sev]}** ${sev}`)
    .join(' · ');
  out.push(
    `\`${scan.framework}\` · ${scan.fileCount} files · ${(scan.durationMs / 1000).toFixed(1)}s` +
      (counts ? ` · ${counts}` : ''),
  );
  out.push('');

  if (notChecked.length > 0) {
    out.push('> ⚠️ **Not everything could be checked — treat this result as incomplete:**');
    for (const reason of notChecked) out.push(`> - ${mdSafe(reason)}`);
    out.push('');
  }

  if (total === 0) {
    out.push(
      notChecked.length > 0
        ? 'No findings in what could be checked.'
        : 'No security findings. ✅',
    );
    out.push('');
    out.push('<sub>Static pre-flight for AI-built apps · [cleartoship.app](https://cleartoship.app)</sub>');
    return out.join('\n');
  }

  const bySeverity = ['critical', 'high', 'medium', 'low'] as const;
  const blocking = scan.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
  const rest = scan.findings.filter((f) => f.severity === 'medium' || f.severity === 'low');

  const table = (findings: Finding[]) => {
    const rows = ['| Severity | Rule | Finding | Location |', '| --- | --- | --- | --- |'];
    for (const f of findings) {
      const loc = f.file ? `\`${mdSafe(f.file)}${f.line ? `:${f.line}` : ''}\`` : '—';
      const title = mdSafe(f.title).replace(/\|/g, '\\|');
      rows.push(`| ${MD_SEVERITY[f.severity]} | \`${f.id}\` | ${title} | ${loc} |`);
    }
    return rows.join('\n');
  };

  if (blocking.length > 0) {
    out.push(table(blocking));
    out.push('');
  }
  if (rest.length > 0) {
    out.push('<details><summary>' + `${rest.length} lower-severity finding${rest.length === 1 ? '' : 's'}` + '</summary>');
    out.push('');
    out.push(table(rest));
    out.push('');
    out.push('</details>');
    out.push('');
  }

  // The single most severe finding gets its fix shown inline; the rest are a
  // command away, so the comment stays scannable.
  const worst = scan.findings[0];
  if (worst) {
    out.push(
      `<details><summary>How to fix <code>${mdSafe(worst.id)}</code> — ${mdSafe(worst.title)}</summary>`,
    );
    out.push('');
    out.push(mdSafe(worst.detail));
    out.push('');
    out.push('```');
    out.push(fenceSafe(worst.fix));
    out.push('```');
    out.push('');
    out.push('</details>');
    out.push('');
  }

  out.push('Run `npx cleartoship --fix-prompt` for a prompt that fixes all of these in Cursor or Claude Code.');
  out.push('');
  out.push('<sub>Static pre-flight for AI-built apps · [cleartoship.app](https://cleartoship.app)</sub>');
  return out.join('\n');
}

export function renderBadge(scan: FullScan): string {
  const verdict = verdictOf(scan);
  const colour = verdict === 'clear' ? '10b981' : verdict === 'conditional' ? 'f59e0b' : 'ef4444';
  const label = verdict === 'clear' ? 'clear%20to%20ship' : verdict;
  return `[![ClearToShip](https://img.shields.io/badge/ClearToShip-${label}-${colour}?style=flat-square)](https://cleartoship.app)`;
}
