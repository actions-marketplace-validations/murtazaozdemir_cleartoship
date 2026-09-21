export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/** A single security problem found in the project. */
export interface Finding {
  /** Stable rule id, e.g. CTS001. Used for --ignore and for suppression comments. */
  id: string;
  severity: Severity;
  /** Short headline, e.g. "Missing Server Action authorization". */
  title: string;
  /** What is wrong here specifically, in one or two sentences. */
  detail: string;
  /** What to actually do about it. May be multi-line. */
  fix: string;
  /** Path relative to the scan root. Absent for project-wide findings. */
  file?: string;
  line?: number;
  column?: number;
  /** The offending source line, trimmed, for terminal context. */
  snippet?: string;
  cwe?: string;
  owasp?: string;
  /** Extra machine-readable context (package name, table name, ...). */
  meta?: Record<string, unknown>;
}

export interface CheckSummary {
  /** Scanner-level line for the "✔ PASS" rows, e.g. "42 packages verified on npm". */
  label: string;
  passed: boolean;
  note?: string;
}

export interface ScanResult {
  findings: Finding[];
  checks: CheckSummary[];
  /** Non-fatal problems: unreadable file, registry offline, etc. */
  warnings: string[];
  /**
   * Reasons this scanner could not finish checking something it was asked to
   * check — a registry that would not answer, a lookup service that failed.
   * A warning is information; this changes what the result means: with any of
   * these present, "no findings" is not "nothing wrong", so the run is never
   * reported as clear. Optional so a companion package built against an older
   * ScanResult keeps working.
   */
  incomplete?: string[];
}

export interface ProjectContext {
  root: string;
  /** Files to analyse, absolute paths, already filtered by ignore rules. */
  files: string[];
  framework: FrameworkInfo;
  offline: boolean;
  /** Absolute path of the on-disk registry cache directory. */
  cacheDir: string;
  verbose: boolean;
}

export interface FrameworkInfo {
  nextjs: 'app-router' | 'pages-router' | 'both' | null;
  supabase: boolean;
  prisma: boolean;
  drizzle: boolean;
  clerk: boolean;
  nextAuth: boolean;
  stripe: boolean;
  python: boolean;
  reactNative: boolean;
  firebase: boolean;
  /** Human-readable one-liner for the CLI header. */
  describe(): string;
}

export interface Scanner {
  name: string;
  /** Skip the scanner entirely when it has nothing to look at. */
  applies(ctx: ProjectContext): boolean;
  run(ctx: ProjectContext): Promise<ScanResult>;
}

export function emptyResult(): ScanResult {
  return { findings: [], checks: [], warnings: [], incomplete: [] };
}
