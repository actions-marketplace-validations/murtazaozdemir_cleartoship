/**
 * Vulnerability lookups against OSV.dev — Google's Open Source Vulnerabilities
 * database, the same data source behind osv-scanner (Apache-2.0). This is a
 * public HTTP API, so nothing is vendored and no licence attaches; ClearToShip
 * simply queries it.
 *
 * Authoritative CVE data replaces hand-maintained version regexes: a rule that
 * hard-codes "next before 14.1.1" is stale the week after it is written.
 */
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_QUERY = 'https://api.osv.dev/v1/query';
const TIMEOUT_MS = 15_000;

export interface OsvQuery {
  name: string;
  version: string;
  ecosystem: 'npm' | 'PyPI';
}

export interface OsvVulnerability {
  id: string;
  summary: string;
  details?: string;
  aliases: string[];
  /** Highest CVSS base score found on the record, when it publishes one. */
  cvss: number | null;
  /**
   * The qualitative rating the database itself assigns (GitHub's
   * `LOW`/`MODERATE`/`HIGH`/`CRITICAL`), for the records that carry no score
   * this can compute.
   */
  rating: string | null;
  /** Lowest version that is not affected, when the record states one. */
  fixedIn: string | null;
}

const CVSS3_METRICS: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
};
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

/** The spec's own rounding: the smallest one-decimal number >= the input. */
function roundUp1(value: number): number {
  const scaled = Math.round(value * 100_000);
  if (scaled % 10_000 === 0) return scaled / 100_000;
  return (Math.floor(scaled / 10_000) + 1) / 10;
}

/**
 * Base score for a CVSS v3.0/v3.1 vector string.
 *
 * OSV publishes `severity[].score` as the *vector* — `CVSS:3.1/AV:N/AC:L/...`
 * — not as a number, and GitHub-sourced records carry no numeric score
 * anywhere. Reading that field with `Number()` therefore produced `NaN` on
 * essentially every advisory, every CVE fell through to the `null` default, and
 * a 9.8 and a 5.3 were both reported as `high`. So the vector is computed,
 * per the v3.1 specification, rather than hoped for.
 *
 * v2 and v4 vectors are left to the qualitative rating: v2 is long obsolete and
 * v4's scoring is a lookup table, not a formula worth vendoring for a fallback.
 */
export function cvssFromVector(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const parts = new Map<string, string>();
  for (const pair of vector.split('/').slice(1)) {
    const [key, value] = pair.split(':');
    if (key && value) parts.set(key, value);
  }

  const scopeChanged = parts.get('S') === 'C';
  const pr = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[parts.get('PR') ?? ''];
  const av = CVSS3_METRICS.AV![parts.get('AV') ?? ''];
  const ac = CVSS3_METRICS.AC![parts.get('AC') ?? ''];
  const ui = CVSS3_METRICS.UI![parts.get('UI') ?? ''];
  const c = CVSS3_METRICS.C![parts.get('C') ?? ''];
  const i = CVSS3_METRICS.I![parts.get('I') ?? ''];
  const a = CVSS3_METRICS.A![parts.get('A') ?? ''];
  if ([pr, av, ac, ui, c, i, a].some((v) => v === undefined)) return null;

  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;

  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  const base = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return roundUp1(base);
}

function highestCvss(vuln: any): number | null {
  let best: number | null = null;
  const consider = (value: number | null) => {
    if (value === null || !Number.isFinite(value)) return;
    best = best === null ? value : Math.max(best, value);
  };
  for (const s of vuln?.severity ?? []) {
    const raw = s?.score;
    // Some databases publish a bare number here; OSV's own records publish the
    // vector. Accept either rather than assuming which one arrived.
    if (typeof raw === 'number') consider(raw);
    else if (typeof raw === 'string') {
      const asNumber = Number(raw);
      consider(Number.isFinite(asNumber) ? asNumber : cvssFromVector(raw));
    }
  }
  consider(Number(vuln?.database_specific?.cvss?.score));
  return best;
}

/** The database's own qualitative rating, upper-cased, when it publishes one. */
function ratingOf(vuln: any): string | null {
  const raw = vuln?.database_specific?.severity;
  return typeof raw === 'string' && raw ? raw.toUpperCase() : null;
}

function firstFixed(vuln: any): string | null {
  for (const affected of vuln?.affected ?? []) {
    for (const range of affected?.ranges ?? []) {
      for (const event of range?.events ?? []) {
        if (event?.fixed) return String(event.fixed);
      }
    }
  }
  return null;
}

function normalise(vuln: any): OsvVulnerability {
  return {
    id: String(vuln?.id ?? 'unknown'),
    summary: String(vuln?.summary ?? vuln?.details ?? 'No summary published.').split('\n')[0]!,
    details: typeof vuln?.details === 'string' ? vuln.details : undefined,
    aliases: Array.isArray(vuln?.aliases) ? vuln.aliases.map(String) : [],
    cvss: highestCvss(vuln),
    rating: ratingOf(vuln),
    fixedIn: firstFixed(vuln),
  };
}

/**
 * Returns, per input query index, the vulnerabilities affecting that exact
 * version. Failures resolve to an empty list: a database outage must never be
 * reported as "no vulnerabilities", so the caller is told separately —
 * `failed` is true when the batch failed, answered malformed, or any follow-up
 * detail lookup for a package the batch flagged did not come back. Results
 * that did come back are still returned alongside `failed: true`.
 */
export async function queryOsv(
  queries: OsvQuery[],
): Promise<{ results: OsvVulnerability[][]; failed: boolean }> {
  if (queries.length === 0) return { results: [], failed: false };

  const body = {
    queries: queries.map((q) => ({
      version: q.version,
      package: { name: q.name, ecosystem: q.ecosystem },
    })),
  };

  let batch: any;
  try {
    // cleartoship-ignore VG120 — OSV_BATCH is a module constant naming a
    // fixed https://api.osv.dev endpoint; nothing user-controlled reaches it.
    const res = await fetch(OSV_BATCH, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return { results: queries.map(() => []), failed: true };
    batch = await res.json();
  } catch {
    return { results: queries.map(() => []), failed: true };
  }

  // querybatch returns ids only. Re-query the few packages that actually have
  // hits to get summaries and fixed versions.
  const results: OsvVulnerability[][] = queries.map(() => []);
  // A 200 whose body does not answer every query is not an answer.
  if (!Array.isArray(batch?.results) || batch.results.length !== queries.length) {
    return { results, failed: true };
  }
  const affected: number[] = [];
  let detailFailed = false;
  batch.results.forEach((r: any, i: number) => {
    if (Array.isArray(r?.vulns) && r.vulns.length > 0) affected.push(i);
  });

  await Promise.all(
    affected.map(async (i) => {
      const q = queries[i]!;
      try {
        // cleartoship-ignore VG120 — OSV_QUERY is a module constant naming a
        // fixed https://api.osv.dev endpoint; nothing user-controlled reaches it.
        const res = await fetch(OSV_QUERY, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            version: q.version,
            package: { name: q.name, ecosystem: q.ecosystem },
          }),
          signal: AbortSignal.timeout(TIMEOUT_MS),
        });
        // The batch already said this version is vulnerable. A detail query
        // that fails used to leave the list empty and the run "checked" — a
        // known-vulnerable package reported as clean because the second of
        // two requests failed. Now it makes the result incomplete.
        if (!res.ok) {
          detailFailed = true;
          return;
        }
        const detail: any = await res.json();
        if (!Array.isArray(detail?.vulns) || detail.vulns.length === 0) {
          detailFailed = true;
          return;
        }
        results[i] = detail.vulns.map(normalise);
      } catch {
        detailFailed = true;
      }
    }),
  );

  return { results, failed: detailFailed };
}

type OsvSeverity = 'critical' | 'high' | 'medium' | 'low';

/** Maps a CVSS base score onto our severity vocabulary. */
export function severityFromCvss(cvss: number | null): OsvSeverity {
  if (cvss === null) return 'high';
  if (cvss >= 9) return 'critical';
  if (cvss >= 7) return 'high';
  if (cvss >= 4) return 'medium';
  return 'low';
}

const RATINGS: Record<string, OsvSeverity> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MODERATE: 'medium',
  MEDIUM: 'medium',
  LOW: 'low',
};

/**
 * The severity to report for one advisory: its computed CVSS score first, the
 * database's own rating where no score can be derived (a v4-only or v2-only
 * record), and `high` only when the record says nothing at all.
 */
export function severityForVulnerability(vuln: OsvVulnerability): OsvSeverity {
  if (vuln.cvss !== null) return severityFromCvss(vuln.cvss);
  const rated = vuln.rating ? RATINGS[vuln.rating] : undefined;
  return rated ?? 'high';
}
