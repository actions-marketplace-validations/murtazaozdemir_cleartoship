import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const TIMEOUT_MS = 8000;

export interface PackageFacts {
  name: string;
  ecosystem: 'npm' | 'pypi';
  exists: boolean;
  /** ISO date the package was first published. */
  created?: string;
  /** Downloads in the last week (npm only). */
  weeklyDownloads?: number;
  versions?: string[];
  repository?: string;
  maintainers?: number;
  deprecated?: boolean;
  /**
   * npm removed the package for malware and serves HTTP 451. This is a much
   * stronger signal than "does not exist" — the name was actively weaponised.
   */
  securityHold?: boolean;
  /**
   * The package was published and then withdrawn: either a 404 with download
   * traffic still recorded against it, or — the shape that reads as healthy —
   * a 200 whose packument has no versions left at all. Either way the name is
   * free for anyone to take over, and whoever takes it inherits the installs.
   */
  unpublished?: boolean;
  /** Set when the lookup itself failed (offline, rate limited, ...). */
  error?: string;
}

export class Registry {
  private readonly dir: string;
  private readonly memo = new Map<string, PackageFacts>();
  public offline: boolean;
  public networkErrors = 0;

  constructor(cacheDir: string, offline = false) {
    this.dir = cacheDir;
    this.offline = offline;
    if (!offline) {
      try {
        mkdirSync(this.dir, { recursive: true });
      } catch {
        /* cache is an optimisation; carry on without it */
      }
    }
  }

  private cachePath(key: string): string {
    return join(this.dir, createHash('sha256').update(key).digest('hex').slice(0, 40) + '.json');
  }

  private readCache(key: string): PackageFacts | null {
    try {
      const raw = readFileSync(this.cachePath(key), 'utf8');
      const parsed = JSON.parse(raw) as { at: number; facts: PackageFacts };
      if (Date.now() - parsed.at > CACHE_TTL_MS) return null;
      return parsed.facts;
    } catch {
      return null;
    }
  }

  private writeCache(key: string, facts: PackageFacts): void {
    if (facts.error) return;
    try {
      writeFileSync(this.cachePath(key), JSON.stringify({ at: Date.now(), facts }));
    } catch {
      /* ignore */
    }
  }

  private async getJson(url: string, accept?: string): Promise<any | number> {
    // cleartoship-ignore VG120 — the URL is built from a package name against a
    // fixed registry host a few lines below; fetching it is this class's purpose.
    const res = await fetch(url, {
      headers: {
        'user-agent': 'cleartoship (+https://cleartoship.app)',
        ...(accept ? { accept } : {}),
      },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return res.status;
    return await res.json();
  }

  /** Weekly downloads, or undefined when the endpoint has nothing to say. */
  private async downloadsFor(encoded: string): Promise<number | undefined> {
    try {
      const dl = await this.getJson(`https://api.npmjs.org/downloads/point/last-week/${encoded}`);
      if (typeof dl === 'object' && dl && typeof dl.downloads === 'number') return dl.downloads;
    } catch {
      /* the downloads API is flaky and non-essential */
    }
    return undefined;
  }

  async lookup(name: string, ecosystem: 'npm' | 'pypi'): Promise<PackageFacts> {
    const key = `${ecosystem}:${name}`;
    const memo = this.memo.get(key);
    if (memo) return memo;
    const cached = this.readCache(key);
    if (cached) {
      this.memo.set(key, cached);
      return cached;
    }
    if (this.offline) {
      const facts: PackageFacts = { name, ecosystem, exists: true, error: 'offline' };
      this.memo.set(key, facts);
      return facts;
    }

    let facts: PackageFacts;
    try {
      facts = ecosystem === 'npm' ? await this.lookupNpm(name) : await this.lookupPypi(name);
    } catch (err) {
      this.networkErrors++;
      facts = {
        name,
        ecosystem,
        exists: true, // fail open: never claim a package is fake because the network blipped
        error: err instanceof Error ? err.message : String(err),
      };
    }
    this.memo.set(key, facts);
    this.writeCache(key, facts);
    return facts;
  }

  private async lookupNpm(name: string): Promise<PackageFacts> {
    const encoded = name.replace('/', '%2f');
    const doc = await this.getJson(
      `https://registry.npmjs.org/${encoded}`,
      'application/vnd.npm.install-v1+json',
    );

    // 451 is npm's "removed for malware" response. Never conflate it with 404.
    if (doc === 451) {
      return { name, ecosystem: 'npm', exists: false, securityHold: true };
    }
    if (doc === 404) {
      // A name with no packument but real install traffic was published and then
      // pulled, which leaves it open to takeover rather than merely invented.
      const downloads = await this.downloadsFor(encoded);
      return {
        name,
        ecosystem: 'npm',
        exists: false,
        weeklyDownloads: downloads,
        unpublished: downloads !== undefined && downloads > 0,
      };
    }
    if (typeof doc === 'number') throw new Error(`npm registry returned ${doc}`);

    const versions = Object.keys(doc.versions ?? {});

    // A packument with no versions left is an unpublish, not a package. npm
    // answers **200** for it — the document carries `time.unpublished` and an
    // empty `versions` — so reading the status instead of the content called the
    // name a package that exists, and `time.created` then made it a *recent*
    // one: CTS021, "newly published, barely used". This project's own name is
    // the example (unpublished 2026-09-03, and its README says so in prose),
    // which is how the 2026-10-13 audit found it — the scanner reported the
    // sentence warning people off the name as a barely-used dependency of this
    // repository. An install of such a name fails, and the name is free for
    // anyone to claim and inherit those installs, which is CTS027's whole point.
    if (versions.length === 0) {
      const downloads = await this.downloadsFor(encoded);
      return {
        name,
        ecosystem: 'npm',
        exists: false,
        unpublished: true,
        weeklyDownloads: downloads,
        created: typeof doc.time?.created === 'string' ? doc.time.created : undefined,
      };
    }

    const facts: PackageFacts = { name, ecosystem: 'npm', exists: true, versions };

    const downloads = await this.downloadsFor(encoded);
    facts.weeklyDownloads = downloads;

    // The full document carries publish dates and maintainer counts, but it is
    // large. Only fetch it for packages that are not obviously well established.
    if (downloads === undefined || downloads < 10_000) {
      try {
        const full = await this.getJson(`https://registry.npmjs.org/${encoded}`);
        if (typeof full === 'object' && full) {
          facts.created = full.time?.created;
          facts.maintainers = Array.isArray(full.maintainers) ? full.maintainers.length : undefined;
          const repo = full.repository;
          facts.repository = typeof repo === 'string' ? repo : repo?.url;
          const latest = full['dist-tags']?.latest;
          facts.deprecated = Boolean(latest && full.versions?.[latest]?.deprecated);
        }
      } catch {
        /* keep the abbreviated facts */
      }
    }
    return facts;
  }

  private async lookupPypi(name: string): Promise<PackageFacts> {
    const doc = await this.getJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
    if (doc === 404) return { name, ecosystem: 'pypi', exists: false };
    if (doc === 451) return { name, ecosystem: 'pypi', exists: false, securityHold: true };
    if (typeof doc === 'number') throw new Error(`PyPI returned ${doc}`);

    const releases: Record<string, any[]> = doc.releases ?? {};
    let earliest: string | undefined;
    for (const files of Object.values(releases)) {
      for (const f of files ?? []) {
        const t = f?.upload_time_iso_8601 ?? f?.upload_time;
        if (t && (!earliest || t < earliest)) earliest = t;
      }
    }
    return {
      name,
      ecosystem: 'pypi',
      exists: true,
      created: earliest,
      versions: Object.keys(releases),
      repository:
        doc.info?.project_urls?.Source ??
        doc.info?.project_urls?.Homepage ??
        doc.info?.home_page ??
        undefined,
    };
  }
}

/** Runs `worker` over `items` with bounded concurrency, preserving order. */
export async function pool<T, R>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = cursor++;
      if (i >= items.length) return;
      results[i] = await worker(items[i]!, i);
    }
  });
  await Promise.all(runners);
  return results;
}
