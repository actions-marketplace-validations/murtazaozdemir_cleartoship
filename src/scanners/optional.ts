import type { Scanner } from '../types.js';

/**
 * First-party companion packages that add scanners to a run when installed
 * and licensed. Currently just `cleartoship-rules-pro` (Supabase/Postgres RLS,
 * Next.js Server Actions & Route Handlers, LLM/agent risk) — the moat rules
 * that moved out of this MIT package.
 *
 * This module deliberately knows nothing about licenses or how a package
 * decides whether to return scanners: all of that lives in the optional
 * package itself, so this free/MIT code never has to be audited for whether
 * it phones home. It only tries to load a package by name and, if that
 * succeeds and it exports `getScanners`, asks it for scanners.
 */
const OPTIONAL_SCANNER_PACKAGES = ['cleartoship-rules-pro'];

interface OptionalScannerModule {
  getScanners?(opts?: { offline?: boolean }): Promise<Scanner[]>;
}

export async function loadOptionalScanners(
  opts: { offline?: boolean } = {},
  // A function parameter, not a literal `import()` call at the use site: this
  // is what keeps TypeScript (and esbuild, see scripts/bundle.mjs) from ever
  // trying to statically resolve or inline `cleartoship-rules-pro` into this
  // package's build. It also makes this loader unit-testable without a real
  // pro package installed — tests substitute a stub `importer`.
  importer: (spec: string) => Promise<unknown> = (spec) => import(spec),
): Promise<Scanner[]> {
  const out: Scanner[] = [];
  for (const pkg of OPTIONAL_SCANNER_PACKAGES) {
    try {
      const mod = (await importer(pkg)) as OptionalScannerModule;
      if (typeof mod.getScanners === 'function') {
        out.push(...(await mod.getScanners(opts)));
      }
    } catch {
      // Not installed, or it threw constructing its scanners — the free tier
      // behaves identically either way: as if the package were never there.
    }
  }
  return out;
}
