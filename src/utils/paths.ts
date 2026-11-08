import { SEVERITY_ORDER } from '../types.js';
import type { Severity } from '../types.js';

/**
 * Where a file sits decides how much a finding in it matters. A dependency CVE
 * already gets this treatment — CTS024 separates what ships from what only ever
 * runs on a developer's machine — and the same reasoning applies to the rules
 * that read code: an interpolated query in a migration script you run by hand is
 * a different risk from one behind a public HTTP endpoint, and neither is the
 * same as one in a test fixture.
 */
export type PathClass = 'production' | 'dev-tooling' | 'non-production';

/**
 * Tests, fixtures, examples and docs: the code is there to be read, not run.
 *
 * The test family accepts an affix — `transfer-tests/`, `integration_test/` —
 * because that is how those directories get named. The rest are matched whole
 * on purpose: `demo` is a fixture directory, but `demo-billing/` may well be a
 * shipped feature, and quietly downgrading it would be the worse mistake.
 * Every segment must be followed by a slash — these are directories. A file
 * named `spec-parser.ts` is production code that happens to parse specs.
 */
const NON_PRODUCTION =
  // `_test.go` and `testdata/` are Go's own conventions, and `test_*.py` /
  // `conftest.py` are pytest's: none of them spells "test" the JavaScript way,
  // so a Go scanner's 187 fixture keys were criticals while the same strings
  // in a `.test.ts` were low.
  /(^|\/)(?:(?:[\w.]+[-_])?(?:tests?|specs?|e2e|fixtures?|mocks?)(?:[-_][\w.]+)?|__tests__|__mocks__|__fixtures__|examples?|docs?|demo|samples?|cypress|playwright|stories|testdata)\/|\.(test|spec|stories|fixture)\.[a-z]+$|_test\.go$|(^|\/)(?:test_[^/]*\.py|conftest\.py)$/i;

/**
 * Build and maintenance tooling. It runs on a developer's machine or in CI,
 * with credentials its author already holds, and never answers a request from
 * the internet — so nothing here is reachable by an attacker who is not already
 * inside the repository.
 *
 * `bin/` is deliberately absent: for a published CLI that is the shipped entry
 * point. So is `migrations/`, which is the production schema.
 */
const DEV_TOOLING =
  /(^|\/)(scripts?|tools?|tooling|\.github|\.husky|\.circleci|seeds?|benchmarks?|codegen)\/|(^|\/)[^/]*\.config\.[cm]?[jt]s$|(^|\/)(Makefile|Dockerfile[^/]*|docker-compose[^/]*\.ya?ml)$/i;

export function pathClass(relPath: string): PathClass {
  if (NON_PRODUCTION.test(relPath)) return 'non-production';
  if (DEV_TOOLING.test(relPath)) return 'dev-tooling';
  return 'production';
}

const ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

/** One step down the scale, floored at `low`. */
export function demote(severity: Severity): Severity {
  const index = SEVERITY_ORDER[severity];
  return ORDER[Math.max(1, index - 1)]!;
}

/**
 * One step up the scale, capped at `critical`.
 *
 * The mirror of `demote`, for the case where the surrounding context makes a
 * finding worse than the rule alone knows: a credential that would be a
 * contained problem on the server is a different problem once the file it sits
 * in is compiled into the bundle every visitor downloads.
 */
export function promote(severity: Severity): Severity {
  const index = SEVERITY_ORDER[severity];
  return ORDER[Math.min(ORDER.length - 1, index + 1)]!;
}

/**
 * The severity a finding should carry once you know where it lives, plus the
 * sentence explaining the adjustment — always stated, never silent.
 */
export function adjustForPath(
  severity: Severity,
  relPath: string,
): { severity: Severity; note: string } {
  switch (pathClass(relPath)) {
    case 'non-production':
      return {
        severity: 'low',
        note: ' (Path looks like tests, fixtures or docs, so the severity is reduced.)',
      };
    case 'dev-tooling':
      return {
        severity: demote(severity),
        note:
          ' (Path is build or maintenance tooling rather than shipped code — it runs on a ' +
          'developer machine or in CI, not in response to a request — so the severity is one ' +
          'step lower than it would be in the app itself.)',
      };
    default:
      return { severity, note: '' };
  }
}
