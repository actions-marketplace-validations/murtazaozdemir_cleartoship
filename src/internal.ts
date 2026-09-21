/**
 * Generic scanner infrastructure, re-exported for first-party companion
 * packages that implement their own `Scanner`s outside this repository. None is
 * loaded by this build; every scanner it runs is compiled in.
 *
 * This is not a public API in the semver sense: it exists so a companion
 * package can reuse the same AST/file/suppression plumbing every scanner in
 * `src/scanners/` already depends on, and it may change shape between minor
 * versions the way Node's own `internal/` modules do. Anyone outside a
 * first-party companion package should import from `cleartoship` (`.`) instead.
 */
export type {
  Finding,
  ProjectContext,
  ScanResult,
  Scanner,
  Severity,
} from './types.js';
export { emptyResult, SEVERITY_ORDER } from './types.js';

export { parseSource, calleeName, calleeTail, hasDirective } from './utils/ast.js';
export { traverse } from './utils/traverse.js';
export type { Visitor } from './utils/traverse.js';
export { buildModuleIndex } from './utils/modules.js';
export type { ModuleIndex } from './utils/modules.js';
export {
  splitStatements,
  clauseAfter,
  normaliseTable,
  isAlwaysTrue,
  QUALIFIED_NAME,
} from './utils/sql.js';
export type { SqlStatement } from './utils/sql.js';
export { read, rel, isScript, isSql, snippetAt } from './utils/files.js';
export { adjustForPath } from './utils/paths.js';
export { Suppressions } from './utils/suppress.js';
export { OWASP_LLM, normaliseOwasp, llmCategory } from './utils/owasp.js';
