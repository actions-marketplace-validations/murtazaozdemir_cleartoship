import { parse } from '@babel/parser';
import type { File } from '@babel/types';
import { traverse } from './traverse.js';
import type { Visitor } from './traverse.js';

/**
 * Deepest AST this tool will hand to a scanner. `@babel/traverse` recurses once
 * per level and overflows the stack somewhere between 2,000 and 3,000 levels;
 * a 20,000-deep `a.b.b.b…` member chain in one file used to throw "Maximum call
 * stack size exceeded" out of a scanner's traversal and take every other file's
 * findings from that scanner down with it. Real source code nests a few dozen
 * levels deep; a long generated `"a" + "b" + …` concatenation reaches a few
 * hundred.
 */
export const MAX_AST_DEPTH = 1000;

/** Keys that hold positions, comments or tokens rather than child nodes. */
const NOT_CHILDREN = new Set([
  'loc', 'start', 'end', 'range', 'extra', 'comments', 'leadingComments',
  'trailingComments', 'innerComments', 'tokens', 'errors',
]);

function isNode(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof (value as { type?: unknown }).type === 'string'
  );
}

/**
 * The deepest nesting of AST nodes under `root`, measured with an explicit
 * stack rather than recursion — measuring a tree too deep to recurse over must
 * not itself recurse. Stops early once past `stopAt`.
 */
export function astDepth(root: unknown, stopAt = Infinity): number {
  let max = 0;
  const stack: Array<[Record<string, unknown>, number]> = [];
  if (isNode(root)) stack.push([root, 1]);
  while (stack.length) {
    const [node, depth] = stack.pop()!;
    if (depth > max) {
      max = depth;
      if (max > stopAt) return max;
    }
    for (const key in node) {
      if (NOT_CHILDREN.has(key)) continue;
      const value = node[key];
      if (Array.isArray(value)) {
        for (const item of value) if (isNode(item)) stack.push([item, depth + 1]);
      } else if (isNode(value)) {
        stack.push([value, depth + 1]);
      }
    }
  }
  return max;
}

/**
 * Files that could not be parsed or walked in this process, by the name they
 * were parsed under, with the reason. `scan()` drains the entries for its own
 * files after every scanner has run and reports any that no scanner already
 * mentioned — a backstop, so a scanner that forgets to report a null parse
 * still cannot turn "never read" into "nothing found".
 */
const failures = new Map<string, string>();

/** A process that parses outside `scan()` must not grow this without bound. */
const MAX_RECORDED = 10_000;

function record(file: string, reason: string): void {
  if (failures.size >= MAX_RECORDED) failures.delete(failures.keys().next().value!);
  failures.set(file, reason);
}

/** Removes and returns the recorded failures for `files`. */
export function takeParseFailures(files: Iterable<string>): Map<string, string> {
  const out = new Map<string, string>();
  for (const f of files) {
    const reason = failures.get(f);
    if (reason !== undefined) {
      out.set(f, reason);
      failures.delete(f);
    }
  }
  return out;
}

export interface ParseOutcome {
  ast: File | null;
  /** Why `ast` is null, in words fit for an "incomplete" line. */
  reason?: string;
}

type Attempt = { ok: true; file: File; errors: number } | { ok: false; error: unknown };

function tryParse(code: string, plugins: any[]): Attempt {
  try {
    const file = parse(code, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      allowSuperOutsideMethod: true,
      allowUndeclaredExports: true,
      errorRecovery: true,
      plugins,
    }) as File & { errors?: unknown[] };
    return { ok: true, file, errors: file.errors?.length ?? 0 };
  } catch (error) {
    return { ok: false, error };
  }
}

/**
 * Parses TS/TSX/JS permissively. Vibe-coded repos routinely contain
 * decorators and other syntax soup, so every plugin that cannot conflict is
 * enabled and errors are recovered from rather than thrown.
 *
 * JSX is enabled for `.tsx`, `.js`, `.jsx`, `.mjs` and `.cjs` — and *not* for
 * `.ts`/`.mts`/`.cts`, where TypeScript itself forbids JSX and `<string>x` is a
 * type assertion. With `jsx` on, that assertion read as an unterminated JSX
 * element, the parse threw, and the whole file was silently skipped by every
 * AST rule. A `.js`-family file is tried with JSX first (React code routinely
 * lives in `.js`) and again without it if that parse fails.
 *
 * Never throws. A file that cannot be parsed, or whose tree is deeper than
 * `MAX_AST_DEPTH`, comes back with `ast: null` and a reason. The caller must
 * then report the file as not checked (push it to `result.incomplete`): a file
 * no rule could read is not a file with nothing wrong in it.
 */
export function parseSourceDetailed(code: string, filename: string): ParseOutcome {
  const outcome = parseUnrecorded(code, filename);
  if (outcome.ast === null) record(filename, outcome.reason ?? 'it could not be parsed');
  return outcome;
}

function parseUnrecorded(code: string, filename: string): ParseOutcome {
  const isTs = /\.(ts|tsx|mts|cts)$/.test(filename);
  const isTsx = /\.tsx$/.test(filename);
  const base: any[] = [
    'decorators-legacy',
    'classProperties',
    'classPrivateProperties',
    'classPrivateMethods',
    'dynamicImport',
    'topLevelAwait',
    // `importAssertions` until Babel 8 removed it, which makes every parse
    // throw and silently costs every AST rule its findings. The replacement
    // has existed since 7.22, so this is correct on both.
    'importAttributes',
    'explicitResourceManagement',
    isTs ? 'typescript' : 'flow',
  ];
  const wantsJsx = isTsx || !isTs;
  let attempt = tryParse(code, wantsJsx ? ['jsx', ...base] : base);
  if (wantsJsx && !isTsx && (!attempt.ok || attempt.errors > 0)) {
    const retry = tryParse(code, base);
    if (retry.ok && (!attempt.ok || retry.errors < attempt.errors)) attempt = retry;
  }
  if (!attempt.ok) {
    const err = attempt.error;
    return {
      ast: null,
      reason:
        err instanceof RangeError
          ? 'it is nested too deeply to parse'
          : `it could not be parsed (${err instanceof Error ? err.message.split('\n')[0] : String(err)})`,
    };
  }
  try {
    if (astDepth(attempt.file, MAX_AST_DEPTH) > MAX_AST_DEPTH) {
      return {
        ast: null,
        reason: `it nests more than ${MAX_AST_DEPTH} levels deep, which the AST rules cannot walk safely`,
      };
    }
  } catch {
    return { ast: null, reason: 'its syntax tree could not be measured' };
  }
  return { ast: attempt.file };
}

/**
 * The same, returning only the tree: null when the file could not be parsed or
 * is too deep to walk safely. A null here means the file was NOT checked, and
 * the scanner should say so in `result.incomplete`.
 */
export function parseSource(code: string, filename: string): File | null {
  return parseSourceDetailed(code, filename).ast;
}

/**
 * `traverse`, but a throw — a stack overflow on a pathological tree, or a bug
 * in a visitor — ends the walk of this one file instead of the whole scanner.
 *
 * Returns true when the traversal completed and false when it did not. On
 * false, whatever the visitors already recorded is real, but the file was not
 * fully checked: push it to `result.incomplete` and carry on with the next file.
 * Pass `file` (the absolute path, as in `ctx.files`) and `scan()` reports it
 * too, if the scanner does not.
 */
export function safeTraverse(ast: unknown, visitor: Visitor, file?: string): boolean {
  try {
    traverse(ast, visitor);
    return true;
  } catch (err) {
    if (file !== undefined) {
      record(
        file,
        err instanceof RangeError
          ? 'walking its syntax tree overflowed the stack'
          : `walking its syntax tree failed (${err instanceof Error ? err.message.split('\n')[0] : String(err)})`,
      );
    }
    return false;
  }
}

/** Dotted name for a callee expression: `supabase.auth.getUser` -> that string. */
export function calleeName(node: any): string {
  const parts: string[] = [];
  let cur = node;
  let guard = 0;
  while (cur && guard++ < 24) {
    if (cur.type === 'Identifier') {
      parts.unshift(cur.name);
      break;
    }
    if (cur.type === 'ThisExpression') {
      parts.unshift('this');
      break;
    }
    if (cur.type === 'MemberExpression') {
      if (cur.property?.type === 'Identifier' && !cur.computed) {
        parts.unshift(cur.property.name);
      } else if (cur.property?.type === 'StringLiteral') {
        parts.unshift(cur.property.value);
      } else {
        parts.unshift('*');
      }
      cur = cur.object;
      continue;
    }
    if (cur.type === 'CallExpression' || cur.type === 'OptionalCallExpression') {
      cur = cur.callee;
      continue;
    }
    if (cur.type === 'TSNonNullExpression' || cur.type === 'AwaitExpression') {
      cur = cur.expression ?? cur.argument;
      continue;
    }
    break;
  }
  return parts.join('.');
}

/** Last segment of a dotted callee name. */
export function calleeTail(node: any): string {
  const full = calleeName(node);
  const i = full.lastIndexOf('.');
  return i === -1 ? full : full.slice(i + 1);
}

/** True when the directive list of a function or program contains `use server`. */
export function hasDirective(node: any, directive: string): boolean {
  const body = node?.body?.type === 'BlockStatement' ? node.body : node;
  const directives = body?.directives;
  if (Array.isArray(directives)) {
    for (const d of directives) {
      if (d?.value?.value === directive) return true;
    }
  }
  // Some parses keep the directive as a plain expression statement.
  const stmts = body?.body;
  if (Array.isArray(stmts)) {
    for (const s of stmts.slice(0, 3)) {
      if (
        s?.type === 'ExpressionStatement' &&
        s.expression?.type === 'StringLiteral' &&
        s.expression.value === directive
      ) {
        return true;
      }
    }
  }
  return false;
}
