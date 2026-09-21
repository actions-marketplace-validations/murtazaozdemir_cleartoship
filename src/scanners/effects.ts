import { read, parseSource, calleeName, calleeTail } from '../internal.js';
import type { ModuleIndex } from '../internal.js';
import type { File } from '@babel/types';

/**
 * Which first-party functions provably do nothing outside the process?
 *
 * A route that POSTs is assumed to write, because the handler alone rarely shows where.
 * When the only things it calls are helpers — `refineQuery(body)`, `evaluate(text)`,
 * `toFile(data)` — the assumption can be checked rather than made: read the helper. If
 * every call inside it (and inside whatever it calls) is a string or array method, a
 * response builder, or an LLM client call, then no caller-supplied value can reach a
 * data store through it, and the "write with no auth check" claim has nothing behind it.
 *
 * The test is a whitelist on purpose. A helper is inert only if *every* call in it is
 * known to be; an unrecognised call — `db.thing()`, `fetch(...)`, `sendEmail(...)`, a
 * method on a client the scanner has never heard of — makes it not inert. That keeps
 * the errors on the side of reporting, so this can only ever remove a finding by
 * positively showing there was nothing to protect. Third-party packages are never
 * followed: a call into one is unknown, hence not inert.
 */

/** How many import hops to follow before giving up. */
const MAX_DEPTH = 3;

const EMPTY: ReadonlySet<string> = new Set();

/** Stands in for a construct with effects that has no callee name, such as a tagged template. */
const OPAQUE = '\u0000opaque';

export interface EffectOptions {
  /** True for a call with no effect outside the process. Supplied by the caller. */
  isInert(full: string, tail: string): boolean;
  index: ModuleIndex;
  /** Per-scan memo, keyed by absolute file path. */
  cache: Map<string, ReadonlySet<string>>;
}

interface Call {
  full: string;
  tail: string;
}

function callsIn(node: any, out: Call[], depth = 0): void {
  if (!node || typeof node !== 'object' || depth > 400) return;
  if (Array.isArray(node)) {
    for (const child of node) callsIn(child, out, depth + 1);
    return;
  }
  if (typeof node.type !== 'string') return;
  if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression') {
    const full = calleeName(node.callee);
    // A callee that is not a plain name — `(await getClient()).send(x)`, `fns[i]()` — cannot be
    // shown inert, so it is recorded as something that is not.
    out.push(full ? { full, tail: calleeTail(node.callee) } : { full: OPAQUE, tail: OPAQUE });
  } else if (node.type === 'TaggedTemplateExpression') {
    out.push({ full: OPAQUE, tail: OPAQUE });
  }
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'leadingComments' || key === 'trailingComments') continue;
    const value = node[key];
    if (value && typeof value === 'object') callsIn(value, out, depth + 1);
  }
}

/** Top-level `function f()` / `const f = () => {}`, exported or not, with the calls in each. */
function collectFunctions(ast: File): Map<string, Call[]> {
  const found = new Map<string, Call[]>();

  const add = (name: string | undefined, body: any) => {
    if (!name || !body) return;
    const calls: Call[] = [];
    callsIn(body, calls);
    found.set(name, calls);
  };

  const fromDeclaration = (decl: any, isDefault = false) => {
    if (!decl) return;
    if (decl.type === 'FunctionDeclaration') {
      add(decl.id?.name, decl.body);
      if (isDefault) add('default', decl.body);
      return;
    }
    if (decl.type !== 'VariableDeclaration') return;
    for (const d of decl.declarations ?? []) {
      if (d?.id?.type !== 'Identifier') continue;
      const init = d.init;
      if (init?.type === 'ArrowFunctionExpression' || init?.type === 'FunctionExpression') {
        add(d.id.name, init.body);
      }
    }
  };

  for (const stmt of ast.program.body) {
    if (stmt.type === 'ExportNamedDeclaration') fromDeclaration((stmt as any).declaration);
    else if (stmt.type === 'ExportDefaultDeclaration') fromDeclaration((stmt as any).declaration, true);
    else fromDeclaration(stmt);
  }
  return found;
}

/**
 * Names, as spelled in `file`, of functions with no effect outside the process: defined
 * here, or imported from a first-party module where they are defined that way.
 */
export function inertNamesFor(
  file: string,
  opts: EffectOptions,
  preparsed?: File | null,
  depth = 0,
  stack: Set<string> = new Set(),
): ReadonlySet<string> {
  const memo = opts.cache.get(file);
  if (memo) return memo;
  if (stack.has(file) || depth > MAX_DEPTH) return EMPTY;

  let ast = preparsed ?? null;
  if (!ast) {
    const source = read(file);
    if (source === null) return EMPTY;
    ast = parseSource(source, file);
    if (!ast) {
      opts.cache.set(file, EMPTY);
      return EMPTY;
    }
  }

  stack.add(file);
  const imported = new Set<string>();
  for (const stmt of ast.program.body) {
    if (stmt.type !== 'ImportDeclaration') continue;
    const spec = (stmt.source as any)?.value;
    const target = typeof spec === 'string' ? opts.index.resolve(spec, file) : null;
    if (!target) continue;
    const exported = inertNamesFor(target, opts, null, depth + 1, stack);
    if (exported.size === 0) continue;
    for (const s of stmt.specifiers ?? []) {
      const local = (s as any).local?.name;
      if (!local) continue;
      const name =
        s.type === 'ImportSpecifier'
          ? ((s.imported as any).name ?? (s.imported as any).value)
          : s.type === 'ImportDefaultSpecifier'
            ? 'default'
            : null;
      if (name && exported.has(name)) imported.add(local);
    }
  }

  // Greatest fixed point: assume every function here is inert, then remove any that makes
  // a call which is neither inert nor a function still assumed inert, until nothing moves.
  // Mutual recursion between two pure helpers therefore stays pure.
  const functions = collectFunctions(ast);
  const inert = new Set(functions.keys());
  for (let changed = true; changed; ) {
    changed = false;
    for (const name of [...inert]) {
      const ok = functions
        .get(name)!
        .every((c) => c.full !== OPAQUE && (opts.isInert(c.full, c.tail) || imported.has(c.full) || inert.has(c.full)));
      if (!ok) {
        inert.delete(name);
        changed = true;
      }
    }
  }
  for (const name of imported) inert.add(name);

  stack.delete(file);
  opts.cache.set(file, inert);
  return inert;
}
