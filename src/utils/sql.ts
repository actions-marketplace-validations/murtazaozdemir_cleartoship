/**
 * Minimal PostgreSQL statement splitter. Deliberately not a full parser: it
 * only needs to know where one statement ends, which means respecting string
 * literals, dollar-quoted function bodies and both comment styles.
 */
export interface SqlStatement {
  text: string;
  /** 1-indexed line where the statement starts. */
  line: number;
}

export function splitStatements(source: string): SqlStatement[] {
  const out: SqlStatement[] = [];
  let buf = '';
  let line = 1;
  let startLine = 1;
  let pendingStart = true;
  let i = 0;

  // Statements are separated by blank lines and comments, so the recorded line
  // has to be the first line carrying an actual token.
  const emit = (text: string) => {
    if (pendingStart && text.trim()) {
      startLine = line;
      pendingStart = false;
    }
    buf += text;
  };

  const flush = () => {
    if (buf.trim()) out.push({ text: buf.trim(), line: startLine });
    buf = '';
    pendingStart = true;
  };

  while (i < source.length) {
    const ch = source[i]!;
    const next = source[i + 1];

    if (ch === '-' && next === '-') {
      while (i < source.length && source[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) {
        if (source[i] === '\n') line++;
        i++;
      }
      i += 2;
      continue;
    }
    if (ch === "'" || ch === '"') {
      const quote = ch;
      emit(ch);
      i++;
      while (i < source.length) {
        if (source[i] === '\n') line++;
        if (source[i] === quote) {
          if (source[i + 1] === quote) {
            emit(quote + quote);
            i += 2;
            continue;
          }
          emit(quote);
          i++;
          break;
        }
        emit(source[i]!);
        i++;
      }
      continue;
    }
    if (ch === '$') {
      const tag = /^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/.exec(source.slice(i));
      if (tag) {
        const marker = tag[0];
        const end = source.indexOf(marker, i + marker.length);
        const chunk = end === -1 ? source.slice(i) : source.slice(i, end + marker.length);
        emit(chunk);
        for (const c of chunk) if (c === '\n') line++;
        i += chunk.length;
        continue;
      }
    }
    if (ch === ';') {
      flush();
      i++;
      continue;
    }
    if (ch === '\n') {
      emit(ch);
      line++;
      i++;
      continue;
    }
    emit(ch);
    i++;
  }
  flush();
  return out;
}

/** Reads a parenthesised group starting at `open` (index of the `(`). */
export function readBalanced(text: string, open: number): string | null {
  if (text[open] !== '(') return null;
  let depth = 0;
  let inString: string | null = null;
  for (let i = open; i < text.length; i++) {
    const ch = text[i]!;
    if (inString) {
      if (ch === inString) {
        if (text[i + 1] === inString) { i++; continue; }
        inString = null;
      }
      continue;
    }
    if (ch === "'" || ch === '"') { inString = ch; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return text.slice(open + 1, i);
    }
  }
  return null;
}

/** Grabs the expression after a keyword such as USING or WITH CHECK. */
export function clauseAfter(text: string, keyword: RegExp): string | null {
  const m = keyword.exec(text);
  if (!m) return null;
  let i = m.index + m[0].length;
  while (i < text.length && /\s/.test(text[i]!)) i++;
  return readBalanced(text, i);
}

/**
 * Normalises `"public"."posts"` / `public.posts` / `posts` to `public.posts`.
 * PostgreSQL folds unquoted identifiers to lower case, so `Profiles` and
 * `profiles` name the same table while `"Profiles"` names a different one:
 * unquoted parts are lowercased, quoted parts are kept exactly as written.
 */
export function normaliseTable(raw: string): string {
  const parts = raw
    .trim()
    .split('.')
    .map((p) => p.trim())
    .map((p) => (/^".*"$/.test(p) ? p.slice(1, -1) : p.toLowerCase()))
    .filter(Boolean);
  if (parts.length === 0) return '';
  if (parts.length === 1) return `public.${parts[0]}`;
  return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
}

const IDENT = `(?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)`;
export const QUALIFIED_NAME = `${IDENT}(?:\\s*\\.\\s*${IDENT})*`;

/** Removes parentheses that wrap the whole expression, however deeply nested. */
function stripOuterParens(expr: string): string {
  let s = expr.trim();
  while (s.startsWith('(')) {
    const inner = readBalanced(s, 0);
    if (inner === null || inner.length + 2 !== s.length) break;
    s = inner.trim();
  }
  return s;
}

/** A constant literal (`true`, `1`, `'a'`) with any trailing cast dropped, or null. */
function literalValue(expr: string): string | null {
  const s = stripOuterParens(expr)
    .replace(/\s*::\s*(boolean|bool|int|integer|text)\s*$/i, '')
    .trim();
  const lowered = s.toLowerCase();
  if (lowered === 'true' || lowered === 'false') return lowered;
  if (/^-?\d+(\.\d+)?$/.test(s)) return String(Number(s));
  if (/^'(?:[^']|'')*'$/.test(s)) return s;
  return null;
}

/** Splits `a = b` at its single top-level `=` (not part of `<=`, `>=`, `!=`, `=>`). */
function splitEquality(expr: string): [string, string] | null {
  let depth = 0;
  let inString = false;
  let at = -1;
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i]!;
    if (inString) { if (ch === "'") inString = false; continue; }
    if (ch === "'") { inString = true; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    else if (ch === '=' && depth === 0) {
      const prev = expr[i - 1];
      const next = expr[i + 1];
      if (prev === '<' || prev === '>' || prev === '!' || next === '>' || next === '=') return null;
      if (at !== -1) return null;
      at = i;
    }
  }
  return at === -1 ? null : [expr.slice(0, at), expr.slice(at + 1)];
}

/** true / false for a constant predicate, null for anything that depends on the row or caller. */
function constantTruth(expr: string, depth = 0): boolean | null {
  if (depth > 20) return null;
  const s = stripOuterParens(expr).replace(/\s+/g, ' ');
  const lit = literalValue(s);
  if (lit === 'true' || lit === '1') return true;
  if (lit === 'false' || lit === '0') return false;
  const not = /^not\s+(.+)$/i.exec(s);
  if (not) {
    const inner = constantTruth(not[1]!, depth + 1);
    return inner === null ? null : !inner;
  }
  const eq = splitEquality(s);
  if (eq) {
    const left = literalValue(eq[0]);
    const right = literalValue(eq[1]);
    if (left !== null && right !== null) return left === right;
  }
  return null;
}

/**
 * True when a policy predicate lets everything through: `true`, `((true))`,
 * `1 = 1`, `'a' = 'a'`, `true = true`, `not false`, `true::boolean`. Only
 * constant expressions are judged; anything reading a column or calling a
 * function is not always-true as far as this is concerned.
 */
export function isAlwaysTrue(expr: string | null): boolean {
  if (expr === null) return false;
  return constantTruth(expr) === true;
}
