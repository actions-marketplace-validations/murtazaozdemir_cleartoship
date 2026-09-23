/**
 * Where the strings and comments are in a file.
 *
 * A regex ruleset has no idea whether it matched code, a sentence about code,
 * or a URL — and the difference decides whether a finding is real. Our own
 * source proved it: a comment reading "merely calling `jwt.verify(token,
 * secret)`" was reported as a JWT vulnerability, and a rule *description*
 * quoting `eval()` was reported as dynamic code execution.
 *
 * The naive fix — treat everything after `//` as a comment — is worse than the
 * bug, because `"https://api.example.com"` would silence every finding on that
 * line. So this walks the file once, tracking quotes as it goes, and both
 * answers come out correct.
 */

export interface Span {
  start: number;
  end: number;
  kind: 'string' | 'comment';
}

export interface CommentStyle {
  /** `//` line comments and `/* *\/` blocks. */
  slashes: boolean;
  /** `#` line comments: shell, Python, Ruby, YAML, Terraform, Dockerfile. */
  hash: boolean;
  /** `--` line comments: SQL. */
  dashes: boolean;
  /**
   * `/…/` regex literals: JavaScript and TypeScript. A quote or backtick inside
   * one is not a string opening, and before this was tracked a single
   * `/\`\s*,/` in this repo's own community.ts opened a phantom template
   * literal that swallowed the next hundred lines, so every comment in them read
   * as code and a vendored rule fired on a sentence.
   */
  regex?: boolean;
}

export function commentStyleFor(languages: readonly string[]): CommentStyle {
  const has = (l: string) => languages.includes(l);
  return {
    slashes:
      has('javascript') || has('typescript') || has('go') || has('php') || has('sql'),
    hash:
      has('python') ||
      has('shell') ||
      has('ruby') ||
      has('yaml') ||
      has('terraform') ||
      has('dockerfile'),
    dashes: has('sql'),
    regex: has('javascript') || has('typescript'),
  };
}

/** Files past this size are skipped by the caller anyway; this is belt and braces. */
const MAX_SOURCE = 1_000_000;

export function lexSpans(source: string, style: CommentStyle): Span[] {
  const spans: Span[] = [];
  if (source.length > MAX_SOURCE) return spans;

  for (let i = 0; i < source.length; i++) {
    const ch = source[i]!;

    // Strings. A template literal is taken whole, interpolations included —
    // nothing here needs to reason about what is inside one.
    if (ch === '"' || ch === "'" || ch === '`') {
      const start = i;
      const quote = ch;
      i++;
      while (i < source.length) {
        const c = source[i]!;
        if (c === '\\') {
          i += 2;
          continue;
        }
        if (c === quote) break;
        // An unterminated single- or double-quoted string ends at the newline,
        // which is what an apostrophe in a comment looks like.
        if (c === '\n' && quote !== '`') break;
        i++;
      }
      spans.push({ start, end: Math.min(i, source.length - 1), kind: 'string' });
      continue;
    }

    const two = source.slice(i, i + 2);

    if (style.regex && ch === '/' && two !== '//' && two !== '/*' && regexCanStart(source, i)) {
      const end = regexEnd(source, i);
      if (end !== -1) {
        i = end; // code, not a string or a comment: nothing to record
        continue;
      }
    }

    if (style.slashes && two === '/*') {
      const end = source.indexOf('*/', i + 2);
      const close = end === -1 ? source.length - 1 : end + 1;
      spans.push({ start: i, end: close, kind: 'comment' });
      i = close;
      continue;
    }

    const lineComment =
      (style.slashes && two === '//') ||
      (style.dashes && two === '--') ||
      (style.hash && ch === '#');
    if (lineComment) {
      const newline = source.indexOf('\n', i);
      const close = newline === -1 ? source.length - 1 : newline - 1;
      spans.push({ start: i, end: close, kind: 'comment' });
      i = close;
      continue;
    }
  }

  return spans;
}

/** Keywords after which a `/` starts a regex rather than dividing. */
const REGEX_AFTER_WORD = /\b(?:return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/;

/**
 * Whether a `/` at `index` can open a regex literal: the previous significant
 * character is an operator or opening punctuation, or a keyword like `return`.
 * After an identifier, a number or a closing bracket it is division.
 */
function regexCanStart(source: string, index: number): boolean {
  let j = index - 1;
  while (j >= 0 && (source[j] === ' ' || source[j] === '\t' || source[j] === '\n' || source[j] === '\r')) j--;
  if (j < 0) return true;
  const prev = source[j]!;
  if ('(,=:[!&|?{};+-*%~^'.includes(prev)) return true; // not < or >: `</div>` is JSX
  return REGEX_AFTER_WORD.test(source.slice(Math.max(0, j - 10), j + 1));
}

/**
 * Index of the closing `/` of a regex literal opened at `start`, honouring
 * escapes and `[...]` classes, or -1 if the line ends first — then it was not a
 * regex after all, and the caller carries on as before.
 */
function regexEnd(source: string, start: number): number {
  let inClass = false;
  for (let i = start + 1; i < source.length; i++) {
    const c = source[i]!;
    if (c === '\n') return -1;
    if (c === '\\') {
      i++;
      continue;
    }
    if (inClass) {
      if (c === ']') inClass = false;
    } else if (c === '[') inClass = true;
    else if (c === '/') return i;
  }
  return -1;
}

/** Binary search: is `index` inside a span of this kind? */
export function spanAt(spans: readonly Span[], index: number): Span | null {
  let low = 0;
  let high = spans.length - 1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    const span = spans[mid]!;
    if (index < span.start) high = mid - 1;
    else if (index > span.end) low = mid + 1;
    else return span;
  }
  return null;
}

export function isInside(spans: readonly Span[], index: number, kind: Span['kind']): boolean {
  return spanAt(spans, index)?.kind === kind;
}
