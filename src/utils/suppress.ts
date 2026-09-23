import { commentStyleFor, lexSpans, spanAt } from './spans.js';
import type { CommentStyle, Span } from './spans.js';
import { languagesFor } from './files.js';

/**
 * Honours inline suppressions:
 *   // cleartoship-ignore CTS001  (same line, or anywhere in the comment block
 *                                 directly above)
 *   // cts-ignore                 (suppresses every rule at that location)
 *
 * The directive is looked for on the finding's own line and then upward through
 * the contiguous comment lines above it, so a directive can sit at the top of a
 * multi-line explanation — which is where anyone writing a real justification
 * naturally puts it.
 *
 * Only a directive inside a *comment* counts. The token used to be matched
 * anywhere on the line, so `const mode = "cts-ignore"; eval(x)` — a string
 * literal, in code — silenced every rule on that line, and a hostile commit
 * could hide an `eval` behind one. Comments are located with the same lexer the
 * community rules use (`lexSpans`), plus `<!-- … -->` for Markdown and HTML.
 */
export class Suppressions {
  private readonly lines: string[];
  private readonly lineStarts: number[];
  private readonly source: string;
  private readonly style: CommentStyle;
  private spans: Span[] | null = null;
  /** Only when the language is unknown: a JS-style lexing, to rule out strings. */
  private jsSpans: Span[] | null = null;
  private readonly languageKnown: boolean;

  /** How far above a finding a comment block may start. */
  private static readonly MAX_LOOKBACK = 6;

  /**
   * `file` picks the comment syntax (`//`, `#`, `--`); scanners should pass it.
   * Without it, a directive must be in a comment under some syntax AND not in a
   * string literal under JavaScript's — so neither `i--; "cts-ignore"` nor
   * `this.#x = "cts-ignore"` can pass a string off as a comment.
   */
  constructor(source: string, file?: string) {
    this.source = source;
    this.lines = source.split('\n');
    this.lineStarts = [];
    let at = 0;
    for (const l of this.lines) {
      this.lineStarts.push(at);
      at += l.length + 1;
    }
    const languages = file ? languagesFor(file) : [];
    this.languageKnown = languages.length > 0;
    this.style =
      languages.length > 0
        ? commentStyleFor(languages)
        : { slashes: true, hash: true, dashes: true };
  }

  suppressed(line: number, ruleId: string): boolean {
    if (this.check(line, ruleId)) return true;
    for (let i = 1; i <= Suppressions.MAX_LOOKBACK; i++) {
      const candidate = line - i;
      if (candidate < 1) break;
      const text = this.lines[candidate - 1];
      if (text === undefined) break;
      const trimmed = text.trim();
      // Only walk upward through comments; any real code ends the block.
      if (!/^(\/\/|\/\*|\*|#|--|<!--)/.test(trimmed) && trimmed !== '') break;
      if (this.check(candidate, ruleId)) return true;
      if (trimmed === '') break;
    }
    return false;
  }

  private inComment(line: number, column: number, text: string): boolean {
    this.spans ??= lexSpans(this.source, this.style);
    const index = this.lineStarts[line - 1]! + column;
    if (!this.languageKnown) {
      this.jsSpans ??= lexSpans(this.source, { slashes: true, hash: false, dashes: false });
      if (spanAt(this.jsSpans, index)?.kind === 'string') return false;
    }
    const span = spanAt(this.spans, index);
    if (span) return span.kind === 'comment';
    // `<!-- cleartoship-ignore -->` in Markdown/HTML, which the lexer does not model.
    const open = text.lastIndexOf('<!--', column);
    return open !== -1 && !text.slice(open, column).includes('-->');
  }

  private check(line: number, ruleId: string): boolean {
    const text = this.lines[line - 1];
    if (!text) return false;
    const re = /(?:cleartoship|cts)-ignore(?:\s+([A-Z0-9,\s]+))?/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (!this.inComment(line, m.index, text)) continue;
      const ids = m[1];
      if (!ids || !ids.trim()) return true;
      const listed = ids
        .split(/[,\s]+/)
        .map((s) => s.trim().toUpperCase())
        .filter(Boolean);
      if (listed.includes(ruleId.toUpperCase())) return true;
    }
    return false;
  }
}
