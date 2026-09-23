/**
 * Line numbers and line text for one file, answered in O(log n).
 *
 * `lineAt` in files.ts counts newlines from offset 0 on every call, and
 * `snippetAt` splits the whole file on every call. Both are fine once per
 * finding, and quadratic once per *match*: a 1.9 MB file of one AWS-key-shaped
 * token repeated 90,000 times kept the secrets scanner busy for more than five
 * minutes, rescanning the file from the top for every match it then discarded.
 * A scanner that can be stalled by the file it is reading is a scanner an
 * attacker can switch off, so anything that locates matches in a loop builds
 * one of these per file instead.
 */
export class LineIndex {
  /** Offset of the first character of each line; `starts[0]` is always 0. */
  private readonly starts: number[];

  constructor(private readonly source: string) {
    const starts = [0];
    for (let i = source.indexOf('\n'); i !== -1; i = source.indexOf('\n', i + 1)) {
      starts.push(i + 1);
    }
    this.starts = starts;
  }

  /** 1-based line number of the character at `offset`. Same answer as files.ts `lineAt`. */
  lineAt(offset: number): number {
    let low = 0;
    let high = this.starts.length - 1;
    while (low < high) {
      const mid = (low + high + 1) >> 1;
      if (this.starts[mid]! <= offset) low = mid;
      else high = mid - 1;
    }
    return low + 1;
  }

  /** Offset of the first character of a 1-based line. */
  lineStart(line: number): number {
    return this.starts[Math.max(0, Math.min(line - 1, this.starts.length - 1))]!;
  }

  /** The raw text of a 1-based line, without its newline. */
  lineText(line: number): string {
    if (line < 1 || line > this.starts.length) return '';
    const start = this.starts[line - 1]!;
    const next = line < this.starts.length ? this.starts[line]! - 1 : this.source.length;
    return this.source.slice(start, next);
  }

  /** Same shape as files.ts `snippetAt`: trimmed, capped at 160 characters. */
  snippet(line: number): string {
    return clip(this.lineText(line).trim());
  }
}

/** The snippet length cap every scanner uses. */
export function clip(text: string): string {
  return text.length > 160 ? text.slice(0, 157) + '...' : text;
}
