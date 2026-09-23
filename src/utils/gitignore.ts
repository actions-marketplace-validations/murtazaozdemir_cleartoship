import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { closeSync, fstatSync, lstatSync, openSync, readSync, realpathSync, statSync } from 'node:fs';

/**
 * A `.gitignore` matcher, implemented rather than shelled out to.
 *
 * Two reasons not to call `git check-ignore`: ClearToShip promises it starts no
 * processes while it reads your code (see SECURITY.md), and half the trees worth
 * scanning — an unpacked tarball, a CI checkout of a subdirectory — have no git
 * binary or no repository to ask.
 *
 * Supports what real ignore files use: comments, negation with `!`, directory-only
 * patterns, anchoring, `*`, `?`, `**` and character classes. Precedence follows
 * git: the deepest `.gitignore` wins, and within one file the last matching
 * pattern wins.
 *
 * Checked against `git check-ignore` over four real repositories — 1,858 paths,
 * no disagreement in the direction that matters (nothing is skipped that git
 * would keep). One deliberate divergence remains, and it scans *more* than git
 * would: the user's global ignore file is not read; see `repositoryExcludes`.
 *
 * Git never ignores a file it already tracks, whatever the patterns say. That
 * used to be documented here as a divergence not worth a binary parser — until
 * it turned out to be a way to hide code from the scan: commit `backdoor.ts`,
 * commit a `.gitignore` that lists it, and the run reported CLEAR TO SHIP on a
 * file it never opened. So the walk now reads `.git/index` (`readGitIndex`
 * below) and never skips a tracked path, and when a repository is present but
 * its index cannot be read, it stops honouring `.gitignore` at all rather than
 * guess.
 */

/**
 * One compiled pattern element. Matching is a Thompson-style simulation over
 * these — every live position advanced one character at a time — so the cost is
 * bounded by pattern length times path length, whatever the pattern looks like.
 * The previous implementation translated each pattern into a JavaScript regex,
 * and `*a*a*a*a*a*a*a*a*b` against a 200-character file name backtracked for
 * minutes: a `.gitignore` is text from the repository being scanned, which for a
 * security tool is untrusted input.
 */
type Token =
  | { k: 'lit'; c: string }
  | { k: 'any' }
  | { k: 'class'; neg: boolean; ranges: Array<[number, number]> }
  /** `*`: any run of characters other than `/`. */
  | { k: 'star' }
  /** A trailing or embedded `**`: any run of characters, `/` included. */
  | { k: 'dstar' }
  /** A leading `**​/` (or one after a `/`): zero or more whole directories. */
  | { k: 'dirs' };

interface Rule {
  tokens: Token[];
  /** Set when the whole pattern is a literal, for the common `node_modules` shape. */
  literal: string | null;
  /** Set for `*<literal>` patterns with no slash, for the common `*.log` shape. */
  starSuffix: string | null;
  anchored: boolean;
  negated: boolean;
  dirOnly: boolean;
}

interface Layer {
  /** Absolute directory the patterns are relative to, without a trailing slash. */
  base: string;
  rules: Rule[];
}

/** A character class body that git would reject, e.g. the reversed range `[z-a]`. */
class InvalidPattern extends Error {}

function parseClass(body: string): { neg: boolean; ranges: Array<[number, number]> } {
  let neg = false;
  let i = 0;
  // `!` is git's negation; `^` is what the old regex translation passed through
  // unchanged, and a regex class reads it the same way.
  if (body[0] === '!' || body[0] === '^') {
    neg = true;
    i = 1;
  }
  const ranges: Array<[number, number]> = [];
  const next = (): number => {
    let ch = body[i++]!;
    if (ch === '\\' && i < body.length) ch = body[i++]!;
    return ch.codePointAt(0)!;
  };
  while (i < body.length) {
    const lo = next();
    if (body[i] === '-' && i + 1 < body.length) {
      i++;
      const hi = next();
      if (hi < lo) throw new InvalidPattern('reversed range');
      ranges.push([lo, hi]);
    } else {
      ranges.push([lo, lo]);
    }
  }
  return { neg, ranges };
}

/** Compiles one gitignore pattern body (anchoring already stripped) into tokens. */
function tokenize(pattern: string): Token[] {
  const out: Token[] = [];
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;

    if (ch === '\\' && i + 1 < pattern.length) {
      out.push({ k: 'lit', c: pattern[++i]! });
      continue;
    }

    if (ch === '*') {
      // `****` means no more than `**` does.
      while (pattern[i + 1] === '*' && pattern[i + 2] === '*') i++;
      const doubled = pattern[i + 1] === '*';
      if (doubled) {
        const atStart = i === 0 || pattern[i - 1] === '/';
        const slashAfter = pattern[i + 2] === '/';
        if (atStart && slashAfter) {
          out.push({ k: 'dirs' });
          i += 2;
          continue;
        }
        out.push({ k: 'dstar' });
        i += 1;
        continue;
      }
      // Two adjacent single stars match exactly what one does.
      if (out[out.length - 1]?.k !== 'star') out.push({ k: 'star' });
      continue;
    }

    if (ch === '?') {
      out.push({ k: 'any' });
      continue;
    }

    if (ch === '[') {
      const close = pattern.indexOf(']', i + 1);
      if (close === -1) {
        out.push({ k: 'lit', c: '[' });
        continue;
      }
      out.push({ k: 'class', ...parseClass(pattern.slice(i + 1, close)) });
      i = close;
      continue;
    }

    out.push({ k: 'lit', c: ch });
  }
  return out;
}

function classMatches(tok: { neg: boolean; ranges: Array<[number, number]> }, ch: string): boolean {
  const code = ch.codePointAt(0)!;
  let hit = false;
  for (const [lo, hi] of tok.ranges) {
    if (code >= lo && code <= hi) {
      hit = true;
      break;
    }
  }
  return tok.neg ? !hit : hit;
}

/**
 * Whether `tokens` match all of `text` (anchored) or a suffix of it that starts
 * at the beginning or just after a `/` (unanchored).
 *
 * Every token `t` owns state `2t`; a `dirs` token also owns `2t + 1`, "inside a
 * directory name". State `2n` is the accepting one. No state is ever revisited
 * for the same character, so there is nothing to backtrack.
 */
function matchTokens(tokens: Token[], text: string, anchored: boolean): boolean {
  const n = tokens.length;
  const size = 2 * n + 2;
  let cur = new Int32Array(size);
  let next = new Int32Array(size);
  let curLen = 0;
  let nextLen = 0;
  const seen = new Int32Array(size);
  let generation = 1;

  // Adds a state and everything reachable from it without consuming input.
  const add = (into: Int32Array, len: number, state: number): number => {
    let s = state;
    for (;;) {
      if (seen[s] === generation) return len;
      seen[s] = generation;
      into[len++] = s;
      if (s & 1) return len; // inside a directory name: no free moves
      const t = s >> 1;
      if (t >= n) return len;
      const k = tokens[t]!.k;
      if (k !== 'star' && k !== 'dstar' && k !== 'dirs') return len;
      s = 2 * (t + 1);
    }
  };

  curLen = add(cur, 0, 0);
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    generation++;
    nextLen = 0;
    const slash = ch === '/';
    for (let j = 0; j < curLen; j++) {
      const s = cur[j]!;
      const t = s >> 1;
      if (t >= n) continue;
      const tok = tokens[t]!;
      if (s & 1) {
        // Inside a `dirs` directory name: keep reading it, or close it with `/`.
        nextLen = add(next, nextLen, slash ? 2 * t : s);
        continue;
      }
      switch (tok.k) {
        case 'lit':
          if (ch === tok.c) nextLen = add(next, nextLen, 2 * (t + 1));
          break;
        case 'any':
          if (!slash) nextLen = add(next, nextLen, 2 * (t + 1));
          break;
        case 'class':
          if (!slash && classMatches(tok, ch)) nextLen = add(next, nextLen, 2 * (t + 1));
          break;
        case 'star':
          if (!slash) nextLen = add(next, nextLen, s);
          break;
        case 'dstar':
          nextLen = add(next, nextLen, s);
          break;
        case 'dirs':
          if (!slash) nextLen = add(next, nextLen, s + 1);
          break;
      }
    }
    // Unanchored: a match may also begin just after any `/`.
    if (slash && !anchored) nextLen = add(next, nextLen, 0);
    const swap = cur;
    cur = next;
    next = swap;
    curLen = nextLen;
    if (curLen === 0 && anchored) return false;
  }
  for (let j = 0; j < curLen; j++) if (cur[j] === 2 * n) return true;
  return false;
}

function ruleMatches(rule: Rule, text: string): boolean {
  if (rule.literal !== null) {
    return rule.anchored
      ? text === rule.literal
      : text === rule.literal || text.endsWith('/' + rule.literal);
  }
  if (rule.starSuffix !== null) {
    const slash = text.lastIndexOf('/');
    if (rule.anchored && slash !== -1) return false;
    return text.slice(slash + 1).endsWith(rule.starSuffix);
  }
  return matchTokens(rule.tokens, text, rule.anchored);
}

/**
 * A pattern longer than this is not a real ignore rule. The matcher is linear,
 * but its cost is still pattern length times path length, and this text comes
 * from the repository being scanned.
 */
const MAX_PATTERN = 500;

/** Likewise, a `.gitignore` with more rules than this is not one. */
const MAX_RULES = 2000;

function compile(line: string): Rule | null {
  // Trailing whitespace is not part of the pattern unless it was escaped.
  let pattern = line.replace(/(?<!\\)\s+$/, '');
  if (pattern === '' || pattern.startsWith('#')) return null;
  if (pattern.length > MAX_PATTERN) return null;

  let negated = false;
  if (pattern.startsWith('!')) {
    negated = true;
    pattern = pattern.slice(1);
  } else if (pattern.startsWith('\\!') || pattern.startsWith('\\#')) {
    pattern = pattern.slice(1);
  }

  let dirOnly = false;
  if (pattern.endsWith('/')) {
    dirOnly = true;
    pattern = pattern.slice(0, -1);
  }
  if (pattern === '') return null;

  // A slash anywhere but the end anchors the pattern to this file's directory;
  // otherwise it matches a basename at any depth.
  const anchored = pattern.includes('/');
  if (pattern.startsWith('/')) pattern = pattern.slice(1);

  // No subtree suffix: a pattern matches a path, not everything beneath it.
  // Git prunes ignored directories during traversal instead, which is what the
  // walk does — and only that order makes `logos/*` followed by
  // `!logos/logos-in-app/` mean what git means. Matching the subtree here made
  // the negation unreachable: every file under the re-included directory stayed
  // ignored, 28 of them tracked, in one real repository.
  let tokens: Token[];
  try {
    tokens = tokenize(pattern);
  } catch {
    // `[z-a]` is a reversed range, and one line of it used to end the scan.
    // A pattern git itself would not honour is not worth dying over — skip it
    // and read the rest of the file.
    return null;
  }
  const allLiteral = tokens.every((t) => t.k === 'lit');
  const literal = allLiteral ? tokens.map((t) => (t as { c: string }).c).join('') : null;
  let starSuffix: string | null = null;
  if (
    !allLiteral &&
    tokens[0]?.k === 'star' &&
    tokens.length > 1 &&
    tokens.slice(1).every((t) => t.k === 'lit' && t.c !== '/')
  ) {
    starSuffix = tokens.slice(1).map((t) => (t as { c: string }).c).join('');
  }
  return { tokens, literal, starSuffix, anchored, negated, dirOnly };
}

export class Gitignore {
  private constructor(private readonly layers: readonly Layer[]) {}

  static empty(): Gitignore {
    return new Gitignore([]);
  }

  /** A copy of this matcher with one more `.gitignore`'s worth of rules. */
  extend(base: string, content: string): Gitignore {
    const rules: Rule[] = [];
    for (const line of content.split(/\r?\n/)) {
      if (rules.length >= MAX_RULES) break;
      const rule = compile(line);
      if (rule) rules.push(rule);
    }
    if (rules.length === 0) return this;
    return new Gitignore([...this.layers, { base: base.replace(/\/+$/, ''), rules }]);
  }

  get isEmpty(): boolean {
    return this.layers.length === 0;
  }

  /**
   * Whether git would ignore `absPath`. Deepest layer first, and inside a layer
   * the last matching pattern decides — both are git's own rules.
   */
  ignores(absPath: string, isDir: boolean): boolean {
    for (let i = this.layers.length - 1; i >= 0; i--) {
      const layer = this.layers[i]!;
      if (!absPath.startsWith(layer.base + '/')) continue;
      const relative = absPath.slice(layer.base.length + 1);
      for (let j = layer.rules.length - 1; j >= 0; j--) {
        const rule = layer.rules[j]!;
        if (rule.dirOnly && !isDir) continue;
        if (ruleMatches(rule, relative)) return !rule.negated;
      }
    }
    return false;
  }
}

/**
 * The ignore rules that apply to one path, assembled by descending from the
 * scan root — root `.gitignore`, `.git/info/exclude`, and every nested
 * `.gitignore` on the way down, in git's own precedence order.
 *
 * Exists so a rule that needs to ask "would git ignore this?" about a single
 * file can ask this matcher instead of pattern-matching the text of a
 * `.gitignore` itself. CTS032 did the latter — it compared the root file's
 * lines against five literal strings — and so reported `/.env` and `.env.local`
 * as *not* covering the very files they cover, a high-severity finding on a
 * correctly configured repository.
 *
 * Whatever `read` the caller passes, a path that resolves outside `root` — a
 * `.gitignore` symlinked to `/dev/zero` or to a file elsewhere — reads as absent.
 */
export function rulesForPath(
  root: string,
  absPath: string,
  read: (path: string) => string | null,
): Gitignore {
  const contained = containedReader(root, read);
  let rules = extendedAt(repositoryExcludes(root, contained), root, contained);
  if (!absPath.startsWith(root)) return rules;
  const segments = absPath
    .slice(root.length)
    .split(/[/\\]+/)
    .filter(Boolean)
    .slice(0, -1); // the file's own name is not a directory to descend into
  let dir = root.replace(/[/\\]+$/, '');
  for (const segment of segments) {
    dir = join(dir, segment);
    rules = extendedAt(rules, dir, contained);
  }
  return rules;
}

/** An ignore file bigger than this is not one; see `readBounded`. */
const MAX_IGNORE_FILE = 2_000_000;

/**
 * Wraps a reader so that it only ever answers for regular files inside `root`,
 * and never for more than `MAX_IGNORE_FILE` bytes of them.
 */
export function containedReader(
  root: string,
  _read?: (path: string) => string | null,
): (path: string) => string | null {
  let rootReal: string;
  try {
    rootReal = realpathSync(root);
  } catch {
    return () => null;
  }
  return (path: string) => readBounded(path, MAX_IGNORE_FILE, rootReal);
}

/**
 * Reads a regular file of at most `maxBytes`, optionally only when its real
 * path lies under `insideReal`. Returns null for anything else: a FIFO, a
 * device such as `/dev/zero` (which a symlinked `.gitignore` used to stream
 * into memory without end), a directory, or a file that escapes the root.
 *
 * The size is checked on the opened descriptor and the read itself is capped,
 * so a file that grows between the check and the read still cannot overrun.
 */
export function readBounded(path: string, maxBytes: number, insideReal?: string): string | null {
  const buf = readBoundedBytes(path, maxBytes, insideReal);
  return buf === null ? null : buf.toString('utf8');
}

export function readBoundedBytes(path: string, maxBytes: number, insideReal?: string): Buffer | null {
  let fd: number | undefined;
  try {
    if (insideReal !== undefined) {
      const real = realpathSync(path);
      const prefix = insideReal.endsWith('/') ? insideReal : insideReal + '/';
      if (real !== insideReal && !real.startsWith(prefix)) return null;
    }
    fd = openSync(path, 'r');
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > maxBytes) return null;
    const buf = Buffer.alloc(Math.min(st.size, maxBytes) + 1);
    let total = 0;
    while (total < buf.length) {
      const got = readSync(fd, buf, total, buf.length - total, total);
      if (got === 0) break;
      total += got;
    }
    if (total > maxBytes) return null;
    return buf.subarray(0, total);
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* already closed */
      }
    }
  }
}

/** The ignore rules that apply at `dir`, given those inherited from above. */
export function extendedAt(
  parent: Gitignore,
  dir: string,
  read: (path: string) => string | null,
): Gitignore {
  const content = read(join(dir, '.gitignore'));
  return content === null ? parent : parent.extend(dir, content);
}

/**
 * Repository-local excludes. Same syntax, same precedence as a root
 * `.gitignore`, but kept out of version control — so a machine-specific
 * scratch directory is invisible here without appearing in anyone's diff.
 *
 * The user's *global* ignore file (`core.excludesFile`, usually
 * `~/.config/git/ignore`) is deliberately not read: it lives outside the scan
 * root, which SECURITY.md promises we do not touch, and it is per-machine — a
 * CI checkout would not have it, so honouring it would make a local scan
 * quieter than the one that gates the merge.
 */
export function repositoryExcludes(
  root: string,
  read: (path: string) => string | null,
): Gitignore {
  const content = read(join(root, '.git', 'info', 'exclude'));
  return content === null ? Gitignore.empty() : Gitignore.empty().extend(root, content);
}

// ---------------------------------------------------------------------------
// The index: which paths git tracks, and therefore never ignores.
// ---------------------------------------------------------------------------

/** What a repository's index says is tracked, relative to the repository root. */
export interface TrackedPaths {
  /** Tracked files (and submodule paths), `/`-separated, NFC-normalised. */
  files: Set<string>;
  /** Every directory that contains a tracked path, plus sparse-index directories. */
  dirs: Set<string>;
  /** Sparse-index directory entries: everything beneath one of these is tracked. */
  sparseDirs: string[];
}

export type IndexLookup =
  /** No `.git` here: not a repository, so `.gitignore` is all there is. */
  | { kind: 'none' }
  | { kind: 'ok'; tracked: TrackedPaths }
  /** A repository whose index could not be read or understood. */
  | { kind: 'error'; reason: string };

/**
 * An index bigger than this is not one this tool will hold in memory. The
 * largest public monorepos have indexes in the tens of megabytes.
 */
const MAX_INDEX_BYTES = 256_000_000;

/** A `.git` *file* (worktree, submodule) is one line; anything big is not one. */
const MAX_GITFILE_BYTES = 4096;

/**
 * Finds and parses the index of the repository whose working tree is `dir`.
 *
 * `.git` may be a directory, or — in a linked worktree or a submodule — a file
 * holding `gitdir: <path>`, which can point outside the scan root. Reading the
 * index there is safe in the direction that matters: the only thing taken from
 * it is a list of paths, and the only effect of a path being listed is that it
 * gets scanned when an ignore rule would have skipped it. Nothing from it is
 * ever quoted in a report.
 */
export function readGitIndex(dir: string): IndexLookup {
  const dotGit = join(dir, '.git');
  let st;
  try {
    st = lstatSync(dotGit);
  } catch {
    return { kind: 'none' };
  }
  let gitDir: string;
  if (st.isDirectory()) {
    gitDir = dotGit;
  } else if (st.isFile()) {
    const content = readBounded(dotGit, MAX_GITFILE_BYTES);
    const m = content === null ? null : /^gitdir:[ \t]*(.+?)[ \t]*$/m.exec(content);
    if (!m) return { kind: 'error', reason: '.git is a file but does not name a gitdir' };
    gitDir = resolve(dir, m[1]!);
  } else if (st.isSymbolicLink()) {
    try {
      if (!statSync(dotGit).isDirectory()) {
        return { kind: 'error', reason: '.git is a symlink to something other than a directory' };
      }
    } catch {
      return { kind: 'error', reason: '.git is a dangling symlink' };
    }
    gitDir = dotGit;
  } else {
    return { kind: 'error', reason: '.git is neither a file nor a directory' };
  }

  try {
    if (!statSync(gitDir).isDirectory()) {
      return { kind: 'error', reason: `the gitdir ${gitDir} is not a directory` };
    }
  } catch {
    return { kind: 'error', reason: `the gitdir ${gitDir} does not exist` };
  }

  const indexPath = join(gitDir, 'index');
  try {
    statSync(indexPath);
  } catch (err) {
    // A repository with nothing staged yet — `git init` and no `git add` — has
    // no index file at all, and git then tracks nothing. That is an answer,
    // not a failure.
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') {
      return { kind: 'ok', tracked: { files: new Set(), dirs: new Set(), sparseDirs: [] } };
    }
    return { kind: 'error', reason: 'the index could not be opened' };
  }
  const buf = readBoundedBytes(indexPath, MAX_INDEX_BYTES);
  if (buf === null) return { kind: 'error', reason: 'the index could not be read (unreadable, not a regular file, or too large)' };
  const parsed = parseGitIndex(buf);
  if (typeof parsed === 'string') return { kind: 'error', reason: parsed };
  return { kind: 'ok', tracked: parsed };
}

/** Git's own offset varint (`decode_varint` in varint.c), used by index v4. */
function readVarint(buf: Buffer, at: number): { value: number; next: number } | null {
  if (at >= buf.length) return null;
  let byte = buf[at++]!;
  let value = byte & 127;
  while (byte & 128) {
    if (at >= buf.length || value > 0x3fffffff) return null;
    byte = buf[at++]!;
    value = ((value + 1) * 128) | (byte & 127);
  }
  return { value, next: at };
}

/** Which hash the trailing checksum was made with, when it can be told. */
function checksumHashLength(buf: Buffer): number[] {
  for (const [algo, len] of [['sha1', 20], ['sha256', 32]] as const) {
    if (buf.length < 12 + len) continue;
    const body = buf.subarray(0, buf.length - len);
    const trailer = buf.subarray(buf.length - len);
    if (createHash(algo).update(body).digest().equals(trailer)) return [len];
  }
  // `index.skipHash` (enabled by `feature.manyFiles`) writes a zero trailer, so
  // the checksum cannot say which object format this is. Try both.
  return [20, 32];
}

/**
 * Parses a git index (versions 2, 3 and 4). Returns the tracked paths, or a
 * sentence saying why the file could not be understood.
 *
 * Format: `DIRC`, version, entry count; then per entry 40 bytes of stat data,
 * the object hash (20 bytes for SHA-1, 32 for SHA-256 repositories), 16 bits
 * of flags, 16 more when the extended bit is set (v3+), and the path. v2 and
 * v3 store the whole path NUL-padded to a multiple of 8; v4 stores a varint
 * saying how many bytes to drop from the previous path, then the new suffix.
 */
export function parseGitIndex(buf: Buffer): TrackedPaths | string {
  if (buf.length < 12 || buf.toString('latin1', 0, 4) !== 'DIRC') return 'the index has no DIRC header';
  const version = buf.readUInt32BE(4);
  if (version < 2 || version > 4) return `index version ${version} is not supported`;
  const count = buf.readUInt32BE(8);

  let lastError = 'the index is malformed';
  for (const hashLen of checksumHashLength(buf)) {
    const result = parseEntries(buf, version, count, hashLen);
    if (typeof result !== 'string') return result;
    lastError = result;
  }
  return lastError;
}

function parseEntries(buf: Buffer, version: number, count: number, hashLen: number): TrackedPaths | string {
  const end = buf.length - hashLen;
  const files = new Set<string>();
  const dirs = new Set<string>();
  const sparseDirs: string[] = [];
  let at = 12;
  let previous: Buffer = Buffer.alloc(0);
  const decoder = new TextDecoder('utf-8');

  for (let e = 0; e < count; e++) {
    const start = at;
    const fixed = 40 + hashLen + 2;
    if (start + fixed > end) return 'the index ends in the middle of an entry';
    const mode = buf.readUInt32BE(start + 24);
    const flags = buf.readUInt16BE(start + 40 + hashLen);
    let nameAt = start + fixed;
    if (flags & 0x4000) {
      if (version < 3) return 'an extended entry in a version 2 index';
      nameAt += 2;
    }
    let path: Buffer;
    if (version === 4) {
      const v = readVarint(buf, nameAt);
      if (!v || v.value > previous.length) return 'a v4 path prefix is out of range';
      const nul = buf.indexOf(0, v.next);
      if (nul === -1 || nul >= end) return 'a v4 path is not terminated';
      path = Buffer.concat([previous.subarray(0, previous.length - v.value), buf.subarray(v.next, nul)]);
      at = nul + 1;
    } else {
      const nul = buf.indexOf(0, nameAt);
      if (nul === -1 || nul >= end) return 'a path is not terminated';
      const nameLen = flags & 0xfff;
      if (nameLen < 0xfff && nul - nameAt !== nameLen) return 'a path length disagrees with its flags';
      path = buf.subarray(nameAt, nul);
      // 1 to 8 NUL bytes of padding, to a multiple of 8 from the entry start.
      const entryLen = ((nameAt - start) + path.length + 8) & ~7;
      at = start + entryLen;
      if (at > end) return 'an entry runs past the end of the index';
      for (let p = nul; p < at; p++) if (buf[p] !== 0) return 'entry padding is not zero';
    }
    previous = path;
    if (path.length === 0) return 'an entry has an empty path (a split index, which is not supported?)';

    let name = decoder.decode(path).normalize('NFC');
    const objectType = mode >>> 12;
    if (objectType === 0o04) {
      // A sparse-index directory entry: the whole subtree is tracked.
      name = name.replace(/\/+$/, '');
      sparseDirs.push(name);
      dirs.add(name);
    } else {
      files.add(name);
    }
    for (let slash = name.lastIndexOf('/'); slash > 0; slash = name.lastIndexOf('/', slash - 1)) {
      const dir = name.slice(0, slash);
      if (dirs.has(dir)) break;
      dirs.add(dir);
    }
  }

  // Extensions. A split index (`link`) keeps most entries in a separate shared
  // file; this parser does not follow it, and a partial list of tracked paths
  // would be a quiet way back to the bug this exists to close.
  while (at + 8 <= end) {
    const sig = buf.toString('latin1', at, at + 4);
    const size = buf.readUInt32BE(at + 4);
    if (sig === 'link') return 'the index is split (core.splitIndex), which is not supported';
    at += 8 + size;
  }
  if (at !== end) return 'the index extensions do not line up with its end';
  return { files, dirs, sparseDirs };
}

/** Whether `relPath` (relative to the repository root, `/`-separated) is tracked. */
export function isTracked(tracked: TrackedPaths, relPath: string, isDir: boolean): boolean {
  const key = relPath.normalize('NFC');
  if (isDir ? tracked.dirs.has(key) : tracked.files.has(key)) return true;
  for (const d of tracked.sparseDirs) {
    if (key === d || key.startsWith(d + '/')) return true;
  }
  return false;
}
