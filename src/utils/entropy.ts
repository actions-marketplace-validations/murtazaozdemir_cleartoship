/**
 * Shannon entropy in bits per character. Real credentials are near-random and
 * score high; words, paths and placeholders score low. gitleaks ships a
 * threshold with many of its rules, and applying it is most of what keeps a
 * broad credential ruleset from drowning a report in noise.
 */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * How a credential is shown in a report: enough of each end to recognise which
 * key it is, never enough to use it. Every finding that quotes a secret-shaped
 * value — in its detail or in its snippet — goes through this one function, so
 * no rule prints more of a key than another does. A report is pasted into pull
 * requests, CI logs and chat; the full value must never reach one.
 */
export function redactCredential(value: string): string {
  if (value.length > 14) return `${value.slice(0, 8)}…${value.slice(-4)}`;
  // Short enough that showing the ends would show most of it.
  if (value.length > 6) return `${value.slice(0, 2)}…`;
  return value;
}
