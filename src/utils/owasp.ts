/**
 * One taxonomy out, whatever went in.
 *
 * ClearToShip's own rules label findings against the OWASP Top 10:2025. The
 * vendored ruleset does not: measured across it, "Injection" arrives as both
 * `A02:2025` and `A03:2025`, "Security Misconfiguration" as `A05:2025` and
 * `A05:2021`, and a handful of rules carry API Top 10 categories instead. A
 * user filtering a report by category, or reading the SARIF in a dashboard,
 * would see three Injections and no way to total them.
 *
 * So the labels are normalised on the way out. The upstream string is kept in
 * `meta.owaspUpstream` — this is a relabelling, not a correction of somebody
 * else's judgement, and it should stay checkable.
 */

export const OWASP_2025 = {
  A01: 'A01:2025 - Broken Access Control',
  A02: 'A02:2025 - Security Misconfiguration',
  A03: 'A03:2025 - Software Supply Chain Failures',
  A04: 'A04:2025 - Cryptographic Failures',
  A05: 'A05:2025 - Injection',
  A06: 'A06:2025 - Insecure Design',
  A07: 'A07:2025 - Authentication Failures',
  A08: 'A08:2025 - Software & Data Integrity Failures',
  A09: 'A09:2025 - Security Logging & Alerting Failures',
  A10: 'A10:2025 - Mishandling of Exceptional Conditions',
} as const;

/**
 * Two of these are judgement calls, made once and written down rather than
 * left to vary per rule: the 2025 list has no standalone SSRF category (it sits
 * under Broken Access Control) and no standalone Vulnerable Components category
 * (it sits under Software Supply Chain Failures).
 */
const NORMALISE: [RegExp, string][] = [
  [/broken access control|object level authorization|object property level|function level auth/i, OWASP_2025.A01],
  [/server-?side request forgery|\bssrf\b/i, OWASP_2025.A01],
  [/security misconfiguration/i, OWASP_2025.A02],
  [/supply chain|vulnerable (and outdated )?components/i, OWASP_2025.A03],
  [/cryptographic failures|sensitive data exposure/i, OWASP_2025.A04],
  [/injection|cross-?site scripting|\bxss\b/i, OWASP_2025.A05],
  [/insecure design/i, OWASP_2025.A06],
  [/auth(entication)? failures|identification and auth|broken auth/i, OWASP_2025.A07],
  [/data integrity failures/i, OWASP_2025.A08],
  [/logging|monitoring|alerting/i, OWASP_2025.A09],
  [/mishandling|exceptional conditions/i, OWASP_2025.A10],
];

/**
 * The canonical 2025 category for a rule's own label, or null when it belongs
 * to a different standard. API Top 10 categories are left alone: they are
 * accurate about a different list, and flattening them into the web Top 10
 * would invent a mapping nobody published.
 */
export function normaliseOwasp(raw: string | undefined): string | null {
  if (!raw) return null;
  // The API Security Top 10 is a different list with its own numbering, and a
  // few rules cite it — sometimes without the `API` prefix, as `A04:2023`.
  // Anything from the 2023 list is kept on that list rather than flattened into
  // a web category nobody published a mapping for. But it is not left as it
  // came: eight vendored rules label themselves `A04:2023 Unrestricted Resource
  // Consumption`, which printed beside `A04:2025 - Cryptographic Failures` reads
  // as the same A04. The API list numbers its categories `API1`…`API10`, so the
  // prefix is restored — the category is unchanged, and the upstream text is
  // still kept in `meta.owaspUpstream`.
  const apiWithoutPrefix = /^\s*A(\d{1,2}):2023\b\s*(?:-\s*)?(.*)$/.exec(raw);
  if (apiWithoutPrefix) {
    const label = apiWithoutPrefix[2]!.trim();
    return `API${Number(apiWithoutPrefix[1])}:2023${label ? ` ${label}` : ''}`;
  }
  if (/^API\d/i.test(raw.trim()) || /:2023\b/.test(raw)) return null;
  for (const [pattern, canonical] of NORMALISE) {
    if (pattern.test(raw)) return canonical;
  }
  return null;
}

/**
 * OWASP Top 10 for LLM Applications, **2026 edition** (published 4 August 2026).
 *
 * The renumbering is not cosmetic and it is easy to ship stale: Excessive Agency
 * moved 06 → 03, Unbounded Consumption 10 → 06, Improper Output Handling 05 →
 * 10, Misinformation 09 → 07, and System Prompt Leakage was renamed and
 * broadened into **Hidden Context Exposure** at 08. Only LLM01 and LLM02 kept
 * their numbers. Eight of ten identifiers change between editions, so anything
 * that hard-codes them dates fast — which is why the mapping below keys off
 * category *names*, and only the label carries the number.
 */
export const OWASP_LLM = {
  LLM01: 'LLM01:2026 - Prompt Injection',
  LLM02: 'LLM02:2026 - Sensitive Information Disclosure',
  LLM03: 'LLM03:2026 - Excessive Agency',
  LLM04: 'LLM04:2026 - Supply Chain',
  LLM05: 'LLM05:2026 - Data and Model Poisoning',
  LLM06: 'LLM06:2026 - Unbounded Consumption',
  LLM07: 'LLM07:2026 - Misinformation',
  LLM08: 'LLM08:2026 - Hidden Context Exposure',
  LLM09: 'LLM09:2026 - Vector and Embedding Weaknesses',
  LLM10: 'LLM10:2026 - Improper Output Handling',
} as const;

/**
 * A second, independent label for the findings that are about an LLM or agent
 * rather than a web app. Matched on the rule's own words, not on a hand-kept
 * list of ids, so re-vendoring the upstream ruleset does not silently drop the
 * mapping. Deliberately conservative: a rule that does not clearly belong to a
 * category gets none, because a wrong category is worse than no category.
 */
const LLM_RULES: [RegExp, string][] = [
  // Ordered deliberately: "LLM output used in a dangerous sink" is about
  // handling the output, even though its description discusses injection.
  [
    /(llm|ai|model) output[^.]{0,60}(unescaped|innerhtml|dangerouslysetinnerhtml|render|eval|exec|sink|shell|command|markdown)|(unescaped|unsanitised|unsanitized)[^.]{0,30}(llm|ai|model) output/i,
    OWASP_LLM.LLM10,
  ],
  [
    /prompt injection|injected instruction|hidden instruction|jailbreak|(tool|skill) (description|definition)[^.]{0,40}(instruction|encoded|obfuscat|inject)|untrusted content into (the )?prompt/i,
    OWASP_LLM.LLM01,
  ],
  // 2026 broadened "System Prompt Leakage" into Hidden Context Exposure: the
  // guidance is that nothing in the context window is a secret, so retrieved
  // context and tool output belong here alongside the system prompt.
  [
    /(system prompt|hidden context|context window)[^.]{0,40}(leak|expos|client|bundle|browser|discoverab)/i,
    OWASP_LLM.LLM08,
  ],
  [
    // A hardcoded provider key is disclosure wherever it sits, so no exposure
    // word is required after a *named* provider. The generic "llm"/"ai" wording
    // still needs one, or every mention of an AI feature would qualify.
    /(openai|anthropic|gemini|claude|mistral|cohere|huggingface|replicate|groq|perplexity|xai|pinecone)[^.]{0,40}(api[ _-]?key|token|secret)|(llm|\bai\b)[^.]{0,40}(api[ _-]?key|token|secret)[^.]{0,40}(expos|public|client|browser|bundle)|base_?url[^.]{0,40}(non-|redirect)|dangerouslyallowbrowser/i,
    OWASP_LLM.LLM02,
  ],
  [/(mcp|model|agent)[^.]{0,40}(@latest|unpinned|unverified|untrusted (source|registry))/i, OWASP_LLM.LLM04],
  [
    // "Hook" is overloaded: an npm `postinstall` hook that shells out is a
    // supply-chain finding, not an agent given too much authority. The AI
    // context has to be in the text.
    /auto[- ]?approve|allowedtools|excessive agency|(mcp|agent|assistant|settings|claude|ai)[- ]?(config|hook|tool)[^.]{0,60}(execut|pipes|network|write|permissive|broad|access)|permission prompt[^.]{0,40}(bypass|skip)|overly (broad|permissive)[^.]{0,30}tool/i,
    OWASP_LLM.LLM03,
  ],
  // "Embedding media" is not a vector embedding — matching the bare word put a
  // TinyMCE XSS rule in this category.
  [
    /vector (store|database|db|index|search)\b|\bembeddings\b|embedding (vector|model|store)|\brag\b[^.]{0,30}(poison|inject)/i,
    OWASP_LLM.LLM09,
  ],
  [
    /(llm|ai|model|token)[^.]{0,40}(unbounded|no (rate|token) limit|runaway|budget)|unbounded consumption/i,
    OWASP_LLM.LLM06,
  ],
];

/** The LLM category a rule's own words place it in, if any. */
export function llmCategory(text: string): string | null {
  for (const [pattern, category] of LLM_RULES) {
    if (pattern.test(text)) return category;
  }
  return null;
}
