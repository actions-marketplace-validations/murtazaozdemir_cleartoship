# The standards behind the labels

`cleartoship` labels findings against two published lists rather than inventing
its own taxonomy. This page explains what those lists are, who publishes them,
and what each category means. For **what ClearToShip actually detects** in each
category — the honest, category-by-category coverage — see the two tables in
[README.md](../README.md#owasp-top-102025-coverage--honest-version) instead;
this page is background on the standards themselves, not a coverage claim.

## Who publishes these

Both lists come from **OWASP**, the **Open Worldwide Application Security
Project** (formerly "Open Web Application Security Project" — the name changed,
the acronym didn't). It's a nonprofit foundation, not a vendor: the lists are
produced by volunteer working groups from community-contributed data and
public comment, not sold or licensed, and nobody's product ranking depends on
where a category lands.

- Organization: https://owasp.org/
- OWASP Top 10 project (web applications): https://owasp.org/www-project-top-ten/
- OWASP Top 10 for LLM Applications project (part of the OWASP GenAI Security
  Project): https://owasp.org/www-project-top-10-for-large-language-model-applications/

Both are living documents revised every few years as the threat landscape
changes — categories get renamed, merged, split, or renumbered between
editions. `cleartoship` pins to a specific edition of each (2025 for the web
list, 2026 for the LLM list) and says so, because a rule that cites "A05"
without an edition is citing a moving target.

## OWASP Top 10:2025 — the ten categories

The general web application list. `cleartoship`'s own categories live in
`OWASP_2025` in `src/utils/owasp.ts`.

| # | Category | What it means |
| --- | --- | --- |
| A01 | Broken Access Control | A user can act on, or see, data or functions they shouldn't be able to reach — missing auth checks, IDOR, privilege escalation. Also folds in SSRF in the 2025 edition. |
| A02 | Security Misconfiguration | Insecure defaults, unnecessary features left on, missing security headers, permissive CORS, verbose error output — the app is fine, the setup around it isn't. |
| A03 | Software Supply Chain Failures | Risk introduced through dependencies, build tooling, or CI/CD rather than first-party code: known-vulnerable packages, typosquats, compromised or unpinned actions. |
| A04 | Cryptographic Failures | Sensitive data handled, stored, or transmitted with weak or absent cryptography — hardcoded keys, weak hashing, plaintext where encryption was needed. |
| A05 | Injection | Untrusted input reaching an interpreter as if it were code or structured syntax — SQL, command, XSS, and similar. |
| A06 | Insecure Design | The vulnerability is in the architecture or threat model itself, not an implementation bug — no amount of secure coding fixes a design that never considered the threat. |
| A07 | Authentication Failures | Weaknesses in confirming who a user is — weak session handling, credential stuffing exposure, broken MFA, forgeable tokens. |
| A08 | Software & Data Integrity Failures | Code or data trusted without verifying its integrity — unsigned updates, insecure deserialization, CI/CD pipelines that can be tampered with. |
| A09 | Security Logging & Alerting Failures | Attacks that go undetected because the events that should have been logged, or alerted on, weren't. |
| A10 | Mishandling of Exceptional Conditions | Error and edge-case paths that fail unsafely — failing open, swallowing a security-relevant exception, undefined behavior on malformed input. |

## OWASP Top 10 for LLM Applications (2026) — the ten categories

Specific to applications built on, or around, large language models and
agents. `cleartoship`'s categories live in `OWASP_LLM` in the same file. The
2026 edition renumbered eight of the ten from the prior edition, so an old
citation like "LLM06: Excessive Agency" is stale — it's LLM03 now.

| # | Category | What it means |
| --- | --- | --- |
| LLM01 | Prompt Injection | Untrusted input changes the model's instructions or behavior — directly, or indirectly via content the model reads (a fetched page, a document, a tool result). |
| LLM02 | Sensitive Information Disclosure | The model, or the app around it, exposes data that shouldn't be exposed — training data, system internals, PII, or credentials leaking through a prompt, response, or client-side bundle. |
| LLM03 | Excessive Agency | The model or an agent built on it is given more permission, autonomy, or reach than the task needs — a tool that can take an irreversible action with no human check. |
| LLM04 | Supply Chain | Risk from the model, dataset, plugin, or agent-framework supply chain — an unpinned or unverified model source, a compromised third-party component. |
| LLM05 | Data and Model Poisoning | Training, fine-tuning, or embedding data manipulated to introduce vulnerabilities, biases, or backdoors into the model's behavior. |
| LLM06 | Unbounded Consumption | Nothing limits how much the model can be made to do or cost — no rate limit, no token ceiling, no resource cap on inference triggered by user input. |
| LLM07 | Misinformation | The model produces plausible but false or unsupported output, and something downstream — a person or a system — trusts it without verification. |
| LLM08 | Hidden Context Exposure | Anything placed in the model's context window — system prompt, retrieved documents, tool output — leaks to a party who shouldn't see it. Broadened from the prior edition's narrower "System Prompt Leakage." |
| LLM09 | Vector and Embedding Weaknesses | Weaknesses in how embeddings and vector stores are generated, stored, or retrieved — unauthorized access, poisoning, or retrieval that reintroduces untrusted content into a prompt. |
| LLM10 | Improper Output Handling | The model's output is passed downstream — into a shell, a database query, `eval`, or rendered as HTML — without the validation or escaping that output deserves. |

## How `cleartoship` uses these

Every finding — first-party or vendored — gets normalized onto exactly one
`OWASP_2025` category, and the ones that are about an LLM or agent get a second,
independent `OWASP_LLM` category alongside it (`meta.llm`). A CWE is a separate
matter: ClearToShip's own rules and the gitleaks-derived credential rules each
name one (`cwe`), while vendored GuardVibe findings carry none, because
upstream publishes none and this project does not invent one per rule. The
OWASP mapping is
derived from each rule's own wording, not a hand-kept id list, and is
deliberately conservative: a rule that doesn't clearly belong to a category
gets none rather than a guess. The original upstream label — which is not
always internally consistent — is preserved in `meta.owaspUpstream` so the
relabeling stays checkable. See the header comment in `src/utils/owasp.ts` for
the full reasoning, and the coverage tables in `README.md` for what's actually
detected per category, honestly including the one LLM category (LLM05) nothing
in a static source scan can answer.
