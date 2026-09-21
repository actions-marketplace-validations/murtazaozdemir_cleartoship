import { read, rel, isScript, snippetAt } from '../utils/files.js';
import { adjustForPath } from '../utils/paths.js';
import { parseSource, calleeName, calleeTail } from '../utils/ast.js';
import { traverse } from '../utils/traverse.js';
import { Suppressions } from '../utils/suppress.js';
import { emptyResult } from '../types.js';
import type { Finding, ProjectContext, ScanResult, Scanner } from '../types.js';

/**
 * Cross-cutting logic checks for OWASP categories a pattern scanner can only
 * touch in specific, high-signal slices:
 *   A09 (Logging Failures)      — secrets/PII written to logs
 *   A10 (Exceptional Conditions)— fail-open / swallowed errors on a security path
 *   A08 (Integrity Failures)    — insecure deserialization of untrusted data
 *
 * Each rule is deliberately narrow: the goal is a true positive a developer will
 * act on, not coverage for its own sake.
 *
 * The LLM/agent-specific checks (CTS080-085) live in `agent-logic.ts` — see that
 * file for the OWASP LLM Top 10 categories it covers.
 */

const LOG_METHODS = new Set(['log', 'info', 'warn', 'error', 'debug', 'trace', 'fatal', 'verbose']);
const LOG_OBJECTS = /^(console|logger|log|pino|winston|fastify\.log|req\.log|ctx\.log|this\.logger)$/i;

/** A property/identifier name that names a real secret or piece of PII. */
const SENSITIVE_NAME =
  /(?:^|[._])(password|passwd|pwd|secret|secrets|token|tokens|apikey|api_key|authorization|auth_?token|accesstoken|access_token|refreshtoken|refresh_token|sessiontoken|session_token|privatekey|private_key|clientsecret|client_secret|creditcard|card_?number|cardnumber|cvv|cvc|ssn|social_?security|passport|jwt)(?:$|[._])/i;

/** Reading a whole request/response body into a log dumps everything in it. */
const BODY_EXPR = /(?:^|\.)(body|rawBody|payload)$/;

/** Deserializers that can instantiate objects or run code from their input. */
const UNSAFE_DESERIALIZE = [
  'unserialize', // node-serialize / serialize-to-js — RCE on crafted input
  'deserialize',
  'funcster.deepDeserialize', // cleartoship-ignore VG070 — rule-name data, not a call
  'pickle.loads', // python
  'pickle.load',
  'cPickle.loads',
  'yaml.unsafe_load', // python
];

/** Function names that signal the body is making a security decision. */
const SECURITY_FN =
  /(verify|validate|authenticate|authorize|auth|check(?:auth|access|permission)?|hasaccess|haspermission|isallowed|isauthorized|canaccess|ensure|guard|require(?:auth|user|admin)?)/i;

/** Values a security check must never return from a swallowed error (fail-open). */
function isPermissiveReturn(node: any): boolean {
  if (!node) return false;
  if (node.type === 'BooleanLiteral' && node.value === true) return true;
  if (node.type === 'Identifier' && /^(user|session|account|token|claims)$/i.test(node.name)) return true;
  if (node.type === 'ObjectExpression') {
    return node.properties.some(
      (p: any) =>
        p?.key &&
        /^(authorized|authenticated|valid|allowed|ok|success)$/i.test(p.key.name ?? p.key.value) &&
        p.value?.value === true,
    );
  }
  if (node.type === 'CallExpression') {
    // next() with no error argument lets the request continue.
    return calleeTail(node.callee) === 'next' && (node.arguments ?? []).length === 0;
  }
  return false;
}

export const logicScanner: Scanner = {
  name: 'Logging, exception-handling & deserialization',

  applies(ctx) {
    return ctx.files.some((f) => isScript(f) || f.endsWith('.py'));
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    let analysed = 0;

    for (const file of ctx.files) {
      const script = isScript(file);
      const python = file.endsWith('.py');
      if (!script && !python) continue;
      const source = read(file);
      if (source === null) continue;
      const relPath = rel(ctx.root, file);
      // A swallowed error or a logged token in a maintenance script is a
      // smaller problem than the same line inside a request handler.
      const place = (f: any) => {
        const placed = adjustForPath(f.severity, relPath);
        return { ...f, severity: placed.severity, detail: f.detail + placed.note };
      };
      const suppress = new Suppressions(source);

      const push = (f: Omit<Finding, 'file'> & { line: number }) => {
        if (suppress.suppressed(f.line, f.id)) return;
        result.findings.push({ ...place(f), file: relPath, snippet: snippetAt(source, f.line) });
      };

      // Python is regex-only (no JS AST). Cover its highest-signal cases.
      if (python) {
        analysed++;
        source.split('\n').forEach((lineText, i) => {
          const line = i + 1;
          if (/\b(pickle|cPickle)\.loads?\s*\(/.test(lineText) || /\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)/.test(lineText)) {
            push({
              id: 'CTS072',
              severity: 'high',
              title: 'Insecure deserialization of untrusted data',
              detail:
                'This call deserializes input with a loader that can construct arbitrary objects — ' +
                '`pickle` and unqualified `yaml.load` both execute code embedded in a crafted payload.',
              fix: 'Use `yaml.safe_load` (or `Loader=yaml.SafeLoader`); never `pickle.loads` on data that crossed a trust boundary. Prefer JSON for untrusted input.',
              line,
              cwe: 'CWE-502: Deserialization of Untrusted Data',
              owasp: 'A08:2025 - Software & Data Integrity Failures',
            });
          }
        });
        continue;
      }

      const ast = parseSource(source, file);
      if (!ast) continue;
      analysed++;

      traverse(ast, {
        CallExpression(path: any) {
          const node = path.node;
          const tail = calleeTail(node.callee);
          const full = calleeName(node.callee);

          // --- A09: secrets / PII written to a log ---
          const base = full.slice(0, full.lastIndexOf('.'));
          const isLog =
            LOG_METHODS.has(tail) && (LOG_OBJECTS.test(base) || base === '' || /log$/i.test(base));
          if (isLog) {
            for (const arg of node.arguments ?? []) {
              // Only value expressions count — a string message that merely
              // contains the word "password" is not logging a password.
              if (arg.type === 'StringLiteral' || arg.type === 'TemplateLiteral') continue;
              const name = arg.type === 'MemberExpression' || arg.type === 'Identifier' ? calleeName(arg) : '';
              const sensitive = name && SENSITIVE_NAME.test(name);
              const wholeBody = name && BODY_EXPR.test(name);
              if (sensitive || wholeBody) {
                push({
                  id: 'CTS070',
                  severity: wholeBody && !sensitive ? 'medium' : 'high',
                  title: wholeBody && !sensitive ? 'Request body written to logs' : 'Secret or PII written to logs',
                  detail:
                    (wholeBody && !sensitive
                      ? `\`${name}\` is logged in full, so whatever a caller put in the request body — ` +
                        'passwords, tokens, personal data — lands in your log store and anywhere it is shipped.'
                      : `\`${name}\` is written to a log. Logs are retained, replicated to aggregators and ` +
                        'often world-readable to a whole team; a credential or piece of PII there is a ' +
                        'leak that outlives the request.'),
                  fix:
                    'Do not log the raw value. Log a non-reversible reference (a user id, a hash prefix) ' +
                    'or redact the field before logging.',
                  line: node.loc?.start.line ?? 0,
                  cwe: 'CWE-532: Insertion of Sensitive Information into Log File',
                  owasp: 'A09:2025 - Security Logging & Alerting Failures',
                  meta: { logged: name },
                });
                break;
              }
            }
          }

          // --- A08: insecure deserialization ---
          if (UNSAFE_DESERIALIZE.some((d) => full === d || full.endsWith('.' + d) || tail === d)) {
            const arg = (node.arguments ?? [])[0];
            // A string literal is a fixed, trusted payload; only flag dynamic input.
            if (arg && arg.type !== 'StringLiteral') {
              push({
                id: 'CTS072',
                severity: 'high',
                title: 'Insecure deserialization of untrusted data',
                detail:
                  `\`${full}(...)\` reconstructs objects from its input. Deserializers of this kind can ` +
                  'instantiate arbitrary types and invoke their side effects, so a crafted payload is ' +
                  'remote code execution — this is why `JSON.parse` is safe and these are not.',
                fix:
                  'Deserialize untrusted data with `JSON.parse` only. If you need richer types, validate ' +
                  'the parsed shape with a schema; never hand attacker-controlled bytes to an object ' +
                  'deserializer.',
                line: node.loc?.start.line ?? 0,
                cwe: 'CWE-502: Deserialization of Untrusted Data',
                owasp: 'A08:2025 - Software & Data Integrity Failures',
              });
            }
          }
        },

        // --- A10: fail-open / swallowed error on a security path ---
        CatchClause(path: any) {
          const node = path.node;
          const body = node.body?.body ?? [];

          // Name of the nearest enclosing function, to tell whether this catch
          // guards a security decision.
          let fnName = '';
          let p = path.parentPath;
          let hops = 0;
          while (p && hops++ < 8) {
            const n = p.node;
            if (n?.type === 'FunctionDeclaration' || n?.type === 'FunctionExpression') {
              fnName = n.id?.name ?? '';
              break;
            }
            if (n?.type === 'ArrowFunctionExpression' || n?.type === 'VariableDeclarator') {
              fnName = n.id?.name ?? fnName;
            }
            p = p.parentPath;
          }
          const securityContext = SENSITIVE_NAME.test(fnName) || SECURITY_FN.test(fnName);
          if (!securityContext) return;

          const returns = body.filter((s: any) => s.type === 'ReturnStatement');
          const permissive = returns.some((r: any) => isPermissiveReturn(r.argument));
          const empty = body.length === 0;
          const swallows =
            empty ||
            body.every(
              (s: any) =>
                s.type === 'ReturnStatement' ||
                (s.type === 'ExpressionStatement' &&
                  /console|log/i.test(calleeName(s.expression?.callee ?? {}))),
            );

          if (permissive || (empty && securityContext) || (swallows && permissive)) {
            push({
              id: 'CTS071',
              severity: permissive ? 'high' : 'medium',
              title: permissive
                ? 'Security check fails open on error'
                : 'Security check swallows its error',
              detail:
                `The catch block in \`${fnName || 'this function'}\` ` +
                (permissive
                  ? 'returns a permissive value (authorized / a user / next()) when the guarded ' +
                    'operation throws. An attacker who can make the check error — a malformed token, a ' +
                    'timeout — is then let straight through.'
                  : 'discards the error from a security-relevant operation. A verification that throws ' +
                    'is a failure, not a pass; swallowing it hides the failure and risks failing open.'),
              fix:
                'Fail closed: on error, deny — `return false` / throw / respond 401 — and log the error. ' +
                'Never return a success value from the catch of a security check.',
              line: node.loc?.start.line ?? 0,
              cwe: 'CWE-703: Improper Check or Handling of Exceptional Conditions',
              owasp: 'A10:2025 - Mishandling of Exceptional Conditions',
              meta: { function: fnName },
            });
          }
        },
      });
    }

    result.checks.push({
      label: `Logging, error-handling & deserialization (${analysed} file${analysed === 1 ? '' : 's'})`,
      passed: !result.findings.some((f) => f.severity === 'critical' || f.severity === 'high'),
    });
    return result;
  },
};
