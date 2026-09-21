import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { scan } from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => join(here, 'fixtures', name);
const VULNERABLE = fixture('vulnerable-app');
const CLEAN = fixture('clean-app');

// Unlike server-actions.test.js, these assertions never touch the generated
// .env / symlink state buildFixtures() produces, and skipping the call here
// avoids a symlink-creation race when `node --test` runs multiple files
// concurrently.

const AGENT_IDS = ['CTS080', 'CTS081', 'CTS082', 'CTS083', 'CTS084', 'CTS085'];

test('the LLM rules fire on the shape they name, and not on the safe one', async () => {
  const bad = await scan({ root: VULNERABLE, offline: true });
  const byId = (id) => bad.findings.find((f) => f.id === id);

  assert.equal(byId('CTS080').meta.llm, 'LLM01:2026 - Prompt Injection');
  assert.equal(byId('CTS080').file, 'app/ai/assistant.ts');
  assert.equal(byId('CTS081').meta.llm, 'LLM06:2026 - Unbounded Consumption');
  assert.equal(byId('CTS082').meta.llm, 'LLM08:2026 - Hidden Context Exposure');
  assert.equal(byId('CTS082').file, 'app/ai/panel.tsx');

  const clean = await scan({ root: CLEAN, offline: true });
  const cleanAgent = clean.findings.filter((f) => AGENT_IDS.includes(f.id));
  assert.deepEqual(cleanAgent.map((f) => `${f.id} ${f.file}`), []);
});

test('the agent rules fire on the shape they name, and stand down on the gated one', async () => {
  const bad = await scan({ root: VULNERABLE, offline: true });
  const only = (id) => bad.findings.filter((f) => f.id === id);

  const agency = only('CTS083');
  assert.deepEqual(agency.map((f) => f.meta.tool).sort(), ['purgeWorkspace', 'run_maintenance']);
  assert.ok(agency.every((f) => f.meta.llm === 'LLM03:2026 - Excessive Agency'));
  assert.ok(!agency.some((f) => f.meta.tool === 'archiveWorkspace'), 'a gated tool is not reported');
  assert.ok(!agency.some((f) => f.meta.tool === 'listWorkspaces'), 'a read-only tool is not reported');
  assert.ok(
    !agency.some((f) => f.meta.tool === 'forgetSession'),
    'Map.delete() inside a tool is not an irreversible database write',
  );

  const output = only('CTS084');
  assert.deepEqual(output.map((f) => f.meta.sink).sort(), ['dangerouslySetInnerHTML', 'execSync', 'new Function']);
  assert.equal(
    output.filter((f) => f.severity === 'critical').length,
    2,
    'the eval-class sinks are critical; rendering as HTML is high',
  );
  assert.ok(output.every((f) => f.meta.llm === 'LLM10:2026 - Improper Output Handling'));

  const decision = only('CTS085');
  assert.equal(decision.length, 2);
  assert.ok(decision.every((f) => f.meta.llm === 'LLM07:2026 - Misinformation'));
  assert.ok(decision.every((f) => f.file === 'lib/agent/triage.ts'));
  assert.ok(!decision.some((f) => f.line > 30), 'summarise() must not be flagged');

  const clean = await scan({ root: CLEAN, offline: true });
  const cleanAgent = clean.findings.filter((f) => AGENT_IDS.includes(f.id));
  assert.deepEqual(cleanAgent.map((f) => `${f.id} ${f.file}`), []);
});
