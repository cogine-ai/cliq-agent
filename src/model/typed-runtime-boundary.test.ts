import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const SOURCE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TYPED_RUNTIME_SOURCES = [
  'protocol/agent-ir.ts',
  'kernel/artifact-plan.ts',
  'kernel/json.ts',
  'model/attempt.ts',
  'model/capabilities.ts',
  'model/pricing.ts',
  'model/provider-observation.ts',
  'model/request.ts',
  'model/run-assembly.ts',
  'model/model-session.ts',
  'model/immutable.ts',
  'kernel/continuation.ts',
  'kernel/tool-authorization.ts',
  'kernel/user-input.ts',
  'kernel/stop.ts',
  'runtime/continuation.ts',
  'runtime/model-retry.ts',
  'runtime/user-input.ts',
  'runtime/stop.ts',
  'runtime/context-compaction.ts',
  'tools/input-contract.ts',
  'tools/input-schema.ts',
  'tools/builtin-inputs.ts',
  'tools/request-input.ts',
  'policy/decision.ts',
  'policy/engine.ts',
  'policy/decision-table.ts',
  'policy/bash-parse.ts',
  'policy/canonical-bash.ts',
  'policy/runtime-authority.ts',
  'policy/tool-policy.ts',
  'state/agent-context.ts',
  'state/agent-recovery.ts',
  'state/input-recovery.ts',
  'state/stop-recovery.ts',
  'state/resource-stop.ts',
  'state/continuation-commit.ts',
  'state/tool-cut.ts',
  'state/tool-checkpoint.ts',
  'state/tool-recovery.ts',
  'state/reducers/agent.ts',
  'state/reducers/input.ts',
  'state/reducers/stop.ts',
  'state/reducers/tool.ts'
] as const;

const LEGACY_DEPENDENCIES = [
  /protocol\/model\/actions/u,
  /protocol\/model\/json-repair/u,
  /providers\/prompt-mapping/u,
  /runtime\/runner/u
] as const;

const LEGACY_CONTROL_SYMBOLS = [
  /\bModelAction\b/u,
  /\bparseModelAction\b/u,
  /\brepairJsonStrings\b/u,
  /\bbuildTextActionFallbackInstructions\b/u,
  /TEXT ACTION FALLBACK MODE/u,
  /['"]text-action['"]/u
] as const;

test('typed model-attempt modules have no dependency on the legacy JSON-action runner', async () => {
  for (const relativePath of TYPED_RUNTIME_SOURCES) {
    const source = await readFile(resolve(SOURCE_ROOT, relativePath), 'utf8');
    for (const pattern of [...LEGACY_DEPENDENCIES, ...LEGACY_CONTROL_SYMBOLS]) {
      assert.doesNotMatch(source, pattern, `${relativePath} matched forbidden legacy pattern ${pattern}`);
    }
    if (relativePath.startsWith('model/')) {
      assert.doesNotMatch(source, /from ['"]\.\/types\.js['"]/u, `${relativePath} imports legacy model types`);
    }
    if (relativePath.startsWith('tools/')) {
      assert.doesNotMatch(source, /from ['"](?:node:fs(?:\/promises)?|\.\/types\.js|\.\.\/policy\/(?:types|subjects)\.js)['"]/u,
        `${relativePath} imports host I/O or the retiring tool/policy contract`);
    }
    if (relativePath.startsWith('policy/')) {
      assert.doesNotMatch(source, /from ['"]\.\/(?:types|subjects)\.js['"]/u,
        `${relativePath} imports the retiring policy contract`);
    }
    if (['policy/canonical-bash.ts', 'policy/tool-policy.ts', 'tools/builtin-inputs.ts'].includes(relativePath)) {
      assert.doesNotMatch(source, /from ['"][^'"]*\/(?:engine|decision-table|bash-parse)\.js['"]/u,
        `${relativePath} imports the retiring policy interpreter`);
    }
  }
});

test('typed model modules use the strict wire decoder instead of direct JSON.parse', async () => {
  for (const relativePath of TYPED_RUNTIME_SOURCES.filter((path) => path.startsWith('model/'))) {
    const source = await readFile(resolve(SOURCE_ROOT, relativePath), 'utf8');
    assert.doesNotMatch(source, /\bJSON\.parse\s*\(/u, `${relativePath} bypasses the strict JSON boundary`);
    if (relativePath === 'model/request.ts') {
      assert.doesNotMatch(source, /\bparseJsonStrict\b/u, 'request preparation must not re-decode typed tool arguments');
    }
  }
});
