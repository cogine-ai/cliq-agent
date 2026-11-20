import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import ts from 'typescript';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import { runSnapshot, sessionSnapshot, ref, at } from '../../../src/client/testing/protocol.js';
import { encodeControlCheckpointCursor } from '../../../src/kernel/control-wire.js';
import { parseClientInvocation } from '../../../src/client/commands.js';
import { decodeInstalledControlResponse, type InstalledControlRequestV1 } from '../../../src/control/v1.js';
import type { RunSnapshotV1 } from '../../../src/kernel/types.js';
import { PROVIDER_JOURNEY_FILES, providerToolDiagnostic, InstalledProviderJourneyError, runInstalledProviderJourney, runInstalledDailyProviderJourney,
  readInstalledTerminalCut, type InstalledProviderJourneyContext, type InstalledProviderJourneyInput } from './installed-provider-journey.js';
import { PR532_POLL_INTERVAL_MS, PR532_RUN_WALL_TIME_MS } from './provider-journey-input.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';

// Public-protocol data and a fixed command-data check with an owned local
// child/file. Installed authority and physical retirement require Linux.
const input: InstalledProviderJourneyInput = {
  workspacePath: '/owned/workspace', model: { provider: 'openai-compatible', model: 'inert-wire-model',
    endpoint: { kind: 'registered', endpointRegistrationId: 'inert-endpoint' }, modelCredentialGrantIds: ['inert-credential'] },
  budgets: { wallTimeMs: 300_000, modelTokens: 20_000, costMicros: 100_000, toolCalls: 16, repairAttempts: 1, childDepth: 0, childConcurrency: 1 },
  guestToolchainManifestId: 'inert-guest', endpointIdentityDigest: ref
};
const snapshot = (): RunSnapshotV1 => ({ ...runSnapshot(), run: { ...runSnapshot().run, sessionId: sessionSnapshot().session.id } });
function fixture(handler?: (request: InstalledControlRequestV1) => unknown | Promise<unknown>) {
  const calls: InstalledControlRequestV1[] = [], artifacts: string[] = [];
  let reconnects = 0;
  const context: InstalledProviderJourneyContext = {
    async send(request, timeoutMs) {
      assert.equal(timeoutMs, 30_000); calls.push(request);
      if (request.method === 'session.create') return { protocolVersion: 1, ok: true, result: { method: 'session.create', snapshot: sessionSnapshot() } };
      if (request.method === 'authorization.create') return { protocolVersion: 1, ok: true, result: { method: 'authorization.create', grant: {
        schemaVersion: 1, grantId: 'inert-verifier-identity', state: 'active', targetKind: 'execution_identity_read', purpose: 'verifier',
        targetDigest: ref, useCount: 0, rowVersion: 1, createdAt: at, expiresAt: '2026-10-27T00:00:00.000Z'
      } } };
      if (handler) return handler(request);
      throw new Error('this inert protocol has no model or executor');
    },
    async artifact(ref) { artifacts.push(ref); throw new Error('no real artifacts exist in this protocol test'); },
    async reconnect() { reconnects++; },
    async observeWorkspace() { return { paths: ['check.test.mjs', 'math.mjs'], math: Buffer.from(PROVIDER_JOURNEY_FILES['math.mjs']),
      test: Buffer.from(PROVIDER_JOURNEY_FILES['check.test.mjs']) }; },
    async verifySource() { throw new Error('no actual verifier retirement or repair authority exists in this protocol test'); }
  };
  return { context, calls, artifacts, reconnects: () => reconnects };
}
const refusedAt = (stage: InstalledProviderJourneyError['stage']) => (error: unknown) => {
  assert(error instanceof InstalledProviderJourneyError); assert.equal(error.stage, stage);
  assert.equal(Object.hasOwn(error, 'cause'), false); return true;
};

test('the complete tiny workspace is checked before any public admission or model preparation', async () => {
  const f = fixture(), original = f.context.observeWorkspace;
  await assert.rejects(runInstalledProviderJourney(input, { ...f.context, observeWorkspace: async () => ({ ...await original(), paths: ['math.mjs'] }) }), refusedAt('workspace'));
  assert.equal(f.calls.length, 0); assert.equal(f.artifacts.length, 0);
});

test('one explicit admission freezes the real-model budget and required original Node test, and transport loss is never retried', async () => {
  const failure = 'untrusted provider text must not escape';
  const f = fixture(request => { assert.equal(request.method, 'run.submit'); throw new Error(failure); });
  await assert.rejects(runInstalledProviderJourney(input, f.context), error => {
    refusedAt('admission')(error); assert(!String(error).includes(failure)); return true;
  });
  assert.deepEqual(f.calls.map(request => request.method), ['session.create', 'authorization.create', 'run.submit']);
  const request = f.calls[2]; assert(request?.method === 'run.submit');
  assert.deepEqual(request.model, input.model); assert.deepEqual(request.budgets, input.budgets); assert.equal(request.allowUnverified, false);
  assert.equal(request.verifiers.length, 1); assert.equal(request.verifiers[0]!.required, true);
  assert.deepEqual(request.verifiers[0]!.argv.map(arg => arg.value), ['--test', '--test-concurrency=1', 'check.test.mjs']);
  assert.equal(request.verifiers[0]!.executable.kind, 'toolchain'); assert.equal(request.verifiers[0]!.identityReadGrantId, 'inert-verifier-identity');
  assert.equal(request.maxChangedPaths, 1); assert.deepEqual(request.dependency, { mode: 'none' });
  assert.equal(f.reconnects(), 0);
});

test('the original PR532 apply command carries the explicit admitted Delivery budget', async () => {
  // Only the original argument construction runs. No response, Run, grant or
  // installation is created by this closed-data regression.
  const source = readFileSync(new URL('./installed-pr532-journey.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('pr532.ts', source, ts.ScriptTarget.Latest, true);
  let applied: ts.VariableStatement | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isVariableStatement(node) && node.declarationList.declarations.some(declaration =>
      ts.isIdentifier(declaration.name) && declaration.name.text === 'applied')) {
      assert.equal(applied, undefined); applied = node;
    }
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(applied);
  const budgets = { ...input.budgets, wallTimeMs: 3_600_000, toolCalls: 100 };
  const consent = { sourceInspectionGrantId: 'inert-source-consent', ignoreReadGrantIds: ['inert-ignore-consent'] };
  let observed: readonly string[] | undefined;
  const context = vm.createContext({ input: { budgets }, deliveryConsent: consent,
    runId: runSnapshot().run.id, answer: { result: { ref } },
    admitted: async (argv: readonly string[], method: string) => {
      assert.equal(observed, undefined); assert.equal(method, 'run.apply'); observed = argv;
    } });
  vm.runInContext(ts.transpileModule(`globalThis.invoke = async () => { ${applied.getText(parsed)} };`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText, context);
  await context.invoke(); assert(observed);
  const invocation = parseClientInvocation(observed, '/unused');
  assert.equal(invocation.kind, 'apply'); if (invocation.kind !== 'apply') throw new Error('apply expected');
  assert.equal(canonicalSha256(invocation.options), canonicalSha256({ ...consent,
    budgets: { wallTimeMs: budgets.wallTimeMs, toolCalls: budgets.toolCalls } }));
  assert.equal(invocation.expectedRunResultRef, ref); assert(invocation.detach && invocation.json);
});

test('the PR532 report retains the exact applied bytes and original review output for inspection', () => {
  // Execute the original data projection only, with inert result identifiers.
  const source = readFileSync(new URL('./installed-pr532-journey.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('pr532.ts', source, ts.ScriptTarget.Latest, true);
  const journey = parsed.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'runInstalledPr532Journey');
  assert(journey && ts.isFunctionDeclaration(journey) && journey.body);
  const result = journey.body.statements.findLast(ts.isReturnStatement); assert(result);
  const fixed = Buffer.from('export const answer = "修复";\n'), review = Buffer.from('original reviewed diff\n');
  const appliedDigest = sha256Bytes(fixed);
  const context = vm.createContext({ runId: 'inert-run', deliveryId: 'inert-delivery', answer: { result: { ref } },
    first: { exitCode: 1 }, last: { exitCode: 0 }, diagnostic: { reportedLines: [12] },
    cut: { snapshot: { run: { budgetConsumed: { costMicros: 1 } } } }, sha256Bytes,
    input: { testBytes: Buffer.from('original check'), lockBytes: Buffer.from('original lock') },
    change: { after: { blobRef: appliedDigest } }, fixed, reviewed: { stdout: review }, TextDecoder });
  vm.runInContext(ts.transpileModule(`globalThis.project = () => { ${result.getText(parsed)} };`,
    { compilerOptions: { target: ts.ScriptTarget.ES2023 } }).outputText, context);
  const report = context.project();
  assert(Buffer.from(report.appliedFileUtf8).equals(fixed)); assert.equal(report.appliedFileDigest, appliedDigest);
  assert.equal(report.reviewOutputUtf8, review.toString('utf8'));
});

test('the original PR532 reader preserves a closed refusal even when its diagnostic sink fails', async () => {
  const source = readFileSync(new URL('./installed-pr532-journey.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('pr532.ts', source, ts.ScriptTarget.Latest, true);
  let reader: ts.Expression | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.name.getText(parsed) === 'read' &&
        node.initializer?.getText(parsed).includes('decodeInstalledControlResponse')) reader = node.initializer;
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(reader);
  for (const sinkFails of [false, true]) {
    const observed: unknown[] = [];
    const context = vm.createContext({ assert, decodeInstalledControlResponse, context: {
      send: async () => ({ protocolVersion: 1, ok: false, method: 'run.get', error: { schemaVersion: 1,
        code: 'INTERNAL', retryable: false, messageCode: 'control.internal', errorId: '11111111-1111-4111-8111-111111111111' } }),
      controlRefusal: (value: Record<string, unknown>) => { observed.push({ ...value }); if (sinkFails) throw new Error('sink failed'); }
    } });
    vm.runInContext(ts.transpileModule(`globalThis.read = ${reader.getText(parsed)};`,
      { compilerOptions: { target: ts.ScriptTarget.ES2023 } }).outputText, context);
    await assert.rejects(context.read({ protocolVersion: 1, method: 'run.get', runId: 'inert' }, 'run.get'), { code: 'ERR_ASSERTION' });
    assert.deepEqual(observed, [{ diagnosticOnly: true, method: 'run.get', code: 'INTERNAL', retryable: false }]);
  }
});

test('the controlled PR532 model covers the existing compaction output and full request reservation', () => {
  const source = readFileSync(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('journey.ts', source, ts.ScriptTarget.Latest, true);
  let assignment: ts.BinaryExpression | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isBinaryExpression(node) && node.left.getText(parsed) === 'ownedModelFixture' && ts.isObjectLiteralExpression(node.right))
      assignment = node;
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(assignment);
  const context = vm.createContext({ Date, model: 'inert-model', address: { port: 1 }, cert: Buffer.from('inert certificate'),
    pin: 'inert-pin', mcpStatusUserReplay: false, ownedModelFixture: undefined });
  const code = ts.transpileModule(assignment.getText(parsed), { compilerOptions: { target: ts.ScriptTarget.ES2023 } }).outputText;
  for (const pr532 of [false, true]) {
    context.pr532 = pr532; vm.runInContext(code, context);
    const selected = context.ownedModelFixture;
    assert.equal(selected.claims.contextLimitTokens, pr532 ? 1_000_000 : 32768);
    assert.equal(selected.claims.maxOutputTokens, pr532 ? 8192 : 4096);
    assert(selected.claims.maxOutputTokens >= Math.min(8192, Math.floor(selected.claims.contextLimitTokens / 8)));
    assert(selected.requestTokenCeiling.inputTokens >= selected.claims.contextLimitTokens);
    assert(selected.requestTokenCeiling.outputTokens >= selected.claims.maxOutputTokens);
  }
});

test('the controlled PR532 journey continues a rejected edit in the same batch before reading and repairing its generations', () => {
  const source = readFileSync(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('journey.ts', source, ts.ScriptTarget.Latest, true);
  let branch: ts.IfStatement | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isIfStatement(node) && node.expression.getText(parsed) === 'pr532' &&
        node.thenStatement.getText(parsed).includes('pr532-preview-read-')) branch = node;
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(branch);
  const replies: any[] = [], observed = new Set<string>();
  const context = vm.createContext({ assert, Buffer, JSON, parseJsonStrict, report: {}, pr532: true, postCount: 0, model: 'inert-model', expectedToolNames: ['read', 'edit', 'bash'],
    body: { tools: ['read', 'edit', 'bash'].map(name => ({ function: { name } })), messages: [{ content:
      'Verifier "node-tests" failed an assertion (exit 1) "original.test.ts" "lines":[1]' }] },
    PR532_FILE: 'original.ts', PR532_CHECK: 'original.test.ts', PR532_BASE: 'inert-base', PR532_CHECK_SOURCE: 'inert-reference',
    readGitBlob: (commit: string) => Buffer.from(commit), scanBytes: () => {},
    outgoing: { writeHead() {}, end(bytes: Buffer) { replies.push(JSON.parse(bytes.toString())); } } });
  vm.runInContext(ts.transpileModule(`globalThis.reply = () => { ${branch.getText(parsed)} };`,
    { compilerOptions: { target: ts.ScriptTarget.ES2023 } }).outputText, context);
  for (let index = 0; index < 7; index++) {
    if (index === 4) context.body.messages.push({ role: 'tool', tool_call_id: 'pr532-preview-rejected-edit',
      content: JSON.stringify({ code: 'TOOL_EXECUTION_FAILED' }) });
    if (index === 5) for (let call = 0; call < 13; call++) context.body.messages.push({ role: 'tool',
      tool_call_id: `pr532-preview-bash-${call}`, content: JSON.stringify({ tool: 'bash', terminationReason: 'exit', exitCode: 0, durationMs: 1,
        stdout: { text: 'CLIQ_PR532_NODE_WRITE_OK\n' } }) });
    context.reply();
  }
  assert.equal(replies[0].choices[0].finish_reason, 'stop');
  assert.equal(replies[6].choices[0].finish_reason, 'stop');
  for (const reply of replies.slice(1, 3)) {
    const calls = reply.choices[0].message.tool_calls;
    assert.deepEqual(calls.map((call: any) => [call.function.name, JSON.parse(call.function.arguments).path]),
      Array.from({ length: 8 }, (_, index) => ['read', index % 2 ? 'original.test.ts' : 'original.ts']));
    for (const call of calls) { assert(!observed.has(call.id)); observed.add(call.id); }
  }
  const edited = replies[3].choices[0].message.tool_calls;
  assert.equal(edited.length, 2); assert(edited.every((call: any) => call.function.name === 'edit'));
  assert.equal(edited[0].id, 'pr532-preview-rejected-edit');
  const rejectedEdit = JSON.parse(edited[0].function.arguments);
  assert.equal(rejectedEdit.path, 'original.ts');
  assert(!'inert-base'.includes(rejectedEdit.old_text));
  const firstEdit = JSON.parse(edited[1].function.arguments);
  assert.equal(firstEdit.old_text, 'inert-base');
  assert.equal(firstEdit.new_text, '// Controlled intermediate edit.\ninert-base');
  const afterEdit = replies[4].choices[0].message.tool_calls;
  assert.equal(afterEdit.length, 15); assert(afterEdit.slice(0, 2).every((call: any) => call.function.name === 'read'));
  assert.equal(JSON.parse(afterEdit[0].function.arguments).path, 'original.ts');
  assert.equal(JSON.parse(afterEdit[1].function.arguments).path, 'original.test.ts');
  const bash = afterEdit.slice(2);
  assert.equal(bash.length, 13);
  assert.equal(context.report.pr532ControlledBash.length, 13);
  assert(context.report.pr532ControlledBash.every((value: any) => value.durationMs === 1 && value.exitCode === 0));
  for (const [index, call] of bash.entries()) {
    assert.equal(call.id, `pr532-preview-bash-${index}`); assert.equal(call.function.name, 'bash');
    assert(!observed.has(call.id)); observed.add(call.id);
    assert.equal(JSON.parse(call.function.arguments).command, JSON.parse(bash[0].function.arguments).command);
  }
  // Command-data regression using the host Node and an owned file. The actual
  // signed /usr/bin/node, private workspace and retirement require Linux.
  const command = JSON.parse(bash[0].function.arguments).command as string;
  const prefix = '/usr/bin/node'; assert(command.startsWith(prefix + ' --no-addons -e '));
  const directory = mkdtempSync(path.join(os.tmpdir(), 'cliq-bash-command-'));
  try {
    const bytes = Buffer.from([0xef, 0xbb, 0xbf, 0xff, 0, 10]); writeFileSync(path.join(directory, 'original.ts'), bytes);
    const hostNode = "'" + process.execPath.replaceAll("'", "'\\''") + "'";
    const executed = spawnSync('/bin/bash', ['--noprofile', '--norc', '-c', hostNode + command.slice(prefix.length)],
      { cwd: directory, timeout: 5000, encoding: 'utf8' });
    assert.equal(executed.status, 0); assert.equal(executed.stderr, '');
    assert.equal(executed.stdout, 'CLIQ_PR532_NODE_WRITE_OK\n');
    assert.deepEqual(readFileSync(path.join(directory, 'original.ts')), bytes);
  } finally { rmSync(directory, { recursive: true, force: true }); }
  const finalEdit = JSON.parse(replies[5].choices[0].message.tool_calls[0].function.arguments);
  assert.equal(finalEdit.old_text, firstEdit.new_text); assert.equal(finalEdit.new_text, 'inert-reference');
  assert.throws(() => context.reply());
  const original = context.body.messages.find((entry: any) => entry.tool_call_id === 'pr532-preview-bash-0');
  const content = original.content;
  for (const changed of [{ exitCode: 127 }, { terminationReason: 'controller_stop' }, { stdout: { text: 'untrusted output' } }]) {
    context.postCount = 5; original.content = JSON.stringify({ ...JSON.parse(content), ...changed });
    assert.throws(() => context.reply());
  }
  original.content = content;
  context.postCount = 4;
  context.body.messages = context.body.messages.filter((entry: any) => entry.tool_call_id !== 'pr532-preview-rejected-edit');
  assert.throws(() => context.reply());
});

test('PR532 observation stays within the original client frame budget through a full Run and rejects late success', async () => {
  const source = readFileSync(new URL('./installed-pr532-journey.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('pr532.ts', source, ts.ScriptTarget.Latest, true);
  let finish: ts.VariableStatement | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isVariableStatement(node) && node.declarationList.declarations.some(declaration =>
      ts.isIdentifier(declaration.name) && declaration.name.text === 'finish')) finish = node;
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(finish);
  for (const late of [false, true]) {
    let now = 0, frames = 1, observations = 0;
    const wallTimeMs = PR532_RUN_WALL_TIME_MS;
    const context = vm.createContext({ input: { budgets: { wallTimeMs } }, Date: { now: () => now }, assert, PR532_POLL_INTERVAL_MS,
      readInstalledTerminalCut,
      context: { progress() {} }, read: async (request: Extract<InstalledControlRequestV1, { method: 'run.get' }>) => {
        assert(frames < 1024, 'original installed client frame budget exhausted'); frames++;
        if (late) now = wallTimeMs + 1;
        const after = request.afterJournalSeq ?? 0;
        const journal = Array.from({ length: Math.min(request.journalLimit ?? 100, 132 - after) }, (_, index) => ({ seq: after + index + 1 }));
        return { snapshot: { run: { status: now >= wallTimeMs - PR532_POLL_INTERVAL_MS ? 'succeeded' : 'running',
          latestCheckpointId: 'inert-checkpoint' } }, items: [], nextItemSeq: 0, journal, nextJournalSeq: after + journal.length,
          highWaterJournalSeq: 132, highWaterItemSeq: 0, checkpoints: request.checkpointCursor ? [] : [{ id: 'inert-checkpoint' }],
          highWaterCheckpointCursor: 'inert-checkpoint-cursor', nextCheckpointCursor: 'inert-checkpoint-cursor' };
      }, describeToolActivity: async () => { observations++; throw new Error('optional data unavailable'); },
      delay: async (milliseconds: number) => { now += milliseconds; } });
    vm.runInContext(ts.transpileModule(`${finish.getText(parsed)}; globalThis.finish = finish;`,
      { compilerOptions: { target: ts.ScriptTarget.ES2023 } }).outputText, context);
    if (late) await assert.rejects(context.finish('inert-run'), /preview observation deadline/);
    else {
      const terminal = await context.finish('inert-run');
      assert.equal(terminal.journal.length, 132); assert.equal(terminal.nextJournalSeq, 132);
      assert(frames < 1024);
    }
    assert(observations > 0);
  }
});

test('failed PR532 diagnosis collects the complete stable terminal cut and preserves failure if that cut changes', async () => {
  const source = readFileSync(new URL('./installed-pr532-journey.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('pr532.ts', source, ts.ScriptTarget.Latest, true);
  let finish: ts.VariableStatement | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isVariableStatement(node) && node.declarationList.declarations.some(declaration =>
      ts.isIdentifier(declaration.name) && declaration.name.text === 'finish')) finish = node;
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(finish);
  for (const changeCut of [false, true]) {
    let frames = 0;
    const observations: Array<{ items: number; complete: boolean }> = [];
    const context = vm.createContext({ input: { budgets: { wallTimeMs: PR532_RUN_WALL_TIME_MS } }, Date: { now: () => 0 }, assert,
      readInstalledTerminalCut, context: { progress() {} },
      read: async (request: Extract<InstalledControlRequestV1, { method: 'run.get' }>) => {
        assert(frames++ < 1024);
        const itemAfter = request.afterItemSeq ?? 0, journalAfter = request.afterJournalSeq ?? 0;
        const items = Array.from({ length: Math.min(request.itemLimit ?? 100, 132 - itemAfter) }, (_, index) =>
          ({ itemSeq: itemAfter + index + 1, itemId: `inert-item-${itemAfter + index + 1}` }));
        const journal = Array.from({ length: Math.min(request.journalLimit ?? 100, 132 - journalAfter) }, (_, index) =>
          ({ seq: journalAfter + index + 1, opKind: 'tool' }));
        return { snapshot: { run: { id: 'inert-run', status: 'failed', nextStep: null, latestCheckpointId: 'inert-checkpoint' } },
          items, journal, nextItemSeq: itemAfter + items.length, nextJournalSeq: journalAfter + journal.length,
          highWaterItemSeq: 132, highWaterJournalSeq: changeCut && journalAfter === 100 ? 133 : 132,
          checkpoints: request.checkpointCursor ? [] : [{ id: 'inert-checkpoint' }],
          highWaterCheckpointCursor: 'inert-checkpoint-cursor', nextCheckpointCursor: 'inert-checkpoint-cursor' };
      },
      describeDependencyFailure: async () => {},
      describeToolActivity: async (cut: { items: unknown[] }, complete = false) => { observations.push({ items: cut.items.length, complete }); } });
    vm.runInContext(ts.transpileModule(`${finish.getText(parsed)}; globalThis.finish = finish;`,
      { compilerOptions: { target: ts.ScriptTarget.ES2023 } }).outputText, context);
    await assert.rejects(context.finish('inert-run'), /installed Run stopped at failed/u);
    assert.deepEqual(observations.at(-1), { items: changeCut ? 8 : 132, complete: !changeCut });
    assert(frames < 1024);
  }
});

test('an authoritative admission refusal cannot become a replacement Run or an application', async () => {
  const f = fixture(() => ({ protocolVersion: 1, ok: false, method: 'run.submit',
    error: { schemaVersion: 1, code: 'MODEL_COST_UNKNOWN', retryable: false, messageCode: 'control.model_cost_unknown' } }));
  await assert.rejects(runInstalledProviderJourney(input, f.context), refusedAt('admission'));
  assert.equal(f.calls.filter(request => request.method === 'run.submit').length, 1);
  assert.equal(f.calls.some(request => request.method === 'run.apply'), false); assert.equal(f.artifacts.length, 0);
});

for (const providerKind of ['owned_https', 'real_provider'] as const)
test(`${providerKind} normal admission uses the actual alias, explicit fixed check and original budgets without a hidden mutation or retry`, async () => {
  const f = fixture(); let commands = 0;
  const budgets = { ...input.budgets, modelTokens: 20_000_000, costMicros: 5_000_000, repairAttempts: providerKind === 'real_provider' ? 2 : 1 };
  await assert.rejects(runInstalledDailyProviderJourney({ workspacePath: input.workspacePath,
    model: { provider: 'openai-compatible', model: input.model.model }, modelAlias: 'owned-daily', providerKind, budgets,
    endpointIdentityDigest: input.endpointIdentityDigest }, { ...f.context,
    async command(argv, timeout) {
      commands++; assert.equal(timeout, 30_000); assert.equal(argv[0], 'run');
      assert(argv.includes('--trust-workspace') && argv.includes('--detach') && argv.includes('--json'));
      const invocation = parseClientInvocation(argv.filter(flag => flag !== '--trust-workspace'), '/unused', {
        guestToolchainManifestId: input.guestToolchainManifestId, preferences: { schemaVersion: 1, modelSelections: [{ alias: 'owned-daily',
          provider: 'openai-compatible', model: input.model.model, endpointRegistrationId: 'existing-endpoint', credentialGrantId: 'existing-credential' }] } });
      assert.equal(invocation.kind, 'run'); if (invocation.kind !== 'run') throw new Error('run expected');
      assert.equal(invocation.intent.workspacePath, input.workspacePath); assert.deepEqual(invocation.intent.budgets, budgets);
      assert.equal(invocation.intent.policyMode, 'yolo'); assert.equal(invocation.intent.allowUnverified, false);
      assert.deepEqual(invocation.nodeCheck, { path: 'check.test.mjs', guestToolchainManifestId: input.guestToolchainManifestId });
      assert.deepEqual(invocation.intent.verifiers, []); assert.equal(invocation.intent.maxChangedPaths, 1);
      assert.equal(invocation.intent.maxChangedBytes, 65_536);
      throw new Error('lost command response is not permission to invent or resend an admission');
    }, async verifySource() { throw new Error('no real verifier evidence exists in this protocol test'); }
  }), refusedAt('admission'));
  assert.equal(commands, 1); assert.equal(f.calls.length, 0); assert.equal(f.artifacts.length, 0); assert.equal(f.reconnects(), 0);
});

test('UNKNOWN reconciliation remains an explicit failed journey without auto-probe, permission or dispatch', async () => {
  const f = fixture(request => {
    if (request.method === 'run.submit') return { protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: snapshot() } };
    assert.equal(request.method, 'run.get'); const waiting = snapshot();
    waiting.run.status = 'waiting'; waiting.run.waitingReason = 'reconciliation'; waiting.run.waitingOnRef = ref;
    return { protocolVersion: 1, ok: true, result: { method: 'run.get', snapshot: waiting, items: [], journal: [], checkpoints: [],
      highWaterItemSeq: 0, highWaterJournalSeq: 0, highWaterCheckpointCursor: encodeControlCheckpointCursor('run', { createdAt: at, checkpointId: 'checkpoint' }),
      nextItemSeq: 0, nextJournalSeq: 0 } };
  });
  await assert.rejects(runInstalledProviderJourney(input, f.context), error => {
    refusedAt('execution')(error); assert(error instanceof InstalledProviderJourneyError);
    assert.equal(error.progress.length, 1);
    const cut = error.progress[0]!;
    assert.deepEqual(Object.keys(cut).sort(), ['elapsedMs', 'itemSeq', 'journalSeq', 'nextStep', 'operations', 'readElapsedMs', 'revision', 'stage', 'status']);
    assert.equal(cut.status, 'waiting'); assert.equal(cut.stage, 'execution');
    assert.equal(cut.journalSeq, 0); assert.equal(cut.itemSeq, 0);
    assert(Number.isSafeInteger(cut.elapsedMs) && cut.elapsedMs >= 0);
    assert(Number.isSafeInteger(cut.readElapsedMs) && cut.readElapsedMs >= 0 && cut.readElapsedMs <= cut.elapsedMs);
    return true;
  });
  assert.deepEqual(f.calls.map(request => request.method), ['session.create', 'authorization.create', 'run.submit', 'run.get']);
  assert.equal(f.reconnects(), 0); assert.equal(f.artifacts.length, 0);
});

function terminalPage(request: Extract<InstalledControlRequestV1, { method: 'run.get' }>, changeSecondPage: boolean, deferredCheckpoints = false) {
  const queued = snapshot(), { frontierRef: _frontier, ...run } = queued.run;
  const terminal: RunSnapshotV1 = { ...queued, latestRunItemSeq: 202, run: { ...run, revision: 2, status: 'succeeded', nextStep: null,
    terminalReason: 'verified', resultRef: ref } };
  const start = request.afterItemSeq ?? 0, length = Math.min(request.itemLimit ?? 100, 202 - start);
  const cursor = encodeControlCheckpointCursor('run', { createdAt: at, checkpointId: 'checkpoint' });
  const checkpoint = { schemaVersion: 1, id: 'checkpoint', runId: 'run', basedOnRunRevision: 1, contextManifestRef: ref, workspaceStateRef: ref,
    runItemSeq: 0, journalSeq: 0, reason: 'initial', createdAt: at };
  const reachedCheckpoints = !deferredCheckpoints || start + length === 202;
  if (changeSecondPage && start === 100) terminal.run.revision = 3;
  return { protocolVersion: 1, ok: true, result: { method: 'run.get', snapshot: terminal,
    items: Array.from({ length }, (_, index) => ({ schemaVersion: 1, itemId: `inert-item-${start + index + 1}`, itemSeq: start + index + 1,
      payloadRef: ref, payloadDigest: ref, createdAt: at })), journal: [], checkpoints: request.checkpointCursor || !reachedCheckpoints ? [] : [checkpoint],
    highWaterItemSeq: 202, highWaterJournalSeq: 0, highWaterCheckpointCursor: cursor,
    nextItemSeq: start + length, nextJournalSeq: 0, ...(reachedCheckpoints ? { nextCheckpointCursor: cursor } : {}) } };
}

for (const changeSecondPage of [false, true]) test(`terminal inspection ${changeSecondPage ? 'refuses a changed cut' : 'collects all original pages without a turn-count assumption'}`, async () => {
  const f = fixture(request => {
    if (request.method === 'run.submit') return { protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: snapshot() } };
    assert(request.method === 'run.get'); return terminalPage(request, changeSecondPage);
  });
  await assert.rejects(runInstalledProviderJourney(input, f.context), refusedAt(changeSecondPage ? 'execution' : 'result'));
  const gets = f.calls.filter((request): request is Extract<InstalledControlRequestV1, { method: 'run.get' }> => request.method === 'run.get');
  assert.deepEqual(gets.map(request => request.afterItemSeq), changeSecondPage ? [0, 0, 100] : [0, 0, 100, 200]);
  assert.equal(f.calls.some(request => request.method === 'run.apply'), false);
  assert.equal(f.artifacts.length, changeSecondPage ? 0 : 1);
});

test('a full item/Journal page cannot skip original checkpoints by substituting the high-water cursor', async () => {
  const f = fixture(request => {
    if (request.method === 'run.submit') return { protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: snapshot() } };
    assert(request.method === 'run.get'); return terminalPage(request, false, true);
  });
  // Reaching result-artifact inspection proves the complete original cut was
  // collected. This inert fixture has no artifacts or native/runtime authority.
  await assert.rejects(runInstalledProviderJourney(input, f.context), refusedAt('result'));
  const gets = f.calls.filter((request): request is Extract<InstalledControlRequestV1, { method: 'run.get' }> => request.method === 'run.get');
  assert.deepEqual(gets.map(request => request.afterItemSeq), [0, 0, 100, 200]);
  assert(gets.every(request => request.checkpointCursor === undefined), 'no checkpoint has been consumed when these requests are sent');
  assert.equal(f.artifacts.length, 1); assert.equal(f.calls.some(request => request.method === 'run.apply'), false);
});

test('actual shared accounting retains verified repairs independently from invocation settlements for both provider entrances', async () => {
  // Execute only the actual pure accounting body, with powerless numeric data.
  // This creates no Run, accepted response, receipt or native retirement proof.
  const source = readFileSync(new URL('./installed-provider-journey.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('journey.ts', source, ts.ScriptTarget.Latest, true);
  let accounting: ts.FunctionDeclaration | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'accounting') { assert.equal(accounting, undefined); accounting = node; }
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(accounting);
  const script = ts.transpileModule(accounting.getText(parsed) + '\nglobalThis.accounting = accounting;',
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const zero = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  const context = vm.createContext({ ZERO: zero, check: assert.ok,
    same: (left: unknown, right: unknown) => assert.deepEqual(JSON.parse(JSON.stringify(left)), JSON.parse(JSON.stringify(right))) });
  vm.runInContext(script, context);
  for (const repairs of [0, 1, 2]) {
    const cut = { journal: [], snapshot: { run: { budgetReserved: zero, budgetConsumed: { ...zero, repairAttempts: repairs } } } };
    const consumed = await context.accounting(cut, repairs);
    assert.equal(consumed.repairAttempts, repairs);
    if (repairs) await assert.rejects(context.accounting(cut, 0));
  }
  assert(source.includes('const sourceVerification = await context.verifySource(source, session, fixedMath)'));
  assert(source.includes('await accounting(source, sourceVerification.repairCount)'));
  assert(!source.includes('accounting(source, source.snapshot.run.repairCount)'));
});


test('terminal observation yields after expensive authenticated reads without extending the original deadline or advancing a wait', async () => {
  // Exercise only fixture scheduling with inert cuts; no installed authority.
  const source = readFileSync(new URL('./installed-provider-journey.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('journey.ts', source, ts.ScriptTarget.Latest, true);
  let terminal: ts.FunctionDeclaration | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'terminal') { assert.equal(terminal, undefined); terminal = node; }
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(terminal);
  const script = ts.transpileModule(terminal.getText(parsed) + '\nglobalThis.terminal = terminal;',
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  for (const mode of ['complete', 'deadline', 'waiting'] as const) {
    let now = 0, calls = 0; const waits: number[] = [];
    const context = vm.createContext({ TERMINAL_MS: 90_000, Date: { now: () => now }, performance: { now: () => now },
      started: 0, stage: 'execution', progress: [], check: assert.ok,
      send: async () => { calls++; now += mode === 'deadline' ? 90_000 : 1700;
        return { snapshot: { run: { status: mode === 'waiting' ? 'waiting' : calls === 1 ? 'running' : 'succeeded',
          nextStep: 'agent', revision: calls } }, journal: [], nextJournalSeq: 0, highWaterJournalSeq: calls, highWaterItemSeq: calls }; },
      delay: async (ms: number) => { waits.push(ms); now += ms; } });
    vm.runInContext(script, context);
    if (mode === 'complete') { await context.terminal('inert'); assert.equal(calls, 2); assert.deepEqual(waits, [3400]); }
    else { await assert.rejects(context.terminal('inert')); assert.equal(calls, 1); assert.deepEqual(waits, []); }
  }
});


test('retained tool diagnosis binds the original Journal and emits only fixed outcomes, never content or unknown error codes', () => {
  const secret = 'inert-private-model-tool-text';
  const observation = { schemaVersion: 1, format: 'cliq-tool-observation-v1', runId: 'run', opId: 'op', attempt: 0,
    requestRef: ref, dispatchId: 'dispatch', targetRef: ref, grantRef: ref,
    outcome: 'executed', content: { text: secret }, observationDigest: '' };
  observation.observationDigest = digestOmitting(observation, 'observationDigest');
  const row = { seq: 3, opKind: 'tool', phase: 'completed', runId: 'run', opId: 'op', attempt: 0,
    requestRef: ref, dispatchId: 'dispatch', target: ref, grantRef: ref, resultRef: canonicalSha256(observation) };
  const summary = providerToolDiagnostic(row as never, observation);
  assert.deepEqual(summary, { seq: 3, outcome: 'executed' }); assert(!JSON.stringify(summary).includes(secret));
  assert.throws(() => providerToolDiagnostic({ ...row, dispatchId: 'other' } as never, observation));
  const error = { ...observation, outcome: 'error', code: secret, observationDigest: '' };
  error.observationDigest = digestOmitting(error, 'observationDigest');
  assert.throws(() => providerToolDiagnostic({ ...row, resultRef: canonicalSha256(error) } as never, error));
  error.code = 'TOOL_PROTOCOL_ERROR'; error.observationDigest = digestOmitting(error, 'observationDigest');
  assert.deepEqual(providerToolDiagnostic({ ...row, resultRef: canonicalSha256(error) } as never, error),
    { seq: 3, outcome: 'error', code: 'TOOL_PROTOCOL_ERROR' });
});
