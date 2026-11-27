// Inert callback regression for the actual Store/reducer identity handoff.
// It cannot create an authenticated frame, grant, StateOwner or native proof.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import ts from 'typescript';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys } from '../policy/runtime-authority.js';

async function source(file: string) {
  return ts.createSourceFile(file, await readFile(new URL(file, import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
}
const compile = (text: string) => ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;

test('Store passes the original frame separately from immutable verifier approval data for either Run operation', async () => {
  const parsed = await source('./store.ts'), matches: ts.VariableDeclaration[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.name.getText(parsed) === 'result' &&
        node.initializer?.getText(parsed).includes('continuation.approveVerifier(')) matches.push(node);
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(matches.length, 1);
  const invoke = new Function('continuation', 'input', 'signal', 'identity', 'mcpServerSubject', 'verifierSubject',
    `return (async () => { ${compile(matches[0]!.getText(parsed).replace(/^result\s*=/u, 'return'))} })();`) as (...args: unknown[]) => Promise<unknown>;
  const identity = Object.freeze({ principalId: 'principal', channelIdentityRef: 'ref', channelIdentityDigest: 'digest' });
  const input = { ...identity, decision: 'allow' }, signal = new AbortController().signal;
  for (const operation of ['agent', 'delivery']) {
    let invoked = false;
    await invoke({ operation, approveVerifier(data: unknown, cancellation: unknown, original: unknown) {
      invoked = true; assert.equal(data, input); assert.equal(cancellation, signal); assert.equal(original, identity);
    } }, input, signal, identity, false, true);
    assert(invoked);
  }
});

test('verifier approval preserves exact live identity through copying and rechecks it before committing', async () => {
  const parsed = await source('./verifier-execution.ts'), methods: ts.ArrowFunction[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isPropertyAssignment(node) && node.name.getText(parsed) === 'approveVerifier' && ts.isCallExpression(node.initializer)) {
      const fn = node.initializer.arguments[1]; assert(fn && ts.isArrowFunction(fn)); methods.push(fn);
    }
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(methods.length, 1);
  const identity = Object.freeze({ principalId: 'principal', channelIdentityRef: 'ref', channelIdentityDigest: 'digest' });
  const input = { ...identity, requestId: 'request', expectedRunRevision: 1, waitingOnRef: 'wait', decision: 'allow', ttlMs: 30000 };
  let active = true, checks = 0, commits = 0, closeBeforeCommit = false;
  const run = { id: 'run', revision: 1, status: 'waiting', waitingReason: 'approval', waitingOnRef: 'wait' };
  const denied = new Error('not the original current frame');
  const bindings = {
    immutableSnapshot, exactKeys, runId: run.id, owner: {}, spec: { operation: 'agent' }, toolApprovalRequestDigest: () => 'request-digest',
    validateControlChannelClosure: async (_artifacts: unknown, _owner: unknown, data: unknown) => {
      assert.notEqual(data, input, 'approval request data remains copied'); assert.deepEqual(data, input);
      return { channel: { transport: { kind: 'uds_peer' } }, metadata: [] };
    },
    assertCurrentControlFrame: (_owner: unknown, original: unknown) => {
      checks++; if (!active || original !== identity) throw denied;
    },
    readControlRequest: () => undefined,
    cut: async () => ({ run, principalId: identity.principalId, journal: [], frontier: {}, evaluator: { approve: () => ({ format: 'grant' }) } }),
    permissionContext: () => ({}),
    // The original dynamic history call is replaced only in this inert route
    // harness; none of these values can be passed into production authority.
    readWait: async () => ({ wait: {}, evidence: {} }),
    sampleCanonicalNow: () => '2026-01-01T00:00:00.000Z', toolApprovalDecision: () => ({ format: 'decision' }),
    canonicalSha256: () => 'digest', verifierPolicyItem: () => ({}), verifierApprovalDecisionCheckpointId: () => 'checkpoint',
    planCanonicalArtifact: () => ({}),
    graph: async () => ({ metadata: [], runUpdate: {}, throughItemSeq: 0, commit: () => { commits++; } }),
    artifacts: { publishCanonical: async () => { if (closeBeforeCommit) active = false; return { ref: 'artifact' }; } },
    driver: { transaction: (operation: (connection: unknown) => void) => operation({ prepare: () => ({ run() {} }) }) },
    accept: () => 'healthy', insertArtifactMetadata() {}, requireEqual() {}, readRun: () => run, appendRunStateEvent() {},
    insertControlRequest() {}, requireHealthyFence() {},
  };
  const original = methods[0]!.getText(parsed);
  const call = "(await import('./verifier-permission-history.js')).readVerifierApprovalWait";
  assert.equal(original.split(call).length, 2);
  const invoke = new Function(...Object.keys(bindings), compile(`return (${original.replace(call, 'readWait')});`))(...Object.values(bindings)) as
    (data: unknown, signal?: AbortSignal, identity?: unknown) => Promise<unknown>;
  await invoke(input, undefined, identity); assert.equal(commits, 1); assert.equal(checks, 2);
  commits = 0; checks = 0;
  for (const original of [undefined, { ...identity }])
    await assert.rejects(invoke(input, undefined, original), error => error === denied);
  assert.equal(commits, 0, 'missing or copied identity cannot commit an approval');
  checks = 0; closeBeforeCommit = true;
  await assert.rejects(invoke(input, undefined, identity), error => error === denied);
  assert.equal(checks, 2); assert.equal(commits, 0, 'closing the original frame still fences the final transaction');
});
