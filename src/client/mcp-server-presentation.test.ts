// Inert canonical display data. This creates no accepted Run, signed image,
// native owner, consumed identity, approval, StateOwner or physical evidence.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { mcpServerLaunchOperationId } from '../kernel/mcp-stdio.js';
import { mcpServerLaunchSubject } from '../kernel/mcp-server-authorization.js';
import { readMcpServerWaitingPresentation } from './mcp-server-presentation.js';
import { readWaitingPresentation } from './artifacts.js';
import { runSnapshot, at, ref } from './testing/protocol.js';

function fixture() {
  const objects = new Map<string, Buffer>(), reads: string[] = [];
  const save = (data: Record<string, unknown>, key?: string) => {
    const value = key ? { ...data, [key]: canonicalSha256(data) } : data, reference = canonicalSha256(value);
    objects.set(reference, canonicalJsonBytes(value)); return { value, ref: reference };
  };
  const executable = save({ kind: 'runtime_bundle', runtimeBundleRef: ref, executableId: 'owned-server',
    executionPath: '/runtime/mcp-server', executableDigest: ref });
  const targetCore = { schemaVersion: 1 as const, format: 'cliq-mcp-server-launch-target-v1' as const, runId: 'run', registrationId: 'owned',
    registryRevisionRef: ref, registryManifestDigest: ref, lifecycleSeq: 0, batchItemId: 'batch', callId: 'call', callIndex: 0,
    toolRequestRef: ref, toolRequestDigest: ref, executableIdentityRef: executable.ref, executableIdentityDigest: executable.ref,
    argv: ['--stdio', ''], initializeDigest: ref, capabilityDigest: ref, probedToolsListDigest: ref, maxLaunches: 2, launchTimeoutMs: 5000, callTimeoutMs: 20_000 };
  const target = { ...targetCore, targetDigest: canonicalSha256(targetCore) }, targetArtifact = save(target);
  const frontier = save({ schemaVersion: 1, kind: 'tool', batchItemId: 'batch', orderedCallIds: ['call'], nextCallIndex: 0 });
  const spec = save({ schemaVersion: 1, operation: 'agent', objectiveRef: ref, admittedContextRef: ref, baseWorkspaceManifestRef: ref,
    sourceProjectionRef: ref, assemblyRef: ref, policyRef: ref, sandboxProfileRef: ref, verifierSpecRef: ref, credentialGrantRefs: [], budgets: {} });
  const opId = mcpServerLaunchOperationId('run', 'batch', 0, 'call', ref, 0);
  const request = save({ schemaVersion: 1, format: 'cliq-mcp-server-launch-request-v1', runId: 'run', opId, frontierRef: frontier.ref,
    assemblyRef: ref, registryRevisionRef: ref, registryManifestDigest: ref, lifecycleSeq: 0, batchItemId: 'batch', callId: 'call', callIndex: 0,
    toolRequestRef: ref, toolRequestDigest: ref, targetRef: targetArtifact.ref, targetDigest: target.targetDigest }, 'requestDigest');
  const named = mcpServerLaunchSubject(target);
  const evidence = save({ schemaVersion: 1, format: 'cliq-policy-channel-evidence-v1', principalId: 'inert-principal', runId: 'run',
    policyRef: ref, policyDigest: ref, frontierRef: frontier.ref, opId, requestRef: request.ref, requestDigest: request.value.requestDigest,
    targetRef: targetArtifact.ref, targetDigest: target.targetDigest, actionClass: 'mcp', decisionSource: 'mode_fallthrough', matchedRuleIds: [],
    effectiveDisposition: 'ask', evaluatedAt: at, channel: 'named-action', namedAction: named,
    identityKey: `mcp_server_launch/${ref}/0` }, 'evidenceDigest');
  const wait = save({ schemaVersion: 1, kind: 'approval', runId: 'run', createdFromRevision: 1, createdAt: at, frontierRef: frontier.ref,
    subject: { ...named, opId, target: targetArtifact.ref, policyChannelEvidenceRef: evidence.ref, policyChannelEvidenceDigest: evidence.value.evidenceDigest } });
  const snapshot = runSnapshot(); snapshot.run = { ...snapshot.run, specRef: spec.ref, frontierRef: frontier.ref,
    status: 'waiting', waitingReason: 'approval', waitingOnRef: wait.ref, revision: 2 };
  const app = { async artifact(reference: string, options: { maxBytes: number; signal?: AbortSignal }) {
    options.signal?.throwIfAborted(); reads.push(reference); const bytes = objects.get(reference);
    if (!bytes || bytes.length > options.maxBytes) throw new TypeError('inert display artifact unavailable'); return Buffer.from(bytes);
  }, async readRun(): Promise<never> { throw new Error('display must not replace its captured Run'); } };
  return { snapshot, wait: wait.value, targetArtifact, evidence, executable, objects, reads, app };
}
test('the shared CLI/TUI wait projects original server identity, argv, scope and separate charge', async () => {
  const data = fixture(), shown = await readWaitingPresentation(data.app, data.snapshot);
  assert.equal(shown.waitingOnRef, data.snapshot.run.waitingOnRef);
  for (const text of ['Launch MCP server "owned"', 'Executable: "owned-server"', 'Arguments: "--stdio" ""',
    'no network', 'at most 2 original launch claims', 'tool effect has its own permission and charge']) assert(shown.text.includes(text));
  assert(data.reads.includes(data.executable.ref)); assert.equal(data.reads.length, 7);
});
test('server consent display rejects source substitution, a changed captured wait and cancellation without any mutation', async () => {
  const data = fixture(); data.objects.set(data.targetArtifact.ref, canonicalJsonBytes({ ...data.targetArtifact.value, argv: ['other'] }));
  await assert.rejects(readMcpServerWaitingPresentation(data.app, data.snapshot, data.wait), /original artifact bytes/);
  const original = fixture();
  await assert.rejects(readMcpServerWaitingPresentation(original.app, { ...original.snapshot,
    run: { ...original.snapshot.run, waitingOnRef: ref } }, original.wait), /captured Run/);
  await assert.rejects(readMcpServerWaitingPresentation(original.app, { ...original.snapshot,
    run: { ...original.snapshot.run, cancelRequested: true } }, original.wait), /captured Run/);
  const cancelled = new AbortController(), reason = new Error('original consumer closed'); cancelled.abort(reason);
  await assert.rejects(readMcpServerWaitingPresentation(original.app, original.snapshot, original.wait, cancelled.signal), error => error === reason);
});
