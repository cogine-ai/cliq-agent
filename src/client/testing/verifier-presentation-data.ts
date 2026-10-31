// Inert canonical wire artifacts for a display consumer. No accepted Run,
// authorization, StateOwner or signed/native execution proof is constructed.
import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import { identityHash } from '../../kernel/identity.js';
import { at, ref, runSnapshot } from './protocol.js';
type RecordData = Record<string, unknown>;
export function verifierPresentationData(options: { required?: boolean; operation?: 'agent' | 'delivery';
  change?: (kind: string, value: RecordData) => RecordData } = {}) {
  const required = options.required ?? true, operation = options.operation ?? 'agent';
  const objects = new Map<string, Buffer>(), values: Record<string, RecordData> = {}, refs: Record<string, string> = {};
  function save(kind: string, core: RecordData, digestKey?: string) {
    const data = options.change?.(kind, structuredClone(core)) ?? core;
    const value = digestKey ? { ...data, [digestKey]: canonicalSha256(data) } : data;
    values[kind] = value; const digest = canonicalSha256(value); refs[kind] = digest; objects.set(digest, canonicalJsonBytes(value)); return value;
  }
  const command = save('command', { schemaVersion: 1, format: 'cliq-verifier-command-v1', verifierId: 'node-tests', verifierVersion: '1',
    executable: { kind: 'guest_toolchain', guestToolchainManifestRef: ref, guestToolchainManifestDigest: ref,
      toolId: 'node', executionPath: '/toolchain/node', executableDigest: ref, abiFingerprint: 'inert-linux-abi' },
    argv: ['--test', '--test-concurrency=1', 'test/check.mjs'].map(value => ({ kind: 'non_secret_literal', value })), cwd: '.' }, 'commandDigest');
  const environment = save('environment', { schemaVersion: 1, format: 'cliq-verifier-environment-v1', verifierId: 'node-tests', verifierVersion: '1',
    commandRef: refs.command, commandDigest: command.commandDigest, variables: [], writableEphemeralPaths: [], sourceProjectionRef: ref,
    sourceAccess: 'read_only', networkAccess: 'denied', sandboxProfile: 'cliq-verifier-readonly-v1', runtimeBundleRef: ref,
    runtimeBundleManifestDigest: ref, guestToolchainManifestRef: ref, guestToolchainManifestDigest: ref }, 'environmentDigest');
  const entry = save('entry', { index: 0, id: 'node-tests', version: '1', gate: required ? 'required' : 'advisory',
    commandRef: refs.command, commandDigest: command.commandDigest, environmentRef: refs.environment,
    environmentDigest: environment.environmentDigest, timeoutMs: 10000, retries: 0, outputLimitBytes: 65536 }, 'entryDigest');
  const frozen = save('frozen', { schemaVersion: 1, format: 'cliq-verifier-spec-v1', verifiers: [entry] }, 'specDigest');
  const policy = save('policy', { schemaVersion: 1, format: 'cliq-run-policy-v1', principalId: 'inert-principal', workspaceIdentityDigest: ref,
    mode: 'default', engine: { id: 'cliq-policy-v1', version: '1', runtimeBundleRef: ref, profileEntryId: 'policy', profileRef: ref, profileDigest: ref },
    toolManifestRef: ref, toolManifestDigest: ref, decisions: { read: 'allow', plan: 'allow', write: 'ask', exec: 'ask', mcp: 'ask', verifier: 'ask',
      dependency_install_scripts: 'ask', delivery: 'ask', child_read_only: 'ask', child_mutating: 'ask' },
    decisionRules: [], repositoryRequestRefs: [], createdAt: at }, 'policyDigest');
  save('spec', { schemaVersion: 1, operation, objectiveRef: ref, admittedContextRef: ref, baseWorkspaceManifestRef: ref,
    sourceProjectionRef: ref, assemblyRef: ref, policyRef: refs.policy, sandboxProfileRef: ref, verifierSpecRef: refs.frozen, credentialGrantRefs: [],
    budgets: { wallTimeMs: 60000, modelTokens: 1000, costMicros: 1000, toolCalls: 10, repairAttempts: 0, childDepth: 0, childConcurrency: 0 } });
  const planEntry = { index: 0, verifierId: 'node-tests', verifierSpecDigest: frozen.specDigest, verifierEntryDigest: entry.entryDigest,
    commandRef: refs.command, commandDigest: command.commandDigest, environmentRef: refs.environment, environmentDigest: environment.environmentDigest, required, maxAttempts: 1 };
  const plan = save('plan', { schemaVersion: 1, runId: 'run', candidateItemId: 'inert-candidate', resultSourceRef: ref,
    verifierSpecRef: refs.frozen, verifierSpecDigest: frozen.specDigest, entries: [planEntry] }, 'planDigest');
  save('frontier', { schemaVersion: 1, kind: 'verify', phase: 'verifiers', candidateItemId: 'inert-candidate', resultSourceRef: ref,
    verifierPlanRef: refs.plan, nextVerifierIndex: 0, afterPass: operation === 'delivery' ? 'delivery_approval' : 'finalize' });
  const opId = identityHash('cliq-verifier-operation-v1', 'run', 'inert-candidate', refs.plan, '0');
  const target = save('target', { schemaVersion: 1, format: 'cliq-verifier-target-v1', runId: 'run', candidateItemId: 'inert-candidate', resultSourceRef: ref,
    sourceDigest: ref, verifierPlanRef: refs.plan, verifierPlanDigest: plan.planDigest, verifierSpecRef: refs.frozen, verifierSpecDigest: frozen.specDigest,
    verifierIndex: 0, verifierId: 'node-tests', verifierVersion: '1', verifierEntryDigest: entry.entryDigest, commandRef: refs.command,
    commandDigest: command.commandDigest, environmentRef: refs.environment, environmentDigest: environment.environmentDigest, required, maxAttempts: 1 }, 'targetDigest');
  const request = save('request', { schemaVersion: 1, format: 'cliq-verifier-request-v1', runId: 'run', opId, frontierRef: refs.frontier, assemblyRef: ref,
    candidateItemId: 'inert-candidate', verifierPlanRef: refs.plan, verifierIndex: 0, targetRef: refs.target, targetDigest: target.targetDigest }, 'requestDigest');
  const evidence = save('evidence', { schemaVersion: 1, format: 'cliq-policy-channel-evidence-v1', principalId: 'inert-principal', runId: 'run',
    policyRef: refs.policy, policyDigest: policy.policyDigest, frontierRef: refs.frontier, opId, requestRef: refs.request, requestDigest: request.requestDigest,
    targetRef: refs.target, targetDigest: target.targetDigest, actionClass: 'verifier', decisionSource: 'mode_fallthrough', matchedRuleIds: [],
    effectiveDisposition: 'ask', evaluatedAt: at, channel: 'named-action', namedAction: { kind: 'verifier', candidateItemId: 'inert-candidate', verifierPlanRef: refs.plan, verifierId: 'node-tests' },
    identityKey: 'verifier/node-tests' }, 'evidenceDigest');
  const wait = save('wait', { schemaVersion: 1, kind: 'approval', runId: 'run', createdFromRevision: 1, createdAt: at, frontierRef: refs.frontier,
    subject: { kind: 'verifier_launch', candidateItemId: 'inert-candidate', resultSourceRef: ref, verifierPlanRef: refs.plan, verifierIndex: 0,
      verifierId: 'node-tests', verifierSpecDigest: frozen.specDigest, opId, target: refs.target, required,
      policyChannelEvidenceRef: refs.evidence, policyChannelEvidenceDigest: evidence.evidenceDigest } });
  const snapshot = runSnapshot(); snapshot.operation = operation;
  snapshot.run = { ...snapshot.run, specRef: refs.spec!, status: 'waiting', nextStep: 'verify', frontierRef: refs.frontier,
    waitingReason: 'approval', waitingOnRef: refs.wait, revision: 2 };
  const reads: string[] = [];
  const app = { async artifact(digest: string, options: { maxBytes: number; signal?: AbortSignal }) {
    options.signal?.throwIfAborted(); reads.push(digest); const bytes = objects.get(digest);
    if (!bytes || bytes.length > options.maxBytes) throw new TypeError('inert artifact is unavailable or oversized');
    return Buffer.from(bytes);
  }, async readRun(): Promise<never> { throw new Error('verifier display must not replace its captured snapshot'); } };
  return { snapshot, wait, app, objects, values, refs, reads };
}
