// Data refusal only. No synthetic successful retirement/native proof or
// authority is constructed; physical positives remain the Linux campaigns.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting } from '../../../src/kernel/identity.js';
import { planVerifierRequest } from '../../../src/state/verifier-policy.js';
import { assertInstalledVerifierRetirement } from './installed-verifier-evidence.js';

// Pure frozen request data only. Deliberately invalid source bytes stop this
// graph before any launch, owner or retirement evidence can be accepted.
function sourceRefusal() {
  const ref = canonicalSha256;
  const command = { schemaVersion: 1, format: 'cliq-verifier-command-v1', verifierId: 'tests', verifierVersion: '1',
    executable: { kind: 'guest_toolchain', guestToolchainManifestRef: ref('guest'), guestToolchainManifestDigest: ref('guest-digest'), toolId: 'node',
      executionPath: '/usr/bin/node', executableDigest: ref('node'), abiFingerprint: ref('guest-digest') },
    argv: [{ kind: 'non_secret_literal', value: '--test' }], cwd: '.', commandDigest: '' };
  command.commandDigest = digestOmitting(command, 'commandDigest');
  const environment = { schemaVersion: 1, format: 'cliq-verifier-environment-v1', verifierId: 'tests', verifierVersion: '1',
    commandRef: ref(command), commandDigest: command.commandDigest, variables: [], writableEphemeralPaths: [], sourceProjectionRef: ref('projection'),
    sourceAccess: 'read_only', networkAccess: 'denied', sandboxProfile: 'cliq-verifier-readonly-v1', runtimeBundleRef: ref('bundle'),
    runtimeBundleManifestDigest: ref('manifest'), guestToolchainManifestRef: ref('guest'), guestToolchainManifestDigest: ref('guest-digest'), environmentDigest: '' };
  environment.environmentDigest = digestOmitting(environment, 'environmentDigest');
  const entry = { index: 0, id: 'tests', version: '1', gate: 'required', commandRef: ref(command), commandDigest: command.commandDigest,
    environmentRef: ref(environment), environmentDigest: environment.environmentDigest, timeoutMs: 1000, retries: 0, outputLimitBytes: 65_536, entryDigest: '' };
  entry.entryDigest = digestOmitting(entry, 'entryDigest');
  const verifierSpec = { schemaVersion: 1, format: 'cliq-verifier-spec-v1', verifiers: [entry], specDigest: '' };
  verifierSpec.specDigest = digestOmitting(verifierSpec, 'specDigest');
  const plan = { schemaVersion: 1, runId: 'data-run', candidateItemId: 'candidate-1', resultSourceRef: ref({}), verifierSpecRef: ref(verifierSpec),
    verifierSpecDigest: verifierSpec.specDigest, entries: [{ index: 0, verifierId: entry.id, verifierSpecDigest: verifierSpec.specDigest,
      verifierEntryDigest: entry.entryDigest, commandRef: entry.commandRef, commandDigest: entry.commandDigest, environmentRef: entry.environmentRef,
      environmentDigest: entry.environmentDigest, required: true, maxAttempts: 1 }], planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  const requestContext = { runId: plan.runId, frontierRef: ref('frontier'), assemblyRef: ref('assembly'), candidateItemId: plan.candidateItemId,
    resultSourceRef: plan.resultSourceRef, sourceDigest: ref('source-digest'), verifierPlanRef: ref(plan), plan, verifierSpecRef: ref(verifierSpec),
    verifierSpec, verifierIndex: 0, command, environment } as Parameters<typeof planVerifierRequest>[0];
  const { request, target } = planVerifierRequest(requestContext);
  const data = new Map([[ref(request), canonicalJsonBytes(request)], [ref(target), canonicalJsonBytes(target)], [ref({}), canonicalJsonBytes({})]]);
  const input = { run: { id: plan.runId, deadlineAt: '2026-10-18T00:01:00.000Z' }, checkpoints: [],
    prepared: { phase: 'prepared', runId: plan.runId, opKind: 'verifier', opId: request.opId, attempt: 0, seq: 1, requestRef: ref(request), target: ref(target) },
    claim: { phase: 'dispatch_claimed', runId: plan.runId, opKind: 'verifier', opId: request.opId, attempt: 0, seq: 2, sandboxLaunchSpecRef: ref('unread-launch') },
    terminal: { phase: 'completed', runId: plan.runId, opKind: 'verifier', opId: request.opId, attempt: 0, seq: 3 }, requestContext, measurement: {},
    readRetainedArtifact: async (key: string) => { const value = data.get(key); assert(value); return value; },
    readOwnerHistory: async () => { throw new Error('owner reads must remain unreachable'); } };
  return { input };
}

test('retirement refusal reports only its fixed request phase and contains observer exceptions', async () => {
  const phases: string[] = [];
  const input = { run: { id: 'data-run', deadlineAt: '2026-10-18T00:01:00.000Z' },
    checkpoints: [], prepared: { phase: 'prepared' }, claim: { phase: 'prepared' }, terminal: { phase: 'completed' },
    requestContext: {}, measurement: {}, readRetainedArtifact: async () => { throw new Error('unexpected retained read'); },
    readOwnerHistory: async () => { throw new Error('unexpected owner read'); } };
  let touched = 0;
  const privateFailure = Object.defineProperties({}, {
    message: { get() { touched++; throw new Error('private observer message'); } },
    cause: { get() { touched++; throw new Error('private observer cause'); } },
  });
  for (const fail of [false, true]) {
    await assert.rejects(assertInstalledVerifierRetirement(input, phase => {
      phases.push(phase); if (fail) throw privateFailure;
    }), { message: 'installed verifier retirement evidence refused' });
  }
  assert.deepEqual(phases, ['verifier_retirement_request', 'verifier_retirement_request']);
  assert.equal(touched, 0);
});

test('shared verifier evidence refuses an unclaimed/mismatched attempt before reading retained objects', async () => {
  let reads = 0;
  await assert.rejects(assertInstalledVerifierRetirement({ run: { id: 'data-run', deadlineAt: '2026-10-18T00:01:00.000Z' },
    checkpoints: [], prepared: { phase: 'prepared' }, claim: { phase: 'prepared' }, terminal: { phase: 'completed' },
    requestContext: {}, measurement: {}, readRetainedArtifact: async () => { reads++; throw new Error('private-data-must-not-escape'); },
    readOwnerHistory: async () => { reads++; throw new Error('private-owner-must-not-escape'); } }),
  { message: 'installed verifier retirement evidence refused' });
  assert.equal(reads, 0);
});

test('source-stage diagnostics preserve the original fully awaited retained read and fixed refusal', async () => {
  const { input } = sourceRefusal(), phases: string[] = [], reads: string[] = [];
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  let reached!: () => void;
  const entered = new Promise<void>(resolve => { reached = resolve; });
  let settled = false;
  const pending = assertInstalledVerifierRetirement({ ...input, readRetainedArtifact: async key => {
    reads.push(key);
    if (key === input.requestContext.resultSourceRef) { reached(); await gate; }
    return input.readRetainedArtifact(key);
  } }, phase => { phases.push(phase); }).finally(() => { settled = true; });
  const rejected = assert.rejects(pending, { message: 'installed verifier retirement evidence refused' });
  try {
    await Promise.race([entered, rejected]);
    assert.equal(settled, false, 'the real retained reader must remain joined before returning a diagnostic refusal');
    assert.deepEqual(phases, ['verifier_retirement_request', 'verifier_retirement_source']);
  } finally {
    release();
    await Promise.allSettled([pending, rejected]);
  }
  await rejected;
  assert.equal(reads.length, 3);
  assert.equal(settled, true);
});

test('optional observer objects and thrown reader details are never inspected or attached', async () => {
  const { input } = sourceRefusal();
  let touched = 0;
  const bad = () => { touched++; throw new Error('private property'); };
  const data = Object.defineProperties({}, { message: { get: bad }, cause: { get: bad }, observe: { get: bad }, call: { get: bad } });
  const observer = data as unknown as NonNullable<Parameters<typeof assertInstalledVerifierRetirement>[1]>;
  await assert.rejects(assertInstalledVerifierRetirement({ ...input, readRetainedArtifact: async () => { throw data; } }, observer), error => {
    assert(error instanceof Error); assert.equal(error.message, 'installed verifier retirement evidence refused');
    assert.equal(Object.hasOwn(error, 'cause'), false); return true;
  });
  assert.equal(touched, 0);
  const phases: string[] = [];
  await assert.rejects(assertInstalledVerifierRetirement(input, phase => { phases.push(phase); throw data; }),
    { message: 'installed verifier retirement evidence refused' });
  assert.deepEqual(phases, ['verifier_retirement_request', 'verifier_retirement_source']);
  assert.equal(touched, 0);
});
