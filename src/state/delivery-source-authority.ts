import { canonicalSha256 } from '../kernel/canonical.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import { assertArtifactRef } from '../kernel/identity.js';
import type { RunResult, VerificationClosureV1 } from '../kernel/result.js';
import type { Run, RunAssemblyV1, RunSpec, Session, VerifierSpec } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { decodeRunResult, decodeVerificationClosure } from './result-artifacts.js';
import { readRun, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { decodeVerifierSpec } from './verifier-artifacts.js';

declare const verifiedSource: unique symbol;
/** A retained-graph selection, not execution, permission or native evidence.
 * Only the complete recovery reader below can produce its process-local brand. */
export type VerifiedDeliverySource = Readonly<{
  readonly [verifiedSource]: true;
  run: Run;
  spec: RunSpec;
  result: RunResult;
  closure: VerificationClosureV1;
  session: Session;
  assembly: RunAssemblyV1;
  verifierSpec: VerifierSpec;
}>;
const sources = new WeakMap<object, { driver: SqliteDriver; owner: StateOwnerContext; epoch: number }>();
type SourceInput = { principalId: string; sourceRunId: string; expectedRunResultRef: string; signal?: AbortSignal };
type RetainedDeliverySource = Omit<VerifiedDeliverySource, typeof verifiedSource>;
const sourceWalk = new AsyncLocalStorage<ReadonlySet<string>>();

export function assertVerifiedDeliverySource(driver: SqliteDriver, owner: StateOwnerContext,
  value: unknown): VerifiedDeliverySource {
  const held = value !== null && typeof value === 'object' ? sources.get(value) : undefined;
  if (!held || held.driver !== driver || held.owner !== owner || held.epoch !== owner.ownerEpoch)
    throw new TypeError('a genuine same-owner verified delivery source is required');
  assertActiveStateOwner(driver, owner);
  return value as VerifiedDeliverySource;
}

/** Validate the original source graph, including every required Journal-backed
 * receipt and retained resource retirement. A public descriptor or a digest-
 * valid closure by itself is not source authority. No model credential is
 * refreshed and no original receipt is copied or relabeled. */
async function readSourceGraph(
  driver: SqliteDriver, artifacts: ArtifactCatalog, input: SourceInput
): Promise<RetainedDeliverySource> {
  // Startup/historical inspection needs the same original graph validation,
  // but cannot claim a current StateOwner or mint the live selection brand.
  input.signal?.throwIfAborted();
  // The complete historical walk may rehash large signed images and source
  // blobs. Cancellation belongs to those original descriptor reads as well,
  // not just checks surrounding an uncancellable graph walk.
  if (input.signal) artifacts = artifacts.withReadSignal(input.signal);
  assertArtifactRef(input.expectedRunResultRef);
  const run = readRun(driver, input.sourceRunId);
  const session = readSession(driver, run.sessionId);
  if (readSessionPrincipalId(driver, session.id) !== input.principalId || run.status !== 'succeeded' ||
      run.terminalReason !== 'verified' || run.resultRef !== input.expectedRunResultRef)
    throw new KernelStorageError('INVALID_REQUEST', 'delivery requires its principal’s exact verified immutable source result');
  const cut = await readRecoveryClosure(driver, artifacts, run.id);
  input.signal?.throwIfAborted();
  const result = decodeRunResult(await readCanonicalArtifact(artifacts, input.expectedRunResultRef));
  input.signal?.throwIfAborted();
  const closure = decodeVerificationClosure(await readCanonicalArtifact(artifacts, result.verificationClosureRef));
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, cut.runSpec.assemblyRef));
  input.signal?.throwIfAborted();
  const verifierSpec = decodeVerifierSpec(await readCanonicalArtifact(artifacts, cut.runSpec.verifierSpecRef));
  input.signal?.throwIfAborted();
  const currentSession = readSession(driver, session.id);
  if (canonicalSha256(cut.run) !== canonicalSha256(run) || canonicalSha256(readRun(driver, run.id)) !== canonicalSha256(run) ||
      currentSession.workspaceIdentityRef !== session.workspaceIdentityRef ||
      readSessionPrincipalId(driver, session.id) !== input.principalId || result.runId !== run.id || closure.runId !== run.id ||
      closure.resultSourceRef !== result.resultSourceRef ||
      closure.verification.kind === 'local' && closure.verification.outcome !== 'verified')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'delivery source changed or lacks its exact verified recovery closure');
  return immutableSnapshot({ run, spec: cut.runSpec, result, closure, session: currentSession, assembly, verifierSpec });
}

export const readRetainedVerifiedDeliverySource = stateOperation('RECOVERY_REQUIRED', async function readRetainedVerifiedDeliverySource(
  driver: SqliteDriver, artifacts: ArtifactCatalog, input: SourceInput
): Promise<RetainedDeliverySource> {
  input = { principalId: input.principalId, sourceRunId: input.sourceRunId,
    expectedRunResultRef: input.expectedRunResultRef, ...(input.signal ? { signal: input.signal } : {}) };
  const parents = sourceWalk.getStore() ?? new Set<string>();
  if (parents.has(input.sourceRunId)) throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery source history contains a cycle');
  const next = new Set(parents); next.add(input.sourceRunId);
  return sourceWalk.run(next, () => readSourceGraph(driver, artifacts, input));
});

export const readVerifiedDeliverySource = stateOperation('RECOVERY_REQUIRED', async function readVerifiedDeliverySource(
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: SourceInput
): Promise<VerifiedDeliverySource> {
  input.signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  const value = await readRetainedVerifiedDeliverySource(driver, artifacts, input) as VerifiedDeliverySource;
  input.signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  sources.set(value, { driver, owner, epoch: owner.ownerEpoch });
  return value;
});
