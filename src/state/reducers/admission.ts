import { canonicalSha256, normalizeCanonicalText } from '../../kernel/canonical.js';
import {
  addCanonicalDuration,
  assertAdmissionKey,
  assertArtifactRef,
  assertRequestId,
  digestOmitting,
  identityHash,
  normalizeAbsolutePath,
  normalizeBoundedText
} from '../../kernel/identity.js';
import type {
  AdmittedContextManifest,
  ContextManifest,
  ControlApplicationResponseV1,
  ControlResultV1,
  DirectUnverifiedConsentV1,
  Run,
  RunEvent,
  RunFrontier,
  RunObjectiveV1,
  RunSnapshotV1,
  RunSpec,
  RepositoryIdentityV1,
  SourceProjectionSpec,
  WorkspaceIdentityV1
} from '../../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from '../artifacts.js';
import { insertArtifactMetadata } from '../artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import { validateControlChannelClosure } from '../control-channel.js';
import {
  decodeAdmittedContext,
  decodeContextManifest,
  decodeFrozenIgnoreRules,
  decodeRunObjective,
  decodeRunSpec,
  decodeRepositoryIdentity,
  decodeSessionProjection,
  decodeSourceManifest,
  decodeSourceProjection,
  decodeUnverifiedConsent,
  decodeVerifierSpec,
  decodeWorkspaceEntries,
  decodeWorkspaceIdentity,
  decodeWorkspaceState
} from '../decoders.js';
import { KernelStorageError } from '../errors.js';
import { validateFrozenIgnoreSourceBytes } from '../frozen-ignore-sources.js';
import { validateGitSourceIndex } from '../git-index.js';
import { assertLiveSourceIncludeEvidence, validateBuiltinSourceIncludes } from '../source-includes.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import {
  DEFAULT_RUN_BUDGETS,
  insertControlRequest,
  insertRunEvent,
  mergeBudgets,
  readAdmissionReplay,
  readControlRequest,
  readRun,
  readSession,
  readSessionPrincipalId,
  ZERO_BUDGET
} from '../rows.js';
import type { SqliteDriver } from '../sqlite-driver.js';
import { assertCurrentLiveWorkspaceIdentity, recaptureLiveWorkspaceIdentity } from '../workspace-identity.js';
import { validateWorkspaceEntryBlobs } from '../workspace-entry-blobs.js';
import { assertLiveFrozenIgnoreSources } from '../workspace-source-ignore.js';
import { assertLiveSourceGitIndex } from '../workspace-source-index.js';

export type AdmitRunInput = {
  principalId: string;
  requestId: string;
  admissionKey: string;
  channelIdentityRef: string;
  channelIdentityDigest: string;
  sessionId: string;
  expectedContextRevision: number;
  workspacePath: string;
  objective: string;
  assemblyRef: string;
  policyRef: string;
  sandboxProfileRef: string;
  verifierSpecRef: string;
  credentialGrantRefs?: string[];
  budgets?: Partial<typeof DEFAULT_RUN_BUDGETS>;
  allowUnverified: boolean;
  /** Normalized caller intent. The refs below are Supervisor-resolved output
   * and must not feed the include authorization's admission-intent digest. */
  sourceIncludes?: Array<{ path: string; scope: 'entry' | 'subtree' }>;
  sourceExcludes?: Array<{ path: string; scope: 'entry' | 'subtree' }>;
  sourceProjectionRef: string;
  frozenIgnoreRulesRef: string;
  baseWorkspaceManifestRef: string;
};

type RunSubmitResponse = {
  protocolVersion: 1;
  ok: true;
  result: Extract<ControlResultV1, { method: 'run.submit' }>;
};

type SourceSelector = { path: string; scope: 'entry' | 'subtree' };

function normalizeRequestedSelectors(
  value: readonly SourceSelector[] | undefined,
  label: string
): SourceSelector[] {
  if (value !== undefined && !Array.isArray(value)) {
    throw new KernelStorageError('INVALID_REQUEST', `${label} must be an array`);
  }
  const selectors: readonly SourceSelector[] = value ?? [];
  if (selectors.length > 128) {
    throw new KernelStorageError('INVALID_REQUEST', `${label} exceeds the 128-selector bound`);
  }
  const seen = new Set<string>();
  return selectors.map((selector) => {
    if (selector === null || typeof selector !== 'object' || Array.isArray(selector) ||
        Object.keys(selector).length !== 2 || !Object.hasOwn(selector, 'path') ||
        !Object.hasOwn(selector, 'scope') || typeof selector.path !== 'string' ||
        (selector.scope !== 'entry' && selector.scope !== 'subtree')) {
      throw new KernelStorageError('INVALID_REQUEST', `${label} has an invalid selector`);
    }
    let canonical: string;
    try { canonical = normalizeCanonicalText(selector.path); }
    catch { throw new KernelStorageError('INVALID_REQUEST', `${label} has invalid Unicode`); }
    const parts = selector.path.split('/');
    if (canonical !== selector.path || selector.path.includes('\\') ||
        Buffer.byteLength(selector.path, 'utf8') > 4096 ||
        parts.some((part) => part === '' || part === '.' || part === '..' ||
          part.toLowerCase() === '.git' || Buffer.byteLength(part, 'utf8') > 255)) {
      throw new KernelStorageError('INVALID_REQUEST', `${label} is not canonical and in-root`);
    }
    const key = `${selector.path}\0${selector.scope}`;
    if (seen.has(key)) {
      throw new KernelStorageError('INVALID_REQUEST', `${label} has a duplicate selector`);
    }
    seen.add(key);
    return { path: selector.path, scope: selector.scope };
  });
}

function assertResolvedSelectorsMatchIntent(
  resolved: SourceProjectionSpec,
  includes: readonly SourceSelector[],
  excludes: readonly SourceSelector[]
): void {
  const actualIncludes = resolved.explicitIncludes.map(({ path, scope }) => ({ path, scope }));
  if (canonicalSha256(actualIncludes) !== canonicalSha256(includes) ||
      canonicalSha256(resolved.explicitExcludes) !== canonicalSha256(excludes)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      'resolved source selectors differ from the normalized Run request');
  }
}

export type AdmitRunResult = {
  replayed: boolean;
  run: Run;
  response: RunSubmitResponse;
};

function admitIntent(
  input: AdmitRunInput,
  workspacePath: string,
  objective: string,
  budgets: typeof DEFAULT_RUN_BUDGETS,
  sourceIncludes: readonly SourceSelector[],
  sourceExcludes: readonly SourceSelector[]
): string {
  return canonicalSha256({
    principalId: input.principalId,
    method: 'run.submit',
    request: {
      method: 'run.submit',
      sessionId: input.sessionId,
      expectedContextRevision: input.expectedContextRevision,
      workspacePath,
      objective,
      assemblyRef: input.assemblyRef,
      policyRef: input.policyRef,
      sandboxProfileRef: input.sandboxProfileRef,
      verifierSpecRef: input.verifierSpecRef,
      credentialGrantRefs: input.credentialGrantRefs ?? [],
      budgets,
      allowUnverified: input.allowUnverified,
      sourceIncludes,
      sourceExcludes
    }
  });
}

function admitRequestDigest(
  input: AdmitRunInput,
  workspacePath: string,
  objective: string,
  budgets: typeof DEFAULT_RUN_BUDGETS,
  sourceIncludes: readonly SourceSelector[],
  sourceExcludes: readonly SourceSelector[]
): string {
  return canonicalSha256({
    protocolVersion: 1,
    requestId: input.requestId,
    method: 'run.submit',
    admissionKey: input.admissionKey,
    sessionId: input.sessionId,
    expectedContextRevision: input.expectedContextRevision,
    workspacePath,
    objective,
    assemblyRef: input.assemblyRef,
    policyRef: input.policyRef,
    sandboxProfileRef: input.sandboxProfileRef,
    verifierSpecRef: input.verifierSpecRef,
    credentialGrantRefs: input.credentialGrantRefs ?? [],
    budgets,
    allowUnverified: input.allowUnverified,
    sourceIncludes,
    sourceExcludes
  });
}

async function readPublishedResponse(
  artifacts: ArtifactCatalog,
  responseRef: string
): Promise<RunSubmitResponse> {
  const response = await artifacts.readCanonical<ControlApplicationResponseV1>(responseRef);
  if (response.ok && response.result.method === 'run.submit') {
    return { protocolVersion: 1, ok: true, result: response.result };
  }
  throw new KernelStorageError('RECOVERY_REQUIRED', 'run.submit replay did not return a success snapshot');
}

async function replayAdmitRun(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  input: AdmitRunInput,
  admissionIntentDigest: string,
  requestDigest: string
): Promise<AdmitRunResult | undefined> {
  const existingControl = readControlRequest(driver, input.principalId, 'run.submit', input.requestId);
  if (existingControl !== undefined) {
    if (existingControl.requestDigest !== requestDigest) {
      throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.submit requestId was reused with different bytes');
    }
    const response = await readPublishedResponse(artifacts, existingControl.responseRef);
    return { replayed: true, run: response.result.snapshot.run, response };
  }

  const existingAdmission = readAdmissionReplay(driver, 'runs', input.principalId, 'run.submit', input.admissionKey);
  if (existingAdmission !== undefined) {
    if (existingAdmission.admissionIntentDigest !== admissionIntentDigest) {
      throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'run.submit admissionKey was reused with a different intent');
    }
    const run = readRun(driver, existingAdmission.id);
    const response: RunSubmitResponse = {
      protocolVersion: 1,
      ok: true,
      result: {
        method: 'run.submit',
        snapshot: { schemaVersion: 1, operation: 'agent', run, latestRunItemSeq: 0 }
      }
    };
    return { replayed: true, run, response };
  }
  return undefined;
}

export async function admitRun(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: AdmitRunInput
): Promise<AdmitRunResult> {
  assertRequestId(input.requestId);
  assertAdmissionKey(input.admissionKey);
  for (const ref of [
    input.channelIdentityRef,
    input.assemblyRef,
    input.policyRef,
    input.sandboxProfileRef,
    input.verifierSpecRef,
    input.sourceProjectionRef,
    input.frozenIgnoreRulesRef,
    input.baseWorkspaceManifestRef,
    ...(input.credentialGrantRefs ?? [])
  ]) {
    assertArtifactRef(ref);
  }

  const workspacePath = normalizeAbsolutePath(input.workspacePath);
  const objectiveText = normalizeBoundedText(input.objective, 1, 262_144);
  const budgets = mergeBudgets(input.budgets);
  const sourceIncludes = normalizeRequestedSelectors(input.sourceIncludes, 'sourceIncludes');
  const sourceExcludes = normalizeRequestedSelectors(input.sourceExcludes, 'sourceExcludes');
  const admissionIntentDigest = admitIntent(input, workspacePath, objectiveText, budgets,
    sourceIncludes, sourceExcludes);
  const requestDigest = admitRequestDigest(input, workspacePath, objectiveText, budgets,
    sourceIncludes, sourceExcludes);
  const runId = identityHash('cliq-run-id-v1', input.principalId, 'run.submit', input.admissionKey);

  // A retained control response is never a substitute for current caller
  // authentication. Replay preserves the first committed channel's provenance.
  const channelClosure = await validateControlChannelClosure(artifacts, owner, input);
  const channel = channelClosure.channel;
  const replayed = await replayAdmitRun(driver, artifacts, input, admissionIntentDigest, requestDigest);
  if (replayed !== undefined) return replayed;

  const session = readSession(driver, input.sessionId);
  if (readSessionPrincipalId(driver, input.sessionId) !== input.principalId) {
    throw new KernelStorageError('INVALID_REQUEST', 'session does not belong to the calling principal');
  }
  if (session.contextRevision !== input.expectedContextRevision) {
    throw new KernelStorageError('INVALID_REQUEST', 'session context revision does not match the admitted cursor');
  }
  const workspaceIdentity = decodeWorkspaceIdentity(
    await artifacts.readCanonical(session.workspaceIdentityRef)
  ) as Extract<WorkspaceIdentityV1, { kind: 'live' }>;
  if (workspaceIdentity.kind !== 'live') {
    throw new KernelStorageError('INVALID_REQUEST', 'only live Sessions may admit a Run');
  }
  if (workspaceIdentity.ownerPrincipalId !== input.principalId) {
    throw new KernelStorageError('INVALID_REQUEST', 'workspace identity is not owned by the calling principal');
  }
  let repositoryIdentity: RepositoryIdentityV1 | undefined;
  if (workspaceIdentity.repositoryIdentityRef !== undefined) {
    repositoryIdentity = decodeRepositoryIdentity(
      await artifacts.readCanonical(workspaceIdentity.repositoryIdentityRef)
    );
    if (repositoryIdentity.repositoryIdentityDigest !== workspaceIdentity.repositoryIdentityDigest ||
        repositoryIdentity.platform !== workspaceIdentity.platform ||
        repositoryIdentity.gitDirectoryIdentity.ownerUid !== workspaceIdentity.rootIdentity.ownerUid) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace repository artifact differs from the Session identity');
    }
  }
  await recaptureLiveWorkspaceIdentity(workspaceIdentity, workspacePath, owner.filesystem);

  const projection = decodeSessionProjection(await artifacts.readCanonical(session.contextProjectionRef));
  if (
    projection.sessionId !== session.id ||
    projection.contextRevision !== session.contextRevision ||
    projection.throughItemSeq !== session.latestItemSeq
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'session projection does not match the Session row');
  }

  const frozenIgnore = decodeFrozenIgnoreRules(await artifacts.readCanonical(input.frozenIgnoreRulesRef));
  if (frozenIgnore.repositoryIdentityDigest !== workspaceIdentity.repositoryIdentityDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore rules are not bound to the live repository identity');
  }
  await validateFrozenIgnoreSourceBytes(artifacts, frozenIgnore);
  const sourceProjection = decodeSourceProjection(await artifacts.readCanonical(input.sourceProjectionRef));
  assertResolvedSelectorsMatchIntent(sourceProjection, sourceIncludes, sourceExcludes);
  if (
    sourceProjection.frozenIgnoreRulesRef !== input.frozenIgnoreRulesRef ||
    sourceProjection.frozenIgnoreRulesDigest !== frozenIgnore.rulesDigest
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source projection is not bound to the frozen ignore rules');
  }
  const sourceManifest = decodeSourceManifest(await artifacts.readCanonical(input.baseWorkspaceManifestRef));
  if (
    sourceManifest.role !== 'base' ||
    sourceManifest.sourceProjectionRef !== input.sourceProjectionRef ||
    sourceManifest.sourceProjectionDigest !== sourceProjection.projectionDigest ||
    sourceManifest.frozenIgnoreRulesRef !== input.frozenIgnoreRulesRef ||
    sourceManifest.frozenIgnoreRulesDigest !== frozenIgnore.rulesDigest ||
    sourceManifest.workspaceIdentityDigest !== workspaceIdentity.identityDigest
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'base SourceManifest is not bound to the admitted Session workspace');
  }
  const sourceEntries = decodeWorkspaceEntries(await artifacts.readCanonical(sourceManifest.entriesRef));
  if (sourceManifest.treeDigest !== sourceEntries.treeDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'base SourceManifest entries do not match its tree digest');
  }
  await validateWorkspaceEntryBlobs(artifacts, sourceEntries);
  if ((sourceManifest.git === undefined) !== (workspaceIdentity.repositoryIdentityDigest === undefined)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'SourceManifest git identity does not match the live workspace');
  }
  if (
    sourceManifest.git !== undefined &&
    sourceManifest.git.repositoryIdentityDigest !== workspaceIdentity.repositoryIdentityDigest
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'SourceManifest repository digest does not match the live workspace');
  }
  const indexSnapshot = sourceManifest.git && repositoryIdentity
    ? await validateGitSourceIndex(artifacts, sourceManifest.git, repositoryIdentity)
    : undefined;
  if (repositoryIdentity && indexSnapshot) {
    assertLiveSourceGitIndex(owner.filesystem, workspacePath,
      workspaceIdentity.rootIdentity, repositoryIdentity, indexSnapshot);
  }
  assertLiveFrozenIgnoreSources(owner.filesystem, workspacePath,
    workspaceIdentity.rootIdentity, repositoryIdentity, frozenIgnore, sourceEntries);
  const sourceIncludesClosure = await validateBuiltinSourceIncludes(artifacts, {
    principalId: input.principalId, runId, sessionId: session.id,
    workspaceIdentityRef: session.workspaceIdentityRef,
    workspaceIdentityDigest: workspaceIdentity.identityDigest,
    admissionIntentDigest, projection: sourceProjection, entries: sourceEntries,
    frozenIgnoreRulesRef: input.frozenIgnoreRulesRef, frozenIgnoreRules: frozenIgnore,
    ...(sourceManifest.git && indexSnapshot ? {
      git: { indexRef: sourceManifest.git.indexRef, snapshot: indexSnapshot }
    } : {})
  });
  assertLiveSourceIncludeEvidence(owner.filesystem, workspacePath,
    workspaceIdentity.rootIdentity, sourceEntries, sourceIncludesClosure.evidences);

  const verifierSpec = decodeVerifierSpec(await artifacts.readCanonical(input.verifierSpecRef));
  const requiredVerifiers = verifierSpec.verifiers.filter((entry) => entry.gate === 'required');
  if (requiredVerifiers.length > 0 && input.allowUnverified) {
    throw new KernelStorageError('INVALID_REQUEST', 'allowUnverified is forbidden when a required verifier exists');
  }
  if (requiredVerifiers.length === 0 && !input.allowUnverified) {
    throw new KernelStorageError('INVALID_REQUEST', 'an empty required verifier set needs allowUnverified=true');
  }

  await artifacts.readBytes(input.assemblyRef);
  await artifacts.readBytes(input.policyRef);
  await artifacts.readBytes(input.sandboxProfileRef);

  const referencedMetadata = await Promise.all([
    artifacts.describe(input.assemblyRef, 'application/json', 'cliq-run-assembly-v1'),
    artifacts.describe(input.policyRef, 'application/json', 'cliq-run-policy-v1'),
    artifacts.describe(input.sandboxProfileRef, 'application/json', 'cliq-sandbox-profile-v1'),
    artifacts.describe(input.verifierSpecRef, 'application/json', 'cliq-verifier-spec-v1'),
    artifacts.describe(input.sourceProjectionRef, 'application/json', 'cliq-source-projection-v1'),
    artifacts.describe(input.frozenIgnoreRulesRef, 'application/json', 'cliq-frozen-ignore-rules-v1'),
    artifacts.describe(input.baseWorkspaceManifestRef, 'application/json', 'cliq-source-manifest-v1'),
    artifacts.describe(sourceManifest.entriesRef, 'application/json', 'cliq-workspace-entries-v1'),
    ...(sourceManifest.git && indexSnapshot ? [
      artifacts.describe(sourceManifest.git.indexRef, 'application/json', 'cliq-git-index-snapshot-v1'),
      artifacts.describe(indexSnapshot.canonicalIndexBytesRef, 'application/octet-stream', 'cliq-git-index-canonical-v2')
    ] : []),
    ...(input.credentialGrantRefs ?? []).map((ref) =>
      artifacts.describe(ref, 'application/json', 'cliq-endpoint-credential-grant-binding-v1')
    )
  ]);

  const now = sampleCanonicalNow();
  const checkpointId = identityHash('cliq-checkpoint-id-v1', runId, 'initial', 0);
  const turnId = identityHash('cliq-turn-id-v1', runId, 'initial');

  const objective: RunObjectiveV1 = {
    schemaVersion: 1,
    format: 'cliq-run-objective-v1',
    utf8: objectiveText,
    byteCount: Buffer.byteLength(objectiveText, 'utf8'),
    objectiveDigest: ''
  };
  objective.objectiveDigest = digestOmitting(objective, 'objectiveDigest');
  const published: PublishedArtifact[] = [...channelClosure.metadata, ...referencedMetadata,
    ...sourceIncludesClosure.metadata];
  const objectiveArtifact = await artifacts.publishCanonical(objective, 'cliq-run-objective-v1');
  published.push(objectiveArtifact);
  decodeRunObjective(objective);

  const admittedContext: AdmittedContextManifest = {
    schemaVersion: 1,
    format: 'cliq-admitted-context-v1',
    sessionId: session.id,
    sessionContextRevision: session.contextRevision,
    throughSessionItemSeq: session.latestItemSeq,
    sessionProjectionRef: session.contextProjectionRef,
    parentContextRefs: [],
    additionalArtifactRefs: [],
    contextDigest: ''
  };
  admittedContext.contextDigest = digestOmitting(admittedContext, 'contextDigest');
  const admittedContextArtifact = await artifacts.publishCanonical(admittedContext, 'cliq-admitted-context-v1');
  published.push(admittedContextArtifact);
  decodeAdmittedContext(admittedContext);

  const workspaceState = {
    schemaVersion: 1 as const,
    format: 'cliq-workspace-state-v1' as const,
    runId,
    baseWorkspaceManifestRef: input.baseWorkspaceManifestRef,
    entriesRef: sourceManifest.entriesRef,
    invalidatedEphemeralPaths: [] as string[],
    sourceProjectionDigest: sourceProjection.projectionDigest,
    stateDigest: ''
  };
  workspaceState.stateDigest = digestOmitting(workspaceState, 'stateDigest');
  const workspaceStateArtifact = await artifacts.publishCanonical(workspaceState, 'cliq-workspace-state-v1');
  published.push(workspaceStateArtifact);
  decodeWorkspaceState(workspaceState);

  const runSpecCore: RunSpec = {
    schemaVersion: 1,
    operation: 'agent',
    objectiveRef: objectiveArtifact.ref,
    admittedContextRef: admittedContextArtifact.ref,
    baseWorkspaceManifestRef: input.baseWorkspaceManifestRef,
    sourceProjectionRef: input.sourceProjectionRef,
    assemblyRef: input.assemblyRef,
    policyRef: input.policyRef,
    sandboxProfileRef: input.sandboxProfileRef,
    verifierSpecRef: input.verifierSpecRef,
    credentialGrantRefs: input.credentialGrantRefs ?? [],
    budgets
  };
  const runSpecCoreDigest = canonicalSha256(runSpecCore);
  let runSpec = runSpecCore;
  if (requiredVerifiers.length === 0) {
    const consent: DirectUnverifiedConsentV1 = {
      schemaVersion: 1,
      kind: 'direct_unverified_consent',
      principalId: input.principalId,
      client: channel.client,
      channelIdentityRef: input.channelIdentityRef,
      channelIdentityDigest: input.channelIdentityDigest,
      admissionIntentDigest,
      runSpecCoreDigest,
      allowUnverified: true,
      createdAt: now,
      consentDigest: ''
    };
    consent.consentDigest = digestOmitting(consent, 'consentDigest');
    const consentArtifact = await artifacts.publishCanonical(consent, 'cliq-direct-unverified-consent-v1');
    published.push(consentArtifact);
    decodeUnverifiedConsent(consent);
    runSpec = { ...runSpecCore, unverifiedConsentRef: consentArtifact.ref };
  }
  const specArtifact = await artifacts.publishCanonical(runSpec, 'cliq-run-spec-v1');
  published.push(specArtifact);
  decodeRunSpec(runSpec);

  const contextManifest: ContextManifest = {
    schemaVersion: 1,
    format: 'cliq-context-manifest-v1',
    runId,
    throughItemSeq: 0,
    admittedContextRef: admittedContextArtifact.ref,
    segments: [],
    assemblyRef: input.assemblyRef,
    projectionDigest: ''
  };
  contextManifest.projectionDigest = digestOmitting(contextManifest, 'projectionDigest');
  const contextManifestArtifact = await artifacts.publishCanonical(contextManifest, 'cliq-context-manifest-v1');
  published.push(contextManifestArtifact);
  decodeContextManifest(contextManifest);

  const frontier: Extract<RunFrontier, { kind: 'agent' }> = {
    schemaVersion: 1,
    kind: 'agent',
    phase: 'model_turn',
    turnId,
    contextItemSeq: 0,
    cause: 'initial'
  };
  const frontierArtifact = await artifacts.publishCanonical(frontier, 'cliq-run-frontier-v1');
  published.push(frontierArtifact);

  const deadlineAt = addCanonicalDuration(now, budgets.wallTimeMs);
  const run: Run = {
    id: runId,
    sessionId: session.id,
    specRef: specArtifact.ref,
    status: 'queued',
    nextStep: 'agent',
    frontierRef: frontierArtifact.ref,
    revision: 1,
    leaseEpoch: 0,
    latestCheckpointId: checkpointId,
    budgetReserved: ZERO_BUDGET,
    budgetConsumed: ZERO_BUDGET,
    repairCount: 0,
    cancelRequested: false,
    createdAt: now,
    deadlineAt,
    updatedAt: now
  };
  const snapshot: RunSnapshotV1 = {
    schemaVersion: 1,
    operation: 'agent',
    run,
    latestRunItemSeq: 0
  };
  const event: Extract<RunEvent, { kind: 'state_changed' }> = {
    schemaVersion: 1,
    kind: 'state_changed',
    runId,
    eventSeq: 1,
    runRevision: 1,
    status: 'queued',
    nextStep: 'agent',
    frontierRef: frontierArtifact.ref,
    latestRunItemSeq: 0,
    occurredAt: now
  };
  const response: RunSubmitResponse = {
    protocolVersion: 1,
    ok: true,
    result: { method: 'run.submit', snapshot }
  };
  const responseArtifact = await artifacts.publishCanonical(response, 'cliq-control-response-v1');
  published.push(responseArtifact);

  const admittedRequestDigest = canonicalSha256({
    admissionIntentDigest,
    objectiveRef: objectiveArtifact.ref,
    admittedContextRef: admittedContextArtifact.ref,
    runSpecRef: specArtifact.ref,
    workspaceIdentityDigest: workspaceIdentity.identityDigest,
    repositoryIdentityDigest: workspaceIdentity.repositoryIdentityDigest ?? null,
    sourceProjectionRef: input.sourceProjectionRef,
    frozenIgnoreRulesRef: input.frozenIgnoreRulesRef,
    baseWorkspaceManifestRef: input.baseWorkspaceManifestRef,
    workspaceStateRef: workspaceStateArtifact.ref,
    assemblyRef: input.assemblyRef,
    policyRef: input.policyRef,
    sandboxProfileRef: input.sandboxProfileRef,
    verifierSpecRef: input.verifierSpecRef,
    unverifiedConsentRef: runSpec.unverifiedConsentRef ?? null,
    credentialGrantRefs: runSpec.credentialGrantRefs
  });

  let committed = false;
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    const control = readControlRequest(connection, input.principalId, 'run.submit', input.requestId);
    if (control !== undefined) {
      if (control.requestDigest !== requestDigest) {
        throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.submit requestId was reused with different bytes');
      }
      return;
    }
    const admission = readAdmissionReplay(connection, 'runs', input.principalId, 'run.submit', input.admissionKey);
    if (admission !== undefined) {
      if (admission.admissionIntentDigest !== admissionIntentDigest) {
        throw new KernelStorageError(
          'ADMISSION_KEY_CONFLICT',
          'run.submit admissionKey was reused with a different intent'
        );
      }
      return;
    }

    const lockedSession = readSession(connection, input.sessionId);
    if (readSessionPrincipalId(connection, input.sessionId) !== input.principalId) {
      throw new KernelStorageError('INVALID_REQUEST', 'session does not belong to the calling principal');
    }
    if (lockedSession.contextRevision !== input.expectedContextRevision) {
      throw new KernelStorageError('INVALID_REQUEST', 'session context revision changed before admission committed');
    }

    assertActiveStateOwner(connection, owner);
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch);
    if (fenceOutcome !== 'healthy') return;
    assertCurrentLiveWorkspaceIdentity(workspaceIdentity, workspacePath, owner.filesystem);
    if (repositoryIdentity && indexSnapshot) {
      assertLiveSourceGitIndex(owner.filesystem, workspacePath,
        workspaceIdentity.rootIdentity, repositoryIdentity, indexSnapshot);
    }
    assertLiveFrozenIgnoreSources(owner.filesystem, workspacePath,
      workspaceIdentity.rootIdentity, repositoryIdentity, frozenIgnore, sourceEntries);
    assertLiveSourceIncludeEvidence(owner.filesystem, workspacePath,
      workspaceIdentity.rootIdentity, sourceEntries, sourceIncludesClosure.evidences);
    for (const artifact of published) insertArtifactMetadata(connection, artifact, now);

    connection
      .prepare(
        `INSERT INTO checkpoints (
           id, schema_version, run_id, based_on_run_revision, run_item_seq,
           context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason
         ) VALUES (?, 1, ?, 0, 0, ?, 0, ?, ?, 'initial')`
      )
      .run(checkpointId, runId, contextManifestArtifact.ref, workspaceStateArtifact.ref, now);
    connection
      .prepare(
        `INSERT INTO runs (
           id, session_id, parent_run_id, spec_ref, status, next_step, frontier_ref,
           waiting_reason, waiting_on_ref, revision, lease_epoch, active_worker_launch_id,
           latest_checkpoint_id, budget_reserved_json, budget_consumed_json, repair_count,
           result_ref, terminal_reason, terminal_detail_ref, stop_intent_ref, cancel_requested,
           created_at, deadline_at, updated_at, principal_id, admission_method, admission_key,
           admission_intent_digest, admitted_request_digest
         ) VALUES (?, ?, NULL, ?, 'queued', 'agent', ?, NULL, NULL, 1, 0, NULL, ?, ?, ?, 0,
                   NULL, NULL, NULL, NULL, 0, ?, ?, ?, ?, 'run.submit', ?, ?, ?)`
      )
      .run(
        runId,
        session.id,
        specArtifact.ref,
        frontierArtifact.ref,
        checkpointId,
        JSON.stringify(ZERO_BUDGET),
        JSON.stringify(ZERO_BUDGET),
        now,
        deadlineAt,
        now,
        input.principalId,
        input.admissionKey,
        admissionIntentDigest,
        admittedRequestDigest
      );
    insertRunEvent(connection, event);
    insertControlRequest(connection, {
      principalId: input.principalId,
      method: 'run.submit',
      requestId: input.requestId,
      channelIdentityRef: input.channelIdentityRef,
      channelIdentityDigest: input.channelIdentityDigest,
      requestDigest,
      responseRef: responseArtifact.ref,
      committedAt: now
    });
    committed = true;
  });

  if (fenceOutcome === 'clock_regressed') {
    throw new KernelStorageError('INVALID_REQUEST', 'canonical clock has regressed; admission is paused');
  }
  if (fenceOutcome === 'still_regressed') {
    throw new KernelStorageError('INVALID_REQUEST', 'canonical clock is still in clock_regressed');
  }
  if (committed) return { replayed: false, run, response };
  const raced = await replayAdmitRun(driver, artifacts, input, admissionIntentDigest, requestDigest);
  if (raced !== undefined) return raced;
  throw new KernelStorageError('RECOVERY_REQUIRED', 'run.submit transaction committed no Run');
}
