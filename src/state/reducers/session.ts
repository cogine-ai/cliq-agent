import path from 'node:path';
import { decodeSessionCreatePublicRequest } from '../../kernel/control-wire.js';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { immutableSnapshot } from '../../model/immutable.js';
import { exactKeys } from '../../policy/runtime-authority.js';
import {
  assertAdmissionKey,
  assertArtifactRef,
  assertRequestId,
  digestOmitting,
  identityHash,
  normalizeAbsolutePath,
  normalizeBoundedText
} from '../../kernel/identity.js';
import type {
  ControlApplicationResponseV1,
  ControlResultV1,
  Session,
  SessionContextProjection,
  WorkspaceIdentityV1
} from '../../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from '../artifacts.js';
import { insertArtifactMetadata } from '../artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import { assertCurrentControlFrame, validateControlChannelClosure, type AuthenticatedControlIdentity } from '../control-channel.js';
import { readCanonicalArtifact } from '../agent-context.js';
import { decodeSessionProjection, decodeWorkspaceIdentity } from '../decoders.js';
import { KernelStorageError, ResourceRetirementError } from '../errors.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import {
  insertControlRequest,
  readAdmissionReplay,
  readControlRequest
} from '../rows.js';
import type { SqliteDriver } from '../sqlite-driver.js';
import { captureLiveWorkspaceIdentity, captureInstalledWorkspaceIdentity } from '../workspace-identity.js';
import { loadInstalledCredentialPlatform, withHeldInstalledRuntime, type HeldInstalledRuntime } from '../installed-runtime.js';
import { assertWorkspaceSourceTrust, holdWorkspaceSourceTrust, type HeldWorkspaceSourceTrust } from '../source-trust.js';

export type CreateSessionInput = {
  principalId: string;
  requestId: string;
  admissionKey: string;
  workspacePath: string;
  name?: string;
  channelIdentityRef: string;
  channelIdentityDigest: string;
};

type SessionCreateResponse = {
  protocolVersion: 1;
  ok: true;
  result: Extract<ControlResultV1, { method: 'session.create' }>;
};

export type CreateSessionResult = {
  replayed: boolean;
  session: Session;
  response: SessionCreateResponse;
};

type SessionCreatePublicCore = {
  protocolVersion: 1;
  method: 'session.create';
  requestId: string;
  admissionKey: string;
  workspacePath: string;
  name?: string;
};
type InstalledSessionRequest = {
  core: Readonly<SessionCreatePublicCore>;
  requestDigest: string;
  identity: AuthenticatedControlIdentity;
  controlledHome: string;
  signal: AbortSignal;
};

function readSessionCreatePublicRequest(request: unknown,
  errorCode: 'INVALID_REQUEST' | 'RECOVERY_REQUIRED' = 'INVALID_REQUEST') {
  try { return decodeSessionCreatePublicRequest(request); }
  catch (cause) { throw new KernelStorageError(errorCode, 'session.create public request is invalid', { cause }); }
}
async function publishSessionCreatePublicCore(artifacts: ArtifactCatalog, installed: InstalledSessionRequest): Promise<PublishedArtifact> {
  const artifact = await artifacts.publishCanonical(installed.core, 'cliq-session-create-request-core-v1');
  if (artifact.ref !== installed.requestDigest)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'session.create original public core digest changed');
  return artifact;
}

function sessionCreateIntent(input: {
  principalId: string;
  workspacePath: string;
  name?: string;
}): string {
  const request: Record<string, unknown> = {
    method: 'session.create',
    workspacePath: input.workspacePath
  };
  if (input.name !== undefined) request.name = input.name;
  return canonicalSha256({
    principalId: input.principalId,
    method: 'session.create',
    request
  });
}

function sessionCreateRequestDigest(input: {
  requestId: string;
  admissionKey: string;
  workspacePath: string;
  name?: string;
}): string {
  const request: Record<string, unknown> = {
    protocolVersion: 1,
    requestId: input.requestId,
    method: 'session.create',
    admissionKey: input.admissionKey,
    workspacePath: input.workspacePath
  };
  if (input.name !== undefined) request.name = input.name;
  return canonicalSha256(request);
}

async function readPublishedResponse(
  artifacts: ArtifactCatalog,
  responseRef: string
): Promise<SessionCreateResponse> {
  const response = await artifacts.readCanonical<ControlApplicationResponseV1>(responseRef);
  if (response.ok && response.result.method === 'session.create') {
    return { protocolVersion: 1, ok: true, result: response.result };
  }
  throw new KernelStorageError('RECOVERY_REQUIRED', 'session.create replay did not return a success snapshot');
}

async function replayCreateSession(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: CreateSessionInput,
  admissionIntentDigest: string,
  requestDigest: string,
  installed?: InstalledSessionRequest
): Promise<CreateSessionResult | undefined> {
  const existingControl = readControlRequest(driver, input.principalId, 'session.create', input.requestId);
  if (existingControl !== undefined) {
    if (existingControl.requestDigest !== requestDigest) {
      throw new KernelStorageError('REQUEST_ID_CONFLICT', 'session.create requestId was reused with different bytes');
    }
    const response = await readPublishedResponse(artifacts, existingControl.responseRef);
    return { replayed: true, session: response.result.snapshot.session, response };
  }

  const existingAdmission = readAdmissionReplay(
    driver,
    'sessions',
    input.principalId,
    'session.create',
    input.admissionKey
  );
  if (existingAdmission !== undefined) {
    if (existingAdmission.admissionIntentDigest !== admissionIntentDigest) {
      throw new KernelStorageError(
        'ADMISSION_KEY_CONFLICT',
        'session.create admissionKey was reused with a different intent'
      );
    }
    if (existingAdmission.admissionRequestId === null) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'session admission has no original control request');
    }
    const originalRequestId = existingAdmission.admissionRequestId;
    const original = readControlRequest(driver, input.principalId, 'session.create', originalRequestId);
    if (!original) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'session admission original control request does not match');
    }
    if (installed) {
      const originalCore = await readCanonicalArtifact<object>(artifacts, original.requestDigest);
      const retained = readSessionCreatePublicRequest({ ...originalCore, requestDigest: original.requestDigest }, 'RECOVERY_REQUIRED');
      if (retained.core.requestId !== originalRequestId || retained.core.admissionKey !== input.admissionKey ||
          sessionCreateIntent({ principalId: input.principalId, workspacePath: normalizeAbsolutePath(retained.core.workspacePath),
            ...(retained.core.name === undefined ? {} : { name: normalizeBoundedText(retained.core.name, 1, 256) }) }) !== admissionIntentDigest)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'session admission original public request does not bind its intent');
    } else if (original.requestDigest !== sessionCreateRequestDigest({ ...input, requestId: originalRequestId })) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'session admission original control request does not match');
    }
    const response = await readPublishedResponse(artifacts, original.responseRef);
    const session = response.result.snapshot.session;
    if (session.id !== existingAdmission.id) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'session admission original response names another Session');
    }
    const channel = await validateControlChannelClosure(artifacts, owner, input);
    const requestArtifact = installed ? await publishSessionCreatePublicCore(artifacts, installed) : undefined;
    let fenceOutcome: TimeFenceAdvance | undefined;
    driver.transaction(connection => {
      const control = readControlRequest(connection, input.principalId, 'session.create', input.requestId);
      if (control !== undefined) {
        if (control.requestDigest !== requestDigest || control.responseRef !== original.responseRef) {
          throw new KernelStorageError('REQUEST_ID_CONFLICT', 'session.create requestId was reused with different bytes');
        }
        return;
      }
      const current = readAdmissionReplay(connection, 'sessions', input.principalId, 'session.create', input.admissionKey);
      const currentOriginal = readControlRequest(connection, input.principalId, 'session.create', originalRequestId);
      if (!current || !currentOriginal || canonicalSha256(current) !== canonicalSha256(existingAdmission) ||
          canonicalSha256(currentOriginal) !== canonicalSha256(original)) {
        throw new KernelStorageError('RECOVERY_REQUIRED', 'session admission original response link changed');
      }
      if (installed) {
        assertCurrentControlFrame(owner, installed.identity);
        // Existing exact bindings above remain replayable; a new alias is
        // still a write and cannot cross this handler's shutdown gate.
        installed.signal.throwIfAborted();
      }
      assertActiveStateOwner(connection, owner);
      const now = sampleCanonicalNow();
      fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
      if (fenceOutcome !== 'healthy') return;
      for (const artifact of channel.metadata) insertArtifactMetadata(connection, artifact, now);
      if (requestArtifact) insertArtifactMetadata(connection, requestArtifact, now);
      insertControlRequest(connection, { principalId: input.principalId, method: 'session.create', requestId: input.requestId,
        channelIdentityRef: input.channelIdentityRef, channelIdentityDigest: input.channelIdentityDigest, requestDigest,
        responseRef: original.responseRef, committedAt: now });
    });
    if (fenceOutcome !== undefined && fenceOutcome !== 'healthy') {
      throw new KernelStorageError('INVALID_REQUEST', 'canonical clock has regressed; admission replay binding is paused');
    }
    return { replayed: true, session, response };
  }
  return undefined;
}

export async function createSession(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: CreateSessionInput,
  selected?: HeldInstalledRuntime
): Promise<CreateSessionResult> {
  return createSessionWithin(driver, artifacts, owner, input, selected);
}

/** Installed production friend: validates public wire identity itself, never accepts a digest override. */
export async function createInstalledSession(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  request: unknown,
  identity: AuthenticatedControlIdentity,
  selected: HeldInstalledRuntime,
  controlledHome: string,
  signal: AbortSignal
): Promise<CreateSessionResult> {
  assertCurrentControlFrame(owner, identity);
  signal.throwIfAborted();
  const wire = readSessionCreatePublicRequest(request);
  const result = await createSessionWithin(driver, artifacts, owner, { ...identity, requestId: wire.core.requestId,
    admissionKey: wire.core.admissionKey, workspacePath: wire.core.workspacePath,
    ...(wire.core.name === undefined ? {} : { name: wire.core.name }) }, selected, { ...wire, identity, controlledHome, signal });
  assertCurrentControlFrame(owner, identity);
  return result;
}

async function createSessionWithin(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: CreateSessionInput,
  selected?: HeldInstalledRuntime,
  installed?: InstalledSessionRequest
): Promise<CreateSessionResult> {
  assertRequestId(input.requestId);
  assertAdmissionKey(input.admissionKey);
  assertArtifactRef(input.channelIdentityRef);
  const workspacePath = normalizeAbsolutePath(input.workspacePath);
  const name = input.name === undefined ? undefined : normalizeBoundedText(input.name, 1, 256);
  input = immutableSnapshot({ ...input, workspacePath, ...(name === undefined ? {} : { name }) });
  const admissionIntentDigest = sessionCreateIntent({
    principalId: input.principalId,
    workspacePath,
    name
  });
  const requestDigest = installed?.requestDigest ?? sessionCreateRequestDigest({
    requestId: input.requestId,
    admissionKey: input.admissionKey,
    workspacePath,
    name
  });

  const replayed = await replayCreateSession(driver, artifacts, owner, input, admissionIntentDigest, requestDigest, installed);
  if (replayed !== undefined) return replayed;
  installed?.signal.throwIfAborted();

  const channelClosure = await validateControlChannelClosure(artifacts, owner, input);
  installed?.signal.throwIfAborted();
  const channel = channelClosure.channel;

  const resources: Array<{ close(): void }> = [];
  let trust: HeldWorkspaceSourceTrust | undefined, failure: unknown;
  try {
    if (installed) {
      if (!selected) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed Session requires its held runtime');
      const native = await withHeldInstalledRuntime(selected, async runtime => {
        await runtime.revalidate(); const native = await runtime.loadStateOwner(); await runtime.revalidate(); return native;
      });
      installed.signal.throwIfAborted();
      const platform = await loadInstalledCredentialPlatform(selected);
      installed.signal.throwIfAborted();
      if (path.join(platform.currentUser().home, '.cliq') !== installed.controlledHome)
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed Session home is not the actual platform controlled home');
      const home = native.openWorkspaceRoot(installed.controlledHome); resources.push(home);
      trust = await holdWorkspaceSourceTrust(home, workspacePath, installed.signal); resources.push(trust);
      installed.signal.throwIfAborted();
      assertWorkspaceSourceTrust(trust, workspacePath);
    }
    const capture = { workspacePath, ownerPrincipalId: input.principalId };
    const captured = selected ? await captureInstalledWorkspaceIdentity(selected, capture) : await captureLiveWorkspaceIdentity(capture);
    installed?.signal.throwIfAborted();
    if (trust) assertWorkspaceSourceTrust(trust, workspacePath);
    const published: PublishedArtifact[] = [...channelClosure.metadata];
    if (installed) published.push(await publishSessionCreatePublicCore(artifacts, installed));
    let workspaceIdentity: Extract<WorkspaceIdentityV1, { kind: 'live' }> = captured.identity;
    if (captured.repository !== undefined) {
      const repositoryArtifact = await artifacts.publishCanonical(
        captured.repository,
        captured.repository.format
      );
      published.push(repositoryArtifact);
      workspaceIdentity = {
        ...workspaceIdentity,
        repositoryIdentityRef: repositoryArtifact.ref,
        repositoryIdentityDigest: captured.repository.repositoryIdentityDigest,
        identityDigest: ''
      };
      workspaceIdentity.identityDigest = digestOmitting(workspaceIdentity, 'identityDigest');
    }

    const workspaceArtifact = await artifacts.publishCanonical(workspaceIdentity, 'cliq-workspace-identity-v1');
    published.push(workspaceArtifact);
    decodeWorkspaceIdentity(workspaceIdentity);

    const now = sampleCanonicalNow();
    const sessionId = identityHash('cliq-session-id-v1', input.principalId, 'session.create', input.admissionKey);
    const projection: SessionContextProjection = {
      schemaVersion: 1,
      format: 'cliq-session-context-v1',
      sessionId,
      contextRevision: 1,
      throughItemSeq: 0,
      segments: [],
      projectionDigest: ''
    };
    projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
    const projectionArtifact = await artifacts.publishCanonical(projection, 'cliq-session-context-v1');
    published.push(projectionArtifact);
    decodeSessionProjection(projection);

    const session: Session = {
      schemaVersion: 1,
      id: sessionId,
      workspaceIdentityRef: workspaceArtifact.ref,
      contextRevision: 1,
      latestItemSeq: 0,
      contextProjectionRef: projectionArtifact.ref,
      createdAt: now,
      updatedAt: now
    };
    if (name !== undefined) session.name = name;

    const response: SessionCreateResponse = {
      protocolVersion: 1,
      ok: true,
      result: { method: 'session.create', snapshot: { schemaVersion: 1, session } }
    };
    const responseArtifact = await artifacts.publishCanonical(response, 'cliq-control-response-v1');
    published.push(responseArtifact);

    let committed = false;
    let fenceOutcome: TimeFenceAdvance | undefined;
    driver.transaction((connection) => {
      const control = readControlRequest(connection, input.principalId, 'session.create', input.requestId);
      if (control !== undefined) {
        if (control.requestDigest !== requestDigest) {
          throw new KernelStorageError('REQUEST_ID_CONFLICT', 'session.create requestId was reused with different bytes');
        }
        return;
      }
      const admission = readAdmissionReplay(
        connection,
        'sessions',
        input.principalId,
        'session.create',
        input.admissionKey
      );
      if (admission !== undefined) {
        if (admission.admissionIntentDigest !== admissionIntentDigest) {
          throw new KernelStorageError(
            'ADMISSION_KEY_CONFLICT',
            'session.create admissionKey was reused with a different intent'
          );
        }
        return;
      }

      if (installed) {
        assertCurrentControlFrame(owner, installed.identity);
        installed.signal.throwIfAborted();
      }
      if (trust) assertWorkspaceSourceTrust(trust, workspacePath);
      assertActiveStateOwner(connection, owner);
      fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch);
      if (fenceOutcome !== 'healthy') return;
      for (const artifact of published) insertArtifactMetadata(connection, artifact, now);
      connection
        .prepare(
          `INSERT INTO sessions (
             id, workspace_identity_ref, name, parent_session_id, forked_through_item_seq,
             context_revision, latest_item_seq, context_projection_ref, created_at, updated_at,
             principal_id, admission_method, admission_key, admission_intent_digest, admission_request_id
           ) VALUES (?, ?, ?, NULL, NULL, 1, 0, ?, ?, ?, ?, 'session.create', ?, ?, ?)`
        )
        .run(
          session.id,
          session.workspaceIdentityRef,
          session.name ?? null,
          session.contextProjectionRef,
          session.createdAt,
          session.updatedAt,
          input.principalId,
          input.admissionKey,
          admissionIntentDigest,
          input.requestId
        );
      insertControlRequest(connection, {
        principalId: input.principalId,
        method: 'session.create',
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
    if (committed) return { replayed: false, session, response };
    const raced = await replayCreateSession(driver, artifacts, owner, input, admissionIntentDigest, requestDigest, installed);
    if (raced !== undefined) return raced;
    throw new KernelStorageError('RECOVERY_REQUIRED', 'session.create transaction committed no Session');
  } catch (error) {
    failure = (error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT'
      ? new ResourceRetirementError('installed Session descriptor retirement failed', error) : error;
    throw failure;
  } finally {
    const failures: unknown[] = [];
    for (const resource of [...resources].reverse()) {
      try { resource.close(); } catch (error) { failures.push(error); }
    }
    if (failures.length) throw new ResourceRetirementError('Session Trust descriptors did not retire',
      new AggregateError(failure === undefined ? failures : [failure, ...failures]));
  }
}
