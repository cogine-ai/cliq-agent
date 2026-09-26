import { canonicalSha256 } from '../../kernel/canonical.js';
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
import { validateControlChannelClosure } from '../control-channel.js';
import { decodeSessionProjection, decodeWorkspaceIdentity } from '../decoders.js';
import { KernelStorageError } from '../errors.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import {
  insertControlRequest,
  readAdmissionReplay,
  readControlRequest,
  readSession
} from '../rows.js';
import type { SqliteDriver } from '../sqlite-driver.js';
import { assertCurrentLiveWorkspaceIdentity, captureLiveWorkspaceIdentity } from '../workspace-identity.js';

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
  input: CreateSessionInput,
  admissionIntentDigest: string,
  requestDigest: string
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
    const session = readSession(driver, existingAdmission.id);
    const response: SessionCreateResponse = {
      protocolVersion: 1,
      ok: true,
      result: { method: 'session.create', snapshot: { schemaVersion: 1, session } }
    };
    return { replayed: true, session, response };
  }
  return undefined;
}

export async function createSession(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: CreateSessionInput
): Promise<CreateSessionResult> {
  assertRequestId(input.requestId);
  assertAdmissionKey(input.admissionKey);
  assertArtifactRef(input.channelIdentityRef);
  const workspacePath = normalizeAbsolutePath(input.workspacePath);
  const name = input.name === undefined ? undefined : normalizeBoundedText(input.name, 1, 256);
  const admissionIntentDigest = sessionCreateIntent({
    principalId: input.principalId,
    workspacePath,
    name
  });
  const requestDigest = sessionCreateRequestDigest({
    requestId: input.requestId,
    admissionKey: input.admissionKey,
    workspacePath,
    name
  });

  // Authenticate this call before looking up a retained response. The original
  // response keeps its first channel provenance when replayed on a new channel.
  const channelClosure = await validateControlChannelClosure(artifacts, owner, input);
  const channel = channelClosure.channel;
  const replayed = await replayCreateSession(driver, artifacts, input, admissionIntentDigest, requestDigest);
  if (replayed !== undefined) return replayed;

  const captured = await captureLiveWorkspaceIdentity({
    workspacePath,
    ownerPrincipalId: input.principalId,
    filesystem: owner.filesystem
  });
  const published: PublishedArtifact[] = [...channelClosure.metadata];
  let workspaceIdentity: Extract<WorkspaceIdentityV1, { kind: 'live' }> = captured.identity;
  if (captured.repository !== undefined) {
    const repositoryArtifact = await artifacts.publishCanonical(
      captured.repository,
      'cliq-repository-identity-v1'
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

    assertActiveStateOwner(connection, owner);
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch);
    if (fenceOutcome !== 'healthy') return;
    assertCurrentLiveWorkspaceIdentity(workspaceIdentity, workspacePath, owner.filesystem);
    for (const artifact of published) insertArtifactMetadata(connection, artifact, now);
    connection
      .prepare(
        `INSERT INTO sessions (
           id, workspace_identity_ref, name, parent_session_id, forked_through_item_seq,
           context_revision, latest_item_seq, context_projection_ref, created_at, updated_at,
           principal_id, admission_method, admission_key, admission_intent_digest
         ) VALUES (?, ?, ?, NULL, NULL, 1, 0, ?, ?, ?, ?, 'session.create', ?, ?)`
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
        admissionIntentDigest
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
  const raced = await replayCreateSession(driver, artifacts, input, admissionIntentDigest, requestDigest);
  if (raced !== undefined) return raced;
  throw new KernelStorageError('RECOVERY_REQUIRED', 'session.create transaction committed no Session');
}
