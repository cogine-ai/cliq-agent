import { mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { TestContext } from 'node:test';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { digestOmitting } from '../../kernel/identity.js';
import { testFixture } from '../../model/testing/fixtures.js';
import { createWorkspaceTrustContext, writePersistedWorkspaceTrust } from '../../session/trust.js';
import { openStateStore, publishInProcessChannel } from '../store.js';
import { admissionKey, uuidv7 } from './fixtures.js';
import { signedToolBundle } from './tool-authority.js';
import { fixtureSandboxProfile } from './worker-launch.js';

/** Client request bytes, not capture/admission/evidence authority. */
export function sourceInspectionRequest(overrides: Record<string, unknown> = {}) {
  const { requestDigest: _digest, ...fields } = overrides;
  const core = { protocolVersion: 1, requestId: uuidv7(), method: 'run.submit', admissionKey: admissionKey('source-target'),
    sessionId: 'session', expectedContextRevision: 1, workspacePath: '/workspace', objective: 'inspect source',
    model: { provider: 'ollama', model: 'local' }, policyMode: 'default', verifiers: [], dependency: { mode: 'none' },
    sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [], allowUnverified: true, ...fields };
  return { ...core, requestDigest: canonicalSha256(core) };
}

/** Real StateStore, Ed25519 test bootstrap, persisted Trust and native paths.
 * No process is launched and no installed Linux/VM qualification is claimed. */
export async function createSourceInspectionFixture(t: Pick<TestContext, 'after'>, label: string) {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), `cliq-source-${label}-`));
  const stateRoot = path.join(directory, 'state'), home = path.join(directory, 'home'), workspace = path.join(directory, 'workspace');
  for (const member of [stateRoot, home, workspace]) await mkdir(member, { mode: 0o700 });
  const trustContext = await createWorkspaceTrustContext(workspace, home); await writePersistedWorkspaceTrust(trustContext, 'trusted');
  const signed = await signedToolBundle(testFixture().assembly, []);
  const profile = fixtureSandboxProfile(); profile.allowedOwners = ['source_inspection']; profile.profileDigest = digestOmitting(profile, 'profileDigest');
  const authority = { bundle: signed.bundle, releaseKeys: signed.releaseKeys, sourceInspection: { controlledHome: home, sandboxProfile: profile } };
  const store = await openStateStore(stateRoot, authority);
  t.after(async () => {
    // Preserve uncertain retirement state if close refuses. An assertion or
    // helper must never erase a still-held durable resource to make cleanup pass.
    await store.close(); await rm(directory, { recursive: true, force: true });
  });
  const identity = await publishInProcessChannel(store);
  const created = await store.createSession({ ...identity, requestId: uuidv7(), admissionKey: admissionKey(`${label}-session`), workspacePath: workspace });
  const request = sourceInspectionRequest({ sessionId: created.session.id, workspacePath: workspace });
  return { directory, stateRoot, home, workspace, authority, store, identity, request, session: created.session, trustContext };
}
