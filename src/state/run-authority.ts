import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { Run, ToolContractManifestV1 } from '../kernel/types.js';
import type { RunPolicySnapshotV1, PolicyEngineProfileV1 } from '../kernel/tool-authorization.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { immutableSnapshot } from '../model/immutable.js';
import { type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { decodeToolExecutionIdentity } from '../tools/execution-identity.js';
import { assertSupervisorControlIdentity, readToolRuntimeAuthority } from './tool-runtime-authority.js';
import { assertRunPolicySnapshot } from '../policy/tool-policy.js';
import { loadToolContracts } from '../tools/input-contract.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeRunSpec, decodeVerifierSpec, decodeWorkspaceIdentity } from './decoders.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readRun, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { validateVerifierRunAdmission } from './verifier-admission.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { assertDeliveryModelFreeCut } from './run-model-free.js';

type RunAuthorityInput = { runId: string; operation: 'agent' | 'delivery'; releaseKeys?: readonly ReleaseTrustKey[] };

/** Closed material only. No history shortcut is returned to an execution or
 * replay: each caller retains its own complete fresh recovery boundary. */
async function readRunAuthorityMaterial(
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: RunAuthorityInput, run: Run, signal?: AbortSignal
) {
  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  const openingReads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const releaseKeys = input.releaseKeys === undefined ? undefined : immutableSnapshot(input.releaseKeys);
  const spec = immutableSnapshot(decodeRunSpec(await readCanonicalArtifact(openingReads, run.specRef)));
  if (spec.operation !== input.operation) throw new TypeError(input.operation === 'agent'
    ? 'delivery Runs cannot load a model' : 'an Agent Run cannot load a delivery continuation');
  const assembly = immutableSnapshot(decodeRetainedRunAssembly(await readCanonicalArtifact(openingReads, spec.assemblyRef)));
  if (decodeVerifierSpec(await readCanonicalArtifact(openingReads, spec.verifierSpecRef)).verifiers.length) {
    if (!releaseKeys) throw new TypeError('verifier authority requires the original trusted Supervisor release roots');
    const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(openingReads, assembly.runtime.runtimeBundleRef);
    await validateVerifierRunAdmission(driver, openingReads, owner, { bundle, releaseKeys }, run.id, signal);
  }
  const manifest = await readCanonicalArtifact<ToolContractManifestV1>(openingReads, assembly.tools.manifestRef);
  const exactKeys = (value: object, keys: string[]) => Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
  if (manifest.schemaVersion !== 1 || manifest.format !== 'cliq-tool-contracts-v1' ||
      !exactKeys(manifest, ['schemaVersion', 'format', 'entries', 'manifestDigest']) ||
      manifest.manifestDigest !== assembly.tools.manifestDigest || digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest ||
      new Set(manifest.entries.map(entry => entry.name)).size !== manifest.entries.length)
    throw new TypeError('Run tool manifest does not match its retained assembly');
  const contracts = immutableSnapshot(await openingReads.mapReads(manifest.entries, async entry => {
    const output = entry.outputSchemaRef !== undefined;
    if (!exactKeys(entry, ['name', 'version', 'description', 'access', 'inputSchemaRef', 'inputSchemaDigest', 'replayClass', 'execution',
      ...(output ? ['outputSchemaRef', 'outputSchemaDigest'] : [])]) || typeof entry.version !== 'string' || !entry.version ||
        !['read', 'write', 'exec', 'plan', 'control'].includes(entry.access)) throw new TypeError('invalid frozen tool contract schema');
    const execution = decodeToolExecutionIdentity(entry.execution);
    if (execution.kind === 'mcp') {
      if (!assembly.mcpServers.some(server =>
            server.registrationId === execution.registrationId && server.registryRevisionRef === execution.registryRevisionRef &&
            server.manifestDigest === execution.registryManifestDigest)) throw new TypeError('tool contract differs from the frozen MCP registration');
    } else if (!['manual', 'retry'].includes(entry.replayClass)) throw new TypeError('invalid builtin replay contract');
    const schema = await readCanonicalArtifact(openingReads, entry.inputSchemaRef);
    if (canonicalSha256(schema) !== entry.inputSchemaDigest) throw new TypeError('tool input schema digest mismatch');
    if (output && canonicalSha256(await readCanonicalArtifact(openingReads, entry.outputSchemaRef!)) !== entry.outputSchemaDigest)
      throw new TypeError('tool output schema digest mismatch');
    return { ...entry, inputSchema: schema };
  }));
  const session = readSession(driver, run.sessionId), principalId = readSessionPrincipalId(driver, run.sessionId);
  const toolContracts = loadToolContracts(contracts);
  const assertAuthority = async (readSignal?: AbortSignal) => {
    const reads = readSignal ? artifacts.withReadSignal(readSignal) : artifacts;
    reads.assertReadActive();
    assertActiveStateOwner(driver, owner);
    if (!releaseKeys) throw new KernelStorageError('RECOVERY_REQUIRED', 'tool authority requires the trusted release key set and canonical policy/profile closure');
    const current = readRun(driver, run.id);
    if (current.specRef !== run.specRef || current.createdAt !== run.createdAt || current.deadlineAt !== run.deadlineAt)
      throw new TypeError('loaded execution authority no longer belongs to this Run');
    const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(reads, session.workspaceIdentityRef));
    if (principalId !== workspace.ownerPrincipalId || driver.prepare('SELECT principal_id FROM runs WHERE id = ?')
      .get<{ principal_id: string }>(run.id)?.principal_id !== principalId) throw new TypeError('Run, Session and workspace do not share one principal');
    const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(reads, spec.policyRef);
    assertRunPolicySnapshot({ policy, policyRef: spec.policyRef, assembly, principalId, workspaceIdentityDigest: workspace.identityDigest });
    const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(reads, assembly.runtime.runtimeBundleRef);
    const profile = await readCanonicalArtifact<PolicyEngineProfileV1>(reads, policy.engine.profileRef);
    const tools = contracts.map(({ inputSchema: _schema, ...entry }) => entry);
    const sandbox = decodeSandboxProfile(await readCanonicalArtifact(reads, spec.sandboxProfileRef));
    await readToolRuntimeAuthority(reads, { assembly, policy, bundle, profile, tools, releaseKeys, resources: sandbox.resources }, readSignal);
    assertSupervisorControlIdentity(assertActiveStateOwner(driver, owner), assembly, tools);
    for (const ref of new Set([spec.policyRef, assembly.runtime.runtimeBundleRef, policy.engine.profileRef,
      ...policy.decisionRules.flatMap(rule => rule.sourceRef ? [rule.sourceRef] : [])])) await reads.readBytes(ref);
    readSignal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  };
  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  return { run, spec, assembly, releaseKeys, contracts, toolContracts, session,
    controlAuthority: { run, spec, assembly, principalId, resolveToolInput: toolContracts.resolveToolInput, assertAuthority } };
}

/** Shared retained execution inputs. Productive loading keeps its complete
 * opening history validation before any continuation is constructed. */
export const readRunAuthority = stateOperation('RECOVERY_REQUIRED', async function readRunAuthority(
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: RunAuthorityInput, signal?: AbortSignal
) {
  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const selected = { ...input, releaseKeys: input.releaseKeys === undefined ? undefined : immutableSnapshot(input.releaseKeys) };
  const recovered = await readRecoveryClosure(driver, reads, selected.runId);
  if (recovered.runSpec.operation === 'delivery') assertDeliveryModelFreeCut(recovered);
  const material = await readRunAuthorityMaterial(driver, artifacts, owner, selected, recovered.run, signal);
  return { recovered, ...material };
});

/** Read-only terminal cancellation inputs. The terminal-only stop reader must
 * still validate the entire fresh history before replay, conflict or refusal.
 * This does not load an agent, resolve credentials, or open a native producer. */
export const readTerminalRunMaterial = stateOperation('RECOVERY_REQUIRED', async function readTerminalRunMaterial(
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: RunAuthorityInput, signal?: AbortSignal
) {
  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  const run = readRun(driver, input.runId), session = readSession(driver, run.sessionId);
  const principalId = readSessionPrincipalId(driver, session.id);
  if (!['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(run.status))
    throw new KernelStorageError('REVISION_CONFLICT', 'terminal cancellation lost its original terminal cut');
  const material = await readRunAuthorityMaterial(driver, artifacts, owner, input, run, signal);
  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  if (canonicalSha256(readRun(driver, run.id)) !== canonicalSha256(run) ||
      canonicalSha256(readSession(driver, session.id)) !== canonicalSha256(session) ||
      canonicalSha256(material.session) !== canonicalSha256(session) ||
      readSessionPrincipalId(driver, session.id) !== principalId ||
      material.controlAuthority.principalId !== principalId)
    throw new KernelStorageError('REVISION_CONFLICT', 'terminal cancellation material changed its original Run or Session');
  return material;
});

export type RunAuthority = Awaited<ReturnType<typeof readRunAuthority>>;
