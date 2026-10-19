import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting } from '../kernel/identity.js';
import type { ToolContractManifestV1 } from '../kernel/types.js';
import type { RunPolicySnapshotV1, PolicyEngineProfileV1 } from '../kernel/tool-authorization.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyToolRuntimeAuthority, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { assertRunPolicySnapshot } from '../policy/tool-policy.js';
import { loadToolContracts } from '../tools/input-contract.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeRunSpec, decodeVerifierSpec, decodeWorkspaceIdentity } from './decoders.js';
import { joinResourceOperations, KernelStorageError, stateOperation } from './errors.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readRun, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { validateVerifierRunAdmission } from './verifier-admission.js';
import { assertDeliveryModelFreeCut } from './run-model-free.js';

/** Shared retained execution inputs. This reader never creates a model session,
 * resolves live credentials or validates provider pricing/capability material. */
export const readRunAuthority = stateOperation('RECOVERY_REQUIRED', async function readRunAuthority(
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { runId: string; operation: 'agent' | 'delivery'; releaseKeys?: readonly ReleaseTrustKey[] }, signal?: AbortSignal
) {
  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  const releaseKeys = input.releaseKeys === undefined ? undefined : immutableSnapshot(input.releaseKeys);
  const recovered = await readRecoveryClosure(driver, artifacts, input.runId), run = recovered.run;
  const spec = immutableSnapshot(decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef)));
  if (spec.operation !== input.operation) throw new TypeError(input.operation === 'agent'
    ? 'delivery Runs cannot load a model' : 'an Agent Run cannot load a delivery continuation');
  if (spec.operation === 'delivery') assertDeliveryModelFreeCut(recovered);
  const assembly = immutableSnapshot(decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, spec.assemblyRef)));
  if (decodeVerifierSpec(await readCanonicalArtifact(artifacts, spec.verifierSpecRef)).verifiers.length) {
    if (!releaseKeys) throw new TypeError('verifier authority requires the original trusted Supervisor release roots');
    const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, assembly.runtime.runtimeBundleRef);
    await validateVerifierRunAdmission(driver, artifacts, owner, { bundle, releaseKeys }, run.id, signal);
  }
  const manifest = await readCanonicalArtifact<ToolContractManifestV1>(artifacts, assembly.tools.manifestRef);
  const exactKeys = (value: object, keys: string[]) => Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
  if (manifest.schemaVersion !== 1 || manifest.format !== 'cliq-tool-contracts-v1' ||
      !exactKeys(manifest, ['schemaVersion', 'format', 'entries', 'manifestDigest']) ||
      manifest.manifestDigest !== assembly.tools.manifestDigest || digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest ||
      new Set(manifest.entries.map(entry => entry.name)).size !== manifest.entries.length)
    throw new TypeError('Run tool manifest does not match its retained assembly');
  const contracts = immutableSnapshot(await joinResourceOperations(manifest.entries.map(async entry => {
    const output = entry.outputSchemaRef !== undefined;
    if (!exactKeys(entry, ['name', 'version', 'description', 'access', 'inputSchemaRef', 'inputSchemaDigest', 'replayClass', 'execution',
      ...(output ? ['outputSchemaRef', 'outputSchemaDigest'] : [])]) || typeof entry.version !== 'string' || !entry.version ||
        !['read', 'write', 'exec', 'plan', 'control'].includes(entry.access)) throw new TypeError('invalid frozen tool contract schema');
    const execution = entry.execution;
    if (execution.kind === 'builtin') {
      if (!exactKeys(execution, ['kind', 'adapterId', 'adapterVersion', 'adapterCodeDigest']) ||
          !['manual', 'retry'].includes(entry.replayClass) || typeof execution.adapterId !== 'string' || !execution.adapterId ||
          typeof execution.adapterVersion !== 'string' || !execution.adapterVersion) throw new TypeError('invalid builtin execution contract');
      assertArtifactRef(execution.adapterCodeDigest);
    } else if (execution.kind === 'mcp') {
      if (!exactKeys(execution, ['kind', 'registrationId', 'registryRevisionRef', 'registryManifestDigest', 'serverToolName', 'toolContractDigest']) ||
          typeof execution.serverToolName !== 'string' || !execution.serverToolName || !assembly.mcpServers.some(server =>
            server.registrationId === execution.registrationId && server.registryRevisionRef === execution.registryRevisionRef &&
            server.manifestDigest === execution.registryManifestDigest)) throw new TypeError('tool contract differs from the frozen MCP registration');
      assertArtifactRef(execution.toolContractDigest);
    } else throw new TypeError('unknown tool execution contract');
    const schema = await readCanonicalArtifact(artifacts, entry.inputSchemaRef);
    if (canonicalSha256(schema) !== entry.inputSchemaDigest) throw new TypeError('tool input schema digest mismatch');
    if (output && canonicalSha256(await readCanonicalArtifact(artifacts, entry.outputSchemaRef!)) !== entry.outputSchemaDigest)
      throw new TypeError('tool output schema digest mismatch');
    return { ...entry, inputSchema: schema };
  })));
  const session = readSession(driver, run.sessionId), principalId = readSessionPrincipalId(driver, run.sessionId);
  const toolContracts = loadToolContracts(contracts);
  const assertAuthority = async () => {
    assertActiveStateOwner(driver, owner);
    if (!releaseKeys) throw new KernelStorageError('RECOVERY_REQUIRED', 'tool authority requires the trusted release key set and canonical policy/profile closure');
    const current = readRun(driver, run.id);
    if (current.specRef !== run.specRef || current.createdAt !== run.createdAt || current.deadlineAt !== run.deadlineAt)
      throw new TypeError('loaded execution authority no longer belongs to this Run');
    const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, session.workspaceIdentityRef));
    if (principalId !== workspace.ownerPrincipalId || driver.prepare('SELECT principal_id FROM runs WHERE id = ?')
      .get<{ principal_id: string }>(run.id)?.principal_id !== principalId) throw new TypeError('Run, Session and workspace do not share one principal');
    const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, spec.policyRef);
    assertRunPolicySnapshot({ policy, policyRef: spec.policyRef, assembly, principalId, workspaceIdentityDigest: workspace.identityDigest });
    const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, assembly.runtime.runtimeBundleRef);
    const profile = await readCanonicalArtifact<PolicyEngineProfileV1>(artifacts, policy.engine.profileRef);
    verifyToolRuntimeAuthority({ assembly, policy, bundle, profile, tools: contracts.map(({ inputSchema: _schema, ...entry }) => entry), releaseKeys });
    for (const ref of new Set([spec.policyRef, assembly.runtime.runtimeBundleRef, policy.engine.profileRef,
      ...policy.decisionRules.flatMap(rule => rule.sourceRef ? [rule.sourceRef] : [])])) await artifacts.readBytes(ref);
    signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  };
  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  return { recovered, run, spec, assembly, releaseKeys, contracts, toolContracts,
    controlAuthority: { run, spec, assembly, principalId, resolveToolInput: toolContracts.resolveToolInput, assertAuthority } };
});

export type RunAuthority = Awaited<ReturnType<typeof readRunAuthority>>;
