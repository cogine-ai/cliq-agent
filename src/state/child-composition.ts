// Complete immutable narrowing data. Only the owning reducer's final
// transaction may admit these bytes or reserve ancestor-inclusive budgets.
import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import type { ChildCapabilityGrantV1, DelegateRequest } from '../kernel/children.js';
import { digestOmitting } from '../kernel/identity.js';
import type { RunAssemblyV1, RunSpec, ToolContractManifestV1 } from '../kernel/types.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { assertRunPolicySnapshot, modeDecisions } from '../policy/tool-policy.js';
import { loadToolContracts } from '../tools/input-contract.js';
import { decodeDelegateRequest } from '../tools/child-inputs.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';

const compare = (a: string, b: string) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const sorted = (values: string[]) => [...new Set(values)].sort(compare);
export async function planChildComposition(artifacts: ArtifactCatalog, input: {
  request: DelegateRequest; parentSpec: RunSpec; principalId: string; workspaceIdentityDigest: string;
  delegateRequestRef: string; grantedBudgets: RunSpec['budgets']; createdAt: string;
}) {
  const request = decodeDelegateRequest(input.request), reads = artifacts;
  const parent = decodeRetainedRunAssembly(await readCanonicalArtifact(reads, input.parentSpec.assemblyRef));
  const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(reads, input.parentSpec.policyRef);
  const manifest = await readCanonicalArtifact<ToolContractManifestV1>(reads, parent.tools.manifestRef);
  assertRunPolicySnapshot({ policy, policyRef: input.parentSpec.policyRef, assembly: parent,
    principalId: input.principalId, workspaceIdentityDigest: input.workspaceIdentityDigest });
  if (manifest.schemaVersion !== 1 || manifest.format !== 'cliq-tool-contracts-v1' ||
      digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest || manifest.manifestDigest !== parent.tools.manifestDigest)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'child composition lost its complete original parent manifest');
  loadToolContracts(await reads.mapReads(manifest.entries, async entry => ({ ...entry,
    inputSchema: await readCanonicalArtifact(reads, entry.inputSchemaRef) })));
  const requestedNames = new Set(request.capabilities.builtinToolNames), requestedServers = new Set(request.capabilities.registeredMcpServerIds);
  const entries = manifest.entries.filter(entry => {
    if (entry.execution.kind === 'mcp') return request.mode === 'mutating' && requestedServers.has(entry.execution.registrationId);
    if (!requestedNames.has(entry.name)) return false;
    if (entry.name === 'bash' && !request.capabilities.allowShell) return false;
    if (entry.access === 'write' && !request.capabilities.allowSourceWrite) return false;
    return request.mode !== 'read_only' || ['read', 'plan', 'control'].includes(entry.access) ||
      entry.execution.kind === 'supervisor_operation' && entry.execution.handlerId === 'delegate';
  }).sort((a, b) => compare(a.name, b.name));
  const toolCore = { schemaVersion: 1 as const, format: 'cliq-tool-contracts-v1' as const, entries };
  const tools: ToolContractManifestV1 = { ...toolCore, manifestDigest: canonicalSha256(toolCore) };
  const toolPlan = planCanonicalArtifact(tools, tools.format);
  const mcp = parent.mcpServers.filter(server => entries.some(entry => entry.execution.kind === 'mcp' && entry.execution.registrationId === server.registrationId));
  // The currently installed broker has no MCP or dependency acquisition
  // consumer. A retained shape cannot invent credential or launch support.
  if (mcp.length || request.verifierMode === 'inherit_parent' && input.parentSpec.dependencyPolicyRef)
    throw new KernelStorageError('INVALID_REQUEST', 'this installed child recipe has no MCP or dependency acquisition backend');
  const granted: ChildCapabilityGrantV1['granted'] = {
    builtinToolNames: entries.filter(entry => entry.execution.kind !== 'mcp').map(entry => entry.name),
    registeredMcpServerIds: mcp.map(server => server.registrationId).sort(compare),
    allowShell: request.mode === 'mutating' && request.capabilities.allowShell && entries.some(entry => entry.name === 'bash'),
    allowSourceWrite: request.mode === 'mutating' && request.capabilities.allowSourceWrite && entries.some(entry => entry.access === 'write') };
  const child: RunAssemblyV1 = structuredClone(parent);
  child.tools = { manifestRef: toolPlan.ref, manifestDigest: tools.manifestDigest };
  child.mcpServers = mcp;
  child.provider.negotiation.exposedToolNames = child.provider.negotiation.mode === 'native-tools' ? entries.map(entry => entry.name) : [];
  if (child.provider.pricing.kind === 'trusted_price_table') child.provider.pricing.maxRunCostMicros = input.grantedBudgets.costMicros;
  child.retry.tools = entries.map(entry => {
    const retry = parent.retry.tools.find(retry => retry.toolName === entry.name);
    if (!retry || retry.replayClass !== entry.replayClass) throw new KernelStorageError('ARTIFACT_MISMATCH', 'child tool lost its exact original recovery contract');
    return structuredClone(retry);
  });
  child.createdAt = input.createdAt; child.assemblyDigest = digestOmitting(child, 'assemblyDigest');
  const childPolicy: RunPolicySnapshotV1 = structuredClone(policy);
  childPolicy.toolManifestRef = toolPlan.ref; childPolicy.toolManifestDigest = tools.manifestDigest;
  childPolicy.decisions = modeDecisions(childPolicy.mode);
  const floors: Array<[RunPolicySnapshotV1['decisionRules'][number]['channel'], string]> = [];
  if (!granted.allowShell) floors.push(['bash', '*']);
  if (!granted.allowSourceWrite) floors.push(['fs-write', '*']);
  if (request.mode === 'read_only') floors.push(['named-action', 'child_mutating']);
  for (const [channel, pattern] of floors) childPolicy.decisionRules.push({ ruleId: `child-floor:${input.delegateRequestRef}:${channel}:${pattern}`,
    order: childPolicy.decisionRules.length, source: 'session', sourceRef: input.delegateRequestRef, channel, pattern, disposition: 'deny' });
  childPolicy.createdAt = input.createdAt; childPolicy.policyDigest = digestOmitting(childPolicy, 'policyDigest');
  const policyPlan = planCanonicalArtifact(childPolicy, childPolicy.format), assemblyPlan = planCanonicalArtifact(child, child.format);
  assertRunPolicySnapshot({ policy: childPolicy, policyRef: policyPlan.ref, assembly: child,
    principalId: input.principalId, workspaceIdentityDigest: input.workspaceIdentityDigest });
  const credentialGrantRefs = sorted(child.provider.credentialGrantRefs);
  if (credentialGrantRefs.some(ref => !input.parentSpec.credentialGrantRefs.includes(ref)))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'child credentials are not a subset of the exact parent union');
  return Object.freeze({ ...immutableSnapshot({ parent, parentPolicy: policy, tools, assembly: child, policy: childPolicy, granted,
    credentialGrantRefs }), plans: Object.freeze([toolPlan, assemblyPlan, policyPlan]) as readonly PlannedArtifact[] });
}
