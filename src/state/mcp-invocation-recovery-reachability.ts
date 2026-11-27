// Complete retained MCP data graph, issued only by the existing historical
// readers over the original SQL/CAS cut. This creates no StateOwner, native
// resource, execution/death proof, retry permission or deletion authority.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { controlWireRef, controlWireRecord } from '../kernel/control-wire-data.js';
import { decodeMcpMutationRequest, decodeMcpRecoveryContract, decodeAdminProbePayloadCore, type McpRegistryRevisionV1 } from '../kernel/mcp.js';
import { decodeMcpRetryDispatchClosure } from '../kernel/mcp-retry.js';
import { decodeMcpInvocationWait, type McpInvocationWaitV1, type McpStatusProbePreparationV1 } from '../kernel/mcp-status.js';
import { decodeRetryUnknownCancelledResult } from '../kernel/retry-unknown.js';
import { decodeMcpRecoveryAdapterManifest, decodeMcpRecoveryStatusRequestTemplate } from '../kernel/mcp-recovery.js';
import type { CoreRetentionArtifactPurpose } from '../kernel/retention-purpose.js';
import type { RuntimeFailureEvidenceV1 } from '../kernel/stop.js';
import type { RecoveryClosureV1, InvocationJournalEntry, RunAssemblyV1, ContinuationItem, TerminalDetail, PlatformProcessIdentityV1,
  Checkpoint, ToolResultPayloadV1, ToolResultModelContentV1 } from '../kernel/types.js';
import type { ToolRequestV1, ToolTargetV1, ToolOperationGrantV1 } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { decodeAgentStop } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { decodePlatformProcessIdentity } from './decoders.js';
import { readMcpOriginalClaim } from './mcp-execution.js';
import type { McpRegistryRetainedParent } from './mcp-registration.js';
import { readMcpStdioCapture } from './mcp-stdio-history.js';
import { MCP_RECOVERY_REACHABILITY_PURPOSES, readMcpRecoveryArtifactEdges, type McpRecoveryReachabilityPurpose, type McpRecoveryDependencyPurpose,
  type McpRecoveryReachabilityContext } from './mcp-recovery-reachability.js';
import type { McpStdioReachabilityPurpose } from './mcp-stdio-reachability.js';
import { readMcpRetryJournalHistory, validateMcpRetryTerminalHistory } from './mcp-retry-admission.js';
import { validateMcpRetryCancelledItem } from './mcp-retry-terminal.js';
import { readMcpStatusProbeEvidence, readMcpStatusWaitHistory, readMcpStatusUserSource } from './mcp-status-history.js';
import { readMcpStatusProbePreparation } from './mcp-status-preparation.js';
import { readMcpReconciledEffectHistory, validateMcpReconciledToolResult } from './mcp-status-result-history.js';
import { decodeMcpStatusCapture } from './mcp-status-native-history.js';
import type { McpStatusRetirementV1 } from './mcp-status-proof.js';
import type { readMcpReconcileSource } from './mcp-status-source.js';
import { validateModelFailureStop } from './model-failure.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { readRun, readCheckpoint, readControlRequest } from './rows.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { assertSqliteConnectionOwnedBy, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import { assertInstalledExclusiveReadSource, type InstalledExclusiveReadSource } from './store.js';

export const MCP_INVOCATION_RECOVERY_RETENTION_PURPOSES = [
  ...MCP_RECOVERY_REACHABILITY_PURPOSES,
  'mcp.retry.http_claim_identity', 'mcp.retry.dispatch_closure', 'mcp.retry.unused_result', 'mcp.retry.runtime_failure',
  'mcp.recovery.creator_process_identity',
  'mcp.status.wait', 'mcp.status.dispatch', 'mcp.status.preparation', 'mcp.status.native_recipe',
  'mcp.status.broker_request', 'mcp.status.broker_target', 'mcp.status.request_frame',
  'mcp.status.retirement', 'mcp.status.native_lifecycle_raw', 'mcp.status.native_lifecycle_projection',
  'mcp.status.native_cleanup_raw', 'mcp.status.native_cleanup_projection',
  'mcp.status.capture', 'mcp.status.finite_capture', 'mcp.status.response',
  'mcp.status.probe_evidence', 'mcp.status.subject_evidence', 'mcp.status.timeout_closure', 'mcp.status.cancellation_closure',
  'mcp.status.reconciled_effect_result',
  'mcp.status.tool_result_payload', 'mcp.status.model_content',
  'mcp.status.user_request_core', 'mcp.status.user_first_response',
] as const;
export type McpInvocationRecoveryPurpose = typeof MCP_INVOCATION_RECOVERY_RETENTION_PURPOSES[number];
export type McpInvocationRecoveryDependencyPurpose = CoreRetentionArtifactPurpose | McpStdioReachabilityPurpose | McpRecoveryDependencyPurpose | 'run_spec' | 'parent_cancellation';
type Purpose = McpInvocationRecoveryPurpose | McpInvocationRecoveryDependencyPurpose;
declare const contextBrand: unique symbol;
export type McpInvocationRecoveryContext = Readonly<{ readonly [contextBrand]: true }>;
export type McpInvocationRecoveryEdge = Readonly<{ ref: string; purpose: Purpose; context: McpInvocationRecoveryContext }>;
export type McpInvocationRecoveryParent = Readonly<{
  scope: string; run: RecoveryClosureV1['run']; runSpec: RecoveryClosureV1['runSpec']; journal: readonly InvocationJournalEntry[];
  checkpoints: readonly Checkpoint[];
  workerLaunches: RecoveryClosureV1['workerLaunches']; workspaceGenerations: RecoveryClosureV1['workspaceGenerations'];
  assembly: RunAssemblyV1; bundle: RuntimeBundleManifest; prepared: InvocationJournalEntry; claim: InvocationJournalEntry;
  unknown?: InvocationJournalEntry; request: ToolRequestV1; target: ToolTargetV1; grant: ToolOperationGrantV1;
  registryRef: string; registry: McpRegistryRevisionV1; registryParents: readonly McpRegistryRetainedParent[];
  registeredParent?: McpRegistryRetainedParent; registeredBundle?: RuntimeBundleManifest;
  recoveryProfileId?: string; recoveryToolName?: string; recoveryMemberKind?: 'static_arguments' | 'completed' | 'failed';
  wait?: McpInvocationWaitV1; preparation?: McpStatusProbePreparationV1;
  retirement?: McpStatusRetirementV1; retirementEvidence?: StatusRetirement['evidence'];
}>;
type PendingEdge = Readonly<{ ref: string; purpose: Purpose; parent: McpInvocationRecoveryParent }>;
type Node = { ref: string; purpose: McpInvocationRecoveryPurpose; parent: McpInvocationRecoveryParent;
  kind: 'json' | 'bytes'; byteCount: number; edges: PendingEdge[] };
type Graph = { artifacts: ArtifactCatalog; processId: number;
  nodes: Map<string, Node>; dependencies: Map<string, McpInvocationRecoveryParent>; contexts: Map<string, McpInvocationRecoveryContext>;
  continuations: Map<string, PendingEdge[]>;
  roots: McpInvocationRecoveryEdge[]; assertions: Array<(connection: SqliteConnection) => void>;
  assertScope(): void; assertUnchanged(connection: SqliteConnection): void };
// Per-Run proof limits cover distinct parent purposes as well as repeated
// references. The complete collection pass refuses an oversized graph.
const MAX_NODES = 131_072;
const MAX_EDGES = 524_288;
const MAX_CONTEXTS = MAX_NODES + MAX_EDGES;
const MAX_ASSERTIONS = 65_536;
const MAX_RETAINED_MATERIAL_UNITS = 128 * 1024 * 1024;
const contexts = new WeakMap<object, { graph: Graph; key: string; ref: string; purpose: Purpose; parent: McpInvocationRecoveryParent }>();
const purposes = new Set<string>(MCP_INVOCATION_RECOVERY_RETENTION_PURPOSES);
export class UnsupportedMcpInvocationRecoveryReachability extends TypeError {
  constructor() { super('unsupported, changed or incomplete original MCP invocation recovery retention context'); }
}
function unsupported(): never { throw new UnsupportedMcpInvocationRecoveryReachability(); }
const keyOf = (parent: McpInvocationRecoveryParent, ref: string, purpose: Purpose) => `${parent.scope}\0${purpose}\0${ref}`;
function edge(graph: Graph, refValue: string, purpose: Purpose, parent: McpInvocationRecoveryParent): McpInvocationRecoveryEdge {
  const ref = controlWireRef(refValue), key = keyOf(parent, ref, purpose); let context = graph.contexts.get(key);
  if (!context) {
    if (graph.contexts.size >= MAX_CONTEXTS) unsupported();
    context = Object.freeze({}) as McpInvocationRecoveryContext;
    contexts.set(context, { graph, key, ref, purpose, parent }); graph.contexts.set(key, context);
  }
  if (!purposes.has(purpose)) graph.dependencies.set(key, parent);
  return Object.freeze({ ref, purpose, context });
}
function issued(value: McpInvocationRecoveryContext) {
  const selected = contexts.get(value);
  if (!selected || selected.graph.processId !== process.pid) unsupported();
  selected.graph.assertScope(); return selected;
}
async function verifyOriginalBytes(artifacts: ArtifactCatalog, ref: string, byteCount: number) {
  // Exhaustion verifies the full original hash, size, held-file identity and
  // real closes. A node retains its validated digest/length, never its body.
  for await (const _chunk of artifacts.readChunks(ref, byteCount)) { /* Verify, then discard. */ }
}
/** Data provenance for the core/domain reader of a foreign dependency.
 * A caller boolean or equal structural object cannot manufacture this view. */
export function readMcpInvocationRecoveryDependency(context: McpInvocationRecoveryContext) {
  const selected = issued(context);
  if (!selected.graph.dependencies.has(selected.key) || purposes.has(selected.purpose)) unsupported();
  return Object.freeze({ ref: selected.ref, purpose: selected.purpose, parent: selected.parent });
}
/** Core parents may continue only the exact children declared by that same
 * fully validated original parent. Multiple uses retain separate contexts. */
export function continueMcpInvocationRecoveryDependency(context: McpInvocationRecoveryContext, child: Readonly<{ ref: string; purpose: string }>): readonly McpInvocationRecoveryContext[] {
  const selected = issued(context);
  if (!selected.graph.dependencies.has(selected.key)) unsupported();
  const matches = selected.graph.continuations.get(selected.key)?.filter(value => value.ref === child.ref && value.purpose === child.purpose);
  if (!matches?.length) unsupported();
  return Object.freeze(matches.map(value => edge(selected.graph, value.ref, value.purpose, value.parent).context));
}
/** The caller consumes every (ref,purpose,original-parent) separately. This
 * proof of a data edge grants no physical deletion or current cleanup. */
export async function readMcpInvocationRecoveryEdges(context: McpInvocationRecoveryContext, input: Readonly<{ ref: string; purpose: string }>): Promise<readonly McpInvocationRecoveryEdge[]> {
  const selected = issued(context), { graph } = selected;
  if (input.ref !== selected.ref || input.purpose !== selected.purpose || !purposes.has(input.purpose)) unsupported();
  const node = graph.nodes.get(selected.key); if (!node) unsupported();
  await verifyOriginalBytes(graph.artifacts, node.ref, node.byteCount);
  graph.assertScope();
  return Object.freeze(node.edges.map(child => edge(graph, child.ref, child.purpose, child.parent)));
}

type Original = Awaited<ReturnType<typeof readMcpOriginalClaim>>;
type StatusSource = Awaited<ReturnType<typeof readMcpReconcileSource>>;
type PreparedStatus = Awaited<ReturnType<typeof readMcpStatusProbePreparation>>;
type StatusProof = Awaited<ReturnType<typeof readMcpStatusProbeEvidence>>;
type StatusRetirement = StatusProof['retirement'];
type StatusCapture = NonNullable<StatusProof['capture']>;
/** This factory only consumes the current quiescent Store's genuine EX.
 * An archive's old read-only SQL image needs its separate source issuer. */
export async function captureMcpInvocationRecoveryContext(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  scope: InstalledExclusiveReadSource, input: Readonly<{ runId: string; expectedRunRevision: number }>, signal?: AbortSignal) {
  assertInstalledExclusiveReadSource(scope, driver, owner);
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const assertScope = () => { assertInstalledExclusiveReadSource(scope, driver, owner); reads.assertReadActive(); };
  assertScope(); assertSqliteConnectionOwnedBy(driver, driver); assertActiveStateOwner(driver, owner);
  let materialUnits = 0, edgeCount = 0;
  const accounted = new WeakSet<object>();
  const charge = (count: number) => {
    materialUnits += count; if (materialUnits > MAX_RETAINED_MATERIAL_UNITS) unsupported();
  };
  const account = (value: unknown): void => {
    if (typeof value === 'string') { charge(16 + value.length * 2); return; }
    if (!value || typeof value !== 'object') { charge(16); return; }
    if (accounted.has(value)) return;
    accounted.add(value); charge(64);
    for (const [name, child] of Object.entries(value)) {
      charge(24 + name.length * 2); account(child);
    }
  };
  const snapshot = await readRecoveryClosure(driver, reads, input.runId);
  account(snapshot);
  const cut = immutableSnapshot(snapshot);
  materialUnits = 0; account(cut);
  if (cut.run.revision !== input.expectedRunRevision || cut.runSpec.operation !== 'agent') unsupported();
  const assembly = immutableSnapshot(await readCanonicalArtifact<RunAssemblyV1>(reads, cut.runSpec.assemblyRef));
  const bundle = immutableSnapshot(await readCanonicalArtifact<RuntimeBundleManifest>(reads, assembly.runtime.runtimeBundleRef));
  const itemRows = (connection: SqliteConnection) => connection.prepare('SELECT item_id,item_seq,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: unknown; payload_ref: string; created_at: string }>(cut.run.id)
    .map(row => ({ itemId: row.item_id, itemSeq: Number(row.item_seq), payloadRef: row.payload_ref, createdAt: row.created_at }));
  const originalItems = itemRows(driver);
  const checkpoints = (connection: SqliteConnection) => connection.prepare('SELECT id FROM checkpoints WHERE run_id=? ORDER BY id')
    .all<{ id: string }>(cut.run.id).map(row => readCheckpoint(connection, row.id));
  const originalCheckpoints = immutableSnapshot(checkpoints(driver));
  account(originalItems); account(originalCheckpoints); account(assembly); account(bundle);
  requireEqual(originalItems,
    cut.items.map(row => ({ itemId: row.itemId, itemSeq: row.itemSeq, payloadRef: row.payloadRef, createdAt: row.createdAt })), 'MCP retention actual original item rows');
  const graph: Graph = { artifacts: reads, processId: process.pid, nodes: new Map(), dependencies: new Map(), contexts: new Map(),
    continuations: new Map(), roots: [], assertions: [], assertScope,
    assertUnchanged(connection) {
      assertScope(); assertSqliteConnectionOwnedBy(driver, connection); assertActiveStateOwner(connection, owner);
      requireEqual(readRun(connection, cut.run.id), cut.run, 'MCP retention original Run cut');
      requireEqual(readInvocationJournal(connection, cut.run.id), cut.journal, 'MCP retention original complete Journal');
      requireEqual(readCheckpoint(connection, cut.latestCheckpoint.id), cut.latestCheckpoint, 'MCP retention original latest Checkpoint');
      requireEqual(checkpoints(connection), originalCheckpoints, 'MCP retention original complete ready Checkpoint history');
      requireEqual(itemRows(connection), originalItems, 'MCP retention original ordered SQL item references');
      requireEqual(readWorkerLaunchesForRun(connection, cut.run.id), cut.workerLaunches, 'MCP retention original worker births and retirement');
      requireEqual(readWorkspaceGenerationsForRun(connection, cut.run.id), cut.workspaceGenerations, 'MCP retention original generation lifecycle');
      requireEqual(readChildAllocationsForRun(connection, cut.run.id), cut.childAllocations, 'MCP retention original child accounting cut');
      for (const assert of graph.assertions) assert(connection);
      assertScope();
    } };
  const accountEdge = (parent: McpInvocationRecoveryParent) => {
    if (++edgeCount > MAX_EDGES) unsupported(); account(parent);
  };
  const assertWith = (assert: (connection: SqliteConnection) => void) => {
    if (graph.assertions.length >= MAX_ASSERTIONS) unsupported(); graph.assertions.push(assert);
  };
  const link = (ref: string, purpose: Purpose, parent: McpInvocationRecoveryParent): PendingEdge => {
    accountEdge(parent); return { ref: controlWireRef(ref), purpose, parent };
  };
  const root = (ref: string, purpose: Purpose, parent: McpInvocationRecoveryParent) => {
    accountEdge(parent); graph.roots.push(edge(graph, ref, purpose, parent));
  };
  const sameEdges = (before: PendingEdge[], after: PendingEdge[]) => requireEqual(
    before.map(value => [value.ref, value.purpose, value.parent.scope]),
    after.map(value => [value.ref, value.purpose, value.parent.scope]), 'MCP retention repeated original children');
  async function json(ref: string, purpose: McpInvocationRecoveryPurpose, expected: unknown, edges: PendingEdge[], parent: McpInvocationRecoveryParent) {
    assertScope();
    const encoded = canonicalJsonBytes(expected); if (sha256Bytes(encoded) !== controlWireRef(ref)) unsupported();
    const key = keyOf(parent, ref, purpose), existing = graph.nodes.get(key);
    if (existing) {
      if (existing.kind !== 'json' || existing.byteCount !== encoded.length) unsupported();
      sameEdges(existing.edges, edges); return;
    }
    if (graph.nodes.size >= MAX_NODES) unsupported();
    await verifyOriginalBytes(reads, ref, encoded.length); assertScope(); account(parent);
    graph.nodes.set(key, { ref, purpose, parent, kind: 'json', byteCount: encoded.length, edges });
  }
  async function bytes(ref: string, purpose: McpInvocationRecoveryPurpose, limit: number, edges: PendingEdge[], parent: McpInvocationRecoveryParent) {
    assertScope();
    const actual = await reads.readBoundedBytes(ref, limit); if (sha256Bytes(actual) !== controlWireRef(ref)) unsupported();
    const key = keyOf(parent, ref, purpose), existing = graph.nodes.get(key);
    if (existing) {
      if (existing.kind !== 'bytes' || existing.byteCount !== actual.length) unsupported();
      sameEdges(existing.edges, edges); return;
    }
    if (graph.nodes.size >= MAX_NODES) unsupported();
    assertScope(); account(parent);
    graph.nodes.set(key, { ref, purpose, parent, kind: 'bytes', byteCount: actual.length, edges });
  }
  function continuation(ref: string, purpose: McpInvocationRecoveryDependencyPurpose, parent: McpInvocationRecoveryParent, children: PendingEdge[]) {
    const selected = edge(graph, ref, purpose, parent), actual = contexts.get(selected.context);
    if (!actual) unsupported(); const previous = graph.continuations.get(actual.key) ?? [];
    for (const child of children) if (!previous.some(value => value.ref === child.ref && value.purpose === child.purpose && value.parent.scope === child.parent.scope)) previous.push(child);
    graph.continuations.set(actual.key, previous);
  }
  function parentFor(prepared: InvocationJournalEntry, claim: InvocationJournalEntry, original: Original, unknown?: InvocationJournalEntry): McpInvocationRecoveryParent {
    const parent: McpInvocationRecoveryParent = Object.freeze({ scope: canonicalSha256(['cliq-mcp-retention-original-parent-v1', cut.run.id, prepared.opId, prepared.attempt, claim.seq]),
      run: cut.run, runSpec: cut.runSpec, journal: cut.journal, checkpoints: originalCheckpoints, workerLaunches: cut.workerLaunches, workspaceGenerations: cut.workspaceGenerations,
      assembly, bundle, prepared, claim, ...(unknown ? { unknown } : {}), request: immutableSnapshot(original.request), target: immutableSnapshot(original.target), grant: immutableSnapshot(original.grant),
      registryRef: original.registry.ref, registry: original.registry.registry, registryParents: original.registry.readOriginalParents() });
    const { registry, history } = original;
    account(history.entries); account(parent);
    assertWith(connection => { registry.assertUnchanged(connection); history.assertUnchanged(connection); });
    return parent;
  }
  async function creator(ref: string, value: PlatformProcessIdentityV1, parent: McpInvocationRecoveryParent) {
    const checked = decodePlatformProcessIdentity(value);
    await json(ref, 'mcp.recovery.creator_process_identity', checked, [link(checked.executableImageDigest, 'image_bytes', parent)], parent);
  }
  const registryWalks = new Set<string>();
  const registeredChildren = new Map<string, PendingEdge[]>();
  const scoped = (parent: McpInvocationRecoveryParent, ...parts: unknown[]): McpInvocationRecoveryParent =>
    Object.freeze({ ...parent, scope: canonicalSha256([parent.scope, ...parts]) });
  async function registryMembers(parent: McpInvocationRecoveryParent) {
    if (registryWalks.has(parent.scope)) return; registryWalks.add(parent.scope);
    const retryMembers = new Map<string, PendingEdge>();
    for (const original of [...parent.registryParents].sort((left, right) => left.registry.registryRevision - right.registry.registryRevision)) {
      const registerParent: McpInvocationRecoveryParent = Object.freeze({ ...scoped(parent, 'registry', original.ref), registeredParent: original });
      const originalChildren: PendingEdge[] = [];
      if (original.target.method === 'mcp.register') {
        const request = decodeMcpMutationRequest(await readCanonicalArtifact(reads, original.target.originalRequestRef));
        if (request.method !== 'mcp.register') unsupported();
        for (const requested of original.target.requestedToolRecovery) if (requested.recovery.kind === 'retry') {
          const consent = await readCanonicalArtifact(reads, requested.recovery.explicitRiskConsentRef), assertion = await readCanonicalArtifact(reads, requested.recovery.safetyAssertionRef);
          const selected: McpRecoveryReachabilityContext = { kind: 'original_retry', request, target: original.target, consent, assertion };
          const consentParent = scoped(registerParent, 'original_retry', requested.toolName);
          for (const [purpose, ref, value] of [
            ['mcp_retry_risk_consent', requested.recovery.explicitRiskConsentRef, consent],
            ['mcp_retry_safety_assertion', requested.recovery.safetyAssertionRef, assertion],
          ] as const) {
            const edges = readMcpRecoveryArtifactEdges(purpose, value, selected).map(value => link(value.ref, value.purpose, consentParent));
            await json(ref, purpose, value, edges, consentParent);
            const child = link(ref, purpose, consentParent); retryMembers.set(`${purpose}\0${ref}`, child); originalChildren.push(child);
          }
        }
      }
      for (const tool of original.registry.tools) {
        const recovery = decodeMcpRecoveryContract(tool.recovery);
        if (recovery.kind === 'retry') {
          for (const [purpose, ref] of [['mcp_retry_risk_consent', recovery.explicitRiskConsentRef], ['mcp_retry_safety_assertion', recovery.safetyAssertionRef]] as const) {
            const child = retryMembers.get(`${purpose}\0${ref}`); if (!child) unsupported();
            if (!originalChildren.some(value => value.ref === child.ref && value.purpose === child.purpose && value.parent.scope === child.parent.scope)) originalChildren.push(child);
          }
        } else if (recovery.kind === 'reconcile') {
          const core = decodeAdminProbePayloadCore(await readCanonicalArtifact(reads, original.operation.probePayloadCoreRef));
          const originalBundle = immutableSnapshot(await readCanonicalArtifact<RuntimeBundleManifest>(reads, core.runtimeBundleRef));
          const manifest = decodeMcpRecoveryAdapterManifest(await readCanonicalArtifact(reads, recovery.adapterRef));
          const adapterContext: McpRecoveryReachabilityContext = { kind: 'adapter', bundle: originalBundle,
            releaseKeys: reads.releaseTrustRoots(), adapterRef: recovery.adapterRef };
          const adapterParent: McpInvocationRecoveryParent = Object.freeze({ ...scoped(registerParent, 'adapter', manifest.adapterId), registeredBundle: originalBundle });
          const members = new Map<string, PendingEdge>();
          const adapterChildren: PendingEdge[] = [];
          // Every signed profile member belongs to its own exact original
          // profile use, including two uses of the same content reference.
          const declared = readMcpRecoveryArtifactEdges('mcp_recovery_adapter_manifest', manifest, adapterContext);
          adapterChildren.push(link(manifest.executableDigest, 'image_bytes', adapterParent));
          for (const profile of manifest.profiles) {
            for (const [memberKind, ref, purpose] of [
              ['static_arguments', profile.staticArgumentsRef, 'mcp_recovery_static_arguments'],
              ['completed', profile.completedPredicateRef, 'mcp_recovery_predicate'],
              ['failed', profile.failedPredicateRef, 'mcp_recovery_predicate'],
            ] as const) {
              const memberParent: McpInvocationRecoveryParent = Object.freeze({ ...scoped(adapterParent, 'profile', profile.profileId, memberKind),
                recoveryProfileId: profile.profileId, recoveryToolName: profile.serverToolName, recoveryMemberKind: memberKind });
              const value = await readCanonicalArtifact(reads, ref);
              const memberContext: McpRecoveryReachabilityContext = { ...adapterContext, kind: 'profile_member', manifest, profileId: profile.profileId, memberRef: ref, memberKind };
              const edges = readMcpRecoveryArtifactEdges(purpose, value, memberContext).map(value => link(value.ref, value.purpose, memberParent));
              await json(ref, purpose, value, edges, memberParent);
              const child = link(ref, purpose, memberParent); members.set(`${profile.profileId}\0${memberKind}`, child); adapterChildren.push(child);
            }
          }
          requireEqual(adapterChildren.map(value => ({ ref: value.ref, purpose: value.purpose })), declared, 'MCP retention complete signed adapter member closure');
          await json(recovery.adapterRef, 'mcp_recovery_adapter_manifest', manifest, adapterChildren, adapterParent);
          const template = decodeMcpRecoveryStatusRequestTemplate(await readCanonicalArtifact(reads, recovery.statusRequestTemplateRef));
          const templateContext: McpRecoveryReachabilityContext = { ...adapterContext, kind: 'template', manifest,
            target: original.target, result: original.result, registryRevision: original.registry.registryRevision };
          const templateParent: McpInvocationRecoveryParent = Object.freeze({ ...scoped(registerParent, 'template', tool.name),
            recoveryProfileId: template.profileId, recoveryToolName: tool.name });
          const templateChildren = readMcpRecoveryArtifactEdges('mcp_recovery_status_template', template, templateContext).map(value => {
            if (value.purpose === 'mcp_recovery_adapter_manifest') return link(value.ref, value.purpose, adapterParent);
            if (value.purpose === 'mcp_recovery_static_arguments') {
              const child = members.get(`${template.profileId}\0static_arguments`); if (!child || child.ref !== value.ref) unsupported(); return child;
            }
            return link(value.ref, value.purpose, templateParent);
          });
          await json(recovery.statusRequestTemplateRef, 'mcp_recovery_status_template', template, templateChildren, templateParent);
          originalChildren.push(link(recovery.adapterRef, 'mcp_recovery_adapter_manifest', adapterParent),
            link(recovery.statusRequestTemplateRef, 'mcp_recovery_status_template', templateParent));
          for (const kind of ['completed', 'failed'] as const) { const member = members.get(`${recovery.profileId}\0${kind}`); if (!member) unsupported(); originalChildren.push(member); }
        }
      }
      continuation(original.ref, 'mcp_registry_revision', registerParent, originalChildren);
      if (original.ref === parent.registryRef) { continuation(original.ref, 'mcp_registry_revision', parent, originalChildren); registeredChildren.set(parent.scope, originalChildren); }
      continuation(canonicalSha256(original.target), 'mcp_admin_probe_target', registerParent, originalChildren.filter(value =>
        value.purpose === 'mcp_retry_risk_consent' || value.purpose === 'mcp_retry_safety_assertion'));
      // All of these are actual ancestors already consumed by the original
      // registry walk, never catalog objects discovered by a hash scan.
      root(original.ref, 'mcp_registry_revision', registerParent);
    }
  }
  const originals = new Map<string, McpInvocationRecoveryParent>();
  async function originalParent(prepared: InvocationJournalEntry, claim: InvocationJournalEntry, unknown?: InvocationJournalEntry) {
    const key = `${prepared.opId}\0${prepared.attempt}`; const existing = originals.get(key); if (existing) return existing;
    if (!claim.stateOwnerEpoch) unsupported();
    const original = await readMcpOriginalClaim(driver, reads, { prepared, claim, assembly, throughEpoch: claim.stateOwnerEpoch });
    const parent = parentFor(prepared, claim, original, unknown); originals.set(key, parent); await registryMembers(parent);
    await creator(original.claiming.owner.processIdentityRef, original.claiming.process, parent);
    if (original.httpRetryIdentity) {
      if (!claim.evidenceRef) unsupported();
      await json(claim.evidenceRef, 'mcp.retry.http_claim_identity', original.httpRetryIdentity, [
        link(prepared.requestRef, 'tool_request', parent), link(prepared.target, 'tool_target', parent), link(original.request.assemblyRef, 'run_assembly', parent),
        link(canonicalSha256(original.grant), 'tool_operation_grant', parent), link(original.registry.ref, 'mcp_registry_revision', parent),
        link(original.claiming.owner.processIdentityRef, 'mcp.recovery.creator_process_identity', parent),
      ], parent);
      root(claim.evidenceRef, 'mcp.retry.http_claim_identity', parent);
    }
    return parent;
  }
  async function retryClosure(ref: string, value: ReturnType<typeof decodeMcpRetryDispatchClosure>, parent: McpInvocationRecoveryParent) {
    const children = [link(value.requestRef, 'tool_request', parent), link(value.targetRef, 'tool_target', parent), link(value.grantRef, 'tool_operation_grant', parent),
      link(value.registryRef, 'mcp_registry_revision', parent), link(value.unknownEvidenceRef, 'broker_ambiguity', parent),
      link(value.budgetSettlementRef, 'budget_settlement', parent), link(value.inspectorIdentityRef, 'supervisor_inspector', parent),
      link(value.originalClaimIdentity.ref, value.originalClaimIdentity.kind === 'http_retry_binding' ? 'mcp.retry.http_claim_identity' : 'mcp.stdio.instance_identity', parent)];
    if (value.kind === 'broker_process_domain_dead') children.push(link(value.deathEvidenceRef, 'broker_process_domain_death', parent));
    await json(ref, 'mcp.retry.dispatch_closure', value, children, parent);
  }
  const retryIds = [...new Set(cut.journal.filter(entry => entry.opKind === 'mcp' && entry.replayClass === 'retry').map(entry => entry.opId))];
  for (const opId of retryIds) {
    const history = await readMcpRetryJournalHistory(driver, reads, assembly, cut.journal, opId, sampleCanonicalNow());
    for (const prepared of history.preparations) {
      const claim = history.entries.find(entry => entry.attempt === prepared.attempt && entry.phase === 'dispatch_claimed'); if (!claim) continue;
      const unknown = history.entries.find(entry => entry.attempt === prepared.attempt && entry.phase === 'unknown');
      await originalParent(prepared, claim, unknown);
    }
    for (const closure of history.closures) {
      const parent = originals.get(`${closure.data.opId}\0${closure.data.attempt}`); if (!parent) unsupported();
      const { history } = closure; account(history.entries);
      assertWith(connection => history.assertUnchanged(connection));
      const ref = canonicalSha256(closure.data); await retryClosure(ref, closure.data, parent); root(ref, 'mcp.retry.dispatch_closure', parent);
    }
  }
  let detail: TerminalDetail | undefined;
  if (cut.run.terminalDetailRef && retryIds.length) {
    detail = await readCanonicalArtifact<TerminalDetail>(reads, cut.run.terminalDetailRef);
    const closed = await validateMcpRetryTerminalHistory(driver, reads, cut, detail);
    for (const value of closed) {
      const parent = originals.get(`${value.opId}\0${value.attempt}`); if (!parent) unsupported();
      const closure = decodeMcpRetryDispatchClosure(await readCanonicalArtifact(reads, value.dispatchFenceOrDeathEvidenceRef));
      await retryClosure(value.dispatchFenceOrDeathEvidenceRef, closure, parent); root(value.dispatchFenceOrDeathEvidenceRef, 'mcp.retry.dispatch_closure', parent);
    }
  }
  const carriers = new Map<string, McpInvocationRecoveryParent>();
  if (detail) for (const reference of cut.items) {
    const item = await readCanonicalArtifact<ContinuationItem>(reads, reference.payloadRef);
    if (item.kind !== 'tool_result' || item.outcome !== 'cancelled' || !item.opId || !retryIds.includes(item.opId)) continue;
    const value = await readCanonicalArtifact(reads, item.resultRef);
    if (!value || typeof value !== 'object' || !('kind' in value) || value.kind !== 'retry_unknown_cancelled') continue;
    await validateMcpRetryCancelledItem(driver, reads, cut, detail, item);
    const result = decodeRetryUnknownCancelledResult(value), parent = originals.get(`${result.opId}\0${result.attempt}`); if (!parent) unsupported();
    await json(item.resultRef, 'mcp.retry.unused_result', result, [link(result.budgetSettlementRef, 'budget_settlement', parent),
      link(result.dispatchFenceOrDeathEvidenceRef, 'mcp.retry.dispatch_closure', parent)], parent);
    continuation(reference.payloadRef, 'continuation_item', parent, [link(item.resultRef, 'mcp.retry.unused_result', parent)]);
    carriers.set(item.resultRef, parent); root(item.resultRef, 'mcp.retry.unused_result', parent);
  }
  if (cut.run.stopIntentRef && retryIds.length) {
    const intent = decodeAgentStop(await readCanonicalArtifact(reads, cut.run.stopIntentRef), cut.run);
    if (intent.origin === 'runtime' && intent.runtimeSubtype === 'runtime') {
      const failure = await readCanonicalArtifact<RuntimeFailureEvidenceV1>(reads, intent.runtimeFailureRef);
      if (failure.failureKind === 'retry_unknown_exhausted' || failure.failureKind === 'mcp_call_resource_exhausted') {
        await validateModelFailureStop(driver, reads, cut, intent);
        const parent = carriers.get(failure.retryUnknownResultRef); if (!parent) unsupported();
        await json(intent.runtimeFailureRef, 'mcp.retry.runtime_failure', failure, [link(failure.frontierRef, 'run_frontier', parent),
          link(failure.inspectorIdentityRef, 'supervisor_inspector', parent), link(failure.retryUnknownResultRef, 'mcp.retry.unused_result', parent)], parent);
        continuation(cut.run.stopIntentRef, 'agent_stop', parent, [link(intent.runtimeFailureRef, 'mcp.retry.runtime_failure', parent)]);
        root(intent.runtimeFailureRef, 'mcp.retry.runtime_failure', parent);
      }
    }
  }
  const waitParent = (base: McpInvocationRecoveryParent, wait: McpInvocationWaitV1, preparation?: McpStatusProbePreparationV1): McpInvocationRecoveryParent =>
    Object.freeze({ ...scoped(base, 'status-wait', canonicalSha256(wait)), wait, ...(preparation ? { preparation } : {}) });
  function recoveryChild(base: McpInvocationRecoveryParent, source: StatusSource, ref: string, purpose: McpRecoveryReachabilityPurpose): PendingEdge {
    const matches = registeredChildren.get(base.scope)?.filter(value => value.ref === ref && value.purpose === purpose &&
      (purpose === 'mcp_recovery_adapter_manifest' || value.parent.recoveryProfileId === source.profile.profileId && value.parent.recoveryToolName === source.original.execution.serverToolName));
    if (!matches?.length || matches.some(value => value.parent.scope !== matches[0]?.parent.scope)) unsupported();
    const selected = matches[0]; if (!selected) unsupported(); return selected;
  }
  function originalStatusEdges(base: McpInvocationRecoveryParent, source: StatusSource): PendingEdge[] {
    return [link(source.prepared.requestRef, 'tool_request', base), link(source.prepared.target, 'tool_target', base),
      link(canonicalSha256(source.original.grant), 'tool_operation_grant', base), link(source.registry.ref, 'mcp_registry_revision', base),
      link(controlWireRef(source.claim.evidenceRef), 'mcp.stdio.instance_identity', base),
      recoveryChild(base, source, source.recovery.adapterRef, 'mcp_recovery_adapter_manifest'),
      recoveryChild(base, source, source.recovery.statusRequestTemplateRef, 'mcp_recovery_status_template'),
      recoveryChild(base, source, source.recovery.completedPredicateRef, 'mcp_recovery_predicate'),
      recoveryChild(base, source, source.recovery.failedPredicateRef, 'mcp_recovery_predicate')];
  }
  const preparedStatus = new Map<string, { parent: McpInvocationRecoveryParent }>();
  async function statusUserData(prepared: PreparedStatus, source: StatusSource, base: McpInvocationRecoveryParent, parent: McpInvocationRecoveryParent): Promise<PendingEdge[]> {
    const state = prepared.wait.probeState; if (state.phase !== 'user_in_flight') return [];
    const original = await readMcpStatusUserSource(driver, reads, cut, prepared.wait), requestId = state.dispatch.controlRequestId;
    const { requestDigest: _digest, ...core } = original.request;
    await json(state.dispatch.controlRequestDigest, 'mcp.status.user_request_core', core,
      [link(prepared.preparation.previousWaitingSubjectRef, 'mcp.status.wait', waitParent(base, prepared.previous))], parent);
    if (!original.response.ok || original.response.result.method !== 'run.reconcile') unsupported();
    const run = original.response.result.snapshot.run;
    if (run.frontierRef !== prepared.wait.frontierRef || run.resultRef || run.terminalDetailRef || run.activeWorkerLaunchId ||
        !originalCheckpoints.some(checkpoint => checkpoint.id === run.latestCheckpointId && checkpoint.runId === cut.run.id)) unsupported();
    const responseChildren = [link(canonicalSha256(prepared.wait), 'mcp.status.wait', parent),
      link(run.specRef, 'run_spec', base), link(prepared.wait.frontierRef, 'run_frontier', base)];
    if (run.stopIntentRef) responseChildren.push(link(run.stopIntentRef, 'agent_stop', base));
    if (run.parentCancellationRef) responseChildren.push(link(run.parentCancellationRef, 'parent_cancellation', base));
    await json(original.row.responseRef, 'mcp.status.user_first_response', original.response, responseChildren, parent);
    const snapshot = immutableSnapshot(original.row);
    account(snapshot);
    const principalId = source.original.principalId;
    assertWith(connection => requireEqual(readControlRequest(connection, principalId, 'run.reconcile', requestId), snapshot,
      'MCP retention exact original authenticated user request/channel/response/commit row'));
    return [link(state.dispatch.controlRequestDigest, 'mcp.status.user_request_core', parent), link(original.row.responseRef, 'mcp.status.user_first_response', parent),
      link(original.row.channelIdentityRef, 'control_channel', parent)];
  }
  async function statusPreparation(prepared: PreparedStatus, source: StatusSource, base: McpInvocationRecoveryParent) {
    const ref = prepared.dispatch.preparationRef, parent = waitParent(base, prepared.wait, prepared.preparation), key = keyOf(parent, ref, 'mcp.status.preparation');
    const existing = preparedStatus.get(key); if (existing) return existing;
    const { history } = prepared, { registry, original: { history: effectHistory } } = source;
    account(history.entries); account(effectHistory.entries);
    assertWith(connection => { history.assertUnchanged(connection); registry.assertUnchanged(connection); effectHistory.assertUnchanged(connection); });
    const previous = link(prepared.preparation.previousWaitingSubjectRef, 'mcp.status.wait', waitParent(base, prepared.previous));
    const request = prepared.request, sourceEdges = originalStatusEdges(base, source);
    await bytes(request.statusRequest.ref, 'mcp.status.request_frame', request.statusRequest.bytes.length, [], parent);
    await json(request.targetArtifact.ref, 'mcp.status.broker_target', request.target,
      [previous, ...sourceEdges, link(request.statusRequest.ref, 'mcp.status.request_frame', parent)], parent);
    await json(request.requestArtifact.ref, 'mcp.status.broker_request', request.request,
      [previous, link(request.targetArtifact.ref, 'mcp.status.broker_target', parent), link(request.statusRequest.ref, 'mcp.status.request_frame', parent)], parent);
    await bytes(prepared.preparation.nativeRecipeRef, 'mcp.status.native_recipe', prepared.recipeBytes.length,
      [link(source.manifest.executableDigest, 'image_bytes', base)], parent);
    await creator(prepared.original.owner.processIdentityRef, prepared.original.process, parent);
    await json(ref, 'mcp.status.preparation', prepared.preparation, [previous, ...sourceEdges,
      link(request.requestArtifact.ref, 'mcp.status.broker_request', parent), link(request.targetArtifact.ref, 'mcp.status.broker_target', parent),
      link(prepared.preparation.nativeRecipeRef, 'mcp.status.native_recipe', parent), link(prepared.preparation.plannedContainmentRef, 'process_containment_plan', parent),
      link(prepared.preparation.sandboxLaunchSpecRef, 'sandbox_launch_spec', parent), link(prepared.original.owner.processIdentityRef, 'mcp.recovery.creator_process_identity', parent)], parent);
    const user = await statusUserData(prepared, source, base, parent);
    await json(canonicalSha256(prepared.dispatch), 'mcp.status.dispatch', prepared.dispatch,
      [previous, link(ref, 'mcp.status.preparation', parent), ...user], parent);
    const selected = { parent }; preparedStatus.set(key, selected); return selected;
  }
  const retirementNodes = new Map<string, PendingEdge>();
  async function statusRetirement(retirement: StatusRetirement, prepared: PreparedStatus, source: StatusSource, base: McpInvocationRecoveryParent) {
    const selected = await statusPreparation(prepared, source, base), value = retirement.value, ref = canonicalSha256(value);
    const parent: McpInvocationRecoveryParent = Object.freeze({ ...scoped(selected.parent, 'retirement', ref), retirement: value, retirementEvidence: retirement.evidence });
    const key = keyOf(parent, ref, 'mcp.status.retirement'), existing = retirementNodes.get(key); if (existing) return existing;
    const { history } = retirement; account(history.entries);
    assertWith(connection => history.assertUnchanged(connection));
    const bindingEdges = [link(canonicalSha256(prepared.wait), 'mcp.status.wait', selected.parent),
      link(prepared.preparation.previousWaitingSubjectRef, 'mcp.status.wait', waitParent(base, prepared.previous)), ...originalStatusEdges(base, source),
      link(prepared.preparation.brokerRequestRef, 'mcp.status.broker_request', selected.parent),
      link(prepared.preparation.brokerTargetRef, 'mcp.status.broker_target', selected.parent),
      link(prepared.preparation.plannedContainmentRef, 'process_containment_plan', selected.parent),
      link(prepared.preparation.sandboxLaunchSpecRef, 'sandbox_launch_spec', selected.parent),
      link(prepared.preparation.nativeRecipeRef, 'mcp.status.native_recipe', selected.parent)];
    const images = retirement.lifecycle.images;
    const lifecycleEdges = [...bindingEdges, ...[images.server.digest, images.client.digest, images.isolation.digest].map(ref => link(ref, 'image_bytes', parent))];
    const native = value.nativeClosure;
    await bytes(native.lifecycleRawRef, 'mcp.status.native_lifecycle_raw', 16_777_216, lifecycleEdges, parent);
    await json(native.lifecycleProjectionRef, 'mcp.status.native_lifecycle_projection', retirement.lifecycle,
      [link(native.lifecycleRawRef, 'mcp.status.native_lifecycle_raw', parent), ...lifecycleEdges], parent);
    const children = [link(native.lifecycleRawRef, 'mcp.status.native_lifecycle_raw', parent), link(native.lifecycleProjectionRef, 'mcp.status.native_lifecycle_projection', parent),
      link(value.retirementEvidenceRef, retirement.evidence.kind === 'containment_all_descendants_dead' ? 'process_containment_death' : 'process_containment_no_spawn', parent),
      link(retirement.evidence.inspectorIdentityRef, 'supervisor_inspector', parent)];
    if (value.processContainmentRef) children.push(link(value.processContainmentRef, 'process_containment', parent));
    if ('cleanupRawRef' in native) {
      // The full production reader already checked separate original birth
      // bytes, current cleanup bytes, strictly newer owner and actual old
      // creator-domain death. No joined object is borrowed across this XOR.
      const cleanup = await readCanonicalArtifact(reads, native.cleanupProjectionRef);
      await bytes(native.cleanupRawRef, 'mcp.status.native_cleanup_raw', 16_777_216, bindingEdges, parent);
      await json(native.cleanupProjectionRef, 'mcp.status.native_cleanup_projection', cleanup,
        [link(native.cleanupRawRef, 'mcp.status.native_cleanup_raw', parent), ...bindingEdges], parent);
      children.push(link(native.cleanupRawRef, 'mcp.status.native_cleanup_raw', parent), link(native.cleanupProjectionRef, 'mcp.status.native_cleanup_projection', parent));
      const creatorDomain = value.creatorProcessDomain; if (!creatorDomain) unsupported();
      const process = decodePlatformProcessIdentity(await readCanonicalArtifact(reads, creatorDomain.creatorProcessIdentityRef));
      await creator(creatorDomain.creatorProcessIdentityRef, process, parent);
      children.push(link(creatorDomain.creatorProcessIdentityRef, 'mcp.recovery.creator_process_identity', parent));
    }
    await json(ref, 'mcp.status.retirement', value, children, parent);
    const result = link(ref, 'mcp.status.retirement', parent); retirementNodes.set(key, result); return result;
  }
  async function statusCapture(capture: StatusCapture, prepared: PreparedStatus, source: StatusSource, base: McpInvocationRecoveryParent) {
    const selected = await statusPreparation(prepared, source, base), value = decodeMcpStatusCapture(capture.value), ref = canonicalSha256(value);
    const retired = await statusRetirement(capture.retirement, prepared, source, base), children: PendingEdge[] = [retired];
    if (!Array.isArray(value.captures)) unsupported();
    for (const item of value.captures) {
      const descriptor = controlWireRecord(item, ['phase', 'captureRef']), captureRef = controlWireRef(descriptor.captureRef);
      const original = await readMcpStdioCapture(reads, captureRef);
      if (original.capture.phase !== descriptor.phase) unsupported();
      await json(captureRef, 'mcp.status.finite_capture', original.capture, [link(original.capture.rawResponseRef, 'opaque_blob', selected.parent)], selected.parent);
      children.push(link(captureRef, 'mcp.status.finite_capture', selected.parent));
    }
    const responseRef = controlWireRef(value.statusResponseRef);
    await json(responseRef, 'mcp.status.response', capture.projection.response, [], selected.parent);
    children.push(link(responseRef, 'mcp.status.response', selected.parent), link(canonicalSha256(prepared.wait), 'mcp.status.wait', selected.parent));
    await json(ref, 'mcp.status.capture', value, children, selected.parent); return link(ref, 'mcp.status.capture', selected.parent);
  }
  async function statusProof(proof: StatusProof, source: StatusSource, base: McpInvocationRecoveryParent) {
    const selected = await statusPreparation(proof.prepared, source, base), wrapper = proof.wrapper;
    const children = [link(wrapper.waitingSubjectRef, 'mcp.status.wait', selected.parent), link(wrapper.inspectorIdentityRef, 'supervisor_inspector', selected.parent)];
    if (wrapper.outcome === 'subject_observation') {
      if (!proof.evidence || !proof.capture) unsupported();
      const captured = await statusCapture(proof.capture, proof.prepared, source, base), evidence = proof.evidence;
      await json(wrapper.subjectEvidenceRef, 'mcp.status.subject_evidence', evidence, [captured,
        link(wrapper.waitingSubjectRef, 'mcp.status.wait', selected.parent), ...originalStatusEdges(base, source),
        link(evidence.statusResponseRef, 'mcp.status.response', selected.parent)], selected.parent);
      children.push(link(wrapper.subjectEvidenceRef, 'mcp.status.subject_evidence', selected.parent));
    } else {
      if (!proof.closure) unsupported();
      const retired = await statusRetirement(proof.retirement, proof.prepared, source, base), closure = proof.closure;
      const closureChildren = [retired, link(wrapper.waitingSubjectRef, 'mcp.status.wait', selected.parent),
        link(closure.inspectorIdentityRef, 'supervisor_inspector', selected.parent)];
      if (proof.lateCapture) closureChildren.push(await statusCapture(proof.lateCapture, proof.prepared, source, base));
      const purpose = wrapper.outcome === 'probe_cancelled' ? 'mcp.status.cancellation_closure' as const : 'mcp.status.timeout_closure' as const;
      const ref = wrapper.outcome === 'probe_cancelled' ? wrapper.cancellationClosureRef : wrapper.timeoutClosureRef;
      await json(ref, purpose, closure, closureChildren, selected.parent); children.push(link(ref, purpose, selected.parent));
    }
    const ref = canonicalSha256(wrapper); await json(ref, 'mcp.status.probe_evidence', wrapper, children, selected.parent);
    return link(ref, 'mcp.status.probe_evidence', selected.parent);
  }
  const waitWalks = new Map<string, PendingEdge>();
  async function statusWaitGraph(value: McpInvocationWaitV1, source: StatusSource, base: McpInvocationRecoveryParent) {
    const key = `${base.scope}\0${canonicalSha256(value)}`, previous = waitWalks.get(key); if (previous) return previous;
    // This real reader validates the entire monotonic wait/nonce/count/backoff
    // chain before this module can declare any of its typed data edges.
    const history = await readMcpStatusWaitHistory(driver, reads, cut, value);
    for (const ref of history.history) {
      const wait = decodeMcpInvocationWait(await readCanonicalArtifact(reads, ref)), state = wait.probeState;
      const preparation = state.phase === 'automatic_in_flight' || state.phase === 'user_in_flight'
        ? await readMcpStatusProbePreparation(driver, reads, wait, source) : undefined;
      const parent = waitParent(base, wait, preparation?.preparation), children = [link(wait.frontierRef, 'run_frontier', base), ...originalStatusEdges(base, source)];
      if (preparation) {
        const selected = await statusPreparation(preparation, source, base);
        children.push(link(canonicalSha256(preparation.dispatch), 'mcp.status.dispatch', selected.parent));
      } else if (state.phase === 'automatic_exhausted' || state.phase === 'automatic_pending' && state.automaticProbeCount !== 0) {
        const proof = await readMcpStatusProbeEvidence(driver, reads, source, state.lastProbeEvidenceRef, state.lastProbeEvidenceDigest);
        children.push(await statusProof(proof, source, base));
      }
      await json(ref, 'mcp.status.wait', wait, children, parent);
      waitWalks.set(`${base.scope}\0${ref}`, link(ref, 'mcp.status.wait', parent));
    }
    const selected = waitWalks.get(key); if (!selected) unsupported(); return selected;
  }
  const statusSources = new Map<string, { source: StatusSource; parent: McpInvocationRecoveryParent }>();
  async function statusSource(source: StatusSource) {
    const key = `${source.prepared.opId}\0${source.prepared.attempt}`, previous = statusSources.get(key); if (previous) return previous;
    const parent = parentFor(source.prepared, source.claim, source.original, source.unknown);
    await registryMembers(parent); await creator(source.original.claiming.owner.processIdentityRef, source.original.claiming.process, parent);
    const value = { source, parent }; statusSources.set(key, value); return value;
  }
  if (cut.run.waitingOnRef) {
    const value = await readCanonicalArtifact(reads, cut.run.waitingOnRef);
    if (value && typeof value === 'object' && 'subject' in value && value.subject && typeof value.subject === 'object' &&
        'recovery' in value.subject && value.subject.recovery === 'mcp_reconcile') {
      const wait = decodeMcpInvocationWait(value), history = await readMcpStatusWaitHistory(driver, reads, cut, wait), selected = await statusSource(history.source);
      const waiting = await statusWaitGraph(wait, selected.source, selected.parent); root(waiting.ref, waiting.purpose, waiting.parent);
    }
  }
  const itemData = new Map<string, ContinuationItem>();
  const statusEntries = cut.journal.filter(entry => entry.opKind === 'mcp' && entry.replayClass === 'reconcile' && entry.phase === 'prepared');
  for (const prepared of statusEntries) {
    const entries = cut.journal.filter(entry => entry.opId === prepared.opId && entry.attempt === prepared.attempt), terminal = entries.at(-1);
    if (entries.length !== 4 || !terminal || !['completed', 'failed'].includes(terminal.phase)) continue;
    const history = await readMcpReconciledEffectHistory(driver, reads, cut, prepared, terminal), selected = await statusSource(history.source);
    await statusWaitGraph(history.proof.wait, selected.source, selected.parent);
    const proof = await statusProof(history.proof, selected.source, selected.parent);
    await json(history.reference, 'mcp.status.reconciled_effect_result', history.result, [proof,
      link(history.result.budgetSettlementRef, 'budget_settlement', selected.parent), ...originalStatusEdges(selected.parent, selected.source)], selected.parent);
    root(history.reference, 'mcp.status.reconciled_effect_result', selected.parent);
    if (!itemData.size) for (const reference of cut.items) {
      const item = await readCanonicalArtifact<ContinuationItem>(reads, reference.payloadRef);
      account(item); itemData.set(reference.itemId, item);
    }
    await validateMcpReconciledToolResult(driver, reads, cut, prepared, terminal, itemData, originalCheckpoints);
    const items = [...itemData.values()].filter(item => item.kind === 'tool_result' && item.opId === prepared.opId), item = items[0];
    if (items.length !== 1 || item?.kind !== 'tool_result') unsupported();
    const payload = await readCanonicalArtifact<ToolResultPayloadV1>(reads, item.resultRef);
    if (payload.outcome !== 'error' || payload.code !== history.result.code) unsupported();
    const model = await readCanonicalArtifact<ToolResultModelContentV1>(reads, payload.modelContentRef);
    await json(payload.modelContentRef, 'mcp.status.model_content', model, [], selected.parent);
    await json(item.resultRef, 'mcp.status.tool_result_payload', payload,
      [link(payload.modelContentRef, 'mcp.status.model_content', selected.parent), link(history.reference, 'mcp.status.reconciled_effect_result', selected.parent)], selected.parent);
    const row = cut.items.find(reference => reference.itemId === item.itemId); if (!row) unsupported();
    continuation(row.payloadRef, 'continuation_item', selected.parent, [link(item.resultRef, 'mcp.status.tool_result_payload', selected.parent)]);
    root(item.resultRef, 'mcp.status.tool_result_payload', selected.parent);
  }
  assertScope();
  // A missing child purpose/context aborts the entire caller's GC pass. It
  // never degrades to a partial closure or a catalog-wide reference allowlist.
  for (const node of graph.nodes.values()) for (const child of node.edges) {
    if (purposes.has(child.purpose) && !graph.nodes.has(keyOf(child.parent, child.ref, child.purpose))) unsupported();
  }
  itemData.clear(); statusSources.clear(); preparedStatus.clear();
  return Object.freeze({ roots: Object.freeze([...graph.roots]), assertUnchanged(connection: SqliteConnection) { graph.assertUnchanged(connection); } });
}
