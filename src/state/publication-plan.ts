import { setImmediate as yieldToEventLoop } from 'node:timers/promises';
import { planArtifactBytes, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, identityHash } from '../kernel/identity.js';
import { decodeDeliveryCaptureTopology, decodeDeliveryPlan, type DeliveryPlan, type PublicationDesiredEntry, type PublicationExpectedEntry,
  type PublicationOperation } from '../kernel/publication.js';
import type { WorkspaceDiffOperationV1, WorkspaceDiffV1 } from '../kernel/result.js';
import type { SourceManifest, WorkspaceEntry } from '../kernel/types.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { decodeFrozenIgnoreRules, decodeSourceManifest, decodeSourceProjection, decodeWorkspaceEntries, decodeWorkspaceIdentity } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { CandidateSourceLimitError } from './result-source.js';
import { checkEntries, checkSourceManifest, checkProjection } from './source-validation.js';
import { readSourceProjectionData, sameSourceGit } from './source-projection-data.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { decodeRepositoryIdentity } from './repository-identity.js';

export type DeliveryPublicationPlanInput = Readonly<Pick<DeliveryPlan, 'deliveryRunId' | 'sourceRunResultRef' | 'sourceBaseRef' |
  'sourceDesiredRef' | 'capturedWorkspaceRef' | 'captureTopologyRef' | 'desiredSourceRef' | 'diffRef'>>;
const compare = (left: string, right: string) => Buffer.compare(Buffer.from(left), Buffer.from(right));
const parentPath = (path: string) => path.slice(0, Math.max(0, path.lastIndexOf('/')));
function mismatch(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }

/** Immutable data planning, not source-inspection provenance, approval, claim,
 * a live target check or native proof. Those consumers independently bind this
 * exact plan and its original topology to the current owning StateOwner cut. */
export async function planDeliveryPublication(artifacts: ArtifactCatalog, input: DeliveryPublicationPlanInput, signal?: AbortSignal, sandboxProfileRef?: string):
  Promise<Readonly<{ plan: DeliveryPlan; planRef: string; metadata: PublishedArtifact[]; publications: PlannedArtifact[] }>> {
  signal?.throwIfAborted();
  if (typeof input.deliveryRunId !== 'string' || !input.deliveryRunId || input.deliveryRunId.length > 128 ||
      !/^[A-Za-z0-9_-]+$/u.test(input.deliveryRunId)) throw new TypeError('delivery publication requires a canonical Run id');
  for (const [key, ref] of Object.entries(input)) if (key !== 'deliveryRunId') assertArtifactRef(ref);
  const metadata = new Map<string, PublishedArtifact>();
  const read = async <T>(ref: string, schemaKind: string): Promise<T> => {
    signal?.throwIfAborted(); const value = await readCanonicalArtifact<T>(artifacts, ref); signal?.throwIfAborted();
    metadata.set(ref, { ref, mediaType: 'application/json', schemaKind, byteLength: canonicalJsonBytes(value).length }); return value;
  };
  const sources = [];
  for (const [ref, role] of [[input.capturedWorkspaceRef, 'base'], [input.desiredSourceRef, 'result']] as const) {
    const source = decodeSourceManifest(await read(ref, 'cliq-source-manifest-v1'));
    checkSourceManifest(source);
    if (source.role !== role) mismatch('publication source has a different base/result role');
    const entries = decodeWorkspaceEntries(await read(source.entriesRef, 'cliq-workspace-entries-v1')); checkEntries(entries);
    if (entries.treeDigest !== source.treeDigest) mismatch('publication source tree differs from its entries');
    sources.push({ source, entries });
  }
  const [captured, desired] = sources;
  if (!sameSourceGit(captured.source, desired.source)) mismatch('publication desired source changed captured A Git identity');
  for (const key of ['workspaceIdentityDigest', 'sourceProjectionRef', 'sourceProjectionDigest', 'frozenIgnoreRulesRef', 'frozenIgnoreRulesDigest'] as const)
    if (captured.source[key] !== desired.source[key]) mismatch('publication source projection, ignore or workspace identity differs');
  const projection = decodeSourceProjection(await read(captured.source.sourceProjectionRef, 'cliq-source-projection-v1')); checkProjection(projection);
  const rules = decodeFrozenIgnoreRules(await read(captured.source.frozenIgnoreRulesRef, 'cliq-frozen-ignore-rules-v1'));
  if (!exactKeys(rules, ['schemaVersion', 'format', 'matcherVersion', 'sources', 'rules', 'rulesDigest', ...(captured.source.git ? ['repositoryIdentityDigest'] : [])]) ||
      rules.matcherVersion !== 'cliq-git-wildmatch-v1' || !Array.isArray(rules.sources) || !Array.isArray(rules.rules))
    mismatch('publication frozen ignore rules have invalid fields');
  if (projection.projectionDigest !== captured.source.sourceProjectionDigest || projection.frozenIgnoreRulesRef !== captured.source.frozenIgnoreRulesRef ||
      projection.frozenIgnoreRulesDigest !== captured.source.frozenIgnoreRulesDigest || rules.rulesDigest !== captured.source.frozenIgnoreRulesDigest)
    mismatch('publication source projection or frozen ignore closure differs');
  const profile = captured.source.git && sandboxProfileRef ? decodeSandboxProfile(await read(sandboxProfileRef, 'cliq-sandbox-profile-v1')) : undefined;
  if (captured.source.git && !profile) mismatch('Git publication lost its frozen resource profile');
  const classification = profile ? await readSourceProjectionData(artifacts, captured.source, projection, profile.resources, signal) : undefined;
  if (!profile && (rules.sources.length || rules.rules.length || projection.classificationIndexRef)) mismatch('non-Git publication carries unproven classification');
  const topology = decodeDeliveryCaptureTopology(await read(input.captureTopologyRef, 'cliq-delivery-capture-topology-v1'));
  const identity = decodeWorkspaceIdentity(await read(topology.workspaceIdentityRef, 'cliq-workspace-identity-v1'));
  if (identity.kind !== 'live' || !!identity.repositoryIdentityRef !== !!captured.source.git || identity.identityDigest !== topology.workspaceIdentityDigest ||
      topology.capturedWorkspaceRef !== input.capturedWorkspaceRef || topology.workspaceIdentityDigest !== captured.source.workspaceIdentityDigest ||
      identity.rootIdentity.deviceId !== topology.rootIdentity.deviceId || identity.rootIdentity.fileId !== topology.rootIdentity.fileId ||
      identity.rootIdentity.ownerUid !== topology.rootIdentity.ownerUid) mismatch('publication topology does not close its captured workspace and original root');
  if (identity.repositoryIdentityRef) {
    const repository = decodeRepositoryIdentity(await read(identity.repositoryIdentityRef, 'cliq-repository-identity-v2'));
    if (repository.schemaVersion !== 2 || repository.repositoryIdentityDigest !== captured.source.git!.repositoryIdentityDigest ||
        repository.repositoryIdentityDigest !== identity.repositoryIdentityDigest) mismatch('publication repository differs from captured A');
  }
  const before = new Map(captured.entries.entries.map(entry => [entry.path, entry])), after = new Map(desired.entries.entries.map(entry => [entry.path, entry]));
  const directories = new Map(topology.directories.map(entry => [entry.path, entry])), modes = new Map(topology.fileModes.map(entry => [entry.path, entry.mode]));
  if (directories.size !== captured.entries.entries.filter(entry => entry.kind === 'directory').length ||
      modes.size !== captured.entries.entries.filter(entry => entry.kind === 'file').length) mismatch('publication topology does not cover exactly the captured graph');
  const files = new Map<string, number>();
  for (const { entries } of sources) for (const entry of entries.entries) {
    if (classification ? !classification.includes(entry) : projection.explicitExcludes.some(selector => entry.path === selector.path || selector.scope === 'subtree' && entry.path.startsWith(`${selector.path}/`)))
      mismatch('publication source includes a frozen excluded path');
    if (entry.kind === 'file') {
      const size = files.get(entry.blobRef);
      if (size !== undefined && size !== entry.size) mismatch('publication graph aliases a blob with a different length');
      files.set(entry.blobRef, entry.size);
    }
  }
  for (const entry of captured.entries.entries) {
    if (entry.kind === 'directory' && !directories.has(entry.path) || entry.kind === 'file' &&
      (modes.get(entry.path) === undefined || (modes.get(entry.path)! & 0o111 ? 0o755 : 0o644) !== entry.mode))
      mismatch('publication raw captured mode does not match its normalized source entry');
  }
  for (const [ref, byteLength] of files) {
    for await (const _ of artifacts.readChunks(ref, byteLength)) signal?.throwIfAborted();
    metadata.set(ref, { ref, byteLength, mediaType: 'application/octet-stream', schemaKind: 'cliq-workspace-file-v1' });
  }
  const paths = [...new Set([...before.keys(), ...after.keys()])].sort(compare), diffOperations: WorkspaceDiffOperationV1[] = [];
  let changedBytes = 0;
  for (const path of paths) {
    const old = before.get(path), next = after.get(path);
    if (old && next && canonicalJsonBytes(old).equals(canonicalJsonBytes(next))) continue;
    diffOperations.push(!old ? { path, kind: 'add', after: next! } : !next ? { path, kind: 'delete', before: old } : { path, kind: 'modify', before: old, after: next });
    if (next?.kind === 'file' && (old?.kind !== 'file' || old.blobRef !== next.blobRef || old.size !== next.size)) changedBytes += next.size;
  }
  if (diffOperations.length > projection.maxChangedPaths) throw new CandidateSourceLimitError('changed_paths', diffOperations.length, projection.maxChangedPaths);
  if (!Number.isSafeInteger(changedBytes)) mismatch('publication changed byte count overflows');
  if (changedBytes > projection.maxChangedBytes) throw new CandidateSourceLimitError('changed_bytes', changedBytes, projection.maxChangedBytes);
  const expectedDiff: WorkspaceDiffV1 = { schemaVersion: 1, format: 'cliq-workspace-diff-v1', baseSourceRef: input.capturedWorkspaceRef,
    resultSourceRef: input.desiredSourceRef, operations: diffOperations, diffDigest: '' };
  expectedDiff.diffDigest = digestOmitting(expectedDiff, 'diffDigest');
  const suppliedDiff = await read(input.diffRef, expectedDiff.format);
  if (!canonicalJsonBytes(suppliedDiff).equals(canonicalJsonBytes(expectedDiff))) mismatch('publication diff is not the exact captured-to-desired diff');
  const expected = (entry: WorkspaceEntry): PublicationExpectedEntry => entry.kind === 'directory' ? {
    kind: 'directory', mode: directories.get(entry.path)!.mode, identityDigest: directories.get(entry.path)!.identityDigest, empty: true
  } : entry.kind === 'file' ? { kind: 'file', mode: modes.get(entry.path)!, digest: entry.blobRef } : { kind: 'symlink', target: entry.target, digest: entry.targetDigest };
  const wanted = (entry: WorkspaceEntry): PublicationDesiredEntry => entry.kind === 'directory' ? { kind: 'directory', mode: 493 } :
    entry.kind === 'file' ? { kind: 'file', mode: entry.mode, digest: entry.blobRef } : { kind: 'symlink', target: entry.target, digest: entry.targetDigest };
  const operations = new Map<string, PublicationOperation>();
  for (let index = 0; index < diffOperations.length; index++) {
    if (index && index % 1024 === 0) { await yieldToEventLoop(); signal?.throwIfAborted(); }
    const change = diffOperations[index], old = before.get(change.path), next = after.get(change.path);
    const kind = !old ? next!.kind === 'directory' ? 'mkdir' : 'create' : !next ? 'delete' : 'replace';
    const operationId = identityHash('cliq-publication-operation-v1', input.deliveryRunId, kind, change.path);
    const base = { index: 0, operationId, path: change.path, parent: { kind: 'existing_directory' as const, expectedIdentityDigest: topology.rootIdentity.identityDigest } };
    // Every permanent claim owns a distinct private arena. Fixed components
    // cannot collide with user paths and need no workspace sibling allocator.
    const staging = kind === 'create' || kind === 'replace' ? { stagingName: 'desired', stagingExpected: { kind: 'absent' as const } } : undefined;
    const quarantine = kind === 'delete' || kind === 'replace' ? { quarantineName: 'preimage', quarantineExpected: { kind: 'absent' as const } } : undefined;
    let operation: PublicationOperation;
    if (kind === 'mkdir') operation = { ...base, kind, expected: { kind: 'absent' }, desired: { kind: 'directory', mode: 493 } };
    else if (kind === 'create') operation = { ...base, kind, expected: { kind: 'absent' }, desired: wanted(next!) as Exclude<PublicationDesiredEntry, { kind: 'directory' }>, ...staging! };
    else if (kind === 'delete') operation = { ...base, kind, expected: expected(old!), desired: { kind: 'absent' }, ...quarantine! };
    else operation = { ...base, kind, expected: expected(old!), desired: wanted(next!), ...staging!, ...quarantine! };
    operations.set(change.path, operation);
  }
  const dependencies = new Map<string, number>(), successors = new Map<string, string[]>();
  const edge = (first: string, second: string) => {
    successors.set(first, [...(successors.get(first) ?? []), second]); dependencies.set(second, (dependencies.get(second) ?? 0) + 1);
  };
  for (const operation of operations.values()) {
    const path = parentPath(operation.path), priorParent = before.get(path), nextParent = after.get(path), parentOperation = operations.get(path);
    if (path && nextParent?.kind === 'directory' && priorParent?.kind !== 'directory') {
      if (!parentOperation || parentOperation.desired.kind !== 'directory') mismatch('publication creation lacks its exact parent creator');
      operation.parent = { kind: 'planned_directory', createdByOperationId: parentOperation.operationId }; edge(path, operation.path);
    } else {
      const directory = path ? directories.get(path) : topology.rootIdentity;
      if (!directory) mismatch('publication existing parent is absent from the original capture');
      operation.parent = { kind: 'existing_directory', expectedIdentityDigest: directory.identityDigest };
    }
    if (before.has(operation.path) && parentOperation?.expected.kind === 'directory' && parentOperation.desired.kind !== 'directory') edge(operation.path, path);
  }
  // Byte-ordered min-heap makes the independent-operation tie deterministic
  // without repeatedly sorting or scanning the whole graph after each effect.
  const ready: string[] = [];
  const push = (value: string) => { let index = ready.length; ready.push(value); while (index) {
    const parent = (index - 1) >>> 1; if (compare(ready[parent], value) <= 0) break; ready[index] = ready[parent]; index = parent; ready[index] = value;
  } };
  const pop = () => { const value = ready[0], last = ready.pop()!; if (ready.length) { let index = 0; ready[0] = last;
    for (;;) { let child = index * 2 + 1; if (child >= ready.length) break; if (child + 1 < ready.length && compare(ready[child + 1], ready[child]) < 0) child++;
      if (compare(last, ready[child]) <= 0) break; ready[index] = ready[child]; index = child; ready[index] = last;
    } } return value; };
  for (const path of operations.keys()) if (!dependencies.has(path)) push(path);
  const ordered: PublicationOperation[] = [];
  while (ready.length) {
    const path = pop(), operation = operations.get(path)!; ordered.push({ ...operation, index: ordered.length });
    for (const next of successors.get(path) ?? []) { const remaining = dependencies.get(next)! - 1; dependencies.set(next, remaining); if (!remaining) push(next); }
  }
  if (ordered.length !== operations.size) mismatch('publication dependency graph is cyclic');
  const createdDirectories = ordered.filter(operation => operation.desired.kind === 'directory' && operation.expected.kind !== 'directory')
    .sort((a, b) => b.path.split('/').length - a.path.split('/').length || compare(a.path, b.path));
  const plan = decodeDeliveryPlan({ schemaVersion: 1, ...input, captureTopologyDigest: topology.topologyDigest,
    mergeAlgorithm: 'cliq-diff3-v1', publicationStateMachine: 'cliq-publish-v1', forwardOperations: ordered,
    abortOperations: createdDirectories.map((operation, index) => ({ index, operationId: identityHash('cliq-publication-abort-v1', operation.operationId),
      kind: 'abort_rmdir', path: operation.path, createdByOperationId: operation.operationId,
      quarantineName: 'preimage', quarantineExpected: { kind: 'absent' } })) });
  signal?.throwIfAborted();
  const bytes = canonicalJsonBytes(plan), artifact = planArtifactBytes(bytes, 'application/json', 'cliq-delivery-plan-v1');
  const descriptor = { ref: artifact.ref, byteLength: bytes.length, mediaType: artifact.mediaType, schemaKind: artifact.schemaKind };
  return { plan, planRef: artifact.ref, metadata: [...metadata.values(), descriptor], publications: [artifact] };
}
