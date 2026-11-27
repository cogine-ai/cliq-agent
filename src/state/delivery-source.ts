import { setImmediate as yieldToEventLoop } from 'node:timers/promises';
import { planArtifactBytes, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { mergeTextDiff3V1, type Diff3ComputationV1 } from '../kernel/diff3.js';
import { assertArtifactRef, digestOmitting } from '../kernel/identity.js';
import type { WorkspaceDiffOperationV1, WorkspaceDiffV1 } from '../kernel/result.js';
import type { DeliveryMergeLimitCause } from '../kernel/stop.js';
import type { SourceManifest, SourceProjectionSpec, WorkspaceEntry, WorkspaceEntryManifest } from '../kernel/types.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { decodeFrozenIgnoreRules, decodeSourceManifest, decodeSourceProjection, decodeWorkspaceEntries } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { checkEntries, checkSourceManifest, checkProjection } from './source-validation.js';
import { readSourceProjectionData, sameSourceGit } from './source-projection-data.js';
import { MAX_SOURCE_PROJECTION_ENTRIES } from '../workspace/source-projection.js';

export type DeliverySourceInput = Readonly<{ sourceBaseRef: string; sourceDesiredRef: string; capturedWorkspaceRef: string }>;
export type DeliverySourceLimit = Readonly<{ kind: DeliveryMergeLimitCause['limitKind']; observed: number; limit: number }>;
export type DeliverySourceConflict = {
  path: string;
  reason: 'add_add' | 'delete_modify' | 'type_or_mode' | 'non_text' | 'overlapping_text';
  base?: WorkspaceEntry; current?: WorkspaceEntry; desired?: WorkspaceEntry;
  ranges?: Array<{ current: { baseStart: number; baseEnd: number }; desired: { baseStart: number; baseEnd: number } }>;
} | { reason: 'merged_graph' };
export type DeliverySourcePlan = {
  kind: 'ready'; input: DeliverySourceInput; source: SourceManifest; sourceRef: string;
  entries: WorkspaceEntryManifest; diff: WorkspaceDiffV1; diffRef: string; summary: ModelTextV1; summaryRef: string;
  noOp: boolean; identicalToSourceDesired: boolean; metadata: PublishedArtifact[]; publications: PlannedArtifact[];
} | { kind: 'conflict'; input: DeliverySourceInput; conflicts: DeliverySourceConflict[]; metadata: PublishedArtifact[] }
  | { kind: 'limited'; input: DeliverySourceInput; limit: DeliverySourceLimit; metadata: PublishedArtifact[] };

const comparePaths = (a: string, b: string) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const same = (a: WorkspaceEntry | undefined, b: WorkspaceEntry | undefined) =>
  a === undefined || b === undefined ? a === b : canonicalSha256(a) === canonicalSha256(b);
function mismatch(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }
const excluded = (projection: SourceProjectionSpec, path: string) => projection.explicitExcludes.some(selector =>
  path === selector.path || selector.scope === 'subtree' && path.startsWith(`${selector.path}/`));
const canMergeText = (base?: WorkspaceEntry, current?: WorkspaceEntry, desired?: WorkspaceEntry) =>
  base?.kind === 'file' && current?.kind === 'file' && desired?.kind === 'file' && base.mode === current.mode && base.mode === desired.mode;

/**
 * Read and plan immutable B/S/A/M data. Nothing is published here.
 * The consumer still owns admission, source-result provenance, permissions,
 * physical resources, private materialization, verification and publication.
 * Only complete deterministic output-limit measurements are produced here.
 * onWork reports cumulative text-diff steps, not I/O or graph-validation cost.
 * New output snapshots still accumulate and require that real resource owner.
 */
export async function planDeliverySource(artifacts: ArtifactCatalog, selected: DeliverySourceInput & { sandboxProfileRef: string },
  computation: Diff3ComputationV1 = {}): Promise<DeliverySourcePlan> {
  return planImmutableSourceMerge(artifacts, selected, computation, 'base');
}

/** Fixed parent/child CAS-only variant. A is a completely verified current
 * result source, rather than Delivery's captured real-workspace base. The
 * public Delivery recipe retains its original role checks unchanged. */
export async function planChildMergeSource(artifacts: ArtifactCatalog, selected: DeliverySourceInput & { sandboxProfileRef: string; capturedSource: SourceManifest },
  computation: Diff3ComputationV1 = {}): Promise<DeliverySourcePlan> {
  if (canonicalSha256(selected.capturedSource) !== selected.capturedWorkspaceRef || selected.capturedSource.role !== 'result')
    mismatch('child merge captured source differs from its complete planned parent result');
  return planImmutableSourceMerge(artifacts, selected, computation, 'result', selected.capturedSource);
}

async function planImmutableSourceMerge(artifacts: ArtifactCatalog, selected: DeliverySourceInput & { sandboxProfileRef: string },
  computation: Diff3ComputationV1, capturedRole: 'base' | 'result', plannedCaptured?: SourceManifest): Promise<DeliverySourcePlan> {
  const input = Object.freeze({ sourceBaseRef: selected.sourceBaseRef, sourceDesiredRef: selected.sourceDesiredRef,
    capturedWorkspaceRef: selected.capturedWorkspaceRef });
  for (const ref of Object.values(input)) assertArtifactRef(ref);
  const sandboxProfileRef = selected.sandboxProfileRef; assertArtifactRef(sandboxProfileRef);
  const { signal, onWork } = computation;
  const checkpoint = () => { signal?.throwIfAborted(); artifacts.assertReadActive(); };
  checkpoint();
  const metadata = new Map<string, PublishedArtifact>(), publications = new Map<string, PlannedArtifact>();
  const canonicalReads = new Map<string, unknown>();
  const remember = (artifact: PublishedArtifact) => {
    const previous = metadata.get(artifact.ref);
    if (previous && previous.byteLength !== artifact.byteLength) mismatch('delivery source reuses a blob with a different size');
    if (!previous) metadata.set(artifact.ref, artifact);
  };
  const read = async <T>(ref: string, schemaKind: string): Promise<T> => {
    checkpoint();
    let value = canonicalReads.get(ref);
    if (!canonicalReads.has(ref)) {
      // Child A is freshly reconstructed complete CAS data. Its source
      // wrapper is planned, never described as already durable or physical.
      value = plannedCaptured && ref === input.capturedWorkspaceRef ? plannedCaptured : await readCanonicalArtifact(artifacts, ref);
      canonicalReads.set(ref, value);
    }
    checkpoint();
    remember({ ref, schemaKind, mediaType: 'application/json', byteLength: canonicalJsonBytes(value).byteLength });
    return value as T;
  };
  const sources: Array<{ ref: string; source: SourceManifest; entries: WorkspaceEntryManifest }> = [];
  const profile = decodeSandboxProfile(await read(sandboxProfileRef, 'cliq-sandbox-profile-v1'));
  for (const [ref, role] of [[input.sourceBaseRef, 'base'], [input.sourceDesiredRef, 'result'], [input.capturedWorkspaceRef, capturedRole]] as const) {
    const source = decodeSourceManifest(await read(ref, 'cliq-source-manifest-v1'));
    checkSourceManifest(source);
    if (source.role !== role) mismatch('delivery source manifest has the wrong base/result role');
    const entries = decodeWorkspaceEntries(await read(source.entriesRef, 'cliq-workspace-entries-v1'));
    if (entries.treeDigest !== source.treeDigest) mismatch('delivery source tree digest differs from its entries');
    checkEntries(entries); sources.push({ ref, source, entries });
  }
  const [base, desired, captured] = sources;
  if (!sameSourceGit(base.source, desired.source) || !!captured.source.git !== !!base.source.git ||
      base.source.git && captured.source.git?.repositoryIdentityDigest !== base.source.git.repositoryIdentityDigest)
    mismatch('delivery source result changed its admitted Git identity or captured another repository');
  for (const { source } of [desired, captured]) for (const key of ['workspaceIdentityDigest', 'sourceProjectionRef',
    'sourceProjectionDigest', 'frozenIgnoreRulesRef', 'frozenIgnoreRulesDigest'] as const)
    if (source[key] !== base.source[key]) mismatch('delivery source workspace, projection or ignore identity differs');
  const projection = decodeSourceProjection(await read(base.source.sourceProjectionRef, 'cliq-source-projection-v1'));
  checkProjection(projection);
  const rules = decodeFrozenIgnoreRules(await read(base.source.frozenIgnoreRulesRef, 'cliq-frozen-ignore-rules-v1'));
  if (projection.projectionDigest !== base.source.sourceProjectionDigest || projection.frozenIgnoreRulesRef !== base.source.frozenIgnoreRulesRef ||
      projection.frozenIgnoreRulesDigest !== base.source.frozenIgnoreRulesDigest || rules.rulesDigest !== base.source.frozenIgnoreRulesDigest)
    mismatch('delivery source projection and ignore references do not close');
  if (!exactKeys(rules, ['schemaVersion', 'format', 'matcherVersion', 'sources', 'rules', 'rulesDigest', ...(base.source.git ? ['repositoryIdentityDigest'] : [])]) ||
      rules.matcherVersion !== 'cliq-git-wildmatch-v1' || !Array.isArray(rules.sources) || !Array.isArray(rules.rules))
    mismatch('delivery source ignore manifest has invalid fields');
  const classification = await readSourceProjectionData(artifacts, base.source, projection, profile.resources, signal);
  if (captured.source.git) await readSourceProjectionData(artifacts, captured.source, projection, profile.resources, signal);
  for (const source of sources) if (source.entries.entries.some(entry => !classification.includes(entry)))
    mismatch('delivery source includes a frozen excluded path');
  const maps = sources.map(source => new Map(source.entries.entries.map(entry => [entry.path, entry])));
  const [before, wanted, current] = maps;
  const paths = [...new Set(sources.flatMap(source => source.entries.entries.map(entry => entry.path)))].sort(comparePaths);
  const files = new Map<string, number>();
  for (const { entries } of sources) for (const entry of entries.entries) if (entry.kind === 'file') {
    const previous = files.get(entry.blobRef);
    if (previous !== undefined && previous !== entry.size) mismatch('delivery source reuses a blob with a different size');
    files.set(entry.blobRef, entry.size);
  }
  for (const [ref, byteLength] of files) {
    checkpoint();
    for await (const _chunk of artifacts.readChunks(ref, byteLength)) { checkpoint(); }
    remember({ ref, byteLength, mediaType: 'application/octet-stream', schemaKind: 'cliq-workspace-file-v1' });
  }
  const readText = async (entry: Extract<WorkspaceEntry, { kind: 'file' }>): Promise<string | null> => {
    checkpoint();
    let decoder: TextDecoder | undefined = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    let parts: string[] = [], nonText = false;
    // Only this path's B/C/D texts are retained. This second, complete stream
    // rehashes the exact bytes instead of caching all decoded graph contents.
    for await (const chunk of artifacts.readChunks(entry.blobRef, entry.size)) {
      checkpoint();
      if (!decoder) continue;
      if (chunk.includes(0)) { nonText = true; decoder = undefined; parts = []; continue; }
      try { parts.push(decoder.decode(chunk, { stream: true })); }
      catch (error) {
        if (!(error instanceof TypeError)) throw error;
        nonText = true; decoder = undefined; parts = [];
      }
    }
    if (decoder) {
      try { parts.push(decoder.decode()); }
      catch (error) { if (!(error instanceof TypeError)) throw error; nonText = true; parts = []; }
    }
    checkpoint();
    return nonText ? null : parts.join('');
  };
  const accepted: WorkspaceEntry[] = [], conflicts: DeliverySourceConflict[] = [];
  const newBlobs = new Map<string, { artifact: PlannedArtifact; byteLength: number }>();
  let textWork = 0;
  for (let index = 0; index < paths.length; index++) {
    checkpoint();
    if (index !== 0 && index % 1024 === 0) { await yieldToEventLoop(); checkpoint(); }
    const path = paths[index], b = before.get(path), c = current.get(path), d = wanted.get(path);
    let result: WorkspaceEntry | undefined;
    if (same(c, d)) result = c;
    else if (same(c, b)) result = d;
    else if (same(d, b)) result = c;
    else if (canMergeText(b, c, d) && b?.kind === 'file' && c?.kind === 'file' && d?.kind === 'file') {
      const bt = await readText(b), ct = await readText(c), dt = await readText(d);
      if (typeof bt !== 'string' || typeof ct !== 'string' || typeof dt !== 'string') {
        conflicts.push({ path, reason: 'non_text', base: b, current: c, desired: d }); continue;
      }
      let pathWork = 0;
      const merged = await mergeTextDiff3V1(bt, ct, dt, { signal, onWork: work => {
        checkpoint(); pathWork = work.totalWork;
        onWork?.({ ...work, totalWork: textWork + pathWork }); checkpoint();
      } });
      textWork += pathWork;
      if (merged.kind === 'conflict') {
        conflicts.push({ path, reason: 'overlapping_text', base: b, current: c, desired: d,
          ranges: merged.conflicts.map(({ current, desired }) => ({
            current: { baseStart: current.baseStart, baseEnd: current.baseEnd },
            desired: { baseStart: desired.baseStart, baseEnd: desired.baseEnd } })) });
        continue;
      }
      const bytes = Buffer.from(merged.text, 'utf8'), blob = planArtifactBytes(bytes, 'application/octet-stream', 'cliq-workspace-file-v1');
      if (!metadata.has(blob.ref) && !newBlobs.has(blob.ref)) newBlobs.set(blob.ref, { artifact: blob, byteLength: bytes.length });
      result = { path, kind: 'file', mode: b.mode, size: bytes.length, blobRef: blob.ref };
    } else {
      conflicts.push({ path, reason: !b ? 'add_add' : !c || !d ? 'delete_modify' :
        b.kind !== c.kind || b.kind !== d.kind || b.mode !== c.mode || b.mode !== d.mode ? 'type_or_mode' : 'non_text',
        ...(b ? { base: b } : {}), ...(c ? { current: c } : {}), ...(d ? { desired: d } : {}) });
      continue;
    }
    if (result) accepted.push(result);
  }
  checkpoint();
  if (conflicts.length) return { kind: 'conflict', input, conflicts, metadata: [...metadata.values()] };
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: accepted,
    entryCount: accepted.length, byteCount: 0, treeDigest: '' };
  for (const entry of accepted) {
    entries.byteCount += entry.kind === 'file' ? entry.size : entry.kind === 'symlink' ? Buffer.byteLength(entry.target) : 0;
    if (!Number.isSafeInteger(entries.byteCount)) mismatch('delivery merged entry byte count overflows');
  }
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  // All individual inputs already passed these checks. A failure confined to
  // the combined graph is a merge conflict, not corrupt input or cancellation.
  try { checkEntries(entries); }
  catch (error) {
    if (!(error instanceof KernelStorageError) || error.code !== 'ARTIFACT_MISMATCH') throw error;
    return { kind: 'conflict', input, conflicts: [{ reason: 'merged_graph' }], metadata: [...metadata.values()] };
  }
  const operations: WorkspaceDiffOperationV1[] = [];
  const mergedEntries = new Map(accepted.map(entry => [entry.path, entry]));
  let changedBytes = 0;
  for (const path of [...new Set([...current.keys(), ...mergedEntries.keys()])].sort(comparePaths)) {
    const old = current.get(path), next = mergedEntries.get(path);
    if (same(old, next)) continue;
    operations.push(!old ? { path, kind: 'add', after: next! } : !next ? { path, kind: 'delete', before: old } :
      { path, kind: 'modify', before: old, after: next });
    if (next?.kind === 'file' && (old?.kind !== 'file' || old.blobRef !== next.blobRef || old.size !== next.size)) {
      changedBytes += next.size;
      if (!Number.isSafeInteger(changedBytes)) mismatch('delivery changed byte count overflows');
    }
  }
  let generationBytes = 0, singleFileBytes = 0;
  for (const entry of accepted) if (entry.kind === 'file') {
    generationBytes += entry.size; singleFileBytes = Math.max(singleFileBytes, entry.size);
    if (!Number.isSafeInteger(generationBytes)) mismatch('delivery merged regular file byte count overflows');
  }
  // Every input stream and the complete deterministic merged graph have been
  // checked. This data refusal publishes nothing and is never Stop authority.
  // Reproduction uses the same fixed order, not whichever check failed first.
  const limits: Array<[DeliverySourceLimit['kind'], number, number]> = [
    ['changed_paths', operations.length, projection.maxChangedPaths], ['changed_bytes', changedBytes, projection.maxChangedBytes],
    ['generation_bytes', generationBytes, profile.resources.maxGenerationBytes],
    ['single_file_bytes', singleFileBytes, profile.resources.maxSingleFileBytes],
    // Explicit projected entries are a lower bound on walker inventory, not
    // a complete observation of hidden/excluded metadata or physical capacity.
    ['merged_entries', accepted.length, MAX_SOURCE_PROJECTION_ENTRIES]
  ];
  const exceeded = limits.find(([, observed, ceiling]) => observed > ceiling);
  checkpoint();
  if (exceeded) return { kind: 'limited', input, limit: { kind: exceeded[0], observed: exceeded[1], limit: exceeded[2] },
    metadata: [...metadata.values()] };
  const plan = (artifact: PlannedArtifact, byteLength: number) => {
    if (!metadata.has(artifact.ref)) publications.set(artifact.ref, artifact);
    remember({ ref: artifact.ref, mediaType: artifact.mediaType, schemaKind: artifact.schemaKind, byteLength });
    return artifact.ref;
  };
  const planCanonical = (value: unknown, schemaKind: string) => {
    const bytes = canonicalJsonBytes(value);
    return plan(planArtifactBytes(bytes, 'application/json', schemaKind), bytes.byteLength);
  };
  for (const blob of newBlobs.values()) plan(blob.artifact, blob.byteLength);
  const entriesRef = planCanonical(entries, entries.format);
  const source: SourceManifest = { ...captured.source, role: 'result', entriesRef, treeDigest: entries.treeDigest, manifestDigest: '' };
  source.manifestDigest = digestOmitting(source, 'manifestDigest');
  const sourceRef = planCanonical(source, source.format);
  const diff: WorkspaceDiffV1 = { schemaVersion: 1, format: 'cliq-workspace-diff-v1', baseSourceRef: input.capturedWorkspaceRef,
    resultSourceRef: sourceRef, operations, diffDigest: '' };
  diff.diffDigest = digestOmitting(diff, 'diffDigest');
  const diffRef = planCanonical(diff, diff.format);
  const normalizedCaptured = { ...captured.source, role: 'result' as const, manifestDigest: '' };
  normalizedCaptured.manifestDigest = digestOmitting(normalizedCaptured, 'manifestDigest');
  const noOp = canonicalSha256(normalizedCaptured) === sourceRef;
  const utf8 = `Delivery merge: ${operations.length} changed paths, ${changedBytes} changed file bytes. ` +
    `Base ${input.sourceBaseRef}; source ${input.sourceDesiredRef}; captured ${input.capturedWorkspaceRef}; result ${sourceRef}; diff ${diffRef}.`;
  const summary: ModelTextV1 = { schemaVersion: 1, format: 'cliq-model-text-v1', utf8,
    byteCount: Buffer.byteLength(utf8), textDigest: '' };
  summary.textDigest = digestOmitting(summary, 'textDigest');
  const summaryRef = planCanonical(summary, summary.format);
  checkpoint();
  return { kind: 'ready', input, source, sourceRef, entries, diff, diffRef, summary, summaryRef, noOp,
    identicalToSourceDesired: sourceRef === input.sourceDesiredRef, metadata: [...metadata.values()], publications: [...publications.values()] };
}
