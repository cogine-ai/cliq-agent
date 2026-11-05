// The fixed retained-data side of the Legacy importer. No old normalizer,
// recovery routine, configuration loader, tool action or approval is invoked.
import { canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import { controlWireInteger, controlWireRecord, controlWireText } from '../kernel/control-wire-data.js';
import { parseCanonicalTime } from '../kernel/identity.js';
import { decodeLegacyContextPayload, legacySessionItemId } from '../kernel/legacy-context.js';
import { parseJsonStrict } from '../kernel/json.js';
import { extractPlanItems, isPlanItemStatus } from '../plans/items.js';
import type { ProjectedLegacyItem } from './legacy-source-context.js';

const MAX_SOURCE_BYTES = 1_048_576;
type Data = Record<string, unknown>;
function invalid(): never { throw new TypeError('Legacy artifact differs from its fixed context-only source profile'); }
function safe(value: unknown): string {
  const text = controlWireText(value);
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(text)) return invalid();
  return text;
}
function prose(value: unknown, maximum = 262_144, minimum = 0): string {
  if (typeof value !== 'string') return invalid();
  return controlWireText(normalizeCanonicalText(value), maximum, minimum);
}
function time(value: unknown, preparedAt: string): string {
  const text = controlWireText(value);
  if (parseCanonicalTime(text) > parseCanonicalTime(preparedAt)) return invalid();
  return text;
}
export function decodeLegacyArtifactSource(bytes: Uint8Array): unknown {
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_SOURCE_BYTES) return invalid();
  return parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
}
function originalPaths(value: unknown, expected: Readonly<Record<string, string>>): void {
  const paths = controlWireRecord(value, Object.keys(expected));
  for (const [key, path] of Object.entries(expected)) if (paths[key] !== path) return invalid();
}
function planSource(path: string): Readonly<{ workspaceId: string; sessionId: string; planId: string; directory: string }> {
  const match = /^plans\/([A-Za-z0-9_-]{1,128})\/([A-Za-z0-9_-]{1,128})\/([A-Za-z0-9_-]{1,128})\/plan\.json$/u.exec(path);
  if (!match) return invalid();
  return { workspaceId: match[1]!, sessionId: match[2]!, planId: match[3]!, directory: path.slice(0, -9) };
}
function finish(kind: 'legacy_plan' | 'legacy_handoff', sessionId: string, path: string,
  ordinal: number, content: Data, preparedAt: string): ProjectedLegacyItem {
  controlWireInteger(ordinal); parseCanonicalTime(preparedAt);
  const core = { schemaVersion: 1, format: 'cliq-legacy-portable-payload-v1', kind, legacySessionId: sessionId,
    sourceSchemaId: kind === 'legacy_plan' ? 'plan-v1' : 'handoff-v1', sourceOrdinal: ordinal,
    sourceCanonicalRootRelativePath: path, content };
  const payload = decodeLegacyContextPayload({ ...core, payloadDigest: canonicalSha256(core) });
  return Object.freeze({ payload, payloadRef: canonicalSha256(payload), itemId: legacySessionItemId(payload), createdAt: preparedAt });
}
function planItems(value: unknown): readonly Data[] {
  if (!Array.isArray(value)) return invalid();
  const ids = new Set<string>();
  return value.map(original => {
    const item = controlWireRecord(original, ['id', 'title', 'status'], ['notes']);
    const id = safe(item.id);
    if (ids.has(id) || !isPlanItemStatus(item.status)) return invalid();
    ids.add(id);
    return { id, title: prose(item.title, 4096, 1), status: item.status,
      ...(Object.hasOwn(item, 'notes') ? { notes: prose(item.notes) } : {}) };
  });
}

/** The actual Markdown sibling is a separate captured source. Only a draft
 * uses it, as the old readPlanArtifact does. An approved status is historical
 * user data here, never an approval to execute or a restored active plan. */
export function projectLegacyPlanSource(input: Readonly<{ sourcePath: string; value: unknown;
  legacyRootPath: string; publicationPreparedAt: string; markdown?: string }>): ProjectedLegacyItem {
  const source = planSource(input.sourcePath);
  const plan = controlWireRecord(input.value, ['id', 'sessionId', 'workspaceId', 'status', 'title', 'contentMarkdown',
    'createdAt', 'updatedAt', 'paths'], ['items', 'finalizedAt', 'approvedAt', 'rejectedAt', 'canceledAt', 'approvedTargetMode']);
  if (safe(plan.id) !== source.planId || safe(plan.sessionId) !== source.sessionId || safe(plan.workspaceId) !== source.workspaceId ||
      !['draft', 'finalized', 'approved', 'rejected', 'canceled'].includes(plan.status as string)) return invalid();
  const created = time(plan.createdAt, input.publicationPreparedAt), updated = time(plan.updatedAt, input.publicationPreparedAt);
  if (created > updated) return invalid();
  for (const key of ['finalizedAt', 'approvedAt', 'rejectedAt', 'canceledAt']) if (Object.hasOwn(plan, key)) {
    const value = time(plan[key], input.publicationPreparedAt); if (value < created || value > updated) return invalid();
  }
  if (Object.hasOwn(plan, 'approvedTargetMode') && !['default', 'accept-edits', 'yolo'].includes(plan.approvedTargetMode as string)) return invalid();
  originalPaths(plan.paths, { json: `${input.legacyRootPath}/${input.sourcePath}`,
    markdown: `${input.legacyRootPath}/${source.directory}plan.md` });
  const markdown = plan.status === 'draft' && input.markdown !== undefined ? input.markdown : plan.contentMarkdown;
  const contentMarkdown = prose(markdown);
  // This is the old pure deterministic Markdown extractor, not its lossy
  // normalizers. An explicitly supplied malformed item is always refused.
  const items = plan.items === undefined ? planItems(extractPlanItems(contentMarkdown)) : planItems(plan.items);
  return finish('legacy_plan', source.sessionId, input.sourcePath, 0,
    { planId: source.planId, title: prose(plan.title, 256), contentMarkdown, status: plan.status, items }, input.publicationPreparedAt);
}

/** Progress is validated and retained only in the complete byte backup. It
 * cannot become a second plan, turn draft into approved, or restore an action. */
export function validateLegacyPlanProgress(input: Readonly<{ sourcePath: string; value: unknown;
  legacyRootPath: string; publicationPreparedAt: string }>): void {
  const source = planSource(input.sourcePath.replace(/\/progress\.json$/u, '/plan.json'));
  const data = controlWireRecord(input.value, ['planId', 'sessionId', 'workspaceId', 'title', 'items', 'createdAt', 'updatedAt', 'paths']);
  if (safe(data.planId) !== source.planId || safe(data.sessionId) !== source.sessionId || safe(data.workspaceId) !== source.workspaceId ||
      !Array.isArray(data.items)) return invalid();
  const created = time(data.createdAt, input.publicationPreparedAt), updated = time(data.updatedAt, input.publicationPreparedAt);
  if (created > updated) return invalid();
  prose(data.title, 256);
  const ids = new Set<string>();
  for (const original of data.items) {
    const item = controlWireRecord(original, ['id', 'title', 'status', 'activeForm'], ['notes']);
    const id = safe(item.id); if (ids.has(id) || !isPlanItemStatus(item.status)) return invalid();
    ids.add(id); prose(item.title, 4096, 1); prose(item.activeForm, 4096, 1);
    if (Object.hasOwn(item, 'notes')) prose(item.notes);
  }
  originalPaths(data.paths, { json: `${input.legacyRootPath}/${input.sourcePath}` });
}

export function projectLegacyHandoffSource(input: Readonly<{ sourcePath: string; value: unknown;
  legacyRootPath: string; publicationPreparedAt: string }>): ProjectedLegacyItem {
  const match = /^handoffs\/([A-Za-z0-9_-]{1,128})\/handoff\.json$/u.exec(input.sourcePath);
  if (!match) return invalid();
  const data = controlWireRecord(input.value, ['id', 'createdAt', 'sessionId', 'checkpointId', 'summarySource', 'provider', 'model',
    'summaryMarkdown', 'paths'], ['parentSessionId', 'activeCompactionId', 'workspaceCheckpointId']);
  if (safe(data.id) !== match[1] || !['active-compaction', 'handoff-only'].includes(data.summarySource as string)) return invalid();
  const sessionId = safe(data.sessionId), createdAt = time(data.createdAt, input.publicationPreparedAt);
  safe(data.checkpointId); for (const key of ['parentSessionId', 'activeCompactionId', 'workspaceCheckpointId'])
    if (Object.hasOwn(data, key)) safe(data[key]);
  controlWireText(data.provider); controlWireText(data.model);
  originalPaths(data.paths, { json: `${input.legacyRootPath}/${input.sourcePath}`,
    markdown: `${input.legacyRootPath}/handoffs/${match[1]!}/HANDOFF.md` });
  return finish('legacy_handoff', sessionId, input.sourcePath, 0,
    { handoffId: match[1]!, createdAt, summarySource: data.summarySource, summaryMarkdown: prose(data.summaryMarkdown) }, input.publicationPreparedAt);
}

