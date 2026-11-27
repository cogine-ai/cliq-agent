import { createHash } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireRecord, controlWireRef, controlWireText } from '../kernel/control-wire-data.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import { normalizeSourceReadScopePath } from '../kernel/source-read-scope.js';
import type { SourceIncludeAuthorizationV1 } from '../kernel/source-include.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { assertBoundedJsonValue } from '../kernel/json.js';
import { readSourceIncludeArtifact } from './source-include-artifacts.js';

export type SourceIncludeClassificationEntry = Readonly<{
  path: string; entryKind: 'directory' | 'file' | 'symlink'; workspaceEntryDigest: string; deviceId: string; fileId: string; linkCount: number;
  classification: 'tracked_in_git_index' | 'tracked_ancestor_in_git_index' | 'nonignored_in_root';
}>;
type Identity = Pick<SourceIncludeAuthorizationV1, 'principalId' | 'inspectionId' | 'runId' | 'sessionId' |
  'workspaceIdentityRef' | 'workspaceIdentityDigest' | 'selector' | 'selectorDigest' | 'admissionIntentDigest'>;
export type SourceIncludeClassification = Identity & {
  schemaVersion: 1; format: 'cliq-source-include-classification-v1';
  frozenIgnoreRulesRef: string; frozenIgnoreRulesDigest: string;
  capturedEntriesRef: string; capturedTreeDigest: string;
  gitIndexRef?: string; gitIndexTreeObjectId?: string;
  pageRefs: readonly string[]; entryCount: number; entriesDigest: string;
  observedAt: string; evidenceDigest: string;
};
type Page = {
  schemaVersion: 1; format: 'cliq-source-include-classification-page-v1';
  inspectionId: string; selectorDigest: string; pageIndex: number;
  entries: readonly SourceIncludeClassificationEntry[]; pageDigest: string;
};
const common = ['principalId','inspectionId','runId','sessionId','workspaceIdentityRef','workspaceIdentityDigest',
  'selector','selectorDigest','admissionIntentDigest'];
const MAX_PAGE_BYTES = 512 * 1024, MAX_PAGE_ENTRIES = 128, MAX_PAGES = 8192;
function integer(value: unknown, maximum: number, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum)
    throw new TypeError('source include classification integer is outside its closed bound');
  return value as number;
}
function path(value: unknown): string {
  const result = normalizeSourceReadScopePath(value, 'entry');
  if (result.split('/').some(part => part.toLowerCase() === '.git')) throw new TypeError('source include classification enters Git metadata');
  return result;
}
function entry(value: unknown): SourceIncludeClassificationEntry {
  const data = controlWireRecord(value, ['path','entryKind','workspaceEntryDigest','deviceId','fileId','linkCount','classification']);
  path(data.path); controlWireRef(data.workspaceEntryDigest);
  if (!['directory','file','symlink'].includes(data.entryKind as string)) throw new TypeError('source include classification has another entry kind');
  for (const key of ['deviceId','fileId']) {
    if (!/^(?:0|[1-9][0-9]{0,31})$/u.test(controlWireText(data[key],128)))
      throw new TypeError('source include classification identity is not canonical');
  }
  integer(data.linkCount,Number.MAX_SAFE_INTEGER,1);
  if (!['tracked_in_git_index','tracked_ancestor_in_git_index','nonignored_in_root'].includes(data.classification as string))
    throw new TypeError('source include classification has another reason');
  if (data.classification === 'tracked_ancestor_in_git_index' && data.entryKind !== 'directory')
    throw new TypeError('source include tracked ancestor is not a directory');
  return data as SourceIncludeClassificationEntry;
}
function decodePage(value: unknown): Readonly<Page> {
  assertControlWireJson(value);
  assertBoundedJsonValue(value,'source include classification page');
  const data = controlWireRecord(value,['schemaVersion','format','inspectionId','selectorDigest','pageIndex','entries','pageDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-source-include-classification-page-v1' ||
      canonicalJsonBytes(data).length > MAX_PAGE_BYTES || !Array.isArray(data.entries) || !data.entries.length || data.entries.length > MAX_PAGE_ENTRIES)
    throw new TypeError('source include classification page has another format or size');
  controlWireText(data.inspectionId); controlWireRef(data.selectorDigest); integer(data.pageIndex,MAX_PAGES-1);
  data.entries.forEach(entry); controlWireRef(data.pageDigest);
  if (digestOmitting(data,'pageDigest') !== data.pageDigest) throw new TypeError('source include classification page digest differs');
  return immutableSnapshot(data as Page);
}
export function decodeSourceIncludeClassification(value: unknown): Readonly<SourceIncludeClassification> {
  assertControlWireJson(value);
  assertBoundedJsonValue(value,'source include classification root');
  const data = controlWireRecord(value,[...common,'schemaVersion','format','frozenIgnoreRulesRef','frozenIgnoreRulesDigest','capturedEntriesRef','capturedTreeDigest',
    'pageRefs','entryCount','entriesDigest','observedAt','evidenceDigest'],['gitIndexRef','gitIndexTreeObjectId']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-source-include-classification-v1' ||
      !Array.isArray(data.pageRefs) || !data.pageRefs.length || data.pageRefs.length > MAX_PAGES || new Set(data.pageRefs).size !== data.pageRefs.length ||
      canonicalJsonBytes(data).length > 1024*1024)
    throw new TypeError('source include classification root has another format or page count');
  for (const key of ['principalId','inspectionId','runId','sessionId']) controlWireText(data[key]);
  for (const key of ['workspaceIdentityRef','workspaceIdentityDigest','selectorDigest','admissionIntentDigest',
    'frozenIgnoreRulesRef','frozenIgnoreRulesDigest','capturedEntriesRef','capturedTreeDigest','entriesDigest','evidenceDigest']) controlWireRef(data[key]);
  data.pageRefs.forEach(controlWireRef); integer(data.entryCount,100_000,1);
  const selector = controlWireRecord(data.selector,['path','scope']);
  normalizeSourceReadScopePath(selector.path,selector.scope); path(selector.path);
  if (canonicalSha256(selector) !== data.selectorDigest || digestOmitting(data,'evidenceDigest') !== data.evidenceDigest)
    throw new TypeError('source include classification selector or root digest differs');
  parseCanonicalTime(controlWireText(data.observedAt,24,24));
  if (Object.hasOwn(data,'gitIndexRef') !== Object.hasOwn(data,'gitIndexTreeObjectId'))
    throw new TypeError('source include classification lost one Git index field');
  if (data.gitIndexRef !== undefined) {
    controlWireRef(data.gitIndexRef);
    if (typeof data.gitIndexTreeObjectId !== 'string' || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(data.gitIndexTreeObjectId))
      throw new TypeError('source include classification has another Git index tree');
  }
  return immutableSnapshot(data as SourceIncludeClassification);
}
const sequence = () => createHash('sha256').update('[');
function update(hash: ReturnType<typeof sequence>, value: SourceIncludeClassificationEntry, ordinal: number) {
  if (ordinal) hash.update(','); hash.update(canonicalJsonBytes(value));
}
/** Publishes inert observations from the owning held capture. The caller
 * retains/rechecks all descriptors and the actual original capturing cut. */
export async function publishSourceIncludeClassification(artifacts: ArtifactCatalog,
  input: Omit<SourceIncludeClassification,'schemaVersion'|'format'|'pageRefs'|'entryCount'|'entriesDigest'|'evidenceDigest'>,
  entries: readonly SourceIncludeClassificationEntry[], signal?: AbortSignal) {
  if (!entries.length || entries.length > 100_000) throw new TypeError('source include classification must cover a bounded nonempty selection');
  const pages: Page[] = [], hash = sequence(); let current: SourceIncludeClassificationEntry[] = [], previous = '';
  const page = (members: readonly SourceIncludeClassificationEntry[], index: number): Page => {
    const value: Page = { schemaVersion:1,format:'cliq-source-include-classification-page-v1',inspectionId:input.inspectionId,
      selectorDigest:input.selectorDigest,pageIndex:index,entries:members,pageDigest:'' };
    value.pageDigest = digestOmitting(value,'pageDigest'); return value;
  };
  for (let index=0; index<entries.length; index++) {
    if (index % 64 === 0) await setImmediate();
    signal?.throwIfAborted();
    const item = entry(entries[index]);
    if (previous && Buffer.compare(Buffer.from(previous),Buffer.from(item.path)) >= 0) throw new TypeError('source include classification is not unique byte order');
    previous=item.path; update(hash,item,index);
    const next=[...current,item];
    if (current.length && (next.length > MAX_PAGE_ENTRIES || canonicalJsonBytes(page(next,pages.length)).length > MAX_PAGE_BYTES)) {
      pages.push(page(current,pages.length)); current=[];
    }
    current.push(item);
  }
  if (current.length) pages.push(page(current,pages.length));
  if (pages.length > MAX_PAGES) throw new TypeError('source include classification exceeds its fixed page root');
  pages.forEach(decodePage);
  const metadata: PublishedArtifact[]=[];
  for (let index=0; index<pages.length; index++) {
    signal?.throwIfAborted();
    metadata.push(await artifacts.publishCanonical(pages[index],pages[index]!.format));
  }
  const evidence: SourceIncludeClassification = { ...input,schemaVersion:1,format:'cliq-source-include-classification-v1',
    pageRefs:metadata.map(item=>item.ref),entryCount:entries.length,entriesDigest:hash.update(']').digest('hex'),evidenceDigest:'' };
  evidence.evidenceDigest=digestOmitting(evidence,'evidenceDigest'); decodeSourceIncludeClassification(evidence);
  signal?.throwIfAborted();
  const published=await artifacts.publishCanonical(evidence,evidence.format); metadata.push(published);
  return Object.freeze({ evidence:immutableSnapshot(evidence),ref:published.ref,metadata:Object.freeze(metadata) });
}
/** Full immutable page closure; never a current native observation. */
export async function readSourceIncludeClassification(artifacts: Pick<ArtifactCatalog,'readBoundedBytes'>, ref: string) {
  const evidence=decodeSourceIncludeClassification(await readSourceIncludeArtifact(artifacts,ref));
  if (canonicalSha256(evidence)!==ref) throw new TypeError('source include classification root bytes differ');
  const entries: SourceIncludeClassificationEntry[]=[], hash=sequence(); let previous='';
  for (let index=0; index<evidence.pageRefs.length; index++) {
    const pageRef=evidence.pageRefs[index]!, page=decodePage(await readSourceIncludeArtifact(artifacts,pageRef,MAX_PAGE_BYTES));
    if (canonicalSha256(page)!==pageRef || page.inspectionId!==evidence.inspectionId || page.selectorDigest!==evidence.selectorDigest || page.pageIndex!==index)
      throw new TypeError('source include classification page changed its original binding or ordinal');
    for (const item of page.entries) {
      if (entries.length>=evidence.entryCount || previous && Buffer.compare(Buffer.from(previous),Buffer.from(item.path))>=0)
        throw new TypeError('source include classification sequence is duplicated, reordered or oversized');
      previous=item.path; update(hash,item,entries.length); entries.push(item);
    }
  }
  if (entries.length!==evidence.entryCount || hash.update(']').digest('hex')!==evidence.entriesDigest)
    throw new TypeError('source include classification lost complete sequence bytes');
  return Object.freeze({evidence,entries:Object.freeze(entries)});
}
