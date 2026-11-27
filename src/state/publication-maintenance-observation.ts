import { setImmediate } from 'node:timers/promises';
import { createHash } from 'node:crypto';
import { canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import { assertArtifactRef, sha256Bytes } from '../kernel/identity.js';
import { publicationDirectoryIdentityDigest, type PublicationPathObservationV1, type PublicationPathState } from '../kernel/publication.js';
import { immutableSnapshot } from '../model/immutable.js';
import { MAX_SOURCE_PROJECTION_ENTRIES } from '../workspace/source-projection.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { assertHeldWorkspaceRoot, type HeldWorkspaceCursor, type HeldWorkspaceEntry, type HeldWorkspaceRoot } from './native-owner.js';

export type PublicationMaintenancePathInput = Readonly<{
  path: string; workspaceIdentityDigest: string;
  completedDescendants: readonly Readonly<{ operationId: string; observation: PublicationPathObservationV1 }>[];
  maxSingleFileBytes: number; maxBytes: number; signal?: AbortSignal;
}>;
export type PublicationMaintenancePathObservation = Readonly<{
  observation: PublicationPathObservationV1; ancestorPath?: string;
  descendants: readonly Readonly<{ operationId: string; observation: PublicationPathObservationV1 }>[];
  classification: 'absent' | 'leaf' | 'empty_directory' | 'planned_descendants' | 'unexpected';
}>;
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function checkedPath(value: string): string {
  if (typeof value !== 'string' || !value || value !== normalizeCanonicalText(value) || Buffer.byteLength(value) > 4096 ||
      value.includes('\\') || value.includes('\0') || value.split('/').some(part => !part || part === '.' || part === '..' ||
        Buffer.byteLength(part) > 255 || part.toLowerCase() === '.git')) throw new TypeError('maintenance requires a canonical non-Git workspace path');
  return value;
}
function retire(resources: readonly { close(): void }[], operationError?: unknown): void {
  const failures: unknown[] = [];
  for (const resource of [...resources].reverse()) try { resource.close(); } catch (error) { failures.push(error); }
  if (failures.length) throw new ResourceRetirementError('maintenance observation descriptors did not join',
    new AggregateError(operationError === undefined ? failures : [operationError, ...failures]));
}
type Node = { path: string; parent?: Node; entry?: HeldWorkspaceEntry; childCount: number };
type Descendant = PublicationMaintenancePathInput['completedDescendants'][number];
function copyData(value: unknown, depth = 0): unknown {
  if (value === null || typeof value !== 'object') {
    if (['string', 'number', 'boolean'].includes(typeof value) || value === null) return value;
    throw new TypeError('maintenance descendants require plain data');
  }
  if (depth > 8 || ![Object.prototype, null].includes(Object.getPrototypeOf(value)))
    throw new TypeError('maintenance descendants require bounded plain records');
  const fields = Object.getOwnPropertyDescriptors(value), copy: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(fields)) {
    const field = typeof key === 'string' ? fields[key] : undefined;
    if (!field?.enumerable || !Object.hasOwn(field, 'value')) throw new TypeError('maintenance descendants cannot contain accessors');
    copy[key as string] = copyData(field.value, depth + 1);
  }
  return copy;
}
function checkedInput(value: PublicationMaintenancePathInput): PublicationMaintenancePathInput {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value)))
    throw new TypeError('maintenance input requires a closed plain record');
  const fields = Object.getOwnPropertyDescriptors(value), names = ['path', 'workspaceIdentityDigest', 'completedDescendants', 'maxSingleFileBytes', 'maxBytes'];
  if (names.some(name => !Object.hasOwn(fields, name)) || Reflect.ownKeys(fields).some(name => typeof name !== 'string' || ![...names, 'signal'].includes(name)))
    throw new TypeError('maintenance input requires its exact closed fields');
  const result: Record<string, unknown> = Object.create(null);
  for (const [name, field] of Object.entries(fields)) {
    if (!field.enumerable || !Object.hasOwn(field, 'value') || field.value === undefined)
      throw new TypeError('maintenance input cannot contain accessors or undefined fields');
    result[name] = field.value;
  }
  if (result.signal !== undefined && !(result.signal instanceof AbortSignal)) throw new TypeError('maintenance cancellation requires an actual AbortSignal');
  return result as PublicationMaintenancePathInput;
}

/** Actual read-only data from the original held root. It is neither a native
 * publication proof nor permission to remove even a verified empty directory. */
export async function observePublicationMaintenancePath(root: HeldWorkspaceRoot,
  input: PublicationMaintenancePathInput): Promise<PublicationMaintenancePathObservation> {
  assertHeldWorkspaceRoot(root);
  input = checkedInput(input);
  const selected = checkedPath(input.path), { workspaceIdentityDigest, signal, maxSingleFileBytes, maxBytes } = input;
  assertArtifactRef(workspaceIdentityDigest);
  if (!Number.isSafeInteger(maxSingleFileBytes) || maxSingleFileBytes < 0 ||
      !Number.isSafeInteger(maxBytes) || maxBytes < 0 || !Array.isArray(input.completedDescendants))
    throw new TypeError('maintenance observation limits or descendants are invalid');
  if (input.completedDescendants.length > MAX_SOURCE_PROJECTION_ENTRIES) throw new TypeError('maintenance descendants exceed the source bound');
  const expected = new Map<string, Descendant>(), operationIds = new Set<string>();
  for (let index = 0; index < input.completedDescendants.length; index++) {
    const field = Object.getOwnPropertyDescriptor(input.completedDescendants, String(index));
    if (!field || !Object.hasOwn(field, 'value')) throw new TypeError('maintenance descendants cannot contain holes or accessors');
    const value = copyData(field.value) as Descendant;
    if (!value || typeof value.operationId !== 'string' || !value.operationId || !value.observation ||
        value.observation.location?.kind !== 'workspace' || value.observation.state?.kind === 'absent')
      throw new TypeError('maintenance requires completed present workspace descendant observations');
    const path = checkedPath(value.observation.location.path);
    if (!path.startsWith(`${selected}/`) || expected.has(path) || operationIds.has(value.operationId))
      throw new TypeError('maintenance descendants must have unique operations and strict descendant paths');
    expected.set(path, value); operationIds.add(value.operationId);
  }
  const resources: Array<{ close(): void }> = [], entries: HeldWorkspaceEntry[] = [], cursors: HeldWorkspaceCursor[] = [];
  let inventoryCount = 0, byteCount = 0, operationError: unknown;
  const assertHeld = () => {
    signal?.throwIfAborted(); assertHeldWorkspaceRoot(root);
    for (const entry of entries) entry.assertHeld();
    for (const cursor of cursors) cursor.assertComplete();
  };
  async function scan(parent: Node, select: (path: string) => boolean): Promise<Node[]> {
    const cursor = parent.entry ? parent.entry.openDirectory() : root.openSnapshot();
    cursors.push(cursor); resources.push(cursor);
    const found: Node[] = [];
    for (;;) {
      signal?.throwIfAborted();
      const entry = cursor.next(); if (!entry) break;
      parent.childCount++;
      if (++inventoryCount > MAX_SOURCE_PROJECTION_ENTRIES) { retire([entry]); invalid('maintenance metadata inventory exceeds the entry limit'); }
      if (select(entry.path)) {
        entries.push(entry); resources.push(entry); found.push({ path: entry.path, parent, entry, childCount: 0 });
      } else retire([entry]);
      if ((inventoryCount & 127) === 0) await setImmediate();
    }
    cursor.assertComplete(); return found;
  }
  async function state(node: Node): Promise<PublicationPathState> {
    const entry = node.entry;
    if (!entry) return { kind: 'absent' };
    if (entry.kind === 'directory') return { kind: 'directory', mode: entry.mode, empty: node.childCount === 0,
      identityDigest: publicationDirectoryIdentityDigest(workspaceIdentityDigest, { ...entry.identity, mode: entry.mode }) };
    if (entry.kind === 'symlink') {
      const target = entry.readSymlink(), size = Buffer.byteLength(target);
      if (size > maxBytes - byteCount) invalid('maintenance observed bytes exceed the capture limit');
      byteCount += size; return { kind: 'symlink', target, digest: sha256Bytes(Buffer.from(target)) };
    }
    if (entry.kind !== 'file') invalid('maintenance encountered an unsupported actual filesystem kind');
    if (entry.linkCount !== 1 || !Number.isSafeInteger(entry.byteCount) || entry.byteCount < 0 ||
        entry.byteCount > maxSingleFileBytes || entry.byteCount > maxBytes - byteCount)
      invalid('maintenance file identity or bytes exceed the capture limit');
    const reader = entry.openFile(), hash = createHash('sha256');
    let received = 0, readError: unknown;
    try {
      for (;;) {
        await setImmediate(); signal?.throwIfAborted(); reader.assertHeld();
        const chunk = reader.readChunk();
        if (chunk === null) { reader.assertHeld(); break; }
        received += chunk.byteLength;
        if (received > entry.byteCount) invalid('maintenance file exceeded its original byte count');
        hash.update(chunk);
      }
      if (received !== entry.byteCount) invalid('maintenance file differs from its original byte count');
      byteCount += received; return { kind: 'file', mode: entry.mode, digest: hash.digest('hex') };
    } catch (error) { readError = error; throw error; }
    finally { retire([reader], readError); }
  }
  async function observe(node: Node): Promise<PublicationPathObservationV1> {
    const entry = node.entry, parent = node.parent!, parentIdentity = parent.entry?.identity ?? root.identity;
    return { location: { kind: 'workspace', path: node.path }, state: await state(node),
      parentDeviceId: parentIdentity.deviceId, parentFileId: parentIdentity.fileId,
      parentLinkCount: parent.entry?.linkCount ?? root.linkCount,
      ...(entry ? { entryDeviceId: entry.identity.deviceId, entryFileId: entry.identity.fileId, entryLinkCount: entry.linkCount } : {}) };
  }
  function sameIdentity(node: Node, value: Descendant): boolean {
    const entry = node.entry!, observation = value.observation, actualParent = node.parent!.entry?.identity ?? root.identity;
    if (entry.kind !== observation.state.kind || entry.identity.deviceId !== observation.entryDeviceId ||
        entry.identity.fileId !== observation.entryFileId || actualParent.deviceId !== observation.parentDeviceId ||
        actualParent.fileId !== observation.parentFileId) return false;
    if (observation.state.kind === 'directory') return entry.mode === observation.state.mode &&
      publicationDirectoryIdentityDigest(workspaceIdentityDigest, { ...entry.identity, mode: entry.mode }) === observation.state.identityDigest;
    return entry.linkCount === observation.entryLinkCount && (observation.state.kind !== 'file' ||
      entry.linkCount === 1 && entry.mode === observation.state.mode);
  }
  try {
    signal?.throwIfAborted();
    let parent: Node = { path: '', childCount: 0 }, observed: Node | undefined;
    for (const part of selected.split('/')) {
      const wanted = parent.path ? `${parent.path}/${part}` : part;
      observed = (await scan(parent, path => path === wanted))[0];
      if (!observed) { observed = { path: wanted, parent, childCount: 0 }; break; }
      if (wanted === selected || observed.entry!.kind !== 'directory') break;
      parent = observed;
    }
    if (!observed) invalid('maintenance path has no original observation');
    const entry = observed.entry;
    const descendants: Array<{ operationId: string; observation: PublicationPathObservationV1 }> = [];
    let unexpected = false;
    if (entry?.kind === 'directory') {
      const stack = [observed], selectedNodes: Node[] = [];
      while (stack.length) {
        const node = stack.pop()!;
        const children = await scan(node, path => {
          if (expected.has(path)) return true;
          unexpected = true; return false; // Metadata only: never open an unselected subtree or payload.
        });
        for (const child of children) {
          const original = expected.get(child.path)!;
          if (!sameIdentity(child, original)) { unexpected = true; continue; }
          selectedNodes.push(child);
          if (child.entry!.kind === 'directory') stack.push(child);
        }
      }
      for (const node of selectedNodes.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)))) {
        const original = expected.get(node.path)!, actual = await observe(node);
        if (actual.state.kind !== 'directory' && canonicalSha256(actual.state) !== canonicalSha256(original.observation.state))
          unexpected = true;
        descendants.push({ operationId: original.operationId, observation: actual });
      }
      if (selectedNodes.length !== expected.size) unexpected = true;
    }
    const observation = await observe(observed);
    assertHeld();
    return immutableSnapshot({ observation, descendants: unexpected ? [] : descendants,
      ...(observed.path !== selected ? { ancestorPath: observed.path } : {}),
      classification: !entry ? 'absent' : entry.kind !== 'directory' ? observed.path === selected ? 'leaf' : 'unexpected' :
        observed.childCount === 0 ? 'empty_directory' : !unexpected ? 'planned_descendants' : 'unexpected' });
  } catch (error) { operationError = error; throw error; }
  finally { retire(resources, operationError); }
}
