import { setImmediate } from 'node:timers/promises';
import { normalizeAbsolutePath, sha256Bytes } from '../kernel/identity.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { assertHeldWorkspaceRoot, type HeldWorkspaceEntry,
  type HeldWorkspaceRoot } from './native-owner.js';

export type HeldWorkspaceSourceTrust = Readonly<{ assertCurrent(): void; close(): void }>;
const heldTrust = new WeakMap<HeldWorkspaceSourceTrust, { path: string; assertCurrent(): void }>();

/** Only the trusted Supervisor supplies its controlled home descriptor. A
 * client, repo, environment override or artifact cannot supply a Trust verdict.
 * This gate grants neither source-read scope nor tool/execution permission. */
export async function holdWorkspaceSourceTrust(controlledHome: HeldWorkspaceRoot, workspacePath: string,
  signal?: AbortSignal): Promise<HeldWorkspaceSourceTrust> {
  assertHeldWorkspaceRoot(controlledHome);
  const canonicalPath = normalizeAbsolutePath(workspacePath), workspaceId = sha256Bytes(Buffer.from(canonicalPath));
  const resources: Array<{ close(): void }> = [], selected: HeldWorkspaceEntry[] = [];
  let closed = false, inventory = 0;
  const close = (operationError?: unknown) => {
    closed = true;
    const failures: unknown[] = [];
    for (const resource of [...resources].reverse()) {
      try { resource.close(); } catch (error) { failures.push(error); }
    }
    if (failures.length) throw new ResourceRetirementError('Workspace Trust descriptors did not retire',
      new AggregateError(operationError === undefined ? failures : [operationError, ...failures]));
  };
  function invalid(cause?: unknown): never {
    throw new KernelStorageError('INVALID_REQUEST', 'an exact persisted Workspace Trust decision is required for source capture', { cause });
  }
  try {
    signal?.throwIfAborted();
    let cursor = controlledHome.openSnapshot(); resources.push(cursor);
    let prefix = '';
    for (const component of ['workspaces', workspaceId, 'trust.json']) {
      const wanted = prefix + component;
      let found: HeldWorkspaceEntry | undefined;
      for (;;) {
        await setImmediate(); signal?.throwIfAborted();
        const entry = cursor.next();
        if (entry === null) break;
        if (++inventory > 100_000) { resources.push(entry); invalid(); }
        if (entry.path !== wanted) { entry.close(); continue; }
        if (found) { resources.push(entry); invalid(); }
        resources.push(entry); selected.push(entry); found = entry;
      }
      cursor.assertComplete();
      if (!found || found.identity.ownerUid !== controlledHome.identity.ownerUid || (found.mode & 0o022) !== 0) invalid();
      if (component !== 'trust.json') {
        if (found.kind !== 'directory') invalid();
        cursor = found.openDirectory(); resources.push(cursor); prefix = wanted + '/';
      } else {
        if (found.kind !== 'file' || found.linkCount !== 1 || found.byteCount < 1 || found.byteCount > 16_384) invalid();
        const reader = found.openFile(); resources.push(reader);
        const chunks: Buffer[] = [];
        for (;;) {
          await setImmediate(); signal?.throwIfAborted();
          const chunk = reader.readChunk();
          if (chunk === null) break;
          chunks.push(chunk);
        }
        reader.assertHeld();
        const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
        if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
        const record = value as Record<string, unknown>;
        if (Object.keys(record).length !== 5 || record.version !== 1 || record.workspaceId !== workspaceId ||
            record.workspaceRealPath !== canonicalPath || record.decision !== 'trusted' ||
            typeof record.decidedAt !== 'string' || !Number.isFinite(Date.parse(record.decidedAt))) invalid();
      }
    }
    const assertCurrent = () => {
      if (closed) throw new KernelStorageError('INVALID_REQUEST', 'Workspace Trust observation is closed');
      try {
        assertHeldWorkspaceRoot(controlledHome);
        for (const entry of selected) entry.assertPathHeld();
      } catch (cause) { invalid(cause); }
    };
    assertCurrent();
    const result: HeldWorkspaceSourceTrust = Object.freeze({ assertCurrent, close });
    heldTrust.set(result, { path: canonicalPath, assertCurrent });
    return result;
  } catch (error) {
    close(error);
    if (error instanceof KernelStorageError || error instanceof ResourceRetirementError || signal?.aborted) throw error;
    return invalid(error);
  }
}

/** Source admission consumes the exact live observation, never a boolean. */
export function assertWorkspaceSourceTrust(trust: HeldWorkspaceSourceTrust, workspacePath: string): void {
  const held = heldTrust.get(trust);
  if (!held || held.path !== workspacePath) throw new KernelStorageError('INVALID_REQUEST', 'Workspace Trust observation names another workspace');
  held.assertCurrent();
}
