import path from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { GitIndexSnapshotV1 } from '../kernel/types.js';
import { compileFrozenIgnoreRules, createFrozenIgnoreMatcher } from '../workspace/frozen-ignore.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, readTimeFence } from './canonical-time.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, stateRootIdentityForLock,
  type HeldWorkspaceCursor, type HeldWorkspaceEntry, type HeldWorkspaceRoot } from './native-owner.js';
import { readAuthorizationGrant } from './repositories/authorization-grants.js';
import { sourceGitConsentData } from './source-git-consent.js';
import { readSourceInspectionAttempt } from './source-inspection.js';
import { assertVerifiedSourceInspectionTargetCut, readVerifiedSourceInspectionTarget,
  recheckVerifiedSourceInspectionTarget, type VerifiedSourceInspectionTarget } from './source-target.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';

type RuleSource = { kind: 'git_info_exclude' | 'gitignore'; path: string; bytes: Buffer };
function refused(message: string): never { throw new KernelStorageError('INVALID_REQUEST', message); }
function below(value: string, parent: string): boolean { return value === parent || value.startsWith(`${parent}/`); }
function retire(resources: readonly { close(): void }[], operationError?: unknown) {
  const failures: unknown[] = [];
  for (const resource of [...resources].reverse()) try { resource.close(); } catch (error) { failures.push(error); }
  if (failures.length) throw failures.find(error => error instanceof ResourceRetirementError) ??
    new ResourceRetirementError('source ignore descriptors did not completely retire',
      new AggregateError(operationError === undefined ? failures : [operationError, ...failures]));
  if (operationError instanceof ResourceRetirementError) throw operationError;
}

/** Original owning capture only. Git inspection consent never authorizes
 * ignored/excluded ordinary source bytes. A rule needs either its default
 * tracked/nonignored source classification or its exact separately consumed
 * read_scope; the native-owned info/exclude output always uses the latter. */
export async function captureSourceGitRules(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  target: VerifiedSourceInspectionTarget, controlledHome: HeldWorkspaceRoot, input: {
    index: GitIndexSnapshotV1; exclude: { contentRef: string; sha256: string; byteCount: number } | null; signal: AbortSignal;
  }) {
  const held = readVerifiedSourceInspectionTarget(owner, target), { signal } = input;
  if (held.target.schemaVersion !== 2 || !held.inspectionConsent || !held.workspace.repositoryIdentityDigest ||
      input.index.repositoryIdentityDigest !== held.workspace.repositoryIdentityDigest)
    return refused('ignore capture requires its original Git target and inspection output');
  assertHeldWorkspaceRoot(controlledHome);
  const workspace = held.workspaceRoot, request = held.request, consent = sourceGitConsentData(owner, held.inspectionConsent);
  const scopes = new Map(consent.ignoreReadScopes.map(scope => [scope.canonicalRootRelativePath, scope]));
  const usedScopes = new Set<string>(), sources: RuleSource[] = [], metadata: PublishedArtifact[] = [];
  const key = { principalId: held.target.principalId, method: held.target.method, admissionKey: held.target.admissionKey,
    admissionIntentDigest: held.target.admissionIntentDigest };
  const trackedPaths = input.index.entries.map(entry => entry.canonicalRootRelativePath), tracked = new Set(trackedPaths);
  const trackedBelow = (value: string) => {
    const prefix = `${value}/`, bytes = Buffer.from(prefix); let left = 0, right = trackedPaths.length;
    while (left < right) { const middle = (left + right) >>> 1;
      if (Buffer.compare(Buffer.from(trackedPaths[middle]!), bytes) < 0) left = middle + 1; else right = middle; }
    return trackedPaths[left]?.startsWith(prefix) === true;
  };
  const excluded = (value: string) => request.sourceExcludes.some(item => item.path === value || item.scope === 'subtree' && below(value, item.path));
  const stateRoot = stateRootIdentityForLock(owner.filesystem), workspacePath = heldWorkspaceRootPath(workspace);
  const hardRoots = [heldWorkspaceRootPath(controlledHome), stateRoot.canonicalAbsolutePath].flatMap(root => {
    const relative = path.relative(workspacePath, root);
    if (!relative || relative === '..' || workspacePath.startsWith(`${root}/`)) return refused('source workspace is inside a hard-excluded root');
    return relative.startsWith('../') || path.isAbsolute(relative) ? [] : [relative];
  });
  const cut = (scopedPath: string | undefined, open: () => void) => {
    let clockRejected = false;
    driver.transaction(connection => {
      signal.throwIfAborted(); assertVerifiedSourceInspectionTargetCut(connection, owner, target); controlledHome.assertHeld();
      const row = readSourceInspectionAttempt(connection, key);
      if (!row || row.phase !== 'active' || row.cancelRequested || row.retirementHandoffRef) return refused('ignore capture lost its original active source attempt');
      if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') { clockRejected = true; return; }
      const now = readTimeFence(connection)!.lastAcceptedAt;
      if (now >= row.deadlineAt || now >= consent.expiresAt) throw new KernelStorageError('BUDGET_EXHAUSTED', 'source ignore capture deadline elapsed');
      if (scopedPath) {
        const scope = scopes.get(scopedPath), selected = scope && held.target.schemaVersion === 2 && held.target.ignoreReadConsents.find(item => {
          const grant = readAuthorizationGrant(connection, item.grantId); return grant?.targetDigest === canonicalSha256(scope);
        });
        const grant = selected && readAuthorizationGrant(connection, selected.grantId);
        if (!scope || !selected || !grant || grant.state !== 'consumed' || grant.consumptionReceiptRef !== selected.receiptRef ||
            grant.ownerPrincipalId !== held.target.principalId || now >= grant.expiresAt)
          return refused('ignore file has no exact original consumed read scope');
      }
      open();
    });
    if (clockRejected) throw new KernelStorageError('RECOVERY_REQUIRED', 'ignore capture requires healthy canonical time');
  };
  const cursors: HeldWorkspaceCursor[] = [], entries: HeldWorkspaceEntry[] = [];
  let count = 0, total = 0, operationError: unknown;
  try {
    await recheckVerifiedSourceInspectionTarget(owner, target); signal.throwIfAborted();
    if (input.exclude) {
      cut('.git/info/exclude', () => {});
      if (input.exclude.contentRef !== input.exclude.sha256) return refused('exclude output differs from its original fixed result');
      const bytes = await artifacts.withReadSignal(signal).readBoundedBytes(input.exclude.contentRef,
        Math.min(1_048_576, request.sandboxResources.maxSingleFileBytes, request.sandboxResources.maxInvocationOutputBytes));
      const scope = scopes.get('.git/info/exclude')!;
      if (bytes.length !== input.exclude.byteCount || scope.expectedDigest !== undefined && scope.expectedDigest !== input.exclude.sha256)
        return refused('exclude output differs from its exact read scope');
      sources.push({ kind: 'git_info_exclude', path: '.git/info/exclude', bytes }); total += bytes.length; usedScopes.add('.git/info/exclude');
    }
    const top = workspace.openSnapshot(); cursors.push(top);
    const queue: Array<{ cursor: HeldWorkspaceCursor; parents: RuleSource[] }> = [{ cursor: top, parents: [...sources] }];
    for (let at = 0; at < queue.length; at++) {
      signal.throwIfAborted(); const frame = queue[at]!, members: HeldWorkspaceEntry[] = [];
      for (;;) {
        await setImmediate(); signal.throwIfAborted(); const entry = frame.cursor.next(); if (!entry) break;
        entries.push(entry); members.push(entry);
        if (++count > 100_000) throw new KernelStorageError('BUDGET_EXHAUSTED', 'source ignore metadata exceeds its original inventory limit');
      }
      frame.cursor.assertComplete();
      const inherited = compileFrozenIgnoreRules(frame.parents, input.index.repositoryIdentityDigest), parentIgnored = createFrozenIgnoreMatcher(inherited);
      const rule = members.find(entry => entry.path.split('/').at(-1) === '.gitignore');
      const current = [...frame.parents];
      if (rule && (scopes.has(rule.path) || !excluded(rule.path) && (tracked.has(rule.path) || !parentIgnored(rule.path, false)))) {
        if (rule.kind !== 'file' || rule.identity.deviceId !== workspace.identity.deviceId ||
            rule.byteCount > Math.min(1_048_576, request.sandboxResources.maxSingleFileBytes, request.sandboxResources.maxInvocationOutputBytes))
          return refused('selected ignore source is not a bounded same-device ordinary file');
        let reader: ReturnType<HeldWorkspaceEntry['openFile']> | undefined;
        await recheckVerifiedSourceInspectionTarget(owner, target); cut(scopes.has(rule.path) ? rule.path : undefined, () => { reader = rule.openFile(); });
        const chunks: Buffer[] = []; let byteCount = 0, readError: unknown;
        try {
          for (;;) { await setImmediate(); signal.throwIfAborted(); reader!.assertHeld(); const chunk = reader!.readChunk();
            if (chunk === null) break; byteCount += chunk.length;
            if (byteCount > rule.byteCount || byteCount > 16_777_216 - total) return refused('ignore sources exceed their original complete byte limits'); chunks.push(chunk); }
          reader!.assertHeld(); rule.assertHeld();
          if (byteCount !== rule.byteCount) return refused('ignore source changed during its actual complete read');
        } catch (error) { readError = error; throw error; }
        finally { if (reader) retire([reader], readError); }
        const bytes = Buffer.concat(chunks, byteCount), published = await artifacts.publishBytes(bytes,
          'text/plain; charset=utf-8', 'cliq-ignore-rule-source-v1'); signal.throwIfAborted(); rule.assertHeld();
        const scope = scopes.get(rule.path);
        if (scope?.expectedDigest !== undefined && scope.expectedDigest !== published.ref) return refused('ignore source differs from its expected read digest');
        if (scope) usedScopes.add(rule.path);
        metadata.push(published); const source = { kind: 'gitignore' as const, path: rule.path, bytes };
        sources.push(source); current.push(source); total += byteCount;
      }
      const ignored = createFrozenIgnoreMatcher(compileFrozenIgnoreRules(current, input.index.repositoryIdentityDigest));
      for (const entry of members) {
        if (entry.kind !== 'directory' || hardRoots.some(root => below(entry.path, root)) ||
            entry.identity.deviceId !== workspace.identity.deviceId ||
            entry.identity.deviceId === controlledHome.identity.deviceId && entry.identity.fileId === controlledHome.identity.fileId ||
            entry.identity.deviceId === stateRoot.deviceId && entry.identity.fileId === stateRoot.directoryFileId) continue;
        const scopedDescendant = [...scopes.keys()].some(value => value.startsWith(`${entry.path}/`));
        if (!scopedDescendant && (excluded(entry.path) || ignored(entry.path, true)) && !trackedBelow(entry.path)) continue;
        const child = entry.openDirectory(); cursors.push(child); queue.push({ cursor: child, parents: current });
      }
    }
    if ([...scopes.keys()].some(value => !usedScopes.has(value))) return refused('source supplied a rule scope with no corresponding captured ordinary file');
    const rules = compileFrozenIgnoreRules(sources, input.index.repositoryIdentityDigest);
    const rulesArtifact = await artifacts.publishCanonical(rules, rules.format); signal.throwIfAborted();
    workspace.assertHeld(); controlledHome.assertHeld(); owner.filesystem.assertHeld();
    for (const cursor of cursors) cursor.assertComplete(); for (const entry of entries) entry.assertHeld();
    return { rules, rulesArtifact, metadata: [...metadata, rulesArtifact] };
  } catch (error) { operationError = error; throw error; }
  finally { retire([...cursors, ...entries], operationError); }
}
