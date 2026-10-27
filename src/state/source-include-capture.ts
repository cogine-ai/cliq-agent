import { canonicalSha256 } from '../kernel/canonical.js';
import { setImmediate } from 'node:timers/promises';
import { digestOmitting } from '../kernel/identity.js';
import type { SourceIncludeAuthorizationV1 } from '../kernel/source-include.js';
import type { FrozenIgnoreRulesV1, GitIndexSnapshotV1, WorkspaceEntryManifest } from '../kernel/types.js';
import { createSourceClassifier } from '../workspace/source-classification.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { VerifierAuthorizationError } from './authorization-artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import type { HeldWorkspaceEntry } from './native-owner.js';
import { decodeSourceIncludeAuthorization, readSourceIncludeGrantReceipt } from './source-include-artifacts.js';
import { publishSourceIncludeClassification, type SourceIncludeClassificationEntry } from './source-include-classification.js';
import type { readVerifiedSourceIncludeCapture } from './source-target.js';
import { assertSourceIncludeExpectedDigest } from './source-include-constraints.js';

/** Inert data construction from the owning capture's original descriptor
 * observations. The caller checks its genuine target/SQL cut before payload
 * reads and retains every descriptor through publication and complete reread. */
export async function publishSourceIncludeAuthorizations(input: {
  artifacts: ArtifactCatalog; capture: ReturnType<typeof readVerifiedSourceIncludeCapture>;
  entries: WorkspaceEntryManifest; observations: ReadonlyMap<string, HeldWorkspaceEntry>;
  rules: FrozenIgnoreRulesV1; rulesRef: string; index?: GitIndexSnapshotV1; indexRef?: string; signal?: AbortSignal;
}) {
  const { artifacts, capture, observations, signal } = input;
  const classifier = createSourceClassifier(input.rules,input.index);
  const includes: Array<{ path: string; scope: 'entry' | 'subtree'; authorizationRef: string }> = [];
  const metadata: PublishedArtifact[] = [];
  for (const selector of capture.selectors) {
    signal?.throwIfAborted();
    const { path, scope } = selector;
    const entries: WorkspaceEntryManifest['entries'] = [];
    for (let index=0;index<input.entries.entries.length;index++) {
      if (index % 128 === 0) { await setImmediate();signal?.throwIfAborted(); }
      const entry = input.entries.entries[index]!;
      if (entry.path === path || scope === 'subtree' && entry.path.startsWith(`${path}/`)) entries.push(entry);
    }
    if (!entries.length) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const common = { schemaVersion: 1 as const, format: 'cliq-source-include-authorization-v1' as const,
      principalId: capture.principalId, inspectionId: capture.inspectionId, runId: capture.runId, sessionId: capture.sessionId,
      workspaceIdentityRef: capture.workspaceIdentityRef, workspaceIdentityDigest: capture.workspaceIdentityDigest,
      selector: { path, scope }, selectorDigest: canonicalSha256({ path, scope }),
      admissionIntentDigest: capture.admissionIntentDigest, capturedEntriesRef:canonicalSha256(input.entries),
      capturedTreeDigest:input.entries.treeDigest, createdAt: capture.createdAt, authorizationDigest: '' };
    let authorization: SourceIncludeAuthorizationV1;
    if (selector.readGrantId !== undefined) {
      const consent = capture.scopes.find(value => value.grantId === selector.readGrantId);
      if (!consent || consent.target.canonicalRootRelativePath !== path || consent.target.scope !== scope ||
          !entries.some(entry => classifier.classify(entry) === undefined))
        throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
      assertSourceIncludeExpectedDigest(consent.target,input.entries);
      authorization = { ...common, kind: 'consumed_user_read_grant', authorizationGrantId: consent.grantId,
        consumedGrantSnapshotRef:consent.snapshotRef,
        authorizationGrantTargetDigest: consent.receipt.targetDigest, consumptionReceiptRef: canonicalSha256(consent.receipt),
        consumptionReceiptDigest: consent.receipt.receiptDigest };
      authorization.authorizationDigest = digestOmitting(authorization,'authorizationDigest');
      readSourceIncludeGrantReceipt(authorization,consent.receipt);
    } else {
      const classified: SourceIncludeClassificationEntry[] = [];
      for (let index=0;index<entries.length;index++) {
        if (index % 128 === 0) { await setImmediate();signal?.throwIfAborted(); }
        const entry = entries[index]!;
        const observed = observations.get(entry.path);
        if (!observed || observed.kind !== entry.kind) throw new TypeError('source include has no original held observation');
        observed.assertHeld();
        const classification = classifier.classify(entry);
        if (!classification) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
        classified.push({ path:entry.path,entryKind:entry.kind,workspaceEntryDigest:canonicalSha256(entry),deviceId:observed.identity.deviceId,
          fileId:observed.identity.fileId,linkCount:observed.linkCount,classification });
      }
      const usesGit = classified.some(entry => entry.classification !== 'nonignored_in_root');
      if (usesGit && (!input.index || !input.indexRef)) throw new TypeError('tracked source include lost its original canonical Git index');
      const evidence = await publishSourceIncludeClassification(artifacts, {
        principalId:capture.principalId,inspectionId:capture.inspectionId,runId:capture.runId,sessionId:capture.sessionId,
        workspaceIdentityRef:capture.workspaceIdentityRef,workspaceIdentityDigest:capture.workspaceIdentityDigest,
        selector:{path,scope},selectorDigest:common.selectorDigest,admissionIntentDigest:capture.admissionIntentDigest,
        frozenIgnoreRulesRef:input.rulesRef,frozenIgnoreRulesDigest:input.rules.rulesDigest,
        capturedEntriesRef:canonicalSha256(input.entries),capturedTreeDigest:input.entries.treeDigest,
        ...(usesGit ? {gitIndexRef:input.indexRef!,gitIndexTreeObjectId:input.index!.indexTreeObjectId} : {}),
        observedAt:sampleCanonicalNow()
      },classified,signal);
      metadata.push(...evidence.metadata);
      authorization = { ...common,kind:'builtin_nonignored',frozenIgnoreRulesRef:input.rulesRef,
        frozenIgnoreRulesDigest:input.rules.rulesDigest,classification:'tracked_or_nonignored_in_root',
        classificationEvidenceRef:evidence.ref,classificationEvidenceDigest:evidence.evidence.evidenceDigest };
      authorization.authorizationDigest = digestOmitting(authorization,'authorizationDigest');
    }
    decodeSourceIncludeAuthorization(authorization); signal?.throwIfAborted();
    const published = await artifacts.publishCanonical(authorization,authorization.format); metadata.push(published);
    includes.push({path,scope,authorizationRef:published.ref});
  }
  return Object.freeze({ includes,metadata:Object.freeze(metadata) });
}
