import { decodePublicationActualPreimage, decodePublicationArenaBirth, decodePublicationProof,
  type PublicationAbortOperation, type PublicationArenaBirthV1, type PublicationOperation, type PublicationProofV1 } from '../kernel/publication.js';
import type { InvocationJournalEntry } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { WorkspaceEntryManifest } from '../kernel/types.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeWorkspaceEntries } from './decoders.js';
import type { HeldPublicationOperation } from './native-owner.js';

type Ambiguity = Extract<PublicationProofV1, { kind: 'path_ambiguity' }>;
type OriginalBinding = Readonly<{
  operation: PublicationOperation | PublicationAbortOperation;
  birth?: PublicationArenaBirthV1;
  claim: Pick<InvocationJournalEntry, 'phase' | 'runId' | 'opId' | 'attempt' | 'dispatchId' | 'evidenceRef' | 'evidenceDigest'>;
}>;

/** Readonly physical data plus CAS only. This does not validate the approved
 * preimage or grant progress, completion or cleanup authority. The owning
 * producer must independently retain and reassert its original native brand. */
export async function preserveActualEmptyPublicationDirectory(artifacts: ArtifactCatalog,
  original: Pick<HeldPublicationOperation, 'describeActualPreimage'>) {
  const actual = original.describeActualPreimage();
  if (actual.kind !== 'directory' || actual.empty !== true)
    throw new TypeError('actual displaced directory is not completely empty');
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [],
    entryCount: 0, byteCount: 0, treeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [] }) };
  const metadata = await artifacts.publishCanonical(entries, entries.format);
  requireEqual(original.describeActualPreimage(), actual, 'actual displaced empty directory across CAS preservation');
  return { actual, metadata, payload: { kind: 'empty_directory' as const, entriesRef: metadata.ref } };
}

/** Retained data only. The owning prefix reader must first validate the exact
 * original claim, birth, inspector/StateOwner lifetime and SQL cut. This helper
 * rehashes their data association and complete CAS payload; it mints no native
 * proof, progress, completion or cleanup authority. Labels are not authority. */
export async function readPublicationActualPreimage(artifacts: ArtifactCatalog, value: Ambiguity, binding: OriginalBinding) {
  const proof = decodePublicationProof(value);
  if (proof.kind !== 'path_ambiguity') throw new TypeError('actual preimage data belongs only to an unknown original operation');
  if (proof.preservedActualPreimageRef === undefined) return undefined;
  const { operation, claim } = binding;
  if (!binding.birth || !claim.evidenceRef || operation.kind !== 'replace' && operation.kind !== 'delete' ||
      claim.phase !== 'dispatch_claimed' || proof.sequence !== 'forward' || claim.runId !== proof.deliveryRunId ||
      claim.opId !== proof.opId || claim.attempt !== proof.attempt || claim.dispatchId !== proof.launchDispatchId ||
      operation.index !== proof.operationIndex || operation.operationId !== proof.operationId)
    throw new TypeError('actual preimage has no exact original displaced-operation binding');
  const birth = decodePublicationArenaBirth(await readCanonicalArtifact(artifacts, claim.evidenceRef));
  requireEqual(birth, decodePublicationArenaBirth(binding.birth), 'actual preimage exact original retained birth');
  if (birth.birthDigest !== claim.evidenceDigest || birth.deliveryRunId !== proof.deliveryRunId || birth.deliveryPlanRef !== proof.deliveryPlanRef ||
      birth.sequence !== proof.sequence || birth.operationIndex !== proof.operationIndex || birth.operationId !== proof.operationId ||
      birth.opId !== proof.opId || birth.attempt !== proof.attempt || birth.dispatchId !== proof.launchDispatchId ||
      birth.workspaceIdentityRef !== proof.workspaceIdentityRef || birth.workspaceIdentityDigest !== proof.workspaceIdentityDigest ||
      birth.inspectorIdentityRef !== proof.inspectorIdentityRef || birth.inspectorIdentityDigest !== proof.inspectorIdentityDigest)
    throw new TypeError('actual preimage changed its original claim, private birth or native owner');
  const data = decodePublicationActualPreimage(await readCanonicalArtifact(artifacts, proof.preservedActualPreimageRef));
  const components = operation.kind === 'replace' ? [operation.stagingName, operation.quarantineName] : [operation.quarantineName];
  if (data.deliveryRunId !== proof.deliveryRunId || data.deliveryPlanRef !== proof.deliveryPlanRef || data.sequence !== proof.sequence ||
      data.operationIndex !== proof.operationIndex || data.operationId !== proof.operationId || data.opId !== proof.opId || data.attempt !== proof.attempt ||
      data.dispatchId !== proof.launchDispatchId || data.arenaBirthRef !== claim.evidenceRef || data.location.arenaId !== birth.arenaId ||
      !components.includes(data.location.component) || data.physical.identity.deviceId !== birth.arenaIdentity.deviceId ||
      data.physical.identity.ownerUid !== birth.arenaIdentity.ownerUid)
    throw new TypeError('actual preimage substituted its exact original operation or controlled slot');
  if (data.payload.kind === 'empty_directory') {
    const entries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, data.payload.entriesRef));
    if (entries.entries.length || entries.entryCount || entries.byteCount) throw new TypeError('actual directory preimage is not empty');
  } else {
    for await (const _ of artifacts.readChunks(data.payload.bytesRef, data.payload.byteCount)) { /* complete raw hash and actual close/join */ }
  }
  return data;
}
