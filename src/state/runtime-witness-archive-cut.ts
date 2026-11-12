import { canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from '../kernel/control-wire-data.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import { decodeLocalModelRegistration } from '../kernel/local-inference.js';
import { splitLocalInferenceNativeInput } from '../kernel/local-inference-native-input.js';
import { decodeRuntimeWitnessArchiveEntry, RUNTIME_WITNESS_MAX_ENTRIES, type RuntimeWitnessArchiveEntry } from '../kernel/kernel-archive-runtime-witness.js';
import { decodeKernelArchiveDirectoryIdentity } from '../kernel/kernel-archive-namespace.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { withInstalledWorkerRoot, type HeldInstalledAnchor, type HeldInstalledRuntime } from './installed-runtime.js';
import { readRetainedLocalInferenceLaunch } from './local-inference-launch.js';
import { readLocalInferenceCycle, readLocalInferenceLaunch } from './local-inference-rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import type { RetainedStateOwnerHistory } from './state-owner-history.js';
import { assertInstalledExclusiveReadSource, type InstalledExclusiveReadSource } from './store.js';
import { readSupervisorInspector } from './supervisor-inspector.js';

export type InstalledRuntimeWitnessCut = Readonly<{ count: number }>;
export type OriginalRuntimeWitnessEntry = Readonly<{
  origin: Buffer; kind: 1 | 2; verifyObservation(value: unknown): RuntimeWitnessArchiveEntry;
}>;
const cuts = new WeakMap<InstalledRuntimeWitnessCut, Readonly<{
  selected: HeldInstalledRuntime; anchor?: HeldInstalledAnchor; assertCurrent(): void;
  entries(): AsyncIterable<OriginalRuntimeWitnessEntry>;
}>>();
function fail(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }

/** Fixed whole SQL launch cut under the genuine Store EX. Every retained
 * launch requires its exact original cycle, signed recipe, birth and
 * retirement evidence. The actual native observation is separate. */
export function openInstalledRuntimeWitnessCut(input: Readonly<{
  selected: HeldInstalledRuntime; anchor?: HeldInstalledAnchor; source: InstalledExclusiveReadSource;
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; history: RetainedStateOwnerHistory;
}>, signal?: AbortSignal): InstalledRuntimeWitnessCut {
  const { selected, source, driver, artifacts, owner, history } = input;
  const assertCurrent = () => {
    signal?.throwIfAborted(); assertInstalledExclusiveReadSource(source, driver, owner); artifacts.assertReadActive();
  };
  assertCurrent();
  const count = driver.readSnapshot(connection => {
    history.assertUnchanged(connection);
    if (connection.prepare("SELECT 1 FROM local_inference_launches WHERE phase <> 'retired' OR retired_at IS NULL LIMIT 1").get())
      return fail('runtime witness capture requires every original local service launch to be retired');
    const size = connection.prepare('SELECT count(*) AS count FROM local_inference_launches').get<{ count: bigint }>()?.count;
    if (typeof size !== 'bigint' || size < 0n || size > BigInt(RUNTIME_WITNESS_MAX_ENTRIES))
      return fail('retained local runtime witness inventory exceeds its original bound');
    return Number(size);
  });
  if (count && !input.anchor) return fail('retired runtime witnesses require their original genuine installed Anchor');
  const result = Object.freeze({ count });
  async function* entries(): AsyncIterableIterator<OriginalRuntimeWitnessEntry> {
    assertCurrent();
    let after = '', total = 0;
    for (;;) {
      const page = driver.prepare('SELECT launch_id FROM local_inference_launches WHERE launch_id > ? COLLATE BINARY ORDER BY launch_id COLLATE BINARY LIMIT 64')
        .all<{ launch_id: string }>(after);
      if (!page.length) break;
      for (const row of page) {
        assertCurrent();
        const launch = readLocalInferenceLaunch(driver, row.launch_id);
        if (!launch || launch.phase !== 'retired' || row.launch_id <= after || ++total > count)
          return fail('retained runtime witness launch membership changed');
        after = row.launch_id;
        const cycle = readLocalInferenceCycle(driver, launch.activationCycleId);
        if (!cycle || cycle.launchIds[launch.activationAttempt - 1] !== launch.launchId) return fail('retained runtime launch lost its exact cycle');
        const registration = decodeLocalModelRegistration(await readCanonicalArtifact(artifacts, cycle.localModelRegistrationRef));
        const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, registration.serviceSpec.runtimeBundleRef);
        const recipe = await readRetainedLocalInferenceLaunch(artifacts, launch, cycle, registration, bundle);
        const { original } = recipe, originalEpoch = original.data.binding.stateOwnerEpoch;
        const originalOwner = history.entries[originalEpoch - 1];
        if (!originalOwner || originalOwner.owner.ownerEpoch !== originalEpoch ||
            originalOwner.owner.supervisorInstanceId !== launch.supervisorInstanceId ||
            originalOwner.owner.runtimeBundleRef !== registration.serviceSpec.runtimeBundleRef ||
            (originalEpoch === owner.ownerEpoch ? originalOwner.owner.state !== 'active' :
              originalEpoch >= owner.ownerEpoch || originalOwner.owner.state !== 'terminal'))
          return fail('retained runtime witness belongs to another original Supervisor');
        if (originalEpoch < owner.ownerEpoch)
          owner.filesystem.assertPriorProcessDead(originalOwner.process.pid, originalOwner.process.processStartToken);
        const kind = launch.retirementKind === 'no_spawn' ? 1 : 2;
        const proofValue = await readCanonicalArtifact(artifacts, launch.retirementEvidenceRef);
        assertControlWireJson(proofValue);
        const proof = controlWireRecord(proofValue, ['schemaVersion', 'kind', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest',
          'owner', 'launchNonceDigest', 'inspectorSupervisorInstanceId', 'inspectorIdentityRef', 'inspectorIdentityDigest',
          'backend', 'observedAt', 'evidenceDigest', ...(kind === 2 ? ['containmentRef'] : [])]);
        const inspectorIdentityRef = controlWireRef(proof.inspectorIdentityRef);
        const inspectorLocation = await readCanonicalArtifact<{ stateOwnerEpoch?: unknown }>(artifacts, inspectorIdentityRef);
        const inspectorEpoch = controlWireInteger(inspectorLocation?.stateOwnerEpoch, originalEpoch, owner.ownerEpoch);
        const inspector = history.entries[inspectorEpoch - 1];
        if (!inspector || inspector.owner.ownerEpoch !== inspectorEpoch ||
            inspector.owner.supervisorInstanceId !== proof.inspectorSupervisorInstanceId || proof.schemaVersion !== 1 ||
            proof.kind !== (kind === 1 ? 'containment_plan_quiescent' : 'containment_all_descendants_dead') ||
            proof.planRef !== launch.containmentPlanRef || proof.sandboxLaunchSpecRef !== launch.sandboxLaunchSpecRef ||
            proof.sandboxLaunchSpecDigest !== recipe.spec.launchSpecDigest || proof.launchNonceDigest !== recipe.plan.launchNonceDigest ||
            canonicalSha256(proof.owner) !== canonicalSha256(recipe.plan.owner) || proof.observedAt !== launch.retiredAt ||
            digestOmitting(proof, 'evidenceDigest') !== proof.evidenceDigest ||
            (inspector.owner.state === 'terminal' && inspector.owner.releasedAt < launch.retiredAt))
          return fail('retained runtime witness has an incompatible original retirement record');
        await readSupervisorInspector(artifacts, inspector.owner, { runtime: inspector.owner }, {
          inspectorIdentityRef, inspectorIdentityDigest: controlWireRef(proof.inspectorIdentityDigest),
          observedAt: launch.retiredAt
        });
        const containmentRef = launch.retirementKind === 'death' ? launch.processContainmentRef : undefined;
        const containment = containmentRef ? await readCanonicalArtifact(artifacts, containmentRef) : undefined;
        if (kind === 2 && (!containmentRef || proof.containmentRef !== containmentRef)) return fail('retired service lost its original containment');
        assertCurrent();
        const origin = splitLocalInferenceNativeInput(recipe.bytes).origin;
        yield Object.freeze({ origin, kind, verifyObservation(value: unknown) {
          assertCurrent(); assertControlWireJson(value);
          const actual = controlWireRecord(value, ['nativeNonce', 'launchId', 'file', 'sha256', 'sourceCtimeSeconds', 'sourceCtimeNanos',
            'cgroupFileId', 'pidNamespaceId', 'namespaceInitStartToken', 'byteCount']);
          const file = decodeKernelArchiveDirectoryIdentity(actual.file);
          const cgroupId = controlWireText(actual.cgroupFileId, 20), namespaceId = controlWireText(actual.pidNamespaceId, 20);
          const init = typeof actual.namespaceInitStartToken === 'string' ? actual.namespaceInitStartToken : fail('native runtime witness lacks namespace identity');
          if (!/^(0|[1-9][0-9]*)$/u.test(cgroupId) || !/^(0|[1-9][0-9]*)$/u.test(namespaceId) ||
              ((namespaceId === '0') !== (init === '')) || (init !== '' && !/^linux-proc-start-ticks:[1-9][0-9]{0,19}$/u.test(init)) ||
              actual.nativeNonce !== original.data.binding.nativeNonce || actual.launchId !== launch.launchId ||
              file.fileId !== original.origin.witness.fileId || file.deviceId !== original.origin.witness.deviceId ||
              file.ownerUid !== original.origin.witness.uid)
            return fail('current native witness differs from its exact original launch birth');
          const { cgroupPath, pidNamespaceReservationId, subreaperStartToken } = recipe.plan.backend;
          if (kind === 1) {
            const expected = { kind: 'linux', cgroupPath, subreaperStartToken, matchingLaunchNonceProcessCount: 0,
              cgroupObservation: cgroupId === '0' ? { kind: 'absent' } : { kind: 'empty', cgroupId, populated: 0 },
              pidNamespaceObservation: init === '' ? { kind: 'never_created', pidNamespaceReservationId } :
                { kind: 'dead_reaped', pidNamespaceReservationId, namespaceInitStartToken: init } };
            if (canonicalSha256(proof.backend) !== canonicalSha256(expected))
              return fail('current runtime no-spawn proof differs from the exact retired observation');
          } else {
            if (cgroupId === '0' || namespaceId === '0' || !containment) return fail('current runtime death proof lacks its original namespace');
            assertControlWireJson(containment);
            const record = controlWireRecord(containment, ['schemaVersion', 'owner', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest',
              'filesystemBinding', 'launchNonceDigest', 'backend', 'createdAt']);
            const createdAt = controlWireText(record.createdAt);
            parseCanonicalTime(createdAt);
            const backend = { kind: 'linux', pidNamespaceId: namespaceId, cgroupId, namespaceInitStartToken: init,
              pidNamespaceReservationId, subreaperStartToken, cgroupPath };
            if (createdAt < launch.createdAt || createdAt >= launch.activationDeadlineAt ||
                canonicalSha256(record) !== canonicalSha256({ schemaVersion: 1, owner: recipe.plan.owner,
                  planRef: launch.containmentPlanRef, sandboxLaunchSpecRef: launch.sandboxLaunchSpecRef,
                  sandboxLaunchSpecDigest: recipe.spec.launchSpecDigest, filesystemBinding: recipe.plan.filesystemBinding,
                  launchNonceDigest: recipe.plan.launchNonceDigest, backend, createdAt }) ||
                canonicalSha256(proof.backend) !== canonicalSha256({ ...backend, cgroupPopulated: 0,
                  namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 }))
              return fail('current runtime death proof differs from the exact original retired containment');
          }
          return decodeRuntimeWitnessArchiveEntry({
            nativeNonce: actual.nativeNonce, launchId: launch.launchId, sourceFileId: file.fileId, byteCount: controlWireInteger(actual.byteCount),
            sha256: actual.sha256, nativeInputRef: launch.nativeInputRef, retirementEvidenceRef: launch.retirementEvidenceRef,
            retirementKind: launch.retirementKind, sourceCtimeSeconds: actual.sourceCtimeSeconds, sourceCtimeNanos: actual.sourceCtimeNanos
          });
        } });
      }
    }
    assertCurrent(); if (total !== count) return fail('retained runtime witness cut ended before its original launch count');
  }
  cuts.set(result, { selected, ...(input.anchor ? { anchor: input.anchor } : {}), assertCurrent, entries });
  return result;
}
export function installedRuntimeWitnessEntries(cut: InstalledRuntimeWitnessCut): AsyncIterable<OriginalRuntimeWitnessEntry> {
  const original = cuts.get(cut);
  if (!original) throw new TypeError('runtime witness read requires the genuine installed EX cut');
  original.assertCurrent(); return original.entries();
}
export function withInstalledRuntimeWitnessAnchor(cut: InstalledRuntimeWitnessCut, operation: (fd: number) => void): void {
  const original = cuts.get(cut);
  if (!original?.anchor) throw new TypeError('runtime witness observation requires its genuine installed Anchor');
  original.assertCurrent(); withInstalledWorkerRoot(original.selected, original.anchor, fd => operation(fd)); original.assertCurrent();
}
