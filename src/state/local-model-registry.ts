// One original model-store EX scope owns the pointer pager, immutable graph,
// source package and final admission consumer. This is not a Run ledger.
import { DatabaseSync } from 'node:sqlite';
import { setImmediate as yieldImmediate } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, sha256Bytes } from '../kernel/identity.js';
import { controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from '../kernel/control-wire-data.js';
import { decodeLocalInferenceServiceSpec, decodeLocalModelManifest, decodeLocalModelObjectClosure,
  decodeLocalModelRegistration, decodeLocalModelRegistryHead, localServiceSpecCoreDigest,
  type LocalModelManifestV1, type LocalModelObjectClosureV1, type LocalModelRegistrationV1,
  type LocalModelRegistryHeadV1, type LocalModelObjectV1 } from '../kernel/local-inference.js';
import type { StateRootIdentityV1 } from '../kernel/types.js';
import { verifyLocalModelManifestAuthority } from '../policy/local-model-authority.js';
import { requireEqual, verifyRuntimeBundle, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { immutableSnapshot } from '../model/immutable.js';
import { joinResourceOperations, KernelStorageError, ResourceRetirementError } from './errors.js';
import { withInstalledLocalModelStore, withInstalledExistingLocalModelStore, withInstalledLocalAdmissionCredentialLock,
  type HeldCredentialAuthorityLock, type InstalledRuntimeBorrow } from './installed-runtime.js';
import type { NativeLocalModelStore } from './local-model-store-native.js';
import { validateLocalModelRegistryStep, assertLocalModelRetiredCopy, nextLocalModelPort, type LocalModelRegistryStep } from './local-model-registry-data.js';
import { installedLocalInferenceProfile } from './local-inference-profile.js';
import { decodeSandboxProfile } from './execution-closure.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';

const URI = 'file:cliq-local-model-registry?vfs=cliq-local-model-store-v1';
const TABLE = `CREATE TABLE model_registry (
  ownerPrincipalId TEXT NOT NULL,
  provider TEXT NOT NULL CHECK(provider = 'ollama'),
  model TEXT NOT NULL,
  currentHeadRef TEXT NOT NULL,
  currentHeadDigest TEXT NOT NULL,
  headRevision INTEGER NOT NULL CHECK(headRevision >= 1),
  PRIMARY KEY(ownerPrincipalId, provider, model)
) STRICT, WITHOUT ROWID`;
type Pointer = Readonly<{ ownerPrincipalId: string; provider: 'ollama'; model: string;
  currentHeadRef: string; currentHeadDigest: string; headRevision: number }>;
type Active = LocalModelRegistrationV1 & { state: 'active' };
type Retired = LocalModelRegistrationV1 & { state: 'retired' };
type Step = LocalModelRegistryStep & { head: LocalModelRegistryHeadV1 };
export type RetainedLocalModel = Readonly<{ head: LocalModelRegistryHeadV1; active?: Active; retired?: Retired }>;
export type LocalModelRegistry = Readonly<{
  readonly rootIdentity: StateRootIdentityV1;
  readonly ownerPrincipalId: string;
  assertHeld(): void;
  /** Current head is for new selection only. The callback remains inside the
   * original store lock, including the final new-Run admission transaction. */
  select(model: string): Promise<RetainedLocalModel | undefined>;
  list(): Promise<readonly RetainedLocalModel[]>;
  retainedRegistrations(): Promise<readonly LocalModelRegistrationV1[]>;
  readOriginalRegistration(reference: string, digest: string): LocalModelRegistrationV1;
  readObject(reference: string): Buffer;
  retainForRun(registration: LocalModelRegistrationV1, artifacts: ArtifactCatalog): Promise<readonly PublishedArtifact[]>;
  withAdmissionCredentials<T>(operation: (token: HeldCredentialAuthorityLock) => Promise<T>): Promise<T>;
  importPackage(manifestPath: string, signal?: AbortSignal): Promise<Readonly<{
    manifest: LocalModelManifestV1; closure: LocalModelObjectClosureV1 }>>;
  /** The original lock chooses the signed recipe and retained port. */
  enroll(manifest: LocalModelManifestV1, closure: LocalModelObjectClosureV1,
    committedAt: string): Promise<RetainedLocalModel>;
  retire(model: string, committedAt: string): Promise<RetainedLocalModel>;
}>;
function mismatch(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function decodePointer(value: unknown): Pointer {
  const data = controlWireRecord(value, ['ownerPrincipalId', 'provider', 'model', 'currentHeadRef', 'currentHeadDigest', 'headRevision']);
  controlWireText(data.ownerPrincipalId, 512); controlWireText(data.model, 512);
  if (data.provider !== 'ollama') mismatch('local registry provider differs from the fixed recipe');
  controlWireRef(data.currentHeadRef); controlWireRef(data.currentHeadDigest); controlWireInteger(data.headRevision, 1);
  return data as Pointer;
}
function decodeObject<T>(scope: NativeLocalModelStore, reference: string, decode: (value: unknown) => T): T {
  controlWireRef(reference); scope.assertHeld();
  const bytes = scope.readSmallObject(reference);
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 1_048_576 || sha256Bytes(bytes) !== reference)
    mismatch('original model-store object bytes differ from their content identity');
  let value: T;
  try { value = decode(JSON.parse(bytes.toString('utf8')) as unknown); }
  catch { return mismatch('original model-store object has invalid closed data'); }
  if (!canonicalJsonBytes(value).equals(bytes)) mismatch('original model-store structured object is not complete JCS');
  scope.assertHeld(); return value;
}
function publish(scope: NativeLocalModelStore, value: unknown): string {
  const bytes = canonicalJsonBytes(value), reference = sha256Bytes(bytes);
  scope.assertHeld(); scope.publishSmallObject(reference, bytes); scope.assertHeld(); return reference;
}
function withDigest<T extends { [key: string]: unknown }>(value: T, member: keyof T & string): T {
  return { ...value, [member]: digestOmitting(value, member) };
}
function expectedInventory(manifest: LocalModelManifestV1): Buffer {
  const objects = [{ reference: manifest.signatureRef, size: 64 }, { reference: manifest.tokenizerRef, size: 0 },
    ...manifest.files.map(file => ({ reference: file.contentRef, size: file.sizeBytes }))];
  if (objects.length > 10000) throw new TypeError('model package inventory exceeds its fixed entry budget');
  const bytes = Buffer.alloc(objects.length * 72);
  for (const [index, object] of objects.entries()) {
    bytes.write(object.reference, index * 72, 64, 'ascii'); bytes.writeBigUInt64LE(BigInt(object.size), index * 72 + 64);
  }
  return bytes;
}
function capturedInventory(bytes: Buffer, manifest: LocalModelManifestV1): ReadonlyMap<string, number> {
  const expected = expectedInventory(manifest), sizes = new Map<string, number>();
  if (!Buffer.isBuffer(bytes) || bytes.length !== expected.length) mismatch('native model inventory differs from its original closed count');
  for (let offset = 0; offset < bytes.length; offset += 72) {
    const reference = bytes.toString('ascii', offset, offset + 64), count = bytes.readBigUInt64LE(offset + 64);
    controlWireRef(reference);
    if (count < 1n || count > BigInt(Number.MAX_SAFE_INTEGER) || sizes.has(reference)) mismatch('native model inventory has invalid size or duplicate identity');
    sizes.set(reference, Number(count));
  }
  for (let offset = 0; offset < expected.length; offset += 72) {
    const reference = expected.toString('ascii', offset, offset + 64), size = Number(expected.readBigUInt64LE(offset + 64));
    if (!sizes.has(reference) || size && sizes.get(reference) !== size) mismatch('native model inventory differs from the signed original sizes');
  }
  return sizes;
}
async function importOriginalPackage(scope: NativeLocalModelStore, installed: InstalledRuntimeBorrow,
  rootIdentity: StateRootIdentityV1, manifestPath: string, signal?: AbortSignal): Promise<Readonly<{
    manifest: LocalModelManifestV1; closure: LocalModelObjectClosureV1 }>> {
  signal?.throwIfAborted(); scope.assertHeld();
  const original = scope.openPackage(manifestPath);
  let failed = false, failure: unknown;
  try {
    const bytes = original.readManifest();
    if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 1_048_576) throw new TypeError('model manifest must be bounded complete JCS');
    const manifest = decodeLocalModelManifest(JSON.parse(bytes.toString('utf8')) as unknown);
    if (!canonicalJsonBytes(manifest).equals(bytes)) throw new TypeError('model manifest must contain exactly its signed JCS bytes');
    const sizes = capturedInventory(original.captureInventory(expectedInventory(manifest)), manifest);
    const signatureBytes = original.readSignature(manifest.signatureRef);
    verifyLocalModelManifestAuthority({ bundle: installed.bundle, releaseKeys: installed.releaseKeys, manifestBytes: bytes, signatureBytes });
    const objects: LocalModelObjectV1[] = [
      { kind: 'model_manifest', logicalPath: 'model-manifest.json', artifactRef: canonicalSha256(manifest), artifactDigest: canonicalSha256(manifest), sizeBytes: bytes.length },
      { kind: 'model_signature', logicalPath: 'model-signature', artifactRef: manifest.signatureRef, artifactDigest: manifest.signatureRef, sizeBytes: 64 },
      { kind: 'tokenizer', logicalPath: 'tokenizer', artifactRef: manifest.tokenizerRef, artifactDigest: manifest.tokenizerRef, sizeBytes: sizes.get(manifest.tokenizerRef)! },
      ...manifest.files.map(file => ({ kind: 'model_file' as const, logicalPath: file.canonicalRelativePath,
        artifactRef: file.contentRef, artifactDigest: file.contentDigest, sizeBytes: file.sizeBytes }))
    ];
    let totalBytes = 0;
    for (const object of objects) { totalBytes += object.sizeBytes; if (!Number.isSafeInteger(totalBytes)) throw new TypeError('complete model object bytes exceed the safe total'); }
    const closure = decodeLocalModelObjectClosure(withDigest({ schemaVersion: 1, format: 'cliq-local-model-object-closure-v1',
      stateRootIdentityRef: canonicalSha256(rootIdentity), stateRootIdentityDigest: rootIdentity.identityDigest,
      objectStoreRootRelativePath: 'local-models/objects', modelManifestRef: canonicalSha256(manifest),
      modelManifestDigest: manifest.modelManifestDigest, objects, objectCount: objects.length, totalBytes, closureDigest: '' }, 'closureDigest'), manifest);
    // Every bounded step joins before yielding or observing cancellation. A
    // cancelled import leaves only fully verified orphan objects, never a head.
    for (const object of objects.slice(1)) {
      let complete = false;
      while (!complete) { signal?.throwIfAborted(); complete = original.copyObjectStep(object.artifactRef); await yieldImmediate(); }
    }
    original.finish(); signal?.throwIfAborted();
    if (!original.readManifest().equals(bytes)) throw new TypeError('original model manifest changed after complete import');
    publish(scope, installed.bundle); publish(scope, rootIdentity);
    publish(scope, manifest); publish(scope, closure); scope.assertHeld();
    return immutableSnapshot({ manifest, closure });
  } catch (error) { failed = true; failure = error; throw error; }
  finally {
    try { original.close(); }
    catch (error) { throw new ResourceRetirementError('original model source and private copy did not join',
      failed ? new AggregateError([failure, error]) : error); }
  }
}
function initializeDatabase(scope: NativeLocalModelStore, allowInitialize: boolean): DatabaseSync {
  scope.assertHeld();
  const db = new DatabaseSync(URI, { allowExtension: false });
  try {
    db.exec('PRAGMA trusted_schema=OFF; PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0');
    const databases = db.prepare('PRAGMA database_list').all();
    if (databases.length !== 1 || databases[0]?.name !== 'main' || databases[0]?.file !== '/cliq-local-model-registry')
      mismatch('model registry pager did not use its fixed original-descriptor VFS');
    const entries = db.prepare("SELECT type, name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name").all();
    if (entries.length === 0 && allowInitialize) db.exec(TABLE);
    else if (entries.length !== 1 || entries[0]?.type !== 'table' || entries[0]?.name !== 'model_registry' || entries[0]?.sql !== TABLE)
      mismatch('model registry must have exactly its fixed six-field pointer schema');
    scope.assertHeld(); return db;
  } catch (error) {
    try { db.close(); }
    catch (close) { throw new ResourceRetirementError('model registry bootstrap pager did not join', new AggregateError([error, close])); }
    throw error;
  }
}
/** The original native holder surrounds the whole callback. A new Run's
 * caller must await its final admission transaction here, not return selected
 * data and release the lock before committing. Frozen historical reads use
 * readOriginalRegistration and never substitute today's pointer. */
export function withLocalModelRegistry<T>(installed: InstalledRuntimeBorrow,
  operation: (registry: LocalModelRegistry) => Promise<T>, signal?: AbortSignal): Promise<T> {
  return withInstalledLocalModelStore(installed, (scope, origin) => useLocalModelRegistry(installed, scope, origin, operation, true, signal), signal);
}
/** Source-only selection/revocation does not initialize an absent/incomplete
 * store. Each historical registration verifies its original signed runtime;
 * today's local-engine support is an enrollment/execution concern. */
export function withExistingLocalModelRegistry<T>(installed: InstalledRuntimeBorrow,
  operation: (registry: LocalModelRegistry | undefined) => Promise<T>, signal?: AbortSignal): Promise<T> {
  return withInstalledExistingLocalModelStore(installed, (scope, origin) => scope
    ? useLocalModelRegistry(installed, scope, origin, operation, false, signal) : operation(undefined), signal);
}
async function useLocalModelRegistry<T>(installed: InstalledRuntimeBorrow, scope: NativeLocalModelStore,
  origin: Readonly<{ rootIdentity: StateRootIdentityV1; ownerPrincipalId: string }>, operation: (registry: LocalModelRegistry) => Promise<T>,
  allowInitialize: boolean, signal?: AbortSignal): Promise<T> {
    const db = initializeDatabase(scope, allowInitialize); let active = true;
    const assertHeld = () => { if (!active) throw new TypeError('original model registry callback ended'); scope.assertHeld(); };
    const readRegistration = (reference: string, digest: string): LocalModelRegistrationV1 => {
      assertHeld(); const registration = decodeObject(scope, reference, decodeLocalModelRegistration);
      if (registration.registrationDigest !== controlWireRef(digest) || registration.ownerPrincipalId !== origin.ownerPrincipalId ||
          registration.objectClosure.stateRootIdentityRef !== canonicalSha256(origin.rootIdentity) ||
          registration.objectClosure.stateRootIdentityDigest !== origin.rootIdentity.identityDigest)
        mismatch('original model registration differs from its same-user selected root');
      requireEqual(decodeObject(scope, registration.expectedServiceSpecRef, decodeLocalInferenceServiceSpec), registration.serviceSpec, 'original registry service spec');
      requireEqual(decodeObject(scope, registration.expectedModelManifestRef, decodeLocalModelManifest), registration.modelManifest, 'original registry model manifest');
      requireEqual(decodeObject(scope, registration.expectedObjectClosureRef, value => decodeLocalModelObjectClosure(value, registration.modelManifest)),
        registration.objectClosure, 'original registry object closure');
      const bundle = decodeObject(scope, registration.serviceSpec.runtimeBundleRef, value => {
        const bundle = value as RuntimeBundleManifest; verifyRuntimeBundle(bundle, installed.releaseKeys); return bundle;
      });
      if (bundle.manifestDigest !== registration.serviceSpec.runtimeBundleManifestDigest)
        mismatch('original registry RuntimeBundle semantic identity differs');
      const profile = decodeObject(scope, registration.serviceSpec.sandboxProfileRef, decodeSandboxProfile);
      if (profile.profileDigest !== registration.serviceSpec.sandboxProfileDigest || profile.backend !== registration.serviceSpec.backend ||
          profile.allowedOwners.length !== 1 || profile.allowedOwners[0] !== 'local_inference_service')
        mismatch('original registry service profile differs from its original owner or semantic identity');
      requireEqual(profile.resources, registration.serviceSpec.resources, 'original registry service resource profile');
      verifyLocalModelManifestAuthority({ bundle, releaseKeys: installed.releaseKeys,
        manifestBytes: canonicalJsonBytes(registration.modelManifest), signatureBytes: scope.readSmallObject(registration.modelManifest.signatureRef) });
      const executable = bundle.entries.filter(entry => entry.entryId === registration.serviceSpec.executableId);
      if (executable.length !== 1 || executable[0]!.role !== 'local_inference' || !executable[0]!.executable ||
          executable[0]!.version !== registration.serviceSpec.executableVersion || executable[0]!.digest !== registration.serviceSpec.executableDigest)
        mismatch('original registry service executable differs from its original signed RuntimeBundle');
      return registration;
    };
    const readStep = (headRef: string, headDigest: string): RetainedLocalModel => {
      const head = decodeObject(scope, headRef, decodeLocalModelRegistryHead);
      if (head.headDigest !== headDigest || head.ownerPrincipalId !== origin.ownerPrincipalId) mismatch('model registry head differs from original pointer identity');
      const activeRegistration = 'activeRegistrationRef' in head ? readRegistration(head.activeRegistrationRef, head.activeRegistrationDigest) : undefined;
      const retiredRegistration = 'retiredRegistrationRef' in head ? readRegistration(head.retiredRegistrationRef, head.retiredRegistrationDigest) : undefined;
      if (activeRegistration && activeRegistration.state !== 'active' || retiredRegistration && retiredRegistration.state !== 'retired') mismatch('model registry head has substituted registration state');
      return immutableSnapshot({ head, ...(activeRegistration ? { active: activeRegistration as Active } : {}),
        ...(retiredRegistration ? { retired: retiredRegistration as Retired } : {}) });
    };
    const history = async (pointer: Pointer): Promise<readonly RetainedLocalModel[]> => {
      if (pointer.ownerPrincipalId !== origin.ownerPrincipalId) mismatch('foreign model registry pointer');
      const steps: RetainedLocalModel[] = [], visited = new Set<string>(); let reference = pointer.currentHeadRef, digest = pointer.currentHeadDigest;
      while (true) {
        assertHeld(); signal?.throwIfAborted();
        if (visited.has(reference)) mismatch('model registry predecessor cycle'); visited.add(reference);
        const step = readStep(reference, digest);
        if (step.head.model !== pointer.model || step.head.provider !== pointer.provider) mismatch('model registry history switched model identity');
        if (steps.length === 0 && step.head.headRevision !== pointer.headRevision) mismatch('model registry pointer revision differs from immutable head');
        steps.push(step);
        if (step.head.transition === 'initial') break;
        reference = step.head.predecessorHeadRef; digest = step.head.predecessorHeadDigest; await yieldImmediate();
      }
      for (let i = steps.length - 1; i >= 0; --i)
        validateLocalModelRegistryStep({ ...steps[i]!, ...(i + 1 < steps.length ? { predecessor: steps[i + 1]! } : {}) });
      return steps;
    };
    const pointers = (): readonly Pointer[] => {
      assertHeld(); return db.prepare('SELECT ownerPrincipalId, provider, model, currentHeadRef, currentHeadDigest, headRevision FROM model_registry ORDER BY ownerPrincipalId, provider, model').all().map(decodePointer);
    };
    const pointerFor = (model: string): Pointer | undefined => {
      assertHeld(); controlWireText(model, 512);
      const row = db.prepare('SELECT ownerPrincipalId, provider, model, currentHeadRef, currentHeadDigest, headRevision FROM model_registry WHERE ownerPrincipalId = ? AND provider = ? AND model = ?')
        .get(origin.ownerPrincipalId, 'ollama', model);
      return row === undefined ? undefined : decodePointer(row);
    };
    const commit = (step: Step, previous?: RetainedLocalModel): void => {
      assertHeld(); validateLocalModelRegistryStep({ ...step, ...(previous ? { predecessor: previous } : {}) });
      const reference = publish(scope, step.head); db.exec('BEGIN IMMEDIATE'); let transactionOpen = true;
      try {
        assertHeld(); const current = pointerFor(step.head.model);
        if (previous ? !current || current.currentHeadRef !== canonicalSha256(previous.head) || current.currentHeadDigest !== previous.head.headDigest ||
            current.headRevision !== previous.head.headRevision : current !== undefined)
          mismatch('original model registry head changed before its pointer CAS');
        if (!current) db.prepare('INSERT INTO model_registry VALUES (?, ?, ?, ?, ?, ?)').run(origin.ownerPrincipalId, 'ollama', step.head.model,
          reference, step.head.headDigest, step.head.headRevision);
        else {
          const result = db.prepare('UPDATE model_registry SET currentHeadRef = ?, currentHeadDigest = ?, headRevision = ? WHERE ownerPrincipalId = ? AND provider = ? AND model = ? AND currentHeadRef = ? AND currentHeadDigest = ? AND headRevision = ?')
            .run(reference, step.head.headDigest, step.head.headRevision, origin.ownerPrincipalId, 'ollama', step.head.model,
              current.currentHeadRef, current.currentHeadDigest, current.headRevision);
          if (result.changes !== 1) mismatch('original model registry pointer CAS did not update exactly one head');
        }
        assertHeld(); db.exec('COMMIT'); transactionOpen = false; assertHeld();
      } catch (error) {
        try { if (transactionOpen) db.exec('ROLLBACK'); }
        catch (rollback) { throw new ResourceRetirementError('model registry pointer transaction did not join', new AggregateError([error, rollback])); }
        throw error;
      }
    };
    const jobs: Promise<unknown>[] = [];
    const track = <R>(pending: Promise<R>): Promise<R> => {
      jobs.push(pending); void pending.catch(() => undefined); return pending;
    };
    let mutationActive = false;
    const trackMutation = <R>(mutate: () => Promise<R>): Promise<R> => {
      assertHeld();
      if (mutationActive) throw new TypeError('the original model-store mutation is already in progress');
      mutationActive = true;
      return track(Promise.resolve().then(mutate).finally(() => { mutationActive = false; }));
    };
    const retainForRun = async (registration: LocalModelRegistrationV1, artifacts: ArtifactCatalog): Promise<readonly PublishedArtifact[]> => {
      const reference = canonicalSha256(registration);
      const frozen = readRegistration(reference, registration.registrationDigest);
      if (frozen.state !== 'active') mismatch('Run source requires its exact original active local model registration');
      requireEqual(frozen, registration, 'original local model registration selected for Run');
      if (typeof scope.openObjectSource !== 'function')
        throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'original bounded model object source is unavailable');
      const closure = frozen.objectClosure, service = frozen.serviceSpec;
      const structured: readonly (readonly [string, string])[] = [
        [reference, frozen.format], [frozen.expectedServiceSpecRef, service.format], [frozen.expectedObjectClosureRef, closure.format],
        [closure.stateRootIdentityRef, 'cliq-state-root-identity-v1'], [service.runtimeBundleRef, 'cliq-runtime-bundle-v1'],
        [service.sandboxProfileRef, 'cliq-sandbox-profile-v1'],
      ];
      const metadata = await artifacts.mapReads(structured, async ([ref, format]) => {
        signal?.throwIfAborted(); assertHeld();
        const bytes = scope.readSmallObject(ref), artifact = await artifacts.publishBytes(bytes, 'application/json', format);
        if (artifact.ref !== ref || artifact.byteLength !== bytes.length) mismatch('Run local model metadata differs from the original store');
        return artifact;
      });
      for (const object of closure.objects) {
        signal?.throwIfAborted(); assertHeld();
        const source = scope.openObjectSource(object.artifactRef, object.sizeBytes);
        let failed = false, failure: unknown;
        try {
          const chunks = async function* () {
            for (;;) {
              signal?.throwIfAborted();
              const bytes = source.readChunk();
              if (bytes === null) return;
              if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > 65536) mismatch('native model source exceeded its fixed chunk bound');
              yield bytes;
            }
          };
          const kind = object.kind === 'model_manifest' ? frozen.modelManifest.format :
            object.kind === 'model_signature' ? 'cliq-ed25519-signature-v1' :
            object.kind === 'tokenizer' ? 'cliq-local-model-tokenizer-v1' : 'cliq-local-model-file-v1';
          const artifact = await artifacts.publishChunks(chunks(), object.kind === 'model_manifest' ? 'application/json' : 'application/octet-stream',
            kind, object.sizeBytes);
          if (artifact.ref !== object.artifactRef || artifact.byteLength !== object.sizeBytes) mismatch('Run CAS differs from the original model object bytes');
          metadata.push(artifact);
        } catch (error) { failed = true; failure = error; throw error; }
        finally {
          try { source.close(); }
          catch (error) {
            throw new ResourceRetirementError('original Run model object source did not retire', failed ? new AggregateError([failure, error]) : error);
          }
        }
      }
      assertHeld(); signal?.throwIfAborted(); return Object.freeze(metadata);
    };
    const implementation: LocalModelRegistry = {
      rootIdentity: origin.rootIdentity, ownerPrincipalId: origin.ownerPrincipalId,
      assertHeld() { if (this !== registry) throw new TypeError('invalid local registry receiver'); assertHeld(); },
      async select(model) {
        assertHeld(); const pointer = pointerFor(model); return pointer ? (await history(pointer))[0] : undefined;
      },
      async list() {
        const result: RetainedLocalModel[] = [];
        for (const pointer of pointers()) result.push((await history(pointer))[0]!);
        return immutableSnapshot(result);
      },
      async retainedRegistrations() {
        const result = new Map<string, LocalModelRegistrationV1>();
        for (const pointer of pointers()) for (const step of await history(pointer)) for (const registration of [step.active, step.retired])
          if (registration) result.set(canonicalSha256(registration), registration);
        return immutableSnapshot([...result.values()]);
      },
      readOriginalRegistration(reference, digest) { return readRegistration(reference, digest); },
      readObject(reference) { assertHeld(); return Buffer.from(scope.readSmallObject(controlWireRef(reference))); },
      retainForRun,
      withAdmissionCredentials(operation) {
        assertHeld();
        return withInstalledLocalAdmissionCredentialLock(installed, scope, operation, signal);
      },
      importPackage(manifestPath, importSignal) {
        assertHeld();
        if (!allowInitialize) return Promise.reject(new TypeError('existing model-store selection/revocation cannot import a model'));
        return importOriginalPackage(scope, installed, origin.rootIdentity, manifestPath,
          signal && importSignal ? AbortSignal.any([signal, importSignal]) : signal ?? importSignal);
      },
      async enroll(manifestValue, closureValue, committedAt) {
        assertHeld();
        if (!allowInitialize) throw new TypeError('existing model-store selection/revocation cannot enroll a model');
        const manifest = decodeLocalModelManifest(manifestValue), closure = decodeLocalModelObjectClosure(closureValue, manifest);
        const profile = installedLocalInferenceProfile();
        if (closure.stateRootIdentityRef !== canonicalSha256(origin.rootIdentity) || closure.stateRootIdentityDigest !== origin.rootIdentity.identityDigest)
          mismatch('model enrollment source differs from its original signed root');
        const entry = installed.bundle.entries.filter(value => value.entryId === 'ollama_local_inference' && value.role === 'local_inference' && value.executable);
        const executable = entry[0];
        if (entry.length !== 1 || !executable)
          mismatch('model enrollment requires its exact unique signed service executable');
        requireEqual(decodeObject(scope, canonicalSha256(manifest), decodeLocalModelManifest), manifest, 'original imported model manifest');
        requireEqual(decodeObject(scope, canonicalSha256(closure), value => decodeLocalModelObjectClosure(value, manifest)), closure, 'original imported model closure');
        verifyLocalModelManifestAuthority({ bundle: installed.bundle, releaseKeys: installed.releaseKeys,
          manifestBytes: canonicalJsonBytes(manifest), signatureBytes: scope.readSmallObject(manifest.signatureRef) });
        const previous = await registry.select(manifest.model);
        if (previous && previous.head.committedAt > committedAt) mismatch('model enrollment wall clock regressed');
        const requestedService = (port: number) => {
          const core = {
            schemaVersion: 1 as const, format: 'cliq-local-inference-service-v1' as const, ownerPrincipalId: origin.ownerPrincipalId,
            runtimeBundleRef: installed.bundleDigest, runtimeBundleManifestDigest: installed.bundle.manifestDigest,
            executableId: 'ollama_local_inference' as const, executableVersion: executable.version, executableDigest: executable.digest,
            modelManifestRef: canonicalSha256(manifest), modelManifestDigest: manifest.modelManifestDigest,
            endpoint: { scheme: 'http' as const, host: '127.0.0.1' as const, port },
            backend: profile.backend, sandboxProfileRef: canonicalSha256(profile), sandboxProfileDigest: profile.profileDigest,
            resources: profile.resources,
          };
          const serviceSpecCoreDigest = localServiceSpecCoreDigest(core);
          return decodeLocalInferenceServiceSpec(withDigest({ ...core, createdAt: committedAt, serviceSpecCoreDigest,
            serviceId: identityHash(origin.ownerPrincipalId, 'ollama', manifest.model, serviceSpecCoreDigest), serviceSpecDigest: '' }, 'serviceSpecDigest'));
        };
        if (previous?.active && requestedService(previous.active.serviceSpec.endpoint.port).serviceSpecCoreDigest === previous.active.serviceSpec.serviceSpecCoreDigest)
          return previous;
        const service = requestedService(nextLocalModelPort(await registry.retainedRegistrations()));
        const priorRegistration = previous?.active ?? previous?.retired;
        const activeRegistration = decodeLocalModelRegistration(withDigest({ schemaVersion: 1, format: 'cliq-local-model-registration-v1',
          ownerPrincipalId: origin.ownerPrincipalId, provider: 'ollama', model: manifest.model,
          registryRevision: (priorRegistration?.registryRevision ?? 0) + 1, serviceId: service.serviceId,
          serviceSpec: service, expectedServiceSpecRef: canonicalSha256(service), modelManifest: manifest,
          expectedModelManifestRef: canonicalSha256(manifest), objectClosure: closure, expectedObjectClosureRef: canonicalSha256(closure),
          createdAt: committedAt, state: 'active', registrationDigest: '' }, 'registrationDigest')) as Active;
        let retired: Retired | undefined;
        const originalActive = previous?.active;
        if (originalActive) {
          const { registrationDigest: _digest, ...old } = originalActive;
          const originalRetired = decodeLocalModelRegistration(withDigest({ ...old, state: 'retired', retiredAt: committedAt, registrationDigest: '' }, 'registrationDigest'));
          if (originalRetired.state !== 'retired') mismatch('model retirement decoder did not retain its exact requested state');
          assertLocalModelRetiredCopy(originalActive, originalRetired, committedAt); publish(scope, originalRetired);
          retired = originalRetired;
        }
        publish(scope, profile); publish(scope, service); publish(scope, activeRegistration);
        const predecessor = previous ? { predecessorHeadRef: canonicalSha256(previous.head), predecessorHeadDigest: previous.head.headDigest } : {};
        const head = decodeLocalModelRegistryHead(withDigest({ schemaVersion: 1, format: 'cliq-local-model-registry-head-v1',
          ownerPrincipalId: origin.ownerPrincipalId, provider: 'ollama', model: manifest.model, headRevision: (previous?.head.headRevision ?? 0) + 1,
          committedAt, state: 'active', transition: !previous ? 'initial' : previous.active ? 'replace' : 'reenroll', ...predecessor,
          activeRegistrationRef: canonicalSha256(activeRegistration), activeRegistrationDigest: activeRegistration.registrationDigest,
          ...(retired ? { retiredRegistrationRef: canonicalSha256(retired), retiredRegistrationDigest: retired.registrationDigest } : {}), headDigest: '' }, 'headDigest'));
        const step = immutableSnapshot({ head, active: activeRegistration, ...(retired ? { retired } : {}) });
        commit(step, previous); return step;
      },
      async retire(model, committedAt) {
        assertHeld(); const previous = await registry.select(model);
        if (!previous) throw new TypeError('local model is not enrolled');
        if (!previous.active) return previous;
        if (committedAt < previous.head.committedAt) mismatch('model retirement wall clock regressed');
        const { registrationDigest: _digest, ...base } = previous.active;
        const retired = decodeLocalModelRegistration(withDigest({ ...base, state: 'retired', retiredAt: committedAt, registrationDigest: '' }, 'registrationDigest')) as Retired;
        assertLocalModelRetiredCopy(previous.active, retired, committedAt); publish(scope, retired);
        const head = decodeLocalModelRegistryHead(withDigest({ schemaVersion: 1, format: 'cliq-local-model-registry-head-v1',
          ownerPrincipalId: origin.ownerPrincipalId, provider: 'ollama', model, headRevision: previous.head.headRevision + 1,
          committedAt, transition: 'retire', state: 'retired', predecessorHeadRef: canonicalSha256(previous.head),
          predecessorHeadDigest: previous.head.headDigest, retiredRegistrationRef: canonicalSha256(retired),
          retiredRegistrationDigest: retired.registrationDigest, headDigest: '' }, 'headDigest'));
        const step = immutableSnapshot({ head, retired }); commit(step, previous); return step;
      }
    };
    const registry: LocalModelRegistry = Object.freeze({ ...implementation,
      select(model: string) { return track(implementation.select.call(registry, model)); },
      list() { return track(implementation.list.call(registry)); },
      retainedRegistrations() { return track(implementation.retainedRegistrations.call(registry)); },
      retainForRun(registration: LocalModelRegistrationV1, artifacts: ArtifactCatalog) { return track(retainForRun(registration, artifacts)); },
      withAdmissionCredentials<T>(operation: (token: HeldCredentialAuthorityLock) => Promise<T>) {
        return track(implementation.withAdmissionCredentials(operation));
      },
      importPackage(manifestPath: string, importSignal?: AbortSignal) {
        return track(implementation.importPackage.call(registry, manifestPath, importSignal));
      },
      enroll(manifest: LocalModelManifestV1, closure: LocalModelObjectClosureV1, committedAt: string) {
        return trackMutation(() => implementation.enroll.call(registry, manifest, closure, committedAt));
      },
      retire(model: string, committedAt: string) { return trackMutation(() => implementation.retire.call(registry, model, committedAt)); }
    });
    let failed = false, failure: unknown;
    try {
      const work = Promise.resolve().then(() => operation(registry));
      await work.then(() => undefined, () => undefined);
      // A caller-unawaited import or graph read still belongs to this original
      // lock. Every tracked outer operation joins its own nested work before
      // this one pager and the native store can retire.
      return (await joinResourceOperations([work, ...jobs] as const))[0];
    }
    catch (error) { failed = true; failure = error; throw error; }
    finally {
      active = false;
      try { db.close(); }
      catch (error) { throw new ResourceRetirementError('original model registry pager did not join', failed ? new AggregateError([failure, error]) : error); }
    }
}
