import path from 'node:path';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireText } from '../kernel/control-wire-data.js';
import { normalizeAbsolutePath } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeLocalIdentity } from '../kernel/local-inference.js';
import { immutableSnapshot } from '../model/immutable.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { checkCanonicalBytes } from './installed-artifacts.js';
import { withHeldInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import { installedLocalInferenceProfile } from './local-inference-profile.js';
import { bindLocalInferenceRuntime, localInferenceRuntimeRoots } from './local-inference-runtime.js';
import { withExistingLocalModelRegistry, withLocalModelRegistry, type RetainedLocalModel } from './local-model-registry.js';

export type InstalledLocalModelRequest =
  | Readonly<{ schemaVersion: 1; kind: 'list' }>
  | Readonly<{ schemaVersion: 1; kind: 'enroll'; manifestPath: string }>
  | Readonly<{ schemaVersion: 1; kind: 'retire'; model: string }>;
export type InstalledLocalModelSummary = Readonly<{
  provider: 'ollama'; model: string; serviceId: string; registryRevision: number; state: 'active' | 'retired';
}>;

export function decodeInstalledLocalModelRequest(value: unknown): InstalledLocalModelRequest {
  assertControlWireJson(value);
  const kind = (value as { kind?: unknown } | null)?.kind;
  if (kind !== 'list' && kind !== 'enroll' && kind !== 'retire') throw new TypeError('unknown installed model operation');
  const extra = kind === 'enroll' ? ['manifestPath'] : kind === 'retire' ? ['model'] : [];
  const request = controlWireRecord(value, ['schemaVersion', 'kind', ...extra]);
  if (request.schemaVersion !== 1) throw new TypeError('unsupported installed model request version');
  if (kind === 'enroll') {
    const manifestPath = controlWireText(request.manifestPath, 4095);
    if (normalizeAbsolutePath(manifestPath) !== manifestPath || path.posix.basename(manifestPath) !== 'model-manifest.json')
      throw new TypeError('model import requires a canonical absolute model-manifest.json path');
  }
  if (kind === 'retire') controlWireText(request.model, 512);
  return immutableSnapshot(request) as InstalledLocalModelRequest;
}

export function decodeInstalledLocalModelCommand(command: string | undefined): InstalledLocalModelRequest {
  try {
    if (typeof command !== 'string' || !command.length || command.length > 87382 || !/^[A-Za-z0-9_-]+$/u.test(command))
      throw new TypeError('invalid model metadata envelope');
    const bytes = Buffer.from(command, 'base64url');
    if (bytes.length > 65536 || bytes.toString('base64url') !== command) throw new TypeError('noncanonical model metadata envelope');
    const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!canonicalJsonBytes(value).equals(bytes)) throw new TypeError('noncanonical model command');
    return decodeInstalledLocalModelRequest(value);
  } catch (cause) {
    throw new KernelStorageError('INVALID_REQUEST', 'expected bounded canonical model operation metadata', { cause });
  }
}

export function decodeInstalledLocalModelSummaries(value: unknown): readonly InstalledLocalModelSummary[] {
  if (!Array.isArray(value) || value.length > 16384) throw new TypeError('invalid installed model summary collection');
  assertControlWireJson(value);
  const models = new Set<string>();
  return Object.freeze(value.map((item: unknown) => {
    const entry = controlWireRecord(item, ['provider', 'model', 'serviceId', 'registryRevision', 'state']);
    const model = controlWireText(entry.model, 512);
    if (entry.provider !== 'ollama' || (entry.state !== 'active' && entry.state !== 'retired') || models.has(model))
      throw new TypeError('invalid or duplicate installed model summary');
    models.add(model);
    return Object.freeze({ provider: 'ollama' as const, model, serviceId: decodeLocalIdentity(entry.serviceId),
      registryRevision: controlWireInteger(entry.registryRevision, 1), state: entry.state });
  }));
}

function summary(step: RetainedLocalModel): InstalledLocalModelSummary {
  const registration = step.active ?? step.retired;
  if (!registration) throw new KernelStorageError('RECOVERY_REQUIRED', 'original model head lacks its retained registration');
  return Object.freeze({ provider: 'ollama', model: registration.model, serviceId: registration.serviceId,
    registryRevision: registration.registryRevision, state: registration.state });
}

/** Fixed installed models role. Registration publishes a request for the
 * signed recipe. The persistent activation owner must still establish the
 * strong process boundary before Run admission or model dispatch. */
export function executeInstalledLocalModelOperation(selected: HeldInstalledRuntime, value: InstalledLocalModelRequest,
  signal?: AbortSignal): Promise<readonly InstalledLocalModelSummary[]> {
  const request = decodeInstalledLocalModelRequest(value);
  return withHeldInstalledRuntime(selected, async installed => {
    if (request.kind !== 'enroll') return withExistingLocalModelRegistry(installed, async registry => {
      if (request.kind === 'list') return registry ? Object.freeze((await registry.list()).map(summary)) : Object.freeze([]);
      if (!registry || !await registry.select(request.model)) throw new KernelStorageError('NOT_FOUND', 'local model is not registered');
      signal?.throwIfAborted();
      return Object.freeze([summary(await registry.retire(request.model, sampleCanonicalNow()))]);
    }, signal);

    const root = localInferenceRuntimeRoots(installed.bundle)[0];
    const profileBytes = root && installed.objects.get(root.artifactRef);
    if (!root || !profileBytes || process.platform !== 'linux' || process.arch !== 'x64')
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'the fixed signed local inference recipe is unavailable in this installation');
    const runtime = bindLocalInferenceRuntime(installed.bundle, root.artifactRef, checkCanonicalBytes(profileBytes));
    return withLocalModelRegistry(installed, async registry => {
      const { manifest, closure } = await registry.importPackage(request.manifestPath, signal);
      // Manifest/signature/tokenizer closure is already verified by the
      // original store. Only the manifest and tokenizer are mounted.
      const { maxSingleFileBytes, memoryBytes } = installedLocalInferenceProfile().resources;
      const mountedCode = [runtime.engineEntryId, runtime.helperEntryId, runtime.loaderEntryId, ...runtime.libraries.map(library => library.entryId)];
      const codeBytes = mountedCode.reduce((sum, entryId) => {
        const entry = installed.bundle.entries.find(candidate => candidate.entryId === entryId);
        if (!entry) throw new KernelStorageError('ARTIFACT_MISMATCH', 'signed local runtime mount is absent');
        return sum + entry.byteCount;
      }, 0);
      if (manifest.files.length + mountedCode.length + 2 > 32 || closure.objects.some(object => object.sizeBytes > maxSingleFileBytes) ||
          closure.totalBytes - 64 + codeBytes > memoryBytes)
        throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'the signed model exceeds the fixed installed service input limits');
      signal?.throwIfAborted();
      return Object.freeze([summary(await registry.enroll(manifest, closure, sampleCanonicalNow()))]);
    }, signal);
  }, signal);
}

async function delegate(selected: HeldInstalledRuntime, request: InstalledLocalModelRequest,
  signal?: AbortSignal): Promise<readonly InstalledLocalModelSummary[]> {
  const { runInstalledLocalModelRequest } = await import('./installed-local-model-client.js');
  return decodeInstalledLocalModelSummaries(await runInstalledLocalModelRequest(selected, decodeInstalledLocalModelRequest(request), signal));
}

function one(summaries: readonly InstalledLocalModelSummary[], state: InstalledLocalModelSummary['state'], model?: string): InstalledLocalModelSummary {
  const result = summaries[0];
  if (summaries.length !== 1 || !result || result.state !== state || model !== undefined && result.model !== model)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'installed model response does not match its original request');
  return result;
}

export async function enrollInstalledLocalModel(selected: HeldInstalledRuntime, manifestPath: string,
  signal?: AbortSignal): Promise<InstalledLocalModelSummary> {
  return one(await delegate(selected, { schemaVersion: 1, kind: 'enroll', manifestPath }, signal), 'active');
}

export function listInstalledLocalModels(selected: HeldInstalledRuntime,
  signal?: AbortSignal): Promise<readonly InstalledLocalModelSummary[]> {
  return delegate(selected, { schemaVersion: 1, kind: 'list' }, signal);
}

export async function retireInstalledLocalModel(selected: HeldInstalledRuntime, model: string,
  signal?: AbortSignal): Promise<InstalledLocalModelSummary> {
  return one(await delegate(selected, { schemaVersion: 1, kind: 'retire', model }, signal), 'retired', model);
}
