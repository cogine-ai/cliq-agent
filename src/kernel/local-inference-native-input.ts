// The original native witness and its fixed input share one binary CAS object.
// Its data decoder cannot create a native source, controller or observation.
import { DEFAULT_SANDBOX_RESOURCES } from './control-submit.js';
import { controlWireText } from './control-wire-data.js';
import { canonicalSha256 } from './canonical.js';
import type { SandboxResourceSpec } from './execution.js';
import { parseCanonicalTime, sha256Bytes } from './identity.js';
import { decodeLocalIdentity, decodeLocalModelPath, LOCAL_INFERENCE_ACTIVATION_MS,
  type LocalInferenceActivationCycleV1, type LocalInferenceServiceLaunchV1, type LocalModelRegistrationV1 } from './local-inference.js';
import { immutableSnapshot } from '../model/immutable.js';

export const LOCAL_INFERENCE_NATIVE_INPUT_KIND = 'cliq-local-inference-native-input-v1';
const SERVICE_MAGIC = 0x434c5331;
const BIRTH_MAGIC = 0x434c4231;
const CONFIG_SIZE = 136688;
const ORIGIN_SIZE = 4144;
const PACKET_SIZE = 3496;
const FILE_OFFSET = 2800;
const FILE_SIZE = 4184;
const FILE_COUNT = 32;
const CONFIG_BINDING_OFFSET = 16;
const PACKET_BINDING_OFFSET = 88;
const BINDING_SIZE = 2488;
const RESOURCE_SIZE = 72;
const PACKET_OBSERVATION_OFFSET = PACKET_BINDING_OFFSET + BINDING_SIZE + RESOURCE_SIZE;

const idFields = ['ownerPrincipalId', 'serviceId', 'serviceLaunchId', 'activationCycleId', 'supervisorInstanceId'] as const;
const digestFields = [
  'localModelRegistrationRef', 'localModelRegistrationDigest', 'serviceSpecRef', 'serviceSpecDigest',
  'runtimeBundleRef', 'runtimeBundleManifestDigest', 'modelManifestRef', 'modelManifestDigest',
  'objectClosureRef', 'objectClosureDigest', 'sandboxProfileRef', 'sandboxProfileDigest',
  'containmentPlanRef', 'containmentPlanDigest', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'nativeNonce', 'activationNonce',
] as const;
const resourceFields = [
  'maxProcesses', 'memoryBytes', 'cpuQuotaMicrosPerSecond', 'maxOpenFiles', 'maxSingleFileBytes',
  'maxGenerationBytes', 'maxInvocationOutputBytes', 'maxIpcFrameBytes', 'maxQueuedIpcBytes',
] as const satisfies readonly (keyof SandboxResourceSpec)[];
const fileKinds = ['model_manifest', 'model_tokenizer', 'model_file', 'engine', 'library', 'helper', 'loader'] as const;

export type LocalInferenceNativeBinding = Readonly<Record<typeof idFields[number] | typeof digestFields[number], string> & {
  stateOwnerEpoch: number; createdAtMs: number; activationDeadlineAtMs: number; activationAttempt: 1 | 2; port: number;
}>;
type NativeFileKind = typeof fileKinds[number];
export type LocalInferenceNativeFile = Readonly<{ kind: NativeFileKind; artifactRef: string; byteCount: number; guestPath: string }>;
export type LocalInferenceNativeImage = Readonly<{ digest: string; byteCount: number }>;
export type LocalInferenceNativeInputData = Readonly<{
  binding: LocalInferenceNativeBinding; resources: SandboxResourceSpec; bootstrap: LocalInferenceNativeImage;
  controller: LocalInferenceNativeImage; bubblewrap: LocalInferenceNativeImage; files: readonly LocalInferenceNativeFile[];
}>;
type NativeObjectIdentity = Readonly<{ deviceId: string; fileId: string; uid: number; gid: number; mode: number }>;
type NativeProcessIdentity = Readonly<{ pid: number; processStartToken: string }>;
export type LocalInferenceNativeOrigin = Readonly<{
  controller: NativeProcessIdentity;
  controllerImage: Readonly<{ deviceId: string; fileId: string; uid: number }>;
  stateRoot: NativeObjectIdentity; runtime: NativeObjectIdentity; privateParent: NativeObjectIdentity; witness: NativeObjectIdentity;
  controllerAnchor: NativeObjectIdentity; controllerParent: NativeObjectIdentity; controllerLeaf: NativeObjectIdentity;
  controllerLeafName: string;
}>;
export type LocalInferenceNativeObservation = Readonly<{
  observedAtMs: number; cgroupDeviceId: string; cgroupFileId: string; pidNamespaceId: string;
  preparation?: NativeProcessIdentity; monitor?: NativeProcessIdentity; namespaceInit?: NativeProcessIdentity; bootstrap?: NativeProcessIdentity;
  preparedCount: number; populated: boolean; remainingDescendants: number; allReaped: boolean;
}>;
export type LocalInferenceNativeInputV1 = Readonly<{
  data: LocalInferenceNativeInputData; origin: LocalInferenceNativeOrigin; inputBytesDigest: string; originBytesDigest: string;
}>;

function invalid(): never { throw new TypeError('original local inference native source does not match its fixed binary layout'); }
function zero(bytes: Buffer, from: number, to: number): void {
  if (bytes.subarray(from, to).some(byte => byte !== 0)) invalid();
}
function text(bytes: Buffer, offset: number, length: number, optional = false): string {
  const field = bytes.subarray(offset, offset + length);
  const end = field.indexOf(0);
  if (end < 0 || end === 0 && !optional) invalid();
  zero(field, end, length);
  const result = new TextDecoder('utf-8', { fatal: true }).decode(field.subarray(0, end));
  return end === 0 ? result : controlWireText(result, length - 1);
}
function digest(bytes: Buffer, offset: number): string {
  const result = text(bytes, offset, 65);
  if (!/^[0-9a-f]{64}$/u.test(result)) invalid();
  return result;
}
function number(value: bigint, maximum = Number.MAX_SAFE_INTEGER): number {
  if (value < 0n || value > BigInt(maximum)) invalid();
  return Number(value);
}
function u64(bytes: Buffer, offset: number, maximum?: number): number {
  return number(bytes.readBigUInt64LE(offset), maximum);
}
function positive(value: number): number {
  if (value <= 0) invalid();
  return value;
}
function processIdentity(bytes: Buffer, pidOffset: number, tokenOffset: number): NativeProcessIdentity | undefined {
  const pid = number(bytes.readBigInt64LE(pidOffset), 0x7fffffff);
  const processStartToken = text(bytes, tokenOffset, 192, pid === 0);
  if (!pid && processStartToken === '') return undefined;
  if (!pid || !/^linux-proc-start-ticks:[1-9][0-9]{0,19}$/u.test(processStartToken) ||
      BigInt(processStartToken.slice('linux-proc-start-ticks:'.length)) > 18446744073709551615n) invalid();
  return { pid, processStartToken };
}
function fileIdentity(bytes: Buffer, offset: number): NativeObjectIdentity {
  const deviceId = bytes.readBigUInt64LE(offset).toString(), fileId = bytes.readBigUInt64LE(offset + 8).toString();
  if (fileId === '0') invalid();
  return { deviceId, fileId, uid: u64(bytes, offset + 16, 0xffffffff), gid: u64(bytes, offset + 24, 0xffffffff),
    mode: u64(bytes, offset + 32, 0xffff) };
}

export function decodeLocalInferenceNativeInputData(config: Buffer): LocalInferenceNativeInputData {
  if (!Buffer.isBuffer(config) || config.length !== CONFIG_SIZE || config.readUInt32LE(0) !== SERVICE_MAGIC ||
      config.readUInt32LE(4) !== 1) invalid();
  const count = config.readUInt32LE(8);
  if (count < 6 || count > FILE_COUNT) invalid();
  const offset = CONFIG_BINDING_OFFSET;
  const ids = Object.fromEntries(idFields.map((key, index) => [key, text(config, offset + index * 257, 257)])) as Record<typeof idFields[number], string>;
  for (const key of ['serviceId', 'serviceLaunchId', 'activationCycleId'] as const) decodeLocalIdentity(ids[key]);
  const refs = Object.fromEntries(digestFields.map((key, index) => [key, digest(config, offset + 1285 + index * 65)])) as Record<typeof digestFields[number], string>;
  zero(config, offset + 2455, offset + 2456);
  const stateOwnerEpoch = positive(u64(config, offset + 2456)), createdAtMs = positive(u64(config, offset + 2464));
  const activationDeadlineAtMs = u64(config, offset + 2472), activationAttempt = config.readUInt32LE(offset + 2480), port = config.readUInt32LE(offset + 2484);
  if (activationDeadlineAtMs !== createdAtMs + LOCAL_INFERENCE_ACTIVATION_MS ||
      (activationAttempt !== 1 && activationAttempt !== 2) || port < 49152 || port > 65535) invalid();
  const binding: LocalInferenceNativeBinding = { ...ids, ...refs, stateOwnerEpoch, createdAtMs, activationDeadlineAtMs, activationAttempt, port };
  const resourceOffset = offset + BINDING_SIZE;
  for (const [index, key] of resourceFields.entries())
    if (u64(config, resourceOffset + index * 8) !== DEFAULT_SANDBOX_RESOURCES[key]) invalid();
  const resources = DEFAULT_SANDBOX_RESOURCES;
  const images = resourceOffset + RESOURCE_SIZE;
  const image = (index: number): LocalInferenceNativeImage => ({
    digest: digest(config, images + index * 65), byteCount: positive(u64(config, 2776 + index * 8, resources.maxSingleFileBytes)),
  });
  zero(config, 2771, 2776);
  const files: LocalInferenceNativeFile[] = [];
  let total = 0;
  const fixedPaths: Partial<Record<NativeFileKind, string>> = {
    model_manifest: '/models/model-manifest.json', model_tokenizer: '/models/tokenizer',
    engine: '/runtime/bin/ollama', helper: '/runtime/lib/ollama/llama-server', loader: '/lib64/ld-linux-x86-64.so.2',
  };
  const seen = new Set<NativeFileKind>();
  for (let index = 0; index < count; index++) {
    const field = FILE_OFFSET + index * FILE_SIZE;
    const kind = fileKinds[config.readUInt32LE(field) - 1];
    const mode = config.readUInt32LE(field + 4);
    if (!kind || mode !== (kind === 'engine' || kind === 'helper' || kind === 'loader' ? 0o500 : 0o400)) invalid();
    const artifactRef = digest(config, field + 16), byteCount = positive(u64(config, field + 8, resources.maxSingleFileBytes));
    const guestPath = text(config, field + 81, 4096);
    if (!guestPath.startsWith('/')) invalid();
    decodeLocalModelPath(guestPath.slice(kind === 'model_file' && guestPath.startsWith('/models/files/') ? '/models/files/'.length : 1));
    const fixed = fixedPaths[kind];
    if (fixed && (guestPath !== fixed || seen.has(kind))) invalid();
    if (kind === 'model_manifest' && artifactRef !== binding.modelManifestRef ||
        kind === 'model_file' && !guestPath.startsWith('/models/files/') ||
        kind === 'library' && !['/runtime/lib/ollama/', '/lib/', '/lib64/', '/usr/lib/'].some(root => guestPath.startsWith(root)) ||
        files.some(file => file.guestPath === guestPath || file.guestPath.startsWith(guestPath + '/') || guestPath.startsWith(file.guestPath + '/')))
      invalid();
    zero(config, field + 4177, field + FILE_SIZE);
    seen.add(kind); total += byteCount;
    if (total > resources.memoryBytes) invalid();
    files.push({ kind, guestPath, artifactRef, byteCount });
  }
  if (Object.keys(fixedPaths).some(kind => !seen.has(kind as NativeFileKind)) || !seen.has('model_file') ||
      config.readUInt32LE(12) !== files.filter(file => file.kind === 'model_file').length + 2) invalid();
  zero(config, FILE_OFFSET + count * FILE_SIZE, CONFIG_SIZE);
  return immutableSnapshot({ binding, resources, bootstrap: image(0), controller: image(1), bubblewrap: image(2), files });
}

function assertPacket(config: Buffer, packet: Buffer, command: number): void {
  if (packet.length !== PACKET_SIZE || packet.readUInt32LE(0) !== SERVICE_MAGIC || packet.readUInt32LE(4) !== 1 ||
      packet.readUInt32LE(8) !== command || packet.readUInt32LE(12) !== 0 || digest(packet, 16) !== sha256Bytes(config) ||
      !packet.subarray(PACKET_BINDING_OFFSET, PACKET_OBSERVATION_OFFSET).equals(
        config.subarray(CONFIG_BINDING_OFFSET, CONFIG_BINDING_OFFSET + BINDING_SIZE + RESOURCE_SIZE))) invalid();
  zero(packet, 81, PACKET_BINDING_OFFSET);
}

export function decodeLocalInferenceNativeObservation(config: Buffer, packet: Buffer, command: number): LocalInferenceNativeObservation {
  if (!Buffer.isBuffer(config) || config.length !== CONFIG_SIZE || !Buffer.isBuffer(packet)) invalid();
  assertPacket(config, packet, command);
  const offset = PACKET_OBSERVATION_OFFSET;
  const observedAtMs = positive(u64(packet, offset));
  const cgroupDeviceId = packet.readBigUInt64LE(offset + 8).toString(), cgroupFileId = packet.readBigUInt64LE(offset + 16).toString();
  const pidNamespaceId = packet.readBigUInt64LE(offset + 24).toString();
  const preparation = processIdentity(packet, offset + 32, offset + 64), monitor = processIdentity(packet, offset + 40, offset + 256);
  const namespaceInit = processIdentity(packet, offset + 48, offset + 448), bootstrap = processIdentity(packet, offset + 56, offset + 640);
  const preparedCount = packet.readUInt32LE(offset + 832), populated = packet.readUInt32LE(offset + 836);
  const remainingDescendants = packet.readUInt32LE(offset + 840), allReaped = packet.readUInt32LE(offset + 844);
  if ((cgroupDeviceId === '0') !== (cgroupFileId === '0') || (pidNamespaceId !== '0') !== (!!namespaceInit && !!bootstrap) ||
      preparedCount > FILE_COUNT || populated > 1 || remainingDescendants > 4096 || allReaped > 1) invalid();
  return immutableSnapshot({ observedAtMs, cgroupDeviceId, cgroupFileId, pidNamespaceId, preparedCount, populated: populated === 1,
    remainingDescendants, allReaped: allReaped === 1, ...(preparation ? { preparation } : {}), ...(monitor ? { monitor } : {}),
    ...(namespaceInit ? { namespaceInit } : {}), ...(bootstrap ? { bootstrap } : {}) });
}

export function splitLocalInferenceNativeInput(bytes: Buffer): Readonly<{ config: Buffer; origin: Buffer }> {
  if (!Buffer.isBuffer(bytes) || bytes.length !== CONFIG_SIZE + ORIGIN_SIZE) invalid();
  return { config: bytes.subarray(0, CONFIG_SIZE), origin: bytes.subarray(CONFIG_SIZE) };
}

export function decodeLocalInferenceNativeInput(bytes: Buffer): LocalInferenceNativeInputV1 {
  const { config, origin } = splitLocalInferenceNativeInput(bytes);
  const data = decodeLocalInferenceNativeInputData(config);
  if (origin.readUInt32LE(0) !== BIRTH_MAGIC || origin.readUInt32LE(4) !== 1 || origin.readUInt32LE(8) !== 1 ||
      origin.readUInt32LE(12) !== 1 || origin.subarray(4112).toString('hex') !== sha256Bytes(origin.subarray(0, 4112))) invalid();
  const packet = origin.subarray(16, 16 + PACKET_SIZE);
  assertPacket(config, packet, 2);
  zero(packet, PACKET_OBSERVATION_OFFSET, PACKET_SIZE);
  zero(origin, 4080, 4112);
  const controller = processIdentity(origin, 3512, 3520), controllerLeafName = text(origin, 4016, 64);
  if (!controller || !/^controller-[0-9a-f]{32}$/u.test(controllerLeafName)) invalid();
  const stateRoot = fileIdentity(origin, 3736), runtime = fileIdentity(origin, 3776), privateParent = fileIdentity(origin, 3816),
    witness = fileIdentity(origin, 3856), controllerAnchor = fileIdentity(origin, 3896), controllerParent = fileIdentity(origin, 3936),
    controllerLeaf = fileIdentity(origin, 3976);
  if ([stateRoot, runtime, privateParent].some(identity => identity.mode !== 0o40700 || identity.uid !== stateRoot.uid) ||
      witness.mode !== 0o100600 || witness.uid !== stateRoot.uid) invalid();
  const imageFileId = origin.readBigUInt64LE(3720).toString();
  if (imageFileId === '0') invalid();
  return immutableSnapshot({ data, inputBytesDigest: sha256Bytes(config), originBytesDigest: sha256Bytes(origin), origin: {
    controller, controllerImage: { deviceId: origin.readBigUInt64LE(3712).toString(), fileId: imageFileId, uid: u64(origin, 3728, 0xffffffff) },
    stateRoot, runtime, privateParent, witness, controllerAnchor, controllerParent, controllerLeaf, controllerLeafName,
  } });
}

/** Source validation is relative to the owning retained launch and cycle.
 * Runtime code and every original model object are revalidated by their
 * parent closures before a current native owner may consume this source. */
export function decodeBoundLocalInferenceNativeInput(bytes: Buffer, launch: LocalInferenceServiceLaunchV1,
  cycle: LocalInferenceActivationCycleV1, registration: LocalModelRegistrationV1): LocalInferenceNativeInputV1 {
  const source = decodeLocalInferenceNativeInput(bytes), binding = source.data.binding, service = registration.serviceSpec;
  if (sha256Bytes(bytes) !== launch.nativeInputRef || registration.state !== 'active' ||
      binding.ownerPrincipalId !== launch.ownerPrincipalId || binding.ownerPrincipalId !== registration.ownerPrincipalId ||
      binding.serviceId !== launch.serviceId || binding.serviceId !== registration.serviceId ||
      binding.serviceLaunchId !== launch.launchId || binding.activationCycleId !== launch.activationCycleId ||
      binding.activationCycleId !== cycle.activationCycleId || binding.supervisorInstanceId !== launch.supervisorInstanceId ||
      binding.activationAttempt !== launch.activationAttempt || cycle.launchIds[launch.activationAttempt - 1] !== launch.launchId ||
      binding.localModelRegistrationRef !== cycle.localModelRegistrationRef || binding.localModelRegistrationRef !== canonicalSha256(registration) ||
      binding.localModelRegistrationDigest !== cycle.localModelRegistrationDigest || binding.localModelRegistrationDigest !== registration.registrationDigest ||
      binding.serviceSpecRef !== launch.serviceSpecRef || binding.serviceSpecRef !== registration.expectedServiceSpecRef ||
      binding.serviceSpecDigest !== launch.serviceSpecDigest || binding.serviceSpecDigest !== service.serviceSpecDigest ||
      binding.runtimeBundleRef !== service.runtimeBundleRef || binding.runtimeBundleManifestDigest !== service.runtimeBundleManifestDigest ||
      binding.modelManifestRef !== registration.expectedModelManifestRef || binding.modelManifestDigest !== registration.modelManifest.modelManifestDigest ||
      binding.objectClosureRef !== registration.expectedObjectClosureRef || binding.objectClosureDigest !== registration.objectClosure.closureDigest ||
      binding.sandboxProfileRef !== service.sandboxProfileRef || binding.sandboxProfileDigest !== service.sandboxProfileDigest ||
      binding.containmentPlanRef !== launch.containmentPlanRef || binding.sandboxLaunchSpecRef !== launch.sandboxLaunchSpecRef ||
      binding.createdAtMs !== parseCanonicalTime(launch.createdAt) || binding.activationDeadlineAtMs !== parseCanonicalTime(launch.activationDeadlineAt) ||
      sha256Bytes(Buffer.from(binding.activationNonce, 'hex')) !== launch.activationNonceDigest ||
      binding.port !== service.endpoint.port || service.endpoint.host !== '127.0.0.1' || source.data.bootstrap.digest !== service.executableDigest)
    invalid();
  return source;
}
