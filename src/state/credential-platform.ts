import { canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';

// These are private installed-producer models. Decoding a returned object is
// not authentication, a platform-store proof, or permission to write a phase.
// Only the held-FD installed loader supplies the actual native implementation.
export const CREDENTIAL_PLATFORM_ENTRY_ID = 'linux_credential_platform';
export const CREDENTIAL_PLATFORM_RELATIVE_PATH = 'native/linux-x64/linux-credential-platform.node';

export type CredentialPlatformUser = Readonly<{ uid: number; gid: number; home: string }>;
export type PlatformDirectoryIdentity = Readonly<{ deviceId: string; fileId: string }>;
export type PlatformBusObservation = Readonly<{
  guid: string; runtime: PlatformDirectoryIdentity; socket: PlatformDirectoryIdentity;
  uid: number; pid: number; processStartToken: string;
}>;
export type PlatformServiceObservation = Readonly<{ uniqueName: string; uid: number; pid: number; processStartToken: string }>;
export type SecretServiceSelector = Readonly<{
  itemId: string; ownerPrincipalId: string; stateRootIdentityDigest: string;
  creatingOperationId: string; credentialGrantId: string; secretGeneration: number; credentialTargetDigest: string;
}>;
export type SecretServiceObservation = Readonly<{
  schemaVersion: 1; kind: 'stored' | 'present' | 'absent' | 'deleted'; selector: SecretServiceSelector;
  bus: PlatformBusObservation; service: PlatformServiceObservation; collectionPath: string;
  itemPath?: string; observationDigest: string;
}>;
export type NativeSecretServiceInput =
  | Readonly<{ kind: 'create_compare'; selector: SecretServiceSelector; secret: Buffer }>
  | Readonly<{ kind: 'inspect'; selector: SecretServiceSelector; expectedObservation: SecretServiceObservation }>
  | Readonly<{ kind: 'delete_known'; selector: SecretServiceSelector }>;
export type NativeSystemdCommand = Readonly<{ path: string; argv: readonly string[]; flags: readonly string[] }>;
export type InstalledUnitObservation = Readonly<{
  Id: string; Names: readonly string[]; Following: string; LoadState: string; ActiveState: string; SubState: string;
  FragmentPath: string; SourcePath: string; DropInPaths: readonly string[]; NeedDaemonReload: boolean; Transient: boolean;
  Requires: readonly string[]; Requisite: readonly string[]; Wants: readonly string[]; BindsTo: readonly string[];
  PartOf: readonly string[]; Conflicts: readonly string[]; Before: readonly string[]; After: readonly string[];
  OnFailure: readonly string[]; OnSuccess: readonly string[];
  Type: string; ExecStart: readonly NativeSystemdCommand[]; ExecCondition: readonly NativeSystemdCommand[];
  ExecStartPre: readonly NativeSystemdCommand[]; ExecStartPost: readonly NativeSystemdCommand[];
  ExecReload: readonly NativeSystemdCommand[]; ExecStop: readonly NativeSystemdCommand[]; ExecStopPost: readonly NativeSystemdCommand[];
  Environment: readonly string[]; EnvironmentFiles: readonly Readonly<{ path: string; optional: boolean }>[];
  PassEnvironment: readonly string[]; UnsetEnvironment: readonly string[];
  User: string; Group: string; DynamicUser: boolean; PAMName: string; WorkingDirectory: string;
  RootDirectory: string; RootImage: string; UMask: number;
  Delegate: boolean; DelegateControllers: readonly string[]; KillMode: string; KillSignal: number; SendSIGKILL: boolean;
  Restart: string; RestartUSec: string; TimeoutStartUSec: string; TimeoutStopUSec: string;
  MainPID: number; ExecMainPID: number; ControlPID: number; InvocationID: string; ControlGroup: string;
  Result: string; NRestarts: number;
}>;
export type NativeUserManagerInput = Readonly<{ kind: 'reload' }> | Readonly<{ kind: 'start' | 'inspect'; unit: string }>;
export type UserManagerObservation = Readonly<{
  schemaVersion: 1; kind: 'reload' | 'start' | 'inspect'; uid: number; gid: number; home: string;
  bus: PlatformBusObservation; manager: PlatformServiceObservation; unit?: InstalledUnitObservation; jobPath?: string;
}>;
export type NativeCredentialPlatformBinding = Readonly<{
  interfaceVersion: 1;
  currentUser(): CredentialPlatformUser;
  secretService(input: NativeSecretServiceInput): Promise<unknown>;
  userManager(input: NativeUserManagerInput): Promise<unknown>;
}>;

function object(value: unknown, keys: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('invalid platform observation');
  const result = value as Record<string, unknown>;
  if (keys.some(key => !Object.hasOwn(result, key)) ||
      Reflect.ownKeys(result).some(key => typeof key !== 'string' || ![...keys, ...optional].includes(key)))
    throw new TypeError('invalid platform observation fields');
  return result;
}
function text(value: unknown, empty = false, maximum = 4096): string {
  if (typeof value !== 'string' || (!empty && !value) || value.includes('\0') || Buffer.byteLength(value) > maximum ||
      normalizeCanonicalText(value) !== value) throw new TypeError('invalid platform observation text');
  return value;
}
function integer(value: unknown, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > 0xffffffff)
    throw new TypeError('invalid platform observation integer');
  return value;
}
function generation(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1)
    throw new TypeError('invalid platform generation');
  return value;
}
function decimal(value: unknown): string {
  const result = text(value);
  if (!/^(0|[1-9][0-9]*)$/u.test(result) || BigInt(result) > 0xffffffffffffffffn)
    throw new TypeError('invalid platform observation identity');
  return result;
}
function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new TypeError('invalid platform observation boolean');
  return value;
}
function strings(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length > 256) throw new TypeError('invalid platform observation list');
  return Object.freeze(value.map(entry => text(entry)));
}
function start(value: unknown): string {
  const result = text(value);
  if (!/^linux-proc-start-ticks:[1-9][0-9]*$/u.test(result)) throw new TypeError('invalid platform process lifetime');
  decimal(result.slice('linux-proc-start-ticks:'.length));
  return result;
}
function objectPath(value: unknown): string {
  const result = text(value);
  if (!/^\/[A-Za-z0-9_]+(?:\/[A-Za-z0-9_]+)*$/u.test(result)) throw new TypeError('invalid platform object path');
  return result;
}
function directory(value: unknown): PlatformDirectoryIdentity {
  const result = object(value, ['deviceId', 'fileId']);
  return Object.freeze({ deviceId: decimal(result.deviceId), fileId: decimal(result.fileId) });
}
function bus(value: unknown): PlatformBusObservation {
  const result = object(value, ['guid', 'runtime', 'socket', 'uid', 'pid', 'processStartToken']);
  const guid = text(result.guid);
  if (!/^[0-9a-f]{32}$/u.test(guid)) throw new TypeError('invalid platform bus identity');
  return Object.freeze({ guid, runtime: directory(result.runtime), socket: directory(result.socket),
    uid: integer(result.uid, 1), pid: integer(result.pid, 1), processStartToken: start(result.processStartToken) });
}
function service(value: unknown): PlatformServiceObservation {
  const result = object(value, ['uniqueName', 'uid', 'pid', 'processStartToken']);
  const uniqueName = text(result.uniqueName);
  if (!/^:[0-9]+\.[0-9]+$/u.test(uniqueName)) throw new TypeError('invalid platform service identity');
  return Object.freeze({ uniqueName, uid: integer(result.uid, 1), pid: integer(result.pid, 1), processStartToken: start(result.processStartToken) });
}
export function decodeCredentialPlatformUser(value: unknown): CredentialPlatformUser {
  const result = object(value, ['uid', 'gid', 'home']);
  const home = text(result.home);
  if (!home.startsWith('/')) throw new TypeError('invalid platform home');
  return Object.freeze({ uid: integer(result.uid, 1), gid: integer(result.gid), home });
}
export function decodeSecretServiceSelector(value: unknown): SecretServiceSelector {
  const result = object(value, ['itemId', 'ownerPrincipalId', 'stateRootIdentityDigest', 'creatingOperationId',
    'credentialGrantId', 'secretGeneration', 'credentialTargetDigest']);
  for (const key of ['stateRootIdentityDigest', 'credentialTargetDigest'])
    if (!/^[0-9a-f]{64}$/u.test(text(result[key]))) throw new TypeError('invalid platform selector digest');
  return Object.freeze({ itemId: text(result.itemId, false, 65536), ownerPrincipalId: text(result.ownerPrincipalId, false, 65536),
    stateRootIdentityDigest: result.stateRootIdentityDigest as string, creatingOperationId: text(result.creatingOperationId, false, 65536),
    credentialGrantId: text(result.credentialGrantId, false, 65536), secretGeneration: generation(result.secretGeneration),
    credentialTargetDigest: result.credentialTargetDigest as string });
}
function secretObservation(value: unknown, retained: boolean): SecretServiceObservation {
  const result = object(value, ['schemaVersion', 'kind', 'selector', 'bus', 'service', 'collectionPath',
    ...(retained ? ['observationDigest'] : [])], ['itemPath']);
  if (result.schemaVersion !== 1 || !['stored', 'present', 'absent', 'deleted'].includes(result.kind as string))
    throw new TypeError('invalid platform observation kind');
  const collectionPath = objectPath(result.collectionPath);
  if (collectionPath === '/org/freedesktop/secrets/collection/session')
    throw new TypeError('invalid platform collection');
  const itemPath = Object.hasOwn(result, 'itemPath') ? objectPath(result.itemPath) : undefined;
  if ((result.kind === 'stored' || result.kind === 'present') !== (itemPath !== undefined) ||
      itemPath === collectionPath)
    throw new TypeError('invalid platform item locator');
  const body = { schemaVersion: 1 as const, kind: result.kind as SecretServiceObservation['kind'],
    selector: decodeSecretServiceSelector(result.selector), bus: bus(result.bus), service: service(result.service), collectionPath,
    ...(itemPath === undefined ? {} : { itemPath }) };
  if (body.bus.uid !== body.service.uid) throw new TypeError('platform service is not same-user');
  const observationDigest = canonicalSha256(body);
  if (retained && result.observationDigest !== observationDigest) throw new TypeError('platform observation digest differs');
  return Object.freeze({ ...body, observationDigest });
}
/** Shape/hash only. The installed producer must consume its actual native job. */
export function decodeSecretServiceObservation(value: unknown): SecretServiceObservation { return secretObservation(value, false); }
export function decodeRetainedSecretServiceObservation(value: unknown): SecretServiceObservation { return secretObservation(value, true); }

const unitTextFields = ['Id', 'Following', 'LoadState', 'ActiveState', 'SubState', 'FragmentPath', 'SourcePath', 'Type',
  'User', 'Group', 'PAMName', 'WorkingDirectory', 'RootDirectory', 'RootImage', 'KillMode', 'Restart', 'InvocationID', 'ControlGroup', 'Result'] as const;
const unitListFields = ['Names', 'DropInPaths', 'Requires', 'Requisite', 'Wants', 'BindsTo', 'PartOf', 'Conflicts', 'Before', 'After',
  'OnFailure', 'OnSuccess', 'Environment', 'PassEnvironment', 'UnsetEnvironment', 'DelegateControllers'] as const;
const unitBooleanFields = ['NeedDaemonReload', 'Transient', 'DynamicUser', 'Delegate', 'SendSIGKILL'] as const;
const unitIntegerFields = ['UMask', 'KillSignal', 'MainPID', 'ExecMainPID', 'ControlPID', 'NRestarts'] as const;
const unitDecimalFields = ['RestartUSec', 'TimeoutStartUSec', 'TimeoutStopUSec'] as const;
const unitCommandFields = ['ExecStart', 'ExecCondition', 'ExecStartPre', 'ExecStartPost', 'ExecReload', 'ExecStop', 'ExecStopPost'] as const;
function unit(value: unknown): InstalledUnitObservation {
  const result = object(value, [...unitTextFields, ...unitListFields, ...unitBooleanFields, ...unitIntegerFields,
    ...unitDecimalFields, ...unitCommandFields, 'EnvironmentFiles']);
  const decoded: Record<string, unknown> = {};
  for (const key of unitTextFields) decoded[key] = text(result[key], true);
  for (const key of unitListFields) decoded[key] = strings(result[key]);
  for (const key of unitBooleanFields) decoded[key] = boolean(result[key]);
  for (const key of unitIntegerFields) decoded[key] = integer(result[key]);
  for (const key of unitDecimalFields) decoded[key] = decimal(result[key]);
  for (const key of unitCommandFields) {
    const values = result[key];
    if (!Array.isArray(values) || values.length > 16) throw new TypeError('invalid platform command list');
    decoded[key] = Object.freeze(values.map(value => {
      const command = object(value, ['path', 'argv', 'flags']);
      return Object.freeze({ path: text(command.path), argv: strings(command.argv), flags: strings(command.flags) });
    }));
  }
  if (!Array.isArray(result.EnvironmentFiles) || result.EnvironmentFiles.length > 16) throw new TypeError('invalid platform environment files');
  decoded.EnvironmentFiles = Object.freeze(result.EnvironmentFiles.map(value => {
    const file = object(value, ['path', 'optional']);
    return Object.freeze({ path: text(file.path), optional: boolean(file.optional) });
  }));
  if (!/^(?:[0-9a-f]{32})?$/u.test(decoded.InvocationID as string)) throw new TypeError('invalid manager invocation');
  return Object.freeze(decoded) as InstalledUnitObservation;
}
export function decodeUserManagerObservation(value: unknown): UserManagerObservation {
  const result = object(value, ['schemaVersion', 'kind', 'uid', 'gid', 'home', 'bus', 'manager'], ['unit', 'jobPath']);
  if (result.schemaVersion !== 1 || !['reload', 'start', 'inspect'].includes(result.kind as string)) throw new TypeError('invalid manager operation');
  const user = decodeCredentialPlatformUser({ uid: result.uid, gid: result.gid, home: result.home });
  const observedBus = bus(result.bus), manager = service(result.manager);
  if (observedBus.uid !== user.uid || manager.uid !== user.uid) throw new TypeError('manager is not same-user');
  if (result.kind === 'reload' ? Object.hasOwn(result, 'unit') || Object.hasOwn(result, 'jobPath')
    : !Object.hasOwn(result, 'unit') || (result.kind === 'start') !== Object.hasOwn(result, 'jobPath'))
    throw new TypeError('invalid manager result fields');
  return Object.freeze({ schemaVersion: 1, kind: result.kind as UserManagerObservation['kind'], ...user,
    bus: observedBus, manager,
    ...(Object.hasOwn(result, 'unit') ? { unit: unit(result.unit) } : {}),
    ...(Object.hasOwn(result, 'jobPath') ? { jobPath: objectPath(result.jobPath) } : {}) });
}
