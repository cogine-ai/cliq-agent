import { createHash } from 'node:crypto';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, sha256Bytes } from '../../kernel/identity.js';
import type { SandboxResourceSpec } from '../../kernel/execution.js';
import type { FrozenIgnoreRulesV1, SourceManifest, WorkspaceStateManifest, PrivateGitStateManifest,
  GitIndexSnapshotV1, GitObjectClosureV1, SanitizedGitConfigV1 } from '../../kernel/types.js';
import type { ArtifactCatalog } from '../../state/artifacts.js';
import { KernelStorageError } from '../../state/errors.js';
import { readGitIndexData, readPrivateGitData, type PrivateGitData, type PrivateGitReader } from '../private-git-data.js';
import { sanitizedGitConfigText } from '../source-git-config.js';
import { canonicalJsonBytes } from '../../kernel/canonical.js';

type RecordValue = Record<string, unknown>;
type GitConfig = { schemaVersion: 1; format: 'cliq-sanitized-git-config-v1'; core: {
  repositoryFormatVersion: 0 | 1; fileMode: boolean; bare: false; logAllRefUpdates?: boolean;
  ignoreCase?: boolean; precomposeUnicode?: boolean;
}; extensions?: { objectFormat: 'sha1' | 'sha256' }; configDigest: string };
type EmptyIndex = { schemaVersion: 1; format: 'cliq-git-index-snapshot-v1'; repositoryIdentityDigest: string;
  objectFormat: 'sha1' | 'sha256'; canonicalIndexVersion: 2; entries: [];
  canonicalIndexBytesRef: string; canonicalIndexBytesDigest: string; canonicalIndexByteCount: number;
  indexTreeObjectId: string; snapshotDigest: string };
type EmptyClosure = { schemaVersion: 1; format: 'cliq-git-object-closure-v1'; repositoryIdentityDigest: string;
  objectFormat: 'sha1' | 'sha256'; packs: []; reachableObjectIds: []; closureDigest: string };
type UnbornManifest = { schemaVersion: 1; format: 'cliq-private-git-v1'; head: { kind: 'unborn'; branch: string };
  indexRef: string; refs: []; objectClosureRef: string; objectClosureDigest: string;
  sanitizedConfigRef: string; sanitizedConfigDigest: string; manifestDigest: string };
export type PrivateGitFile = Readonly<{ sha256: string; byteCount: number }> &
  (Readonly<{ kind: 'inline'; bytes: Buffer }> | Readonly<{ kind: 'cas'; ref: string }>);
export type FrozenPrivateGit = Readonly<{ manifestRef: string; manifest: PrivateGitStateManifest; index: GitIndexSnapshotV1;
  closure: GitObjectClosureV1; config: SanitizedGitConfigV1; requiresPreparation: boolean; data?: PrivateGitData;
  directories: readonly string[]; files: ReadonlyMap<string, PrivateGitFile> }>;
const directories = ['.git', '.git/objects', '.git/objects/info', '.git/objects/pack', '.git/refs', '.git/refs/heads'];
function inline(bytes: Buffer): PrivateGitFile { return { kind: 'inline', bytes, sha256: sha256Bytes(bytes), byteCount: bytes.length }; }
function cas(ref: string, byteCount: number): PrivateGitFile { return { kind: 'cas', ref, sha256: ref, byteCount }; }
function ordinary(data: PrivateGitData): FrozenPrivateGit {
  if (!data.pack) return unsupported();
  const head = data.manifest.head;
  const headText = head.kind === 'detached' ? `${head.objectId}\n` : `ref: ${head.kind === 'unborn' ? `refs/heads/${head.branch}` : head.ref}\n`;
  const files = new Map<string, PrivateGitFile>([['.git/HEAD', inline(Buffer.from(headText))],
    ['.git/config', inline(Buffer.from(sanitizedGitConfigText(data.config)))],
    ['.git/index', cas(data.index.canonicalIndexBytesRef, data.index.canonicalIndexByteCount)],
    ['.git/packed-refs', inline(Buffer.from('# pack-refs with: sorted\n' + data.manifest.refs.map(ref => `${ref.objectId} ${ref.name}\n`).join('')))],
    [`.git/objects/pack/pack-${data.pack.packTrailerObjectHash}.pack`, cas(data.pack.packBytesRef, data.pack.packByteCount)],
    [`.git/objects/pack/pack-${data.pack.packTrailerObjectHash}.idx`, cas(data.pack.packIndexBytesRef, data.pack.packIndexByteCount)]]);
  return { ...data, requiresPreparation: true, data, directories, files };
}

function invalid(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }
function unsupported(): never {
  throw new KernelStorageError('INVALID_REQUEST', 'nonempty Git index/ref/object closure requires the retained trusted Git toolchain');
}
function record(value: unknown, keys: readonly string[], label: string): RecordValue {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !keys.includes(key))) {
    invalid(`${label} must have the exact frozen Git schema`);
  }
  return value as RecordValue;
}
function ref(value: unknown): string {
  if (typeof value !== 'string') invalid('frozen Git artifact ref must be a string');
  assertArtifactRef(value); return value;
}
function digest(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) invalid('frozen Git digest must be SHA-256');
  return value;
}
async function artifact(artifacts: PrivateGitReader, input: unknown, format: string, keys: readonly string[], digestKey: string,
  signal?: AbortSignal, maximum = 1_048_576): Promise<RecordValue> {
  signal?.throwIfAborted();
  const artifactRef = ref(input);
  const bytes = await artifacts.readBoundedBytes(artifactRef, maximum);
  const value = record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), keys, format);
  signal?.throwIfAborted();
  if (value.schemaVersion !== 1 || value.format !== format || !canonicalJsonBytes(value).equals(bytes) || canonicalSha256(value) !== artifactRef ||
      digestOmitting(value, digestKey) !== digest(value[digestKey])) invalid(`${format} frozen bytes/digest differ`);
  return value;
}
function emptyArray(value: unknown, label: string): void {
  if (!Array.isArray(value)) invalid(`${label} must be an array`);
  if (value.length) unsupported();
}
function branch(value: unknown): string {
  if (typeof value !== 'string' || !value || value !== value.normalize('NFC') || Buffer.byteLength(value) > 4096 ||
      value.startsWith('-') || value.includes('..') || value.includes('@{') || value === '@' ||
      /[\x00-\x20\x7f~^:?*\[\\]/.test(value) || value.endsWith('.') ||
      value.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) invalid('unborn Git branch is not a safe canonical ref');
  return value;
}
function configBytes(config: GitConfig): Buffer {
  const core = config.core;
  let text = `[core]\n\trepositoryformatversion = ${core.repositoryFormatVersion}\n\tfilemode = ${core.fileMode}\n\tbare = false\n`;
  for (const [key, field] of [['logallrefupdates', 'logAllRefUpdates'], ['ignorecase', 'ignoreCase'],
    ['precomposeunicode', 'precomposeUnicode']] as const) if (core[field] !== undefined) text += `\t${key} = ${core[field]}\n`;
  if (config.extensions) text += `[extensions]\n\tobjectformat = ${config.extensions.objectFormat}\n`;
  return Buffer.from(text);
}
function emptyTree(objectFormat: 'sha1' | 'sha256'): string {
  return createHash(objectFormat).update(Buffer.from('tree 0\0')).digest('hex');
}

/** Retained bytes are data only. A nonempty graph additionally requires a
 * fresh native preparation completion before any generation payload write. */
export async function loadFrozenPrivateGit(artifacts: PrivateGitReader, source: SourceManifest,
  state: WorkspaceStateManifest, rules: FrozenIgnoreRulesV1, signal?: AbortSignal, resources?: SandboxResourceSpec): Promise<FrozenPrivateGit | undefined> {
  signal?.throwIfAborted();
  if (source.git === undefined) {
    if (state.privateGitStateRef !== undefined || rules.repositoryIdentityDigest !== undefined || rules.sources.length || rules.rules.length) {
      invalid('non-Git workspace must not retain private Git or repository ignore metadata');
    }
    return undefined;
  }
  const sourceGit = record(source.git, ['repositoryIdentityDigest', 'head', 'indexRef', 'indexTreeObjectId'], 'SourceManifest.git');
  const repository = digest(sourceGit.repositoryIdentityDigest);
  if (rules.repositoryIdentityDigest !== repository || state.privateGitStateRef === undefined) invalid('Git workspace/source/ignore identity differs');
  const manifest = await artifact(artifacts, state.privateGitStateRef, 'cliq-private-git-v1', ['schemaVersion', 'format', 'head',
    'indexRef', 'refs', 'objectClosureRef', 'objectClosureDigest', 'sanitizedConfigRef', 'sanitizedConfigDigest', 'manifestDigest'], 'manifestDigest', signal,
  resources ? Math.min(resources.maxSingleFileBytes, resources.maxInvocationOutputBytes) : 1_048_576);
  const closureData = await artifact(artifacts, manifest.objectClosureRef, 'cliq-git-object-closure-v1', ['schemaVersion', 'format',
    'repositoryIdentityDigest', 'objectFormat', 'packs', 'reachableObjectIds', 'closureDigest'], 'closureDigest', signal,
  resources ? Math.min(resources.maxSingleFileBytes, resources.maxInvocationOutputBytes) : 1_048_576);
  if (!Array.isArray(closureData.packs)) invalid('frozen Git object closure is not an array');
  if (closureData.packs.length) {
    if (!resources) return unsupported();
    const expected = { repositoryIdentityDigest: repository, resources };
    const data = await readPrivateGitData(artifacts, state.privateGitStateRef, expected, signal);
    const admitted = await readGitIndexData(artifacts, ref(sourceGit.indexRef), expected, signal);
    if (sourceGit.indexTreeObjectId !== admitted.indexTreeObjectId || admitted.objectFormat !== data.index.objectFormat)
      invalid('private Git object format differs from its independently retained admitted index');
    return ordinary(data);
  }
  const head = record(manifest.head, ['kind', 'branch', 'ref', 'objectId'], 'PrivateGitStateManifest.head');
  const sourceHead = record(sourceGit.head, ['kind', 'branch', 'ref', 'objectId'], 'SourceManifest.git.head');
  if (head.kind !== 'unborn' || sourceHead.kind !== 'unborn') unsupported();
  const name = branch(head.branch);
  if (sourceHead.branch !== name || sourceHead.ref !== undefined || sourceHead.objectId !== undefined ||
      head.ref !== undefined || head.objectId !== undefined) invalid('private unborn HEAD differs from source');
  emptyArray(manifest.refs, 'PrivateGitStateManifest.refs');
  const index = await artifact(artifacts, manifest.indexRef, 'cliq-git-index-snapshot-v1', ['schemaVersion', 'format',
    'repositoryIdentityDigest', 'objectFormat', 'canonicalIndexVersion', 'entries', 'canonicalIndexBytesRef',
    'canonicalIndexBytesDigest', 'canonicalIndexByteCount', 'indexTreeObjectId', 'snapshotDigest'], 'snapshotDigest', signal);
  emptyArray(index.entries, 'GitIndexSnapshot.entries');
  if (index.objectFormat !== 'sha1' && index.objectFormat !== 'sha256') invalid('Git object format is unsupported');
  const objectFormat = index.objectFormat;
  const header = Buffer.from('444952430000000200000000', 'hex');
  const indexBytes = Buffer.concat([header, createHash(objectFormat).update(header).digest()]);
  const indexBytesRef = ref(index.canonicalIndexBytesRef);
  if (index.repositoryIdentityDigest !== repository || index.canonicalIndexVersion !== 2 ||
      index.canonicalIndexByteCount !== indexBytes.length || indexBytesRef !== digest(index.canonicalIndexBytesDigest) ||
      index.indexTreeObjectId !== emptyTree(objectFormat) || sourceGit.indexTreeObjectId !== index.indexTreeObjectId ||
      sourceGit.indexRef !== manifest.indexRef) invalid('empty canonical Git index/source identity differs');
  const captured: Buffer[] = [];
  for await (const chunk of artifacts.readChunks(indexBytesRef, indexBytes.length)) {
    signal?.throwIfAborted(); captured.push(chunk);
  }
  signal?.throwIfAborted();
  if (!Buffer.concat(captured).equals(indexBytes)) invalid('empty canonical Git index bytes/checksum differ');
  const closure = await artifact(artifacts, manifest.objectClosureRef, 'cliq-git-object-closure-v1', ['schemaVersion', 'format',
    'repositoryIdentityDigest', 'objectFormat', 'packs', 'reachableObjectIds', 'closureDigest'], 'closureDigest', signal);
  emptyArray(closure.packs, 'GitObjectClosure.packs'); emptyArray(closure.reachableObjectIds, 'GitObjectClosure.reachableObjectIds');
  if (closure.repositoryIdentityDigest !== repository || closure.objectFormat !== objectFormat ||
      digest(manifest.objectClosureDigest) !== closure.closureDigest) invalid('empty Git object closure identity differs');
  const config = await artifact(artifacts, manifest.sanitizedConfigRef, 'cliq-sanitized-git-config-v1',
    ['schemaVersion', 'format', 'core', 'extensions', 'configDigest'], 'configDigest', signal);
  const core = record(config.core, ['repositoryFormatVersion', 'fileMode', 'bare', 'logAllRefUpdates', 'ignoreCase', 'precomposeUnicode'], 'SanitizedGitConfig.core');
  if ((core.repositoryFormatVersion !== 0 && core.repositoryFormatVersion !== 1) || typeof core.fileMode !== 'boolean' || core.bare !== false ||
      ['logAllRefUpdates', 'ignoreCase', 'precomposeUnicode'].some(key => core[key] !== undefined && typeof core[key] !== 'boolean')) invalid('sanitized Git config core is invalid');
  if (config.extensions !== undefined) {
    const extensions = record(config.extensions, ['objectFormat'], 'SanitizedGitConfig.extensions');
    if (extensions.objectFormat !== objectFormat) invalid('sanitized Git config object format differs');
  }
  if ((objectFormat === 'sha256' && (core.repositoryFormatVersion !== 1 || config.extensions === undefined)) ||
      digest(manifest.sanitizedConfigDigest) !== config.configDigest) invalid('sanitized Git config identity differs');
  const configValue = config as unknown as GitConfig;
  return { manifestRef: state.privateGitStateRef, manifest: manifest as unknown as UnbornManifest,
    index: index as unknown as EmptyIndex, closure: closure as unknown as EmptyClosure, config: configValue,
    requiresPreparation: false, directories,
    files: new Map([['.git/HEAD', inline(Buffer.from(`ref: refs/heads/${name}\n`))], ['.git/index', inline(indexBytes)],
      ['.git/config', inline(configBytes(configValue))]]) };
}

/** Actual all-and-only streamed file observations retain the original graph.
 * A mutable config, extra object, or changed index cannot become trusted CAS. */
export async function observedPrivateGit(_artifacts: ArtifactCatalog, frozen: FrozenPrivateGit,
  directories: Set<string>, files: Map<string, Readonly<{ sha256: string; byteCount: number }>>, signal?: AbortSignal): Promise<string> {
  signal?.throwIfAborted();
  if (directories.size !== frozen.directories.length || frozen.directories.some(path => !directories.has(path)) ||
      files.size !== frozen.files.size || [...frozen.files].some(([path, expected]) => {
        const actual = files.get(path); return !actual || actual.sha256 !== expected.sha256 || actual.byteCount !== expected.byteCount;
      })) {
    invalid('physical private Git index/HEAD/config/object closure differs');
  }
  return frozen.manifestRef;
}
