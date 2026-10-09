import { createHash } from 'node:crypto';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { assertArtifactRef, digestOmitting } from '../../kernel/identity.js';
import type { FrozenIgnoreRulesV1, SourceManifest, WorkspaceStateManifest } from '../../kernel/types.js';
import type { ArtifactCatalog } from '../../state/artifacts.js';
import { KernelStorageError } from '../../state/errors.js';

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
export type FrozenPrivateGit = Readonly<{ manifestRef: string; manifest: UnbornManifest; index: EmptyIndex;
  closure: EmptyClosure; config: GitConfig; directories: readonly string[]; files: ReadonlyMap<string, Buffer> }>;

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
async function artifact(artifacts: ArtifactCatalog, input: unknown, format: string, keys: readonly string[], digestKey: string,
  signal?: AbortSignal): Promise<RecordValue> {
  signal?.throwIfAborted();
  const artifactRef = ref(input);
  const value = record(await artifacts.readCanonical(artifactRef), keys, format);
  signal?.throwIfAborted();
  if (value.schemaVersion !== 1 || value.format !== format || canonicalSha256(value) !== artifactRef ||
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

/** This reader handles only the genuinely empty reachable Git graph. A pack
 * is never accepted without the retained trusted index-pack verifier. */
export async function loadFrozenPrivateGit(artifacts: ArtifactCatalog, source: SourceManifest,
  state: WorkspaceStateManifest, rules: FrozenIgnoreRulesV1, signal?: AbortSignal): Promise<FrozenPrivateGit | undefined> {
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
    'indexRef', 'refs', 'objectClosureRef', 'objectClosureDigest', 'sanitizedConfigRef', 'sanitizedConfigDigest', 'manifestDigest'], 'manifestDigest', signal);
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
    directories: ['.git', '.git/objects', '.git/objects/info', '.git/objects/pack', '.git/refs', '.git/refs/heads'],
    files: new Map([['.git/HEAD', Buffer.from(`ref: refs/heads/${name}\n`)], ['.git/index', indexBytes], ['.git/config', configBytes(configValue)]]) };
}

/** Complete all-and-only physical metadata observation proves the empty
 * reachable graph; no mutable repository or ambient Git participates. */
export async function observedPrivateGit(artifacts: ArtifactCatalog, frozen: FrozenPrivateGit,
  directories: Set<string>, files: Map<string, Buffer>, signal?: AbortSignal): Promise<string> {
  signal?.throwIfAborted();
  if (directories.size !== frozen.directories.length || frozen.directories.some(path => !directories.has(path)) ||
      files.size !== frozen.files.size || [...frozen.files].some(([path, bytes]) => !files.get(path)?.equals(bytes))) {
    invalid('physical private Git index/HEAD/config/object closure differs');
  }
  const bytes = files.get('.git/index')!;
  const blob = await artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-git-index-bytes-v1');
  signal?.throwIfAborted();
  const index = { ...frozen.index, canonicalIndexBytesRef: blob.ref, canonicalIndexBytesDigest: blob.ref,
    canonicalIndexByteCount: bytes.length, indexTreeObjectId: emptyTree(frozen.index.objectFormat), snapshotDigest: '' };
  index.snapshotDigest = digestOmitting(index, 'snapshotDigest');
  const indexRef = (await artifacts.publishCanonical(index, index.format)).ref;
  signal?.throwIfAborted();
  const closure = { ...frozen.closure, packs: [], reachableObjectIds: [], closureDigest: '' };
  closure.closureDigest = digestOmitting(closure, 'closureDigest');
  const objectClosureRef = (await artifacts.publishCanonical(closure, closure.format)).ref;
  signal?.throwIfAborted();
  const config = { ...frozen.config, configDigest: '' };
  config.configDigest = digestOmitting(config, 'configDigest');
  const sanitizedConfigRef = (await artifacts.publishCanonical(config, config.format)).ref;
  signal?.throwIfAborted();
  const head = { kind: 'unborn' as const, branch: files.get('.git/HEAD')!.toString('utf8').slice('ref: refs/heads/'.length, -1) };
  const manifest = { ...frozen.manifest, head, indexRef, objectClosureRef, objectClosureDigest: closure.closureDigest,
    sanitizedConfigRef, sanitizedConfigDigest: config.configDigest, manifestDigest: '' };
  manifest.manifestDigest = digestOmitting(manifest, 'manifestDigest');
  const observedRef = (await artifacts.publishCanonical(manifest, manifest.format)).ref;
  signal?.throwIfAborted();
  if (observedRef !== frozen.manifestRef) invalid('observed private Git semantic digest differs');
  return observedRef;
}
