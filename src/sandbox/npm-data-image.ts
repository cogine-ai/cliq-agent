// A single signed data asset, not an executable selector or authority token.
// The fixed dependency recipe alone may materialize it into its volatile root.
import { types } from 'node:util';
import { sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';

export const NPM_DATA_RECIPE = Object.freeze({ entryId: 'npm_package_data', version: '10.9.2',
  relativePath: 'runtime/npm-10.9.2.image', runtimePath: '/runtime/npm', cliPath: '/runtime/npm/bin/npm-cli.js',
  imageBytes: 33_554_432, expandedBytes: 33_554_432, fileBytes: 1_048_576, files: 4096,
  officialArchive: 'https://registry.npmjs.org/npm/-/npm-10.9.2.tgz', archiveBytes: 2_714_270,
  archiveSha256: '5cd1e5ab971ea6333f910bc2d50700167c5ef4e66da279b2a3efc874c6b116e4',
  completeImageDigest: '535b226efa5fa1c33d82e0634ac22a997c200db5799a787edd980f7de7a56f89', completeImageBytes: 11_950_276,
  archiveSha512: '8ab88f10f224a0c614cb717a7f7c30499014f77134120e9c1f0211ea3cf3397592cbe483feb38e0c4b3be1c54e347292c76a1b5edb94a3289d5448484ab8ac81' } as const);
const MAGIC = Buffer.from('cliq-npm-data-image-v1\0', 'ascii');
const HEADER_BYTES = MAGIC.length + 16;
const RECORD_BYTES = 40; // u16 path bytes, u16 original mode, u32 bytes, SHA-256.
export type NpmDataFile = Readonly<{ path: string; sourceMode: 0o644 | 0o755; byteCount: number; digest: string; payloadOffset: number }>;
export type NpmDataImage = Readonly<{ version: '10.9.2'; imageDigest: string; byteCount: number;
  expandedBytes: number; pageRoundedBytes: number; files: readonly NpmDataFile[] }>;
function fail(): never { throw new TypeError('fixed npm data image is incomplete or outside its bounds'); }
function pathBytes(value: string): Buffer {
  if (typeof value !== 'string' || !value || value.normalize('NFC') !== value || value.includes('\\') || value.includes('\0') ||
      value.split('/').some(part => !part || part === '.' || part === '..' || part === '.git' || /[\u0000-\u001f\u007f]/u.test(part) || Buffer.byteLength(part) > 255)) fail();
  const bytes = Buffer.from(value);
  if (bytes.length > 4096 || bytes.toString('utf8') !== value) fail();
  return bytes;
}
function npmIdentity(image: Buffer, files: readonly NpmDataFile[]): void {
  const root = files.find(file => file.path === 'package.json'), cli = files.find(file => file.path === 'bin/npm-cli.js');
  if (!root || !cli) fail();
  const bytes = image.subarray(root.payloadOffset, root.payloadOffset + root.byteCount);
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  if (!Buffer.from(text).equals(bytes)) fail();
  const value = parseJsonStrict(text) as Record<string, unknown>;
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.name !== 'npm' || value.version !== NPM_DATA_RECIPE.version) fail();
}
/** Synchronous full-byte projection only. A parsed image never mints a native borrow. */
export function readNpmDataImage(image: Buffer): NpmDataImage {
  if (!Buffer.isBuffer(image) || image.length < HEADER_BYTES || image.length > NPM_DATA_RECIPE.imageBytes ||
      !image.subarray(0, MAGIC.length).equals(MAGIC)) fail();
  const count = image.readUInt32LE(MAGIC.length), declared = image.readBigUInt64LE(MAGIC.length + 4), reserved = image.readUInt32LE(MAGIC.length + 12);
  if (count < 2 || count > NPM_DATA_RECIPE.files || declared > BigInt(NPM_DATA_RECIPE.expandedBytes) || reserved !== 0) fail();
  let offset = HEADER_BYTES, expanded = 0, pages = 0;
  const files: NpmDataFile[] = [], names = new Set<string>(), folded = new Set<string>(), directories = new Set<string>();
  const foldedDirectories = new Map<string, string>();
  let previous: Buffer | undefined;
  for (let index = 0; index < count; index++) {
    if (offset > image.length - RECORD_BYTES) fail();
    const length = image.readUInt16LE(offset), sourceMode = image.readUInt16LE(offset + 2), size = image.readUInt32LE(offset + 4);
    const digest = image.subarray(offset + 8, offset + 40).toString('hex');
    offset += RECORD_BYTES;
    if (!length || length > 4096 || size > NPM_DATA_RECIPE.fileBytes || sourceMode !== 0o644 && sourceMode !== 0o755 ||
        offset > image.length - length || offset + length > image.length - size) fail();
    const raw = image.subarray(offset, offset + length), path = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
    if (!pathBytes(path).equals(raw) || previous && Buffer.compare(previous, raw) >= 0 || folded.has(path.toLowerCase())) fail();
    const parts = path.split('/');
    for (let depth = 1; depth < parts.length; depth++) {
      const directory = parts.slice(0, depth).join('/');
      const foldedDirectory = directory.toLowerCase(), original = foldedDirectories.get(foldedDirectory);
      if (names.has(directory) || folded.has(foldedDirectory) || original !== undefined && original !== directory) fail();
      foldedDirectories.set(foldedDirectory, directory);
      directories.add(directory);
    }
    if (directories.has(path)) fail();
    offset += length;
    if (sha256Bytes(image.subarray(offset, offset + size)) !== digest) fail();
    files.push(Object.freeze({ path, sourceMode, byteCount: size, digest, payloadOffset: offset }));
    names.add(path); folded.add(path.toLowerCase()); previous = raw; offset += size;
    expanded += size; pages += Math.ceil(size / 4096) * 4096;
    if (expanded > NPM_DATA_RECIPE.expandedBytes || pages > NPM_DATA_RECIPE.expandedBytes) fail();
  }
  // Reserve one 4-KiB unit per actually needed directory, too. This is a
  // conservative representation bound; native tmpfs accounting remains real.
  pages += (directories.size + 1) * 4096;
  if (offset !== image.length || expanded !== Number(declared) || pages > NPM_DATA_RECIPE.expandedBytes ||
      files.length + directories.size > NPM_DATA_RECIPE.files) fail();
  npmIdentity(image, files);
  return Object.freeze({ version: NPM_DATA_RECIPE.version, imageDigest: sha256Bytes(image), byteCount: image.length,
    expandedBytes: expanded, pageRoundedBytes: pages, files: Object.freeze(files) });
}

/** Publisher data assembly, never called on workspace/package install input. */
export function encodeNpmDataImage(input: readonly Readonly<{ path: string; sourceMode: 0o644 | 0o755; bytes: Buffer }>[]): Buffer {
  if (types.isProxy(input) || !Array.isArray(input) || input.length < 2 || input.length > NPM_DATA_RECIPE.files) fail();
  const files = input.map(item => {
    if (!item || typeof item !== 'object' || types.isProxy(item)) fail();
    const data = Object.getOwnPropertyDescriptors(item);
    if (Reflect.ownKeys(data).length !== 3 || ['path', 'sourceMode', 'bytes'].some(key => !Object.hasOwn(data, key) || !('value' in data[key]!) || !data[key]!.enumerable)) fail();
    const path = pathBytes(data.path!.value), sourceMode = data.sourceMode!.value as number, bytes = data.bytes!.value as unknown;
    if (sourceMode !== 0o644 && sourceMode !== 0o755 || !Buffer.isBuffer(bytes) || bytes.length > NPM_DATA_RECIPE.fileBytes) fail();
    return { path, sourceMode, bytes: Buffer.from(bytes) };
  }).sort((left, right) => Buffer.compare(left.path, right.path));
  const total = files.reduce((sum, file) => sum + file.bytes.length, 0);
  const size = HEADER_BYTES + files.reduce((sum, file) => sum + RECORD_BYTES + file.path.length + file.bytes.length, 0);
  if (total > NPM_DATA_RECIPE.expandedBytes || size > NPM_DATA_RECIPE.imageBytes) fail();
  const image = Buffer.alloc(size); MAGIC.copy(image); image.writeUInt32LE(files.length, MAGIC.length); image.writeBigUInt64LE(BigInt(total), MAGIC.length + 4);
  let offset = HEADER_BYTES;
  for (const file of files) {
    image.writeUInt16LE(file.path.length, offset); image.writeUInt16LE(file.sourceMode, offset + 2); image.writeUInt32LE(file.bytes.length, offset + 4);
    Buffer.from(sha256Bytes(file.bytes), 'hex').copy(image, offset + 8); offset += RECORD_BYTES;
    file.path.copy(image, offset); offset += file.path.length; file.bytes.copy(image, offset); offset += file.bytes.length;
  }
  readNpmDataImage(image); return image;
}
