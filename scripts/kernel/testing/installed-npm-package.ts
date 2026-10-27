// Build/publisher only. Preserve every file from the one hash-pinned official
// upstream archive in one signed data image; never invoke a host npm command.
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { encodeNpmDataImage, NPM_DATA_RECIPE, readNpmDataImage } from '../../../src/sandbox/npm-data-image.js';
import { build } from 'esbuild';
import path from 'node:path';
import { NPM_DEPENDENCY_RECIPE } from '../../../src/sandbox/dependency-recipe.js';

export async function buildInstalledNpmAdapterAsset(repository: string) {
  const result = await build({ entryPoints: [path.join(repository, 'src/sandbox/dependency-npm-program.ts')],
    bundle: true, write: false, format: 'esm', platform: 'node', target: 'node24.21', minify: true,
    legalComments: 'none', logLevel: 'silent' });
  if (result.outputFiles.length !== 1) fail();
  const bytes = Buffer.from(result.outputFiles[0]!.contents);
  if (bytes.length < 1 || bytes.length > 1_048_576) fail();
  return { entryId: NPM_DEPENDENCY_RECIPE.adapterId, role: 'tool_adapter' as const, version: NPM_DEPENDENCY_RECIPE.adapterVersion,
    relativePath: NPM_DEPENDENCY_RECIPE.adapterPath, executable: false as const, digest: sha256Bytes(bytes), byteCount: bytes.length, bytes };
}

function fail(): never { throw new TypeError('official npm archive does not match its complete pinned source'); }
function octal(bytes: Buffer): number {
  const text = bytes.toString('ascii');
  if (!/^[0-7]+[\0 ]*$/u.test(text)) fail();
  const value = Number.parseInt(text.replace(/[\0 ]+$/u, ''), 8);
  if (!Number.isSafeInteger(value) || value < 0) fail();
  return value;
}
function string(bytes: Buffer): string {
  const end = bytes.indexOf(0), raw = end < 0 ? bytes : bytes.subarray(0, end);
  if (end >= 0 && bytes.subarray(end).some(byte => byte !== 0)) fail();
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
  if (!Buffer.from(text).equals(raw)) fail();
  return text;
}
export function buildInstalledNpmDataAsset(archive: Buffer) {
  if (!Buffer.isBuffer(archive) || archive.length !== NPM_DATA_RECIPE.archiveBytes ||
      sha256Bytes(archive) !== NPM_DATA_RECIPE.archiveSha256 ||
      createHash('sha512').update(archive).digest('hex') !== NPM_DATA_RECIPE.archiveSha512) fail();
  const tar = gunzipSync(archive, { maxOutputLength: NPM_DATA_RECIPE.imageBytes });
  const files: Array<{ path: string; sourceMode: 0o644 | 0o755; bytes: Buffer }> = [];
  let offset = 0, ended = false;
  while (offset < tar.length) {
    if (offset > tar.length - 512) fail();
    const header = tar.subarray(offset, offset + 512); offset += 512;
    if (header.every(byte => byte === 0)) { ended = true; break; }
    const checksum = octal(header.subarray(148, 156));
    let actual = 0;
    for (let index = 0; index < 512; index++) actual += index >= 148 && index < 156 ? 32 : header[index]!;
    if (checksum !== actual || header[156] !== 0 && header[156] !== 48 || string(header.subarray(157, 257)) ||
        string(header.subarray(257, 263)) !== 'ustar' || string(header.subarray(345, 500))) fail();
    const path = string(header.subarray(0, 100)), size = octal(header.subarray(124, 136)), mode = octal(header.subarray(100, 108));
    if (!path.startsWith('package/') || !path.slice(8) || size > NPM_DATA_RECIPE.fileBytes || mode !== 0o644 && mode !== 0o755 ||
        offset > tar.length - size || files.length >= NPM_DATA_RECIPE.files) fail();
    files.push({ path: path.slice(8), sourceMode: mode as 0o644 | 0o755, bytes: tar.subarray(offset, offset + size) });
    const next = offset + Math.ceil(size / 512) * 512;
    if (next > tar.length || tar.subarray(offset + size, next).some(byte => byte !== 0)) fail();
    offset = next;
  }
  if (!ended || tar.length - offset < 512 || tar.subarray(offset).some(byte => byte !== 0) || files.length !== 2408 ||
      files.reduce((sum, file) => sum + file.bytes.length, 0) !== 11_745_533) fail();
  const bytes = encodeNpmDataImage(files), image = readNpmDataImage(bytes);
  if (image.imageDigest !== NPM_DATA_RECIPE.completeImageDigest || bytes.length !== NPM_DATA_RECIPE.completeImageBytes) fail();
  return { entryId: NPM_DATA_RECIPE.entryId, role: 'bundle_object' as const, version: NPM_DATA_RECIPE.version,
    relativePath: NPM_DATA_RECIPE.relativePath, executable: false as const, digest: image.imageDigest, byteCount: bytes.length, bytes,
    source: Object.freeze({ kind: 'official_npm_archive' as const, archiveDigest: NPM_DATA_RECIPE.archiveSha256,
      archiveBytes: archive.length, fileCount: image.files.length, expandedBytes: image.expandedBytes, pageRoundedBytes: image.pageRoundedBytes }) };
}
