import crypto from 'node:crypto';
import { writeFile } from 'node:fs/promises';

const [outputPath, kernelSha256, initramfsSha256, workerSha256] = process.argv.slice(2);
const digestPattern = /^[0-9a-f]{64}$/;

if (
  outputPath === undefined ||
  !digestPattern.test(kernelSha256 ?? '') ||
  !digestPattern.test(initramfsSha256 ?? '') ||
  !digestPattern.test(workerSha256 ?? '')
) {
  throw new Error(
    'usage: write-execution-probe-manifest.mjs OUTPUT KERNEL_SHA256 INITRAMFS_SHA256 WORKER_SHA256'
  );
}

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number') {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(',')}}`;
  }
  throw new TypeError('manifest contains a non-canonical value');
}

const core = {
  schemaVersion: 1,
  format: 'cliq-execution-probe-manifest-v1',
  backend: 'macos_vm',
  guest: {
    kernelPath: 'Contents/Resources/Image',
    kernelSha256,
    initramfsPath: 'Contents/Resources/cliq-initramfs-virt',
    initramfsSha256,
    workerSha256,
    protocolVersion: 'cliq-guest-probe-v1'
  }
};
const manifestDigest = crypto.createHash('sha256').update(canonical(core)).digest('hex');
const manifest = { ...core, manifestDigest };
await writeFile(outputPath, `${canonical(manifest)}\n`, { encoding: 'utf8', mode: 0o444 });
process.stdout.write(`${manifestDigest}\n`);
