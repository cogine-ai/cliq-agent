import crypto from 'node:crypto';
import { writeFile } from 'node:fs/promises';

const [outputPath, launcherSha256, bubblewrapPath, bubblewrapSha256] = process.argv.slice(2);
const digestPattern = /^[0-9a-f]{64}$/;
if (
  outputPath === undefined ||
  !digestPattern.test(launcherSha256 ?? '') ||
  bubblewrapPath === undefined ||
  !bubblewrapPath.startsWith('/') ||
  !digestPattern.test(bubblewrapSha256 ?? '')
) {
  throw new Error(
    'usage: write-linux-execution-probe-manifest.mjs OUTPUT LAUNCHER_SHA256 BWRAP_PATH BWRAP_SHA256'
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
  backend: 'linux_namespace',
  launcher: {
    path: 'bin/cliq-linux-probe',
    sha256: launcherSha256,
    protocolVersion: 'cliq-linux-probe-v1'
  },
  bubblewrap: {
    path: bubblewrapPath,
    sha256: bubblewrapSha256
  }
};
const manifestDigest = crypto.createHash('sha256').update(canonical(core)).digest('hex');
await writeFile(outputPath, `${canonical({ ...core, manifestDigest })}\n`, {
  encoding: 'utf8',
  mode: 0o444
});
process.stdout.write(`${manifestDigest}\n`);
