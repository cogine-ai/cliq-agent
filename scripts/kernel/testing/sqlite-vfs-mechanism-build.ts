// Closed test-only same-engine probe construction; never a production loader.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SUPERVISOR_SEA_NODE_VERSION } from './supervisor-sea-builder.js';

const headers = {
  'sqlite3.h': '919e7f2e8ed1d8f56ac17b412b8971c76aa5d1a879752cc6058f75e7d5910e1d',
  'sqlite3ext.h': 'ac9645e5c9ff0cf176efdd6e75cb5e98f46295d38e02db5c4d208826a39ab4be',
};

export async function buildSqliteVfsMechanismHelper(fixture: string, nodeRoot: string) {
  return buildFixedProbe(fixture, nodeRoot, 'sqlite-vfs-mechanism-probe.c', 'sqlite-vfs-mechanism');
}

/** Closed test-only candidate, not a production extension/FD/path loader. */
export async function buildCredentialVfsProbe(fixture: string, nodeRoot: string) {
  return buildFixedProbe(fixture, nodeRoot, 'credential-vfs-probe.c', 'credential-vfs-probe');
}

/** Fixed fault translation unit; the candidate itself has no fault controls. */
export async function buildCredentialVfsRetirementProbe(fixture: string, nodeRoot: string) {
  return buildFixedProbe(fixture, nodeRoot, 'credential-vfs-retirement-probe.c', 'credential-vfs-retirement-probe');
}

async function buildFixedProbe(fixture: string, nodeRoot: string, sourceLeaf: string, helperName: string) {
  const includes = path.join(fixture, 'sqlite-vfs-mechanism-headers');
  await mkdir(includes, { mode: 0o700 });
  for (const [name, digest] of Object.entries(headers)) {
    const response = await fetch(`https://raw.githubusercontent.com/nodejs/node/v${SUPERVISOR_SEA_NODE_VERSION}/deps/sqlite/${name}`,
      { signal: AbortSignal.timeout(60000) });
    assert(response.ok, `fixed SQLite header download failed: ${response.status}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    assert.equal(createHash('sha256').update(bytes).digest('hex'), digest, `fixed ${name} checksum mismatch`);
    await writeFile(path.join(includes, name), bytes, { flag: 'wx', mode: 0o600 });
  }
  const source = fileURLToPath(new URL(sourceLeaf, import.meta.url));
  const helper = path.join(fixture, `${helperName}.node`);
  const args = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fPIC', '-fvisibility=hidden',
    ...(process.platform === 'darwin' ? ['-dynamiclib', '-undefined', 'dynamic_lookup'] : ['-shared']),
    '-I', path.join(nodeRoot, 'include/node'), '-I', includes, source, '-o', helper];
  const compiled = spawnSync('cc', args, { cwd: fixture, encoding: 'utf8', timeout: 60000, maxBuffer: 262144 });
  assert.equal(compiled.error, undefined); assert.equal(compiled.status, 0, compiled.stderr);
  await chmod(helper, 0o555);
  const bytes = await readFile(helper);
  return { helper, claim: { leaf: path.basename(helper), byteCount: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex') },
  construction: { headers, sourceSha256: createHash('sha256').update(await readFile(source)).digest('hex'),
    compilerArguments: args, secondSqliteEngineLinked: false } };
}
