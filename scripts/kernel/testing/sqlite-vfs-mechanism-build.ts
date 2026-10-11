// Closed test-only same-engine probe construction; never a production loader.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SUPERVISOR_SEA_NODE_VERSION } from './supervisor-sea-builder.js';
import { SQLITE_EXTENSION_HEADER_PINS, SQLITE_EXTENSION_NODE_VERSION,
  verifiedSqliteExtensionIncludes } from '../sqlite-extension-headers.mjs';

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
  assert.equal(SUPERVISOR_SEA_NODE_VERSION, SQLITE_EXTENSION_NODE_VERSION, 'fixed SQLite headers must match the SEA qualification carrier');
  const includes = await verifiedSqliteExtensionIncludes();
  const source = fileURLToPath(new URL(sourceLeaf, import.meta.url));
  const helper = path.join(fixture, `${helperName}.node`);
  const args = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fPIC', '-fvisibility=hidden',
    ...(process.platform === 'darwin' ? ['-dynamiclib', '-undefined', 'dynamic_lookup'] : ['-shared']),
    '-I', includes, '-I', path.join(nodeRoot, 'include/node'), source, '-o', helper];
  const compiled = spawnSync('cc', args, { cwd: fixture, encoding: 'utf8', timeout: 60000, maxBuffer: 262144 });
  assert.equal(compiled.error, undefined); assert.equal(compiled.status, 0, compiled.stderr);
  await chmod(helper, 0o555);
  const bytes = await readFile(helper);
  return { helper, claim: { leaf: path.basename(helper), byteCount: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex') },
  construction: { headers: SQLITE_EXTENSION_HEADER_PINS, sourceSha256: createHash('sha256').update(await readFile(source)).digest('hex'),
    compilerArguments: args, secondSqliteEngineLinked: false } };
}
