import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { createHash } from 'node:crypto';

// These are compiled original pure C data consumers. They do not manufacture
// a broker owner, claim, StateOwner, sandbox scope or installed qualification.
test('native public dependency input and framing consumers keep their complete bounded original bytes', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-dependency-data-'));
  try {
    const ref = 'a'.repeat(64);
    const tlsPolicyDigest = canonicalSha256({ serverNameAscii: 'registry.example', minimumVersion: 'TLSv1.3',
      trustStoreRuntimeBundleRef: ref, trustStoreRuntimeBundleManifestDigest: ref, trustStoreEntryId: 'default_https_trust_store',
      trustStoreRef: ref, trustStoreDigest: ref, spkiSha256Pins: [ref] });
    assert.notEqual(tlsPolicyDigest, ref, 'TLS policy and CA bytes are different original hash domains');
    const config = { schemaVersion: 1, transport: 'public_integrity_get_v1', descriptorSequenceDigest: ref,
      maxPackageBytes: 67_108_864, maxTransferBytes: 5 * 1_073_741_824, packageCount: 2, packageDescriptorBytes: 700,
      planDigest: ref, runRemainingMs: 60_000, sandboxLaunchSpecRef: ref, trustStoreDigest: ref,
      targets: [{ basePath: '/', endpointRegistrationRef: ref, hostAscii: 'registry.example', port: 443,
        serverNameAscii: 'registry.example', spkiSha256Pins: [ref], tlsPolicyDigest }] };
    const binding = { attempt: 0, brokerFenceTokenDigest: ref, dispatchId: 'dispatch-1', dispatchJournalSeq: 1,
      grantRef: ref, leaseEpoch: 3, opId: 'op-1', requestDigest: ref, requestRef: ref, runId: 'run-1', stateOwnerEpoch: 2,
      supervisorInstanceId: 'supervisor-1', targetDigest: ref, targetRef: ref };
    const configPath = path.join(root, 'config.json'), bindingPath = path.join(root, 'binding.json');
    await writeFile(configPath, canonicalJsonBytes(config), { flag: 'wx', mode: 0o600 });
    await writeFile(bindingPath, canonicalJsonBytes(binding), { flag: 'wx', mode: 0o600 });
    for (const family of ['descriptors', 'http', 'broker-input']) {
      const binary = path.join(root, family);
      const source = fileURLToPath(new URL(`../../../native/linux/dependency-${family}.test.c`, import.meta.url));
      const built = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', source, '-o', binary],
        { encoding: 'utf8', timeout: 30_000, maxBuffer: 65_536 });
      assert.equal(built.error, undefined); assert.equal(built.signal, null); assert.equal(built.status, 0, built.stderr);
      const run = spawnSync(binary, family === 'broker-input' ? [configPath, bindingPath] : [],
        { encoding: 'utf8', timeout: 5000, maxBuffer: 65_536 });
      assert.equal(run.error, undefined); assert.equal(run.signal, null); assert.equal(run.status, 0, run.stderr);
      assert.match(run.stdout, /^dependency_(?:descriptor|http|input)_checks=[1-9][0-9]*\n$/u);
      console.log(run.stdout.trim());
    }
    const descriptor = { packageName: '@owned/pkg', packageVersion: '1.0.0-beta.1+owned', endpointRegistrationRef: ref,
      canonicalPackagePath: '/@owned/pkg/-/pkg-1.0.0.tgz', integrityAlgorithm: 'sha256', integrityDigest: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' };
    const descriptorBytes = canonicalJsonBytes(descriptor), length = Buffer.alloc(4); length.writeUInt32LE(descriptorBytes.length);
    const sequence = createHash('sha256').update('cliq-dependency-package-descriptors-v1\0', 'ascii').update(length).update(descriptorBytes).digest('hex');
    const source = fileURLToPath(new URL('../../../native/linux/dependency-input-record.test.c', import.meta.url));
    const binary = path.join(root, 'input-record');
    const built = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', source, '-o', binary],
      { encoding: 'utf8', timeout: 30_000, maxBuffer: 65_536 });
    assert.equal(built.error, undefined); assert.equal(built.signal, null); assert.equal(built.status, 0, built.stderr);
    const run = spawnSync(binary, [canonicalJsonBytes({ schemaVersion: 1, firstIndex: 0, descriptors: [descriptor] }).toString(), sequence],
      { encoding: 'utf8', timeout: 5000, maxBuffer: 65_536 });
    assert.equal(run.error, undefined); assert.equal(run.signal, null); assert.equal(run.status, 0, run.stderr);
    assert.equal(run.stdout, canonicalJsonBytes({ ...descriptor, blobBytes: 123, blobSha256: 'b'.repeat(64) }).toString() + '\n');
    console.log('dependency_fd4_record_full_structure_sequence_and_bytes=passed');
  } finally { await rm(root, { recursive: true, force: true }); }
});
