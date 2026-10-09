import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import path from 'node:path';
import { canonicalSha256 } from '../../src/kernel/canonical.js';
import type { ToolContractManifestV1 } from '../../src/kernel/types.js';
import { testFixture } from '../../src/model/testing/fixtures.js';
import { openLinuxWorkerLauncher } from '../../src/sandbox/linux-worker.js';
import { signedLinuxWorkerTestRuntime } from '../../src/sandbox/testing/worker-runtime.js';
import { fixtureSandboxProfile } from '../../src/state/testing/worker-launch.js';
import { builtinInputContracts } from '../../src/tools/builtin-inputs.js';

// Installation authentication only: no controller, worker, model request or
// containment qualification. This requires actual Linux images and ownership.
if (process.platform !== 'linux') throw new Error('Linux installation ownership regression requires Linux (not skipped)');
const [installationRoot, foreignInstallationRoot, cgroupParent] = process.argv.slice(2);
if (![installationRoot, foreignInstallationRoot, cgroupParent].every(value => value && path.isAbsolute(value))) {
  throw new Error('usage: check-linux-worker-installation.ts INSTALLATION FOREIGN_OWNED_INSTALLATION CGROUP_PARENT');
}
assert.notEqual(installationRoot, foreignInstallationRoot, 'the original installation must not be modified');
const effectiveUid = process.geteuid!();
assert.notEqual(effectiveUid, 0, 'the regression must run as the ordinary CI runner');

async function addon(root: string) {
  const file = await open(path.join(root, 'linux-worker.node'), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true });
    assert.ok(before.isFile() && before.nlink === 1n && before.size > 0n && before.size <= 16n * 1024n * 1024n);
    const bytes = await file.readFile(); // Prove readability; EACCES is not the negative test.
    const after = await file.stat({ bigint: true });
    assert.equal(after.dev, before.dev); assert.equal(after.ino, before.ino);
    assert.equal(after.uid, before.uid); assert.equal(after.mode, before.mode);
    assert.equal(after.size, before.size); assert.equal(after.mtimeNs, before.mtimeNs); assert.equal(after.ctimeNs, before.ctimeNs);
    return { uid: before.uid, mode: before.mode & 0o7777n, digest: createHash('sha256').update(bytes).digest('hex') };
  } finally { await file.close(); }
}

const original = await addon(installationRoot!);
const foreign = await addon(foreignInstallationRoot!);
assert.equal(original.uid, BigInt(effectiveUid));
assert.equal(original.mode, 0o500n);
assert.equal(foreign.uid, 65534n); assert.notEqual(foreign.uid, BigInt(effectiveUid));
assert.equal(foreign.mode, 0o555n);
assert.equal(foreign.digest, original.digest, 'only actual ownership/mode differs, not the signed native bytes');

const authority = testFixture(), builtin = builtinInputContracts.edit;
const schemaRef = canonicalSha256(builtin.inputSchema);
const tools: ToolContractManifestV1['entries'] = [{ name: 'edit', version: '1', description: 'Installation ownership regression',
  access: builtin.access, inputSchemaRef: schemaRef, inputSchemaDigest: schemaRef, replayClass: builtin.replayClass,
  execution: { kind: 'builtin', adapterId: 'edit', adapterVersion: '1', adapterCodeDigest: '' } }];
const runtimeAuthority = await signedLinuxWorkerTestRuntime({ installationRoot: installationRoot!,
  assembly: authority.assembly, tools, sandboxProfile: fixtureSandboxProfile() });
const signedAddon = runtimeAuthority.bundle.entries.find(entry => entry.entryId === 'linux_worker_native');
assert.equal(signedAddon?.digest, original.digest);

const launcher = await openLinuxWorkerLauncher({ installationRoot: installationRoot!, cgroupParent: cgroupParent!, runtimeAuthority });
await launcher.close();
await assert.rejects(async () => {
  const unexpected = await openLinuxWorkerLauncher({ installationRoot: foreignInstallationRoot!, cgroupParent: cgroupParent!, runtimeAuthority });
  await unexpected.close(); // A failing regression must still release its real held images.
},
  { code: 'ARTIFACT_MISMATCH' }, 'readable signed bytes owned by an external UID cannot be loaded');
console.log(JSON.stringify({ regression: 'actual-native-installation-ownership', runnerUid: effectiveUid,
  refusedAddonUid: Number(foreign.uid), addonDigest: original.digest, note: 'no process spawn or Linux containment qualification' }));
