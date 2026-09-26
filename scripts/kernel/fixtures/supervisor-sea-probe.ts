import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { getAsset, isSea } from 'node:sea';

import { KERNEL_CAS_DIRECTORY } from '../../../src/config.js';
import { decodeSignedRuntimeBundle } from '../../../src/runtime-bundle/manifest.js';
import { loadNativeStateOwner, STATE_OWNER_NATIVE_PATH } from '../../../src/state/native-owner.js';
import { openStateStore } from '../../../src/state/store.js';

async function main(): Promise<void> {
  const [mode, stateRoot] = process.argv.slice(-2);
  if (!isSea() || !['import', 'reopen'].includes(mode ?? '') || !stateRoot) {
    throw new Error('signed Supervisor SEA fixture requires import|reopen and a StateRoot');
  }
  const packageRoot = path.dirname(process.execPath);
  const releaseKeys = JSON.parse(getAsset('release-keys.json', 'utf8')) as Array<{
    keyId: string; publicKeyPem: string;
  }>;
  const { bundle, bundleRef } = decodeSignedRuntimeBundle(
    readFileSync(path.join(packageRoot, 'runtime-bundle.json')), releaseKeys
  );
  const native = await loadNativeStateOwner(bundle);
  const store = await openStateStore(stateRoot, { bundle, releaseKeys });
  try {
    if (mode === 'import') {
      const imported = await store.importRuntimeBundlePackage(packageRoot);
      if (imported !== bundleRef) throw new Error('signed package import returned a different bundle');
    }
    const policyRef = bundle.entries.find((entry) => entry.role === 'policy_engine')!.digest;
    const policyBytes = await store.artifacts.readBytes(policyRef);
    process.stdout.write(`${JSON.stringify({
      mode,
      sea: isSea(),
      executableImageDigest: createHash('sha256').update(readFileSync(process.execPath)).digest('hex'),
      helperPath: STATE_OWNER_NATIVE_PATH,
      processStartToken: native.processStartToken(),
      execArgv: process.execArgv,
      bundleRef,
      ownerEpoch: store.ownerEpoch,
      policyDigest: createHash('sha256').update(policyBytes).digest('hex'),
      casRoot: path.join(stateRoot, KERNEL_CAS_DIRECTORY)
    })}\n`);
  } finally {
    await store.close();
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
