import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { createConnection } from 'node:net';
import path from 'node:path';
import { getAsset, isSea } from 'node:sea';

import { KERNEL_CAS_DIRECTORY } from '../../../src/config.js';
import { decodeSignedRuntimeBundle } from '../../../src/runtime-bundle/manifest.js';
import { loadNativeStateOwner, STATE_OWNER_NATIVE_PATH } from '../../../src/state/native-owner.js';
import { openStateStore } from '../../../src/state/store.js';

async function readControlLine(socket: ReturnType<typeof createConnection>): Promise<string> {
  let bytes = Buffer.alloc(0);
  for await (const chunk of socket) {
    bytes = Buffer.concat([bytes, chunk]);
    if (bytes.byteLength > 8192) throw new Error('UDS hello response exceeds the fixture bound');
    const newline = bytes.indexOf(10);
    if (newline >= 0) return bytes.subarray(0, newline).toString('utf8');
  }
  throw new Error('UDS hello connection ended before its response');
}

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
    await store.serveLocalControl();
    const socket = createConnection(path.join(stateRoot, 'runtime', 'control-v1.sock'));
    let helloBundleRef: string;
    try {
      await once(socket, 'connect');
      socket.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'control.hello', params: {
        protocolVersion: 1, clientBuild: 'sea-qualification',
        controlSchemaRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
        requestedFeatureIds: []
      } })}\n`);
      const response = JSON.parse(await readControlLine(socket)) as {
        result?: { runtimeBundleRef?: string };
      };
      helloBundleRef = response.result?.runtimeBundleRef ?? '';
      if (helloBundleRef !== bundleRef) throw new Error('UDS hello selected a different RuntimeBundle');
    } finally {
      socket.destroy();
    }
    process.stdout.write(`${JSON.stringify({
      mode,
      sea: isSea(),
      executableImageDigest: createHash('sha256').update(readFileSync(process.execPath)).digest('hex'),
      helperPath: STATE_OWNER_NATIVE_PATH,
      processStartToken: native.processStartToken(),
      execArgv: process.execArgv,
      bundleRef,
      helloBundleRef,
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
