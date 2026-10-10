import { readFile } from 'node:fs/promises';
import { getAsset, isSea } from 'node:sea';
import type { ReleaseTrustKey, RuntimeBundleManifest } from '../../policy/runtime-authority.js';
import { openStateStore } from '../store.js';

declare const __QUALIFICATION_IMAGE_VARIANT__: string;

// Test-only self-image seam. The public test root is compiled into this SEA;
// no control client, environment variable or detached manifest can replace it.
// This does not implement installation, admission or model dispatch.
async function main() {
  if (!isSea() || process.argv.length !== 4) throw new Error('expected a SEA, StateRoot and detached test manifest');
  const releaseKeys = JSON.parse(Buffer.from(getAsset('explicit-test-root.json')).toString('utf8')) as ReleaseTrustKey[];
  const bundle = JSON.parse(await readFile(process.argv[3]!, 'utf8')) as RuntimeBundleManifest;
  let accepted = false;
  let code: string | undefined;
  try {
    const store = await openStateStore(process.argv[2]!, { bundle, releaseKeys });
    try { accepted = true; } finally { await store.close(); }
  } catch (error) {
    accepted = false;
    code = (error as { code?: string }).code;
  }
  console.log(JSON.stringify({ diagnosticOnly: true, variant: __QUALIFICATION_IMAGE_VARIANT__, accepted, code }));
}
void main().catch(error => { console.error(error); process.exitCode = 1; });
