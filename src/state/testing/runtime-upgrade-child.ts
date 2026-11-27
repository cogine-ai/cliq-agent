// Test process only. The legacy Store is loaded from its exact separately
// frozen production source, not a current database with user_version reset.
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { upgradeRetiredRuntime } from '../runtime-upgrade.js';
import { ArtifactCatalog } from '../artifacts.js';
import { openStateStore } from '../store.js';
import type { StateStoreRuntimeAuthority } from '../store.js';
const [mode, root, authorityFile, legacyRoot] = process.argv.slice(2);
if (!root || !authorityFile) throw new TypeError('missing owned fixture');
const authority = JSON.parse(await readFile(authorityFile, 'utf8')) as StateStoreRuntimeAuthority;
try {
  if (mode === 'legacy' || mode === 'legacy-refuse') {
    if (!legacyRoot) throw new TypeError('missing frozen source');
    const original: typeof import('../store.js') = await import(pathToFileURL(path.join(legacyRoot, 'src/state/store.ts')).href);
    const store = await original.openStateStore(root, authority);
    try { process.send?.({ kind: 'opened', epoch: store.ownerEpoch }); }
    finally { await store.close(); }
  } else if (mode === 'upgrade-resource-fail') {
    // Inject only after the actual four index writes/full reads/closes join.
    // This is not a simulated native result or a production hook.
    const original = ArtifactCatalog.prototype.publishCanonicalFour;
    ArtifactCatalog.prototype.publishCanonicalFour = async function (values) {
      const result = await original.call(this, values);
      if (values.every(value => value.schemaKind === 'cliq-upgrade-resource-index-v1'))
        throw new Error('owned resource index post-durability failure');
      return result;
    };
    try { await upgradeRetiredRuntime({ stateRoot: root, target: authority }); throw new Error('owned publication failure was not reached'); }
    finally { ArtifactCatalog.prototype.publishCanonicalFour = original; }
  } else if (mode === 'upgrade') {
    const receipt = await upgradeRetiredRuntime({ stateRoot: root, target: authority });
    process.send?.({ kind: 'upgraded', receipt });
  } else if (mode === 'current') {
    const store = await openStateStore(root, authority);
    try { process.send?.({ kind: 'opened', epoch: store.ownerEpoch }); }
    finally { await store.close(); }
  } else throw new TypeError('unknown fixed fixture role');
} catch (error) {
  const record = error as { code?: string; message?: string };
  process.send?.({ kind: 'refused', code: record.code ?? 'unclassified', message: record.message ?? 'unclassified' });
  process.exitCode = 2;
}
