import { readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { testFixture } from '../../model/testing/fixtures.js';
import { openStateStore, type StateStore } from '../store.js';
import { loadNativeStateOwner } from '../native-owner.js';
import { signedToolBundle } from './tool-authority.js';

// This disposable child keeps executing its original Node image. Its old name
// is replaced before any signing/hash helper runs. The explicit fixture root
// signs the replacement bytes, not the actual running executable. This checks
// bootstrap refusal; it is not a complete signed-installation qualification.
let store: StateStore | undefined;
let substituted = false;
let observedBeforeSubstitution = false;
let reply: { accepted: boolean; substituted: boolean; observedBeforeSubstitution: boolean; code?: string };
try {
  // Real physical-producer preflight, not authority or a signed pathname. Do
  // not warm signedToolBundle's pathname digest cache before replacement.
  await (await loadNativeStateOwner()).observeCurrentProcess();
  observedBeforeSubstitution = true;
  const removed = process.argv[3] === 'removed-after-open';
  const replacement = removed ? await readFile(process.execPath) : Buffer.from('not the running executable image\n');
  if (removed) {
    store = await openStateStore(process.argv[4]!, await signedToolBundle(testFixture().assembly, []));
    await store.close();
    store = undefined;
  }
  await rename(process.execPath, `${process.execPath}.running`);
  if (removed) await unlink(`${process.execPath}.running`);
  await writeFile(process.execPath, replacement, { mode: 0o500 });
  substituted = true;
  const authority = await signedToolBundle(testFixture().assembly, []);
  store = await openStateStore(process.argv[2]!, authority);
  reply = { accepted: true, substituted, observedBeforeSubstitution };
} catch (error) {
  reply = { accepted: false, substituted, observedBeforeSubstitution, code: (error as { code?: string }).code };
} finally {
  await store?.close();
}
process.send!(reply, () => process.disconnect());
