import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { ArtifactCatalog } from '../state/artifacts.js';
import type { HeldPreparingGitInput } from '../state/native-owner.js';
import type { LinuxWorkerController } from './linux-worker.js';
import { openInstalledPreparingGit, readPreparingGitCompletion, type PreparingGitCompletion } from './preparation-git.js';

test('private Git preparation rejects a structural controller before observing any caller data or native input', async () => {
  let traps = 0;
  const inert = new Proxy({}, { get() { traps++; throw new Error('foreign getter was observed'); },
    ownKeys() { traps++; throw new Error('foreign keys were observed'); } });
  await assert.rejects(openInstalledPreparingGit(inert as LinuxWorkerController, inert as HeldPreparingGitInput,
    inert as ArtifactCatalog, inert as Parameters<typeof openInstalledPreparingGit>[3]), /original real native owner/u);
  assert.equal(traps, 0);
});

test('private Git completion cannot be reconstructed from matching data or a borrowed input description', () => {
  let traps = 0;
  const inert = new Proxy({}, { get() { traps++; throw new Error('foreign completion was observed'); },
    ownKeys() { traps++; throw new Error('foreign completion keys were observed'); } });
  for (const receipt of [{}, { completed: 1, lastBirthPhase: 10, origin: 'original_owner_joined' }, inert])
    assert.throws(() => readPreparingGitCompletion(receipt as PreparingGitCompletion, inert as HeldPreparingGitInput),
      /original joined native input/u);
  assert.equal(traps, 0);
  // These are brand-denial regressions only. Actual fixed Git execution,
  // whole-domain death and normal completion need the installed Linux path.
});
