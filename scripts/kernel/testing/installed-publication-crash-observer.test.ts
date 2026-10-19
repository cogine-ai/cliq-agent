// Pure closed-output tests only; these literals are not process/death evidence.
import assert from 'node:assert/strict';
import test from 'node:test';
import { decodePublicationCrashObserverOutput } from './installed-publication-crash-observer.js';

test('only a complete joined one-shot observer transcript reports the requested signal', () => {
  assert.deepEqual(decodePublicationCrashObserverOutput(Buffer.from('publication_parent_watch_ready\npublication_original_birth_armed\npublication_original_supervisor_killed\n'), 0, null),
    { watchReady: true, originalBirthArmed: true, uniqueSignalSent: true, processAndPipesJoined: true });
});

test('missing, duplicated, reordered, extra, non-ASCII or unjoined output cannot report a crash cut', () => {
  const ready = 'publication_parent_watch_ready\n', armed = 'publication_original_birth_armed\n', killed = 'publication_original_supervisor_killed\n';
  for (const output of ['', ready, ready + armed, ready + killed + armed, ready + armed + killed + killed,
    ready + armed + killed + 'arbitrary\n', ready + armed + killed + '\0', ready + armed + 'publication_original_supervisor_killéd\n'])
    assert.throws(() => decodePublicationCrashObserverOutput(Buffer.from(output), 0, null));
  assert.throws(() => decodePublicationCrashObserverOutput(Buffer.from(ready + armed + killed), 98, null));
  assert.throws(() => decodePublicationCrashObserverOutput(Buffer.from(ready + armed + killed), null, 'SIGKILL'));
});
