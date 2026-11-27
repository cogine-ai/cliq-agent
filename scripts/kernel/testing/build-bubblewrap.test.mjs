import assert from 'node:assert/strict';
import { access, realpath } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { assertBubblewrapRecipeSyntax, assertBubblewrapSource, BUBBLEWRAP_SOURCE } from '../build-bubblewrap.mjs';

test('bubblewrap source cannot be replaced by an unpinned or partially read archive', () => {
  for (const value of [undefined, '', new Uint8Array(), Buffer.alloc(BUBBLEWRAP_SOURCE.byteCount),
    Buffer.alloc(BUBBLEWRAP_SOURCE.byteCount - 1), Buffer.alloc(BUBBLEWRAP_SOURCE.byteCount + 1)])
    assert.throws(() => assertBubblewrapSource(value), /complete archive hash/u);
  assert(Object.isFrozen(BUBBLEWRAP_SOURCE));
  assert.equal(BUBBLEWRAP_SOURCE.version, '0.12.0');
});

test('actual installed legacy bubblewrap fails the required size parser before namespace creation',
  { skip: process.platform !== 'linux' }, async t => {
    try { await access('/usr/bin/bwrap'); } catch { t.skip('no original system bubblewrap is installed'); return; }
    const binary = await realpath('/usr/bin/bwrap');
    const version = await promisify(execFile)(binary, ['--version'], { timeout: 5000, maxBuffer: 4096 });
    if (/^bubblewrap 0\.6\.1\s*$/u.test(version.stdout)) {
      await assert.rejects(assertBubblewrapRecipeSyntax(binary), error =>
        error.code === 1 && /Unknown option --size/u.test(error.stderr));
    } else {
      // This remains only an actual syntax observation, never evidence of
      // namespace, tmpfs limits, READY or installed Run qualification.
      const result = await assertBubblewrapRecipeSyntax(binary);
      assert.match(result.sha256, /^[a-f0-9]{64}$/u); assert(result.byteCount > 0);
    }
  });
