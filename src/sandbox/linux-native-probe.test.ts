import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const probeSourceUrl = new URL('../../native/linux/cliq-linux-probe.c', import.meta.url);

test('Linux probe copies the verified helper fd into the sandbox', async () => {
  const source = await readFile(probeSourceUrl, 'utf8');

  assert.doesNotMatch(source, /\/proc\/%ld\/exe/);
  assert.match(
    source,
    /"--perms",\s*"0555",\s*"--ro-bind-data",\s*helper_fd_text,\s*"\/cliq-probe"/
  );
});
