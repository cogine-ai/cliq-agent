import * as assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { mock, test } from 'node:test';

import { checkForPackageUpdate, isVersionGreater, readCurrentPackageVersion } from './updates.js';

test('isVersionGreater compares semantic versions numerically', () => {
  assert.equal(isVersionGreater('0.10.0', '0.9.9'), true);
  assert.equal(isVersionGreater('1.0.0', '0.99.99'), true);
  assert.equal(isVersionGreater('0.9.0', '0.9.0'), false);
  assert.equal(isVersionGreater('0.9.0', '0.10.0'), false);
  assert.equal(isVersionGreater('1.0.0', '1.0.0-rc.1'), true);
  assert.equal(isVersionGreater('1.0.0-rc.2', '1.0.0-rc.1'), true);
  assert.equal(isVersionGreater('1.0.0-rc.1', '1.0.0'), false);
});

test('checkForPackageUpdate returns latest when npm has a newer version', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (url: Parameters<typeof fetch>[0]) => {
    assert.equal(String(url), 'https://registry.npmjs.org/%40cogineai%2Fcliq/latest');
    return Response.json({ version: '0.10.0' });
  });

  try {
    assert.deepEqual(
      await checkForPackageUpdate({ packageName: '@cogineai/cliq', currentVersion: '0.9.0' }),
      { current: '0.9.0', latest: '0.10.0' }
    );
  } finally {
    fetchMock.mock.restore();
  }
});

test('checkForPackageUpdate returns null when latest is not newer or fetch fails', async () => {
  const sameVersionFetch = mock.method(globalThis, 'fetch', async () =>
    Response.json({ version: '0.9.0' })
  );
  try {
    assert.equal(
      await checkForPackageUpdate({ packageName: '@cogineai/cliq', currentVersion: '0.9.0' }),
      null
    );
  } finally {
    sameVersionFetch.mock.restore();
  }

  const failingFetch = mock.method(globalThis, 'fetch', async () => {
    throw new Error('offline');
  });
  try {
    assert.equal(
      await checkForPackageUpdate({ packageName: '@cogineai/cliq', currentVersion: '0.9.0' }),
      null
    );
  } finally {
    failingFetch.mock.restore();
  }
});

test('readCurrentPackageVersion reads the package version used by npm', async () => {
  const raw = await readFile(new URL('../package.json', import.meta.url), 'utf8');
  const parsed = JSON.parse(raw) as { version?: unknown };
  assert.equal(await readCurrentPackageVersion(), parsed.version);
});
