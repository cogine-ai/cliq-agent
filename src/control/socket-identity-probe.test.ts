import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

test('real Unix sockets distinguish the filesystem endpoint from live descriptors', () => {
  const script = fileURLToPath(new URL('../../scripts/kernel/probe-control-socket-identity.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [script], {
    encoding: 'utf8', timeout: 45_000, maxBuffer: 1024 * 1024
  });
  assert.equal(result.status, 0, result.error?.message ?? result.stderr);
  const observation = JSON.parse(result.stdout);
  assert.equal(observation.platform, process.platform === 'darwin' ? 'macos' : 'linux');
  assert.equal(observation.endpoint.mode, 0o600);
  for (const identity of [observation.endpoint, observation.listenerDescriptor, observation.acceptedDescriptor]) {
    assert.equal(identity.isSocket, true);
    assert.match(identity.deviceId, /^(0|[1-9]\d*)$/u);
    assert.match(identity.fileId, /^(0|[1-9]\d*)$/u);
  }
  assert.equal(observation.endpoint.ownerUid, process.geteuid!());
  assert.equal(observation.peerSamplesMatchSelf, true);
  assert.equal(observation.namespaceAndListenerIdentityEqual, false);
  assert.equal(observation.replacementChangesEndpointIdentity, true);
  assert.equal(observation.replacementPreservesListenerIdentity, true);
  if (process.platform === 'darwin') {
    assert.equal(observation.listenerDescriptor.mode, 0o666);
    assert.equal(observation.socketFchmod.succeeded, false);
    assert.equal(observation.endpointDescriptorOpen.succeeded, false);
  }
});
