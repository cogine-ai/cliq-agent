import assert from 'node:assert/strict';
import test from 'node:test';
import { installedRequestFailureMarker, decodeInstalledRequestFailureMarker } from './installed-client-request-failure.js';

test('fixed child failure marker roundtrips only its complete closed canonical fields', () => {
  const value = { method: 'authorization.create', boundary: 'response_decode', kind: 'type_error', code: null } as const;
  const bytes = installedRequestFailureMarker(value);
  assert(bytes.length <= 512); assert.deepEqual(decodeInstalledRequestFailureMarker(bytes), value);
  for (const changed of [bytes.subarray(0, -1), Buffer.concat([bytes, bytes]),
    Buffer.from(bytes.toString().replace('"code":null', '"code":null,"body":"private"')),
    Buffer.from(bytes.toString().replace('response_decode', 'permission_granted')),
    Buffer.from(bytes.toString().replace('{', '{ ')), Buffer.alloc(513, 65)]) assert.throws(() => decodeInstalledRequestFailureMarker(changed));
});
