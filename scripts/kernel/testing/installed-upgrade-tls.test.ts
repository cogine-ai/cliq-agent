import assert from 'node:assert/strict';
import { createServer, get } from 'node:https';
import { test } from 'node:test';
import { createUpgradeTlsMaterial } from './installed-upgrade-tls.js';
import { createCredentialSecretScanner } from './credential-secret-scan.js';

test('the actual TLS child keeps its private key in stdin/memory and the certificate authenticates an owned TLS1.3 connection', async () => {
  const scanner = createCredentialSecretScanner([Buffer.from('owned-no-output-secret')], { maxStreams: 16, maxBytes: 65536 });
  const material = createUpgradeTlsMaterial(bytes => { const stream = scanner.openStream(); try { stream.scan(bytes); } finally { stream.close(); } });
  assert(material.privatePem.length >= 256 && material.privatePem.length <= 8192);
  assert.equal(material.certificatePem.includes(Buffer.from('PRIVATE KEY')), false);
  const server = createServer({ key: material.privatePem, cert: material.certificatePem, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' },
    (_request, response) => { response.writeHead(204, { Connection: 'close' }); response.end(); });
  material.privatePem.fill(0);
  try {
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address(); assert(address && typeof address === 'object');
    await new Promise<void>((resolve, reject) => {
      const request = get({ host: '127.0.0.1', port: address.port, servername: 'installed-upgrade-fixture.invalid',
        ca: material.certificatePem, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', agent: false }, response => {
        assert.equal(response.statusCode, 204); response.resume(); response.once('end', resolve); response.once('error', reject);
      }); request.once('error', reject);
    });
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); scanner.close(); }
  assert.equal(scanner.stats().streamsOpened, scanner.stats().streamsClosed); assert.equal(scanner.stats().matched, false);
});
