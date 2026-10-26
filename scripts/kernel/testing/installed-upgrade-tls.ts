// Owned qualification TLS only. The caller owns and wipes privatePem after
// createServer consumes it. Neither TLS nor publisher private keys reach disk.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, X509Certificate } from 'node:crypto';
export function createUpgradeTlsMaterial(scan: (bytes: Uint8Array) => void) {
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privatePem = Buffer.from(keys.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  try {
    const made = spawnSync('/usr/bin/openssl', ['req', '-x509', '-new', '-key', '/dev/stdin', '-sha256', '-days', '1',
      '-subj', '/CN=installed-upgrade-fixture.invalid', '-addext', 'subjectAltName=DNS:installed-upgrade-fixture.invalid'],
    { input: privatePem, env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' },
      timeout: 5000, killSignal: 'SIGKILL', maxBuffer: 65536 });
    assert(Buffer.isBuffer(made.stdout) && Buffer.isBuffer(made.stderr)); scan(made.stdout); scan(made.stderr);
    assert.equal(made.error, undefined, 'owned TLS certificate process must join'); assert.equal(made.signal, null); assert.equal(made.status, 0);
    const certificatePem = made.stdout; new X509Certificate(certificatePem);
    return { privatePem, certificatePem };
  } catch (error) { privatePem.fill(0); throw error; }
}
