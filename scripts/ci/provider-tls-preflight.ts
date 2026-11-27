// No credential or HTTP request: observe the runner's actual authenticated
// TLS peer before funding the installed journey. The native broker independently
// repeats all checks; this observation grants no connection or dispatch rights.
import { connect } from 'node:tls';
import { createHash, X509Certificate } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { providerSelection } from './provider-qualification.js';

const { definition } = providerSelection(new Date());
const socket = connect({ host: definition.target.hostAscii, port: definition.target.port,
  servername: definition.tls.serverNameAscii, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', rejectUnauthorized: true });
let authenticated = false, matched = false, peerSpkiSha256: string | null = null;
const deadline = setTimeout(() => socket.destroy(), 30_000);
socket.once('error', () => { /* Retain only fixed failure fields, never remote error text. */ });
socket.once('secureConnect', () => {
  try {
    authenticated = socket.authorized && socket.getProtocol() === 'TLSv1.3';
    if (authenticated) {
      const peer = new X509Certificate(socket.getPeerCertificate().raw);
      peerSpkiSha256 = createHash('sha256').update(peer.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
      matched = definition.tls.spkiSha256Pins.includes(peerSpkiSha256);
    }
  } catch { matched = false; } finally { socket.destroy(); }
});
await new Promise<void>(resolve => socket.once('close', () => { clearTimeout(deadline); resolve(); }));
const report = { diagnosticOnly: true, format: 'cliq-provider-public-tls-v1', authenticated,
  selectedPinMatched: matched, peerSpkiSha256, socketClosed: true, credentialUsed: false, modelRequests: 0 };
if (process.env.RUNNER_TEMP) await writeFile(path.join(process.env.RUNNER_TEMP, 'cliq-provider-tls.json'), JSON.stringify(report) + '\n', { flag: 'wx', mode: 0o600 });
console.log(JSON.stringify(report));
if (!authenticated || !matched) process.exitCode = 1;
