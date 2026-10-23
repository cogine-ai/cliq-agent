// Explicit Delivery qualification, never a production feature override.
import assert from 'node:assert/strict';
import { runInstalledNodeJourney } from './testing/installed-node-journey.js';

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
const [mode, filename, ...extra] = process.argv.slice(2);
assert(filename && extra.length === 0);
if (mode === '--delivery-stop-campaign') {
  await runInstalledNodeJourney(filename, 'delivery', { publicationRetirementDiagnostics: true, publicationRetirementStop: true });
} else if (mode === '--delivery-delay-campaign') {
  await runInstalledNodeJourney(filename, 'delivery', { publicationRetirementDiagnostics: true });
} else {
  assert.equal(mode, '--delivery-campaign');
  await runInstalledNodeJourney(filename, 'delivery');
}
