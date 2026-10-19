// Explicit Delivery qualification, never a production feature override.
import assert from 'node:assert/strict';
import { runInstalledNodeJourney } from './testing/installed-node-journey.js';

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
const [mode, filename, ...extra] = process.argv.slice(2);
assert.equal(mode, '--delivery-campaign'); assert(filename && extra.length === 0);
await runInstalledNodeJourney(filename, 'delivery');
