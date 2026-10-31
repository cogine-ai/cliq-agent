// One fixed real installed campaign; the shared owner retains all producers,
// services, NoEcho scans and complete finally/join. No paid provider option.
import assert from 'node:assert/strict';
import { runInstalledNodeJourney } from './testing/installed-node-journey.js';

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
const [mode, filename, ...extra] = process.argv.slice(2);
assert.equal(mode, '--permission-campaign'); assert(filename); assert.deepEqual(extra, []);
await runInstalledNodeJourney(filename, 'permission');
