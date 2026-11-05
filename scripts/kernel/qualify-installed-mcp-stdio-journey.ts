// Fixed signed-static-stdio campaign. No paid provider or alternate authority.
import assert from 'node:assert/strict';
import { runInstalledNodeJourney } from './testing/installed-node-journey.js';

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
const [mode, filename, ...extra] = process.argv.slice(2);
assert.equal(mode, '--mcp-stdio-campaign'); assert(filename); assert.deepEqual(extra, []);
await runInstalledNodeJourney(filename, 'mcp-stdio');
