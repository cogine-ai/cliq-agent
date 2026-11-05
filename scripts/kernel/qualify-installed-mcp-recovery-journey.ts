// Fixed signed recovery campaign. Ordinary installed entry/v1 UDS only.
import assert from 'node:assert/strict';
import { runInstalledNodeJourney } from './testing/installed-node-journey.js';

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
const [mode, filename, ...extra] = process.argv.slice(2);
assert.equal(mode, '--mcp-recovery-campaign'); assert(filename); assert.deepEqual(extra, []);
await runInstalledNodeJourney(filename, 'mcp-recovery');
