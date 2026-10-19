// Fixed real Linux verifier consumer. The shared owner retains one signed
// installation, HTTPS endpoint, Secret Service and complete finally/join.
import assert from 'node:assert/strict';
import { runInstalledNodeJourney } from './testing/installed-node-journey.js';

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
const [mode, filename, ...extra] = process.argv.slice(2);
assert.equal(mode, '--verifier-campaign'); assert(filename && extra.length === 0);
await runInstalledNodeJourney(filename, 'verifier');
