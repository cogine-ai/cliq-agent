// The normal signed CLI path shares the existing disposable installation,
// actual systemd/Secret Service owner and complete process/resource finalizers.
// Its controlled HTTPS responses do not qualify a paid or official provider.
import assert from 'node:assert/strict';
import { runInstalledNodeJourney } from './testing/installed-node-journey.js';

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
const [mode, filename, ...extra] = process.argv.slice(2);
assert.equal(mode, '--daily-campaign'); assert(filename); assert.equal(extra.length, 0);
await runInstalledNodeJourney(filename, 'daily');
