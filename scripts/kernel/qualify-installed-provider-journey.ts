// Explicit billable experiment, never part of free CI. The same root-owned
// disposable UID/systemd/keyring/installer/finalizers own the complete journey.
import assert from 'node:assert/strict';
import { runInstalledNodeJourney } from './testing/installed-node-journey.js';
import { readProviderJourneyConfiguration, readProviderJourneySecret } from './testing/provider-journey-input.js';

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64'); assert.equal(process.geteuid!(), 0);
const [mode, filename, config, ...extra] = process.argv.slice(2);
assert(mode === '--provider-campaign' || mode === '--provider-daily-campaign'); assert(filename && config && !extra.length);
const selection = await readProviderJourneyConfiguration(config);
// The root-owned caller must not send key bytes during the shell's setup. It
// waits for this fixed marker from this exact original driver, then writes the
// private pipe once and closes it. No child is started until EOF is consumed.
await new Promise<void>((resolve, reject) => process.stdout.write('CLIQ_PROVIDER_SECRET_STDIN_READY_V1\n', error => error ? reject(error) : resolve()));
const secret = await readProviderJourneySecret(process.stdin);
try { await runInstalledNodeJourney(filename, mode === '--provider-daily-campaign' ? 'provider-daily' : 'provider', { provider: { ...selection, secret } }); }
finally { secret.fill(0); }
