import { runInstalledRuntimeUpgradeJourney } from './testing/installed-upgrade-journey.js';
if (process.argv.length !== 5 || process.argv[2] !== '--runtime-upgrade-campaign')
  throw new TypeError('expected only the fixed upgrade campaign, owned ledger and original source directory');
await runInstalledRuntimeUpgradeJourney(process.argv[3]!, process.argv[4]!);
