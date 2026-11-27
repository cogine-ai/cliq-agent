// Qualification build command only. Neither argument is a release trust root.
import { canonicalJsonBytes } from '../../src/kernel/canonical.js';
import { LEGACY_UPGRADE_SOURCE, prepareLegacyUpgradeSource } from './testing/legacy-upgrade-source.js';

if (process.argv.length !== 4) throw new TypeError('expected original source directory and new owned build directory');
const source = await prepareLegacyUpgradeSource(process.argv[2]!, process.argv[3]!);
process.stdout.write(canonicalJsonBytes({ schemaVersion: 1, format: 'cliq-upgrade-source-copy-v1',
  sourceIdentity: LEGACY_UPGRADE_SOURCE, source }).toString('utf8') + '\n');
