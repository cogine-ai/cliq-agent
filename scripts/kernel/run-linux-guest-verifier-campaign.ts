import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalSha256 } from '../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../src/kernel/json.js';
import { qualifyGuestToolchainExtraction } from './testing/guest-toolchain-native.js';
import { qualifyLinuxGuestVerifier } from './testing/guest-verifier-native.js';
import { prepareSupervisorSeaCarrier } from './testing/supervisor-sea-builder.js';
import { joinGuestExtractionChild } from './testing/guest-campaign-child.js';
import { readGuestVerifierBoundaryFailure, readGuestVerifierOutputFailure } from './testing/guest-verifier-diagnostics.js';

// The guest raw image is never mounted. CI's separately disposable ext4
// StateRoot volume is a fixture, not a runtime guest-image loader/authority.
assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
const [mode, ...arguments_] = process.argv.slice(2);
if (mode === '--prepare') {
  assert.equal(arguments_.length, 3);
  const [guestRoot, installationRoot, carrierRoot] = arguments_ as [string, string, string];
  assert.ok(arguments_.every(value => path.isAbsolute(value)));
  await mkdir(carrierRoot, { mode: 0o700 });
  const { carrier } = await prepareSupervisorSeaCarrier(carrierRoot);
  const builder = fileURLToPath(new URL('./build-linux-guest-toolchain.mjs', import.meta.url));
  const built = spawnSync(process.execPath, [builder, guestRoot, installationRoot, carrier], { stdio: 'inherit', timeout: 60_000 });
  assert.equal(built.error, undefined); assert.equal(built.status, 0);
  const raw = await readFile(path.join(guestRoot, 'guest-toolchain-input.json'));
  assert.ok(raw.length > 0 && raw.length <= 1_048_576);
  const metadata = parseJsonStrict(raw.toString('utf8')) as Record<string, any>;
  console.log(JSON.stringify({ phase: 'guest_image_built', imageDigest: metadata.guestImageDigest,
    imageByteCount: metadata.guestImageByteCount, nodeDigest: metadata.node.digest,
    source: 'existing checksum-pinned actual SEA Node carrier, not host Node fallback', qualified: false }));
} else {
  assert(mode === '--run' || mode === '--extract'); assert.equal(arguments_.length, 1);
  assert.notEqual(process.getuid!(), 0, 'the actual verifier campaign must exercise non-root delegation');
  const reportRoot = arguments_[0]!; assert.ok(path.isAbsolute(reportRoot));
  if (mode === '--run') await mkdir(reportRoot, { mode: 0o700 });
  const required = (name: string) => { const value = process.env[name]; assert.ok(value && path.isAbsolute(value), `missing absolute ${name}`); return value; };
  const input = { installationRoot: required('CLIQ_I1_INSTALLATION'), guestImageRoot: required('CLIQ_I1_GUEST_IMAGE'),
    cgroupParent: required('CLIQ_I1_CGROUP_PARENT'), stateVolume: required('CLIQ_I1_GUEST_STATE_VOLUME') };
  const revision = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8', timeout: 5000, maxBuffer: 1024 });
  assert.equal(revision.status, 0); const sourceRevision = revision.stdout.trim(); assert.match(sourceRevision, /^[0-9a-f]{40}$/u);
  const identity = { sourceRevision, node: process.version, platform: process.platform, architecture: process.arch };
  let phase = 'guest_extraction';
  try {
    if (mode === '--extract') {
      const extraction = await qualifyGuestToolchainExtraction(input);
      await writeFile(path.join(reportRoot, 'guest-extractor-report.json'), JSON.stringify({ schemaVersion: 1,
        format: 'cliq-real-guest-extractor-report-v1', ...identity, ...extraction }), { flag: 'wx', mode: 0o600 });
    } else {
      // Keep the real native stages separate so closed /proc/self/fd/N load
      // names are never reused for different addons in one campaign process.
      const controller = new AbortController();
      const stop = () => controller.abort();
      process.once('SIGTERM', stop); process.once('SIGINT', stop);
      try {
        const child = spawn(process.execPath, [...process.execArgv, fileURLToPath(import.meta.url), '--extract', reportRoot],
          { env: process.env, cwd: process.cwd(), stdio: 'inherit' });
        await joinGuestExtractionChild(child, controller.signal);
        assert(!controller.signal.aborted, 'original extractor stage was interrupted');
      } finally { process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop); }
    }
    if (mode === '--run') {
      phase = 'guest_verifier';
      const verifier = await qualifyLinuxGuestVerifier({ ...input, stateVolume: input.stateVolume });
      const report = { schemaVersion: 1, format: 'cliq-real-guest-verifier-report-v1', ...identity, ...verifier };
      await writeFile(path.join(reportRoot, 'guest-verifier-report.json'), JSON.stringify(report), { flag: 'wx', mode: 0o600 });
      console.log(JSON.stringify({ phase: 'guest_campaign_complete', sourceRevision,
        reportDigest: canonicalSha256(report), cases: verifier.reports.length, qualified: verifier.qualified,
        scope: verifier.scope, unverifiedCuts: verifier.unverifiedCuts }));
    }
  } catch (error) {
    const boundaryFailure = phase === 'guest_verifier' ? readGuestVerifierBoundaryFailure(error) : undefined;
    const outputFailure = phase === 'guest_verifier' ? readGuestVerifierOutputFailure(error) : undefined;
    if (mode === '--run') await writeFile(path.join(reportRoot, 'guest-campaign-failure.json'), JSON.stringify({ schemaVersion: 1,
      format: 'cliq-real-guest-campaign-failure-v1', ...identity, phase, qualified: false,
      ...(boundaryFailure ? { boundaryFailure } : {}),
      ...(outputFailure ? { outputFailure } : {}),
      source: 'fixed failure metadata only; no raw log, StateRoot, key or process proof is serialized' }), { flag: 'wx', mode: 0o600 });
    throw error;
  }
}
