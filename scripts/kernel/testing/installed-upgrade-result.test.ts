import assert from 'node:assert/strict';
import { test } from 'node:test';
import { LEGACY_UPGRADE_SOURCE } from './legacy-upgrade-source-data.js';
import { decodeInstalledUpgradeReport, INSTALLED_UPGRADE_PROFILE } from './installed-upgrade-result.js';

// Deliberately inert report data. These tests prove only the closed evidence
// decoder; they do not supply any Store, native receipt or installed authority.
function complete(): Record<string, any> {
  return { diagnosticOnly: true, qualified: true, schemaVersion: 1, format: 'cliq-installed-runtime-upgrade-qualification-v1',
    fixtureProfile: INSTALLED_UPGRADE_PROFILE, phase: 'complete', scope: 'signed_schema7_to8_two_unverified_edit_runs',
    officialReleaseQualified: false, wholeI4Qualified: false, legacy43ErrorReceipt: { kind: 'not_exercised' }, originalSource: LEGACY_UPGRADE_SOURCE,
    packages: { sourceBundleRef: '1'.repeat(64), targetBundleRef: '2'.repeat(64), sourceManifestDigest: '3'.repeat(64), targetManifestDigest: '4'.repeat(64),
      sameActualPublisher: true, schemaConversionDigest: '5'.repeat(64) },
    cases: [7, 8].map((schemaVersion, index) => ({ schemaVersion, runId: (index ? 'b' : 'a').repeat(43), status: 'completed_unverified',
      resultRef: (index ? '7' : '6').repeat(64), firstResponseSha256: (index ? 'c' : '8').repeat(64), modelPosts: 2, toolCalls: 1, launchCount: 1,
      retirementRefs: [(index ? 'a' : '9').repeat(64)], hostSourceUnchanged: true, publicRecoveryRead: true, actualWorkerLifetimesAbsent: true })),
    oldCredentialNewRuntimeRefusal: { code: 'ARTIFACT_MISMATCH', noNewRun: true, noModelDispatch: true },
    upgrade: { receiptRef: 'b'.repeat(64), originalSupervisorAndKeeperLifetimesAbsent: true, realTargetHello: true,
      oldFirstResponseUnchanged: true, originalCasBytesAndInodesUnchanged: true, oldEndpointAndCredentialReadable: true, oldCredentialRevocable: true,
      explicitNewRuntimeEndpointAndCredential: true, sameReceiptRecovery: true, pagedRetirementGraphFullyRead: true, retirementResourceRowCount: 3 },
    servicesStoppedAndJoined: true, secretServiceJoined: true, httpsJoined: true,
    transport: { postCount: 4, acceptedTcp: 4, acceptedTls: 4, providerHealthy: true },
    secretCorpus: { diagnosticOnly: true, qualified: true, filesScanned: 1, fileBytesScanned: 1, sqliteDatabasesScanned: 2,
      logicalRowsScanned: 1, logicalValuesScanned: 1, logicalBytesScanned: 1, evidenceDirectoriesScanned: 0 },
    secretOutputScan: { bytesScanned: 1, chunksScanned: 1, streamsOpened: 1, streamsClosed: 1, needleCount: 1,
      retainedNeedleBytes: 0, retainedTailBytes: 0, matched: false, limitExceeded: false, closed: true } };
}
test('the independent upgrade profile requires both original and target unverified Runs, exact joins and unchanged caps', () => {
  assert.equal(decodeInstalledUpgradeReport(complete()).qualified, true);
  const corruptions: Array<(row: Record<string, any>) => void> = [
    row => { row.fixtureProfile = 'new_unreviewed_profile'; }, row => { row.cases.pop(); }, row => { row.cases.reverse(); },
    row => { row.cases[1].runId = row.cases[0].runId; }, row => { row.cases[1].status = 'succeeded'; },
    row => { row.cases[1].toolCalls = 0; }, row => { row.cases[0].retirementRefs = []; }, row => { row.upgrade.originalCasBytesAndInodesUnchanged = false; },
    row => { row.upgrade.oldFirstResponseUnchanged = false; }, row => { row.upgrade.sameReceiptRecovery = false; },
    row => { row.oldCredentialNewRuntimeRefusal.noModelDispatch = false; }, row => { delete row.oldCredentialNewRuntimeRefusal; },
    row => { row.secretServiceJoined = false; }, row => { row.transport.postCount = 5; }, row => { row.secretOutputScan.streamsOpened = 4097; row.secretOutputScan.streamsClosed = 4097; },
    row => { row.secretOutputScan.bytesScanned = 512 * 1024 * 1024 + 1; }, row => { row.wholeI4Qualified = true; },
    row => { row.error = { diagnosticOnly: true, kind: 'installed_runtime_upgrade_failed', sourceFrames: [] }; },
  ];
  for (const corrupt of corruptions) { const row = complete(); corrupt(row); assert.throws(() => decodeInstalledUpgradeReport(row)); }
});
test('partial upgrade failures stay failures and hostile data cannot execute getters or proxy traps', () => {
  const row = complete(); row.qualified = false; row.phase = 'formal_signed_upgrade_and_real_ready'; row.cases.pop(); delete row.upgrade;
  row.error = { diagnosticOnly: true, kind: 'installed_runtime_upgrade_failed', sourceFrames: [{ file: 'installed-upgrade-journey.ts', line: 1, column: 1 }] };
  assert.equal(decodeInstalledUpgradeReport(row).qualified, false);
  let reads = 0;
  assert.throws(() => decodeInstalledUpgradeReport(new Proxy({}, { ownKeys() { reads++; return []; } })));
  const getter = complete(); Object.defineProperty(getter, 'qualified', { get() { reads++; return true; }, enumerable: true });
  assert.throws(() => decodeInstalledUpgradeReport(getter)); assert.equal(reads, 0);
  const extra = complete(); extra.error = { diagnosticOnly: true, kind: 'installed_runtime_upgrade_failed', sourceFrames: [], rawError: 'not permitted' };
  assert.throws(() => decodeInstalledUpgradeReport(extra));
  const corpus = complete(); corpus.qualified = false; corpus.phase = 'secret_scan_or_report_failure';
  corpus.secretScanFailure = { diagnosticOnly: true, firstFailureStage: 'corpus', beforeCorpus: { streamsOpened: 1, bytesScanned: 1 }, corpusScanFailureCode: 'LIMIT_EXCEEDED' };
  corpus.secretCorpusScanProgress = { diagnosticOnly: true, source: { kind: 'database_logical', database: 'kernel', tableBucket: 'workspace_generations',
    part: 'cell', logicalRowsObserved: 1, logicalValuesAttempted: 2, logicalBytesObserved: 3 } };
  assert.equal(decodeInstalledUpgradeReport(corpus).qualified, false);
  corpus.secretCorpusScanProgress.source.rawPath = '/not-allowed'; assert.throws(() => decodeInstalledUpgradeReport(corpus));
});
