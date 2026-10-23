// Wiring only, never actual public-cut, native-fsync or physical qualification.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
const source = name => readFileSync(new URL(name, import.meta.url), 'utf8');

test('the explicit late journey is mutually exclusive and keeps the normal and stop branches intact', () => {
  const owner = source('./installed-node-journey.ts');
  assert(owner.includes('publicationRetirementLate?: true'));
  assert(owner.includes('assert(!options.publicationRetirementStop || !options.publicationRetirementLate)'));
  assert(owner.includes('if (options.publicationRetirementLate) assert.equal(options.publicationRetirementDiagnostics, true)'));
  assert(owner.includes('assertInstalledPublicationLateAuditRecovery'));
});

test('both cuts are retained from actual public responses during sampling, never reconstructed from an eventual prefix', () => {
  const owner = source('./installed-node-journey.ts');
  const start = owner.indexOf("if (lateDiagnostic) lateDiagnostic.stage = 'sampling';");
  const end = owner.indexOf('const recoveryInput =', start), sampling = owner.slice(start, end);
  assert(start >= 0 && end > start);
  for (const actual of ["recovered = accepted(await client.send({ protocolVersion: 1, method: 'run.get', runId }), 'run.get')",
    'readInstalledPublicationProbeSample({ cut: recovered', "sampled.phase === 'first_before'", 'beforeCut = recovered',
    "sampled.phase === 'first_audit'", 'auditCut = recovered']) assert(sampling.includes(actual));
  assert(sampling.includes("assert(Date.now() < by, 'actual cleanup crash recovery exceeded its original 90-second window')"));
  assert(!/slice\(|structuredClone|\.filter\(/u.test(sampling));
});

test('the raw complete window and clock tuples are retained before cut or physical-hit assertions can fail', () => {
  const owner = source('./installed-node-journey.ts');
  const captured = owner.indexOf('lateDiagnostic.snapshots = snapshots;');
  const causal = owner.indexOf('if (lateDiagnostic.snapshots!.length === 2) assertInstalledPublicationLateCausalOrder({');
  const interval = owner.indexOf('if (probes[0]!.completedAt) lateDiagnostic.interval = assessInstalledPublicationLateInterval');
  const cuts = owner.indexOf("assert(beforeCut && auditCut, 'actual first in-flight beforeCut");
  const audit = owner.indexOf('const audit = await assertInstalledPublicationLateAudit(');
  const hit = owner.indexOf("assert(lateDiagnostic.interval?.hit, 'the same original continuous parent fsync");
  const recovery = owner.indexOf('? await assertInstalledPublicationLateAuditRecovery(');
  const bound = owner.indexOf('lateDiagnostic.currentProcessLifetimeAndImageBound = true; break;', captured);
  assert(captured >= 0 && bound > captured && causal > bound && interval > causal && cuts > interval && audit > cuts && hit > audit && recovery > hit);
  assert(owner.includes(': await assertInstalledPublicationCleanupRecovery(recoveryInput)'));
});

test('the dedicated query has no tail or H filtering and retains original budgets with real process/image bracketing', () => {
  const owner = source('./installed-node-journey.ts');
  const begin = owner.indexOf('assert(windowStart); const logBy = Date.now() + 5000;');
  const end = owner.indexOf("assert(beforeCut && auditCut, 'actual first in-flight beforeCut", begin);
  const query = owner.slice(begin, end);
  assert(begin >= 0 && end > begin);
  for (const part of ["'--no-tail'", "'--output=json'", "'--boot=0'", "'_TRANSPORT=stdout'", '_UID=${ledger.uid}', '_PID=${successorPid}',
    '(Date.parse(windowStart) / 1000).toFixed(3)', '(Date.parse(until) / 1000).toFixed(3)',
    'maxBuffer: 256 * 1024', 'timeout: remaining', "killSignal: 'SIGKILL'",
    'readInstalledLatePublicationRetirementWindow(text', 'expiredProbeKey: probes[0]!.key, freshProbeKey: probes[1]!.key']) assert(query.includes(part));
  assert.equal((query.match(/await bindCurrentProcess\(\)/gu) ?? []).length, 2);
  assert(!/--lines|--grep|MESSAGE=|\.filter\(|Math\.(?:floor|ceil)\(/u.test(query));
  const binding = owner.slice(owner.indexOf('const bindCurrentProcess = async () => {', owner.indexOf('if (lateDiagnostic) {\n              // Preserve')), begin);
  for (const part of ['fixtureProcess(successorPid, ledger.uid)', 'qualifyInstalledOwnerProcess(', 'selectedImage: installedImage',
    'imageDigest: supervisorDigest', "'linux-proc-start-ticks:' + successorStart"]) assert(binding.includes(part));
  assert(owner.includes("assert(windowStart <= probes[0]!.probeStartedAt, 'the actual successor binding must precede the original probe window')"));
  assert(query.includes("observedWindow.phase === 'complete'"));
  assert(query.includes("observedWindow.phase === 'first_packet_only'"));
  assert(query.includes('{ diagnosticOnly: true, complete: false, observedGroups: 1 }'));
  assert(query.includes('delete lateDiagnostic.namespaceWindowProgress'));
});

test('only the existing full join/secret-scan tail promotes the complete late conjunction and every failure resets qualification', () => {
  const owner = source('./installed-node-journey.ts');
  const scan = owner.indexOf('report.secretCorpus = await scanCredentialSecretCorpus');
  const promote = owner.indexOf("Object.assign(late, { stage: 'complete', qualified: true, physicalLateCutQualified: true })");
  assert(scan >= 0 && promote > scan);
  for (const exact of ['assert.equal(late.realPublicCutsQualified, true)', 'assert.equal(late.interval?.hit, true)',
    'assert.equal(late.currentProcessLifetimeAndImageBound, true)', 'assert.equal(late.oldTaskJoinedAndTimedOut, true)',
    'assert.equal(late.originalBackoffAndFreshNonceVerified, true)', 'assert.equal(late.resolutionBudgetDeltaZero, true)',
    'assert.equal(late.originalWorkerAndArenaIndependentlyAbsent, true)', 'assert.equal(late.redispatchCount, 0)',
    'assert.equal(late.additionalModelPosts, 0)', 'assert.equal(late.sameReplayAfterReconnect, true)']) assert(owner.includes(exact));
  const fail = owner.slice(owner.indexOf('if (primary) {', promote));
  assert(fail.includes('report.latePublicationResultQualified = false'));
  assert(fail.includes('report.delivery.latePublicationResultQualified = false'));
  assert(fail.includes('{ qualified: false, physicalLateCutQualified: false }'));
});

test('late qualification requires the same original-parent arena absence observation as the normal stop closure', () => {
  const owner = source('./installed-node-journey.ts');
  const helper = owner.indexOf('const assertArenaAbsent = async (birth: PublicationArenaBirthV1) => {');
  const stop = owner.indexOf('originalStop: async (source, operation) => {');
  const crash = owner.indexOf('cleanupCrash: async source => {', stop);
  assert(helper >= 0 && helper < stop && crash > stop, 'both real closures must share the original strict directory observation');
  const observation = owner.slice(helper, stop);
  for (const fixed of ["[recipe.stateRoot, 'runtime', 'publications']", 'constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW',
    'info.uid === BigInt(ledger.uid)', '(info.mode & 0o7777n) === 0o700n',
    'identity.dev.toString(), birth.parentIdentity.deviceId', 'identity.ino.toString(), birth.parentIdentity.fileId',
    'readCas(birth.deliveryPlanRef)', 'publicationEnvelopeLocations({ birth, operation })',
    'assert.equal(locations.length, 2)', "location.kind === 'publication_arena' && location.arenaId === birth.arenaId",
    'lstat(`/proc/self/fd/${parent.fd}/${birth.arenaId}`)', "code === 'ENOENT'",
    'Promise.allSettled(held.reverse().map(directory => directory.close()))',
    "closes.every(result => result.status === 'fulfilled')"]) assert(observation.includes(fixed), fixed);
  assert(owner.slice(stop, crash).includes('await assertArenaAbsent(claimed.birth); await sameKeeper();'));
  const worker = owner.indexOf('const retired = inspectInstalledRecoveredWorkerRetirement', crash);
  const quarantine = owner.indexOf('lstat(path.join(recipe.stateRoot, retired.quarantinePath))', worker);
  const arena = owner.indexOf('if (lateDiagnostic) await assertArenaAbsent(claimed.birth);', quarantine);
  const qualified = owner.indexOf('originalWorkerAndArenaIndependentlyAbsent: true', arena);
  assert(worker > crash && quarantine > worker && arena > quarantine && qualified > arena,
    'worker death and quarantine absence cannot substitute for the original publication arena/slot observation');
  assert.equal((owner.match(/const assertArenaAbsent =/gu) ?? []).length, 1);
});

test('the full original Delivery core remains mandatory and late metadata does not replace UNKNOWN cleanup qualification', () => {
  const journey = source('./installed-delivery-journey.ts');
  assert(journey.includes("faultCase?: 'original_stop' | 'late_result'"));
  assert(journey.includes('} else await context.cleanupCrash(first);'));
  assert(journey.includes('sourceRunsQualifiedByOriginalFullVerifierReader: 3, actualModelPostsOnlyForSource: 6'));
  assert(journey.includes('cleanupCrashQualified: originalPublicationStopCase === undefined'));
  assert(journey.includes("options.faultCase === 'late_result' ? { latePublicationResultQualified: false"));
});
