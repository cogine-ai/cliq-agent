// Source wiring only. No transcript, clock or data fixture proves a physical
// Linux stop; the separate complete installed campaign must actually pass.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = file => readFileSync(new URL(file, import.meta.url), 'utf8');

test('the separate original-stop mode requires diagnostics and leaves the default cleanup campaign intact', () => {
  const owner = source('./installed-node-journey.ts'), delivery = source('./installed-delivery-journey.ts');
  assert(owner.includes('publicationRetirementStop?: true'));
  assert(owner.includes('if (options.publicationRetirementStop) assert.equal(options.publicationRetirementDiagnostics, true)'));
  assert(delivery.includes("options.faultCase === 'original_stop'"));
  assert(delivery.includes('await context.cleanupCrash(first)'));
  assert.equal((delivery.match(/await context.createSource\(/gu) ?? []).length, 3);
  assert(delivery.includes('originalPublicationStopCase'));
});

test('the actual stop uses its captured public cut before the original two-unit retention and unique actor arm', () => {
  const owner = source('./installed-node-journey.ts');
  const start = owner.indexOf('originalStop: async (source, operation) => {'); assert(start >= 0);
  const stop = owner.slice(start, owner.indexOf('cleanupCrash: async source => {', start));
  const capture = stop.indexOf('await operation.capture(admitted.runId)'), retained = stop.indexOf('await withRetainedUnitHistory('),
    arm = stop.indexOf('observer.arm(claimed.birth)');
  assert(capture >= 0 && capture < retained && retained < arm);
  assert(stop.includes('startPublicationRetirementStopObserver('));
  assert(stop.includes('assert.deepEqual(beforeCut.journal, claimed.journal)'));
  assert(stop.includes('readInstalledOriginalRetirementJournal('));
  assert(stop.includes('isOriginalPublicationFirstParentSignalBracket('));
  assert(stop.includes("['--user', 'start', services!.supervisorUnit]"));
  assert(stop.includes('await observer.close()'));
});

test('only the full original closure plus scanner and real outer joins may promote precise qualification', () => {
  const owner = source('./installed-node-journey.ts'), delivery = source('./installed-delivery-journey.ts');
  assert(delivery.includes('=> assertInstalledPublicationStopResult('));
  assert(delivery.includes('const proof = await prove()'));
  assert(delivery.includes('await stopped.verify(proof)'));
  assert(delivery.includes('await context.reconnect()'));
  assert(delivery.includes('latePublicationResultQualified: false'));
  const scanner = owner.indexOf('report.secretCorpus = await scanCredentialSecretCorpus('),
    qualified = owner.indexOf('report.preciseInFlightPublicationStopQualified = true');
  assert(scanner >= 0 && qualified > scanner);
  assert(owner.includes('historicalSealedMAndRecoverableCheckpointVerified'));
  assert(owner.includes('currentSealedMDirectoryPhysicalBytesQualified: false'));
  assert(owner.includes('assert.equal(postCount, 6)'));
});
