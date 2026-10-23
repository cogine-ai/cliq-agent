// Wiring/contract regressions only. These never constitute installed Delivery
// qualification; the fixed Linux campaign must execute the genuine entry.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const source = name => readFileSync(new URL(name, import.meta.url), 'utf8');

test('every installed Run driver accepts exactly the emitted fixed recipe and verifies the one root-owned publication helper', () => {
  const expected = ['buildFixture', 'controlDirectory', 'installerEntry', 'observer', 'packageRoot', 'publicationObserver',
    'releaseKeysFile', 'reportFile', 'stateRoot', 'storeFixture', 'workspace'].sort();
  const shell = source('../qualify-systemd-user.sh'), start = shell.indexOf('const runJourney =');
  assert(start >= 0);
  const producer = ts.createSourceFile('runJourney.ts', shell.slice(start, shell.indexOf('\nwriteFileSync(file,', start)), ts.ScriptTarget.Latest, true);
  const declaration = producer.statements[0].declarationList.declarations[0];
  assert.equal(declaration.name.getText(producer), 'runJourney');
  assert(ts.isConditionalExpression(declaration.initializer)); assert(ts.isObjectLiteralExpression(declaration.initializer.whenTrue));
  const emitted = declaration.initializer.whenTrue.properties.map(property => {
    assert(ts.isPropertyAssignment(property) && ts.isIdentifier(property.name)); return property.name.text;
  }).sort();
  assert.deepEqual(emitted, expected);
  for (const filename of ['../qualify-installed-run-journey.ts', './installed-node-journey.ts']) {
    const text = source(filename), file = ts.createSourceFile(filename, text, ts.ScriptTarget.Latest, true);
    const checks = [], types = [];
    const visit = node => {
      if (ts.isCallExpression(node) && node.expression.getText(file) === 'assert.deepEqual' &&
          node.arguments[0]?.getText(file) === 'Object.keys(recipe).sort()') checks.push(node);
      if (ts.isTypeAliasDeclaration(node) && node.name.text === 'Recipe') types.push(node);
      ts.forEachChild(node, visit);
    };
    visit(file); assert.equal(checks.length, 1, filename); assert.equal(types.length, 1, filename);
    const sorted = checks[0].arguments[1];
    assert(ts.isCallExpression(sorted) && sorted.arguments.length === 0 && ts.isPropertyAccessExpression(sorted.expression) && sorted.expression.name.text === 'sort');
    const keys = sorted.expression.expression; assert(ts.isArrayLiteralExpression(keys));
    assert(keys.elements.every(key => ts.isStringLiteral(key)));
    assert.deepEqual(keys.elements.map(key => key.text).sort(), expected, filename + ' must not reject the actual emitted recipe');
    assert(ts.isTypeLiteralNode(types[0].type));
    assert.deepEqual(types[0].type.members.map(member => {
      assert(ts.isPropertySignature(member) && ts.isIdentifier(member.name) && !member.questionToken); return member.name.text;
    }).sort(), expected, filename + ' must require every fixed field');
    for (const guard of [
      "assert.equal(recipe.publicationObserver, path.join(ledger.fixture, 'cliq-publication-cleanup-crash-observer'))",
      'const publicationObserver = await lstat(recipe.publicationObserver)',
      'publicationObserver.isFile() && !publicationObserver.isSymbolicLink() && publicationObserver.uid === 0 && publicationObserver.gid === 0 &&',
      'publicationObserver.nlink === 1 && (publicationObserver.mode & 0o7777) === 0o555',
      'open(filename, constants.O_RDONLY | constants.O_NOFOLLOW)',
    ]) assert(text.includes(guard), filename + ' must retain the same fixed helper identity and file guards');
  }
});

test('verifier and Delivery are fixed consumers of one real installed lifecycle', () => {
  const shared = source('./installed-node-journey.ts');
  for (const [file, kind, mode] of [['../qualify-installed-verifier-journey.ts', 'verifier', '--verifier-campaign'],
    ['../qualify-installed-delivery-journey.ts', 'delivery', '--delivery-campaign']]) {
    const entry = source(file);
    assert(entry.includes(`assert.equal(mode, '${mode}')`));
    assert(entry.includes(`await runInstalledNodeJourney(filename, '${kind}')`));
    assert(!entry.includes('buildInstalledSupervisorPackage('));
  }
  assert.equal((shared.match(/await buildInstalledSupervisorPackage\(/gu) ?? []).length, 1);
  assert.equal((shared.match(/const setup = credential\(/gu) ?? []).length, 1);
  assert.equal((shared.match(/await runOwnedEnrollDiagnostic\(/gu) ?? []).length, 1);
  assert.equal((shared.match(/await scanCredentialSecretCorpus\(/gu) ?? []).length, 1);
  for (const assertion of ["assert.equal(stopped.TimeoutStopUSec, '2s')", 'originalDeadlineMs: 60000',
    "'actual candidate/verifier/result did not reach terminal within its fixed 90-second qualification window'",
    "'installed image handoff exceeded the original 30-second restart budget'"])
    assert(shared.includes(assertion), 'original deadline/retirement assertion remains in the actual shared owner');
  assert(!/INSTALLED_DELIVERY_COMPOSITION_COMPLETE|supportsInstalledDelivery\s*=|featureOverride/gu.test(shared));
});

test('the root harness chooses only the fixed Delivery entry', () => {
  const shell = source('../qualify-systemd-user.sh');
  assert(/--run-delivery-journey\)\s*probe_campaign_kind=run-journey;\s*probe_run_driver_mode=--delivery-campaign;\s*shift\s*;;/u.test(shell));
  assert(shell.includes('readonly probe_run_driver="$probe_source_dir/qualify-installed-delivery-journey.ts"'));
  assert(!/probe_run_driver=\$[12]/u.test(shell));
});

test('controlled delayed storage is a fixed free-VM qualification mode, never a production feature switch', () => {
  const shell = source('../qualify-systemd-user.sh'), entry = source('../qualify-installed-delivery-journey.ts');
  const fixture = source('./installed-node-journey.ts');
  const workflow = source('../../../.github/workflows/kernel-foundation.yml');
  assert(shell.includes('--run-delivery-delay-journey) probe_campaign_kind=run-journey; probe_run_driver_mode=--delivery-delay-campaign; shift ;;'));
  assert(shell.includes('"$probe_run_driver_mode" != --delivery-delay-campaign || "$probe_volume_mode" = delay-50ms'));
  assert(entry.includes("mode === '--delivery-delay-campaign'"));
  assert(entry.includes("await runInstalledNodeJourney(filename, 'delivery', { publicationRetirementDiagnostics: true })"));
  assert(fixture.includes('publicationRetirementDiagnostics: options.publicationRetirementDiagnostics'));
  assert(fixture.includes('latePublicationResultQualified: false, preciseInFlightPublicationStopQualified: false'));
  const controlled = workflow.slice(workflow.indexOf('\n  linux-installed-delivery-delayed-volume:'));
  assert(controlled.startsWith('\n  linux-installed-delivery-delayed-volume:'));
  assert(controlled.includes('runs-on: ubuntu-22.04')); assert(controlled.includes('timeout-minutes: 20'));
  assert(controlled.includes('test "$RUNNER_ENVIRONMENT" = github-hosted'));
  assert(controlled.includes('test "$RUNNER_OS" = Linux')); assert(controlled.includes('test "$RUNNER_ARCH" = X64'));
  assert(controlled.includes('sudo /usr/sbin/modprobe dm_delay'));
  assert(controlled.includes('sudo "$probe_node" --test --test-concurrency=1 --import tsx scripts/kernel/testing/installed-publication-crash-observer.test.ts'));
  assert(controlled.includes('--delay-volume --run-delivery-delay-journey'));
  assert(!/self-hosted|modprobe -r|dmsetup (?:remove_all|suspend|reload)|drop_caches/u.test(controlled));
});

test('Delivery keeps retained proof reads distinct from the actual public downloads and does not invent coverage', () => {
  const shared = source('./installed-node-journey.ts'), delivery = source('./installed-delivery-journey.ts');
  assert(shared.includes('readRetainedArtifact: readCas, downloadPublicArtifact: readPublicArtifact'));
  assert(shared.includes("reason: supported ? 'not_yet_executed' : 'production_composition_not_advertised'"));
  assert(shared.includes('qualified: false, attemptStarted: false, capabilityAdvertised: supported'));
  const started = shared.indexOf("report.delivery = { ...report.delivery, attemptStarted: true, reason: 'in_progress' }");
  assert(started >= 0 && started < shared.indexOf('report.delivery = await runInstalledDeliveryCases({'));
  assert(!shared.includes('executed: false'), 'a failed in-progress campaign cannot assert that no effect executed');
  assert(shared.includes('assertWorkerRetired(runId, launchId,'));
  assert(delivery.includes('context.downloadPublicArtifact(result.deliveryTerminalProjectionEvidenceRef)'));
  assert(delivery.includes('context.downloadPublicArtifact(entry.blobRef)'));
  assert(delivery.includes('context.downloadPublicArtifact(ref)'));
  assert(delivery.includes('for (const action of [context.reconnect, context.restart])'));
  assert(delivery.includes('assert.deepEqual(await reads(entry.cut), entry.queries)'));
  for (const field of ['interactiveApprovalQualified: false', 'preciseClaimedCloseCutQualified: false',
    'allCrashCutsQualified: false', 'completeI1Qualified: false', 'completeI4Qualified: false',
    'verifierReleaseBeforeCancelObserved: false', 'preciseInFlightVerifierCancelQualified: false']) assert(delivery.includes(field));
  assert(delivery.includes("context.mark('delivery_cancel_after_observed_verifier_claim')"));
  assert(!delivery.includes('delivery_cancel_real_inflight_verifier'));
  assert(delivery.includes('cancellation: { request: cancellation, response: cancellationResponse }'));
  assert(delivery.includes('await context.assertVerifierProcessesAbsent(identity)'));
  assert(shared.includes('readOwnerHistory: async () => inspectInstalledOwnerHistory(recipe.stateRoot).owners'));
  assert(!/new StateStore|\.transaction\(|new DatabaseSync|loadNativeStateOwner|process\.env/u.test(delivery));
});

test('source and Delivery reuse one complete verifier-retirement graph and independently observe process lifetimes', () => {
  const sourceVerifier = source('./installed-verifier-result.ts'), delivery = source('./installed-delivery-result.ts');
  const shared = source('./installed-verifier-evidence.ts'), fixture = source('./installed-node-journey.ts');
  assert(sourceVerifier.includes('await assertInstalledVerifierRetirement('));
  assert(delivery.includes('await assertInstalledVerifierRetirement('));
  assert(delivery.includes('await assertInstalledDeliveryPublication({ cut, readRetainedArtifact: bytes, readOwnerHistory: input.readOwnerHistory })'));
  for (const edge of ['launch.parentWorkerContainmentRef', 'retirement.snapshotEvidenceRef', 'retirement.parentRetirementEvidenceRef',
    'retirement.deathEvidenceRef', 'retirement.containmentRef', 'snapshot.quiescenceEvidenceRef', 'validateMatchingWorkerDeath',
    "role: 'namespace_init'", "role: 'monitor'", "role: 'subreaper'"]) assert(shared.includes(edge));
  assert(fixture.includes('for (const retirement of proof.retirementIdentities) await assertVerifierProcessesAbsent(retirement)'));
  assert(fixture.includes('assert.notEqual(await processStart(identity.pid), identity.startTicks)'));
});

test('Delivery connects the actual handoff seal to readonly SQL retirement and independent process checks', () => {
  const result = source('./installed-delivery-result.ts'), delivery = source('./installed-delivery-journey.ts');
  const fixture = source('./installed-node-journey.ts');
  assert(result.includes('plan.forwardOperations.length ? deliveryPublicationTerminalCheckpointId(run.id, merged.deliveryPlanRef)'));
  assert(result.includes('publicationWorkerRetirement: publication.publicationWorkerRetirement'));
  assert.equal((delivery.match(/retirements\([^\n]*proof\.publicationWorkerRetirement\)/gu) ?? []).length, 2);
  assert(delivery.includes('const { verifierRetirementIdentities, publicationWorkerRetirement, ...proof } = entry.proof'));
  assert(fixture.includes('retirement: publicationRetirement'));
  assert(fixture.includes('selected.launchIds.includes(publicationRetirement.launchId)'));
});

test('the cleanup crash is an additional strict physical subcase, never a fourth source or a timing pause', () => {
  const fixture = source('./installed-node-journey.ts'), delivery = source('./installed-delivery-journey.ts'),
    observer = source('./publication-cleanup-crash-observer.c'), shell = source('../qualify-systemd-user.sh');
  assert(delivery.includes('await context.cleanupCrash(first)'));
  assert.equal((delivery.match(/await context.createSource\(/gu) ?? []).length, 3);
  assert(fixture.includes('assert.equal(postCount, 6)')); assert(fixture.includes('assert.equal(originalPublicResultBytes.size, 6)'));
  assert(fixture.includes('assert.equal(crash.originalReceiptCommitted, false'));
  assert(fixture.includes('assert.deepEqual(crash.journal.slice(0, 2), claimed.journal)'));
  assert(fixture.includes('joinedAt <= proof.probeStartedAt'));
  assert(fixture.includes('await observer.close()')); assert(fixture.includes('originalReceiptCasObjectAbsenceQualified: false, rebootQualified: false'));
  assert(shell.includes('readonly probe_publication_observer_source="$probe_source_dir/testing/publication-cleanup-crash-observer.c"'));
  assert.equal((observer.match(/SYS_pidfd_send_signal, process, SIGKILL/gu) ?? []).length, 1);
  assert(observer.includes('IN_CREATE | IN_DELETE | IN_ONLYDIR')); assert(observer.includes('named.st_nlink != 0'));
  assert(!/SIGSTOP|SIGCONT|ptrace\(|process\.kill\(|kill\(/u.test(observer));
});

test('cleanup after the normal restart joins only an inspection client that is still held', () => {
  const fixture = source('./installed-node-journey.ts'), delivery = source('./installed-delivery-journey.ts');
  const restart = fixture.slice(fixture.indexOf('restart: async () => {'), fixture.indexOf('cleanupCrash: async source => {'));
  const crash = fixture.slice(fixture.indexOf('cleanupCrash: async source => {'));
  assert(restart.includes('await inspectionClient!.close(); inspectionClient = undefined'));
  assert(delivery.indexOf('for (const action of [context.reconnect, context.restart])') < delivery.indexOf('await context.cleanupCrash(first)'));
  assert(crash.includes('await inspectionClient?.close(); inspectionClient = undefined;'),
    'the normal restart already joined and cleared the original inspection consumer');
  assert(!crash.includes('inspectionClient!.close()'));
  assert(!crash.includes('inspectionClient = await persistentClient()'), 'the cut must not open an unnecessary second authenticated consumer');
});
