// Source wiring only. No transcript, clock or data fixture proves a physical
// Linux stop; the separate complete installed campaign must actually pass.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const source = file => readFileSync(new URL(file, import.meta.url), 'utf8');

test('the separate original-stop mode requires diagnostics and leaves the default cleanup campaign intact', () => {
  const owner = source('./installed-node-journey.ts'), delivery = source('./installed-delivery-journey.ts');
  assert(owner.includes('publicationRetirementStop?: true'));
  assert(owner.includes('if (options.publicationRetirementStop) assert.equal(options.publicationRetirementDiagnostics, true)'));
  assert(delivery.includes("options.faultCase === 'original_stop'"));
  assert(delivery.includes('await context.cleanupCrash(first)'));
  const parsed = ts.createSourceFile('installed-delivery-journey.ts', delivery, ts.ScriptTarget.Latest, true);
  const kinds = [];
  const collect = node => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
        node.expression.expression.getText(parsed) === 'context' && node.expression.name.text === 'createSource') {
      assert.equal(node.arguments.length, 1); assert(ts.isStringLiteral(node.arguments[0]));
      kinds.push(node.arguments[0].text);
    }
    ts.forEachChild(node, collect);
  };
  collect(parsed);
  assert.deepEqual(kinds, ['publish', 'merge', 'git', 'git_merge', 'cancel']);
  assert(delivery.includes("const git = await context.createSource('git'); assert.equal(git.expectedGit, true)"));
  assert(delivery.includes("await finish(git, await apply(git), 'publish', files(git))"));
  assert(delivery.includes("await finish(git, await apply(git), 'no_op', files(git))"));
  assert(delivery.includes("const gitMerge = await context.createSource('git_merge'); assert.equal(gitMerge.expectedGit, true)"));
  assert(delivery.includes("await finish(gitMerge, await apply(gitMerge), 'merge', files(gitMerge, gitNote))"));
  assert(delivery.includes('sourceRunsQualifiedByOriginalFullVerifierReader: 5, actualModelPostsOnlyForSource: 10'));
  assert(owner.includes("const deliverySources = ['delivery_publish', 'delivery_merge', 'delivery_cancel', 'delivery_git', 'delivery_git_merge'] as const"));
  const ownerParsed = ts.createSourceFile('installed-node-journey.ts', owner, ts.ScriptTarget.Latest, true);
  const declaration = ownerParsed.statements.filter(ts.isVariableStatement).flatMap(node => [...node.declarationList.declarations])
    .find(node => ts.isIdentifier(node.name) && node.name.text === 'sourceBehavior');
  assert(declaration && declaration.initializer && ts.isArrowFunction(declaration.initializer));
  const behavior = declaration.initializer.body; assert(ts.isConditionalExpression(behavior));
  assert.equal(behavior.whenTrue.getText(ownerParsed), "'required_pass'");
  assert.equal(behavior.whenFalse.getText(ownerParsed), 'kind');
  for (const kind of kinds) assert(behavior.condition.getText(ownerParsed).includes(`kind === 'delivery_${kind}'`));
  assert(owner.includes("assert.equal(active.posts, sourceKind === 'ordinary_tools_cancel' ? 1 : kind === 'required_pass' ? 2 : kind === 'required_repair' ? 4 : 1)"));
  assert(owner.includes("assert(ordinal <= (sourceKind === 'ordinary_tools_cancel' ? 1 : kind === 'required_repair' ? 4 : kind === 'required_pass' ? 2 : 1), 'completed or unknown claims must not resend model requests')"));
  assert(delivery.includes('originalPublicationStopCase'));
});

test('the separate late cleanup binds all ten original source posts and still forbids any additional model request', () => {
  const owner = source('./installed-node-journey.ts');
  const start = owner.indexOf('cleanupCrash: async source => {'); assert(start >= 0);
  const cleanup = owner.slice(start, owner.indexOf('\n      }, options.publicationRetirementStop', start));
  const original = cleanup.indexOf('const originalPosts = postCount; if (lateDiagnostic) assert.equal(originalPosts, 10);');
  const unchanged = cleanup.indexOf('assert.equal(postCount, originalPosts);');
  assert(original >= 0 && unchanged > original);
  assert(cleanup.includes('redispatchCount: 0, additionalModelPosts: 0'));
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
  assert(stop.includes('assert.equal(postCount, 10); assert.equal(acceptedTcp, postCount); assert.equal(acceptedTls, postCount); assert(!responderFailure)'));
  assert(stop.includes('redispatchCount: 0, additionalModelPosts: 0'));
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
  assert(owner.includes('assert.equal(postCount, 10)'));
});
