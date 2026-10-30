// Consumer wiring only, not installed/native qualification. The real Linux
// campaigns must independently prove every retained execution assertion.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const journey = readFileSync(new URL('../qualify-installed-run-journey.ts', import.meta.url), 'utf8');
const verifier = readFileSync(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
const clientBuild = readFileSync(new URL('./installed-client-build.ts', import.meta.url), 'utf8');
const upgrade = readFileSync(new URL('./installed-upgrade-journey.ts', import.meta.url), 'utf8');
const upgradeBuild = readFileSync(new URL('./installed-upgrade-build.ts', import.meta.url), 'utf8');
const driver = readFileSync(new URL('./installed-control-client-driver.ts', import.meta.url), 'utf8');
const packageBuild = readFileSync(new URL('./installed-supervisor-package.ts', import.meta.url), 'utf8');
const matches = (text, pattern) => assert(pattern.test(text), 'fixed genuine installed consumer wiring missing: ' + pattern.source);
const selectConditional = (source, expression, condition, enabled) => {
  while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)) expression = expression.expression;
  assert(ts.isConditionalExpression(expression)); assert.equal(expression.condition.getText(source), condition);
  return enabled ? expression.whenTrue : expression.whenFalse;
};

test('schema7 and schema8 upgrade clients explicitly select the signed schema3 contract in both directions', () => {
  // Static call-site wiring only. The real old/new Linux installations still
  // have to authenticate and complete both original upgrade Runs themselves.
  matches(upgradeBuild, /const old = await buildInstalledSupervisorPackage\([^;]*headlessSchemaVersion: 3/u);
  matches(upgradeBuild, /const target = await buildInstalledSupervisorPackage\([^;]*headlessSchemaVersion: 3/u);
  matches(driver, /openInstalledSupervisorClient\(selected, schema === undefined \? 1 : 3\)/u);
  matches(upgrade, /const connect = async \(stage: 0 \| 1\) => openInstalledClientConsumer\(\{ executable: '\/usr\/sbin\/runuser', args: \[\.\.\.prefix, process\.execPath,\s*'--disable-warning=ExperimentalWarning', packages\.clients\[stage\]!, filename, '--schema3'\], cwd: ledger\.home, env: environment,\s*headlessSchemaVersion: 3, openScan: \(\) => scanner\.openStream\(\), onJoined: \(\) => \{\} \}\)/u);
});

test('the complete ordinary installed journey sends initial admission and terminal delivery through the genuine client', () => {
  matches(journey, /import \{ InstalledClientConsumerDeadlineError, InstalledClientDriverError, openInstalledClientConsumer \} from '\.\/testing\/installed-client-consumer\.js'/u);
  matches(journey, /const sessionReply = mode === '--campaign' \? await sendGenuine\(sessionRequest\)/u);
  matches(journey, /const submitReply = mode === '--campaign' \? await sendGenuine\(submit\)/u);
  matches(journey, /const events = accepted\(await sendGenuine\(\{ protocolVersion: 1, method: 'run\.attach'/u);
  matches(journey, /await assertGenuineResult\(cut\)/u);
  matches(journey, /await closeGenuineClient\(\);\s*genuineTransport = 'rpc';\s*assert\.deepEqual\(accepted\(await sendGenuine/u);
  matches(journey, /actual_supervisor_restart_after_result[\s\S]*await closeGenuineClient\(\);[\s\S]*selectedSupervisor[\s\S]*await assertGenuineResult\(cut, recoverBy - Date\.now\(\)\)/u);
  const download = journey.slice(journey.indexOf('    const assertGenuineResult = '), journey.indexOf('    const assertTerminalCancelRefused = '));
  const deadline = download.indexOf('by = performance.now() + timeout');
  const firstRead = download.indexOf('await readCas(');
  assert(deadline >= 0 && firstRead > deadline, 'the original whole-download deadline includes its first CAS read');
  matches(download, /await sendGenuine\(\{ protocolVersion: 1, method: 'artifact\.get'[^\n]*remaining\(\)\)/u);
});

test('both real installed workloads bundle the production driver and join its scanned child before corpus qualification', () => {
  for (const [text, schema3] of [[journey, true], [verifier, false]]) {
    if (schema3) {
      matches(text, /new URL\('\.\/testing\/installed-control-client-driver\.ts', import\.meta\.url\)/u);
      matches(text, /\.\.\.installedClientBuildOptions\(\)/u);
    } else {
      matches(text, /import \{ buildInstalledClientDriver \} from '\.\/installed-client-build\.js'/u);
      matches(text, /await writeFile\(installedClientDriver, await buildInstalledClientDriver\(installedClientDriver\), \{ flag: 'wx', mode: 0o444 \}\)/u);
      matches(clientBuild, /new URL\('\.\/installed-control-client-driver\.ts', import\.meta\.url\)/u);
      matches(clientBuild, /\.\.\.installedClientBuildOptions\(\)/u);
      matches(clientBuild, /assert\(bytes\.length > 0 && bytes\.length <= 16 \* 1024 \* 1024\)/u);
    }
    if (schema3) matches(text,
      /args: \[\.\.\.prefix, process\.execPath, '--disable-warning=ExperimentalWarning', installedClientDriver, filename,\s*genuineTransport === 'rpc' \? '--schema3-rpc' : '--schema3'\]/u);
    if (schema3) {
      matches(text, /headlessSchemaVersion: 3/u);
      matches(text, /mode === '--campaign' \? \{ headlessSchemaVersion: 3 \} : \{\}/u);
      matches(text, /await closeGenuineClient\(\);\s*genuineTransport = 'rpc';\s*assert\.deepEqual\(accepted\(await sendGenuine/u);
      matches(text, /genuineTransport === 'rpc' \? \{ headlessTransport: 'rpc' as const \} : \{\}/u);
      matches(text, /decodeInstalledControlResponse\(exchangeFrames\(\[oldHello\]\)\[0\], oldHello\)/u);
      matches(text, /supportedHeadlessRange: \{ min: 3, max: 3 \}, upgradeAction: 'upgrade_client'/u);
      matches(text, /report\.oldHeadlessRangeRefused = true/u);
    }
    assert(!/--no-warnings|NODE_NO_WARNINGS/u.test(text), 'never silence arbitrary warnings or stderr');
    matches(text, /openScan: \(\) => scanner\.openStream\(\)/u);
    matches(text, /metafile: true, write: false/u);
    matches(text, /external && value\.path\.startsWith\('node:'\)/u);
  }
  matches(clientBuild, /external && value\.path\.startsWith\('node:'\)/u);
  const cleanup = journey.slice(journey.indexOf('  } catch (error) {', journey.indexOf('report.closedBrokerProcessDomainDeath')));
  assert(cleanup.indexOf('await closeGenuineClient()') >= 0);
  assert(cleanup.indexOf('await closeGenuineClient()') < cleanup.indexOf('scanCredentialSecretCorpus'));
  assert(!/net\.createConnection/u.test(verifier), 'the verifier journey is a real consumer, not another raw socket client');
});

test('old verifier and delivery keep schema1 while provider and normal daily clients match their signed schema3 packages', () => {
  const source = ts.createSourceFile('installed-node-journey.ts', verifier, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const calls = [];
  const visit = node => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'openInstalledClientConsumer') calls.push(node);
    ts.forEachChild(node, visit);
  };
  visit(source); assert.equal(calls.length, 1);
  const options = calls[0].arguments[0]; assert(ts.isObjectLiteralExpression(options));
  const args = options.properties.find(property => ts.isPropertyAssignment(property) && property.name.getText(source) === 'args');
  assert(args && ts.isArrayLiteralExpression(args.initializer));
  const elements = args.initializer.elements;
  assert.equal(elements.length, 6);
  assert.deepEqual(elements.slice(0, 5).map(value => value.getText(source)),
    ['...prefix', 'process.execPath', "'--disable-warning=ExperimentalWarning'", 'installedClientDriver', 'filename']);
  assert(ts.isSpreadElement(elements[5]));
  const framing = options.properties.filter(property => ts.isSpreadAssignment(property) && property.expression.getText(source).includes('headlessSchemaVersion'));
  assert.equal(framing.length, 1);
  const select = (expression, schema3) => selectConditional(source, expression, 'options.provider || dailyJourney', schema3);
  matches(driver, /schema === undefined \|\| schema === '--schema3' \|\| schema === '--schema3-rpc'/u);
  matches(driver, /openInstalledSupervisorClient\(selected, schema === undefined \? 1 : 3\)/u);
  matches(verifier, /\.\.\.\(dailyJourney \? \{ headlessSchemaVersion: 3 as const \} : \{\}\)/u);
  matches(packageBuild, /headlessSchemaRange: \{ min: options\.headlessSchemaVersion \?\? 1, max: options\.headlessSchemaVersion \?\? 1 \}/u);
  matches(packageBuild, /\{ \.\.\.options, providerModel: definition, headlessSchemaVersion: 3, guestToolchain: 'node-test-v1' \}/u);
  for (const [kind, provider, daily] of [['verifier', false, false], ['delivery', false, false], ['provider', true, false], ['daily', false, true]]) {
    const schema3 = provider || daily;
    const selectedArgs = select(elements[5].expression, schema3); assert(ts.isArrayLiteralExpression(selectedArgs));
    assert.deepEqual(selectedArgs.elements.map(value => { assert(ts.isStringLiteral(value)); return value.text; }), schema3 ? ['--schema3'] : [], kind);
    const selectedConsumer = select(framing[0].expression, schema3); assert(ts.isObjectLiteralExpression(selectedConsumer));
    const schema = selectedConsumer.properties.find(property => ts.isPropertyAssignment(property) && property.name.getText(source) === 'headlessSchemaVersion');
    assert.equal(selectedConsumer.properties.length, schema3 ? 1 : 0, kind);
    if (schema3) {
      assert(schema); let value = schema.initializer; while (ts.isAsExpression(value)) value = value.expression;
      assert(ts.isNumericLiteral(value)); assert.equal(value.text, '3', kind);
    } else assert.equal(schema, undefined, kind);
  }
});

test('only the original client campaign adds its complete private-data scan after all original writers join', () => {
  const source = ts.createSourceFile('qualify-installed-run-journey.ts', journey, ts.ScriptTarget.Latest, true), calls = [];
  const visit = node => { if (ts.isCallExpression(node)) calls.push(node); ts.forEachChild(node, visit); };
  visit(source);
  const named = name => calls.filter(node => ts.isIdentifier(node.expression) && node.expression.text === name);
  const scans = named('scanCredentialSecretCorpus'); assert.equal(scans.length, 1);
  const scan = scans[0]; assert.equal(scan.arguments.length, 1);
  const options = scan.arguments[0]; assert(ts.isObjectLiteralExpression(options));
  assert.equal(options.properties.length, 5);
  assert.deepEqual(options.properties.slice(0, 4).map(property => property.getText(source)),
    ['stateRoot: recipe.stateRoot', 'uid: ledger.uid', 'evidenceDirs: []', 'scanner']);
  const extra = options.properties[4]; assert(ts.isSpreadAssignment(extra));
  const condition = "mode === '--campaign'";
  for (const enabled of [false, true]) {
    const selected = selectConditional(source, extra.expression, condition, enabled); assert(ts.isObjectLiteralExpression(selected));
    assert.deepEqual(selected.properties.map(property => property.getText(source)), enabled ? ['scanInstalledClientData: true as const'] : []);
  }
  let statement = scan;
  while (!ts.isExpressionStatement(statement)) { assert(statement.parent); statement = statement.parent; }
  const block = statement.parent; assert(ts.isBlock(block));
  const index = block.statements.indexOf(statement); assert(index >= 3);
  assert.deepEqual(block.statements.slice(index - 3, index).map(node => node.getText(source)),
    ['assert.equal(report.installedWritersJoined, true);', 'assert.equal(report.httpsJoined, true);', 'assert.equal(report.daemonJoined, true);']);
  assert.equal(block.statements[index + 1].getText(source), 'assert.equal(report.secretCorpus.sqliteDatabasesScanned, 2);');
  const evidence = block.statements[index + 2]; assert(ts.isExpressionStatement(evidence) && ts.isCallExpression(evidence.expression));
  assert.equal(evidence.expression.expression.getText(source), 'assert.equal');
  assert.equal(evidence.expression.arguments.length, 2);
  assert.equal(evidence.expression.arguments[0].getText(source), 'report.secretCorpus.evidenceDirectoriesScanned');
  assert.equal(selectConditional(source, evidence.expression.arguments[1], condition, true).getText(source), '1');
  assert.equal(selectConditional(source, evidence.expression.arguments[1], condition, false).getText(source), '0');
  const complete = block.statements[index + 3]; assert(ts.isIfStatement(complete) && !complete.elseStatement);
  assert.equal(complete.expression.getText(source), condition);
  assert.equal(complete.thenStatement.getText(source), 'assert.equal(report.secretCorpus.installedClientDataScanned, true);');
  const scanners = named('createCredentialSecretScanner'); assert.equal(scanners.length, 1);
  assert.equal(scanners[0].arguments[0].getText(source), '[secret, password]');
  const limits = scanners[0].arguments[1]; assert(ts.isObjectLiteralExpression(limits));
  assert.deepEqual(limits.properties.map(property => property.getText(source)), ['maxBytes: 512 * 1024 * 1024', 'maxStreams: 4096']);
  const clients = named('qualifyInstalledClientApplications'); assert.equal(clients.length, 1);
  let clientScope = clients[0].parent;
  while (clientScope && !ts.isIfStatement(clientScope)) clientScope = clientScope.parent;
  assert(clientScope && clientScope.expression.getText(source) === condition && !clientScope.elseStatement);
  const clientOptions = clients[0].arguments[0]; assert(ts.isObjectLiteralExpression(clientOptions));
  const scanned = clientOptions.properties.find(property => ts.isPropertyAssignment(property) && property.name.getText(source) === 'openScan');
  assert(scanned && scanned.initializer.getText(source) === '() => scanner.openStream()');
});

test('both existing free Linux jobs require driver lifecycle and whole-journey consumer regressions', () => {
  const workflow = readFileSync(new URL('../../../.github/workflows/kernel-foundation.yml', import.meta.url), 'utf8');
  for (const name of ['linux-installed-run', 'linux-installed-verifier']) {
    const start = workflow.indexOf('  ' + name + ':\n'); assert(start >= 0);
    const next = /\n  [a-z][a-z0-9-]*:/u.exec(workflow.slice(start + 1));
    const job = workflow.slice(start, next ? start + 1 + next.index : undefined);
    matches(job, /timeout-minutes:\s*20/u);
    matches(job, /node --test[^\n]*installed-client-journey\.test\.mjs/u);
    matches(job, /node --test --import tsx[^\n]*installed-client-consumer\.test\.ts/u);
    matches(job, /node --test --import tsx[^\n]*installed-control-client-driver\.test\.ts/u);
  }
});
