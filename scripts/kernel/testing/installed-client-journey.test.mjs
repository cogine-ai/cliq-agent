// Consumer wiring only, not installed/native qualification. The real Linux
// campaigns must independently prove every retained execution assertion.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const journey = readFileSync(new URL('../qualify-installed-run-journey.ts', import.meta.url), 'utf8');
const verifier = readFileSync(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
const clientBuild = readFileSync(new URL('./installed-client-build.ts', import.meta.url), 'utf8');
const upgrade = readFileSync(new URL('./installed-upgrade-journey.ts', import.meta.url), 'utf8');
const upgradeBuild = readFileSync(new URL('./installed-upgrade-build.ts', import.meta.url), 'utf8');
const driver = readFileSync(new URL('./installed-control-client-driver.ts', import.meta.url), 'utf8');
const matches = (text, pattern) => assert(pattern.test(text), 'fixed genuine installed consumer wiring missing: ' + pattern.source);

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
    matches(text, schema3
      ? /args: \[\.\.\.prefix, process\.execPath, '--disable-warning=ExperimentalWarning', installedClientDriver, filename,\s*genuineTransport === 'rpc' \? '--schema3-rpc' : '--schema3'\]/u
      : /args: \[\.\.\.prefix, process\.execPath, '--disable-warning=ExperimentalWarning', installedClientDriver, filename\]/u);
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
