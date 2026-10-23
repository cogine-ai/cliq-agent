// Qualification-only observation. This never creates installation or Run authority.
// After the workflow fetches baseline history and installs checkout dependencies:
// node scripts/kernel/testing/installed-status-regression.mjs OUTPUT/status-borrow-regression.json
// A successful expected RED here does not replace the candidate's Linux GREEN run.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, lstat, mkdir, mkdtemp, open, readFile, realpath, symlink } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const baseline = 'b6140b57836e19b0fb937327af449e8138f47eca';
const testRelative = 'src/state/installed-genesis.test.ts';
const testSha256 = '9b610c47d9887e3eb827d6d9c8c240b6cdaaef3d10a4fad021e70c0aee52a096';
const testName = 'installed Supervisor status completes its three full revalidations while an actual held borrow waits for its client response';
const assertionMessage = 'status must return before the waiting client can provide its external response';
const expectedCounts = Object.freeze({ tests: 1, suites: 0, passed: 0, failed: 1, cancelled: 0, skipped: 0, todo: 0, topLevel: 1 });
const reportSummary = Object.freeze({ tests: 1, suites: 0, passed: 0, failed: 1, cancelled: 0, skipped: 0, todo: 0 });
const refusal = () => new Error('fixed installed status regression evidence refused');
function requireValue(value) { if (!value) throw refusal(); }
function data(value, key) {
  if (!value || typeof value !== 'object') throw refusal();
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor && !Object.hasOwn(descriptor, 'value')) throw refusal();
  return descriptor?.value;
}

/** Decode actual Node reporter events; never retain messages, stacks or test output. */
export async function summarizeStatusRegression(source, testFile) {
  let failures = 0, fileSummaries = 0, finalSummaries = 0;
  for await (const event of source) {
    const type = data(event, 'type'), value = data(event, 'data');
    if (type === 'test:pass') throw refusal();
    if (type === 'test:fail') {
      requireValue(++failures === 1 && finalSummaries === 0);
      requireValue(data(value, 'name') === testName && data(value, 'file') === testFile);
      requireValue(data(value, 'nesting') === 0 && data(value, 'testNumber') === 1);
      requireValue(data(value, 'skip') === undefined && data(value, 'todo') === undefined);
      const details = data(value, 'details'), error = data(details, 'error'), cause = data(error, 'cause');
      // Node 22.13 omits this optional marker. The closed summary must still
      // prove exactly one top-level test and zero suites; explicit suites refuse.
      const detailsType = data(details, 'type');
      requireValue((detailsType === undefined || detailsType === 'test') && data(details, 'attempt') === undefined);
      requireValue(data(error, 'code') === 'ERR_TEST_FAILURE' && data(error, 'failureType') === 'testCodeFailure');
      requireValue(data(cause, 'code') === 'ERR_ASSERTION' && data(cause, 'name') === 'AssertionError');
      requireValue(data(cause, 'actual') === 'deadline' && data(cause, 'expected') === 'observed');
      requireValue(data(cause, 'operator') === 'strictEqual' && data(cause, 'generatedMessage') === false);
      const message = data(cause, 'message');
      requireValue(typeof message === 'string' && message.split('\n', 1)[0] === assertionMessage);
    } else if (type === 'test:summary') {
      requireValue(failures === 1 && finalSummaries === 0 && data(value, 'success') === false);
      const counts = data(value, 'counts');
      for (const [key, count] of Object.entries(expectedCounts)) requireValue(data(counts, key) === count);
      if (data(value, 'file') === testFile) requireValue(++fileSummaries === 1);
      else {
        requireValue(data(value, 'file') === undefined && fileSummaries === 1);
        finalSummaries++;
      }
    }
  }
  requireValue(failures === 1 && fileSummaries === 1 && finalSummaries === 1);
  return reportSummary;
}

// Node loads this fixed reporter outside the archived production source. Only
// the real runner's closed observation is forwarded, never raw stdout/stderr.
export default async function* reporter(source) {
  const summary = await summarizeStatusRegression(source, path.resolve(testRelative));
  yield `${JSON.stringify({ version: 1, summary })}\n`;
}

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

async function joined(command, args, cwd, capture = false) {
  const env = { ...process.env, PATH: `${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH ?? ''}` };
  const child = spawn(command, args, { cwd, env, stdio: ['ignore', capture ? 'pipe' : 'ignore', 'ignore'] });
  let spawnError = false, streamError = false, bytes = 0, overflow = false;
  const chunks = [];
  child.on('error', () => { spawnError = true; });
  if (capture) {
    child.stdout.on('error', () => { streamError = true; });
    child.stdout.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 4096) overflow = true;
      if (!overflow) chunks.push(chunk);
    });
  }
  // 'close', not a timer or the 'exit' event, joins the child and its pipes.
  const result = await new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
  requireValue(!spawnError && !streamError && !overflow && result.signal === null);
  return { code: result.code, output: Buffer.concat(chunks).toString('utf8') };
}

async function qualify(reportFile) {
  requireValue(process.platform === 'linux' && process.argv.length === 3);
  // Never discard inherited execution/security flags to obtain qualification.
  // Require the workflow's fixed, uninstrumented invocation instead.
  requireValue(process.execArgv.length === 0 && !process.env.NODE_OPTIONS && !process.env.NODE_V8_COVERAGE);
  const checkout = await realpath(fileURLToPath(new URL('../../..', import.meta.url)));
  const report = path.resolve(reportFile);
  requireValue(path.basename(report) === 'status-borrow-regression.json');
  const candidateTest = path.join(checkout, testRelative);
  requireValue(sha256(await readFile(candidateTest)) === testSha256);
  requireValue((await lstat(await realpath(path.join(checkout, 'node_modules')))).isDirectory());
  // Missing history is a workflow fetch prerequisite, not script-controlled network access.
  requireValue((await joined('git', ['cat-file', '-e', `${baseline}^{commit}`], checkout)).code === 0);
  const owned = await mkdtemp('/tmp/cliq-status-red-');
  const archive = path.join(owned, 'baseline.tar'), source = path.join(owned, 'source');
  await mkdir(source, { mode: 0o700 });
  requireValue((await joined('git', ['archive', '--format=tar', `--output=${archive}`, baseline], checkout)).code === 0);
  const baselineSourceSha256 = sha256(await readFile(archive));
  requireValue((await joined('tar', ['-xf', archive, '-C', source], checkout)).code === 0);
  // Baseline scripts only read dependencies; all emitted source/helper files
  // belong to this new archive. Never run npm ci or build in the live checkout.
  await symlink(await realpath(path.join(checkout, 'node_modules')), path.join(source, 'node_modules'), 'dir');
  requireValue((await joined('npm', ['--logs-max=0', '--loglevel=silent',
    `--logs-dir=${path.join(owned, 'npm-logs')}`, 'run', 'build'], source)).code === 0);
  await copyFile(candidateTest, path.join(source, testRelative));
  requireValue(sha256(await readFile(path.join(source, testRelative))) === testSha256);
  const pattern = `^${testName.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')}$`;
  const observed = await joined(process.execPath, ['--test', '--test-concurrency=1', '--import', 'tsx',
    `--test-name-pattern=${pattern}`, `--test-reporter=${fileURLToPath(import.meta.url)}`, testRelative], source, true);
  requireValue(observed.code === 1);
  // Exact, bounded, closed reporter output: no extra fields or raw test logs.
  requireValue(observed.output === `${JSON.stringify({ version: 1, summary: reportSummary })}\n`);
  requireValue(sha256(await readFile(candidateTest)) === testSha256);
  const evidence = { version: 1, baseline, baselineSourceSha256, testSha256,
    driverSha256: sha256(await readFile(fileURLToPath(import.meta.url))),
    platform: process.platform, arch: process.arch, nodeVersion: process.version,
    fixedExpectedFailureObserved: true, deadlineMs: 5000, summary: reportSummary };
  // Refuse overwrite. Leave the archive and every pre-existing evidence file in place.
  const output = await open(report, 'wx', 0o600);
  try { await output.writeFile(`${JSON.stringify(evidence, null, 2)}\n`); await output.sync(); }
  finally { await output.close(); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { await qualify(process.argv[2]); }
  catch { console.error('Installed status regression qualification refused; no RED evidence was accepted.'); process.exitCode = 1; }
}
