// Pure reporter-data regression, not installed Linux or timing qualification.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { summarizeStatusRegression } from './installed-status-regression.mjs';

const name = 'installed Supervisor status completes its three full revalidations while an actual held borrow waits for its client response';
const message = 'status must return before the waiting client can provide its external response';
const file = '/tmp/cliq-status-red-fixed/source/src/state/installed-genesis.test.ts';
const counts = { tests: 1, suites: 0, passed: 0, failed: 1, cancelled: 0, skipped: 0, todo: 0, topLevel: 1 };

test('the baseline qualification consumes its exact historical fixture, independently of the evolving candidate test', async () => {
  const driver = await readFile(new URL('./installed-status-regression.mjs', import.meta.url), 'utf8');
  const selected = driver.match(/const qualificationFixtureRelative = '([^']+)';/u);
  assert(selected, 'the pinned baseline must not consume the evolving candidate installation fixture');
  assert.equal(selected[1], 'scripts/kernel/testing/fixtures/installed-status-5ad50f3.ts.fixture');
  const bytes = await readFile(new URL('../../../' + selected[1], import.meta.url));
  assert.equal(bytes.length, 16265);
  assert.equal(createHash('sha256').update(bytes).digest('hex'),
    '9b610c47d9887e3eb827d6d9c8c240b6cdaaef3d10a4fad021e70c0aee52a096');
  assert.equal(createHash('sha1').update(Buffer.from('blob 16265\0')).update(bytes).digest('hex'),
    '01571738ea145c92600ea4bd2190d7389e189b7b');
  assert(driver.includes("const baseline = 'b6140b57836e19b0fb937327af449e8138f47eca'"));
  assert(driver.includes('const qualificationFixture = path.join(checkout, qualificationFixtureRelative)'));
  assert(driver.includes('await copyFile(qualificationFixture, path.join(source, testRelative))'));
  assert.equal((driver.match(/sha256\(await readFile\(qualificationFixture\)\) === testSha256/gu) ?? []).length, 2,
    'original before/after source-byte checks stay around the complete joined baseline run');
});
function events() {
  const cause = Object.assign(new Error(`${message}\n+ actual - expected\n\n+ 'deadline'\n- 'observed'\n`), {
    name: 'AssertionError', code: 'ERR_ASSERTION', actual: 'deadline', expected: 'observed',
    operator: 'strictEqual', generatedMessage: false,
  });
  return [
    { type: 'test:fail', data: { name, file, nesting: 0, testNumber: 1,
      details: { type: 'test', duration_ms: 5010, error: Object.assign(new Error('test failed'), {
        code: 'ERR_TEST_FAILURE', failureType: 'testCodeFailure', cause,
      }) } } },
    { type: 'test:summary', data: { file, counts: { ...counts }, duration_ms: 5020, success: false } },
    { type: 'test:summary', data: { file: undefined, counts: { ...counts }, duration_ms: 5030, success: false } },
  ];
}
async function* stream(values) { yield* values; }

test('only the original fixed deadline assertion and closed single-failure summary qualify as RED', async () => {
  assert.deepEqual(await summarizeStatusRegression(stream(events()), file), {
    tests: 1, suites: 0, passed: 0, failed: 1, cancelled: 0, skipped: 0, todo: 0,
  });
});

test('Node 22.13 optional details.type still requires the exact assertion and zero suites', async () => {
  const values = events(); delete values[0].data.details.type;
  assert.deepEqual(await summarizeStatusRegression(stream(values), file), {
    tests: 1, suites: 0, passed: 0, failed: 1, cancelled: 0, skipped: 0, todo: 0,
  });
  for (const type of ['suite', 'another type', null, 0]) {
    const invalid = events(); invalid[0].data.details.type = type;
    await assert.rejects(summarizeStatusRegression(stream(invalid), file), /evidence refused/u);
  }
  const suite = events(); delete suite[0].data.details.type;
  suite[1].data.counts.suites = 1; suite[2].data.counts.suites = 1;
  await assert.rejects(summarizeStatusRegression(stream(suite), file), /evidence refused/u);
});

test('missing API, platform refusal, another assertion, retries and non-unique failures never count as RED', async () => {
  const changes = [
    values => { values[0].data.name = 'test file import failed'; },
    values => { values[0].data.file = '/tmp/another-test.ts'; },
    values => { values[0].data.nesting = 1; },
    values => { values[0].data.testNumber = 2; },
    values => { values[0].data.skip = true; },
    values => { values[0].data.todo = true; },
    values => { values[0].data.details.type = 'suite'; },
    values => { values[0].data.details.attempt = 1; },
    values => { values[0].data.details.error.code = 'ERR_MODULE_NOT_FOUND'; },
    values => { values[0].data.details.error.failureType = 'cancelledByParent'; },
    values => { values[0].data.details.error.cause.code = 'EXECUTION_UNAVAILABLE'; },
    values => { values[0].data.details.error.cause.name = 'Error'; },
    values => { values[0].data.details.error.cause.actual = 'native helper unavailable'; },
    values => { values[0].data.details.error.cause.expected = 'another result'; },
    values => { values[0].data.details.error.cause.operator = 'notStrictEqual'; },
    values => { values[0].data.details.error.cause.generatedMessage = true; },
    values => { values[0].data.details.error.cause.message = `another assertion\n${message}`; },
    values => { values.unshift(values[0]); },
    values => { values.unshift({ type: 'test:pass', data: { name, file } }); },
  ];
  for (const change of changes) {
    const values = events(); change(values);
    await assert.rejects(summarizeStatusRegression(stream(values), file), /evidence refused/u);
  }
});

test('every original summary count and both closed summaries are required', async () => {
  for (const index of [1, 2]) for (const key of Object.keys(counts)) {
    const values = events(); values[index].data.counts[key]++;
    await assert.rejects(summarizeStatusRegression(stream(values), file), /evidence refused/u);
  }
  for (const values of [[], events().slice(0, 1), events().slice(0, 2),
    [events()[0], events()[2]], [...events(), events()[2]],
    [events()[0], events()[1], events()[1], events()[2]]]) {
    await assert.rejects(summarizeStatusRegression(stream(values), file), /evidence refused/u);
  }
  for (const index of [1, 2]) {
    const values = events(); values[index].data.success = true;
    await assert.rejects(summarizeStatusRegression(stream(values), file), /evidence refused/u);
  }
});

test('raw stdout and stderr cannot impersonate a runner failure and their contents are never read', async () => {
  let read = 0;
  const raw = () => ({ get message() { read++; throw new Error('must not read raw output'); } });
  assert.deepEqual(await summarizeStatusRegression(stream([
    { type: 'test:stdout', data: raw() }, { type: 'test:stderr', data: raw() }, ...events(),
  ]), file), { tests: 1, suites: 0, passed: 0, failed: 1, cancelled: 0, skipped: 0, todo: 0 });
  await assert.rejects(summarizeStatusRegression(stream([
    { type: 'test:stdout', data: { message: JSON.stringify(events()) } }, ...events().slice(1),
  ]), file), /evidence refused/u);
  assert.equal(read, 0);
});

test('accessor evidence is refused without evaluating it', async () => {
  let read = 0;
  const values = events();
  Object.defineProperty(values[0].data.details.error.cause, 'actual', {
    get() { read++; return 'deadline'; },
  });
  await assert.rejects(summarizeStatusRegression(stream(values), file), /evidence refused/u);
  assert.equal(read, 0);
});
