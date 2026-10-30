// ELF bytes only. These values are not executable images, loader acceptance,
// signatures, installed runtime authority or evidence of a READY deadline.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

async function compare(original: Buffer, candidate: Buffer, mode: 'debug' | 'static' = 'static') {
  const module = await import('./supervisor-carrier-layout.js').catch(() => undefined);
  assert.equal(typeof module?.compareSupervisorCarrierLayout, 'function', 'the experiment must compare the preserved ELF layout before execution');
  return module!.compareSupervisorCarrierLayout(original, candidate, mode);
}
function fixture(stripped: boolean): Buffer {
  const names = stripped ? ['', '.text', '.note.test', '.dynamic', '.shstrtab']
    : ['', '.text', '.note.test', '.dynamic', '.debug_info', '.symtab', '.strtab', '.shstrtab'];
  const strings = Buffer.from(names.join('\0') + '\0'), shoff = stripped ? 512 : 640;
  const bytes = Buffer.alloc(shoff + names.length * 64);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  bytes.writeUInt16LE(2, 16); bytes.writeUInt16LE(62, 18); bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(256n, 24); bytes.writeBigUInt64LE(64n, 32); bytes.writeBigUInt64LE(BigInt(shoff), 40);
  bytes.writeUInt16LE(64, 52); bytes.writeUInt16LE(56, 54); bytes.writeUInt16LE(3, 56);
  bytes.writeUInt16LE(64, 58); bytes.writeUInt16LE(names.length, 60); bytes.writeUInt16LE(names.length - 1, 62);
  for (const [index, type, offset, length, flags] of [[0, 1, 0, 448, 5], [1, 4, 384, 32, 4], [2, 2, 416, 32, 6]]) {
    const at = 64 + index! * 56;
    bytes.writeUInt32LE(type!, at); bytes.writeUInt32LE(flags!, at + 4);
    bytes.writeBigUInt64LE(BigInt(offset!), at + 8); bytes.writeBigUInt64LE(BigInt(0x400000 + offset!), at + 16);
    bytes.writeBigUInt64LE(BigInt(0x400000 + offset!), at + 24);
    bytes.writeBigUInt64LE(BigInt(length!), at + 32); bytes.writeBigUInt64LE(BigInt(length!), at + 40);
    bytes.writeBigUInt64LE(type === 1 ? 4096n : 8n, at + 48);
  }
  bytes.fill(0x11, 256, 384); bytes.fill(0x22, 384, 416); bytes.fill(0x33, 416, 448);
  bytes.write('NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2:0', 264, 'ascii');
  const stringOffset = stripped ? 448 : 528; strings.copy(bytes, stringOffset);
  const layout: Record<string, [number, number, number, number]> = {
    '.text': [1, 6, 256, 128], '.note.test': [7, 2, 384, 32], '.dynamic': [6, 3, 416, 32],
    '.debug_info': [1, 0, 448, 32], '.symtab': [2, 0, 480, 24], '.strtab': [3, 0, 504, 24],
    '.shstrtab': [3, 0, stringOffset, strings.length],
  };
  for (const [index, name] of names.entries()) {
    if (!index) continue;
    const at = shoff + index * 64, [type, flags, offset, length] = layout[name]!;
    bytes.writeUInt32LE(strings.indexOf(Buffer.from(name + '\0')), at);
    bytes.writeUInt32LE(type, at + 4); bytes.writeBigUInt64LE(BigInt(flags), at + 8);
    bytes.writeBigUInt64LE(BigInt(flags & 2 ? 0x400000 + offset : 0), at + 16);
    bytes.writeBigUInt64LE(BigInt(offset), at + 24); bytes.writeBigUInt64LE(BigInt(length), at + 32);
    bytes.writeBigUInt64LE(1n, at + 48);
  }
  return bytes;
}

test('a smaller experimental carrier preserves all LOAD, notes, dynamic bytes and the SEA fuse', async () => {
  const result = await compare(fixture(false), fixture(true));
  assert.equal(result.originalByteCount, 1152);
  assert.equal(result.candidateByteCount, 832);
  assert.equal(result.savedBytes, 320);
  assert.equal(result.unchangedLoadBytes, 448);
  assert.equal(result.structureOnly, true);
  assert.deepEqual(result.removedSections, ['.debug_info', '.symtab', '.strtab']);
  assert(Object.isFrozen(result) && Object.isFrozen(result.removedSections));
});

test('fixed structural failure stages preserve rejection and cannot be replaced by a throwing observer', async () => {
  const { compareSupervisorCarrierLayout } = await import('./supervisor-carrier-layout.js');
  const original = fixture(false), candidate = fixture(true);
  candidate[384] = candidate[384]! ^ 1;
  const stages: string[] = [], observerFailure = new Error('observer is not a structural result');
  let caught: unknown;
  try {
    compareSupervisorCarrierLayout(original, candidate, 'static', stage => {
      stages.push(stage); throw observerFailure;
    });
  } catch (error) { caught = error; }
  assert(caught instanceof assert.AssertionError, 'the unchanged structural assertion must still reject');
  assert.notEqual(caught, observerFailure, 'observer failure may not replace the original structural rejection');
  assert.equal(caught.message, 'carrier LOAD, interpreter, notes or dynamic extent changed');
  assert.equal(stages.at(-1), 'runtime_extent', 'the failure must retain only a fixed structural stage');
});

test('a throwing stage observer cannot alter a successful structural result or the closed stage vocabulary', async () => {
  const { compareSupervisorCarrierLayout } = await import('./supervisor-carrier-layout.js');
  const original = fixture(false), candidate = fixture(true), observed: string[] = [];
  const expected = compareSupervisorCarrierLayout(original, candidate, 'static');
  const actual = compareSupervisorCarrierLayout(original, candidate, 'static', stage => {
    observed.push(stage); throw new Error('untrusted observer details must not become a result');
  });
  assert.deepEqual(actual, expected, 'all original result fields must remain identical');
  assert.deepEqual([...new Set(observed)], ['original_format', 'candidate_format', 'size_reduction',
    'runtime_headers', 'runtime_extent', 'retained_section_shape', 'retained_section_size',
    'retained_section_bytes', 'removable_metadata', 'section_set', 'debug_removal', 'static_removal']);
  assert(Object.isFrozen(actual) && Object.isFrozen(actual.removedSections), 'the original immutable result remains unchanged');
});

// Execute only the actual experiment's pure comparison/catch or argv AST. No
// strip process, executable or installation authority is manufactured here.
async function experimentLoop() {
  const source = await readFile(new URL('../qualify-supervisor-carrier-size.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('experiment.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  let loop: ts.ForOfStatement | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isForOfStatement(node) && node.expression.getText(parsed) === "[['debug', '--strip-debug'], ['static', '--strip-all']] as const") loop = node;
    ts.forEachChild(node, visit);
  };
  visit(parsed);
  assert(loop && ts.isBlock(loop.statement), 'the two fixed experiment modes must remain explicit');
  return { parsed, body: loop.statement };
}

test('only a failed static row retains a fixed structural stage and rethrows the identical assertion', async () => {
  const { parsed, body } = await experimentLoop();
  const index = body.statements.findIndex(statement => ts.isTryStatement(statement) && statement.tryBlock.getText(parsed).includes('compareSupervisorCarrierLayout('));
  assert(index > 0, 'the original comparison needs a contained failure-only diagnostic catch');
  const variable = body.statements[index - 1]!, block = body.statements[index]!;
  assert(ts.isVariableStatement(variable) && ts.isTryStatement(block), 'only comparison-local stage state may enter this seam');
  const emitted = ts.transpileModule(variable.getText(parsed) + '\n' + block.getText(parsed),
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const execute = new Function('compareSupervisorCarrierLayout', 'row', 'original', 'selected', 'mode', emitted);
  const { compareSupervisorCarrierLayout: realCompare } = await import('./supervisor-carrier-layout.js');
  for (const mode of ['debug', 'static'] as const) {
    const broken = fixture(true); broken[384] = broken[384]! ^ 1;
    const row: Record<string, unknown> = { structureVerified: false }, original = { bytes: fixture(false) };
    let originalError: unknown, calls = 0;
    const observed: typeof realCompare = (...args) => {
      calls++;
      try { return realCompare(...args); } catch (error) { originalError = error; throw error; }
    };
    assert.throws(() => execute(observed, row, original, { bytes: broken }, mode), error => error === originalError,
      'the failure-only report must rethrow the original comparison object');
    assert.equal(calls, 1, 'diagnostics may not rerun comparison');
    assert.deepEqual(Object.keys(row).sort(), mode === 'static' ? ['structureFailureStage', 'structureVerified'] : ['structureVerified']);
    assert.equal(row.structureFailureStage, mode === 'static' ? 'runtime_extent' : undefined);
    assert.equal(row.structureVerified, false, 'diagnostics cannot mark failure as verified');
    const success: Record<string, unknown> = { structureVerified: false };
    execute(realCompare, success, original, { bytes: fixture(true) }, mode);
    assert.equal(success.structureVerified, true);
    assert.equal(Object.hasOwn(success, 'structureFailureStage'), false, 'success rows retain their original closed shape');
  }
});

test('both fixed GNU strip modes explicitly preserve all original notes rather than merging them', async () => {
  const { parsed, body } = await experimentLoop();
  const calls = body.statements.filter(ts.isExpressionStatement).map(statement => statement.expression)
    .filter((expression): expression is ts.CallExpression => ts.isCallExpression(expression) && expression.expression.getText(parsed) === 'run' && expression.arguments[0]?.getText(parsed) === 'strip');
  assert.equal(calls.length, 1, 'the existing single strip invocation must remain the only producer');
  const args = calls[0]!.arguments[1]!;
  assert(ts.isArrayLiteralExpression(args), 'the experiment uses only a fixed argv literal');
  const actualArgs = new Function('option', 'candidate', 'return (' + args.getText(parsed) + ');');
  for (const option of ['--strip-debug', '--strip-all'])
    assert.deepEqual(actualArgs(option, '/owned/never-executed-copy'),
      [option, '--no-merge-notes', '--', '/owned/never-executed-copy'], 'primary mode must not rewrite retained SHT_NOTE bytes');
});

test('unchanged copies and every runtime byte or runtime header mutation fail before execution', async () => {
  const original = fixture(false);
  await assert.rejects(compare(original, Buffer.from(original)), /actually reduce/u);
  for (const offset of [24, 32, 54, 56, 64 + 4, 64 + 8, 256, 384, 416]) {
    const candidate = fixture(true); candidate[offset] = candidate[offset]! ^ 1;
    await assert.rejects(compare(original, candidate), { name: 'AssertionError' }, 'runtime mutation must never pass the structural gate');
  }
  const fuse = fixture(true); fuse[264 + 44] = 0x31;
  await assert.rejects(compare(original, fuse), /fuse|extent changed/u);
});

test('truncated, foreign, oversized-table and malformed section data are rejected', async () => {
  const original = fixture(false);
  for (const candidate of [Buffer.alloc(0), fixture(true).subarray(0, 63), fixture(true).subarray(0, 700)])
    await assert.rejects(compare(original, candidate), { name: 'AssertionError' });
  for (const [offset, width, value] of [[18, 2, 183], [56, 2, 65], [60, 2, 513], [62, 2, 0], [58, 2, 0]]) {
    const candidate = fixture(true); candidate.writeUIntLE(value!, offset!, width!);
    await assert.rejects(compare(original, candidate), { name: 'AssertionError' });
  }
  const outOfFile = fixture(true); outOfFile.writeBigUInt64LE(0xffffffffffffffffn, 40);
  await assert.rejects(compare(original, outOfFile), { name: 'AssertionError' });
  const duplicate = fixture(true); duplicate.writeUInt32LE(1, 512 + 2 * 64);
  await assert.rejects(compare(original, duplicate), /identities/u);
  const renamed = fixture(true); renamed.write('.badx', 449, 'ascii');
  await assert.rejects(compare(original, renamed), /retained/u);
  const highBit = fixture(true); highBit[449] = 0xae;
  await assert.rejects(compare(original, highBit), /ASCII/u, 'high-bit section names must not alias ASCII identifiers');
});

test('metadata removal may never remove a non-LOAD note or mark original removable metadata as runtime data', async () => {
  const original = fixture(false), renamed = Buffer.from(original);
  const at = renamed.indexOf(Buffer.from('.debug_info\0')); assert(at > 0);
  renamed.write('.note.other', at, 'ascii'); renamed.writeUInt32LE(7, 640 + 4 * 64 + 4);
  await assert.rejects(compare(renamed, fixture(true)), /retained/u);
  const allocated = Buffer.from(original); allocated.writeBigUInt64LE(2n, 640 + 5 * 64 + 8);
  await assert.rejects(compare(allocated, fixture(true)), /metadata intersects/u);
});

test('the actual experimental entry rejects invalid provisioning before creating an output or downloading', async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'cliq-carrier-entry-'));
  const output = path.join(parent, 'must-not-exist');
  try {
    const child = spawnSync(process.execPath, ['--import', 'tsx', fileURLToPath(new URL('../qualify-supervisor-carrier-size.ts', import.meta.url)),
      output, '/absolute-unused-cache', 'unsupported-extra'], { encoding: 'utf8', timeout: 5_000, maxBuffer: 16_384 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 1);
    assert.match(child.stderr, /this experiment requires the standard Linux runner|usage: qualify-supervisor-carrier-size/u);
    assert.equal(child.stdout, '');
    await assert.rejects(lstat(output), { code: 'ENOENT' });
    assert.deepEqual(await readdir(parent), []);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

// Source wiring, not GNU strip/SEA execution or installed qualification. The
// Check the exact additive Node qualification input before checking the
// unchanged historical CT projection. This is a validation copy only.
function withoutLockedNodeQualification(workflow: string): string {
  const native = '      - name: Check the actual native dependency family before installed qualification\n' +
    '        run: |\n' +
    '          node --test --test-concurrency=1 --import tsx scripts/kernel/testing/dependency-native-family.test.ts scripts/kernel/testing/dependency-broker-lifecycle.test.ts scripts/kernel/testing/dependency-npm-stage.test.ts scripts/kernel/testing/preparing-git-native.test.ts scripts/kernel/testing/installed-genesis.test.ts\n' +
    "          if ! git cat-file -e 'ba804a59dcadee80cb41c822e2d0e32198462f20^{commit}'; then\n" +
    '            git fetch --no-tags --depth=1 origin ba804a59dcadee80cb41c822e2d0e32198462f20\n' +
    '          fi\n' +
    '          node --import tsx scripts/kernel/testing/qualify-native-callback-lifecycle.ts "$RUNNER_TEMP/cliq-native-callback-lifecycle"\n';
  const callbackRetention = '\n      - name: Retain bounded native callback source and joined output evidence\n' +
    '        if: always()\n        uses: actions/upload-artifact@v4\n        with:\n' +
    '          name: native-callback-lifecycle-${{ github.run_id }}-${{ github.run_attempt }}\n' +
    '          path: |\n' +
    '            ${{ runner.temp }}/cliq-native-callback-lifecycle/*.json\n' +
    '            ${{ runner.temp }}/cliq-native-callback-lifecycle/*.tap\n' +
    '            ${{ runner.temp }}/cliq-native-callback-lifecycle/*.stderr\n' +
    '            ${{ runner.temp }}/cliq-native-callback-lifecycle/*.source.tar\n' +
    '            ${{ runner.temp }}/cliq-native-callback-lifecycle/carrier/*.tar.xz\n' +
    '          if-no-files-found: warn\n          retention-days: 7\n';
  assert.equal(workflow.split(callbackRetention).length, 2, 'the fixed public inputs and bounded original output remain retained');
  const start = workflow.indexOf('      - name: Acquire the exact official npm qualification source\n');
  const end = workflow.indexOf('      - name: Observe the fixed original installed status deadlock\n', start);
  assert(start >= 0 && end > start, 'the exact source step must precede the original status regression');
  const source = workflow.slice(start, end);
  assert.equal(createHash('sha256').update(source).digest('hex'),
    'ee17b46a018af605f5cf753dc602440148f18dd8d2e598ddefef3aa4f2c84728',
    'the only new source step keeps its exact official URL, bounds, full validation, exclusive publication and join');
  const job = workflow.match(/\n  linux-installed-verifier:\n[\s\S]*?(?=\n  [a-z][a-z0-9-]*:\n|$)/u)?.[0];
  assert(job, 'the original installed verifier job must remain');
  assert.equal(workflow.split(native).length, 2, 'the exact native preflight runs once');
  assert.equal(workflow.split(source).length, 2, 'the exact source acquisition runs once');
  assert(job.includes(native + source + '      - name: Observe the fixed original installed status deadlock\n'),
    'the additions remain together immediately before the original status regression');
  const prerequisite = job.indexOf('      - name: Install actual guest, transport and Secret Service prerequisites\n');
  assert(prerequisite >= 0 && prerequisite < job.indexOf(native), 'native prerequisites precede the actual native preflight');
  const invocation = '          probe_node=$(realpath "$(command -v node)")\n' +
    '          probe_npm_archive="$RUNNER_TEMP/cliq-official-npm-10.9.2.tgz"\n' +
    '          sudo /bin/bash scripts/kernel/qualify-systemd-user.sh --run-verifier-journey --locked-node "$probe_npm_archive" "$probe_node" "$RUNNER_TEMP/cliq-installed-verifier-journey"\n';
  const originalInvocation = '          probe_node=$(realpath "$(command -v node)")\n' +
    '          sudo /bin/bash scripts/kernel/qualify-systemd-user.sh --run-verifier-journey "$probe_node" "$RUNNER_TEMP/cliq-installed-verifier-journey"\n';
  const condition = "        if: ${{ !cancelled() && steps.build.outcome == 'success' && steps.npm_source.outcome == 'success' }}\n";
  assert(job.includes(invocation), 'the original verifier receives the fixed trusted npm source');
  assert.equal(workflow.split(invocation).length, 2, 'the exact verifier invocation runs once');
  assert(job.includes(condition), 'the candidate requires its fully verified official source');
  assert.equal(workflow.split(condition).length, 2, 'only the original verifier uses the new source condition');
  return workflow.replace(native, '').replace(callbackRetention, '').replace(source, '').replace(invocation, originalInvocation)
    .replace(condition, "        if: ${{ !cancelled() && steps.build.outcome == 'success' }}\n");
}

function withoutDailyQualification(workflow: string): string {
  const marker = '  linux-installed-daily:\n', start = workflow.indexOf(marker);
  assert(start >= 0 && workflow.split(marker).length === 2, 'one independent daily qualification job is required');
  const end = workflow.indexOf('  linux-installed-verifier:\n', start);
  assert(end > start, 'the added daily job must precede the untouched original verifier job');
  const daily = workflow.slice(start, end);
  assert.equal(createHash('sha256').update(daily).digest('hex'), '4bf9a5daf2a764482fad6bd1ce7f9342806dfc0f091f3f283c242ce0ab0edc10',
    'the independent normal CLI job keeps its exact free runner, prerequisites, commands, joins and bounded evidence retention');
  assert(daily.includes('    runs-on: ubuntu-22.04\n    timeout-minutes: 20\n'));
  assert(daily.includes('      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n'));
  assert(daily.includes('      - uses: actions/setup-node@v4\n        with:\n          node-version: 22.13.0\n          cache: npm\n'));
  assert(daily.includes('      - run: npm ci\n      - run: npm run build\n        id: build\n' +
    '      - name: Check the shared daily client and original harness contracts\n'),
  'the real clean runner must build before its native-backed preflight');
  assert.deepEqual(daily.split('\n').filter(line => line.includes('apt-get install')), [
    '        run: sudo apt-get update && sudo apt-get install -y gnome-keyring libglib2.0-dev libssl-dev musl-tools bubblewrap libcap-dev libselinux1-dev meson ninja-build e2fsprogs libext2fs-dev pkg-config',
  ]);
  assert(daily.includes("        if: ${{ !cancelled() && steps.build.outcome == 'success' }}\n        shell: bash\n        run: |\n" +
    '          test "$RUNNER_ENVIRONMENT" = github-hosted\n          test "$RUNNER_OS" = Linux\n          test "$RUNNER_ARCH" = X64\n' +
    '          probe_node=$(realpath "$(command -v node)")\n' +
    '          sudo /bin/bash scripts/kernel/qualify-systemd-user.sh --run-daily-journey "$probe_node" "$RUNNER_TEMP/cliq-installed-daily-journey"\n'));
  assert(daily.includes('      - name: Retain original daily workflow and unchanged cleanup evidence\n        if: always()\n' +
    '        uses: actions/upload-artifact@v4\n        with:\n' +
    '          name: installed-daily-journey-${{ github.run_id }}-${{ github.run_attempt }}\n' +
    '          path: ${{ runner.temp }}/cliq-installed-daily-journey/*.json\n' +
    '          if-no-files-found: warn\n          retention-days: 7\n'));
  assert(!/(?:continue-on-error|needs):/u.test(daily));
  return workflow.slice(0, start) + workflow.slice(end);
}

// The immutable CT projection preserves every original job and budget after
// independently checking the exact upgrade and normal daily jobs and the
// closed, same-job Node qualification addition.
function assertCarrierExperimentWorkflow(workflow: string): void {
  const upgradeStart = workflow.indexOf('  installed-runtime-upgrade:\n');
  const originalStart = workflow.indexOf('  # Public-repository qualification stays on free standard GitHub-hosted\n', upgradeStart);
  assert.equal(upgradeStart, workflow.indexOf('jobs:\n') + 'jobs:\n'.length);
  assert(originalStart > upgradeStart);
  const upgrade = workflow.slice(upgradeStart, originalStart);
  assert.equal(createHash('sha256').update(upgrade).digest('hex'), 'ad971cd9def7e58b4591e7aef5907ff5dce694917ee4aca0b82ddef02ed5f669',
    'the independent signed7-to-8 job keeps its exact free runner, source, command, publisher, artifact and twenty-minute contract');
  const originalWorkflow = withoutDailyQualification(workflow.slice(0, upgradeStart) + workflow.slice(originalStart));
  const preparingReport = '            ${{ steps.guest.outputs.report_root }}/guest-preparing-git-report.json\n';
  assert.equal(workflow.split(preparingReport).length, 2, 'the original real preparing report must be retained exactly once');
  assert(workflow.includes(
    '          name: native-guest-verifier-${{ github.run_id }}-${{ github.run_attempt }}\n' +
    '          path: |\n' +
    '            ${{ steps.guest.outputs.report_root }}/guest-extractor-report.json\n' + preparingReport +
    '            ${{ steps.guest.outputs.report_root }}/guest-verifier-report.json\n' +
    '            ${{ steps.guest.outputs.report_root }}/guest-campaign-failure.json\n'),
  'only the fixed original preparing JSON is added to the bounded native artifact');
  const experiment = [
    '      - name: Measure fixed carrier metadata reduction without selecting it',
    "        if: ${{ !cancelled() && steps.build.outcome == 'success' }}",
    '        run: >-',
    '          node --import tsx scripts/kernel/qualify-supervisor-carrier-size.ts',
    '          "$RUNNER_TEMP/cliq-supervisor-carrier-size"',
    '          "$RUNNER_TEMP/cliq-supervisor-image/node-v24.21.0-linux-x64.tar.xz"',
    '',
  ].join('\n');
  const retain = [
    '      - name: Retain bounded carrier experiment metadata only',
    '        if: always()',
    '        uses: actions/upload-artifact@v4',
    '        with:',
    '          name: supervisor-carrier-size-${{ github.run_id }}-${{ github.run_attempt }}',
    '          path: ${{ runner.temp }}/cliq-supervisor-carrier-size/carrier-size-experiment.json',
    '          if-no-files-found: warn',
    '          retention-days: 7',
    '',
  ].join('\n');
  assert.equal(workflow.split(experiment).length, 2, 'exactly one fixed experiment step must exist');
  assert.equal(workflow.split(retain).length, 2, 'exactly one metadata-only artifact must exist');
  const adjacent = '        run: node --import tsx scripts/kernel/qualify-supervisor-image.ts "$RUNNER_TEMP/cliq-supervisor-image"\n' + experiment + retain;
  assert(workflow.includes(adjacent), 'the independent experiment belongs immediately after the original complete-image qualifier');
  const parentEvidenceTest = '          scripts/kernel/testing/installed-verifier-parent-evidence.test.ts\n';
  const qualificationPreflightTest = '          scripts/kernel/testing/installed-qualification-preflight.test.ts\n';
  assert.equal(workflow.split(parentEvidenceTest).length, 2, 'the new parent-domain regression must run exactly once in the existing four-job TypeScript matrix');
  assert.equal(workflow.split(qualificationPreflightTest).length, 2, 'the exact qualification source regressions run once in the original four-job matrix');
  assert(workflow.includes('          scripts/kernel/testing/installed-verifier-result.test.ts\n' + parentEvidenceTest + qualificationPreflightTest + '      - run: npm run build\n'),
    'the added regression must remain in the original test command, not in a disabled or independent step');
  const sessionRegression = ' scripts/kernel/testing/installed-session-continuity.test.ts';
  const readinessRegression = ' scripts/kernel/testing/installed-control-readiness.test.ts';
  assert.equal(workflow.split(sessionRegression).length, 2, 'the installed Session regression runs exactly once');
  assert.equal(workflow.split(readinessRegression).length, 2, 'the real replacement-socket regression runs exactly once');
  assert(workflow.includes('      - run: node --test --import tsx scripts/kernel/testing/installed-worker-lease.test.ts ' +
    'scripts/kernel/testing/installed-client-consumer.test.ts scripts/kernel/testing/installed-control-client-driver.test.ts' + sessionRegression + readinessRegression + '\n'),
  'Session conformance remains in the original installed-Run preflight command');
  const processRegression = '          node --test scripts/kernel/testing/systemd-process-fact.test.mjs\n';
  assert.equal(workflow.split(processRegression).length, 2, 'the real process-lifecycle regression runs exactly once');
  assert(workflow.includes('        run: |\n' + processRegression + '          probe_node=$(realpath "$(command -v node)")\n' +
    '          sudo /bin/bash scripts/kernel/qualify-systemd-user.sh "$probe_node" "$RUNNER_TEMP/cliq-systemd-user"\n'),
  'the lifecycle regression precedes the unchanged actual systemd campaign in its original step');
  const buildDependencies = 'bubblewrap libcap-dev libselinux1-dev meson ninja-build';
  const aptLines = originalWorkflow.split('\n').filter(line => line.includes('apt-get install') && /\bbubblewrap\b/u.test(line));
  assert.equal(aptLines.length, 18, 'only the eighteen original bubblewrap installation commands receive fixed source-build dependencies');
  assert.equal(originalWorkflow.split(buildDependencies).length, 19, 'the exact dependency group must occur once in each original command');
  const upgradeAptLines = upgrade.split('\n').filter(line => line.includes('apt-get install') && /\bbubblewrap\b/u.test(line));
  assert.deepEqual(upgradeAptLines, ['        run: sudo apt-get update && sudo apt-get install -y gnome-keyring libglib2.0-dev libssl-dev musl-tools bubblewrap libcap-dev libselinux1-dev meson ninja-build e2fsprogs libext2fs-dev pkg-config']);
  assert.equal(workflow.split('\n').filter(line => line.includes('apt-get install') && /\bbubblewrap\b/u.test(line)).length, 20);
  assert.equal(workflow.split(buildDependencies).length, 21, 'only the exact independent upgrade and daily jobs add dependency commands');
  for (const line of aptLines) assert.equal(line.split(buildDependencies).length, 2,
    'the original APT bubblewrap remains for its negative parameter regression alongside the fixed build dependencies');
  const storageRegression = [
    '          node --test scripts/kernel/testing/build-bubblewrap.test.mjs',
    '          storage_regression="$RUNNER_TEMP/cliq-source-storage-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"',
    '          musl-gcc -std=c11 -O2 -Wall -Wextra -Werror -static \\',
    '            -idirafter /usr/include -idirafter "/usr/include/$(musl-gcc -dumpmachine)" \\',
    '            native/linux/source-storage.test.c -o "$storage_regression"',
    '          "$storage_regression"',
    '',
  ].join('\n');
  assert.equal(workflow.split(storageRegression).length, 2, 'the real bounded-storage and old-APT parameter regressions run exactly once');
  assert(workflow.includes('      - name: Verify real worker seccomp ABI and syscall denials\n' +
    '        shell: bash\n        run: |\n' +
    '          node --test --import tsx scripts/kernel/testing/guest-verifier-process.test.ts scripts/kernel/testing/guest-verifier-diagnostics.test.ts\n' +
    storageRegression + '          regression="$RUNNER_TEMP/cliq-worker-seccomp-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"\n'),
  'the source-build regressions stay inside the original actual native ABI step, before its unchanged compiler and syscall checks');
  const projected = withoutLockedNodeQualification(originalWorkflow).replace(experiment, '').replace(retain, '').replace(parentEvidenceTest, '').replace(qualificationPreflightTest, '')
    .replace(sessionRegression, '').replace(readinessRegression, '').replace(processRegression, '').replaceAll(buildDependencies, 'bubblewrap').replace(storageRegression, '').replace(preparingReport, '');
  assert.equal(createHash('sha256').update(projected).digest('hex'), '346af80a56060feace86c309b316c67560f68c512207d6cd3c95ab965cb225f5',
    'all original CT jobs, runner groups, timeouts, qualifiers and conditions must remain byte-identical');
  assert.equal(workflow.split('qualify-supervisor-carrier-size.ts').length, 2, 'no production job may select the experimental carrier');
}

test('carrier experiments are isolated beside the original image qualifier and retain only their bounded report', async () => {
  assertCarrierExperimentWorkflow(await readFile(new URL('../../../.github/workflows/kernel-foundation.yml', import.meta.url), 'utf8'));
});

test('the exact native preflight preserves every original and added case and rejects extra or residual commands', async () => {
  const workflow = await readFile(new URL('../../../.github/workflows/kernel-foundation.yml', import.meta.url), 'utf8');
  assertCarrierExperimentWorkflow(workflow);
  const cases = ['dependency-native-family', 'dependency-broker-lifecycle', 'dependency-npm-stage', 'preparing-git-native', 'installed-genesis']
    .map(name => ' scripts/kernel/testing/' + name + '.test.ts');
  const mutations = cases.flatMap(filename => [workflow.replace(filename, ''), workflow.replace(filename, filename.repeat(2))]);
  const lastCase = cases.at(-1)!;
  mutations.push(
    workflow.replace('qualify-native-callback-lifecycle.ts', 'callback-qualification-skipped.ts'),
    workflow.replace('origin ba804a59dcadee80cb41c822e2d0e32198462f20', 'origin HEAD'),
    workflow.replace('cliq-native-callback-lifecycle/*.tap', 'cliq-native-callback-lifecycle/omitted.tap'),
    workflow.replace(lastCase + '\n', lastCase + ' scripts/kernel/testing/unexpected-native.test.ts\n'),
    workflow.replace(lastCase + '\n', lastCase + '\n      - run: node --test --import tsx scripts/kernel/testing/unexpected-native.test.ts\n'),
    workflow + '      - run: node --test --import tsx scripts/kernel/testing/unexpected-native.test.ts\n'
  );
  for (const mutated of mutations) {
    assert.notEqual(mutated, workflow, 'each rejection must exercise a real removal, duplicate, extra case or residual command');
    assert.throws(() => assertCarrierExperimentWorkflow(mutated), { name: 'AssertionError' });
  }
});

test('the additive parent-domain regression cannot hide workflow removals, disabled tests or changed runner and time budgets', async () => {
  const workflow = await readFile(new URL('../../../.github/workflows/kernel-foundation.yml', import.meta.url), 'utf8');
  assertCarrierExperimentWorkflow(workflow);
  const parentEvidenceTest = '          scripts/kernel/testing/installed-verifier-parent-evidence.test.ts\n';
  const qualificationPreflightTest = '          scripts/kernel/testing/installed-qualification-preflight.test.ts\n';
  const sessionRegression = ' scripts/kernel/testing/installed-session-continuity.test.ts';
  const readinessRegression = ' scripts/kernel/testing/installed-control-readiness.test.ts';
  const processRegression = '          node --test scripts/kernel/testing/systemd-process-fact.test.mjs\n';
  const buildDependencies = 'bubblewrap libcap-dev libselinux1-dev meson ninja-build';
  const negativeParameters = '          node --test scripts/kernel/testing/build-bubblewrap.test.mjs\n';
  const storageCommand = '            native/linux/source-storage.test.c -o "$storage_regression"\n';
  const storageEnd = '          "$storage_regression"\n';
  const storageStart = workflow.indexOf(negativeParameters);
  const storageRegression = workflow.slice(storageStart, workflow.indexOf(storageEnd, storageStart) + storageEnd.length);
  const upgradeStart = workflow.indexOf('  installed-runtime-upgrade:\n');
  const originalStart = workflow.indexOf('  # Public-repository qualification stays on free standard GitHub-hosted\n', upgradeStart);
  const upgrade = workflow.slice(upgradeStart, originalStart);
  const dailyStart = workflow.indexOf('  linux-installed-daily:\n');
  const dailyEnd = workflow.indexOf('  linux-installed-verifier:\n', dailyStart);
  const daily = workflow.slice(dailyStart, dailyEnd);
  const mutateOriginal = (from: string, to: string) => workflow.slice(0, originalStart) + workflow.slice(originalStart).replace(from, to);
  const mutations = [
    workflow.replace(upgrade, ''),
    workflow.replace(upgrade, upgrade.repeat(2)),
    workflow.replace(daily, ''),
    workflow.replace(daily, daily.repeat(2)),
    workflow.replace(daily, daily.replace('runs-on: ubuntu-22.04', 'runs-on: ubuntu-22.04-8core')),
    workflow.replace(daily, daily.replace('timeout-minutes: 20', 'timeout-minutes: 21')),
    workflow.replace(daily, daily.replace('persist-credentials: false', 'persist-credentials: true')),
    workflow.replace(daily, daily.replace('node-version: 22.13.0', 'node-version: 24.x')),
    workflow.replace(daily, daily.replace('      - run: npm run build\n        id: build\n', '')),
    workflow.replace(daily, daily.replace('src/client/daily.test.ts', '# src/client/daily.test.ts')),
    workflow.replace(daily, daily.replace("if: ${{ !cancelled() && steps.build.outcome == 'success' }}", 'if: false')),
    workflow.replace(daily, daily.replace('--run-daily-journey', '--run-verifier-journey')),
    workflow.replace(daily, daily.replace('libssl-dev ', '')),
    workflow.replace(daily, daily.replace('retention-days: 7', 'retention-days: 30')),
    workflow.replace(daily, daily.replace('cliq-installed-daily-journey/*.json', 'cliq-installed-daily-journey/**')),
    workflow.replace(daily, daily + '      - run: node --test scripts/kernel/testing/unexpected-daily.test.mjs\n'),
    workflow.replace('old_commit=25130cfec913bddaff4d0a8c7ff4aac7ef2db932', 'old_commit=410c8193ea516b0b9f8e6a746c4376003e67b5a4'),
    workflow.replace(parentEvidenceTest, '').replace(qualificationPreflightTest, ''),
    workflow.replace('dependency-native-family.test.ts', 'dependency-native-family-skipped.test.ts'),
    workflow.replace('            ${{ steps.guest.outputs.report_root }}/guest-preparing-git-report.json\n', ''),
    workflow.replace('guest-preparing-git-report.json', 'guest-preparing-git-report*.json'),
    workflow.replace('guest-preparing-git-report.json', 'guest-preparing-git-report.json\n            ${{ steps.guest.outputs.report_root }}/guest-preparing-git-report.json'),
    workflow.replace("redirect: 'error'", "redirect: 'follow'"),
    workflow.replace('total <= NPM_DATA_RECIPE.archiveBytes', 'total <= NPM_DATA_RECIPE.archiveBytes * 2'),
    workflow.replace('buildInstalledNpmDataAsset(archive);', ''),
    workflow.replace('--locked-node "$probe_npm_archive" ', ''),
    workflow.replace(" && steps.npm_source.outcome == 'success'", ''),
    workflow.replace(parentEvidenceTest, parentEvidenceTest.repeat(2)),
    workflow.replace(qualificationPreflightTest, ''),
    workflow.replace(qualificationPreflightTest, qualificationPreflightTest.repeat(2)),
    workflow.replace(qualificationPreflightTest, qualificationPreflightTest.replace('scripts/', '# scripts/')),
    workflow.replace(qualificationPreflightTest + '      - run: npm run build\n', '      - run: npm run build\n' + qualificationPreflightTest),
    workflow.replace(parentEvidenceTest, '          # scripts/kernel/testing/installed-verifier-parent-evidence.test.ts\n'),
    workflow.replace(parentEvidenceTest + qualificationPreflightTest + '      - run: npm run build\n', '      - run: npm run build\n' + parentEvidenceTest + qualificationPreflightTest),
    workflow.replace(sessionRegression, ''),
    workflow.replace(sessionRegression, sessionRegression.repeat(2)),
    workflow.replace(readinessRegression, ''),
    workflow.replace(readinessRegression, readinessRegression.repeat(2)),
    workflow.replace(sessionRegression + readinessRegression + '\n', sessionRegression + '\n' +
      '      - run: node --test --import tsx' + readinessRegression + '\n'),
    workflow.replace(processRegression, ''),
    workflow.replace(processRegression, processRegression.repeat(2)),
    workflow.replace(processRegression, processRegression.replace('node --test', '# node --test')),
    workflow.replace(buildDependencies, 'bubblewrap libcap-dev libselinux1-dev ninja-build meson'),
    ...['libcap-dev', 'libselinux1-dev', 'meson', 'ninja-build'].map(dependency =>
      workflow.replace(buildDependencies, buildDependencies.replace(' ' + dependency, ''))),
    workflow.replace(buildDependencies, 'bubblewrap libcap-dev libselinux1-dev meson ninja-build curl'),
    workflow.replace(buildDependencies, buildDependencies + ' ' + buildDependencies),
    workflow.replace(negativeParameters, ''),
    workflow.replace(negativeParameters, negativeParameters.repeat(2)),
    workflow.replace(negativeParameters, negativeParameters.replace('node --test', '# node --test')),
    workflow.replace(storageCommand, ''),
    workflow.replace(storageCommand, storageCommand.replace('source-storage.test.c', 'worker-channel.test.c')),
    workflow.replace(storageRegression, storageRegression.replace(' -Werror -static', ' -static')),
    workflow.replace(storageRegression, '').replace('        run: |\n', '        run: |\n' + storageRegression),
    workflow.replace('        node: [22.13.0, 24.x]', '        node: [24.x]'),
    mutateOriginal('    runs-on: ubuntu-22.04', '    runs-on: ubuntu-22.04-8core'),
    mutateOriginal('    timeout-minutes: 20', '    timeout-minutes: 21'),
    workflow.replace('    timeout-minutes: 15', '    timeout-minutes: 16'),
    mutateOriginal("        if: ${{ !cancelled() && steps.build.outcome == 'success' }}", '        if: false'),
    workflow.replace('      - run: npm test\n', ''),
  ];
  for (const mutated of mutations) {
    assert.notEqual(mutated, workflow, 'each negative case must exercise a real workflow mutation');
    assert.throws(() => assertCarrierExperimentWorkflow(mutated), { name: 'AssertionError' });
  }
});
