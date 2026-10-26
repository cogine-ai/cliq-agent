import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { cp, mkdir, mkdtemp, open, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import ts from 'typescript';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { build } from 'esbuild';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeSourceGitInspectionOutput } from './source-git-output.js';
import { publishSourceGitArtifacts } from './source-git-artifacts.js';
import { ArtifactCatalog } from '../state/artifacts.js';
import { ContentAddressedStore } from '../state/cas.js';
import { readPrivateGitData } from './private-git-data.js';
import { digestOmitting } from '../kernel/identity.js';
import { compileFrozenIgnoreRules } from './frozen-ignore.js';
import { publishGitSourceProjection } from './source-projection.js';
import { loadNativeStateOwner } from '../state/native-owner.js';
import type { Checkpoint, RunSpec, SourceManifest, WorkspaceEntryManifest, WorkspaceStateManifest } from '../kernel/types.js';
import { normalizeGitIndex } from './git-index.js';
import { loadFrozenPrivateGit } from './run-workspace/private-git.js';
import { createRunWorkspaceMaterialization, readRunWorkspaceBirth, readRunWorkspacePreparingGit } from './run-workspace/generation.js';
import { readCandidateSource } from '../state/result-source.js';
import { installedSandboxProfile } from '../state/installed-sandbox-profile.js';
import { captureFrozenSourceProjection } from './source-projection.js';
import { readSourceProjectionData } from '../state/source-projection-data.js';

test('actual private fixed-Git transport produces and verifies a nonempty reachable pack without the unreachable fixture blob', async () => {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'source-git-pack-data-'));
  try {
    const REPOSITORY = path.join(directory, 'repository'), OUTPUT = path.join(directory, 'output');
    await mkdir(REPOSITORY, { mode: 0o700 }); await mkdir(OUTPUT, { mode: 0o700 });
    const file = fileURLToPath(new URL('./source-git-inspector.ts', import.meta.url)), text = await readFile(file, 'utf8');
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    const declaration = source.statements.find(statement => ts.isFunctionDeclaration(statement) && statement.name?.text === 'git');
    assert(declaration && ts.isFunctionDeclaration(declaration));
    const env = source.statements.find(statement => ts.isVariableStatement(statement) &&
      statement.declarationList.declarations.some(item => ts.isIdentifier(item.name) && item.name.text === 'ENV'));
    assert(env && ts.isVariableStatement(env));
    const code = ts.transpileModule(`${env.getText(source)}\n${declaration.getText(source)}`, {
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None }
    }).outputText;
    const children: Array<ReturnType<typeof spawn>> = [], joined = new Set<ReturnType<typeof spawn>>();
    const actualSpawn = (...args: Parameters<typeof spawn>) => {
      const child = spawn(...args); children.push(child); child.once('close', () => joined.add(child)); return child;
    };
    const git = new Function('spawn', 'open', 'path', 'constants', 'REPOSITORY', 'OUTPUT', 'refused', `${code}; return git;`)(
      actualSpawn, open, path, constants, REPOSITORY, OUTPUT, () => { throw new TypeError('fixed source Git inspection failed'); }
    ) as (args: string[], resources: typeof DEFAULT_SANDBOX_RESOURCES, input?: Buffer, output?: 'reachable.pack') => Promise<Buffer>;
    // Own unsigned host Git generates data only. This exercises the actual
    // private transport body and real pipe/FD joins, not the signed source
    // entry guard, native owner, authorization, namespace or Linux proof.
    await git(['init', '--bare', REPOSITORY], DEFAULT_SANDBOX_RESOURCES);
    const reachable = (await git(['hash-object', '-w', '--stdin'], DEFAULT_SANDBOX_RESOURCES, Buffer.from('declared reachable\n'))).toString().trim();
    const excluded = (await git(['hash-object', '-w', '--stdin'], DEFAULT_SANDBOX_RESOURCES, Buffer.from('unreachable own sentinel\n'))).toString().trim();
    const roots = Buffer.from(`${reachable}\n`);
    const reached = (await git(['rev-list', '--objects', '--no-object-names', '--stdin'], DEFAULT_SANDBOX_RESOURCES, roots)).toString();
    assert.equal(reached, `${reachable}\n`);
    await git(['pack-objects', '--stdout', '--revs', '--delta-base-offset', '--threads=1', '--window=0'], DEFAULT_SANDBOX_RESOURCES, roots, 'reachable.pack');
    await git(['config', 'pack.writeReverseIndex', 'true'], DEFAULT_SANDBOX_RESOURCES);
    await git(['index-pack', '--strict', '--index-version=2', '--no-rev-index', '-o', `${OUTPUT}/reachable.idx`, `${OUTPUT}/reachable.pack`], DEFAULT_SANDBOX_RESOURCES);
    assert.deepEqual((await readdir(OUTPUT)).sort(), ['reachable.idx', 'reachable.pack'],
      'the fixed index-pack flag must override a true reverse-index default without deleting any output');
    await git(['verify-pack', `${OUTPUT}/reachable.idx`], DEFAULT_SANDBOX_RESOURCES);
    const index = await readFile(`${OUTPUT}/reachable.idx`), count = index.readUInt32BE(8 + 255 * 4);
    assert.equal(count, 1); assert.equal(index.subarray(8 + 1024, 8 + 1024 + 20).toString('hex'), reachable);
    assert(!index.includes(Buffer.from(excluded, 'hex')));
    const pack = await readFile(`${OUTPUT}/reachable.pack`);
    assert(pack.subarray(0, 4).equals(Buffer.from('PACK'))); assert.equal(pack.readUInt32BE(8), 1);
    const large = (await git(['hash-object', '-w', '--stdin'], DEFAULT_SANDBOX_RESOURCES, randomBytes(128 * 1024))).toString().trim();
    await assert.rejects(git(['cat-file', 'blob', large], { ...DEFAULT_SANDBOX_RESOURCES, maxInvocationOutputBytes: 65_536 }),
      { message: 'fixed source Git inspection failed' });
    assert.equal(joined.size, children.length, 'a bounded pipe failure still waits for every actual child close');
    assert(children.every(child => child.stdin?.destroyed && child.stdout?.destroyed && child.stderr?.destroyed));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('actual helper algorithm consumes own packed/ref/index data and emits only reachable objects with staged state distinct from HEAD', async () => {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'source-git-algorithm-data-'));
  let children = 0, joined = 0;
  const run = async (binary: string, args: string[], cwd: string, input?: Buffer, extra: number[] = []) => {
    const child = spawn(binary, args, { cwd, env: { PATH: '/usr/bin', HOME: directory, LANG: 'C', LC_ALL: 'C',
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_SYSTEM: '/dev/null', GIT_CONFIG_GLOBAL: '/dev/null', GIT_OPTIONAL_LOCKS: '0',
      GIT_AUTHOR_NAME: 'Own data fixture', GIT_AUTHOR_EMAIL: 'fixture@invalid', GIT_COMMITTER_NAME: 'Own data fixture',
      GIT_COMMITTER_EMAIL: 'fixture@invalid' }, stdio: ['pipe', 'pipe', 'pipe', ...extra] });
    children++; const chunks: Buffer[] = [], errors: Buffer[] = []; let spawnError: unknown;
    child.once('error', error => { spawnError = error; });
    child.stdout!.on('data', bytes => chunks.push(Buffer.from(bytes))); child.stderr!.on('data', bytes => errors.push(Buffer.from(bytes)));
    child.stdin!.on('error', () => {}); child.stdin!.end(input);
    const exit = await new Promise<number | null>(resolve => child.once('close', code => { joined++; resolve(code); }));
    if (spawnError) throw spawnError;
    return { exit, stdout: Buffer.concat(chunks), stderr: Buffer.concat(errors) };
  };
  try {
    const filename = fileURLToPath(new URL('./source-git-inspector.ts', import.meta.url)), text = await readFile(filename, 'utf8');
    const source = ts.createSourceFile(filename, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    const fixedPaths = source.statements.find(statement => ts.isVariableStatement(statement) &&
      statement.declarationList.declarations.some(item => ts.isIdentifier(item.name) && item.name.text === 'INPUT'));
    const inspect = source.statements.find(statement => ts.isFunctionDeclaration(statement) && statement.name?.text === 'inspect');
    assert(fixedPaths && inspect && ts.isFunctionDeclaration(inspect));
    const entryGuard = inspect.body!.statements[0]!; assert(ts.isIfStatement(entryGuard));
    const refusals: ts.CallExpression[] = [];
    const collectRefusals = (node: ts.Node) => { if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'refused') refusals.push(node);
      ts.forEachChild(node, collectRefusals); }; collectRefusals(source);
    assert(entryGuard.getText(source).includes("process.argv[1] !== '/runtime/cliq-source-git-inspector.mjs'"));
    // This private data test substitutes only fixed scratch paths and removes
    // the production entry guard. All actual algorithm/IO bodies remain. It
    // is not a signed helper invocation, authorization or native/Linux proof.
    for (const format of ['sha1', 'sha256'] as const) {
      const root = path.join(directory, format), input = path.join(root, 'input'), repository = path.join(root, 'repository'), output = path.join(root, 'output');
      const original = path.join(root, 'original.git'); await mkdir(input, { recursive: true, mode: 0o700 });
      const git = async (args: string[], bytes?: Buffer) => {
        const result = await run('/usr/bin/git', [`--git-dir=${original}`, ...args], root, bytes);
        assert.equal(result.exit, 0, 'own host Git fixture command must complete'); return result.stdout.toString().trim();
      };
      await git(['init', '--bare', `--object-format=${format}`, original]);
      const declared = await git(['hash-object', '-w', '--stdin'], Buffer.from('HEAD version\n'));
      const staged = await git(['hash-object', '-w', '--stdin'], Buffer.from('different staged version\n'));
      const excluded = await git(['hash-object', '-w', '--stdin'], Buffer.from('own unreachable private sentinel\n'));
      const tree = await git(['mktree'], Buffer.from(`100644 blob ${declared}\tfile.txt\n`));
      const commit = await git(['commit-tree', tree], Buffer.from('own fixture commit\n'));
      await git(['update-ref', 'refs/heads/main', commit]); await git(['symbolic-ref', 'HEAD', 'refs/heads/main']);
      await git(['update-index', '--add', '--cacheinfo', `100644,${staged},file.txt`]);
      await git(['pack-refs', '--all']);
      await git(['-c', 'pack.writeReverseIndex=false', 'pack-objects', path.join(original, 'objects/pack/pack')],
        Buffer.from([declared, staged, excluded, tree, commit].join('\n') + '\n'));
      const packFiles = await readdir(path.join(original, 'objects/pack'));
      assert(packFiles.every(name => /\.(pack|idx)$/u.test(name)), `own fixture pack extensions: ${packFiles.map(name =>
        name.endsWith('.rev') ? 'rev' : name.endsWith('.bitmap') ? 'bitmap' : name.endsWith('.pack') ? 'pack' : name.endsWith('.idx') ? 'idx' : 'unknown').join(',')}`);
      const gitInput = path.join(input, '.git'); await mkdir(gitInput, { mode: 0o700 });
      for (const member of ['HEAD', 'index', 'packed-refs', 'refs', 'objects']) await cp(path.join(original, member), path.join(gitInput, member), { recursive: true });
      const raw = Buffer.from(`[core]\n repositoryformatversion = ${format === 'sha1' ? 0 : 1}\n bare = false\n filemode = true\n` +
        (format === 'sha256' ? '[extensions]\n objectformat = sha256\n' : '') +
        '[remote "private-fixture"]\n url = https://discard-this-inert-value.invalid/private\n fetch = +refs/heads/*:refs/remotes/private-fixture/*\n');
      const definition = canonicalJsonBytes({ schemaVersion: 1, recipe: 'cliq-source-git-inspection-v1', repositoryIdentityDigest: 'a'.repeat(64),
        resources: { ...DEFAULT_SANDBOX_RESOURCES } });
      const configPath = path.join(root, 'raw-config'), intentPath = path.join(root, 'intent');
      await writeFile(configPath, raw, { mode: 0o600 }); await writeFile(intentPath, definition, { mode: 0o600 });
      const replacements = [{ start: fixedPaths.getStart(source), end: fixedPaths.end,
        text: `const INPUT=${JSON.stringify(input)},REPOSITORY=${JSON.stringify(repository)},OUTPUT=${JSON.stringify(output)};` },
      { start: inspect.getStart(source), end: inspect.getStart(source), text: 'let ownFixtureStage = 0, ownFixtureRefusal = 0;\n' },
      { start: entryGuard.getStart(source), end: entryGuard.end, text: '' },
      ...inspect.body!.statements.slice(1).map((statement, index) => ({ start: statement.getStart(source), end: statement.getStart(source), text: `ownFixtureStage=${index + 1};` })),
      ...refusals.filter(node => node.getStart(source) < entryGuard.getStart(source) || node.end > entryGuard.end)
        .map(node => ({ start: node.getStart(source), end: node.end, text: `(ownFixtureRefusal=${refusals.indexOf(node) + 1},refused())` })),
      { start: source.statements.at(-1)!.getStart(source), end: source.statements.at(-1)!.end,
        text: "void inspect().catch(() => { console.error('own_fixture_statement:' + ownFixtureStage + ':refusal:' + ownFixtureRefusal); process.exitCode = 74; });" }
      ].sort((left, right) => right.start - left.start);
      let modified = text; for (const replacement of replacements) modified = modified.slice(0, replacement.start) + replacement.text + modified.slice(replacement.end);
      const bundled = await build({ stdin: { contents: modified, resolveDir: path.dirname(filename), sourcefile: filename, loader: 'ts' },
        bundle: true, write: false, platform: 'node', target: 'node22', format: 'esm', logLevel: 'silent' });
      const config = await open(configPath, constants.O_RDONLY | constants.O_NOFOLLOW), intent = await open(intentPath, constants.O_RDONLY | constants.O_NOFOLLOW);
      let result: Awaited<ReturnType<typeof run>>;
      try { result = await run(process.execPath, ['--input-type=module', '--eval', bundled.outputFiles[0]!.text], input, undefined, [config.fd, intent.fd]); }
      finally { await Promise.all([config.close(), intent.close()]); }
      assert.equal(result.exit, 0, `complete helper algorithm must accept its supported own immutable data fixture ${result.stderr.toString()}`);
      assert.equal(result.stdout.length, 0); assert.equal(result.stderr.length, 0);
      assert.deepEqual((await readdir(output)).sort(), ['canonical.index', 'inspection.json', 'reachable.idx', 'reachable.pack'],
        'the actual source helper must leave all and only the four fixed collector outputs after every child joins');
      const metadata = await readFile(path.join(output, 'inspection.json'));
      const decoded = decodeSourceGitInspectionOutput(metadata, { repositoryIdentityDigest: 'a'.repeat(64), resources: DEFAULT_SANDBOX_RESOURCES });
      assert.deepEqual(decoded.head, { kind: 'symbolic', ref: 'refs/heads/main' });
      assert.equal(decoded.index.entries.length, 1); assert.equal(decoded.index.entries[0]!.objectId, staged);
      assert(decoded.pack.objectIds.includes(declared)); assert(decoded.pack.objectIds.includes(staged));
      assert(!decoded.pack.objectIds.includes(excluded)); assert(!metadata.includes(Buffer.from('discard-this-inert-value')));
      assert.equal((await readFile(path.join(output, 'reachable.pack'))).readUInt32BE(8), decoded.pack.objectIds.length);
      await mkdir(path.join(root, 'cas'), { mode: 0o700 });
      const cas = new ContentAddressedStore(path.join(root, 'cas'));
      const artifacts = new ArtifactCatalog(cas), readers = new Set<string>(), closed = new Set<string>();
      const stream = async function* (name: string) {
        readers.add(name);
        const file = await open(path.join(output, name), constants.O_RDONLY | constants.O_NOFOLLOW);
        try {
          for (;;) {
            const buffer = Buffer.alloc(65_536), next = await file.read(buffer, 0, buffer.length, null);
            if (!next.bytesRead) break;
            yield buffer.subarray(0, next.bytesRead);
          }
        } finally { await file.close(); closed.add(name); }
      };
      // These real helper data bytes and CAS writes do not mint a source
      // inspection result, authorization, native owner or generation proof.
      const retained = await publishSourceGitArtifacts(artifacts, { inspection: stream('inspection.json'),
        index: stream('canonical.index'), pack: stream('reachable.pack'), packIndex: stream('reachable.idx') },
      { repositoryIdentityDigest: 'a'.repeat(64), resources: DEFAULT_SANDBOX_RESOURCES });
      const prepare = async (name: string, selectedMetadata: typeof decoded, selectedPackIndex: Buffer) => {
        const preparationRoot = path.join(root, name), preparationInput = path.join(preparationRoot, 'input'), preparationOutput = path.join(preparationRoot, 'output');
        await mkdir(preparationInput, { recursive: true, mode: 0o700 });
        await writeFile(path.join(preparationInput, 'canonical.index'), await readFile(path.join(output, 'canonical.index')), { mode: 0o600 });
        await writeFile(path.join(preparationInput, 'reachable.pack'), await readFile(path.join(output, 'reachable.pack')), { mode: 0o600 });
        await writeFile(path.join(preparationInput, 'reachable.idx'), selectedPackIndex, { mode: 0o600 });
        const metadataFile = path.join(preparationRoot, 'metadata'), definitionFile = path.join(preparationRoot, 'intent');
        await writeFile(metadataFile, canonicalJsonBytes(selectedMetadata), { mode: 0o600 });
        await writeFile(definitionFile, canonicalJsonBytes({ schemaVersion: 1, recipe: 'cliq-private-git-preparation-v1',
          repositoryIdentityDigest: 'a'.repeat(64), resources: DEFAULT_SANDBOX_RESOURCES }), { mode: 0o600 });
        const originalPaths = `const INPUT=${JSON.stringify(input)},REPOSITORY=${JSON.stringify(repository)},OUTPUT=${JSON.stringify(output)};`;
        assert.equal(modified.split(originalPaths).length, 2);
        const preparationSource = modified.replace(originalPaths,
          `const INPUT=${JSON.stringify(preparationInput)},REPOSITORY=${JSON.stringify(path.join(preparationRoot, 'repository'))},OUTPUT=${JSON.stringify(preparationOutput)};`);
        const program = await build({ stdin: { contents: preparationSource, resolveDir: path.dirname(filename), sourcefile: filename, loader: 'ts' },
          bundle: true, write: false, platform: 'node', target: 'node22', format: 'esm', logLevel: 'silent' });
        const entry = path.join(preparationRoot, 'own-helper.mjs'); await writeFile(entry, program.outputFiles[0]!.text, { mode: 0o500 });
        const inputFd = await open(metadataFile, constants.O_RDONLY | constants.O_NOFOLLOW), definitionFd = await open(definitionFile, constants.O_RDONLY | constants.O_NOFOLLOW);
        try { return { ...await run(process.execPath, [entry, '--prepare-private-git'], preparationInput, undefined, [inputFd.fd, definitionFd.fd]),
          output: preparationOutput }; }
        finally { await Promise.all([inputFd.close(), definitionFd.close()]); }
      };
      const prepared = await prepare('preparation-data', decoded, await readFile(path.join(output, 'reachable.idx')));
      assert.equal(prepared.exit, 0, `same measured helper must accept its fixed CAS-only preparation ${prepared.stderr.toString()}`);
      assert.equal(prepared.stdout.length, 0); assert.equal(prepared.stderr.length, 0);
      assert.deepEqual((await readdir(prepared.output)).sort(), ['canonical.index', 'inspection.json', 'reachable.idx', 'reachable.pack'],
        'fresh actual preparation index validation must leave no reverse index or temporary output after every child joins');
      const preparedData = decodeSourceGitInspectionOutput(await readFile(path.join(prepared.output, 'inspection.json')),
        { repositoryIdentityDigest: 'a'.repeat(64), resources: DEFAULT_SANDBOX_RESOURCES });
      assert.deepEqual(preparedData, decoded);
      const forgedIndex = Buffer.from(await readFile(path.join(output, 'reachable.idx'))), objectCount = forgedIndex.readUInt32BE(8 + 255 * 4);
      const objectHashBytes = format === 'sha1' ? 20 : 32;
      assert(objectCount > 0); forgedIndex[8 + 1024 + objectCount * objectHashBytes]! ^= 1;
      createHash(format).update(forgedIndex.subarray(0, -objectHashBytes)).digest().copy(forgedIndex, forgedIndex.length - objectHashBytes);
      const forgedMetadata = { ...decoded, pack: { ...decoded.pack, indexSha256: createHash('sha256').update(forgedIndex).digest('hex') } };
      const rejectedPreparation = await prepare('preparation-bad-index', forgedMetadata, forgedIndex);
      assert.equal(rejectedPreparation.exit, 74, 'a rehashed index with a forged CRC must fail fresh actual index-pack validation');
      assert.deepEqual(readers, closed, 'every complete data stream is really closed before publication returns');
      assert.equal(readers.size, 4);
      assert.deepEqual(retained.index.entries, decoded.index.entries);
      assert.equal(retained.index.entries[0]!.objectId, staged);
      assert.equal(retained.manifest.indexRef, retained.indexRef);
      assert.deepEqual(retained.manifest.head, decoded.head);
      assert.deepEqual(retained.closure.reachableObjectIds, decoded.pack.objectIds);
      assert(!retained.closure.reachableObjectIds.includes(excluded));
      assert.deepEqual(await artifacts.readCanonical(retained.privateGitStateRef), retained.manifest);
      assert.equal((await artifacts.readBytes(retained.pack.packBytesRef)).readUInt32BE(8), decoded.pack.objectIds.length);
      const reopened = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'cas')));
      const recovered = await readPrivateGitData(reopened, retained.privateGitStateRef,
        { repositoryIdentityDigest: 'a'.repeat(64), resources: DEFAULT_SANDBOX_RESOURCES });
      assert.deepEqual(recovered.manifest, retained.manifest);
      assert.deepEqual(recovered.index.entries, decoded.index.entries);
      assert.deepEqual(recovered.closure.reachableObjectIds, decoded.pack.objectIds);
      assert.equal(recovered.pack?.packBytesRef, retained.pack.packBytesRef);
      assert.equal(recovered.pack?.packIndexBytesRef, retained.pack.packIndexBytesRef);
      assert(!recovered.closure.reachableObjectIds.includes(excluded));
      // Full retained bytes and schemas are data; reopening must never mint
      // the fresh trusted-Git preparation, native source or Run authority.
      assert.deepEqual(Object.keys(recovered).sort(), ['closure', 'config', 'index', 'manifest', 'manifestRef', 'pack']);
      await assert.rejects(readPrivateGitData(reopened, retained.privateGitStateRef,
        { repositoryIdentityDigest: 'b'.repeat(64), resources: DEFAULT_SANDBOX_RESOURCES }), { code: 'ARTIFACT_MISMATCH' });
      const badPackIndex = Buffer.from(await artifacts.readBytes(retained.pack.packIndexBytesRef));
      // The outer CAS hash and index checksum both remain correct. The fixed
      // impossible fanout still has to fail against the real object inventory.
      const hashSize = format === 'sha1' ? 20 : 32;
      badPackIndex.writeUInt32BE(0xffffffff, 8);
      createHash(format).update(badPackIndex.subarray(0, -hashSize)).digest().copy(badPackIndex, badPackIndex.length - hashSize);
      const badBytes = await artifacts.publishBytes(badPackIndex, 'application/octet-stream', 'own-invalid-pack-index-data');
      const badPack = { ...retained.pack, packIndexBytesRef: badBytes.ref, packIndexBytesDigest: badBytes.ref, packDigest: '' };
      badPack.packDigest = digestOmitting(badPack, 'packDigest');
      const badPackArtifact = await artifacts.publishCanonical(badPack, badPack.format);
      const badClosure = { ...retained.closure, packs: [{ ...retained.closure.packs[0]!, packRef: badPackArtifact.ref,
        packDigest: badPack.packDigest }], closureDigest: '' };
      badClosure.closureDigest = digestOmitting(badClosure, 'closureDigest');
      const badClosureArtifact = await artifacts.publishCanonical(badClosure, badClosure.format);
      const badManifest = { ...retained.manifest, objectClosureRef: badClosureArtifact.ref,
        objectClosureDigest: badClosure.closureDigest, manifestDigest: '' };
      badManifest.manifestDigest = digestOmitting(badManifest, 'manifestDigest');
      const badManifestArtifact = await artifacts.publishCanonical(badManifest, badManifest.format);
      await assert.rejects(readPrivateGitData(reopened, badManifestArtifact.ref,
        { repositoryIdentityDigest: 'a'.repeat(64), resources: DEFAULT_SANDBOX_RESOURCES }), { code: 'ARTIFACT_MISMATCH' });
      const abort = new AbortController(), cancellation = new Error('own retained Git read cancelled'); abort.abort(cancellation);
      await assert.rejects(readPrivateGitData(reopened, retained.privateGitStateRef,
        { repositoryIdentityDigest: 'a'.repeat(64), resources: DEFAULT_SANDBOX_RESOURCES }, abort.signal), error => error === cancellation);
      const ordinary = path.join(root, 'ordinary'), controlledHome = path.join(root, 'home'), state = path.join(root, 'state');
      for (const member of [path.join(ordinary, '.git'), path.join(ordinary, 'ignored', 'nested', '.git'), controlledHome, state])
        await mkdir(member, { recursive: true, mode: 0o700 });
      const ruleBytes = Buffer.from('*.txt\nignored/\n');
      for (const [name, bytes] of [['.gitignore', ruleBytes], ['file.txt', Buffer.from('tracked working tree edit\n')],
        ['untracked.txt', Buffer.from('ignored private payload\n')], ['keep.md', Buffer.from('ordinary source\n')]] as const)
        await writeFile(path.join(ordinary, name), bytes, { mode: 0o600 });
      // Existing physical projection seam plus retained-data rules only. These
      // fixtures still cannot create inspection/Run or execution authority.
      await artifacts.publishBytes(ruleBytes, 'text/plain; charset=utf-8', 'cliq-ignore-rule-source-v1');
      const rules = compileFrozenIgnoreRules([{ kind: 'gitignore', path: '.gitignore', bytes: ruleBytes }], 'a'.repeat(64));
      const ruleArtifact = await artifacts.publishCanonical(rules, rules.format), native = await loadNativeStateOwner();
      const lock = native.acquireLock(state, true), workspaceRoot = native.openWorkspaceRoot(ordinary), homeRoot = native.openWorkspaceRoot(controlledHome);
      try {
        const projection = await publishGitSourceProjection({ workspaceRoot, controlledHome: homeRoot, stateOwnerLock: lock,
          artifacts, workspaceIdentityDigest: 'b'.repeat(64), sourceIncludes: [], sourceExcludes: [],
          maxChangedPaths: 100, maxChangedBytes: 1_048_576, maxEntries: 100_000, maxBytes: 1_048_576, maxSingleFileBytes: 1_048_576,
          git: { privateGitStateRef: retained.privateGitStateRef, repositoryIdentityDigest: 'a'.repeat(64),
            resources: DEFAULT_SANDBOX_RESOURCES, frozenIgnoreRulesRef: ruleArtifact.ref } });
        const source = await artifacts.readCanonical<SourceManifest>(projection.baseWorkspaceManifestRef);
        const entries = await artifacts.readCanonical<WorkspaceEntryManifest>(source.entriesRef);
        assert.deepEqual(entries.entries.map(entry => entry.path), ['.gitignore', 'file.txt', 'keep.md']);
        assert.equal(source.git?.indexRef, retained.indexRef);
        assert.deepEqual(source.git?.head, { kind: 'symbolic', ref: 'refs/heads/main', objectId: commit });
        assert.equal(projection.privateGitStateRef, retained.privateGitStateRef);
        assert.equal(source.frozenIgnoreRulesRef, ruleArtifact.ref);
        // Admitted classification and the ready private index are independent
        // complete data graphs. This never installs a Run or native Git proof.
        const admittedBytes = Buffer.from(await artifacts.readBytes(retained.index.canonicalIndexBytesRef));
        Buffer.from(declared, 'hex').copy(admittedBytes, 12 + 40);
        const hashBytes = format === 'sha1' ? 20 : 32;
        createHash(format).update(admittedBytes.subarray(0, -hashBytes)).digest().copy(admittedBytes, admittedBytes.length - hashBytes);
        const admittedData = normalizeGitIndex(admittedBytes, format, { maxBytes: DEFAULT_SANDBOX_RESOURCES.maxSingleFileBytes, maxEntries: 100_000 });
        const admittedRaw = await artifacts.publishBytes(admittedData.canonicalBytes, 'application/octet-stream', 'cliq-git-index-bytes-v1');
        const admittedIndex = { ...retained.index, entries: admittedData.entries, canonicalIndexBytesRef: admittedRaw.ref,
          canonicalIndexBytesDigest: admittedRaw.ref, canonicalIndexByteCount: admittedData.canonicalBytes.length,
          indexTreeObjectId: admittedData.indexTreeObjectId, snapshotDigest: '' };
        admittedIndex.snapshotDigest = digestOmitting(admittedIndex, 'snapshotDigest');
        const admittedRef = (await artifacts.publishCanonical(admittedIndex, admittedIndex.format)).ref;
        const admitted: SourceManifest = { ...source, git: { ...source.git!, indexRef: admittedRef,
          indexTreeObjectId: admittedIndex.indexTreeObjectId }, manifestDigest: '' };
        admitted.manifestDigest = digestOmitting(admitted, 'manifestDigest');
        const baseRef = (await artifacts.publishCanonical(admitted, admitted.format)).ref;
        const frozen: WorkspaceStateManifest = { schemaVersion: 1, format: 'cliq-workspace-state-v1', runId: 'git-data-run',
          baseWorkspaceManifestRef: baseRef, entriesRef: source.entriesRef, privateGitStateRef: retained.privateGitStateRef,
          sourceProjectionDigest: source.sourceProjectionDigest, invalidatedEphemeralPaths: [], stateDigest: '' };
        frozen.stateDigest = digestOmitting(frozen, 'stateDigest');
        const frozenRef = (await artifacts.publishCanonical(frozen, frozen.format)).ref;
        const privateData = await loadFrozenPrivateGit(artifacts, admitted, frozen, rules, undefined, DEFAULT_SANDBOX_RESOURCES);
        assert(privateData?.requiresPreparation); assert.equal(privateData.index.snapshotDigest, retained.index.snapshotDigest);
        assert.notEqual(privateData.index.snapshotDigest, admittedIndex.snapshotDigest);
        const metadata = await artifacts.publishBytes(Buffer.from('new ignored data'), 'application/octet-stream', 'cliq-workspace-file-v1');
        const changedEntries = { ...entries, entries: [...entries.entries,
          { kind: 'file' as const, path: 'new.txt', mode: 0o644, size: metadata.byteLength, blobRef: metadata.ref }], treeDigest: '' };
        changedEntries.entryCount = changedEntries.entries.length; changedEntries.byteCount += metadata.byteLength;
        changedEntries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: changedEntries.entries });
        const changedEntriesRef = (await artifacts.publishCanonical(changedEntries, changedEntries.format)).ref;
        const changed = { ...frozen, entriesRef: changedEntriesRef, stateDigest: '' }; changed.stateDigest = digestOmitting(changed, 'stateDigest');
        const changedRef = (await artifacts.publishCanonical(changed, changed.format)).ref;
        const profile = installedSandboxProfile(), profileRef = (await artifacts.publishCanonical(profile, profile.format)).ref;
        // Only retained-data planning consumes these three fields, no Store or
        // execution API receives this deliberately partial data fixture.
        const dataSpec = { baseWorkspaceManifestRef: baseRef, sourceProjectionRef: admitted.sourceProjectionRef,
          sandboxProfileRef: profileRef } as RunSpec;
        const candidate = await readCandidateSource(artifacts, dataSpec, changedRef);
        assert.deepEqual(candidate.source.git, admitted.git);
        const selected = await artifacts.readCanonical<WorkspaceEntryManifest>(candidate.source.entriesRef);
        assert.deepEqual(selected.entries.map(entry => entry.path), ['.gitignore', 'file.txt', 'keep.md']);
        const movedIndexBytes = Buffer.from(admittedData.canonicalBytes);
        Buffer.from('drop.txt').copy(movedIndexBytes, 12 + 40 + hashBytes + 2);
        createHash(format).update(movedIndexBytes.subarray(0, -hashBytes)).digest().copy(movedIndexBytes, movedIndexBytes.length - hashBytes);
        const movedIndex = normalizeGitIndex(movedIndexBytes, format, { maxBytes: profile.resources.maxSingleFileBytes, maxEntries: 100_000 });
        const movedRaw = await artifacts.publishBytes(movedIndex.canonicalBytes, 'application/octet-stream', 'cliq-git-index-bytes-v1');
        const moved = { ...admittedIndex, entries: movedIndex.entries, canonicalIndexBytesRef: movedRaw.ref, canonicalIndexBytesDigest: movedRaw.ref,
          canonicalIndexByteCount: movedIndex.canonicalBytes.length, indexTreeObjectId: movedIndex.indexTreeObjectId, snapshotDigest: '' };
        moved.snapshotDigest = digestOmitting(moved, 'snapshotDigest');
        const movedRef = (await artifacts.publishCanonical(moved, moved.format)).ref;
        const capturedA = { ...source, git: { ...source.git!, indexRef: movedRef, indexTreeObjectId: moved.indexTreeObjectId }, manifestDigest: '' };
        capturedA.manifestDigest = digestOmitting(capturedA, 'manifestDigest');
        const capturedARef = (await artifacts.publishCanonical(capturedA, capturedA.format)).ref;
        const classification = await readSourceProjectionData(artifacts, capturedA,
          await artifacts.readCanonical(capturedA.sourceProjectionRef), profile.resources);
        assert.equal(classification.index!.entries[0]!.canonicalRootRelativePath, 'drop.txt');
        assert.equal(classification.classificationIndex!.entries[0]!.canonicalRootRelativePath, 'file.txt');
        assert(classification.includes({ kind: 'file', path: 'file.txt', mode: 0o644, size: 0, blobRef: movedRaw.ref }));
        assert(!classification.includes({ kind: 'file', path: 'drop.txt', mode: 0o644, size: 0, blobRef: movedRaw.ref }));
        const observed = await captureFrozenSourceProjection({ workspaceRoot, controlledHome: homeRoot, stateOwnerLock: lock,
          artifacts, workspaceIdentityDigest: source.workspaceIdentityDigest, sourceProjectionRef: source.sourceProjectionRef,
          sourceProjectionDigest: source.sourceProjectionDigest, maxEntries: 100_000, maxBytes: 1_048_576, maxSingleFileBytes: 1_048_576,
          git: { capturedSourceRef: capturedARef, classificationSourceRef: baseRef, resources: DEFAULT_SANDBOX_RESOURCES } });
        assert.equal(observed.resultWorkspaceManifestRef, canonicalSha256({ ...capturedA, role: 'result',
          manifestDigest: digestOmitting({ ...capturedA, role: 'result' }, 'manifestDigest') }));
        const checkpoint: Checkpoint = { schemaVersion: 1, id: 'git-data-checkpoint', runId: frozen.runId,
          basedOnRunRevision: 0, runItemSeq: 0, journalSeq: 0, contextManifestRef: metadata.ref, workspaceStateRef: frozenRef,
          reason: 'initial', createdAt: '2026-10-08T00:00:00.000Z' };
        const materialization = createRunWorkspaceMaterialization({ filesystem: lock, artifacts, checkpoint, gitResources: profile.resources });
        try {
          const birth = await materialization.birth(), identity = readRunWorkspaceBirth(lock, birth);
          const input = readRunWorkspacePreparingGit(lock, birth)!;
          assert.equal(input.privateGitStateRef, retained.privateGitStateRef);
          assert.equal(input.metadataRef, canonicalSha256(decoded));
          await assert.rejects(materialization.finish(), { code: 'RECOVERY_REQUIRED' });
          assert.deepEqual(await readdir(path.join(state, 'runs', frozen.runId, 'generations', identity.generationId)), [],
            'correct retained Git data alone cannot copy even one generation payload byte');
        } finally { await materialization.close(); }
      } finally { workspaceRoot.close(); homeRoot.close(); lock.close(); }
    }
    assert.equal(joined, children, 'all own host-fixture and helper data child processes and pipes must close');
  } finally { await rm(directory, { recursive: true, force: true }); }
});
