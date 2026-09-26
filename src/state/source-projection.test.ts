import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { digestOmitting } from '../kernel/identity.js';
import type { FrozenIgnoreRulesV1, SourceProjectionSpec } from '../kernel/types.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { decodeFrozenIgnoreRules, decodeSourceProjection } from './decoders.js';
import { parseFrozenIgnoreSourceBytes, validateFrozenIgnoreSourceBytes } from './frozen-ignore-sources.js';

const REF = 'a'.repeat(64);

function rehashRules(change: (rules: FrozenIgnoreRulesV1) => void): FrozenIgnoreRulesV1 {
  const rules: FrozenIgnoreRulesV1 = {
    schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1',
    matcherVersion: 'cliq-git-wildmatch-v1', repositoryIdentityDigest: REF,
    sources: [{ index: 0, kind: 'git_info_exclude', canonicalRootRelativePath: '.git/info/exclude',
      baseDirectory: '', contentRef: REF, contentDigest: REF },
    { index: 1, kind: 'gitignore', canonicalRootRelativePath: '.gitignore',
      baseDirectory: '', contentRef: REF, contentDigest: REF },
    { index: 2, kind: 'gitignore', canonicalRootRelativePath: 'src/.gitignore',
      baseDirectory: 'src', contentRef: REF, contentDigest: REF }],
    rules: [{ order: 0, sourceIndex: 1, sourceLine: 2, baseDirectory: '',
      negated: false, directoryOnly: false, anchored: false, pattern: '*.log' },
    { order: 1, sourceIndex: 2, sourceLine: 1, baseDirectory: 'src',
      negated: true, directoryOnly: false, anchored: false, pattern: 'keep.log' }],
    rulesDigest: ''
  };
  change(rules);
  rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
  return rules;
}

function rehashProjection(change: (spec: SourceProjectionSpec) => void): SourceProjectionSpec {
  const spec: SourceProjectionSpec = {
    schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1',
    frozenIgnoreRulesRef: REF, frozenIgnoreRulesDigest: REF,
    explicitIncludes: [{ path: 'src/input.txt', scope: 'entry', authorizationRef: REF }],
    explicitExcludes: [{ path: 'build', scope: 'subtree' }],
    maxChangedPaths: 10_000, maxChangedBytes: 512 * 1024 * 1024,
    projectionDigest: ''
  };
  change(spec);
  spec.projectionDigest = digestOmitting(spec, 'projectionDigest');
  return spec;
}

test('frozen ignore rules require a closed repository-bound source and ordered rule graph', () => {
  assert.deepEqual(decodeFrozenIgnoreRules(rehashRules(() => {})), rehashRules(() => {}));
  assert.throws(() => decodeFrozenIgnoreRules(rehashRules((rules) => {
    Object.assign(rules, { injected: true });
  })), /closed schema/);
  assert.throws(() => decodeFrozenIgnoreRules(rehashRules((rules) => {
    rules.sources[1]!.index = 4;
  })), /indices must be contiguous/);
  assert.throws(() => decodeFrozenIgnoreRules(rehashRules((rules) => {
    rules.sources[2]!.canonicalRootRelativePath = '../src/.gitignore';
  })), /canonical in-root path/);
  assert.throws(() => decodeFrozenIgnoreRules(rehashRules((rules) => {
    rules.sources[2]!.baseDirectory = '';
  })), /base directory/);
  assert.throws(() => decodeFrozenIgnoreRules(rehashRules((rules) => {
    rules.rules[1]!.sourceIndex = 0;
    rules.rules[1]!.baseDirectory = '';
  })), /source and line order/);
  assert.throws(() => decodeFrozenIgnoreRules(rehashRules((rules) => {
    rules.sources[1]!.contentDigest = 'b'.repeat(64);
  })), /differs from its CAS ref/);
  assert.throws(() => decodeFrozenIgnoreRules(rehashRules((rules) => {
    delete rules.repositoryIdentityDigest;
  })), /non-Git.*empty/);
});

test('source projection rejects rehashed selectors outside the root and widened ceilings', () => {
  assert.deepEqual(decodeSourceProjection(rehashProjection(() => {})), rehashProjection(() => {}));
  for (const badPath of ['../outside', '/absolute', 'a//b', '.git/config', '.GiT/config', 'a/./b', 'e\u0301']) {
    assert.throws(() => decodeSourceProjection(rehashProjection((spec) => {
      spec.explicitIncludes[0]!.path = badPath;
    })), /canonical in-root path/);
  }
  assert.throws(() => decodeSourceProjection(rehashProjection((spec) => {
    spec.explicitExcludes.push({ path: 'build', scope: 'subtree' });
  })), /duplicate selector/);
  assert.throws(() => decodeSourceProjection(rehashProjection((spec) => {
    spec.maxChangedBytes = 4 * 1024 * 1024 * 1024 + 1;
  })), /ceilings/);
  assert.throws(() => decodeSourceProjection(rehashProjection((spec) => {
    Object.assign(spec.explicitIncludes[0]!, { readGrantId: 'caller-controlled' });
  })), /closed schema/);
});

test('fixed ignore parser preserves Git line, escape, anchor, and directory syntax', () => {
  const source: FrozenIgnoreRulesV1['sources'][number] = {
    index: 2, kind: 'gitignore', canonicalRootRelativePath: 'src/.gitignore',
    baseDirectory: 'src', contentRef: REF, contentDigest: REF
  };
  const bytes = Buffer.from('\uFEFF# comment\r\n\nfoo  \r\n\\#literal\n\\!bang\n!*.tmp\nbuild/\n/src/**/test?.[ch]\nends\\ \n!\nonly-no-lf');
  assert.deepEqual(parseFrozenIgnoreSourceBytes(bytes, source, 3), [
    { order: 3, sourceIndex: 2, sourceLine: 3, baseDirectory: 'src', negated: false,
      directoryOnly: false, anchored: false, pattern: 'foo' },
    { order: 4, sourceIndex: 2, sourceLine: 4, baseDirectory: 'src', negated: false,
      directoryOnly: false, anchored: false, pattern: '\\#literal' },
    { order: 5, sourceIndex: 2, sourceLine: 5, baseDirectory: 'src', negated: false,
      directoryOnly: false, anchored: false, pattern: '\\!bang' },
    { order: 6, sourceIndex: 2, sourceLine: 6, baseDirectory: 'src', negated: true,
      directoryOnly: false, anchored: false, pattern: '*.tmp' },
    { order: 7, sourceIndex: 2, sourceLine: 7, baseDirectory: 'src', negated: false,
      directoryOnly: true, anchored: false, pattern: 'build' },
    { order: 8, sourceIndex: 2, sourceLine: 8, baseDirectory: 'src', negated: false,
      directoryOnly: false, anchored: true, pattern: 'src/**/test?.[ch]' },
    { order: 9, sourceIndex: 2, sourceLine: 9, baseDirectory: 'src', negated: false,
      directoryOnly: false, anchored: false, pattern: 'ends\\ ' },
    { order: 10, sourceIndex: 2, sourceLine: 11, baseDirectory: 'src', negated: false,
      directoryOnly: false, anchored: false, pattern: 'only-no-lf' }
  ]);
  assert.equal(parseFrozenIgnoreSourceBytes(Buffer.from('foo/bar\n'), source)[0]?.anchored, true);
  assert.equal(parseFrozenIgnoreSourceBytes(Buffer.from('\uFEFF\uFEFFname'), source)[0]?.pattern,
    '\uFEFFname');
});

test('retained ignore source bytes must reparse to the exact rule graph', async (t) => {
  const directory = await mkdtemp(path.join(process.cwd(), '.cliq-ignore-sources-'));
  t.after(async () => { await rm(directory, { recursive: true, force: true }); });
  const casRoot = path.join(directory, 'cas');
  await mkdir(casRoot, { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(casRoot));
  const valid = await artifacts.publishBytes(Buffer.from('*.log\n'), 'text/plain; charset=utf-8', 'cliq-frozen-ignore-source-v1');
  const rules = rehashRules((value) => {
    value.sources = [{ index: 0, kind: 'gitignore', canonicalRootRelativePath: '.gitignore',
      baseDirectory: '', contentRef: valid.ref, contentDigest: valid.ref }];
    value.rules = [{ order: 0, sourceIndex: 0, sourceLine: 1, baseDirectory: '',
      negated: false, directoryOnly: false, anchored: false, pattern: '*.log' }];
  });
  await validateFrozenIgnoreSourceBytes(artifacts, decodeFrozenIgnoreRules(rules));
  const repeatedSource = rehashRules((value) => {
    value.sources = [rules.sources[0]!, {
      ...rules.sources[0]!, index: 1, canonicalRootRelativePath: 'src/.gitignore', baseDirectory: 'src'
    }];
    value.rules = [rules.rules[0]!, {
      ...rules.rules[0]!, order: 1, sourceIndex: 1, baseDirectory: 'src'
    }];
  });
  await validateFrozenIgnoreSourceBytes(artifacts, decodeFrozenIgnoreRules(repeatedSource));
  const forged = rehashRules((value) => {
    value.sources = rules.sources;
    value.rules = [{ ...rules.rules[0]!, pattern: '*.secret' }];
  });
  await assert.rejects(validateFrozenIgnoreSourceBytes(artifacts, decodeFrozenIgnoreRules(forged)),
    /differ from retained source bytes/);

  for (const bytes of [Buffer.from([0xff]), Buffer.from('a\0b')]) {
    const bad = await artifacts.publishBytes(bytes, 'text/plain; charset=utf-8', 'cliq-frozen-ignore-source-v1');
    const malformed = rehashRules((value) => {
      value.sources = [{ index: 0, kind: 'gitignore', canonicalRootRelativePath: '.gitignore',
        baseDirectory: '', contentRef: bad.ref, contentDigest: bad.ref }];
      value.rules = [];
    });
    await assert.rejects(validateFrozenIgnoreSourceBytes(artifacts, decodeFrozenIgnoreRules(malformed)),
      /NUL|UTF-8/);
  }
});
