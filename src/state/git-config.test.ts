import assert from 'node:assert/strict';
import { test } from 'node:test';

import { digestOmitting } from '../kernel/identity.js';
import type { SanitizedGitConfigV1 } from '../kernel/types.js';
import { decodeSanitizedGitConfig, parseSanitizedGitConfig } from './git-config.js';

const sha256Config = `[core]
  repositoryformatversion = 1
  filemode = true
  bare = false
  logallrefupdates = true
  ignorecase = true
  precomposeunicode = true
[extensions]
  objectformat = sha256
`;

test('strict Git config parser retains only canonical non-executable values', () => {
  const parsed = parseSanitizedGitConfig(Buffer.from(sha256Config));
  assert.deepEqual(parsed.core, {
    repositoryFormatVersion: 1, fileMode: true, bare: false,
    logAllRefUpdates: true, ignoreCase: true, precomposeUnicode: true
  });
  assert.deepEqual(parsed.extensions, { objectFormat: 'sha256' });
  assert.deepEqual(decodeSanitizedGitConfig(parsed), parsed);
  const equivalent = parseSanitizedGitConfig(Buffer.from(
    `; harmless comment\r\n[CORE]\r\nFILEMODE=TRUE\r\nBARE=FALSE\r\nREPOSITORYFORMATVERSION=1\r\n` +
    `LOGALLREFUPDATES=TRUE\r\nIGNORECASE=TRUE\r\nPRECOMPOSEUNICODE=TRUE\r\n[EXTENSIONS]\r\nOBJECTFORMAT=sha256\r\n`
  ));
  assert.deepEqual(equivalent, parsed);
});

test('Git config parser rejects executable, external and ambiguous settings before use', () => {
  const base = '[core]\nrepositoryformatversion=0\nfilemode=true\nbare=false\n';
  for (const unsafe of [
    'hookspath=/tmp/hooks\n', 'fsmonitor=true\n', 'sshcommand=ssh\n',
    'worktree=/tmp/outside\n', 'excludesfile=/tmp/ignore\n', 'attributesfile=/tmp/attributes\n',
    'filemode=true\n', 'bare=true\n', 'filemode=yes\n', 'filemode\n',
    'filemode="true"\n', 'filemode=true # comment\n', 'filemode=tr\\\nue\n'
  ]) {
    assert.throws(() => parseSanitizedGitConfig(Buffer.from(base + unsafe)), /Git config/);
  }
  for (const invalid of ['filemode=yes', 'bare=true', 'repositoryformatversion=2']) {
    assert.throws(() => parseSanitizedGitConfig(Buffer.from(`[core]\n${invalid}\n`)), /Git config/);
  }
  for (const section of [
    '[include]\npath=/tmp/config\n', '[includeIf "gitdir:~/"]\npath=/tmp/config\n',
    '[remote "origin"]\nurl=https://example.com/repo\n', '[alias]\nx=!sh\n',
    '[filter "lfs"]\nprocess=git-lfs\n', '[core "subsection"]\nfilemode=true\n'
  ]) {
    assert.throws(() => parseSanitizedGitConfig(Buffer.from(base + section)), /Git config/);
  }
  assert.throws(() => parseSanitizedGitConfig(Buffer.from(base + '[extensions]\nobjectformat=sha256\n')),
    /unsupported extension/);
  for (const bytes of [Buffer.alloc(0), Buffer.from([0xef, 0xbb, 0xbf, 0x61]),
    Buffer.from([0xff]), Buffer.from(base + '\0'), Buffer.from(base + '\r'),
    Buffer.alloc(1024 * 1024 + 1, 0x61)]) {
    assert.throws(() => parseSanitizedGitConfig(bytes), /Git config/);
  }
});

test('sanitized Git config decoder rejects rehashed unknown and ill-typed fields', () => {
  const valid = parseSanitizedGitConfig(Buffer.from(sha256Config));
  const rehash = (change: (config: SanitizedGitConfigV1) => void): SanitizedGitConfigV1 => {
    const config = structuredClone(valid);
    change(config);
    config.configDigest = digestOmitting(config, 'configDigest');
    return config;
  };
  assert.throws(() => decodeSanitizedGitConfig(rehash((value) => {
    Object.assign(value.core, { hooksPath: '/tmp/hooks' });
  })), /closed schema/);
  assert.throws(() => decodeSanitizedGitConfig(rehash((value) => {
    Object.assign(value, { remote: 'origin' });
  })), /closed schema/);
  assert.throws(() => decodeSanitizedGitConfig(rehash((value) => {
    value.core.bare = true as false;
  })), /unsupported core value/);
  assert.throws(() => decodeSanitizedGitConfig(rehash((value) => {
    value.core.repositoryFormatVersion = 0;
  })), /unsupported extension/);
  assert.throws(() => decodeSanitizedGitConfig({ ...valid, extensions: undefined }), /closed schema/);
  assert.throws(() => decodeSanitizedGitConfig({ ...valid, configDigest: '0'.repeat(64) }), /digest/);
});
