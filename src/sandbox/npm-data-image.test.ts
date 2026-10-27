import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sha256Bytes } from '../kernel/identity.js';
import { encodeNpmDataImage, readNpmDataImage } from './npm-data-image.js';

const files = () => [
  { path: 'package.json', sourceMode: 0o644 as const, bytes: Buffer.from('{"name":"npm","version":"10.9.2"}') },
  { path: 'bin/npm-cli.js', sourceMode: 0o755 as const, bytes: Buffer.from('#!/usr/bin/env node\nrequire("../lib/cli.js")(process)\n') },
  { path: 'lib/cli.js', sourceMode: 0o644 as const, bytes: Buffer.from('module.exports = process => process.exit(0)\n') }
];
test('one npm data image preserves every source byte and mode with bounded exact EOF', () => {
  const input = files(), image = encodeNpmDataImage(input), data = readNpmDataImage(image);
  assert.equal(data.imageDigest, sha256Bytes(image)); assert.equal(data.files.length, input.length);
  assert.equal(data.expandedBytes, input.reduce((sum, file) => sum + file.bytes.length, 0));
  for (const file of data.files) {
    const original = input.find(item => item.path === file.path)!;
    assert.equal(file.sourceMode, original.sourceMode);
    assert(image.subarray(file.payloadOffset, file.payloadOffset + file.byteCount).equals(original.bytes));
  }
  assert.throws(() => readNpmDataImage(Buffer.concat([image, Buffer.alloc(1)])));
  assert.throws(() => readNpmDataImage(image.subarray(0, -1)));
  const changed = Buffer.from(image); changed[changed.length - 1] ^= 1;
  assert.throws(() => readNpmDataImage(changed));
});
test('npm data does not accept traversal, aliases, duplicate files or executable substitutions', () => {
  for (const path of ['../escape', '/absolute', 'a/../escape', '.git/config', 'a//b', 'a\\b', 'a/\ncontrol'])
    assert.throws(() => encodeNpmDataImage([...files(), { path, sourceMode: 0o644, bytes: Buffer.from('x') }]));
  assert.throws(() => encodeNpmDataImage([...files(), files()[0]!]));
  assert.throws(() => encodeNpmDataImage([...files(), { path: 'LIB/cli.js', sourceMode: 0o644, bytes: Buffer.from('alias') }]));
  assert.throws(() => encodeNpmDataImage([...files(), { path: 'LIB/other.js', sourceMode: 0o644, bytes: Buffer.from('directory alias') }]));
  assert.throws(() => encodeNpmDataImage([...files(), { path: 'lib', sourceMode: 0o644, bytes: Buffer.from('file parent') }]));
  assert.throws(() => encodeNpmDataImage(files().map(file => file.path === 'package.json' ?
    { ...file, bytes: Buffer.from('{"name":"npm","version":"other"}') } : file)));
  let reads = 0; const value = { ...files()[0]!, get bytes() { reads++; return Buffer.from('x'); } };
  assert.throws(() => encodeNpmDataImage([value, ...files().slice(1)])); assert.equal(reads, 0);
});
