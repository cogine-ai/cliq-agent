import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const packageNames = [
  '01-durable-state-and-migration.md',
  '02-typed-runtime-and-provider-capabilities.md',
  '03-trusted-execution-and-workspaces.md',
  '04-detached-supervisor-and-control-protocol.md',
  '05-agentic-verification-and-recovery.md',
  '06-ecosystem-surfaces-and-kernel-cutover.md',
];

function checkFixture(canonical, copied) {
  const fixture = mkdtempSync(path.join(os.tmpdir(), 'cliq-design-contracts-'));
  const write = (relative, content) => {
    const target = path.join(fixture, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  };
  const fence = (source) => `\n\x60\x60\x60ts\n${source}\n\x60\x60\x60\n`;
  try {
    write('docs/rfcs/2026-08-11-durable-verified-run-kernel.md', fence(canonical));
    for (const name of packageNames) write(`docs/backlog/durable-verified-run-kernel/${name}`, '# Fixture\n');
    write(`docs/backlog/durable-verified-run-kernel/${packageNames[0]}`, fence(copied));
    write(`docs/backlog/durable-verified-run-kernel/${packageNames[2]}`, fence('type BrokerRequest = unknown'));
    write(`docs/backlog/durable-verified-run-kernel/${packageNames[5]}`, fence([
      'type RuntimeBundleStructuredArtifactBaseV1 = unknown',
      'type RuntimeBundleStructuredArtifactV1 = unknown',
      'type RuntimeBundleManifest = unknown',
    ].join('\n')));
    const script = 'scripts/kernel/check-design-contracts.mjs';
    mkdirSync(path.join(fixture, 'scripts/kernel'), { recursive: true });
    copyFileSync(path.join(root, script), path.join(fixture, script));
    mkdirSync(path.join(fixture, 'node_modules'));
    symlinkSync(path.join(root, 'node_modules/typescript'), path.join(fixture, 'node_modules/typescript'), 'junction');
    return spawnSync(process.execPath, [path.join(fixture, script)], { encoding: 'utf8', timeout: 10_000 });
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}

test('design guard accepts equivalent formatting, comments and string quoting', () => {
  const result = checkFixture(
    "type Example = { status: 'pending'; requestId: string }",
    'type Example = {\n // retained binding\n status: "pending"\n requestId: string\n}',
  );
  assert.equal(result.status, 0, result.error?.message ?? result.stderr);
  assert.match(result.stdout, /1 shared copies checked; no drift/);
});

for (const [name, canonical, copied] of [
  ['missing identity binding', 'type Example = { requestId: string; channel: string }', 'type Example = { channel: string }'],
  ['optionalized identity binding', 'type Example = { requestId: string }', 'type Example = { requestId?: string }'],
  ['changed discriminator', "type Example = { source: 'invocation' }", "type Example = { source: 'user_input' }"],
  ['changed type operator', 'type Example = readonly string[]', 'type Example = keyof string[]'],
  ['changed template prefix', 'type Example = `sha-${string}`', 'type Example = `other-${string}`'],
  ['changed template suffix', 'type Example = `${string}-v1`', 'type Example = `${string}-v2`'],
]) {
  test(`design guard rejects ${name}`, () => {
    const result = checkFixture(canonical, copied);
    assert.equal(result.status, 1, result.error?.message ?? result.stderr);
    assert.match(result.stderr, /Example differs from docs\/rfcs\//);
  });
}

test('design guard rejects conflicting repeated definitions even if the last matches', () => {
  const result = checkFixture('type Example = string', 'type Example = number\ntype Example = string');
  assert.equal(result.status, 1, result.error?.message ?? result.stderr);
  assert.match(result.stderr, /conflicting repeated definition of Example/);
});

test('design guard rejects malformed schema syntax', () => {
  const result = checkFixture('type Example = string', 'type Example = { value: }');
  assert.equal(result.status, 1, result.error?.message ?? result.stderr);
  assert.match(result.stderr, /Type expected/);
});
