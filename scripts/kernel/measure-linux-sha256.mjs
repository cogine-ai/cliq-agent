// Data-only ABBA observation. Neither algorithm speed nor these opaque bytes
// qualify installed authentication, execution, READY or any other deadline.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

assert.equal(process.platform, 'linux');
const source = await readFile(new URL('../../native/linux/worker-sha256.h', import.meta.url), 'utf8');
const hint = '    /* Keep the four schedule vectors in registers at the baseline -O2 build.\n' +
  '     * The fixed rounds, CPUID gate and portable fallback are unchanged. */\n    #pragma GCC unroll 16\n';
assert.equal(source.split(hint).length, 2);
const baseline = source.replace(hint, '');
// Exact pre-change implementation, not a weakened reference algorithm.
assert.equal(createHash('sha256').update(baseline).digest('hex'), '6235d75c95adbc1ec64ee186c00d6699828403dc53b53b84e67a655a7dc30047');
const vectors = await readFile(new URL('../../native/linux/worker-sha256.test.c', import.meta.url));
const program = `#define _POSIX_C_SOURCE 200809L
#include "worker-sha256.h"
#include <stdio.h>
#include <time.h>
int main(void) {
  uint8_t bytes[65536], digest[32]; struct sha256_context hash; struct timespec start, end;
  for (size_t i=0;i<sizeof(bytes);i++) bytes[i]=(uint8_t)i;
  clock_gettime(CLOCK_MONOTONIC,&start); sha256_init(&hash);
  for (int i=0;i<1024;i++) sha256_update(&hash,bytes,sizeof(bytes));
  sha256_final(&hash,digest); clock_gettime(CLOCK_MONOTONIC,&end);
  printf("{\\"hardware\\":%d,\\"bytes\\":67108864,\\"elapsedMs\\":%.3f,\\"digest\\":\\"",hash.use_x86_sha,
    (end.tv_sec-start.tv_sec)*1000.0+(end.tv_nsec-start.tv_nsec)/1000000.0);
  for (size_t i=0;i<sizeof(digest);i++) printf("%02x",digest[i]);
  puts("\\"}"); return 0;
}
`;
const staging = await mkdtemp(path.join(os.tmpdir(), 'cliq-sha-cost-'));
function run(executable, args) {
  const result = spawnSync(executable, args, { encoding: 'utf8', maxBuffer: 1_048_576 });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}
try {
  for (const [name, header] of [['baseline', baseline], ['unrolled', source]]) {
    const directory = path.join(staging, name); await mkdir(directory);
    await writeFile(path.join(directory, 'worker-sha256.h'), header);
    await writeFile(path.join(directory, 'vectors.c'), vectors);
    await writeFile(path.join(directory, 'cost.c'), program);
    for (const file of ['vectors', 'cost']) run('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      path.join(directory, `${file}.c`), '-o', path.join(directory, file)]);
    const result = run(path.join(directory, 'vectors'), []);
    assert.match(result, /^sha256_backends=portable(?:_and_sha_ni)?$/u);
  }
  const rows = [];
  for (const variant of ['baseline', 'unrolled', 'unrolled', 'baseline']) {
    const result = JSON.parse(run(path.join(staging, variant, 'cost'), []));
    assert.equal(result.bytes, 67_108_864);
    assert.equal(result.digest, '281e519df3077b557c6b03f5da83c4e8d397219259615dd7c3308f89cae8f2a6');
    assert([0, 1].includes(result.hardware)); assert(Number.isFinite(result.elapsedMs) && result.elapsedMs > 0);
    rows.push({ variant, ...result });
  }
  console.log(JSON.stringify({ diagnosticOnly: true, installedQualified: false, architecture: process.arch,
    compiler: run('cc', ['--version']).split('\n')[0], rows, processesAndPipesJoined: true }));
} finally { await rm(staging, { recursive: true, force: true }); }
