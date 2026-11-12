// Explicit funded experiment only. The CI secret is a transport input, never
// an environment fallback for the product. The original installed auth entry
// still enrolls it into the actual same-user Secret Service.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJsonBytes } from '../../src/kernel/canonical.js';
import { decodeProviderJourneyConfiguration } from '../kernel/testing/provider-journey-input.js';

const READY = 'CLIQ_PROVIDER_SECRET_STDIN_READY_V1';
const OUTPUT_LIMIT = 8 * 1024 * 1024;

export function providerSelection(now: Date) {
  assert(Number.isFinite(now.getTime()));
  return decodeProviderJourneyConfiguration({
    budgets: { childConcurrency: 1, childDepth: 0, costMicros: 5_000_000, modelTokens: 20_000_000,
      repairAttempts: 2, toolCalls: 100, wallTimeMs: 300_000 },
    definition: { provider: 'openai-compatible', model: 'deepseek-flash',
      claims: { contextLimitTokens: 32768, maxOutputTokens: 8192, nativeToolCalling: true, streaming: false, trustedUsageEvidence: false },
      prices: { cacheRead: 6000, cacheWrite: 0, input: 300000, output: 1200000 },
      requestTokenCeiling: { cacheReadTokens: 1048576, cacheWriteTokens: 0, inputTokens: 1048576, outputTokens: 393216 },
      target: { basePath: '/', hostAscii: 'api.deepseek.com', port: 443 },
      tls: { serverNameAscii: 'api.deepseek.com', spkiSha256Pins: ['2ac9550952cd8f9b7f7baeccd3a140e4d4ae76c0a721a4e5231975f652a1a836'] },
      validFrom: new Date(now.getTime() - 60_000).toISOString(),
      validThrough: new Date(now.getTime() + 4 * 60 * 60_000).toISOString() },
  });
}

/** Own the actual child and both pipes. No raw output is logged or persisted.
 * The sole private stdin write follows the original driver's exact marker. */
export async function runProviderProcess(command: string, args: readonly string[], secret: Buffer,
  environment: NodeJS.ProcessEnv, onPhase: (phase: string) => void = () => {}) {
  assert(secret.length > 0 && secret.length <= 4096 && !secret.includes(10) && !secret.includes(13));
  assert.equal(environment.CLIQ_PROVIDER_API_KEY, undefined);
  const child = spawn(command, [...args], { env: environment, stdio: ['pipe', 'pipe', 'pipe'], detached: true });
  const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => {
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  let failure = false, sent = false, outputBytes = 0, terminating = false;
  const buffers: [Buffer[], Buffer[]] = [[], []];
  let line = Buffer.alloc(0);
  const stop = () => {
    failure = true;
    if (terminating) return;
    terminating = true;
    if (child.pid) { try { process.kill(-child.pid, 'SIGTERM'); } catch { /* close remains mandatory */ } }
  };
  child.on('error', stop); child.stdin.on('error', stop);
  for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, stop);
  const collect = (chunk: Buffer, stdout: boolean) => {
    outputBytes += chunk.length;
    if (outputBytes > OUTPUT_LIMIT) { stop(); return; }
    buffers[stdout ? 0 : 1].push(Buffer.from(chunk));
    if (!stdout || failure) return;
    line = Buffer.concat([line, chunk]);
    for (;;) {
      const end = line.indexOf(10); if (end < 0) break;
      const bytes = line.subarray(0, end), current = bytes.toString('utf8'); line = line.subarray(end + 1);
      if (bytes.includes(secret)) { stop(); break; }
      if (current === READY) {
        if (sent) { stop(); break; }
        sent = true; child.stdin.end(secret);
      } else if (/^Installed daily journey phase [a-z_]+$/.test(current)) {
        try { onPhase(current); } catch { stop(); break; }
      }
    }
    if (line.length > 65536) stop();
  };
  child.stdout.on('data', chunk => collect(chunk, true));
  child.stderr.on('data', chunk => collect(chunk, false));
  child.stdout.on('error', stop); child.stderr.on('error', stop);
  try {
    const result = await closed;
    for (const stream of buffers) {
      const output = Buffer.concat(stream);
      try { if (output.includes(secret)) failure = true; } finally { output.fill(0); }
    }
    return { exitCode: result.code, signal: result.signal, privateInputSent: sent,
      processAndPipesJoined: true, outputBytes, outputRefused: failure,
      passed: !failure && sent && result.code === 0 && result.signal === null };
  } finally {
    for (const signal of ['SIGINT', 'SIGTERM'] as const) process.removeListener(signal, stop);
    for (const stream of buffers) for (const buffer of stream) buffer.fill(0); line.fill(0);
  }
}

async function main() {
  const secret = Buffer.from(process.env.CLIQ_PROVIDER_API_KEY ?? '');
  delete process.env.CLIQ_PROVIDER_API_KEY;
  try {
    assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
    assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
    assert.equal(process.env.GITHUB_EVENT_NAME, 'workflow_dispatch');
    assert.equal(process.env.GITHUB_REPOSITORY, 'cogine-ai/cliq-agent');
    const revision = process.env.CLIQ_PROVIDER_EXPECTED_REVISION;
    assert(revision && /^[a-f0-9]{40}$/.test(revision));
    assert.equal(revision, process.env.GITHUB_SHA);
    const git = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' });
    assert.equal(git.status, 0); assert.equal(git.stdout.trim(), revision);
    assert(secret.length > 0 && secret.length <= 4096);
    const root = process.env.RUNNER_TEMP; assert(root && path.isAbsolute(root));
    const configuration = path.join(root, 'cliq-provider-input.json');
    const output = path.join(root, 'cliq-installed-provider');
    // Fresh root-owned public bytes; fail rather than replace an existing name.
    const create = spawnSync('sudo', ['-n', 'python3', '-c',
      'import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400); data=sys.stdin.buffer.read(65537); assert 0<len(data)<=65536; f=os.fdopen(fd,"wb"); f.write(data); f.flush(); os.fsync(f.fileno()); f.close()', configuration],
    { input: canonicalJsonBytes(providerSelection(new Date())), timeout: 5000, maxBuffer: 65536 });
    assert.equal(create.status, 0);
    const report = await runProviderProcess('sudo', ['-n', '/bin/bash', 'scripts/kernel/qualify-systemd-user.sh',
      '--run-provider-daily-journey', configuration, process.execPath, output], secret, { ...process.env },
    phase => process.stdout.write(phase + '\n'));
    await writeFile(path.join(root, 'cliq-provider-invocation.json'), JSON.stringify({ format: 'cliq-funded-provider-ci-v1', revision,
      ...report, runCostCeilingUsdMicros: 5_000_000, experimentCeilingCny: 200, automaticRetries: 0,
      actualProviderBillingQualified: false }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    assert(report.passed);
  } finally { secret.fill(0); }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) void main().catch(() => {
  // Arbitrary provider/child diagnostics never become CI log output.
  process.stderr.write('Real-provider qualification refused; inspect the bounded original reports.\n'); process.exitCode = 1;
});
