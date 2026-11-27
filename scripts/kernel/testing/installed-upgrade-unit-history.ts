// Qualification-only retention of the original systemd records through Stop.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import type { CredentialSecretScanner } from './credential-secret-scan.js';

export async function withUpgradeUnitHistory(input: { executable: string; args: readonly string[];
  cwd: string; env: NodeJS.ProcessEnv; scanner: CredentialSecretScanner }, body: () => Promise<void>) {
  const stdout = input.scanner.openStream(); let stderr: ReturnType<CredentialSecretScanner['openStream']>;
  try { stderr = input.scanner.openStream(); } catch (error) { stdout.close(); throw error; }
  let child;
  try { child = spawn(input.executable, [...input.args], { cwd: input.cwd, env: input.env, stdio: ['pipe', 'pipe', 'pipe'] }); }
  catch (error) { stdout.close(); stderr.close(); throw error; }
  const retained = 'systemd_units_retained\n', released = retained + 'systemd_units_released\n';
  let output = '', errorCount = 0, failure: unknown, releasing = false;
  let readyResolve!: () => void, readyReject!: (error: unknown) => void;
  const ready = new Promise<void>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const refuse = (error: unknown) => { failure ??= error; readyReject(error); };
  child.stdin.on('error', refuse); child.stdout.on('error', refuse); child.stderr.on('error', refuse);
  child.stdout.on('data', (bytes: Buffer) => { try {
    stdout.scan(bytes); output += bytes.toString('utf8'); assert(Buffer.byteLength(output) <= 1024 && released.startsWith(output));
    assert(releasing || output.length <= retained.length); if (output === retained) readyResolve();
  } catch (error) { refuse(error); } });
  child.stderr.on('data', (bytes: Buffer) => { try { stderr.scan(bytes); errorCount += bytes.length; assert(errorCount <= 1024); }
    catch (error) { refuse(error); } });
  const joined = new Promise<void>((resolve, reject) => {
    child.once('error', error => { refuse(error); reject(error); });
    child.once('close', (code, signal) => {
      try { stdout.close(); } catch (error) { refuse(error); }
      try { stderr.close(); } catch (error) { refuse(error); }
      if (code !== 0 || signal || failure || output !== released || errorCount !== 0) { const error = failure ?? new Error('unit-history observer did not join'); refuse(error); reject(error); }
      else resolve(); });
  });
  // Observe this rejection immediately; it still must join below.
  void joined.catch(() => {});
  const timer = setTimeout(() => { refuse(new Error('unit-history retained frame exceeded its original ten seconds')); child.kill('SIGKILL'); }, 10000);
  let primary: unknown;
  try { await ready; clearTimeout(timer); await body(); }
  catch (error) { primary = error; }
  finally {
    clearTimeout(timer); releasing = true; child.stdin.end('R');
    const by = setTimeout(() => child.kill('SIGKILL'), 10000);
    try { await joined; } catch (error) { primary = primary === undefined ? error : new AggregateError([primary, error]); }
    finally { clearTimeout(by); }
  }
  if (primary) throw primary;
}
