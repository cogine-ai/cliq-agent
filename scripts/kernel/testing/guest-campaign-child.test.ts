// Actual child/process/pipe ownership only; no guest, Run or native proof.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { joinGuestExtractionChild } from './guest-campaign-child.js';

test('the isolated extractor stage waits for original process and inherited pipe close', async () => {
  const child = spawn(process.execPath, ['-e', "setTimeout(()=>process.stdout.write('joined'),30)"], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; child.stdout!.on('data', bytes => { output += bytes.toString(); });
  await joinGuestExtractionChild(child);
  assert.equal(output, 'joined'); assert.equal(child.exitCode, 0); assert.equal(child.stdout!.destroyed, true);
});

test('a failed extractor child cannot become a successful stage', async () => {
  const child = spawn(process.execPath, ['-e', 'process.exitCode=7'], { stdio: ['ignore', 'pipe', 'pipe'] });
  await assert.rejects(joinGuestExtractionChild(child));
  assert.equal(child.exitCode, 7); assert.equal(child.stdout!.destroyed, true);
});

test('interruption retires the original child and never reports extraction success', async () => {
  const controller = new AbortController();
  const child = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise<void>((resolve, reject) => { child.once('spawn', resolve); child.once('error', reject); });
  const joined = assert.rejects(joinGuestExtractionChild(child, controller.signal));
  controller.abort(); await joined;
  assert.equal(child.signalCode, 'SIGTERM'); assert.equal(child.stdout!.destroyed, true);
});

test('a child that misses its close bound is really killed and joined but remains a failed stage', async () => {
  const controller = new AbortController();
  const child = spawn(process.execPath, ['-e', "process.on('SIGTERM',()=>{});process.stdout.write('ready');setInterval(()=>{},1000)"],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise<void>((resolve, reject) => { child.stdout!.once('data', () => resolve()); child.once('error', reject); });
  const joined = assert.rejects(joinGuestExtractionChild(child, controller.signal), /missed its close bound/u);
  controller.abort(); await joined;
  assert.equal(child.signalCode, 'SIGKILL'); assert.equal(child.stdout!.destroyed, true);
});

test('spawn failure joins its original stdio without claiming an extraction', async () => {
  const child = spawn('/nonexistent-owned-guest-campaign-child', [], { stdio: ['ignore', 'pipe', 'pipe'] });
  await assert.rejects(joinGuestExtractionChild(child), /failed to start/u);
  assert.equal(child.pid, undefined); assert.equal(child.stdout!.destroyed, true);
});
