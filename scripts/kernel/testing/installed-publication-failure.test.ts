import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { INSTALLED_STORE_DIAGNOSTIC_BANNER } from './installed-store-diagnostic-banner.js';
import { readInstalledPublicationFailureJournal } from './installed-store-diagnostic-journal.js';

test('the original publication refusal survives an abnormal exit before retirement joins', () => {
  // This ordinary child carries fixed diagnostic data only. It supplies no
  // Run, worker, original Supervisor identity or retirement proof.
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', INSTALLED_STORE_DIAGNOSTIC_BANNER + `
    const channel = require('node:diagnostics_channel').channel('cliq.installed.run.failures.v1');
    channel.publish({kind:'scheduler_failure',origin:'publication_recovery',phase:'publication_received_read',
      closing:false,errorClass:'kernel',code:'RECOVERY_REQUIRED',sqliteCode:null});
    channel.publish({kind:'scheduler_failure',origin:'publication_preparation',phase:'publication_received_read',
      closing:false,errorClass:'kernel',code:'RECOVERY_REQUIRED',sqliteCode:null});
    const refusal = {kind:'scheduler_failure',origin:'publication_preparation',phase:'publication_prepare_admit',
      closing:false,errorClass:'kernel',code:'LEASE_FENCED',sqliteCode:null};
    channel.publish(refusal); channel.publish(refusal);
    process.kill(process.pid, 'SIGKILL');
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 4096 });
  assert.equal(child.error, undefined); assert.equal(child.signal, 'SIGKILL');
  assert.equal(child.stdout, '');
  assert.equal(child.stderr, 'CLIQ_PUBLICATION_FAILURE_V1:publication_prepare_admit:0:kernel:LEASE_FENCED:-\n');
});

test('publication refusal decoding binds the original journal and rejects malformed classifications', () => {
  const sender = { uid: 1000, pid: 2000, invocationId: 'a'.repeat(32) };
  const message = 'CLIQ_PUBLICATION_FAILURE_V1:publication_prepare_admit:0:kernel:LEASE_FENCED:-';
  const journal = (messages: string[], pid = sender.pid) => messages.map(MESSAGE => JSON.stringify({
    _UID: String(sender.uid), _PID: String(pid), _TRANSPORT: 'stdout',
    _SYSTEMD_INVOCATION_ID: sender.invocationId, MESSAGE })).join('\n');
  assert.deepEqual(readInstalledPublicationFailureJournal(journal([message]), sender), {
    phase: 'publication_prepare_admit', closing: false, errorClass: 'kernel', code: 'LEASE_FENCED', sqliteCode: null,
  });
  assert.equal(readInstalledPublicationFailureJournal('', sender), undefined);
  assert.throws(() => readInstalledPublicationFailureJournal(journal([message], sender.pid + 1), sender));
  for (const rows of [[message, message], [message + ':extra'], [message.replace('kernel', 'secret')],
    [message.replace('LEASE_FENCED', 'unknown')], [message.replace('admit', 'unknown')],
    [message.replace('publication_prepare_admit', 'publication_received_read')],
    [message.replace(':0:', ':2:')], [message.replace(':-', ':1')]])
    assert.throws(() => readInstalledPublicationFailureJournal(journal(rows), sender));
});

