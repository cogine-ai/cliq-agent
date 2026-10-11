import test from 'node:test';
import assert from 'node:assert/strict';
import { checkedThreadCalls } from './credential-vfs-storage.js';

// Parser contracts only. These synthetic records never qualify physical I/O.
const exit = '1.000099 +++ exited with 0 +++\n';
const clone = '1.000001 clone(child_stack=NULL, flags=CLONE_THREAD|CLONE_FILES) = 101\n';
const read = '1.000002 pread64(17</fixed/original>, "proof", 5, 0) = 5\n';

test('closed thread corpus accepts completed calls and matching unfinished/resumed calls', () => {
  const calls = checkedThreadCalls([
    { tid: 100, raw: clone + read + exit },
    { tid: 101, raw: '1.000003 read(0<pipe:[7]>,  <unfinished ...>\n'
      + '1.000004 <... read resumed>"x", 1) = 1\n' + exit },
  ], 100);
  assert.deepEqual(calls.map(call => call.name), ['clone', 'pread64', 'read']);
  assert.equal(calls[2]!.start, 1000003000n); assert.equal(calls[2]!.end, 1000004000n);
});

test('closed thread corpus requires every created TID, even if it exited before an observed barrier', () => {
  assert.throws(() => checkedThreadCalls([{ tid: 100, raw: clone + exit }], 100), /created TID has no complete trace/);
  assert.throws(() => checkedThreadCalls([{ tid: 100, raw: exit }, { tid: 101, raw: exit }], 100), /unbound process\/TID/);
});

test('closed thread corpus rejects a process birth that does not share the owner FD table', () => {
  for (const birth of [clone.replace('CLONE_THREAD|CLONE_FILES', 'SIGCHLD'),
    '1.000001 fork() = 101\n', '1.000001 vfork() = 101\n']) {
    assert.throws(() => checkedThreadCalls([
      { tid: 100, raw: birth + exit },
    ], 100), /only threads sharing its FD table/);
  }
});

test('closed thread corpus rejects mismatched or incomplete resumed calls', () => {
  assert.throws(() => checkedThreadCalls([{ tid: 100, raw: '1.000001 <... read resumed>"x", 1) = 1\n' + exit }], 100), /unmatched resumed trace/);
  assert.throws(() => checkedThreadCalls([{ tid: 100, raw: '1.000001 read(0,  <unfinished ...>\n' + exit }], 100), /incomplete syscall/);
});

test('closed thread corpus rejects truncation at a complete syscall boundary', () => {
  assert.throws(() => checkedThreadCalls([{ tid: 100, raw: read }], 100), /terminal/);
});

test('closed thread corpus rejects duplicate termination or any record after termination', () => {
  assert.throws(() => checkedThreadCalls([{ tid: 100, raw: exit + exit }], 100), /terminal/);
  assert.throws(() => checkedThreadCalls([{ tid: 100, raw: exit + read }], 100), /terminal/);
});
