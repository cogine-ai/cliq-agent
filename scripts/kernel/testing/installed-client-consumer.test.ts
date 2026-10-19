// Actual child-process JSONL transport only. These fixtures do not impersonate
// an installed Supervisor or qualify native authentication/execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { InstalledClientConsumerDeadlineError, InstalledClientDriverError, openInstalledClientConsumer,
  copyInstalledClientAuthenticationWork, installedClientAuthenticationMarker } from './installed-client-consumer.js';

const protocol = `import {createInterface} from 'node:readline';
const emit=v=>process.stdout.write(JSON.stringify(v)+'\\n');
emit({ok:true,protocolVersion:1,result:{method:'control.hello',supervisorInstanceId:'owned-framing-fixture'}});
let count=0;for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})){
const request=JSON.parse(line);++count;
if(request.delay)await new Promise(r=>setTimeout(r,request.delay));
if(request.invalid)process.stdout.write('{"protocolVersion":1,"ok":true}\\n');
else emit({ok:true,protocolVersion:1,result:{count,method:request.method}});
}
await new Promise(r=>setTimeout(r,20));`;

async function fixture(progress = false) {
  const scans: Buffer[] = []; let opened = 0, closed = 0, joined = 0;
  const authentication = ['manager_observer_loaded', 'initial_current_observed', 'native_connected', 'pre_hello_current_verified',
    'hello_exchange_started', 'hello_received', 'final_current_verified']
    .map((stage, index) => `CLIQ_INSTALLED_CLIENT_AUTH_V1:${stage}:${index}:none\n`).join('');
  const client = await openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', progress ? `process.stderr.write('installed control client driver progress phase=authentication\\n');
      process.stderr.write(${JSON.stringify(authentication)});\n${protocol}\nprocess.stderr.write('installed control client driver progress phase=retirement\\n');` : protocol],
    cwd: process.cwd(), env: process.env,
    openScan() { opened++; let retired = false; return {
      scan(bytes) { assert(!retired); scans.push(Buffer.from(bytes)); },
      close() { assert(!retired); retired = true; closed++; }
    }; }, onJoined() { joined++; } });
  return { client, counts: () => ({ opened, closed, joined }), scans };
}

test('the genuine-driver consumer joins real EOF, pipes and process after independent canonical responses', async () => {
  const { client, counts, scans } = await fixture();
  assert.equal(client.supervisorInstanceId, 'owned-framing-fixture');
  assert.equal((await client.send({ protocolVersion: 1, method: 'run.get' })).result?.count, 1);
  assert.equal((await client.send({ protocolVersion: 1, method: 'run.attach' })).result?.count, 2);
  assert.deepEqual(counts(), { opened: 2, closed: 0, joined: 0 });
  await client.close(); await client.close();
  assert.deepEqual(counts(), { opened: 2, closed: 2, joined: 1 });
  assert(Buffer.concat(scans).includes(Buffer.from('control.hello')));
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.get' }));
});

test('the genuine-driver consumer counts automatic hello and never sends frame 1025', async () => {
  const { client, scans } = await fixture(true);
  for (let count = 1; count <= 1023; count++) {
    assert.equal((await client.send({ protocolVersion: 1, method: 'run.get' })).result?.count, count);
  }
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }));
  await client.close();
  const bytes = Buffer.concat(scans);
  assert(bytes.includes(Buffer.from('installed control client driver progress phase=authentication\n')));
  assert(bytes.includes(Buffer.from('installed control client driver progress phase=retirement\n')));
  assert.equal(bytes.toString().split('CLIQ_INSTALLED_CLIENT_AUTH_V1:').length - 1, 7);
});

test('the genuine-driver consumer rejects overlapping sends and makes a malformed response sticky', async () => {
  const { client } = await fixture();
  const first = client.send({ protocolVersion: 1, method: 'run.get', delay: 30 });
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }));
  assert.equal((await first).result?.count, 1);
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.get', invalid: true }));
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }));
  await assert.rejects(client.close());
});

test('the genuine-driver consumer never retries after its original request deadline', async () => {
  const { client, counts } = await fixture();
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit', delay: 40 }, 5), error => {
    assert(error instanceof InstalledClientConsumerDeadlineError);
    assert.deepEqual(Object.keys(error.diagnostic).sort(), ['elapsedMs', 'frames', 'kind', 'originalDeadlineMs', 'stage']);
    assert.equal(error.diagnostic.kind, 'installed_client_deadline'); assert.equal(error.diagnostic.stage, 'request');
    assert.equal(error.diagnostic.originalDeadlineMs, 5); assert.equal(error.diagnostic.frames, 1);
    assert(Number.isSafeInteger(error.diagnostic.elapsedMs) && error.diagnostic.elapsedMs >= 0);
    return true;
  });
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }));
  await assert.rejects(client.close());
  assert.deepEqual(counts(), { opened: 2, closed: 2, joined: 0 });
});

test('the genuine-driver consumer retains only the fixed driver failure stage and still joins its child', async () => {
  let closed = 0, joined = false;
  await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
    args: ['-e', "process.stderr.write('installed control client driver failed phase=selection\\n');process.exitCode=1"],
    cwd: process.cwd(), env: process.env,
    openScan: () => ({ scan() {}, close() { closed++; } }), onJoined() { joined = true; }
  }), error => {
    assert(error instanceof InstalledClientDriverError);
    assert.deepEqual(error.diagnostic, { kind: 'installed_client_driver', stage: 'selection' });
    assert(!error.message.includes('apiKey')); return true;
  });
  assert.equal(closed, 2); assert.equal(joined, false);
});

test('the original ready deadline retains the last scanned split progress marker without extending its budget', async () => {
  const scanned: Buffer[] = []; let closed = 0, joined = false;
  const started = performance.now();
  await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', `
      process.stderr.write('installed control client driver progress phase=selection\\ninstalled control client driver prog');
      await new Promise(resolve=>setTimeout(resolve,10));
      process.stderr.write('ress phase=authentication\\n');
      for await (const _ of process.stdin) { /* join the original EOF */ }
    `], cwd: process.cwd(), env: process.env, timeout: 500,
    openScan: () => ({ scan(bytes) { scanned.push(Buffer.from(bytes)); }, close() { closed++; } }),
    onJoined() { joined = true; }
  }), error => {
    assert(error instanceof InstalledClientConsumerDeadlineError);
    assert.deepEqual(Object.keys(error.diagnostic).sort(),
      ['elapsedMs', 'frames', 'kind', 'lastObservedDriverStage', 'originalDeadlineMs', 'stage']);
    assert.equal(error.diagnostic.stage, 'ready'); assert.equal(error.diagnostic.originalDeadlineMs, 500);
    assert.equal(error.diagnostic.frames, 0); assert.equal(error.diagnostic.lastObservedDriverStage, 'authentication');
    return true;
  });
  assert(performance.now() - started < 2000);
  assert.equal(Buffer.concat(scanned).toString(),
    'installed control client driver progress phase=selection\ninstalled control client driver progress phase=authentication\n');
  assert.equal(closed, 2); assert.equal(joined, false);
});

test('the ready deadline retains scanned split authentication boundaries and actual work counters only as diagnostics', async () => {
  const marker = 'CLIQ_INSTALLED_CLIENT_AUTH_V1:hello_exchange_started:12:1:1:10:3:2:2:20:4:0:0:0:0\n';
  const scanned: Buffer[] = []; let closed = 0;
  await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', `process.stderr.write(${JSON.stringify(marker.slice(0, 33))});
      await new Promise(r=>setTimeout(r,10));process.stderr.write(${JSON.stringify(marker.slice(33))});
      for await(const _ of process.stdin){}`], cwd: process.cwd(), env: process.env, timeout: 500,
    openScan: () => ({ scan(bytes) { scanned.push(Buffer.from(bytes)); }, close() { closed++; } }), onJoined() { assert.fail(); }
  }), error => {
    assert(error instanceof InstalledClientConsumerDeadlineError);
    assert.equal(error.diagnostic.originalDeadlineMs, 500); assert.equal(error.diagnostic.frames, 0);
    const rows = error.diagnostic.authentication; assert.equal(rows?.length, 1);
    assert.equal(rows[0]?.stage, 'hello_exchange_started'); assert.equal(rows[0]?.elapsedMs, 12);
    assert(Number.isSafeInteger(rows[0]?.observedElapsedMs) && rows[0]!.observedElapsedMs >= 0);
    assert.deepEqual(rows[0]?.work, { package: { started: 1, completed: 1, bytesRead: 10, spanElapsedMs: 3 },
      revalidate: { started: 2, completed: 2, bytesRead: 20, spanElapsedMs: 4 },
      createCompare: { started: 0, completed: 0, bytesRead: 0, spanElapsedMs: 0 } });
    assert(Object.isFrozen(rows) && Object.isFrozen(rows[0]) && Object.isFrozen(rows[0]?.work)); return true;
  });
  assert.equal(Buffer.concat(scanned).toString(), marker); assert.equal(closed, 2);
});

test('only primitive fixed driver stages can enter deadline observations without invoking getters', () => {
  let accessed = false;
  const getter = Object.defineProperty({}, 'toString', { get() { accessed = true; throw new Error('untrusted getter'); } });
  for (const stage of [null, {}, getter, new String('authentication'), 'unknown-stage']) {
    assert.throws(() => new InstalledClientDriverError(stage as never), assert.AssertionError);
    assert.throws(() => new InstalledClientConsumerDeadlineError('ready', 5000, performance.now(), 0, stage as never), assert.AssertionError);
  }
  assert.equal(accessed, false);
  for (const stage of ['platform', 'composition', 'selection', 'authentication', 'request', 'output', 'retirement'] as const) {
    const error = new InstalledClientConsumerDeadlineError('ready', 5000, performance.now(), 0, stage);
    assert.equal(error.diagnostic.lastObservedDriverStage, stage); assert(Object.isFrozen(error.diagnostic));
  }
});

test('authentication data never invokes supplied accessors or serializes unknown objects', () => {
  let accessed = false;
  const poison = Object.defineProperty({}, 'package', { get() { accessed = true; throw 0; } });
  assert.throws(() => copyInstalledClientAuthenticationWork(poison), assert.AssertionError);
  assert.throws(() => installedClientAuthenticationMarker('hello_sent' as never, 0));
  const rows = Array(1);
  Object.defineProperty(rows, '0', { get() { accessed = true; throw 0; } });
  assert.throws(() => new InstalledClientConsumerDeadlineError('ready', 5000, performance.now(), 0, undefined, rows), assert.AssertionError);
  assert.equal(accessed, false);
});

test('unknown, partial, duplicate, unordered or invalid authentication markers remain fatal scanned stderr', async () => {
  const prefix = 'CLIQ_INSTALLED_CLIENT_AUTH_V1:';
  const valid = prefix + 'native_connected:4:none\n';
  const bad = [prefix + 'hello_sent:1:none\n', valid + valid,
    valid + prefix + 'initial_current_observed:5:none\n',
    valid + prefix + 'hello_received:3:none\n', prefix + 'native_connected:9007199254740992:none\n',
    prefix + 'native_connected:4:1:2:0:0:0:0:0:0:0:0:0:0\n',
    prefix + 'native_connected:4:0:0:0:0:0:0:0:0:1:1:1:0\n',
    prefix + 'native_connected:4:1:1:10:1:1:1:20:1:0:0:0:0\n' +
      prefix + 'hello_received:5:1:1:9:1:1:1:20:1:0:0:0:0\n',
    prefix + 'native_connected:4:none', prefix + 'native_connected:' + '1'.repeat(513),
    prefix + 'native_connected:4:none:extra\n', prefix + 'native_connected:4:n\u00ffne\n'];
  for (const value of bad) {
    const bytes = Buffer.from(value), scanned: Buffer[] = []; let opened = 0, closed = 0;
    let refused = false;
    try {
      const client = await openInstalledClientConsumer({ executable: process.execPath,
        args: ['--input-type=module', '-e', `process.stderr.write(Buffer.from('${bytes.toString('base64')}','base64'));
          process.stdout.write('{"ok":true,"protocolVersion":1,"result":{"method":"control.hello","supervisorInstanceId":"owned-framing-fixture"}}\\n');
          for await(const _ of process.stdin){}`], cwd: process.cwd(), env: process.env,
        openScan: () => { const stderr = ++opened === 2; return { scan(chunk) { if (stderr) scanned.push(Buffer.from(chunk)); }, close() { closed++; } }; }, onJoined() {}
      });
      await client.close();
    } catch (error) { assert(!(error instanceof InstalledClientConsumerDeadlineError)); refused = true; }
    assert(refused, 'invalid authentication data cannot become a successful ready/close');
    assert(Buffer.concat(scanned).equals(bytes)); assert.equal(closed, 2);
  }
});

test('the secret scanner can refuse authentication data before any diagnostic is retained', async () => {
  const blocked = new Error('owned authentication scan refusal'); let opened = 0, closed = 0;
  await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', "process.stderr.write('CLIQ_INSTALLED_CLIENT_AUTH_V1:native_connected:0:none\\n');for await(const _ of process.stdin){}"],
    cwd: process.cwd(), env: process.env,
    openScan: () => { const stderr = ++opened === 2; return { scan() { if (stderr) throw blocked; }, close() { closed++; } }; },
    onJoined() { assert.fail(); }
  }), error => error === blocked);
  assert.equal(closed, 2);
});

test('unknown, duplicate and incomplete stderr never become accepted driver progress or a positive join', async () => {
  for (const bytes of [
    Buffer.from('private remote diagnostic\ninstalled control client driver progress phase=selection\n'),
    Buffer.from('installed control client driver progress phase=unknown\n'),
    Buffer.from('installed control client driver progress phase=selection'),
    Buffer.from('installed control client driver progress phase=selection\ninstalled control client driver progress phase=selection\n'),
    Buffer.concat([Buffer.from('installed control client driver progress phase=select'), Buffer.from([0xff]), Buffer.from('ion\n')])
  ]) {
    const scanned: Buffer[] = []; let closed = 0, joined = false;
    await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
      args: ['--input-type=module', '-e', `process.stderr.write(Buffer.from('${bytes.toString('base64')}', 'base64'));`],
      cwd: process.cwd(), env: process.env,
      openScan: () => ({ scan(chunk) { scanned.push(Buffer.from(chunk)); }, close() { closed++; } }),
      onJoined() { joined = true; }
    }), error => {
      assert(!(error instanceof InstalledClientConsumerDeadlineError));
      assert(!String(error).includes('private remote diagnostic')); return true;
    });
    assert(Buffer.concat(scanned).equals(bytes)); assert.equal(closed, 2); assert.equal(joined, false);
  }
});

test('a fixed failure marker remains fatal after progress and hello without resending the mutation', async () => {
  let closed = 0, joined = false;
  const client = await openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', `import {createInterface} from 'node:readline';
      process.stderr.write('installed control client driver progress phase=authentication\\n');
      process.stdout.write('{"ok":true,"protocolVersion":1,"result":{"method":"control.hello","supervisorInstanceId":"owned-framing-fixture"}}\\n');
      let count=0;for await(const _ of createInterface({input:process.stdin,crlfDelay:Infinity})) {
        if(++count!==1)process.exitCode=2;
        process.stderr.write('installed control client driver failed phase=request\\n');
      }`], cwd: process.cwd(), env: process.env,
    openScan: () => ({ scan() {}, close() { closed++; } }), onJoined() { joined = true; }
  });
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }), error => {
    assert(error instanceof InstalledClientDriverError);
    assert.deepEqual(error.diagnostic, { kind: 'installed_client_driver', stage: 'request' }); return true;
  });
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }));
  await assert.rejects(client.close()); assert.equal(closed, 2); assert.equal(joined, false);
});

test('the original secret scanner may refuse a fixed progress marker before it enters diagnostics', async () => {
  const blocked = new Error('owned scanner refusal'); let opened = 0, closed = 0;
  await assert.rejects(openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', "process.stderr.write('installed control client driver progress phase=authentication\\n');for await(const _ of process.stdin){}"],
    cwd: process.cwd(), env: process.env,
    openScan: () => { const stderr = ++opened === 2; return {
      scan(bytes) { if (stderr) { assert(Buffer.from(bytes).includes(Buffer.from('progress phase='))); throw blocked; } },
      close() { closed++; }
    }; }, onJoined() { assert.fail('a scanner refusal cannot become a joined consumer'); }
  }), error => error === blocked);
  assert.equal(opened, 2); assert.equal(closed, 2);
});
