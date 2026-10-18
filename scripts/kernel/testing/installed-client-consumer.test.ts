// Actual child-process JSONL transport only. These fixtures do not impersonate
// an installed Supervisor or qualify native authentication/execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { openInstalledClientConsumer } from './installed-client-consumer.js';

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

async function fixture() {
  const scans: Buffer[] = []; let opened = 0, closed = 0, joined = 0;
  const client = await openInstalledClientConsumer({ executable: process.execPath,
    args: ['--input-type=module', '-e', protocol], cwd: process.cwd(), env: process.env,
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
  const { client } = await fixture();
  for (let count = 1; count <= 1023; count++) {
    assert.equal((await client.send({ protocolVersion: 1, method: 'run.get' })).result?.count, count);
  }
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }));
  await client.close();
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
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit', delay: 40 }, 5));
  await assert.rejects(client.send({ protocolVersion: 1, method: 'run.submit' }));
  await assert.rejects(client.close());
  assert.deepEqual(counts(), { opened: 2, closed: 2, joined: 0 });
});
