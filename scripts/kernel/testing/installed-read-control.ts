// Shared independent read-only client/inspection for the actual installed tests.
import assert from 'node:assert/strict';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../../../src/config.js';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { digestOmitting } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { StateOwnerRecordV1 } from '../../../src/kernel/types.js';

export function inspectInstalledOwner(stateRoot: string): StateOwnerRecordV1 | undefined {
  const database = new DatabaseSync(path.join(stateRoot, KERNEL_DATABASE_FILENAME), { readOnly: true, allowExtension: false });
  try {
    assert.equal(database.prepare('PRAGMA user_version').get()?.user_version, KERNEL_STATE_SCHEMA_VERSION);
    const rows = database.prepare('SELECT owner_epoch, supervisor_instance_id, record_json, state, row_digest FROM state_owners').all();
    assert(rows.length <= 1, 'this qualification starts exactly one real Supervisor');
    if (!rows.length) return undefined;
    const row = rows[0]!;
    assert.equal(typeof row.record_json, 'string');
    const owner = parseJsonStrict(row.record_json as string) as StateOwnerRecordV1;
    assert.equal(owner.ownerEpoch, row.owner_epoch); assert.equal(owner.supervisorInstanceId, row.supervisor_instance_id);
    assert.equal(owner.state, row.state); assert.equal(owner.rowDigest, row.row_digest);
    assert.equal(owner.rowDigest, digestOmitting(owner, 'rowDigest'));
    return owner;
  } finally { database.close(); }
}

const helloBytes = canonicalJsonBytes({ protocolVersion: 1, method: 'control.hello',
  clientBuild: 'installed-startup-qualification', controlSchemaRange: { min: 1, max: 1 },
  headlessSchemaRange: { min: 1, max: 1 }, requestedFeatureIds: ['supervisor.status'] }).toString('base64');
const statusBytes = canonicalJsonBytes({ protocolVersion: 1, method: 'supervisor.status' }).toString('base64');
// The caller runs this ordinary Node client as the disposable unprivileged UID.
// It controls only its sockets, never installation or authority evidence.
export const installedReadClientScript = `import assert from 'node:assert/strict';
import net from 'node:net';
const exchanges = [];
for (let attempt = 0; attempt < 2; attempt++) {
  const socket = net.createConnection(process.argv[1]);
  let input = Buffer.alloc(0), waiter, error;
  socket.on('data', chunk => {
    try {
      input = Buffer.concat([input, chunk]);
      assert(input.length <= 1048580);
      while (input.length >= 4) {
        const length = input.readUInt32BE(0);
        assert(length >= 1 && length <= 1048576);
        if (input.length < 4 + length) break;
        const json = new TextDecoder('utf-8', {fatal:true}).decode(input.subarray(4, 4 + length));
        input = input.subarray(4 + length);
        assert(waiter, 'unsolicited response frame');
        const complete = waiter; waiter = undefined; complete.resolve(json);
      }
    } catch (failure) { error = failure; waiter?.reject(failure); socket.destroy(); }
  });
  socket.on('error', failure => { error = failure; waiter?.reject(failure); });
  socket.on('close', () => { error ??= new Error('peer closed before response'); waiter?.reject(error); });
  const closed = new Promise(resolve => socket.once('close', resolve));
  try {
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    const request = async bytes => {
      if (error) throw error;
      assert(!waiter, 'one fixed request is outstanding at a time');
      return await new Promise((resolve, reject) => {
        waiter = {resolve,reject};
        const header = Buffer.alloc(4); header.writeUInt32BE(bytes.length);
        try { socket.write(Buffer.concat([header, bytes])); }
        catch (failure) { waiter = undefined; reject(failure); }
      });
    };
    const hello = await request(Buffer.from(${JSON.stringify(helloBytes)}, 'base64'));
    const status = await request(Buffer.from(${JSON.stringify(statusBytes)}, 'base64'));
    exchanges.push({hello,status});
  } finally { socket.destroy(); await closed; }
}
console.log(JSON.stringify(exchanges));`;
