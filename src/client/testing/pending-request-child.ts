// Real independent Linux process for private-data flock regressions only.
// No StateOwner lock, installed authority, connection, Run or credential exists.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { loadNativeStateOwner } from '../../state/native-owner.js';
import { openPrivateClientDirectory } from '../private-files.js';
import { openPendingRequests, type PendingRequestBinding } from '../pending-requests.js';
import { ClientBusyError, ClientPendingRequestError } from '../errors.js';

assert.equal(process.platform, 'linux'); assert(process.send);
const [supplied] = await once(process, 'message');
const input = supplied as { directoryPath: string; binding: PendingRequestBinding; request: unknown };
assert(input && Object.keys(input).sort().join(',') === 'binding,directoryPath,request');
assert.equal(typeof input.directoryPath, 'string');
const directory = await openPrivateClientDirectory(input.directoryPath, { native: await loadNativeStateOwner() });
let pending: Awaited<ReturnType<typeof openPendingRequests>> | undefined;
try {
  pending = await openPendingRequests(directory, input.binding);
  const start = once(process, 'message'); process.send({ kind: 'ready' });
  const [command] = await start; assert.deepEqual(command, { kind: 'retain' });
  let kind: 'created' | 'busy' | 'pending';
  try { const record = await pending.retain(input.request); assert.equal(record.existing, false); kind = 'created'; }
  catch (error) {
    if (error instanceof ClientBusyError) kind = 'busy';
    else if (error instanceof ClientPendingRequestError) kind = 'pending';
    else throw error;
  }
  await pending.close(); await directory.close();
  await new Promise<void>((resolve, reject) => process.send!({ kind }, error => error ? reject(error) : resolve()));
} finally { await pending?.close(); await directory.close(); process.disconnect(); }
