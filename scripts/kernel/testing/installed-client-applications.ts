// Complete installed client read/replay/detach campaign, through actual held
// selection and the same production application. No direct Store/native call.
import assert from 'node:assert/strict';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { decodeInstalledControlRequest, type InstalledControlRequestV1 } from '../../../src/control/v1.js';
import { openInstalledClientConsumer } from './installed-client-consumer.js';
import { qualifyInstalledInkDetach } from './installed-ink-consumer.js';
type Data = Record<string, any>;
type Scan = { scan(bytes: Uint8Array): void; close(): void };
type Input = { executable: string; args: readonly string[]; cwd: string; env: NodeJS.ProcessEnv;
  runId: string; sessionId: string; originalSubmission: Data; originalAdmission: Data;
  send(request: Data): Promise<Data>; counts(): readonly [number, number, number]; providerHealthy(): boolean;
  openScan(): Scan; onJoined(): void };
const accepted = (value: Data, method: string): Data => { assert(value.ok === true && value.protocolVersion === 1 && value.result.method === method); return value.result; };
const equal = (actual: unknown, expected: unknown) => assert.deepEqual(canonicalJsonBytes(actual), canonicalJsonBytes(expected));

// Data comparison only; callers still obtain both replies from authenticated clients.
export function assertSameAuthorizationListing(expected: Data, actual: Data): void {
  const { nextCursor: expectedCursor, ...expectedPage } = accepted(expected, 'authorization.list');
  const { nextCursor: actualCursor, ...actualPage } = accepted(actual, 'authorization.list');
  equal(actualPage, expectedPage);
  assert.equal(typeof actualCursor, typeof expectedCursor);
}

export async function qualifyInstalledClientApplications(input: Input) {
  const counts = input.counts(); assert.deepEqual(counts, [5, 5, 5]); assert(input.providerHealthy());
  const runGet = { protocolVersion: 1 as const, method: 'run.get' as const, runId: input.runId };
  const sessionGet = { protocolVersion: 1 as const, method: 'session.get' as const, sessionId: input.sessionId };
  const beforeRun = await input.send(runGet), beforeSession = await input.send(sessionGet);
  const first = accepted(beforeRun, 'run.get'); assert.equal(first.snapshot.run.id, input.runId);
  assert.equal(first.snapshot.run.sessionId, input.sessionId); assert.equal(first.snapshot.run.status, 'completed_unverified');
  const authorizationList = { protocolVersion: 1, method: 'authorization.list', limit: 100 };
  const expectedAuthorizations = await input.send(authorizationList);
  const open = (suffix: string[], mode?: 'rpc', initialRequest?: InstalledControlRequestV1) => openInstalledClientConsumer({
    executable: input.executable, args: [...input.args, ...suffix], cwd: input.cwd, env: input.env, headlessSchemaVersion: 3,
    ...(mode ? { headlessTransport: mode } : {}), ...(initialRequest ? { initialRequest } : {}),
    openScan: input.openScan, onJoined: input.onJoined });
  // CLI performs a real natural command and an explicit exact original
  // admission replay; neither fabricates a fresh request or a new Run.
  let client = await open(['--client-entry', 'status', input.runId, '--json'], undefined, runGet);
  try { equal(await client.initialResponse, beforeRun); } finally { await client.close(); }
  const replay = decodeInstalledControlRequest(input.originalSubmission); assert.equal(replay.method, 'run.submit');
  client = await open(['--client-entry', 'request', canonicalJsonBytes(replay).toString('utf8'), '--json'], undefined, replay);
  try { equal(await client.initialResponse, input.originalAdmission); } finally { await client.close(); }
  const list = { protocolVersion: 1, method: 'run.list', sessionId: input.sessionId, operation: 'agent', limit: 1 };
  let cursor: string, next: Data;
  client = await open(['--client-jsonl']);
  try {
    equal(await client.send(runGet), beforeRun); equal(await client.send(sessionGet), beforeSession);
    const page = accepted(await client.send(list), 'run.list');
    assert.equal(page.runs.length, 1); assert.equal(page.runs[0].run.id, input.runId); assert.equal(typeof page.nextCursor, 'string'); cursor = page.nextCursor;
    next = await client.send({ ...list, cursor }); accepted(next, 'run.list');
    assertSameAuthorizationListing(expectedAuthorizations, await client.send(authorizationList));
  } finally { await client.close(); }
  // A newly authenticated RPC client consumes the exact already-materialized
  // list page, independent of current list source/connection ordering.
  client = await open(['--client-rpc'], 'rpc');
  try {
    equal(await client.send({ ...list, cursor }), next);
    equal(await client.send(runGet), beforeRun); equal(await client.send(sessionGet), beforeSession);
  } finally { await client.close(); }
  const ink = await qualifyInstalledInkDetach({ ...input, args: [...input.args, '--client-entry', 'tui', '--run', input.runId] });
  equal(await input.send(runGet), beforeRun); equal(await input.send(sessionGet), beforeSession);
  assert.deepEqual(input.counts(), counts); assert(input.providerHealthy());
  return Object.freeze({ schemaVersion: 1, format: 'cliq-installed-client-applications-v1', qualified: true,
    originalRunId: input.runId, originalProviderRequests: 5, additionalProviderRequests: 0,
    cliNaturalReadAndOriginalAdmissionReplay: true, jsonlReadAndLists: true, rpcReadAndFrozenCursorReplay: true,
    originalRunJournalCheckpointAndSessionPreserved: true, applicationProcessesAndPipesJoined: true, ink,
    newExecutionQualified: false, completeI3Qualified: false });
}
