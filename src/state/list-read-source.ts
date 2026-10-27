import { createHash } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeListRunSnapshot, type ControlListRequestV1 } from '../kernel/control-list.js';
import { decodeWireGrantSummary } from '../kernel/control-wire-data.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeRunSpec } from './decoders.js';
import { KernelStorageError } from './errors.js';
import type { ListSource } from './list-read-cut.js';
import { ListCutCapacityError } from './list-read-cut.js';
import { runFromRow } from './rows.js';
import type { SqliteConnection, SqliteDriver, SqliteInputValue, SqliteRow } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

// Compiled SQL projections of public summary fields only. Neither a caller nor
// a stored locator can select a table, SQL expression or native resource.
type Column = { name: string; expression: string } & (
  | { kind: 'TEXT'; bytes: number; nullable: boolean }
  | { kind: 'INTEGER'; numericType: string });
const text = (name: string, bytes: number, nullable = false, expression = 's.' + name): Column =>
  ({ name, expression, kind: 'TEXT', bytes, nullable });
const integer = (name: string, expression = 's.' + name, jsonField?: string): Column =>
  ({ name, expression, kind: 'INTEGER', numericType: jsonField === undefined ? `typeof(${expression})` : `json_type(s.row_json,'$.${jsonField}')` });
const runColumns: readonly Column[] = [text('id', 128), text('session_id', 128), text('parent_run_id', 128, true),
  text('spec_ref', 64), text('status', 32), text('next_step', 32, true), text('frontier_ref', 64, true),
  text('waiting_reason', 32, true), text('waiting_on_ref', 64, true), integer('revision'), integer('lease_epoch'),
  text('active_worker_launch_id', 128, true), text('latest_checkpoint_id', 128), text('budget_reserved_json', 4096),
  text('budget_consumed_json', 4096), integer('repair_count'), text('result_ref', 64, true),
  text('terminal_reason', 128, true), text('terminal_detail_ref', 64, true), text('stop_intent_ref', 64, true),
  text('parent_cancellation_ref', 64, true),
  integer('cancel_requested'), text('created_at', 24), text('deadline_at', 24), text('updated_at', 24),
  integer('latest_run_item_seq', '(SELECT coalesce(max(item_seq),0) FROM items WHERE run_id=s.id)')];
const grantField = (field: string) => `json_extract(s.row_json,'$.${field}')`;
const grantColumns: readonly Column[] = [text('id', 128, false, 's.grant_id'),
  integer('schema_version', grantField('schemaVersion'), 'schemaVersion'),
  text('claimed_id', 128, false, grantField('grantId')), text('claimed_principal', 128, false, grantField('ownerPrincipalId')),
  text('state', 16), text('claimed_state', 16, false, grantField('state')),
  text('target_kind', 64, false, grantField('target.kind')), text('target_digest', 64, false, grantField('targetDigest')),
  text('purpose', 64, false, `CASE ${grantField('target.kind')} WHEN 'verifier_execution' THEN 'verifier' WHEN 'dependency_install_scripts' THEN 'dependency_install_scripts' ELSE ${grantField('target.purpose')} END`),
  integer('use_count', grantField('useCount'), 'useCount'), integer('row_version', grantField('rowVersion'), 'rowVersion'),
  text('created_at', 24, false, grantField('createdAt')), text('expires_at', 24, false, grantField('expiresAt')),
  text('consumed_at', 24, true, grantField('consumedAt')), text('revoked_at', 24, true, grantField('revokedAt'))];
function corrupt(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'list source is not a closed original public projection'); }
function projection(columns: readonly Column[]): string {
  return columns.map(column => column.kind === 'TEXT'
    ? `CASE WHEN length(CAST(${column.expression} AS BLOB))<=${column.bytes} THEN ${column.expression} END AS ${column.name}`
    : `CASE WHEN ${column.numericType} IN ('integer','real') THEN ${column.expression} END AS ${column.name}`).join(',') + ',(' + columns.filter(column => column.kind === 'TEXT')
    .map(column => `coalesce(length(CAST(${column.expression} AS BLOB))>${column.bytes},0)`).join(' OR ') + ') AS overlong';
}
function sameSource(connection: SqliteConnection, table: string, columns: readonly Column[], where: string, values: readonly SqliteInputValue[]): boolean {
  const live = connection.prepare(`SELECT count(*) AS n FROM (SELECT 1 FROM ${table} s WHERE ${where} LIMIT 100001)`).get<{ n: bigint }>(...values)!;
  const staged = connection.prepare('SELECT count(*) AS n FROM temp.cliq_list_source').get<{ n: bigint }>()!;
  if (live.n !== staged.n) return false;
  const id = columns[0]!.expression;
  const differences = columns.map(column => column.kind === 'TEXT'
    ? `CAST(${column.expression} AS BLOB) IS NOT CAST(p.${column.name} AS BLOB)`
    : `(${column.numericType} IS NOT 'integer' AND ${column.numericType} IS NOT 'real') OR ${column.expression} IS NOT p.${column.name}`).join(' OR ');
  // The source primary key and validated strict captured (createdAt,id)
  // order exclude duplicate identical tuples. A repeated id with different
  // public values fails this comparison. Exact cardinality then closes both
  // directions without a second TEMP unique index.
  return connection.prepare(`SELECT EXISTS(SELECT 1 FROM temp.cliq_list_source p LEFT JOIN ${table} s ON ${id}=p.id AND ${where} WHERE ${id} IS NULL OR ${differences} LIMIT 1) AS changed`)
    .get<{ changed: bigint }>(...values)?.changed === 0n;
}
export function createExtraListSource(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  principalId: string, request: ControlListRequestV1, current: () => void, capturedText: (bytes: unknown) => string): ListSource {
  const run = request.method === 'run.list', table = run ? 'runs' : 'authorization_grants';
  const columns = run ? runColumns : grantColumns;
  const baseWhere: string[] = [run ? 's.principal_id=?' : 's.owner_principal_id=?'];
  const baseValues: SqliteInputValue[] = [principalId];
  if (request.method === 'run.list') {
    if (request.sessionId !== undefined) { baseWhere.push('s.session_id=?'); baseValues.push(request.sessionId); }
    if (request.statuses?.length) { baseWhere.push('s.status IN (SELECT value FROM json_each(?))'); baseValues.push(canonicalJsonBytes(request.statuses).toString('utf8')); }
  } else {
    if (request.state !== undefined) { baseWhere.push('s.state=?'); baseValues.push(request.state); }
    if (request.targetKind !== undefined) { baseWhere.push(grantField('target.kind') + '=?'); baseValues.push(request.targetKind); }
  }
  let operation: { refsDigest: string; matching: string } | undefined;
  const filter = () => ({ where: baseWhere.join(' AND ') + (operation ? ' AND s.spec_ref IN (SELECT value FROM json_each(?))' : ''),
    values: [...baseValues, ...(operation ? [operation.matching] : [])] });
  function refsDigest(connection: SqliteConnection): string {
    const hash = createHash('sha256'); hash.update('['); let previous = '', comma = false;
    for (const row of connection.prepare('SELECT DISTINCT s.spec_ref AS ref FROM runs s WHERE ' + baseWhere.join(' AND ') + ' ORDER BY s.spec_ref')
      .iterate<{ ref: string }>(...baseValues)) {
      if (!/^[0-9a-f]{64}$/u.test(row.ref) || row.ref <= previous) return corrupt();
      if (comma) hash.update(','); hash.update(canonicalJsonBytes(row.ref)); comma = true; previous = row.ref;
    }
    return hash.update(']').digest('hex');
  }
  return {
    schema: columns.map(column => `${column.name} ${column.kind === 'INTEGER' ? 'ANY' : 'TEXT'}`).join(','),
    readProjection: columns.map(column => column.kind === 'TEXT' ? 'CAST(' + column.name + ' AS BLOB) AS ' + column.name : column.name).join(','),
    columns: columns.map(column => column.name), reset() { operation = undefined; },
    async prepare() {
      if (request.method !== 'run.list' || request.operation === undefined || operation) return;
      const hash = createHash('sha256'), matching: string[] = []; hash.update('['); let after = '', comma = false;
      for (;;) {
        current(); assertActiveStateOwner(driver, owner);
        const refs = driver.readSnapshot(connection => connection.prepare('SELECT DISTINCT CASE WHEN length(CAST(s.spec_ref AS BLOB))=64 THEN s.spec_ref END AS ref FROM runs s WHERE ' +
          baseWhere.join(' AND ') + ' AND s.spec_ref>? ORDER BY s.spec_ref LIMIT 128').all<{ ref: string }>(...baseValues, after));
        if (!refs.length) break;
        for (const row of refs) {
          current(); assertActiveStateOwner(driver, owner);
          if (!/^[0-9a-f]{64}$/u.test(row.ref) || row.ref <= after) return corrupt();
          const value = await artifacts.readCanonical(row.ref);
          if (canonicalSha256(value) !== row.ref) return corrupt();
          const spec = decodeRunSpec(value);
          if (spec.operation === request.operation) matching.push(row.ref);
          if (matching.length > 100_000) throw new ListCutCapacityError();
          if (comma) hash.update(','); hash.update(canonicalJsonBytes(row.ref)); comma = true; after = row.ref;
        }
      }
      operation = { refsDigest: hash.update(']').digest('hex'), matching: canonicalJsonBytes(matching).toString('utf8') };
    },
    capture(connection) {
      if (operation && refsDigest(connection) !== operation.refsDigest) return;
      const { where, values } = filter();
      const count = connection.prepare(`SELECT count(*) AS n FROM (SELECT 1 FROM ${table} s WHERE ${where} LIMIT 100001)`)
        .get<{ n: bigint }>(...values)!.n;
      if (count > 100_000n) throw new ListCutCapacityError();
      const names = columns.map(column => column.name).join(',');
      // The fresh private INTEGER PRIMARY KEY assigns contiguous ordinals in
      // this explicit source order, without a second full-row window pass.
      // Valid grant times have the same byte order as their bounded captured
      // values. Ordering by their original expression permits the fixed schema
      // index; overlong/invalid fields still refuse the complete cut below.
      const selected = run ? 'SELECT ' + names + ',overlong FROM (' +
        `SELECT ${projection(columns)} FROM ${table} s WHERE ${where} LIMIT 100001) ORDER BY created_at COLLATE BINARY,id COLLATE BINARY`
        : `SELECT ${projection(columns)} FROM ${table} s WHERE ${where} ` +
          `ORDER BY ${grantField('createdAt')} COLLATE BINARY,s.grant_id COLLATE BINARY LIMIT 100001`;
      connection.prepare('INSERT INTO temp.cliq_list_source(' + names + ',overlong) ' +
        selected).run(...values);
      if (connection.prepare('SELECT count(*) AS n FROM temp.cliq_list_source').get<{ n: bigint }>()!.n !== count) return corrupt();
      return Number(count);
    },
    same(connection) {
      if (operation && refsDigest(connection) !== operation.refsDigest) return false;
      const { where, values } = filter();
      return sameSource(connection, table, columns, where, values);
    },
    async decode(original) {
      try {
        if (original.overlong !== 0n) return corrupt();
        const row: SqliteRow = { ...original };
        for (const column of columns) {
          const cell = original[column.name];
          if (column.kind === 'TEXT') row[column.name] = cell === null && column.nullable ? null : capturedText(cell);
          else if (typeof cell !== 'bigint' && typeof cell !== 'number' || !Number.isSafeInteger(Number(cell))) return corrupt();
        }
        if (run) {
          const spec = decodeRunSpec(await artifacts.readCanonical(String(row.spec_ref)));
          if (request.method === 'run.list' && request.operation !== undefined && spec.operation !== request.operation) return corrupt();
          return decodeListRunSnapshot({ schemaVersion: 1, operation: spec.operation, run: runFromRow(row), latestRunItemSeq: Number(row.latest_run_item_seq) });
        }
        if (row.id !== row.claimed_id || principalId !== row.claimed_principal || row.state !== row.claimed_state) return corrupt();
        return decodeWireGrantSummary({ schemaVersion: Number(row.schema_version), grantId: row.id, state: row.state, targetKind: row.target_kind,
          purpose: row.purpose,
          targetDigest: row.target_digest, useCount: Number(row.use_count), rowVersion: Number(row.row_version),
          createdAt: row.created_at, expiresAt: row.expires_at,
          ...(row.consumed_at === null ? {} : { consumedAt: row.consumed_at }), ...(row.revoked_at === null ? {} : { revokedAt: row.revoked_at }) });
      } catch (error) {
        if (error instanceof TypeError || error instanceof SyntaxError) return corrupt();
        throw error;
      }
    }
  };
}
