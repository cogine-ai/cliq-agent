// Finite, small integration-fixture assertions only. Each collector consumes the
// actual production page/source stream to EOF; production never imports this
// module or reconstructs a whole legacy projection to consume a v2 head.
import { walkSessionContextSegments } from '../../kernel/session-context-page-reader.js';
import type { SessionContextHead } from '../../kernel/session-context-pages.js';
import type { SessionContextSegment } from '../../kernel/types.js';
import type { ArtifactCatalog } from '../artifacts.js';
import type { SqliteDriver } from '../sqlite-driver.js';
import type { SessionCompactionIndex, SessionContextEntry } from '../session-context.js';
import { readCurrentSessionContextGraph, readSessionContextEntryStream, readSessionContextGraphHead } from '../session-context-stream.js';

export async function fixtureSessionContextSegments(artifacts: ArtifactCatalog, head: string | SessionContextHead) {
  const projection = typeof head === 'string' ? await readSessionContextGraphHead(artifacts, head) : head;
  const segments: SessionContextSegment[] = [];
  for await (const segment of walkSessionContextSegments(artifacts, projection)) segments.push(segment);
  return segments;
}
export async function fixtureSessionContextEntries(artifacts: ArtifactCatalog, projection: SessionContextHead,
  compactionIndex?: SessionCompactionIndex) {
  const entries: SessionContextEntry[] = [];
  for await (const entry of readSessionContextEntryStream(artifacts, projection, { compactionIndex })) entries.push(entry);
  return entries;
}
export async function fixtureCurrentSessionContext(driver: SqliteDriver, artifacts: ArtifactCatalog, principalId: string, sessionId: string) {
  const entries: SessionContextEntry[] = [];
  const context = await readCurrentSessionContextGraph(driver, artifacts, principalId, sessionId, undefined,
    { consume: entry => { entries.push(entry); } });
  return { ...context, entries, segments: await fixtureSessionContextSegments(artifacts, context.projection) };
}
