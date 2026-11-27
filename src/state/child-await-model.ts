// Complete model presentation only. Audit refs remain in the owning payload;
// no grant, candidate, result authority or child settlement is minted here.
import { canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson } from '../kernel/control-wire-data.js';
import type { AwaitChildrenResult, ChildMergeModelDiagnostic, ChildResultItem, ChildResultModelContentV1 } from '../kernel/children.js';
import type { ArtifactCatalog } from './artifacts.js';
import { childResultModelContent } from './child-result-artifacts.js';

export async function readChildAwaitModelResult(artifacts: ArtifactCatalog, items: readonly ChildResultItem[], merge?: ChildMergeModelDiagnostic): Promise<AwaitChildrenResult> {
  assertControlWireJson({ items, ...(merge === undefined ? {} : { merge }) });
  if (!items.length || items.length > 64 || new Set(items.map(item => item.childRunId)).size !== items.length) throw new TypeError('await model result has no exact bounded unique child order');
  const results = await artifacts.mapReads(items, async item => {
    if (item.delivery.kind === 'stop_settlement') throw new TypeError('Stop settlement cannot become an await model result');
    const content = await artifacts.readCanonical<ChildResultModelContentV1>(item.modelContentRef),
      expected = childResultModelContent(item.childRunId, item.mode, content.content);
    if (content.contentDigest !== item.modelContentDigest || content.content.status !== item.status ||
        ('terminalReason' in content.content && (!('terminalReason' in item) || content.content.terminalReason !== item.terminalReason)) ||
        canonicalSha256(content) !== canonicalSha256(expected))
      throw new TypeError('await child summary differs from its complete original result');
    return { childRunId: item.childRunId, mode: item.mode, ...content.content };
  });
  return { schemaVersion: 1, results, ...(merge === undefined ? {} : { merge }) };
}
