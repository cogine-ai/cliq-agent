// Retained pure budget planning, not pricing/endpoint/execution authority.
import { canonicalSha256 } from '../kernel/canonical.js';
import type { BudgetUsage, ChildAllocationV1, RunAssemblyV1 } from '../kernel/types.js';
import { createModelRequestReservation, decodeLocalZeroCostProvenanceData, decodeModelPriceTableData } from '../model/pricing.js';
import type { ArtifactCatalog } from './artifacts.js';
import { addBudget } from './invariants.js';
import { ZERO_BUDGET } from './rows.js';

/** Preserve one possible compaction followed by one normal continuation,
 * one explicit await registration, and one merge for each unsettled mutating
 * child. This is one shared floor, not a reservation per descendant. It does
 * not promise that unknown output fits a future prompt or guarantees success. */
export async function readChildContinuationBudgetFloor(artifacts: ArtifactCatalog, input: {
  parentRunId: string; assembly: RunAssemblyV1; allocations: readonly ChildAllocationV1[]; nextMode: 'read_only' | 'mutating';
}): Promise<Readonly<BudgetUsage>> {
  const { assembly } = input, bound = assembly.provider.pricing;
  let pricing;
  if (bound.kind === 'trusted_price_table') {
    const table = decodeModelPriceTableData(await artifacts.readCanonical(bound.priceTableRef));
    if (table.tableDigest !== bound.priceTableDigest || table.provider !== assembly.provider.name || table.model !== assembly.provider.model ||
        table.validThrough !== bound.validThrough ||
        assembly.provider.endpoint.kind === 'local_zero_cost' || table.endpointIdentityDigest !== assembly.provider.endpoint.endpointIdentityDigest)
      throw new TypeError('child continuation price data differs from its frozen assembly');
    pricing = { kind: bound.kind, bound, table };
  } else {
    const provenance = decodeLocalZeroCostProvenanceData(await artifacts.readCanonical(bound.provenanceRef));
    if (canonicalSha256(provenance) !== bound.provenanceRef || provenance.model !== assembly.provider.model || assembly.provider.name !== 'ollama' ||
        assembly.provider.endpoint.kind !== 'local_zero_cost' || assembly.provider.endpoint.localProvenanceRef !== bound.provenanceRef)
      throw new TypeError('child continuation zero-cost data differs from its frozen assembly');
    pricing = { kind: bound.kind, bound, provenance };
  }
  const normal = createModelRequestReservation(assembly.context.contextLimitTokens, assembly.context.reservedOutputTokens, pricing),
    compaction = createModelRequestReservation(assembly.context.contextLimitTokens, assembly.context.summaryTokenCap, pricing);
  const merged = addBudget({ ...ZERO_BUDGET, modelTokens: normal.modelTokens, costMicros: normal.costMicros },
    { ...ZERO_BUDGET, modelTokens: compaction.modelTokens, costMicros: compaction.costMicros });
  let merges = input.nextMode === 'mutating' ? 1 : 0;
  for (const allocation of input.allocations) {
    if (allocation.parentRunId !== input.parentRunId) throw new TypeError('child continuation floor received a foreign allocation');
    if (allocation.state !== 'settled' && allocation.mode === 'mutating') merges++;
  }
  return Object.freeze(addBudget(merged, { ...ZERO_BUDGET, toolCalls: 1 + merges }));
}
