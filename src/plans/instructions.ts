import type { InstructionMessage } from '../instructions/types.js';
import type { Session } from '../session/types.js';
import { readReferencedPlanArtifact } from './store.js';

export async function buildApprovedPlanInstructionMessages(
  cwd: string,
  session: Session
): Promise<InstructionMessage[]> {
  const planId = session.approvedPlanId;
  if (!planId) return [];

  const artifact = await readReferencedPlanArtifact(cwd, session, planId);
  if (!artifact || artifact.status !== 'approved') return [];

  return [
    {
      role: 'system',
      layer: 'core',
      source: 'plan:approved',
      content: [
        'An approved plan is active for this session.',
        `Plan id: ${artifact.id}`,
        `Plan file: ${artifact.paths.markdown}`,
        `Approved target mode: ${artifact.approvedTargetMode ?? 'default'}`,
        'Follow this plan during execution unless current evidence proves it invalid.',
        'If you deviate from the approved plan, explain the reason in the final response.',
        ...(artifact.items.length > 0
          ? ['', 'Plan items:', ...artifact.items.map((item) => `- [${item.status}] ${item.title}`)]
          : []),
        '',
        artifact.contentMarkdown
      ].join('\n')
    }
  ];
}
