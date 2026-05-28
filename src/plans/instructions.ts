import type { InstructionMessage } from '../instructions/types.js';
import type { Session } from '../session/types.js';
import { readReferencedPlanArtifact, readReferencedPlanProgress } from './store.js';

export async function buildApprovedPlanInstructionMessages(
  cwd: string,
  session: Session
): Promise<InstructionMessage[]> {
  const planId = session.approvedPlanId;
  if (!planId) return [];

  const artifact = await readReferencedPlanArtifact(cwd, session, planId);
  if (!artifact || artifact.status !== 'approved') return [];
  const progress = await readReferencedPlanProgress(cwd, session, planId);

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
        'Use the todo action to keep this tracker current during execution.',
        'Todo action shape: {"todo":{"planId":"<plan id>","items":[{"id":"<item id>","title":"<title>","status":"pending|in_progress|completed","activeForm":"<present tense work description>"}]}}.',
        'Each todo action replaces the full tracker list, so include every current tracker item on every update.',
        'Mark an item in_progress before starting it, mark it completed immediately after finishing it, and keep at most one item in_progress.',
        'Do not mark an item completed when tests fail, implementation is partial, dependencies are missing, or blockers remain.',
        ...(artifact.items.length > 0
          ? ['', 'Plan items:', ...artifact.items.map((item) => `- [${item.status}] ${item.title}`)]
          : []),
        ...(progress && progress.items.length > 0
          ? [
              '',
              'Plan execution tracker:',
              ...progress.items.map((item) => {
                const active = item.status === 'in_progress' ? ` - ${item.activeForm}` : '';
                return `- [${item.status}] ${item.title}${active}`;
              })
            ]
          : []),
        '',
        artifact.contentMarkdown
      ].join('\n')
    }
  ];
}
