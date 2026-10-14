import type { PolicyMode } from '../policy/types.js';
import { semanticStyle, type SemanticTone } from './semantic-styles.js';

export type PolicyModeRisk = 'safe' | 'guarded' | 'danger';

export type PolicyModeDescription = {
  mode: PolicyMode;
  label: string;
  shortLabel: string;
  description: string;
  risk: PolicyModeRisk;
  tone: SemanticTone;
};

const POLICY_MODE_ORDER: readonly PolicyMode[] = [
  'default',
  'accept-edits',
  'plan',
  'yolo'
];

const POLICY_MODE_LANGUAGE: Record<PolicyMode, PolicyModeDescription> = {
  default: {
    mode: 'default',
    label: 'Default',
    shortLabel: 'Default',
    description: 'Asks before edits, shell commands, transaction apply, and permission requests.',
    risk: 'guarded',
    tone: 'warning'
  },
  'accept-edits': {
    mode: 'accept-edits',
    label: 'Accept Edits',
    shortLabel: 'Edits',
    description: 'Allows edits and successful transaction apply; asks before shell commands.',
    risk: 'guarded',
    tone: 'info'
  },
  plan: {
    mode: 'plan',
    label: 'Plan',
    shortLabel: 'Plan',
    description: 'Allows inspection and planning; blocks edits, shell commands, and transaction apply.',
    risk: 'safe',
    tone: 'safe'
  },
  yolo: {
    mode: 'yolo',
    label: 'YOLO',
    shortLabel: 'YOLO',
    description: 'Auto-approves normal tool calls and permission requests; deny rules still apply.',
    risk: 'danger',
    tone: 'danger'
  }
};

export function describePolicyMode(mode: PolicyMode): PolicyModeDescription {
  return POLICY_MODE_LANGUAGE[mode];
}

export function listPolicyModeDescriptions(): PolicyModeDescription[] {
  return POLICY_MODE_ORDER.map((mode) => describePolicyMode(mode));
}

export function formatModeForStatus(mode: PolicyMode): string {
  const description = describePolicyMode(mode);
  return `${semanticStyle(description.tone).marker} ${description.label}`;
}

export function formatModeForComposer(mode: PolicyMode): string {
  const description = describePolicyMode(mode);
  return `${semanticStyle(description.tone).marker} ${description.label} Mode`;
}

export function formatModeForHelp(mode: PolicyMode): string {
  const description = describePolicyMode(mode);
  const label = formatModeForStatus(mode);
  return `${label} (${mode}) - ${description.description}`;
}

export function getModeColor(mode: PolicyMode): string {
  return semanticStyle(describePolicyMode(mode).tone).color;
}

export function getModeTone(mode: PolicyMode): SemanticTone {
  return describePolicyMode(mode).tone;
}
