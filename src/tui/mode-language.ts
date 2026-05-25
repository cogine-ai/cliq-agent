import type { PolicyMode } from '../policy/types.js';

export type PolicyModeRisk = 'safe' | 'guarded' | 'danger';

export type PolicyModeDescription = {
  mode: PolicyMode;
  label: string;
  shortLabel: string;
  description: string;
  risk: PolicyModeRisk;
  marker: string;
  color: string;
};

const POLICY_MODE_ORDER: readonly PolicyMode[] = [
  'auto',
  'confirm-write',
  'read-only',
  'confirm-bash',
  'confirm-all'
];

const POLICY_MODE_LANGUAGE: Record<PolicyMode, PolicyModeDescription> = {
  auto: {
    mode: 'auto',
    label: 'Auto Run',
    shortLabel: 'Auto',
    description: 'Runs read, edit, and shell tools without asking first.',
    risk: 'danger',
    marker: '!',
    color: 'red'
  },
  'confirm-write': {
    mode: 'confirm-write',
    label: 'Ask Edits',
    shortLabel: 'Edits?',
    description: 'Asks before file edits and transaction apply; read and shell tools can run.',
    risk: 'guarded',
    marker: '?',
    color: 'yellow'
  },
  'read-only': {
    mode: 'read-only',
    label: 'Read Only',
    shortLabel: 'Read',
    description: 'Allows read/list/find/grep only; blocks writes, shell, and applies.',
    risk: 'safe',
    marker: '',
    color: 'cyan'
  },
  'confirm-bash': {
    mode: 'confirm-bash',
    label: 'Ask Bash',
    shortLabel: 'Bash?',
    description: 'Asks before shell commands; read and edit tools can run.',
    risk: 'guarded',
    marker: '?',
    color: 'yellow'
  },
  'confirm-all': {
    mode: 'confirm-all',
    label: 'Ask All',
    shortLabel: 'Ask',
    description: 'Asks before every tool action, including reads.',
    risk: 'guarded',
    marker: '?',
    color: 'green'
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
  return description.marker ? `${description.marker} ${description.label}` : description.label;
}

export function formatModeForHelp(mode: PolicyMode): string {
  const description = describePolicyMode(mode);
  const label = formatModeForStatus(mode);
  return `${label} (${mode}) - ${description.description}`;
}

export function getModeColor(mode: PolicyMode): string {
  return describePolicyMode(mode).color;
}
