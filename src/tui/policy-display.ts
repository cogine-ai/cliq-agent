import type { PolicyMode } from '../policy/types.js';

export type PolicyModeSeverity = 'safe' | 'guarded' | 'caution' | 'danger';

export type PolicyModeDisplay = {
  label: string;
  description: string;
  severity: PolicyModeSeverity;
  color: string;
};

export const POLICY_MODE_ORDER: readonly PolicyMode[] = [
  'read-only',
  'confirm-all',
  'confirm-write',
  'confirm-bash',
  'auto'
];

export const POLICY_MODE_DISPLAY: Record<PolicyMode, PolicyModeDisplay> = {
  'read-only': {
    label: 'plan',
    description: 'allow read tools only; block writes, shell, permission requests, and transaction apply',
    severity: 'safe',
    color: 'cyan'
  },
  'confirm-all': {
    label: 'ask all',
    description: 'ask before every tool, permission request, and transaction apply',
    severity: 'guarded',
    color: 'green'
  },
  'confirm-write': {
    label: 'ask edits',
    description: 'ask before writes, permission requests, and transaction apply; allow reads and shell',
    severity: 'caution',
    color: 'yellow'
  },
  'confirm-bash': {
    label: 'ask shell',
    description: 'ask before shell and permission requests; allow reads, writes, and transaction apply',
    severity: 'caution',
    color: 'yellow'
  },
  auto: {
    label: 'auto run',
    description: 'run tools, permission requests, and transaction apply without confirmation',
    severity: 'danger',
    color: 'red'
  }
};

export function getPolicyModeDisplay(mode: PolicyMode): PolicyModeDisplay {
  return POLICY_MODE_DISPLAY[mode];
}

export function formatPolicyModeSummary(mode: PolicyMode): string {
  const display = getPolicyModeDisplay(mode);
  return `${display.label} (${mode})`;
}

export function formatPolicyModeDetail(mode: PolicyMode): string {
  return `${formatPolicyModeSummary(mode)}: ${getPolicyModeDisplay(mode).description}`;
}

export function formatPolicyModeList(modes: readonly PolicyMode[] = POLICY_MODE_ORDER): string {
  return modes.map(formatPolicyModeSummary).join(', ');
}

export function formatPolicyModeLabels(modes: readonly PolicyMode[]): string {
  return modes.map((mode) => getPolicyModeDisplay(mode).label).join(' → ');
}
