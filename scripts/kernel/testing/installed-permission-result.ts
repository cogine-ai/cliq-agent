// Closed qualification data, never consent, a native receipt or permission.
import assert from 'node:assert/strict';
import { types } from 'node:util';

export const INSTALLED_PERMISSION_PROFILE = 'default_accept_edits_exact_verifier_delivery_v1';
export const INSTALLED_PERMISSION_CASES = ['default_repair', 'accept_edits_pass', 'required_deny', 'advisory_skip',
  'template_repair', 'template_retry', 'waiting_cancel', 'waiting_deadline'] as const;
export type InstalledPermissionCase = typeof INSTALLED_PERMISSION_CASES[number];
export type InstalledPermissionCaseResult = { kind: InstalledPermissionCase; mode: 'default' | 'accept-edits';
  status: 'succeeded' | 'completed_unverified' | 'failed' | 'cancelled'; modelPosts: number; verifierClaims: number;
  verifierApprovals: number; editApprovals: number; workerFreeWaits: number; candidateCount: number;
  originalHostUnchanged: true; originalAdmissionReplayed: true; allRecordedWorkersRetired: true };
export type InstalledPermissionReport = { diagnosticOnly: true; qualified: true; profile: typeof INSTALLED_PERMISSION_PROFILE;
  cases: InstalledPermissionCaseResult[]; exactWaitReconnectAndRestart: true; duplicateAndWrongRefChecked: true;
  sourceApprovalNotBorrowedByDelivery: true; independentVerifierAndPublicationApproval: true; actualMergedWorkspaceApplied: true;
  inheritedDeliveryNoLocalVerifier: true; explicitUnusedInheritedGrantConsumed: true; consumedGrantCannotEnterAnotherRun: true;
  authorizationExpiryBeforeAdmission: true; wrongTemplateBoundsRefused: true;
  actualProviderQualified: false; realTtyQualified: false; approvalExpiryBeforeClaimQualified: false;
  exactClaimStopCutQualified: false; allCrashCutsQualified: false; wholeI1Qualified: false };

function fields(value: unknown, keys: readonly string[]) {
  assert(value && typeof value === 'object' && !types.isProxy(value) && !Array.isArray(value));
  assert([null, Object.prototype].includes(Object.getPrototypeOf(value)));
  const descriptors = Object.getOwnPropertyDescriptors(value);
  assert.equal(Reflect.ownKeys(descriptors).length, keys.length);
  for (const key of keys) assert(descriptors[key]?.enumerable && Object.hasOwn(descriptors[key]!, 'value'));
  return Object.fromEntries(keys.map(key => [key, descriptors[key]!.value])) as Record<string, any>;
}
const positive = (value: unknown, maximum: number) => assert(Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= maximum);

/** Short diagnostic summaries cannot stand in for the campaign's actual
 * protocol, complete artifacts, /proc observations and joined resource reads. */
export function decodeInstalledPermissionReport(value: unknown): InstalledPermissionReport {
  const yes = ['diagnosticOnly', 'qualified', 'exactWaitReconnectAndRestart', 'duplicateAndWrongRefChecked',
    'sourceApprovalNotBorrowedByDelivery', 'independentVerifierAndPublicationApproval', 'actualMergedWorkspaceApplied',
    'inheritedDeliveryNoLocalVerifier', 'explicitUnusedInheritedGrantConsumed', 'consumedGrantCannotEnterAnotherRun',
    'authorizationExpiryBeforeAdmission', 'wrongTemplateBoundsRefused'];
  const no = ['actualProviderQualified', 'realTtyQualified', 'approvalExpiryBeforeClaimQualified',
    'exactClaimStopCutQualified', 'allCrashCutsQualified', 'wholeI1Qualified'];
  const row = fields(value, [...yes, ...no, 'profile', 'cases']);
  for (const key of yes) assert.equal(row[key], true);
  for (const key of no) assert.equal(row[key], false);
  assert.equal(row.profile, INSTALLED_PERMISSION_PROFILE);
  assert(Array.isArray(row.cases) && !types.isProxy(row.cases) && Object.getPrototypeOf(row.cases) === Array.prototype);
  assert.equal(row.cases.length, INSTALLED_PERMISSION_CASES.length);
  assert.equal(Reflect.ownKeys(row.cases).length, row.cases.length + 1);
  for (const [index, kind] of INSTALLED_PERMISSION_CASES.entries()) {
    const descriptor = Object.getOwnPropertyDescriptor(row.cases, String(index)); assert(descriptor && 'value' in descriptor);
    const entry = fields(descriptor.value, ['kind', 'mode', 'status', 'modelPosts', 'verifierClaims', 'verifierApprovals',
      'editApprovals', 'workerFreeWaits', 'candidateCount', 'originalHostUnchanged', 'originalAdmissionReplayed', 'allRecordedWorkersRetired']);
    assert.equal(entry.kind, kind); assert.equal(entry.mode, kind === 'default_repair' ? 'default' : 'accept-edits');
    const status = kind === 'advisory_skip' ? 'completed_unverified' : kind === 'required_deny' || kind === 'waiting_cancel'
      ? 'cancelled' : kind === 'template_retry' || kind === 'waiting_deadline' ? 'failed' : 'succeeded';
    assert.equal(entry.status, status);
    assert.equal(entry.modelPosts, kind === 'default_repair' || kind === 'template_repair' ? 4 : 2);
    assert.equal(entry.verifierClaims, kind === 'default_repair' || kind === 'template_repair' || kind === 'template_retry' ? 2
      : kind === 'accept_edits_pass' ? 1 : 0);
    assert.equal(entry.verifierApprovals, kind === 'default_repair' ? 2 : kind === 'accept_edits_pass' ? 1 : 0);
    assert.equal(entry.editApprovals, kind === 'default_repair' ? 2 : 0);
    positive(entry.workerFreeWaits, 8);
    assert.equal(entry.workerFreeWaits, kind === 'default_repair' ? 4 : kind.startsWith('template_') ? 0 : 1);
    assert.equal(entry.candidateCount, kind === 'default_repair' || kind === 'template_repair' ? 2 : 1);
    for (const key of ['originalHostUnchanged', 'originalAdmissionReplayed', 'allRecordedWorkersRetired']) assert.equal(entry[key], true);
  }
  return row as InstalledPermissionReport;
}
