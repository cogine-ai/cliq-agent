// Pure data/report and owned-response checks only. These do not qualify an
// installed process, authenticated consent, native retirement or a real TTY.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createInstalledPermissionResponder } from './installed-permission-journey.js';
import { decodeInstalledPermissionReport } from './installed-permission-result.js';

const valid = () => ({ diagnosticOnly: true, qualified: true, profile: 'default_accept_edits_exact_verifier_delivery_v1',
  exactWaitReconnectAndRestart: true, duplicateAndWrongRefChecked: true, sourceApprovalNotBorrowedByDelivery: true,
  independentVerifierAndPublicationApproval: true, actualMergedWorkspaceApplied: true, inheritedDeliveryNoLocalVerifier: true,
  explicitUnusedInheritedGrantConsumed: true, consumedGrantCannotEnterAnotherRun: true, authorizationExpiryBeforeAdmission: true,
  wrongTemplateBoundsRefused: true, actualProviderQualified: false, realTtyQualified: false, approvalExpiryBeforeClaimQualified: false,
  exactClaimStopCutQualified: false, allCrashCutsQualified: false, wholeI1Qualified: false,
  cases: [
    { kind: 'default_repair', mode: 'default', status: 'succeeded', modelPosts: 4, verifierClaims: 2, verifierApprovals: 2, editApprovals: 2, workerFreeWaits: 4, candidateCount: 2 },
    { kind: 'accept_edits_pass', mode: 'accept-edits', status: 'succeeded', modelPosts: 2, verifierClaims: 1, verifierApprovals: 1, editApprovals: 0, workerFreeWaits: 1, candidateCount: 1 },
    { kind: 'required_deny', mode: 'accept-edits', status: 'cancelled', modelPosts: 2, verifierClaims: 0, verifierApprovals: 0, editApprovals: 0, workerFreeWaits: 1, candidateCount: 1 },
    { kind: 'advisory_skip', mode: 'accept-edits', status: 'completed_unverified', modelPosts: 2, verifierClaims: 0, verifierApprovals: 0, editApprovals: 0, workerFreeWaits: 1, candidateCount: 1 },
    { kind: 'template_repair', mode: 'accept-edits', status: 'succeeded', modelPosts: 4, verifierClaims: 2, verifierApprovals: 0, editApprovals: 0, workerFreeWaits: 0, candidateCount: 2 },
    { kind: 'template_retry', mode: 'accept-edits', status: 'failed', modelPosts: 2, verifierClaims: 2, verifierApprovals: 0, editApprovals: 0, workerFreeWaits: 0, candidateCount: 1 },
    { kind: 'waiting_cancel', mode: 'accept-edits', status: 'cancelled', modelPosts: 2, verifierClaims: 0, verifierApprovals: 0, editApprovals: 0, workerFreeWaits: 1, candidateCount: 1 },
    { kind: 'waiting_deadline', mode: 'accept-edits', status: 'failed', modelPosts: 2, verifierClaims: 0, verifierApprovals: 0, editApprovals: 0, workerFreeWaits: 1, candidateCount: 1 },
  ].map(row => ({ ...row, originalHostUnchanged: true, originalAdmissionReplayed: true, allRecordedWorkersRetired: true })) });

test('permission report preserves the complete fixed outcome order and unqualified physical gaps', () => {
  const report = decodeInstalledPermissionReport(valid());
  assert.equal(report.cases.length, 8); assert.equal(report.cases[0]!.verifierApprovals, 2);
  assert.equal(report.realTtyQualified, false); assert.equal(report.approvalExpiryBeforeClaimQualified, false);
  assert.equal(report.exactClaimStopCutQualified, false); assert.equal(report.wholeI1Qualified, false);
});

test('permission report refuses reduced, reordered, inflated or borrowed evidence', () => {
  const mutations: Array<(row: any) => void> = [
    row => { row.cases.pop(); }, row => { row.cases.reverse(); }, row => { row.cases.push(row.cases[0]); },
    row => { row.cases[0].verifierApprovals = 1; }, row => { row.cases[0].editApprovals = 0; },
    ...[0, 1, 2, 3].map(count => (row: any) => { row.cases[0].workerFreeWaits = count; }),
    ...[1, 2, 3, 4, 8].flatMap(count => [4, 5].map(index => (row: any) => { row.cases[index].workerFreeWaits = count; })),
    row => { row.cases[2].verifierClaims = 1; }, row => { row.cases[3].status = 'succeeded'; },
    row => { row.cases[4].candidateCount = 1; }, row => { row.cases[5].verifierClaims = 3; },
    row => { row.cases[6].workerFreeWaits = 0; }, row => { row.cases[7].status = 'succeeded'; },
    row => { row.cases[0].originalHostUnchanged = false; }, row => { row.cases[0].allRecordedWorkersRetired = false; },
    row => { row.actualProviderQualified = true; }, row => { row.realTtyQualified = true; },
    row => { row.approvalExpiryBeforeClaimQualified = true; }, row => { row.exactClaimStopCutQualified = true; },
    row => { row.sourceApprovalNotBorrowedByDelivery = false; }, row => { row.explicitUnusedInheritedGrantConsumed = false; },
    row => { row.authorizationExpiryBeforeAdmission = false; }, row => { row.wholeI1Qualified = true; },
    row => { row.rawOutput = 'untrusted output'; }, row => { row.cases[0].rawPath = '/untrusted'; },
    row => { row.cases[1].workerFreeWaits = NaN; }, row => { row.cases[1].workerFreeWaits = 9; },
  ];
  for (const mutate of mutations) { const row = valid(); mutate(row); assert.throws(() => decodeInstalledPermissionReport(row)); }
});

test('permission report rejects proxies, accessors, sparse arrays and foreign prototypes without reading them', () => {
  let reads = 0;
  const getter = valid(); Object.defineProperty(getter, 'qualified', { enumerable: true, get() { reads++; return true; } });
  assert.throws(() => decodeInstalledPermissionReport(getter));
  const proxy = new Proxy(valid(), { get() { reads++; throw new Error('must not execute'); } });
  assert.throws(() => decodeInstalledPermissionReport(proxy));
  const row = valid(); Object.defineProperty(row.cases, '0', { get() { reads++; return row.cases[1]; } });
  assert.throws(() => decodeInstalledPermissionReport(row)); assert.equal(reads, 0);
  const sparse = valid(); delete sparse.cases[0]; assert.throws(() => decodeInstalledPermissionReport(sparse));
  const foreign = Object.assign(Object.create({ raw: 'outside the closed report' }), valid()); assert.throws(() => decodeInstalledPermissionReport(foreign));
});

const body = (kind: string, replies: any[] = []) => ({ tools: [{ function: { name: 'edit' } }], messages: [
  { role: 'user', content: `Owned ordinary permission case: ${kind}. Change only example.txt; keep check.test.mjs unchanged.` }, ...replies] });

test('owned permission replies require the exact fixed objective, tools and bounded repair diagnostic', () => {
  const responder = createInstalledPermissionResponder('owned-model', () => ['edit']); responder.begin('default_repair');
  assert.equal(responder.respond(body('foreign')), undefined);
  const first = responder.respond(body('default_repair'))!;
  assert.equal(first.choices[0].message.tool_calls[0].function.name, 'edit');
  assert.deepEqual(JSON.parse(first.choices[0].message.tool_calls[0].function.arguments), { path: 'example.txt',
    old_text: 'before the owned ordinary permission edit\n', new_text: 'first owned candidate fails its required assertion\n' });
  responder.respond(body('default_repair', [{ role: 'tool', tool_call_id: 'owned-permission-edit-1' }]));
  const third = responder.respond(body('default_repair', [{ role: 'tool', tool_call_id: 'owned-permission-edit-1' },
    { role: 'user', content: 'Verifier "node-tests" failed an assertion (exit 1). Revise the candidate and try again.' }]))!;
  assert.equal(JSON.parse(third.choices[0].message.tool_calls[0].function.arguments).new_text, 'after the owned ordinary permission repair\n');
  responder.respond(body('default_repair', [{ role: 'tool', tool_call_id: 'owned-permission-edit-3' }]));
  assert.equal(responder.posts('default_repair'), 4);
  assert.throws(() => responder.respond(body('default_repair')));
});

test('owned permission responder cannot authorize an unstarted case, extra tool or repair without a real diagnostic', () => {
  const unused = createInstalledPermissionResponder('owned-model', () => ['edit']);
  assert.throws(() => unused.respond(body('accept_edits_pass')));
  const extra = createInstalledPermissionResponder('owned-model', () => ['edit']); extra.begin('accept_edits_pass');
  const changed = body('accept_edits_pass'); changed.tools.push({ function: { name: 'bash' } }); assert.throws(() => extra.respond(changed));
  const missing = createInstalledPermissionResponder('owned-model', () => ['edit']); missing.begin('template_repair');
  missing.respond(body('template_repair')); missing.respond(body('template_repair', [{ role: 'tool', tool_call_id: 'owned-permission-edit-1' }]));
  assert.throws(() => missing.respond(body('template_repair', [{ role: 'tool', tool_call_id: 'owned-permission-edit-1' }])));
});
