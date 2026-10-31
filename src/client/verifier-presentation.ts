// Original immutable data for a human decision, never a grant, claim or
// assertion that a signed executable or native boundary has been qualified.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText, decodeWireRun } from '../kernel/control-wire-data.js';
import { digestOmitting, identityHash, normalizeAbsolutePath, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { RunSnapshotV1 } from '../kernel/types.js';

type Reader = { artifact(ref: string, options: { maxBytes: number; signal?: AbortSignal }): Promise<Buffer> };
const same = (left: unknown, right: unknown) => canonicalSha256(left) === canonicalSha256(right);
function digest(value: Record<string, unknown>, field: string) {
  if (controlWireRef(value[field]) !== digestOmitting(value, field)) throw new TypeError('verifier presentation artifact digest differs');
}
function path(value: unknown, root = false) {
  const text = controlWireText(value, 4096);
  if (!(root && text === '.') && (text.startsWith('-') || text.includes('\\') ||
      text.split('/').some(part => !part || part === '.' || part === '..' || part === '.git' || Buffer.byteLength(part) > 255)))
    throw new TypeError('verifier presentation path differs from the fixed Node profile');
  return text;
}

/** Closed verifier-launch branch of the shared waiting view. All reads bind
 * exact content addresses; server approval still checks its current authority. */
export async function readVerifierWaitingPresentation(app: Reader, snapshot: RunSnapshotV1, value: unknown, signal?: AbortSignal) {
  signal?.throwIfAborted(); assertControlWireJson(snapshot); assertControlWireJson(value);
  const run = decodeWireRun(snapshot.run), wait = controlWireRecord(value,
    ['schemaVersion', 'kind', 'runId', 'createdFromRevision', 'createdAt', 'frontierRef', 'subject']);
  if (!['agent', 'delivery'].includes(snapshot.operation) || run.status !== 'waiting' || run.waitingReason !== 'approval' || run.nextStep !== 'verify' ||
      wait.schemaVersion !== 1 || wait.kind !== 'approval' || wait.runId !== run.id || canonicalSha256(wait) !== run.waitingOnRef || wait.frontierRef !== run.frontierRef)
    throw new TypeError('verifier approval differs from its captured Run');
  controlWireInteger(wait.createdFromRevision, 1, run.revision - 1);
  const createdAt = controlWireText(wait.createdAt); parseCanonicalTime(createdAt);
  if (createdAt < run.createdAt || createdAt >= run.deadlineAt) throw new TypeError('verifier approval exceeds its Run lifetime');
  const subject = controlWireRecord(wait.subject, ['kind', 'candidateItemId', 'resultSourceRef', 'verifierPlanRef', 'verifierIndex',
    'verifierId', 'verifierSpecDigest', 'opId', 'target', 'required', 'policyChannelEvidenceRef', 'policyChannelEvidenceDigest']);
  if (subject.kind !== 'verifier_launch' || typeof subject.required !== 'boolean') throw new TypeError('invalid verifier approval subject');
  const index = controlWireInteger(subject.verifierIndex, 0, 31), id = controlWireText(subject.verifierId);
  controlWireText(subject.candidateItemId); controlWireText(subject.opId);
  for (const key of ['resultSourceRef', 'verifierPlanRef', 'verifierSpecDigest', 'target', 'policyChannelEvidenceRef', 'policyChannelEvidenceDigest']) controlWireRef(subject[key]);
  const json = async (ref: unknown) => {
    signal?.throwIfAborted(); const bytes = await app.artifact(controlWireRef(ref), { maxBytes: 1_048_576, signal }); signal?.throwIfAborted();
    if (sha256Bytes(bytes) !== ref) throw new TypeError('verifier presentation lost its complete original bytes');
    const parsed = parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    if (!canonicalJsonBytes(parsed).equals(bytes)) throw new TypeError('verifier presentation artifact is not canonical JSON');
    return parsed;
  };
  const evidence = controlWireRecord(await json(subject.policyChannelEvidenceRef), ['schemaVersion', 'format', 'principalId', 'runId', 'policyRef', 'policyDigest',
    'frontierRef', 'opId', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'actionClass', 'decisionSource', 'matchedRuleIds',
    'effectiveDisposition', 'evaluatedAt', 'evidenceDigest', 'channel', 'namedAction', 'identityKey']);
  digest(evidence, 'evidenceDigest');
  const request = controlWireRecord(await json(evidence.requestRef), ['schemaVersion', 'format', 'runId', 'opId', 'frontierRef', 'assemblyRef',
    'candidateItemId', 'verifierPlanRef', 'verifierIndex', 'targetRef', 'targetDigest', 'requestDigest']);
  digest(request, 'requestDigest');
  const target = controlWireRecord(await json(subject.target), ['schemaVersion', 'format', 'runId', 'candidateItemId', 'resultSourceRef', 'sourceDigest',
    'verifierPlanRef', 'verifierPlanDigest', 'verifierSpecRef', 'verifierSpecDigest', 'verifierIndex', 'verifierId', 'verifierVersion', 'verifierEntryDigest',
    'commandRef', 'commandDigest', 'environmentRef', 'environmentDigest', 'required', 'maxAttempts', 'targetDigest']);
  digest(target, 'targetDigest');
  const spec = controlWireRecord(await json(run.specRef), ['schemaVersion', 'operation', 'objectiveRef', 'admittedContextRef', 'baseWorkspaceManifestRef',
    'sourceProjectionRef', 'assemblyRef', 'policyRef', 'sandboxProfileRef', 'verifierSpecRef', 'credentialGrantRefs', 'budgets'], ['dependencyPolicyRef', 'unverifiedConsentRef']);
  const policy = controlWireRecord(await json(spec.policyRef), ['schemaVersion', 'format', 'principalId', 'workspaceIdentityDigest', 'mode', 'engine',
    'toolManifestRef', 'toolManifestDigest', 'decisions', 'decisionRules', 'repositoryRequestRefs', 'policyDigest', 'createdAt']);
  digest(policy, 'policyDigest');
  const frozen = controlWireRecord(await json(spec.verifierSpecRef), ['schemaVersion', 'format', 'verifiers', 'specDigest']);
  digest(frozen, 'specDigest');
  if (!Array.isArray(frozen.verifiers) || frozen.verifiers.length > 32) throw new TypeError('verifier presentation has no bounded frozen spec');
  const entry = controlWireRecord(frozen.verifiers[index], ['index', 'id', 'version', 'gate', 'commandRef', 'commandDigest', 'environmentRef', 'environmentDigest',
    'timeoutMs', 'retries', 'outputLimitBytes', 'entryDigest']);
  digest(entry, 'entryDigest');
  controlWireInteger(entry.timeoutMs, 1000, 3_600_000); controlWireInteger(entry.outputLimitBytes, 65_536, 16_777_216);
  const maxAttempts = controlWireInteger(entry.retries, 0, 3) + 1;
  const plan = controlWireRecord(await json(subject.verifierPlanRef), ['schemaVersion', 'runId', 'candidateItemId', 'resultSourceRef', 'verifierSpecRef',
    'verifierSpecDigest', 'entries', 'planDigest'], ['dependencyPlanRef']);
  digest(plan, 'planDigest');
  if (!Array.isArray(plan.entries) || plan.entries.length !== frozen.verifiers.length) throw new TypeError('verifier presentation plan differs from its frozen spec');
  const planEntry = controlWireRecord(plan.entries[index], ['index', 'verifierId', 'verifierSpecDigest', 'verifierEntryDigest', 'commandRef', 'commandDigest',
    'environmentRef', 'environmentDigest', 'required', 'maxAttempts']);
  const frontier = controlWireRecord(await json(wait.frontierRef), ['schemaVersion', 'kind', 'phase', 'candidateItemId', 'resultSourceRef', 'verifierPlanRef',
    'nextVerifierIndex', 'afterPass'], ['dependencyPlanRef']);
  const named = controlWireRecord(evidence.namedAction, ['kind', 'candidateItemId', 'verifierPlanRef', 'verifierId']);
  const keys = ['candidateItemId', 'verifierPlanRef', 'verifierIndex'] as const;
  if (evidence.schemaVersion !== 1 || evidence.format !== 'cliq-policy-channel-evidence-v1' || evidence.channel !== 'named-action' || evidence.actionClass !== 'verifier' ||
      evidence.effectiveDisposition !== 'ask' || evidence.evidenceDigest !== subject.policyChannelEvidenceDigest || evidence.runId !== run.id ||
      evidence.opId !== subject.opId || evidence.frontierRef !== wait.frontierRef || evidence.evaluatedAt !== createdAt ||
      evidence.requestDigest !== request.requestDigest || evidence.targetDigest !== target.targetDigest || evidence.targetRef !== subject.target ||
      evidence.policyRef !== spec.policyRef || evidence.policyDigest !== policy.policyDigest || evidence.principalId !== policy.principalId ||
      !['rule', 'mode_fallthrough'].includes(evidence.decisionSource as string) || !Array.isArray(evidence.matchedRuleIds) ||
      evidence.matchedRuleIds.length !== (evidence.decisionSource === 'rule' ? 1 : 0) || evidence.identityKey !== `verifier/${id}` ||
      named.kind !== 'verifier' || named.candidateItemId !== subject.candidateItemId || named.verifierPlanRef !== subject.verifierPlanRef || named.verifierId !== id ||
      request.schemaVersion !== 1 || request.format !== 'cliq-verifier-request-v1' || request.runId !== run.id || request.opId !== subject.opId ||
      request.frontierRef !== wait.frontierRef || request.assemblyRef !== spec.assemblyRef || request.targetRef !== subject.target || request.targetDigest !== target.targetDigest ||
      keys.some(key => request[key] !== subject[key] || target[key] !== subject[key]) || target.schemaVersion !== 1 || target.format !== 'cliq-verifier-target-v1' ||
      target.runId !== run.id || target.resultSourceRef !== subject.resultSourceRef || target.verifierId !== id || target.verifierSpecDigest !== subject.verifierSpecDigest ||
      target.required !== subject.required || target.maxAttempts !== maxAttempts || target.verifierPlanDigest !== plan.planDigest || target.verifierSpecRef !== spec.verifierSpecRef ||
      spec.schemaVersion !== 1 || spec.operation !== snapshot.operation || policy.schemaVersion !== 1 || policy.format !== 'cliq-run-policy-v1' ||
      !['default', 'accept-edits', 'plan', 'yolo'].includes(policy.mode as string) || frozen.schemaVersion !== 1 || frozen.format !== 'cliq-verifier-spec-v1' ||
      frozen.specDigest !== target.verifierSpecDigest || entry.index !== index || entry.id !== id || entry.version !== target.verifierVersion ||
      !['required', 'advisory'].includes(entry.gate as string) || (entry.gate === 'required') !== subject.required || entry.entryDigest !== target.verifierEntryDigest ||
      ['commandRef', 'commandDigest', 'environmentRef', 'environmentDigest'].some(key => entry[key] !== target[key] || planEntry[key] !== target[key]) ||
      planEntry.index !== index || planEntry.verifierId !== id || planEntry.verifierSpecDigest !== target.verifierSpecDigest || planEntry.verifierEntryDigest !== entry.entryDigest ||
      planEntry.required !== subject.required || planEntry.maxAttempts !== maxAttempts || plan.schemaVersion !== 1 || plan.runId !== run.id ||
      plan.candidateItemId !== subject.candidateItemId || plan.resultSourceRef !== subject.resultSourceRef || plan.verifierSpecRef !== spec.verifierSpecRef || plan.verifierSpecDigest !== target.verifierSpecDigest ||
      subject.opId !== identityHash('cliq-verifier-operation-v1', run.id, subject.candidateItemId, subject.verifierPlanRef, String(index)) ||
      frontier.schemaVersion !== 1 || frontier.kind !== 'verify' || frontier.phase !== 'verifiers' || frontier.candidateItemId !== subject.candidateItemId ||
      frontier.resultSourceRef !== subject.resultSourceRef || frontier.verifierPlanRef !== subject.verifierPlanRef || frontier.nextVerifierIndex !== index ||
      frontier.afterPass !== (snapshot.operation === 'delivery' ? 'delivery_approval' : 'finalize') ||
      frontier.dependencyPlanRef !== plan.dependencyPlanRef || (spec.dependencyPolicyRef !== undefined) !== (plan.dependencyPlanRef !== undefined))
    throw new TypeError('verifier approval substitutes its original candidate, request, plan, spec or policy');
  const command = controlWireRecord(await json(target.commandRef), ['schemaVersion', 'format', 'verifierId', 'verifierVersion', 'executable', 'argv', 'cwd', 'commandDigest']);
  digest(command, 'commandDigest');
  const executable = controlWireRecord(command.executable, ['kind', 'guestToolchainManifestRef', 'guestToolchainManifestDigest', 'toolId', 'executionPath', 'executableDigest', 'abiFingerprint']);
  const environment = controlWireRecord(await json(target.environmentRef), ['schemaVersion', 'format', 'verifierId', 'verifierVersion', 'commandRef', 'commandDigest', 'variables',
    'writableEphemeralPaths', 'sourceProjectionRef', 'sourceAccess', 'networkAccess', 'sandboxProfile', 'runtimeBundleRef', 'runtimeBundleManifestDigest',
    'guestToolchainManifestRef', 'guestToolchainManifestDigest', 'environmentDigest']);
  digest(environment, 'environmentDigest');
  if (!Array.isArray(command.argv) || command.argv.length !== 3) throw new TypeError('verifier presentation requires the fixed Node argv');
  const argv = command.argv.map(value => { const literal = controlWireRecord(value, ['kind', 'value']);
    if (literal.kind !== 'non_secret_literal') throw new TypeError('verifier command contains another argument kind');
    return controlWireText(literal.value, 8192, 0); });
  const check = path(argv[2]), cwd = path(command.cwd, true);
  for (const key of ['guestToolchainManifestRef', 'guestToolchainManifestDigest', 'executableDigest']) controlWireRef(executable[key]);
  for (const key of ['runtimeBundleRef', 'runtimeBundleManifestDigest']) controlWireRef(environment[key]);
  const executionPath = controlWireText(executable.executionPath, 4096); controlWireText(executable.abiFingerprint);
  if (command.schemaVersion !== 1 || command.format !== 'cliq-verifier-command-v1' || command.verifierId !== id || command.verifierVersion !== entry.version ||
      command.commandDigest !== target.commandDigest || executable.kind !== 'guest_toolchain' || executable.toolId !== 'node' || normalizeAbsolutePath(executionPath) !== executionPath ||
      argv[0] !== '--test' || argv[1] !== '--test-concurrency=1' || !check.endsWith('.mjs') || environment.schemaVersion !== 1 ||
      environment.format !== 'cliq-verifier-environment-v1' || environment.verifierId !== id || environment.verifierVersion !== entry.version ||
      environment.environmentDigest !== target.environmentDigest || environment.commandRef !== target.commandRef || environment.commandDigest !== target.commandDigest ||
      environment.sourceProjectionRef !== spec.sourceProjectionRef || environment.sourceAccess !== 'read_only' || environment.networkAccess !== 'denied' ||
      environment.sandboxProfile !== 'cliq-verifier-readonly-v1' || !same(environment.variables, []) || !same(environment.writableEphemeralPaths, []) ||
      environment.guestToolchainManifestRef !== executable.guestToolchainManifestRef || environment.guestToolchainManifestDigest !== executable.guestToolchainManifestDigest)
    throw new TypeError('verifier approval substitutes its fixed Node command or read-only environment');
  signal?.throwIfAborted();
  return Object.freeze({ waitingOnRef: run.waitingOnRef!, text: `Run ${JSON.stringify(id)} (${subject.required ? 'required' : 'advisory'}) for this exact candidate?\n` +
    `Command: node ${argv.map(value => JSON.stringify(value)).join(' ')}\nWorking directory: ${JSON.stringify(cwd)}\n` +
    `Candidate: ${JSON.stringify(subject.candidateItemId)}\nSource SHA-256: ${subject.resultSourceRef}\n` +
    `Scope: read-only source, no network; up to ${maxAttempts} dispatched attempt${maxAttempts === 1 ? '' : 's'} for this candidate.\n` +
    (subject.required ? 'Deny cancels this Run without executing the required check.' : 'Deny skips this advisory check without executing it.') });
}
