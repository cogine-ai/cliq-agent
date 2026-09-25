import assert from 'node:assert/strict';
import { test } from 'node:test';

import { digestOmitting } from '../kernel/identity.js';
import {
  decodeAdmittedContext,
  decodeContextManifest,
  decodeControlChannel,
  decodeFrozenIgnoreRules,
  decodeRunObjective,
  decodeRunSpec,
  decodeSessionProjection,
  decodeSourceManifest,
  decodeSourceProjection,
  decodeUnverifiedConsent,
  decodeVerifierSpec,
  decodeWorkspaceEntries,
  decodeWorkspaceIdentity,
  decodeWorkspaceState
} from './decoders.js';
import { KernelStorageError } from './errors.js';

const ref = (byte: string) => byte.repeat(64);

function withDigest(value: Record<string, unknown>, digestField: string): Record<string, unknown> {
  const copy = { ...value, [digestField]: '' };
  copy[digestField] = digestOmitting(copy, digestField);
  return copy;
}

function expectArtifactMismatch(fn: () => unknown, message?: RegExp | string): void {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof KernelStorageError);
    assert.equal(error.code, 'ARTIFACT_MISMATCH');
    if (message !== undefined) {
      if (typeof message === 'string') assert.match(error.message, new RegExp(message, 'i'));
      else assert.match(error.message, message);
    }
    return true;
  });
}

function expectInvalidRequest(fn: () => unknown, message?: RegExp | string): void {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof KernelStorageError);
    assert.equal(error.code, 'INVALID_REQUEST');
    if (message !== undefined) {
      if (typeof message === 'string') assert.match(error.message, new RegExp(message, 'i'));
      else assert.match(error.message, message);
    }
    return true;
  });
}

test('decodeWorkspaceIdentity accepts a live identity and rejects digest drift', () => {
  const identity = withDigest(
    {
      schemaVersion: 1,
      format: 'cliq-workspace-identity-v1',
      ownerPrincipalId: 'principal',
      platform: 'linux',
      kind: 'live',
      canonicalRootPath: '/tmp/workspace',
      rootIdentity: { deviceId: '1', fileId: '2', ownerUid: 501 }
    },
    'identityDigest'
  );
  assert.deepEqual(decodeWorkspaceIdentity(identity), identity);
  expectArtifactMismatch(
    () => decodeWorkspaceIdentity({ ...identity, identityDigest: ref('a') }),
    /digest does not rehash/
  );
  expectInvalidRequest(
    () =>
      decodeWorkspaceIdentity(
        withDigest(
          {
            schemaVersion: 1,
            format: 'cliq-workspace-identity-v1',
            ownerPrincipalId: 'principal',
            platform: 'linux',
            kind: 'legacy_unavailable',
            legacyCanonicalRootPath: '/tmp/old',
            unavailableReason: 'missing',
            observedAt: '1970-01-01T00:00:00.000Z'
          },
          'identityDigest'
        )
      ),
    /legacy_unavailable/
  );
  expectArtifactMismatch(() => decodeWorkspaceIdentity({ schemaVersion: 2 }), /wrong schema/);
});

test('decodeSessionProjection and decodeControlChannel enforce schema and digests', () => {
  const projection = withDigest(
    {
      schemaVersion: 1,
      format: 'cliq-session-context-v1',
      sessionId: 'session-1',
      contextRevision: 1,
      throughItemSeq: 0,
      segments: []
    },
    'projectionDigest'
  );
  assert.deepEqual(decodeSessionProjection(projection), projection);
  expectArtifactMismatch(
    () => decodeSessionProjection({ ...projection, projectionDigest: ref('b') }),
    /projection digest/
  );

  const channel = withDigest(
    {
      schemaVersion: 1,
      format: 'cliq-local-control-channel-identity-v1',
      principalIdentityRef: ref('1'),
      principalIdentityDigest: ref('2'),
      principalId: 'principal',
      client: 'cli',
      transport: {
        kind: 'in_process',
        processIdentityRef: ref('3'),
        processIdentityDigest: ref('4')
      },
      openedAt: '1970-01-01T00:00:00.000Z',
      channelNonceDigest: ref('5')
    },
    'channelIdentityDigest'
  );
  assert.deepEqual(decodeControlChannel(channel), channel);
  expectArtifactMismatch(() => decodeControlChannel({ ...channel, format: 'wrong' }), /wrong schema/);
});

test('decodeRunObjective and decodeAdmittedContext reject tampered digests', () => {
  const objective = withDigest(
    {
      schemaVersion: 1,
      format: 'cliq-run-objective-v1',
      utf8: 'inspect',
      byteCount: 7
    },
    'objectiveDigest'
  );
  assert.deepEqual(decodeRunObjective(objective), objective);
  expectArtifactMismatch(() => decodeRunObjective({ ...objective, utf8: 'changed' }), /objective digest/);

  const admitted = withDigest(
    {
      schemaVersion: 1,
      format: 'cliq-admitted-context-v1',
      sessionId: 'session-1',
      sessionContextRevision: 1,
      throughSessionItemSeq: 0,
      sessionProjectionRef: ref('6'),
      parentContextRefs: [],
      additionalArtifactRefs: []
    },
    'contextDigest'
  );
  assert.deepEqual(decodeAdmittedContext(admitted), admitted);
  expectArtifactMismatch(() => decodeAdmittedContext({ ...admitted, contextDigest: ref('7') }), /context digest/);
});

test('decodeContextManifest and decodeWorkspaceState bind run workspace snapshots', () => {
  const context = withDigest(
    {
      schemaVersion: 1,
      format: 'cliq-context-manifest-v1',
      runId: 'run-1',
      throughItemSeq: 0,
      admittedContextRef: ref('8'),
      segments: [],
      assemblyRef: ref('9')
    },
    'projectionDigest'
  );
  assert.deepEqual(decodeContextManifest(context), context);

  const state = withDigest(
    {
      schemaVersion: 1,
      format: 'cliq-workspace-state-v1',
      runId: 'run-1',
      baseWorkspaceManifestRef: ref('a'),
      entriesRef: ref('b'),
      invalidatedEphemeralPaths: [],
      sourceProjectionDigest: ref('c')
    },
    'stateDigest'
  );
  assert.deepEqual(decodeWorkspaceState(state), state);
  expectArtifactMismatch(() => decodeWorkspaceState({ ...state, stateDigest: ref('d') }), /state digest/);
});

test('decodeFrozenIgnoreRules, source projection, entries, and manifests reject schema drift', () => {
  const rules = withDigest(
    {
      schemaVersion: 1,
      format: 'cliq-frozen-ignore-rules-v1',
      matcherVersion: 'cliq-git-wildmatch-v1',
      sources: [],
      rules: []
    },
    'rulesDigest'
  );
  assert.deepEqual(decodeFrozenIgnoreRules(rules), rules);

  const projection = withDigest(
    {
      schemaVersion: 1,
      matcherVersion: 'cliq-exact-path-v1',
      frozenIgnoreRulesRef: ref('e'),
      frozenIgnoreRulesDigest: rules.rulesDigest,
      explicitIncludes: [],
      explicitExcludes: [],
      maxChangedPaths: 100,
      maxChangedBytes: 1024
    },
    'projectionDigest'
  );
  assert.deepEqual(decodeSourceProjection(projection), projection);

  const entries = withDigest(
    {
      schemaVersion: 1,
      format: 'cliq-workspace-entries-v1',
      entries: [],
      entryCount: 0,
      byteCount: 0
    },
    'treeDigest'
  );
  assert.deepEqual(decodeWorkspaceEntries(entries), entries);

  const source = withDigest(
    {
      schemaVersion: 1,
      format: 'cliq-source-manifest-v1',
      role: 'base',
      workspaceIdentityDigest: ref('f'),
      entriesRef: ref('g'),
      sourceProjectionRef: ref('h'),
      sourceProjectionDigest: projection.projectionDigest,
      frozenIgnoreRulesRef: ref('e'),
      frozenIgnoreRulesDigest: rules.rulesDigest,
      treeDigest: entries.treeDigest
    },
    'manifestDigest'
  );
  assert.deepEqual(decodeSourceManifest(source), source);
  expectArtifactMismatch(() => decodeSourceManifest({ ...source, format: 'other' }), /wrong schema/);
});

test('decodeVerifierSpec and decodeUnverifiedConsent enforce consent semantics', () => {
  const verifier = withDigest(
    {
      schemaVersion: 1,
      format: 'cliq-verifier-spec-v1',
      verifiers: []
    },
    'specDigest'
  );
  assert.deepEqual(decodeVerifierSpec(verifier), verifier);

  const consent = withDigest(
    {
      schemaVersion: 1,
      kind: 'direct_unverified_consent',
      principalId: 'principal',
      client: 'cli',
      channelIdentityRef: ref('i'),
      channelIdentityDigest: ref('j'),
      admissionIntentDigest: ref('k'),
      runSpecCoreDigest: ref('l'),
      allowUnverified: true,
      createdAt: '1970-01-01T00:00:00.000Z'
    },
    'consentDigest'
  );
  assert.deepEqual(decodeUnverifiedConsent(consent), consent);
  const badConsent = withDigest(
    {
      schemaVersion: 1,
      kind: 'direct_unverified_consent',
      principalId: 'principal',
      client: 'cli',
      channelIdentityRef: ref('i'),
      channelIdentityDigest: ref('j'),
      admissionIntentDigest: ref('k'),
      runSpecCoreDigest: ref('l'),
      allowUnverified: false,
      createdAt: '1970-01-01T00:00:00.000Z'
    },
    'consentDigest'
  );
  expectArtifactMismatch(() => decodeUnverifiedConsent(badConsent), /allowUnverified=true/);
});

test('decodeRunSpec rejects invalid operations and missing objective refs', () => {
  const base = {
    schemaVersion: 1,
    operation: 'agent',
    objectiveRef: ref('m'),
    admittedContextRef: ref('n'),
    baseWorkspaceManifestRef: ref('o'),
    sourceProjectionRef: ref('p'),
    assemblyRef: ref('q'),
    policyRef: ref('r'),
    sandboxProfileRef: ref('s'),
    verifierSpecRef: ref('t'),
    credentialGrantRefs: [],
    budgets: {
      wallTimeMs: 1,
      modelTokens: 2,
      costMicros: 3,
      toolCalls: 4,
      repairAttempts: 5,
      childDepth: 6,
      childConcurrency: 7
    }
  };
  assert.deepEqual(decodeRunSpec(base), base);
  expectArtifactMismatch(() => decodeRunSpec({ ...base, operation: 'other' }), /operation is invalid/);
  expectArtifactMismatch(() => decodeRunSpec({ ...base, objectiveRef: '' }), /objectiveRef/);
  expectArtifactMismatch(() => decodeRunSpec({ schemaVersion: 2 }), /schemaVersion=1/);
});
