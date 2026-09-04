import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import {
  createByteBpeTokenizer,
  type ByteBpeTokenizerAuthority,
  type TokenizerMergeRanksV1,
  type TokenizerProfileV1,
  type TokenizerVocabularyV1
} from './tokenizer.js';

function authority(): ByteBpeTokenizerAuthority {
  const tokens = Array.from({ length: 256 }, (_, tokenId) => ({
    tokenId,
    bytesBase64url: Buffer.from([tokenId]).toString('base64url')
  }));
  tokens.push(
    { tokenId: 256, bytesBase64url: Buffer.from('ab').toString('base64url') },
    { tokenId: 257, bytesBase64url: Buffer.from('abc').toString('base64url') },
    { tokenId: 258, bytesBase64url: Buffer.from('bc').toString('base64url') },
    { tokenId: 259, bytesBase64url: Buffer.from('aa').toString('base64url') },
    { tokenId: 260, bytesBase64url: Buffer.from('aaaa').toString('base64url') }
  );
  const vocabularyWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-byte-bpe-vocabulary-v1' as const,
    tokens
  };
  const vocabulary: TokenizerVocabularyV1 = {
    ...vocabularyWithoutDigest,
    vocabularyDigest: canonicalSha256(vocabularyWithoutDigest)
  };
  const vocabularyArtifact = planCanonicalArtifact(vocabulary, vocabulary.format);

  const merges = [
    { rank: 0, leftTokenId: 97, rightTokenId: 97, resultTokenId: 259 },
    { rank: 1, leftTokenId: 259, rightTokenId: 259, resultTokenId: 260 },
    { rank: 2, leftTokenId: 97, rightTokenId: 98, resultTokenId: 256 },
    { rank: 3, leftTokenId: 98, rightTokenId: 99, resultTokenId: 258 },
    { rank: 4, leftTokenId: 256, rightTokenId: 99, resultTokenId: 257 }
  ];
  const mergeRanksWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-byte-bpe-merge-ranks-v1' as const,
    merges
  };
  const mergeRanks: TokenizerMergeRanksV1 = {
    ...mergeRanksWithoutDigest,
    mergeRanksDigest: canonicalSha256(mergeRanksWithoutDigest)
  };
  const mergeRanksArtifact = planCanonicalArtifact(mergeRanks, mergeRanks.format);

  const cases: Array<[string, number[]]> = [
    ['', []],
    ['a', [97]],
    ['aa', [259]],
    ['aaaa', [260]],
    ['aaaaa', [260, 97]],
    ['ab', [256]],
    ['abc', [257]],
    ['bc', [258]]
  ];
  const profileWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-tokenizer-profile-v1' as const,
    provider: 'openai' as const,
    model: 'model-1',
    algorithm: 'cliq-byte-bpe-v1' as const,
    vocabularyRef: vocabularyArtifact.ref,
    vocabularyDigest: vocabulary.vocabularyDigest,
    mergeRanksRef: mergeRanksArtifact.ref,
    mergeRanksDigest: mergeRanks.mergeRanksDigest,
    specialTokenPolicy: 'disabled_profile_framing_only' as const,
    goldenVectors: cases.map(([input, tokenIds]) => ({
      renderedBytesBase64url: Buffer.from(input).toString('base64url'),
      tokenIds
    }))
  };
  const profile: TokenizerProfileV1 = {
    ...profileWithoutDigest,
    profileDigest: canonicalSha256(profileWithoutDigest)
  };
  return {
    profileRef: planCanonicalArtifact(profile, profile.format).ref,
    profile,
    vocabularyRef: vocabularyArtifact.ref,
    vocabulary,
    mergeRanksRef: mergeRanksArtifact.ref,
    mergeRanks
  };
}

test('byte BPE applies the globally lowest rank and leftmost occurrence on ties', () => {
  const tokenizer = createByteBpeTokenizer(authority());
  assert.deepEqual(tokenizer.tokenize(Buffer.from('abc')), [257]);
  assert.deepEqual(tokenizer.tokenize(Buffer.from('aaaaa')), [260, 97]);
  assert.equal(tokenizer.count(Buffer.from('abc')), 1);
});

test('byte BPE recognizes arbitrary bytes without special-token interpretation', () => {
  const tokenizer = createByteBpeTokenizer(authority());
  assert.deepEqual(tokenizer.tokenize(Uint8Array.of(0, 255, 10)), [0, 255, 10]);
});

test('tokenizer authority rejects artifact, semantic digest, and golden-vector substitution', () => {
  const wrongRef = authority();
  wrongRef.profileRef = 'f'.repeat(64);
  assert.throws(() => createByteBpeTokenizer(wrongRef), /does not rehash/u);

  const wrongDigest = authority();
  wrongDigest.vocabulary.vocabularyDigest = 'e'.repeat(64);
  assert.throws(() => createByteBpeTokenizer(wrongDigest), /authority does not match/u);

  const wrongGolden = authority();
  wrongGolden.profile.goldenVectors[0]!.tokenIds = [1];
  const withoutProfileDigest = { ...wrongGolden.profile };
  delete (withoutProfileDigest as Partial<TokenizerProfileV1>).profileDigest;
  wrongGolden.profile.profileDigest = canonicalSha256(withoutProfileDigest);
  wrongGolden.profileRef = planCanonicalArtifact(wrongGolden.profile, wrongGolden.profile.format).ref;
  assert.throws(() => createByteBpeTokenizer(wrongGolden), /golden vector does not match/u);

  const duplicateGolden = authority();
  duplicateGolden.profile.goldenVectors[7] = {
    renderedBytesBase64url: duplicateGolden.profile.goldenVectors[0]!.renderedBytesBase64url,
    tokenIds: [...duplicateGolden.profile.goldenVectors[0]!.tokenIds]
  };
  const duplicateProfile = { ...duplicateGolden.profile };
  delete (duplicateProfile as Partial<TokenizerProfileV1>).profileDigest;
  duplicateGolden.profile.profileDigest = canonicalSha256(duplicateProfile);
  duplicateGolden.profileRef = planCanonicalArtifact(duplicateGolden.profile, duplicateGolden.profile.format).ref;
  assert.throws(() => createByteBpeTokenizer(duplicateGolden), /golden vectors must be unique/u);
});

test('tokenizer authority rejects incomplete bytes, invalid merge closure, and unknown fields', () => {
  const incomplete = authority();
  incomplete.vocabulary.tokens.splice(255, 1);
  const vocabularyWithoutDigest = { ...incomplete.vocabulary };
  delete (vocabularyWithoutDigest as Partial<TokenizerVocabularyV1>).vocabularyDigest;
  incomplete.vocabulary.vocabularyDigest = canonicalSha256(vocabularyWithoutDigest);
  incomplete.vocabularyRef = planCanonicalArtifact(incomplete.vocabulary, incomplete.vocabulary.format).ref;
  incomplete.profile.vocabularyRef = incomplete.vocabularyRef;
  incomplete.profile.vocabularyDigest = incomplete.vocabulary.vocabularyDigest;
  const incompleteProfile = { ...incomplete.profile };
  delete (incompleteProfile as Partial<TokenizerProfileV1>).profileDigest;
  incomplete.profile.profileDigest = canonicalSha256(incompleteProfile);
  incomplete.profileRef = planCanonicalArtifact(incomplete.profile, incomplete.profile.format).ref;
  assert.throws(() => createByteBpeTokenizer(incomplete), /all 256/u);

  const badMerge = authority();
  badMerge.mergeRanks.merges[0]!.resultTokenId = 256;
  const mergeWithoutDigest = { ...badMerge.mergeRanks };
  delete (mergeWithoutDigest as Partial<TokenizerMergeRanksV1>).mergeRanksDigest;
  badMerge.mergeRanks.mergeRanksDigest = canonicalSha256(mergeWithoutDigest);
  badMerge.mergeRanksRef = planCanonicalArtifact(badMerge.mergeRanks, badMerge.mergeRanks.format).ref;
  badMerge.profile.mergeRanksRef = badMerge.mergeRanksRef;
  badMerge.profile.mergeRanksDigest = badMerge.mergeRanks.mergeRanksDigest;
  const badMergeProfile = { ...badMerge.profile };
  delete (badMergeProfile as Partial<TokenizerProfileV1>).profileDigest;
  badMerge.profile.profileDigest = canonicalSha256(badMergeProfile);
  badMerge.profileRef = planCanonicalArtifact(badMerge.profile, badMerge.profile.format).ref;
  assert.throws(() => createByteBpeTokenizer(badMerge), /result bytes/u);

  const extended = authority() as ByteBpeTokenizerAuthority & { profile: TokenizerProfileV1 & { extra?: boolean } };
  extended.profile.extra = true;
  assert.throws(() => createByteBpeTokenizer(extended), /schema is invalid/u);

  const unordered = authority();
  [unordered.vocabulary.tokens[0], unordered.vocabulary.tokens[1]] = [
    unordered.vocabulary.tokens[1]!,
    unordered.vocabulary.tokens[0]!
  ];
  const unorderedVocabulary = { ...unordered.vocabulary };
  delete (unorderedVocabulary as Partial<TokenizerVocabularyV1>).vocabularyDigest;
  unordered.vocabulary.vocabularyDigest = canonicalSha256(unorderedVocabulary);
  unordered.vocabularyRef = planCanonicalArtifact(unordered.vocabulary, unordered.vocabulary.format).ref;
  unordered.profile.vocabularyRef = unordered.vocabularyRef;
  unordered.profile.vocabularyDigest = unordered.vocabulary.vocabularyDigest;
  const unorderedProfile = { ...unordered.profile };
  delete (unorderedProfile as Partial<TokenizerProfileV1>).profileDigest;
  unordered.profile.profileDigest = canonicalSha256(unorderedProfile);
  unordered.profileRef = planCanonicalArtifact(unordered.profile, unordered.profile.format).ref;
  assert.throws(() => createByteBpeTokenizer(unordered), /ordered by token id/u);
});
