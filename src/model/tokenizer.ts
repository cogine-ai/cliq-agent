import { canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { assertArtifactRef, digestOmitting } from '../kernel/identity.js';
import type { ArtifactRef, ProviderName } from '../kernel/types.js';

export type TokenizerVocabularyV1 = {
  schemaVersion: 1;
  format: 'cliq-byte-bpe-vocabulary-v1';
  tokens: Array<{ tokenId: number; bytesBase64url: string }>;
  vocabularyDigest: string;
};

export type TokenizerMergeRanksV1 = {
  schemaVersion: 1;
  format: 'cliq-byte-bpe-merge-ranks-v1';
  merges: Array<{
    rank: number;
    leftTokenId: number;
    rightTokenId: number;
    resultTokenId: number;
  }>;
  mergeRanksDigest: string;
};

export type TokenizerProfileV1 = {
  schemaVersion: 1;
  format: 'cliq-tokenizer-profile-v1';
  provider: ProviderName;
  model: string;
  algorithm: 'cliq-byte-bpe-v1';
  vocabularyRef: ArtifactRef;
  vocabularyDigest: string;
  mergeRanksRef: ArtifactRef;
  mergeRanksDigest: string;
  specialTokenPolicy: 'disabled_profile_framing_only';
  goldenVectors: Array<{ renderedBytesBase64url: string; tokenIds: number[] }>;
  profileDigest: string;
};

export type ByteBpeTokenizerAuthority = {
  profileRef: ArtifactRef;
  profile: TokenizerProfileV1;
  vocabularyRef: ArtifactRef;
  vocabulary: TokenizerVocabularyV1;
  mergeRanksRef: ArtifactRef;
  mergeRanks: TokenizerMergeRanksV1;
};

export type ByteBpeTokenizer = {
  tokenize(bytes: Uint8Array): number[];
  count(bytes: Uint8Array): number;
};

type Merge = {
  rank: number;
  resultTokenId: number;
};

type TokenNode = {
  tokenId: number;
  position: number;
  generation: number;
  alive: boolean;
  previous: TokenNode | null;
  next: TokenNode | null;
};

type MergeCandidate = {
  rank: number;
  position: number;
  left: TokenNode;
  right: TokenNode;
  leftGeneration: number;
  rightGeneration: number;
  resultTokenId: number;
};

const VOCABULARY_KEYS = ['schemaVersion', 'format', 'tokens', 'vocabularyDigest'] as const;
const TOKEN_KEYS = ['tokenId', 'bytesBase64url'] as const;
const MERGE_RANKS_KEYS = ['schemaVersion', 'format', 'merges', 'mergeRanksDigest'] as const;
const MERGE_KEYS = ['rank', 'leftTokenId', 'rightTokenId', 'resultTokenId'] as const;
const PROFILE_KEYS = [
  'schemaVersion',
  'format',
  'provider',
  'model',
  'algorithm',
  'vocabularyRef',
  'vocabularyDigest',
  'mergeRanksRef',
  'mergeRanksDigest',
  'specialTokenPolicy',
  'goldenVectors',
  'profileDigest'
] as const;
const GOLDEN_VECTOR_KEYS = ['renderedBytesBase64url', 'tokenIds'] as const;
const PROVIDERS: readonly ProviderName[] = [
  'openai',
  'anthropic',
  'openrouter',
  'openai-compatible',
  'zhipu',
  'ollama'
];
const MAX_TOKENIZER_ENTRIES = 1_000_000;
const MAX_TOKEN_BYTES = 1_048_576;

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isNonnegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function decodeBase64url(value: unknown, label: string, allowEmpty: boolean): Buffer {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0)) {
    throw new TypeError(`${label} must be canonical base64url`);
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) throw new TypeError(`${label} is not canonical base64url`);
  return bytes;
}

function pairKey(leftTokenId: number, rightTokenId: number): string {
  return `${leftTokenId}:${rightTokenId}`;
}

class CandidateHeap {
  private readonly values: MergeCandidate[] = [];

  push(value: MergeCandidate): void {
    this.values.push(value);
    let index = this.values.length - 1;
    while (index > 0) {
      const parent = Math.floor((index - 1) / 2);
      if (!this.less(this.values[index]!, this.values[parent]!)) break;
      [this.values[index], this.values[parent]] = [this.values[parent]!, this.values[index]!];
      index = parent;
    }
  }

  pop(): MergeCandidate | undefined {
    const first = this.values[0];
    const last = this.values.pop();
    if (first === undefined || last === undefined) return first;
    if (this.values.length > 0) {
      this.values[0] = last;
      let index = 0;
      while (true) {
        const left = index * 2 + 1;
        const right = left + 1;
        let smallest = index;
        if (left < this.values.length && this.less(this.values[left]!, this.values[smallest]!)) smallest = left;
        if (right < this.values.length && this.less(this.values[right]!, this.values[smallest]!)) smallest = right;
        if (smallest === index) break;
        [this.values[index], this.values[smallest]] = [this.values[smallest]!, this.values[index]!];
        index = smallest;
      }
    }
    return first;
  }

  private less(left: MergeCandidate, right: MergeCandidate): boolean {
    return left.rank < right.rank || (left.rank === right.rank && left.position < right.position);
  }
}

function compileTokenizer(
  byteTokens: readonly number[],
  merges: ReadonlyMap<string, Merge>
): ByteBpeTokenizer {
  const tokenize = (bytes: Uint8Array): number[] => {
    if (bytes.byteLength === 0) return [];
    const nodes: TokenNode[] = [...bytes].map((byte, position) => ({
      tokenId: byteTokens[byte]!,
      position,
      generation: 0,
      alive: true,
      previous: null,
      next: null
    }));
    for (let index = 0; index < nodes.length; index += 1) {
      nodes[index]!.previous = index === 0 ? null : nodes[index - 1]!;
      nodes[index]!.next = index + 1 === nodes.length ? null : nodes[index + 1]!;
    }
    const heap = new CandidateHeap();
    const offer = (left: TokenNode | null): void => {
      const right = left?.next ?? null;
      if (left === null || right === null || !left.alive || !right.alive) return;
      const merge = merges.get(pairKey(left.tokenId, right.tokenId));
      if (merge === undefined) return;
      heap.push({
        rank: merge.rank,
        position: left.position,
        left,
        right,
        leftGeneration: left.generation,
        rightGeneration: right.generation,
        resultTokenId: merge.resultTokenId
      });
    };
    for (const node of nodes) offer(node);

    while (true) {
      const candidate = heap.pop();
      if (candidate === undefined) break;
      const { left, right } = candidate;
      if (
        !left.alive ||
        !right.alive ||
        left.next !== right ||
        left.generation !== candidate.leftGeneration ||
        right.generation !== candidate.rightGeneration
      ) {
        continue;
      }
      const current = merges.get(pairKey(left.tokenId, right.tokenId));
      if (current?.rank !== candidate.rank || current.resultTokenId !== candidate.resultTokenId) continue;

      left.tokenId = candidate.resultTokenId;
      left.generation += 1;
      right.alive = false;
      right.generation += 1;
      left.next = right.next;
      if (right.next !== null) right.next.previous = left;
      offer(left.previous);
      offer(left);
    }

    const tokenIds: number[] = [];
    let current: TokenNode | null = nodes[0]!;
    while (current !== null) {
      if (current.alive) tokenIds.push(current.tokenId);
      current = current.next;
    }
    return tokenIds;
  };
  return { tokenize, count: (bytes) => tokenize(bytes).length };
}

export function createByteBpeTokenizer(authority: ByteBpeTokenizerAuthority): ByteBpeTokenizer {
  assertArtifactRef(authority.profileRef);
  assertArtifactRef(authority.vocabularyRef);
  assertArtifactRef(authority.mergeRanksRef);
  const { profile, vocabulary, mergeRanks } = authority;
  if (!isRecord(profile) || !hasExactKeys(profile, PROFILE_KEYS)) throw new TypeError('tokenizer profile schema is invalid');
  if (
    profile.schemaVersion !== 1 ||
    profile.format !== 'cliq-tokenizer-profile-v1' ||
    !PROVIDERS.includes(profile.provider) ||
    typeof profile.model !== 'string' ||
    profile.model.length === 0 ||
    normalizeCanonicalText(profile.model) !== profile.model ||
    profile.algorithm !== 'cliq-byte-bpe-v1' ||
    profile.specialTokenPolicy !== 'disabled_profile_framing_only' ||
    !Array.isArray(profile.goldenVectors) ||
    profile.goldenVectors.length < 8 ||
    profile.goldenVectors.length > 64
  ) {
    throw new TypeError('tokenizer profile values are invalid');
  }
  if (
    digestOmitting(profile, 'profileDigest') !== profile.profileDigest ||
    planCanonicalArtifact(profile, profile.format).ref !== authority.profileRef
  ) {
    throw new TypeError('tokenizer profile does not rehash');
  }

  if (!isRecord(vocabulary) || !hasExactKeys(vocabulary, VOCABULARY_KEYS)) {
    throw new TypeError('tokenizer vocabulary schema is invalid');
  }
  if (
    vocabulary.schemaVersion !== 1 ||
    vocabulary.format !== 'cliq-byte-bpe-vocabulary-v1' ||
    !Array.isArray(vocabulary.tokens) ||
    vocabulary.tokens.length < 256 ||
    vocabulary.tokens.length > MAX_TOKENIZER_ENTRIES ||
    digestOmitting(vocabulary, 'vocabularyDigest') !== vocabulary.vocabularyDigest ||
    planCanonicalArtifact(vocabulary, vocabulary.format).ref !== authority.vocabularyRef ||
    profile.vocabularyRef !== authority.vocabularyRef ||
    profile.vocabularyDigest !== vocabulary.vocabularyDigest
  ) {
    throw new TypeError('tokenizer vocabulary authority does not match');
  }

  const tokenBytes = new Map<number, Buffer>();
  const byteSequences = new Set<string>();
  const byteTokens = Array<number>(256).fill(-1);
  for (const [index, token] of vocabulary.tokens.entries()) {
    if (!isRecord(token) || !hasExactKeys(token, TOKEN_KEYS) || !isNonnegativeSafeInteger(token.tokenId)) {
      throw new TypeError('tokenizer vocabulary token is invalid');
    }
    const decoded = decodeBase64url(token.bytesBase64url, 'token bytes', false);
    if (decoded.byteLength > MAX_TOKEN_BYTES) throw new TypeError('tokenizer token bytes exceed 1 MiB');
    if (index > 0 && token.tokenId <= vocabulary.tokens[index - 1]!.tokenId) {
      throw new TypeError('tokenizer vocabulary must be ordered by token id');
    }
    const bytesKey = decoded.toString('base64url');
    if (tokenBytes.has(token.tokenId) || byteSequences.has(bytesKey)) {
      throw new TypeError('tokenizer vocabulary ids and byte sequences must be unique');
    }
    tokenBytes.set(token.tokenId, decoded);
    byteSequences.add(bytesKey);
    if (decoded.byteLength === 1) {
      const byte = decoded[0]!;
      if (byteTokens[byte] !== -1) throw new TypeError('tokenizer has duplicate one-byte tokens');
      byteTokens[byte] = token.tokenId;
    }
  }
  if (byteTokens.some((tokenId) => tokenId === -1)) {
    throw new TypeError('tokenizer vocabulary must contain all 256 one-byte tokens');
  }

  if (!isRecord(mergeRanks) || !hasExactKeys(mergeRanks, MERGE_RANKS_KEYS)) {
    throw new TypeError('tokenizer merge-ranks schema is invalid');
  }
  if (
    mergeRanks.schemaVersion !== 1 ||
    mergeRanks.format !== 'cliq-byte-bpe-merge-ranks-v1' ||
    !Array.isArray(mergeRanks.merges) ||
    mergeRanks.merges.length > MAX_TOKENIZER_ENTRIES ||
    digestOmitting(mergeRanks, 'mergeRanksDigest') !== mergeRanks.mergeRanksDigest ||
    planCanonicalArtifact(mergeRanks, mergeRanks.format).ref !== authority.mergeRanksRef ||
    profile.mergeRanksRef !== authority.mergeRanksRef ||
    profile.mergeRanksDigest !== mergeRanks.mergeRanksDigest
  ) {
    throw new TypeError('tokenizer merge-ranks authority does not match');
  }

  const merges = new Map<string, Merge>();
  const ranks = new Set<number>();
  const resultIds = new Set<number>();
  for (const [index, merge] of mergeRanks.merges.entries()) {
    if (
      !isRecord(merge) ||
      !hasExactKeys(merge, MERGE_KEYS) ||
      !isNonnegativeSafeInteger(merge.rank) ||
      !isNonnegativeSafeInteger(merge.leftTokenId) ||
      !isNonnegativeSafeInteger(merge.rightTokenId) ||
      !isNonnegativeSafeInteger(merge.resultTokenId)
    ) {
      throw new TypeError('tokenizer merge is invalid');
    }
    if (merge.rank !== index) throw new TypeError('tokenizer merge ranks must be ordered and contiguous from zero');
    const leftBytes = tokenBytes.get(merge.leftTokenId);
    const rightBytes = tokenBytes.get(merge.rightTokenId);
    const resultBytes = tokenBytes.get(merge.resultTokenId);
    if (leftBytes === undefined || rightBytes === undefined || resultBytes === undefined) {
      throw new TypeError('tokenizer merge references an unknown token');
    }
    if (!Buffer.concat([leftBytes, rightBytes]).equals(resultBytes)) {
      throw new TypeError('tokenizer merge result bytes do not equal its inputs');
    }
    const key = pairKey(merge.leftTokenId, merge.rightTokenId);
    if (merges.has(key) || ranks.has(merge.rank) || resultIds.has(merge.resultTokenId)) {
      throw new TypeError('tokenizer merge pairs, ranks, and result ids must be unique');
    }
    merges.set(key, { rank: merge.rank, resultTokenId: merge.resultTokenId });
    ranks.add(merge.rank);
    resultIds.add(merge.resultTokenId);
  }
  for (let rank = 0; rank < ranks.size; rank += 1) {
    if (!ranks.has(rank)) throw new TypeError('tokenizer merge ranks must be contiguous from zero');
  }
  for (const [tokenId, token] of tokenBytes) {
    if (token.byteLength > 1 && !resultIds.has(tokenId)) {
      throw new TypeError('every multi-byte token must be produced by one merge');
    }
  }

  const tokenizer = compileTokenizer(byteTokens, merges);
  const goldenVectors = new Set<string>();
  for (const vector of profile.goldenVectors) {
    if (!isRecord(vector) || !hasExactKeys(vector, GOLDEN_VECTOR_KEYS) || !Array.isArray(vector.tokenIds)) {
      throw new TypeError('tokenizer golden vector is invalid');
    }
    const renderedBytes = decodeBase64url(vector.renderedBytesBase64url, 'rendered golden bytes', true);
    if (renderedBytes.byteLength > MAX_TOKEN_BYTES) {
      throw new TypeError('tokenizer golden rendered bytes exceed 1 MiB');
    }
    if (!vector.tokenIds.every(isNonnegativeSafeInteger)) throw new TypeError('tokenizer golden token id is invalid');
    const vectorKey = canonicalSha256(vector);
    if (goldenVectors.has(vectorKey)) throw new TypeError('tokenizer golden vectors must be unique');
    goldenVectors.add(vectorKey);
    const actual = tokenizer.tokenize(renderedBytes);
    if (actual.length !== vector.tokenIds.length || actual.some((tokenId, index) => tokenId !== vector.tokenIds[index])) {
      throw new TypeError('tokenizer golden vector does not match');
    }
  }
  return tokenizer;
}
