#ifndef CLIQ_WORKER_SHA256_H
#define CLIQ_WORKER_SHA256_H
/* Reused from the existing Linux qualification probe, not a new algorithm. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#if defined(__x86_64__) && !defined(__ILP32__) && defined(__GNUC__)
#include <cpuid.h>
#include <immintrin.h>
#define CLIQ_SHA256_X86_INTRINSICS 1
#endif

static inline int sha256_x86_features_supported(uint32_t maximum_leaf, uint32_t leaf1_ecx, uint32_t leaf7_ebx) {
    const uint32_t required_leaf1 = (UINT32_C(1) << 9) | (UINT32_C(1) << 19);
    return maximum_leaf >= 7 && (leaf1_ecx & required_leaf1) == required_leaf1 &&
           (leaf7_ebx & (UINT32_C(1) << 29)) != 0;
}

static inline int sha256_x86_available(void) {
#if defined(CLIQ_SHA256_X86_INTRINSICS)
    unsigned int maximum = __get_cpuid_max(0, NULL), a, b, c, d;
    if (maximum < 7) return 0;
    __cpuid(1, a, b, c, d);
    uint32_t leaf1 = c;
    __cpuid_count(7, 0, a, b, c, d);
    return sha256_x86_features_supported(maximum, leaf1, b);
#else
    return 0;
#endif
}

struct sha256_context {
    uint8_t data[64];
    uint32_t state[8];
    uint64_t bit_length;
    size_t data_length;
    /* Selected once per context, not per block; by-value snapshots retain it.
     * No process-global mutable dispatch state or loader/IFUNC dependency. */
    unsigned char use_x86_sha;
};

static const uint32_t sha256_constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2
};

static inline uint32_t rotate_right(uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32 - bits));
}

static inline void sha256_transform_portable(struct sha256_context *context, const uint8_t block[64]) {
    uint32_t words[64];
    for (size_t index = 0; index < 16; index++) {
        words[index] = ((uint32_t)block[index * 4] << 24) |
                       ((uint32_t)block[index * 4 + 1] << 16) |
                       ((uint32_t)block[index * 4 + 2] << 8) |
                       (uint32_t)block[index * 4 + 3];
    }
    for (size_t index = 16; index < 64; index++) {
        uint32_t s0 = rotate_right(words[index - 15], 7) ^ rotate_right(words[index - 15], 18) ^
                      (words[index - 15] >> 3);
        uint32_t s1 = rotate_right(words[index - 2], 17) ^ rotate_right(words[index - 2], 19) ^
                      (words[index - 2] >> 10);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    uint32_t a = context->state[0], b = context->state[1], c = context->state[2],
             d = context->state[3], e = context->state[4], f = context->state[5],
             g = context->state[6], h = context->state[7];
    for (size_t index = 0; index < 64; index++) {
        uint32_t sigma1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t temporary1 = h + sigma1 + choice + sha256_constants[index] + words[index];
        uint32_t sigma0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = sigma0 + majority;
        h = g; g = f; f = e; e = d + temporary1; d = c; c = b; b = a; a = temporary1 + temporary2;
    }
    context->state[0] += a; context->state[1] += b; context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f; context->state[6] += g; context->state[7] += h;
}

#if defined(CLIQ_SHA256_X86_INTRINSICS)
/* Original implementation of FIPS 180-4's SHA-256 compression using Intel's
 * SHA instruction semantics. Only this function may contain extended ISA
 * instructions; callers retain the baseline compiler target and real CPUID
 * gate. SSSE3 performs byte/word alignment; SSE4.1 extracts state lanes. */
__attribute__((target("sha,ssse3,sse4.1"), noinline))
static void sha256_transform_x86(struct sha256_context *context, const uint8_t block[64]) {
    const __m128i endian = _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
    __m128i messages[4];
    for (size_t i = 0; i < 4; i++)
        messages[i] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(block + i * 16)), endian);

    /* SHA256RNDS2 orders low-to-high lanes as F,E,B,A and H,G,D,C. */
    __m128i abef = _mm_set_epi32((int)context->state[0], (int)context->state[1],
                               (int)context->state[4], (int)context->state[5]);
    __m128i cdgh = _mm_set_epi32((int)context->state[2], (int)context->state[3],
                               (int)context->state[6], (int)context->state[7]);
    for (size_t group = 0; group < 16; group++) {
        size_t slot = group & 3;
        if (group >= 4) {
            __m128i scheduled = _mm_sha256msg1_epu32(messages[slot], messages[(slot + 1) & 3]);
            __m128i previous = _mm_alignr_epi8(messages[(slot + 3) & 3], messages[(slot + 2) & 3], 4);
            scheduled = _mm_add_epi32(scheduled, previous);
            messages[slot] = _mm_sha256msg2_epu32(scheduled, messages[(slot + 3) & 3]);
        }
        __m128i wk = _mm_add_epi32(messages[slot],
                                 _mm_loadu_si128((const __m128i *)(sha256_constants + group * 4)));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_srli_si128(wk, 8));
    }
    context->state[0] += (uint32_t)_mm_extract_epi32(abef, 3);
    context->state[1] += (uint32_t)_mm_extract_epi32(abef, 2);
    context->state[2] += (uint32_t)_mm_extract_epi32(cdgh, 3);
    context->state[3] += (uint32_t)_mm_extract_epi32(cdgh, 2);
    context->state[4] += (uint32_t)_mm_extract_epi32(abef, 1);
    context->state[5] += (uint32_t)_mm_extract_epi32(abef, 0);
    context->state[6] += (uint32_t)_mm_extract_epi32(cdgh, 1);
    context->state[7] += (uint32_t)_mm_extract_epi32(cdgh, 0);
}
#endif

static inline void sha256_transform(struct sha256_context *context, const uint8_t block[64]) {
#if defined(CLIQ_SHA256_X86_INTRINSICS)
    if (context->use_x86_sha) { sha256_transform_x86(context, block); return; }
#endif
    sha256_transform_portable(context, block);
}

static inline void sha256_init(struct sha256_context *context) {
    context->data_length = 0;
    context->bit_length = 0;
    context->use_x86_sha = (unsigned char)sha256_x86_available();
    uint32_t initial[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memcpy(context->state, initial, sizeof(initial));
}

static inline void sha256_update(struct sha256_context *context, const uint8_t *data, size_t length) {
    if (length == 0) return;
    if (context->data_length != 0) {
        size_t wanted = 64 - context->data_length;
        size_t count = length < wanted ? length : wanted;
        if (count != 0) memcpy(context->data + context->data_length, data, count);
        context->data_length += count; data += count; length -= count;
        if (context->data_length == 64) {
            sha256_transform(context, context->data);
            context->bit_length += 512;
            context->data_length = 0;
        }
    }
    while (length >= 64) {
        sha256_transform(context, data);
        context->bit_length += 512;
        data += 64; length -= 64;
    }
    if (length != 0) {
        memcpy(context->data, data, length);
        context->data_length = length;
    }
}

static inline void sha256_final(struct sha256_context *context, uint8_t digest[32]) {
    size_t index = context->data_length;
    context->data[index++] = 0x80;
    if (index > 56) {
        while (index < 64) context->data[index++] = 0;
        sha256_transform(context, context->data);
        index = 0;
    }
    while (index < 56) context->data[index++] = 0;
    context->bit_length += context->data_length * 8;
    for (size_t offset = 0; offset < 8; offset++) {
        context->data[63 - offset] = (uint8_t)(context->bit_length >> (offset * 8));
    }
    sha256_transform(context, context->data);
    for (size_t word = 0; word < 8; word++) {
        digest[word * 4] = (uint8_t)(context->state[word] >> 24);
        digest[word * 4 + 1] = (uint8_t)(context->state[word] >> 16);
        digest[word * 4 + 2] = (uint8_t)(context->state[word] >> 8);
        digest[word * 4 + 3] = (uint8_t)context->state[word];
    }
}


#undef CLIQ_SHA256_X86_INTRINSICS
#endif
