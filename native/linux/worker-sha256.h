#ifndef CLIQ_WORKER_SHA256_H
#define CLIQ_WORKER_SHA256_H
/* Reused from the existing Linux qualification probe, not a new algorithm. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
struct sha256_context {
    uint8_t data[64];
    uint32_t state[8];
    uint64_t bit_length;
    size_t data_length;
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

static inline void sha256_transform(struct sha256_context *context, const uint8_t block[64]) {
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

static inline void sha256_init(struct sha256_context *context) {
    context->data_length = 0;
    context->bit_length = 0;
    uint32_t initial[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memcpy(context->state, initial, sizeof(initial));
}

static inline void sha256_update(struct sha256_context *context, const uint8_t *data, size_t length) {
    for (size_t index = 0; index < length; index++) {
        context->data[context->data_length++] = data[index];
        if (context->data_length == 64) {
            sha256_transform(context, context->data);
            context->bit_length += 512;
            context->data_length = 0;
        }
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


#endif
