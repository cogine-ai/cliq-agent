/* Pure algorithm vectors; SHA-NI executes only when real CPUID permits it.
 * Neither backend's vectors qualify Linux startup or containment. */
#include "worker-sha256.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

static void check_cpu_feature_selection(void) {
    /* Pure CPUID data only. This cannot make unsupported hardware execute an
     * instruction: the real backend is selected separately by sha256_init. */
    for (unsigned int mask = 0; mask < 8; mask++) {
        uint32_t leaf1 = ((mask & 1u) ? UINT32_C(1) << 9 : 0) |
                         ((mask & 2u) ? UINT32_C(1) << 19 : 0);
        uint32_t leaf7 = (mask & 4u) ? UINT32_C(1) << 29 : 0;
        assert(sha256_x86_features_supported(7, leaf1, leaf7) == (mask == 7));
    }
    const uint32_t leaf1 = (UINT32_C(1) << 9) | (UINT32_C(1) << 19);
    const uint32_t leaf7 = UINT32_C(1) << 29;
    assert(!sha256_x86_features_supported(0, leaf1, leaf7));
    assert(!sha256_x86_features_supported(1, leaf1, leaf7));
    assert(!sha256_x86_features_supported(6, leaf1, leaf7));
    assert(sha256_x86_features_supported(31, leaf1 | 1u, leaf7 | 1u));
}

static void check_digest(const uint8_t *bytes, size_t length, const char expected[65]) {
    static const size_t chunks[] = { 0, 1, 2, 3, 7, 31, 55, 56, 63, 64, 65, 127, 1024, 65536 };
    static const char digits[] = "0123456789abcdef";
    for (unsigned int portable = 0; portable < 2; portable++)
    for (size_t selected = 0; selected < sizeof(chunks) / sizeof(chunks[0]); selected++) {
        struct sha256_context hash;
        memset(&hash, 0xa5, sizeof(hash)); sha256_init(&hash);
        assert(hash.use_x86_sha == sha256_x86_available());
#if !defined(__x86_64__) || defined(__ILP32__)
        assert(hash.use_x86_sha == 0);
#endif
        if (portable) hash.use_x86_sha = 0;
        sha256_update(&hash, NULL, 0);
        size_t offset = 0, chunk = chunks[selected] == 0 ? length : chunks[selected];
        while (offset < length) {
            size_t count = length - offset < chunk ? length - offset : chunk;
            sha256_update(&hash, bytes + offset, count); offset += count;
            assert(hash.data_length == offset % 64 && hash.bit_length == (uint64_t)(offset / 64) * 512);
            /* Both NULL+0 and a zero-length pointer at a partial tail retain
             * the original update contract, without padding or a new block. */
            sha256_update(&hash, NULL, 0); sha256_update(&hash, bytes + offset, 0);
            assert(hash.data_length == offset % 64 && hash.bit_length == (uint64_t)(offset / 64) * 512);
        }
        sha256_update(&hash, NULL, 0);
        /* Publication retains a by-value snapshot to finalize independently.
         * Test both partial tails and complete blocks through the same seam. */
        struct sha256_context snapshot = hash;
        uint8_t digest[32], copied_digest[32]; char encoded[65];
        sha256_final(&snapshot, copied_digest);
        sha256_final(&hash, digest);
        assert(memcmp(digest, copied_digest, sizeof(digest)) == 0);
        for (size_t i = 0; i < sizeof(digest); i++) { encoded[2 * i] = digits[digest[i] >> 4]; encoded[2 * i + 1] = digits[digest[i] & 15]; }
        encoded[64] = '\0'; assert(strcmp(encoded, expected) == 0);
    }
}

int main(void) {
    check_cpu_feature_selection();
    check_digest(NULL, 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check_digest((const uint8_t *)"abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    static const uint8_t standard[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert(sizeof(standard) - 1 == 56);
    check_digest(standard, sizeof(standard) - 1, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    uint8_t *million = malloc(1000000); assert(million != NULL); memset(million, 'a', 1000000);
    check_digest(million, 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"); free(million);

    /* Independent fixed SHA-256 digests for bytes[i] = i modulo 256. These
     * cover both padding branches and partial/full blocks across 64KiB reads. */
    static const struct { size_t length; const char *digest; } boundaries[] = {
        {55, "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59"},
        {56, "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562"},
        {57, "2fe741af801cc238602ac0ec6a7b0c3a8a87c7fc7d7f02a3fe03d1c12eac4d8f"},
        {63, "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488"},
        {64, "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108"},
        {65, "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781"},
        {119, "da18797ed7c3a777f0847f429724a2d8cd5138e6ed2895c3fa1a6d39d18f7ec6"},
        {120, "f52b23db1fbb6ded89ef42a23ce0c8922c45f25c50b568a93bf1c075420bbb7c"},
        {121, "335a461692b30bba1d647cc71604e88e676c90e4c22455d0b8c83f4bd7c8ac9b"},
        {127, "92ca0fa6651ee2f97b884b7246a562fa71250fedefe5ebf270d31c546bfea976"},
        {128, "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5"},
        {129, "5099c6a56203f9687f7d33f4bfdf576d31dc91f6b695ecea38b2770c87631135"},
        {65535, "5f1bf999bcba5e05d4c34a13710d2e4bff005877874dcce49ac87af61076231e"},
        {65536, "7daca2095d0438260fa849183dfc67faa459fdf4936e1bc91eec6b281b27e4c2"},
        {65537, "2deb0bd2129a9d3aed91e3cff58b3993752be549642890a3e853ec1065f9b617"}
    };
    uint8_t bytes[65537]; for (size_t i = 0; i < sizeof(bytes); i++) bytes[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); i++)
        check_digest(bytes, boundaries[i].length, boundaries[i].digest);
    uint8_t unaligned[65 + 16];
    for (size_t offset = 1; offset < 16; offset++) {
        memcpy(unaligned + offset, bytes, 65);
        check_digest(unaligned + offset, 65, boundaries[5].digest);
    }
    puts(sha256_x86_available() ? "sha256_backends=portable_and_sha_ni" : "sha256_backends=portable");
    return 0;
}
