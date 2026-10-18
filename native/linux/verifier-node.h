#ifndef CLIQ_VERIFIER_NODE_H
#define CLIQ_VERIFIER_NODE_H

#include "worker-sha256.h"
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>

/* A named namespace-private copy, not the sealed source inode. Its complete
 * bytes must match that source's authenticated config before it may be bound
 * executable. The held reader is the very object used for the self bind. */
static inline bool cliq_verifier_node_same(const struct stat *left, const struct stat *right) {
#if defined(__APPLE__)
    bool timestamps = left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
        left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
        left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
        left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    bool timestamps = left->st_mtim.tv_sec == right->st_mtim.tv_sec && left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
        left->st_ctim.tv_sec == right->st_ctim.tv_sec && left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
    return timestamps && left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
        left->st_size == right->st_size && left->st_mode == right->st_mode &&
        left->st_uid == right->st_uid && left->st_gid == right->st_gid && left->st_nlink == right->st_nlink;
}

static inline bool cliq_verifier_node_current(int directory, int image, const struct stat *held) {
    struct stat reader, named;
    return fstat(image, &reader) == 0 && fstatat(directory, "node", &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(reader.st_mode) && reader.st_nlink == 1 && reader.st_uid == geteuid() && reader.st_gid == getegid() &&
        (reader.st_mode & 07777) == 0555 && cliq_verifier_node_same(held, &reader) && cliq_verifier_node_same(held, &named);
}

static inline int cliq_verifier_node_open(int directory, uint64_t byte_count, const char digest[65], struct stat *held) {
    if (byte_count == 0 || byte_count > UINT64_C(268435456) || strnlen(digest, 65) != 64) return -1;
    for (size_t i = 0; i < 64; i++)
        if (!((digest[i] >= '0' && digest[i] <= '9') || (digest[i] >= 'a' && digest[i] <= 'f'))) return -1;
    int image = openat(directory, "node", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (image < 0) return -1;
    bool valid = fstat(image, held) == 0 && S_ISREG(held->st_mode) && held->st_size > 0 &&
        (uint64_t)held->st_size == byte_count && cliq_verifier_node_current(directory, image, held);
    struct sha256_context hash; sha256_init(&hash);
    uint8_t bytes[65536]; uint64_t offset = 0;
    while (valid && offset < byte_count) {
        size_t wanted = byte_count - offset < sizeof(bytes) ? (size_t)(byte_count - offset) : sizeof(bytes);
        ssize_t count = pread(image, bytes, wanted, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || (size_t)count > wanted) { valid = false; break; }
        sha256_update(&hash, bytes, (size_t)count); offset += (uint64_t)count;
    }
    uint8_t observed[32]; char encoded[65]; static const char digits[] = "0123456789abcdef";
    sha256_final(&hash, observed);
    for (size_t i = 0; i < sizeof(observed); i++) { encoded[i * 2] = digits[observed[i] >> 4]; encoded[i * 2 + 1] = digits[observed[i] & 15]; }
    encoded[64] = '\0';
    valid = valid && offset == byte_count && strcmp(encoded, digest) == 0 && cliq_verifier_node_current(directory, image, held);
    if (!valid) { close(image); return -1; }
    return image;
}

#endif
