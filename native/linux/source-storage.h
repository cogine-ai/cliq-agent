#ifndef CLIQ_SOURCE_STORAGE_H
#define CLIQ_SOURCE_STORAGE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/vfs.h>

/* The fixed source storage accounting already charges 4096-byte pages. Never
 * let the kernel round a caller's byte ceiling up to another writable page. */
static inline uint64_t source_tmpfs_budget(uint64_t bytes) {
    return bytes & ~UINT64_C(4095);
}

/* Actual held tmpfs geometry, not free space, a declaration or a version
 * string. The fixed caller opens only its own / and /scratch namespaces. */
static inline bool source_tmpfs_within(int directory, uint64_t limit) {
    struct stat object; struct statfs filesystem;
    if (fstat(directory, &object) != 0 || !S_ISDIR(object.st_mode) || fstatfs(directory, &filesystem) != 0 ||
        filesystem.f_type != 0x01021994 || filesystem.f_bsize <= 0 || filesystem.f_blocks == 0) return false;
    const uint64_t block = (uint64_t)filesystem.f_bsize, blocks = (uint64_t)filesystem.f_blocks;
    return block <= limit && blocks <= limit / block;
}

#endif
