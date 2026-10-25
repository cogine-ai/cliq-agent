#ifndef CLIQ_SOURCE_GIT_HISTORY_H
#define CLIQ_SOURCE_GIT_HISTORY_H
#include "source-git-history-data.h"
#include <stdlib.h>
static inline bool cliq_source_read_exact(int fd, void *target, size_t length, off_t offset) {
    size_t used = 0;
    while (used < length) {
        ssize_t bytes = pread(fd, (unsigned char *)target + used, length - used, offset + (off_t)used);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) return false;
        used += (size_t)bytes;
    }
    return true;
}
static inline bool cliq_source_history_read_snapshot(int fd, const struct cliq_source_birth *expected,
    struct cliq_source_history *history, unsigned char **snapshot, size_t *length) {
    struct stat before, after;
    const size_t prefix = sizeof(struct cliq_source_birth) + sizeof(struct cliq_source_controller_birth);
    *snapshot = NULL; *length = 0;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_nlink != 1 || (before.st_mode & 07777) != 0600 ||
        before.st_uid != geteuid() || expected->birth_device != (uint64_t)before.st_dev || expected->birth_inode != (uint64_t)before.st_ino ||
        before.st_size < (off_t)prefix || (uint64_t)before.st_size > CLIQ_SOURCE_HISTORY_MAX_BYTES) return false;
    unsigned char *bytes = calloc(1, (size_t)before.st_size);
    bool valid = bytes && cliq_source_read_exact(fd, bytes, (size_t)before.st_size, 0) &&
        cliq_source_history_decode(bytes, (size_t)before.st_size, expected, history) && fstat(fd, &after) == 0 &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_mode == after.st_mode &&
        before.st_uid == after.st_uid && before.st_gid == after.st_gid && before.st_nlink == after.st_nlink && before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
    if (!valid) { free(bytes); return false; }
    *snapshot = bytes; *length = (size_t)before.st_size; return true;
}
static inline bool cliq_source_history_read(int fd, const struct cliq_source_birth *expected, struct cliq_source_history *history) {
    unsigned char *bytes = NULL; size_t length = 0;
    bool valid = cliq_source_history_read_snapshot(fd, expected, history, &bytes, &length);
    free(bytes); return valid;
}
/* Only a completely sealed anonymous in-memory copy may replace the deleted
 * physical birth for the registered-absent read-only checker. */
static inline bool cliq_source_history_read_sealed(int fd, const struct cliq_source_birth *expected,
    struct cliq_source_history *history, unsigned char **snapshot, size_t *length) {
    struct stat before, after;
    const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    *snapshot = NULL; *length = 0;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_nlink != 0 || (before.st_mode & 07777) != 0400 ||
        before.st_uid != geteuid() || before.st_size < (off_t)sizeof(struct cliq_source_birth) ||
        (uint64_t)before.st_size > CLIQ_SOURCE_HISTORY_MAX_BYTES || fcntl(fd, F_GET_SEALS) != seals) return false;
    unsigned char *bytes = calloc(1, (size_t)before.st_size);
    bool valid = bytes && cliq_source_read_exact(fd, bytes, (size_t)before.st_size, 0) &&
        cliq_source_history_decode(bytes, (size_t)before.st_size, expected, history) && fstat(fd, &after) == 0 &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_mode == after.st_mode &&
        before.st_uid == after.st_uid && before.st_gid == after.st_gid && before.st_nlink == after.st_nlink &&
        before.st_size == after.st_size && before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec && fcntl(fd, F_GET_SEALS) == seals;
    if (!valid) { free(bytes); return false; }
    *snapshot = bytes; *length = (size_t)before.st_size; return true;
}
#endif
