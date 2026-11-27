#ifndef CLIQ_DEPENDENCY_PACKAGE_DATA_H
#define CLIQ_DEPENDENCY_PACKAGE_DATA_H
/* Private public-registry output storage. Metadata is never EOF, retirement,
 * a claim, or permission. No JavaScript caller can supply these descriptors. */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <unistd.h>
#include "worker-sha256.h"

#define CLIQ_DEPENDENCY_PACKAGE_MAX_BYTES UINT64_C(67108864)
#define CLIQ_DEPENDENCY_PACKAGE_CHUNK_BYTES 65536
enum cliq_dependency_data_status {
    CLIQ_DEPENDENCY_DATA_OK, CLIQ_DEPENDENCY_DATA_REFUSED, CLIQ_DEPENDENCY_DATA_CANCELLED,
    CLIQ_DEPENDENCY_DATA_BUSY, CLIQ_DEPENDENCY_DATA_IO, CLIQ_DEPENDENCY_DATA_RETIREMENT
};
struct cliq_dependency_package_data {
    int fd; struct stat identity; uint64_t byte_count; char digest[65];
    unsigned readers; atomic_bool revoked; bool initialized, retired, unsafe;
};
struct cliq_dependency_package_reader {
    struct cliq_dependency_package_data *owner; int fd; uint64_t offset;
    struct sha256_context hash; bool initialized, complete, joined, failed;
};
static inline bool cliq_dependency_data_digest(const char *value) {
    if (!value || strnlen(value, 65) != 64) return false;
    for (size_t index = 0; index < 64; index++) if (!((value[index] >= '0' && value[index] <= '9') ||
        (value[index] >= 'a' && value[index] <= 'f'))) return false;
    return true;
}
static inline bool cliq_dependency_data_same(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino && left->st_mode == right->st_mode &&
        left->st_uid == right->st_uid && left->st_gid == right->st_gid && left->st_nlink == right->st_nlink &&
        left->st_size == right->st_size && left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
        left->st_mtim.tv_nsec == right->st_mtim.tv_nsec && left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
        left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}
static inline bool cliq_dependency_data_descriptor(int fd, const struct stat *expected) {
    struct stat actual; int flags = fcntl(fd, F_GETFL), descriptor_flags = fcntl(fd, F_GETFD);
    int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    return flags >= 0 && descriptor_flags >= 0 && (flags & O_ACCMODE) == O_RDONLY && (descriptor_flags & FD_CLOEXEC) != 0 && fstat(fd, &actual) == 0 &&
        cliq_dependency_data_same(expected, &actual) && fcntl(fd, F_GET_SEALS) == seals;
}
/* On success ownership transfers; refusal leaves the caller's FD untouched. */
static inline enum cliq_dependency_data_status cliq_dependency_data_initialize(struct cliq_dependency_package_data *data,
    int fd, uint64_t expected_bytes, uint64_t maximum_bytes, const char *expected_digest) {
    if (!data || fd < 0 || expected_bytes < 1 || maximum_bytes < 1 || maximum_bytes > CLIQ_DEPENDENCY_PACKAGE_MAX_BYTES ||
        expected_bytes > maximum_bytes || !cliq_dependency_data_digest(expected_digest)) return CLIQ_DEPENDENCY_DATA_REFUSED;
    struct stat identity;
    if (fstat(fd, &identity) || !S_ISREG(identity.st_mode) || identity.st_size < 0 ||
        (uint64_t)identity.st_size != expected_bytes || identity.st_uid != geteuid() || identity.st_gid != getegid() ||
        identity.st_nlink != 0 || (identity.st_mode & 07777) != 0400 || !cliq_dependency_data_descriptor(fd, &identity))
        return CLIQ_DEPENDENCY_DATA_REFUSED;
    memset(data, 0, sizeof(*data)); data->fd = fd; data->identity = identity; data->byte_count = expected_bytes;
    memcpy(data->digest, expected_digest, 65); atomic_init(&data->revoked, false); data->initialized = true;
    return CLIQ_DEPENDENCY_DATA_OK;
}
static inline enum cliq_dependency_data_status cliq_dependency_data_open(struct cliq_dependency_package_data *data,
    struct cliq_dependency_package_reader *reader) {
    if (!data || !reader || !data->initialized || data->retired || data->unsafe) return CLIQ_DEPENDENCY_DATA_REFUSED;
    if (atomic_load(&data->revoked)) return CLIQ_DEPENDENCY_DATA_CANCELLED;
    if (!cliq_dependency_data_descriptor(data->fd, &data->identity)) return CLIQ_DEPENDENCY_DATA_REFUSED;
    int fd = fcntl(data->fd, F_DUPFD_CLOEXEC, 3);
    if (fd < 0) return CLIQ_DEPENDENCY_DATA_IO;
    /* The duplicate names the same sealed open-file description. Each reader
     * uses pread and an independent cursor, never the shared seek position. */
    memset(reader, 0, sizeof(*reader)); reader->fd = fd; reader->owner = data; reader->initialized = true;
    sha256_init(&reader->hash); data->readers++;
    return CLIQ_DEPENDENCY_DATA_OK;
}
static inline enum cliq_dependency_data_status cliq_dependency_data_read(struct cliq_dependency_package_reader *reader,
    unsigned char output[CLIQ_DEPENDENCY_PACKAGE_CHUNK_BYTES], size_t *output_bytes) {
    if (output_bytes) *output_bytes = 0;
    if (!reader || !output || !output_bytes || !reader->initialized || reader->joined || reader->failed || !reader->owner ||
        !reader->owner->initialized || reader->owner->retired || reader->owner->unsafe) return CLIQ_DEPENDENCY_DATA_REFUSED;
    struct cliq_dependency_package_data *data = reader->owner;
    if (atomic_load(&data->revoked)) return CLIQ_DEPENDENCY_DATA_CANCELLED;
    if (!cliq_dependency_data_descriptor(reader->fd, &data->identity)) { reader->failed = true; return CLIQ_DEPENDENCY_DATA_REFUSED; }
    if (reader->complete) return CLIQ_DEPENDENCY_DATA_OK;
    if (reader->offset < data->byte_count) {
        size_t wanted = data->byte_count - reader->offset < CLIQ_DEPENDENCY_PACKAGE_CHUNK_BYTES ?
            (size_t)(data->byte_count - reader->offset) : CLIQ_DEPENDENCY_PACKAGE_CHUNK_BYTES;
        ssize_t count;
        do { count = pread(reader->fd, output, wanted, (off_t)reader->offset); } while (count < 0 && errno == EINTR && !atomic_load(&data->revoked));
        if (atomic_load(&data->revoked)) return CLIQ_DEPENDENCY_DATA_CANCELLED;
        if (count < 0) { reader->failed = true; return CLIQ_DEPENDENCY_DATA_IO; }
        if (count == 0 || (size_t)count > wanted) { reader->failed = true; return CLIQ_DEPENDENCY_DATA_REFUSED; }
        sha256_update(&reader->hash, output, (size_t)count); reader->offset += (uint64_t)count; *output_bytes = (size_t)count;
        if (!cliq_dependency_data_descriptor(reader->fd, &data->identity)) { reader->failed = true; return CLIQ_DEPENDENCY_DATA_REFUSED; }
        return CLIQ_DEPENDENCY_DATA_OK;
    }
    unsigned char tail, digest[32]; ssize_t count;
    do { count = pread(reader->fd, &tail, 1, (off_t)reader->offset); } while (count < 0 && errno == EINTR && !atomic_load(&data->revoked));
    if (atomic_load(&data->revoked)) return CLIQ_DEPENDENCY_DATA_CANCELLED;
    if (count < 0) { reader->failed = true; return CLIQ_DEPENDENCY_DATA_IO; }
    if (count != 0 || !cliq_dependency_data_descriptor(reader->fd, &data->identity)) { reader->failed = true; return CLIQ_DEPENDENCY_DATA_REFUSED; }
    sha256_final(&reader->hash, digest); static const char hex[] = "0123456789abcdef"; char text[65];
    for (size_t index = 0; index < 32; index++) { text[index * 2] = hex[digest[index] >> 4]; text[index * 2 + 1] = hex[digest[index] & 15]; }
    text[64] = '\0';
    if (memcmp(text, data->digest, sizeof(text))) { reader->failed = true; return CLIQ_DEPENDENCY_DATA_REFUSED; }
    reader->complete = true; return CLIQ_DEPENDENCY_DATA_OK;
}
static inline bool cliq_dependency_data_complete(const struct cliq_dependency_package_reader *reader) {
    return reader && reader->initialized && !reader->joined && !reader->failed && reader->owner && !reader->owner->unsafe &&
        !atomic_load(&reader->owner->revoked) && reader->complete && reader->offset == reader->owner->byte_count &&
        cliq_dependency_data_descriptor(reader->fd, &reader->owner->identity);
}
static inline enum cliq_dependency_data_status cliq_dependency_data_join(struct cliq_dependency_package_reader *reader) {
    if (!reader || !reader->initialized || !reader->owner) return CLIQ_DEPENDENCY_DATA_REFUSED;
    if (reader->joined) return reader->owner->unsafe ? CLIQ_DEPENDENCY_DATA_RETIREMENT : CLIQ_DEPENDENCY_DATA_OK;
    struct cliq_dependency_package_data *data = reader->owner; int fd = reader->fd; reader->fd = -1; reader->joined = true;
    if (data->readers == 0 || fd < 0 || close(fd) != 0) { data->unsafe = true; return CLIQ_DEPENDENCY_DATA_RETIREMENT; }
    data->readers--; return data->unsafe ? CLIQ_DEPENDENCY_DATA_RETIREMENT : CLIQ_DEPENDENCY_DATA_OK;
}
static inline void cliq_dependency_data_revoke(struct cliq_dependency_package_data *data) {
    if (data && data->initialized) atomic_store(&data->revoked, true);
}
static inline enum cliq_dependency_data_status cliq_dependency_data_retire(struct cliq_dependency_package_data *data) {
    if (!data || !data->initialized) return CLIQ_DEPENDENCY_DATA_REFUSED;
    cliq_dependency_data_revoke(data);
    if (data->unsafe) return CLIQ_DEPENDENCY_DATA_RETIREMENT;
    if (data->retired) return CLIQ_DEPENDENCY_DATA_OK;
    if (data->readers) return CLIQ_DEPENDENCY_DATA_BUSY;
    int fd = data->fd; data->fd = -1;
    if (fd < 0 || close(fd) != 0) { data->unsafe = true; return CLIQ_DEPENDENCY_DATA_RETIREMENT; }
    data->retired = true; return CLIQ_DEPENDENCY_DATA_OK;
}
#endif
