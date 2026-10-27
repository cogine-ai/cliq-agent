#ifndef CLIQ_DEPENDENCY_NPM_IMAGE_H
#define CLIQ_DEPENDENCY_NPM_IMAGE_H
/* Private fixed npm data materialization, not an executable or a generic
 * archive extractor. The original invocation owns the empty volatile root
 * and any partial prefix until its actual cancellation/domain join. */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "worker-sha256.h"

#define CLIQ_NPM_IMAGE_BYTES UINT64_C(11950276)
#define CLIQ_NPM_EXPANDED_BYTES UINT64_C(33554432)
#define CLIQ_NPM_FILES UINT32_C(4096)
#define CLIQ_NPM_FILE_BYTES UINT32_C(1048576)
enum cliq_npm_image_status { CLIQ_NPM_IMAGE_OK, CLIQ_NPM_IMAGE_REFUSED, CLIQ_NPM_IMAGE_CANCELLED,
    CLIQ_NPM_IMAGE_IO, CLIQ_NPM_IMAGE_JOIN };
struct cliq_npm_image_name { unsigned char folded[32], original[32]; unsigned char kind; uint32_t record_offset; };
struct cliq_npm_image_record { const unsigned char *payload, *digest; uint32_t size; uint16_t mode; char path[4097]; };
static inline bool cliq_npm_stat_same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_mode == b->st_mode && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static inline void cliq_npm_digest(const unsigned char *bytes, size_t length, unsigned char output[32]) {
    struct sha256_context hash; sha256_init(&hash); sha256_update(&hash, bytes, length); sha256_final(&hash, output);
}
/* This fixed non-executable data image has two physical ingress forms:
 * the original single-link signed asset, or the same fully hashed bytes in
 * an explicitly sealed Linux memfd. No executable/source guard is changed. */
static inline bool cliq_npm_image_link_form(int fd, const struct stat *metadata) {
    if (metadata->st_nlink == 1) return true;
#if defined(__linux__) && defined(F_GET_SEALS) && defined(F_SEAL_WRITE) && defined(F_SEAL_GROW) && defined(F_SEAL_SHRINK) && defined(F_SEAL_SEAL)
    const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    return metadata->st_nlink == 0 && fcntl(fd, F_GET_SEALS) == seals;
#else
    (void)fd; return false;
#endif
}
static inline uint32_t cliq_npm_u32(const unsigned char *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}
static inline uint64_t cliq_npm_u64(const unsigned char *bytes) {
    return (uint64_t)cliq_npm_u32(bytes) | (uint64_t)cliq_npm_u32(bytes + 4) << 32;
}
static inline bool cliq_npm_path(const char *path) {
    if (!path[0] || path[0] == '/') return false;
    const char *part = path; unsigned int depth = 1;
    for (const char *p = path;; p++) {
        unsigned char c = (unsigned char)*p;
        if (c && c != '/' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
            !(c >= '0' && c <= '9') && c != '.' && c != '_' && c != '-' && c != '@' && c != '+') return false;
        if (!c || c == '/') {
            size_t length = (size_t)(p - part);
            if (!length || length > 255 || (length == 1 && part[0] == '.') ||
                (length == 2 && !memcmp(part, "..", 2)) || (length == 4 && !strncasecmp(part, ".git", 4))) return false;
            if (!c) return true;
            if (++depth > 32) return false;
            part = p + 1;
        }
    }
}
static inline bool cliq_npm_name(struct cliq_npm_image_name *names, const char *path, unsigned char kind, uint32_t offset, bool *added) {
    unsigned char folded[4097], a[32], b[32]; size_t length = strlen(path);
    for (size_t i = 0; i < length; i++) folded[i] = (unsigned char)tolower((unsigned char)path[i]);
    cliq_npm_digest(folded, length, a); cliq_npm_digest((const unsigned char *)path, length, b);
    uint32_t slot = cliq_npm_u32(a) & 8191U;
    for (uint32_t count = 0; count < 8192; count++, slot = (slot + 1) & 8191U) {
        if (!names[slot].kind) {
            memcpy(names[slot].folded, a, 32); memcpy(names[slot].original, b, 32); names[slot].kind = kind;
            names[slot].record_offset = offset; *added = true; return true;
        }
        if (!memcmp(names[slot].folded, a, 32)) {
            *added = false;
            return kind == 1 && names[slot].kind == 1 && !memcmp(names[slot].original, b, 32);
        }
    }
    return false;
}
static inline bool cliq_npm_record(const unsigned char *image, size_t length, size_t *offset, struct cliq_npm_image_record *record) {
    if (*offset > length || length - *offset < 40) return false;
    const unsigned char *at = image + *offset;
    size_t path_size = (size_t)at[0] | (size_t)at[1] << 8;
    record->mode = (uint16_t)((uint16_t)at[2] | (uint16_t)at[3] << 8); record->size = cliq_npm_u32(at + 4);
    record->digest = at + 8; *offset += 40;
    if (!path_size || path_size > 4096 || record->size > CLIQ_NPM_FILE_BYTES ||
        (record->mode != 0644 && record->mode != 0755) || path_size > length - *offset || record->size > length - *offset - path_size ||
        memchr(image + *offset, 0, path_size)) return false;
    memcpy(record->path, image + *offset, path_size); record->path[path_size] = 0; *offset += path_size;
    if (!cliq_npm_path(record->path)) return false;
    record->payload = image + *offset; *offset += record->size;
    unsigned char digest[32]; cliq_npm_digest(record->payload, record->size, digest);
    return !memcmp(digest, record->digest, 32);
}
static inline enum cliq_npm_image_status cliq_npm_empty_root(int root, struct stat *identity) {
    if (fstat(root, identity) || !S_ISDIR(identity->st_mode) || identity->st_uid != geteuid()) return CLIQ_NPM_IMAGE_REFUSED;
    // A dup shares the directory cursor. Use an independent open-file
    // description so this inventory cannot consume the later final audit.
    int copy = openat(root, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (copy < 0) return CLIQ_NPM_IMAGE_IO;
    struct stat copied;
    if (fstat(copy, &copied) || !cliq_npm_stat_same(identity, &copied)) return close(copy) ? CLIQ_NPM_IMAGE_JOIN : CLIQ_NPM_IMAGE_REFUSED;
    DIR *stream = fdopendir(copy); if (!stream) return close(copy) ? CLIQ_NPM_IMAGE_JOIN : CLIQ_NPM_IMAGE_IO;
    enum cliq_npm_image_status status = CLIQ_NPM_IMAGE_OK; errno = 0; struct dirent *entry;
    while ((entry = readdir(stream))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { status = CLIQ_NPM_IMAGE_REFUSED; break; }
    if (errno) status = CLIQ_NPM_IMAGE_IO;
    if (closedir(stream)) status = CLIQ_NPM_IMAGE_JOIN;
    return status;
}
static inline const struct cliq_npm_image_name *cliq_npm_lookup(const struct cliq_npm_image_name *names, const char *path) {
    unsigned char folded[4097], a[32], b[32]; size_t length = strlen(path);
    for (size_t i = 0; i < length; i++) folded[i] = (unsigned char)tolower((unsigned char)path[i]);
    cliq_npm_digest(folded, length, a); cliq_npm_digest((const unsigned char *)path, length, b);
    uint32_t slot = cliq_npm_u32(a) & 8191U;
    for (uint32_t count = 0; count < 8192; count++, slot = (slot + 1) & 8191U) {
        if (!names[slot].kind) return NULL;
        if (!memcmp(names[slot].folded, a, 32)) return memcmp(names[slot].original, b, 32) ? NULL : &names[slot];
    }
    return NULL;
}
static inline bool cliq_npm_directory_same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_mode == b->st_mode && S_ISDIR(a->st_mode);
}
static inline enum cliq_npm_image_status cliq_npm_audit(int root, const struct stat *root_identity, const char *prefix,
    const unsigned char *image, const struct cliq_npm_image_name *names, uint32_t *seen,
    unsigned char buffer[65536], const volatile sig_atomic_t *cancelled) {
    int copy = openat(root, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (copy < 0) return CLIQ_NPM_IMAGE_IO;
    struct stat before, copied;
    if (fstat(root, &before) || fstat(copy, &copied) || !cliq_npm_stat_same(&before, &copied)) return close(copy) ? CLIQ_NPM_IMAGE_JOIN : CLIQ_NPM_IMAGE_REFUSED;
    DIR *stream = fdopendir(copy); if (!stream) return close(copy) ? CLIQ_NPM_IMAGE_JOIN : CLIQ_NPM_IMAGE_IO;
    enum cliq_npm_image_status status = CLIQ_NPM_IMAGE_OK; struct dirent *entry;
    for (;;) {
        errno = 0; entry = readdir(stream);
        if (!entry) { if (errno) status = CLIQ_NPM_IMAGE_IO; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (cancelled && *cancelled) { status = CLIQ_NPM_IMAGE_CANCELLED; break; }
        char path[4097]; size_t prefix_length = strlen(prefix), length = strlen(entry->d_name);
        if (prefix_length + (prefix_length ? 1 : 0) + length > 4096) { status = CLIQ_NPM_IMAGE_REFUSED; break; }
        memcpy(path, prefix, prefix_length); if (prefix_length) path[prefix_length++] = '/';
        memcpy(path + prefix_length, entry->d_name, length + 1);
        const struct cliq_npm_image_name *expected = cliq_npm_lookup(names, path); struct stat named, held, after;
        if (!expected || !cliq_npm_path(path) || fstatat(root, entry->d_name, &named, AT_SYMLINK_NOFOLLOW) ||
            named.st_uid != geteuid() || named.st_dev != root_identity->st_dev || ++*seen > CLIQ_NPM_FILES) { status = CLIQ_NPM_IMAGE_REFUSED; break; }
        int fd = openat(root, entry->d_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | (expected->kind == 1 ? O_DIRECTORY : 0));
        if (fd < 0) { status = CLIQ_NPM_IMAGE_IO; break; }
        if (fstat(fd, &held) || !cliq_npm_stat_same(&named, &held)) status = CLIQ_NPM_IMAGE_REFUSED;
        if (status == CLIQ_NPM_IMAGE_OK && expected->kind == 1) {
            if (!S_ISDIR(held.st_mode) || (held.st_mode & 0777) != 0755) status = CLIQ_NPM_IMAGE_REFUSED;
            else status = cliq_npm_audit(fd, root_identity, path, image, names, seen, buffer, cancelled);
        } else if (status == CLIQ_NPM_IMAGE_OK) {
            uint32_t size = cliq_npm_u32(image + expected->record_offset + 4);
            if (!S_ISREG(held.st_mode) || held.st_nlink != 1 || (held.st_mode & 0777) != 0400 || (uint64_t)held.st_size != size) status = CLIQ_NPM_IMAGE_REFUSED;
            struct sha256_context hash; sha256_init(&hash); size_t offset = 0; unsigned char digest[32];
            while (status == CLIQ_NPM_IMAGE_OK) {
                if (cancelled && *cancelled) { status = CLIQ_NPM_IMAGE_CANCELLED; break; }
                ssize_t n = read(fd, buffer, 65536); if (n < 0 && errno == EINTR) continue;
                if (n < 0 || (uint64_t)n > size - offset) { status = CLIQ_NPM_IMAGE_REFUSED; break; }
                if (!n) break;
                sha256_update(&hash, buffer, (size_t)n); offset += (size_t)n;
            }
            sha256_final(&hash, digest);
            if (status == CLIQ_NPM_IMAGE_OK && (offset != size || memcmp(digest, image + expected->record_offset + 8, 32))) status = CLIQ_NPM_IMAGE_REFUSED;
        }
        if (status == CLIQ_NPM_IMAGE_OK && (fstat(fd, &after) || !cliq_npm_stat_same(&held, &after) ||
            fstatat(root, entry->d_name, &after, AT_SYMLINK_NOFOLLOW) || !cliq_npm_stat_same(&held, &after))) status = CLIQ_NPM_IMAGE_REFUSED;
        if (close(fd)) status = CLIQ_NPM_IMAGE_JOIN;
        if (status != CLIQ_NPM_IMAGE_OK) break;
    }
    if (closedir(stream)) status = CLIQ_NPM_IMAGE_JOIN;
    return status;
}
static inline enum cliq_npm_image_status cliq_npm_write_file(int root, const struct stat *root_identity,
    const struct cliq_npm_image_record *record, const volatile sig_atomic_t *cancelled) {
    char path[4097]; memcpy(path, record->path, strlen(record->path) + 1);
    int parent = fcntl(root, F_DUPFD_CLOEXEC, 3); if (parent < 0) return CLIQ_NPM_IMAGE_IO;
    enum cliq_npm_image_status status = CLIQ_NPM_IMAGE_OK; char *name = path;
    for (char *slash = strchr(name, '/'); slash; slash = strchr(name, '/')) {
        *slash = 0;
        bool created = mkdirat(parent, name, 0755) == 0;
        if (!created && errno != EEXIST) { status = CLIQ_NPM_IMAGE_IO; break; }
        int next = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        struct stat held, named;
        if (next < 0 || (created && fchmod(next, 0755)) || fstat(next, &held) || fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) ||
            !cliq_npm_directory_same(&held, &named) || held.st_dev != root_identity->st_dev || held.st_uid != geteuid() ||
            (held.st_mode & 0777) != 0755) {
            if (next >= 0 && close(next)) status = CLIQ_NPM_IMAGE_JOIN;
            else status = CLIQ_NPM_IMAGE_IO;
            break;
        }
        if (close(parent)) { if (close(next)) { /* Both actual close attempts remain observed as failure. */ } return CLIQ_NPM_IMAGE_JOIN; }
        parent = next; name = slash + 1;
    }
    int writer = -1, reader = -1; struct stat born, held, named;
    if (status == CLIQ_NPM_IMAGE_OK && cancelled && *cancelled) status = CLIQ_NPM_IMAGE_CANCELLED;
    if (status == CLIQ_NPM_IMAGE_OK) {
        writer = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
        if (writer < 0) status = CLIQ_NPM_IMAGE_IO;
    }
    size_t offset = 0;
    while (status == CLIQ_NPM_IMAGE_OK && offset < record->size) {
        if (cancelled && *cancelled) { status = CLIQ_NPM_IMAGE_CANCELLED; break; }
        ssize_t count = write(writer, record->payload + offset, record->size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { status = CLIQ_NPM_IMAGE_IO; break; }
        offset += (size_t)count;
    }
    if (status == CLIQ_NPM_IMAGE_OK && (fchmod(writer, 0400) || fstat(writer, &born) || !S_ISREG(born.st_mode) ||
        born.st_nlink != 1 || born.st_uid != geteuid() || born.st_dev != root_identity->st_dev || (uint64_t)born.st_size != record->size)) status = CLIQ_NPM_IMAGE_IO;
    if (writer >= 0 && close(writer)) status = CLIQ_NPM_IMAGE_JOIN;
    if (status == CLIQ_NPM_IMAGE_OK) {
        reader = openat(parent, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (reader < 0 || fstat(reader, &held) || !cliq_npm_stat_same(&born, &held) ||
            fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) || !cliq_npm_stat_same(&held, &named)) status = CLIQ_NPM_IMAGE_IO;
    }
    struct sha256_context hash; sha256_init(&hash); unsigned char buffer[65536], digest[32]; offset = 0;
    while (status == CLIQ_NPM_IMAGE_OK) {
        if (cancelled && *cancelled) { status = CLIQ_NPM_IMAGE_CANCELLED; break; }
        ssize_t count = read(reader, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 || (uint64_t)count > record->size - offset) { status = CLIQ_NPM_IMAGE_IO; break; }
        if (!count) break;
        sha256_update(&hash, buffer, (size_t)count); offset += (size_t)count;
    }
    sha256_final(&hash, digest);
    if (status == CLIQ_NPM_IMAGE_OK && (offset != record->size || memcmp(digest, record->digest, 32) || fstat(reader, &held) ||
        !cliq_npm_stat_same(&born, &held) || fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) || !cliq_npm_stat_same(&held, &named))) status = CLIQ_NPM_IMAGE_IO;
    if (reader >= 0 && close(reader)) status = CLIQ_NPM_IMAGE_JOIN;
    if (close(parent)) status = CLIQ_NPM_IMAGE_JOIN;
    return status;
}
static inline enum cliq_npm_image_status cliq_npm_materialize(int image_fd, int root, const volatile sig_atomic_t *cancelled) {
    static const unsigned char magic[] = "cliq-npm-data-image-v1";
    static const unsigned char expected[32] = {0x53,0x5b,0x22,0x6e,0xfa,0x5f,0xa1,0xc3,0x3d,0x82,0xe0,0x63,0x4a,0xc2,0x2a,0x99,
        0x7c,0x20,0x0d,0xb5,0x79,0x9a,0x78,0x7e,0xdd,0x98,0x0f,0x7d,0xe7,0xa5,0x6f,0x89};
    if (cancelled && *cancelled) return CLIQ_NPM_IMAGE_CANCELLED;
    struct stat before, after, root_identity; int flags = fcntl(image_fd, F_GETFL), descriptor_flags = fcntl(image_fd, F_GETFD);
    if (flags < 0 || descriptor_flags < 0 || (flags & O_ACCMODE) != O_RDONLY || !(descriptor_flags & FD_CLOEXEC) ||
        fstat(image_fd, &before) || !S_ISREG(before.st_mode) || !cliq_npm_image_link_form(image_fd, &before) || before.st_uid != geteuid() ||
        (before.st_mode & 0777) != 0400 || (uint64_t)before.st_size != CLIQ_NPM_IMAGE_BYTES) return CLIQ_NPM_IMAGE_REFUSED;
    enum cliq_npm_image_status empty = cliq_npm_empty_root(root, &root_identity);
    if (empty != CLIQ_NPM_IMAGE_OK) return empty;
    unsigned char *image = mmap(NULL, (size_t)before.st_size, PROT_READ, MAP_PRIVATE, image_fd, 0);
    if (image == MAP_FAILED) return CLIQ_NPM_IMAGE_IO;
    enum cliq_npm_image_status status = CLIQ_NPM_IMAGE_REFUSED; unsigned char digest[32]; cliq_npm_digest(image, (size_t)before.st_size, digest);
    struct cliq_npm_image_name *names = NULL;
    uint32_t count = cliq_npm_u32(image + sizeof(magic)); size_t offset = sizeof(magic) + 16;
    uint64_t expanded = 0, pages = 4096; uint32_t namespace_entries = 1;
    if (memcmp(digest, expected, 32) || memcmp(image, magic, sizeof(magic)) || count < 2 || count > CLIQ_NPM_FILES ||
        cliq_npm_u64(image + sizeof(magic) + 4) > CLIQ_NPM_EXPANDED_BYTES || cliq_npm_u32(image + sizeof(magic) + 12) != 0) goto done;
    /* < 1MiB fixed temporary scratch, independent of the 32-file old recipes. */
    names = calloc(8192, sizeof(*names)); if (!names) { status = CLIQ_NPM_IMAGE_IO; goto done; }
    char previous[4097] = ""; bool cli = false, package = false;
    for (uint32_t i = 0; i < count; i++) {
        struct cliq_npm_image_record record;
        if (cancelled && *cancelled) { status = CLIQ_NPM_IMAGE_CANCELLED; goto done; }
        size_t record_offset = offset;
        if (!cliq_npm_record(image, (size_t)before.st_size, &offset, &record) || (i && strcmp(previous, record.path) >= 0)) goto done;
        memcpy(previous, record.path, strlen(record.path) + 1);
        if (!strcmp(record.path, "bin/npm-cli.js")) cli = true;
        if (!strcmp(record.path, "package.json")) package = true;
        bool added;
        if (!cliq_npm_name(names, record.path, 2, (uint32_t)record_offset, &added) || !added) goto done;
        namespace_entries++; expanded += record.size; pages += ((uint64_t)record.size + 4095) / 4096 * 4096;
        for (char *slash = strchr(record.path, '/'); slash; slash = strchr(slash + 1, '/')) {
            *slash = 0; bool valid = cliq_npm_name(names, record.path, 1, 0, &added); *slash = '/';
            if (!valid) goto done;
            if (added) { namespace_entries++; pages += 4096; }
        }
        if (namespace_entries > CLIQ_NPM_FILES || pages > CLIQ_NPM_EXPANDED_BYTES || expanded > CLIQ_NPM_EXPANDED_BYTES) goto done;
    }
    if (offset != (size_t)before.st_size || expanded != cliq_npm_u64(image + sizeof(magic) + 4) || !cli || !package ||
        fstat(image_fd, &after) || !cliq_npm_stat_same(&before, &after)) goto done;
    offset = sizeof(magic) + 16;
    for (uint32_t i = 0; i < count; i++) {
        struct cliq_npm_image_record record;
        if (!cliq_npm_record(image, (size_t)before.st_size, &offset, &record)) { status = CLIQ_NPM_IMAGE_REFUSED; goto done; }
        status = cliq_npm_write_file(root, &root_identity, &record, cancelled);
        if (status != CLIQ_NPM_IMAGE_OK) goto done;
    }
    { unsigned char buffer[65536]; uint32_t seen = 1;
      status = cliq_npm_audit(root, &root_identity, "", image, names, &seen, buffer, cancelled);
      if (status != CLIQ_NPM_IMAGE_OK || seen != namespace_entries) { if (status == CLIQ_NPM_IMAGE_OK) status = CLIQ_NPM_IMAGE_REFUSED; goto done; } }
    if (fstat(image_fd, &after) || !cliq_npm_stat_same(&before, &after) || !cliq_npm_image_link_form(image_fd, &after)) status = CLIQ_NPM_IMAGE_REFUSED;
    struct stat current_root;
    if (fstat(root, &current_root) || !cliq_npm_directory_same(&root_identity, &current_root)) status = CLIQ_NPM_IMAGE_REFUSED;
done:
    free(names); if (munmap(image, (size_t)before.st_size)) status = CLIQ_NPM_IMAGE_JOIN;
    return status;
}
#endif
