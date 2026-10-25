#ifndef CLIQ_SOURCE_GIT_SNAPSHOT_H
#define CLIQ_SOURCE_GIT_SNAPSHOT_H

#include "source-git-protocol.h"
#include "worker-sha256.h"
#include <dirent.h>
#include <sys/mman.h>

/* Only called by the already-exec'd, single-threaded in-scope producer after
 * the original one-use capture release. No source bytes enter the controller. */
struct cliq_source_snapshot {
    int shards[CLIQ_SOURCE_MAX_SHARDS];
    uint64_t shard_bytes[CLIQ_SOURCE_MAX_SHARDS];
    uint32_t count, max_depth;
    uint64_t bytes, entries, limit, file_limit, descriptor_limit;
    uint64_t rule_limit, rule_bytes;
    bool exclude_enabled, rule_present;
    struct sha256_context hash;
    unsigned char digest[32];
};
static bool source_close_fd(int *slot) {
    int fd = *slot; *slot = -1;
    return fd < 0 || close(fd) == 0;
}
static bool source_snapshot_close(struct cliq_source_snapshot *snapshot) {
    bool joined = true;
    for (uint32_t i = 0; i < CLIQ_SOURCE_MAX_SHARDS; i++) if (!source_close_fd(&snapshot->shards[i])) joined = false;
    return joined;
}
static void source_snapshot_init(struct cliq_source_snapshot *snapshot, const struct cliq_worker_packet *request) {
    memset(snapshot, 0, sizeof(*snapshot));
    for (size_t i = 0; i < CLIQ_SOURCE_MAX_SHARDS; i++) snapshot->shards[i] = -1;
    snapshot->limit = request->max_generation_bytes;
    snapshot->file_limit = request->max_file_bytes;
    snapshot->descriptor_limit = request->max_open_files;
    snapshot->exclude_enabled = request->source_exclude_grant_digest[0] != '\0';
    snapshot->rule_limit = request->max_output_bytes < request->max_file_bytes ? request->max_output_bytes : request->max_file_bytes;
    sha256_init(&snapshot->hash);
}
static bool source_add_u64(uint64_t *value, uint64_t extra, uint64_t limit) {
    if (*value > limit || extra > limit - *value) return false;
    *value += extra; return true;
}
static bool source_write_all(int fd, const void *buffer, size_t length) {
    const unsigned char *bytes = buffer; size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(fd, bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += (size_t)count;
    }
    return true;
}
static bool source_snapshot_write(struct cliq_source_snapshot *snapshot, const void *buffer, size_t length) {
    if (!source_add_u64(&snapshot->bytes, length, snapshot->limit)) return false;
    const unsigned char *bytes = buffer; size_t offset = 0;
    while (offset < length) {
        if (snapshot->count == 0 || snapshot->shard_bytes[snapshot->count - 1] == snapshot->file_limit) {
            if (snapshot->count == CLIQ_SOURCE_MAX_SHARDS || snapshot->count + 12 >= snapshot->descriptor_limit) return false;
            int fd = memfd_create("cliq-source-snapshot", MFD_CLOEXEC | MFD_ALLOW_SEALING);
            if (fd < 0) return false;
            snapshot->shards[snapshot->count++] = fd;
        }
        uint32_t at = snapshot->count - 1;
        uint64_t available = snapshot->file_limit - snapshot->shard_bytes[at];
        size_t count = available < length - offset ? (size_t)available : length - offset;
        if (!source_write_all(snapshot->shards[at], bytes + offset, count)) return false;
        sha256_update(&snapshot->hash, bytes + offset, count);
        snapshot->shard_bytes[at] += count; offset += count;
    }
    return true;
}
static bool source_stat_same(const struct stat *before, const struct stat *after) {
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino && before->st_uid == after->st_uid &&
        before->st_gid == after->st_gid && before->st_mode == after->st_mode && before->st_nlink == after->st_nlink &&
        before->st_size == after->st_size && before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
        before->st_mtim.tv_nsec == after->st_mtim.tv_nsec && before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
        before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
}
/* Git metadata is the only native capture root. Unsupported control sources
 * are refused, not silently followed or copied into a later Git workspace. */
static bool source_top_entry(const char *name, bool directory) {
    if (directory) return strcmp(name, "objects") == 0 || strcmp(name, "refs") == 0 || strcmp(name, "info") == 0;
    return strcmp(name, "config") == 0 || strcmp(name, "HEAD") == 0 || strcmp(name, "index") == 0 || strcmp(name, "packed-refs") == 0;
}
static bool source_forbidden_path(const char *name) {
    return strcmp(name, "objects/info/alternates") == 0 || strcmp(name, "objects/info/http-alternates") == 0 ||
        strcmp(name, "info/grafts") == 0;
}
static bool source_walk_snapshot(int directory, dev_t device, unsigned int depth, const char *prefix,
    struct cliq_source_snapshot *snapshot, bool copy, struct sha256_context *metadata, uint64_t *predicted, uint64_t *entries) {
    struct stat before, after;
    if (depth >= CLIQ_SOURCE_MAX_DEPTH || 2 * depth + snapshot->count + 12 >= snapshot->descriptor_limit ||
        fstat(directory, &before) != 0 || !S_ISDIR(before.st_mode) || before.st_dev != device || before.st_uid != geteuid()) return false;
    if (depth > snapshot->max_depth) snapshot->max_depth = depth;
    int cursor = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (cursor < 0) return false;
    DIR *stream = fdopendir(cursor);
    if (!stream) { close(cursor); return false; }
    bool valid = true;
    for (;;) {
        errno = 0; struct dirent *entry = readdir(stream);
        if (!entry) { if (errno) valid = false; break; }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        struct stat named;
        if (fstatat(directory, entry->d_name, &named, AT_SYMLINK_NOFOLLOW) != 0 || named.st_dev != device ||
            named.st_uid != geteuid() || (!S_ISREG(named.st_mode) && !S_ISDIR(named.st_mode))) { valid = false; break; }
        if (!*prefix && !source_top_entry(entry->d_name, S_ISDIR(named.st_mode))) {
            /* A normal Git directory contains logs/hooks/description. They
             * are not inputs to this fixed inspection recipe and are never
             * opened. Unsafe redirection markers cannot be ignored. */
            const char *denied[] = { "commondir", "gitdir", "shallow", "worktrees", "modules" };
            for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); i++)
                if (strcmp(entry->d_name, denied[i]) == 0) valid = false;
            if (!valid) break;
            continue;
        }
        char relative[CLIQ_SOURCE_PATH_BYTES];
        int length = snprintf(relative, sizeof(relative), "%s%s%s", prefix, *prefix ? "/" : "", entry->d_name);
        if (length <= 0 || (size_t)length >= sizeof(relative) || !cliq_source_path(relative, (uint32_t)length) ||
            source_forbidden_path(relative) || (strcmp(prefix, "info") == 0 && strcmp(entry->d_name, "exclude") != 0)) { valid = false; break; }
        /* Optional accelerators are not object roots. Do not open their
         * payload, pass them to Git, or let them enter permanent CAS. */
        size_t name_bytes = strlen(entry->d_name);
        bool accelerator = strcmp(prefix, "objects/pack") == 0 &&
            ((name_bytes > 4 && strcmp(entry->d_name + name_bytes - 4, ".rev") == 0) ||
             (name_bytes > 7 && strcmp(entry->d_name + name_bytes - 7, ".bitmap") == 0));
        bool exclude = strcmp(relative, "info/exclude") == 0;
        /* Metadata can establish that the independent ignore input exists;
         * its inspection grant cannot grant that payload. Refuse in the
         * first metadata-only pass, before any copy, rather than capture a
         * projection that silently treats the effective rule as absent. */
        if (exclude && !snapshot->exclude_enabled) { errno = EACCES; valid = false; break; }
        if (accelerator || strcmp(relative, "objects/info/packs") == 0) {
            if (!S_ISREG(named.st_mode) || named.st_nlink != 1) { valid = false; break; }
            continue;
        }
        bool ignored_directory = strcmp(relative, "info") == 0 && S_ISDIR(named.st_mode);
        if (!ignored_directory && !source_add_u64(entries, 1, CLIQ_SOURCE_MAX_ENTRIES)) { valid = false; break; }
        struct cliq_source_entry_header header = { .magic = CLIQ_SOURCE_HEADER_MAGIC,
            .kind = S_ISDIR(named.st_mode) ? CLIQ_SOURCE_DIRECTORY : strcmp(relative, "config") == 0 ? CLIQ_SOURCE_CONFIG :
                exclude ? CLIQ_SOURCE_EXCLUDE : CLIQ_SOURCE_FILE,
            .path_bytes = (uint32_t)length, .mode = S_ISDIR(named.st_mode) ? 0700 : 0600,
            .byte_count = S_ISDIR(named.st_mode) ? 0 : (uint64_t)named.st_size };
        if ((!S_ISDIR(named.st_mode) && (named.st_size < 0 || named.st_nlink != 1 || header.byte_count > snapshot->file_limit ||
             (header.kind == CLIQ_SOURCE_CONFIG && header.byte_count > CLIQ_SOURCE_MAX_CONFIG) ||
             (exclude && header.byte_count > snapshot->rule_limit))) ||
            (!ignored_directory && (!source_add_u64(predicted, sizeof(header) + (uint64_t)length, snapshot->limit) ||
             !source_add_u64(predicted, header.byte_count, snapshot->limit)))) { valid = false; break; }
        if (exclude) { snapshot->rule_present = true; snapshot->rule_bytes = header.byte_count; }
        sha256_update(metadata, (const unsigned char *)&header, sizeof(header));
        sha256_update(metadata, (const unsigned char *)relative, (size_t)length);
        sha256_update(metadata, (const unsigned char *)&named.st_dev, sizeof(named.st_dev));
        sha256_update(metadata, (const unsigned char *)&named.st_ino, sizeof(named.st_ino));
        sha256_update(metadata, (const unsigned char *)&named.st_mtim, sizeof(named.st_mtim));
        sha256_update(metadata, (const unsigned char *)&named.st_ctim, sizeof(named.st_ctim));
        int file = openat(directory, entry->d_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | (S_ISDIR(named.st_mode) ? O_DIRECTORY : O_NONBLOCK));
        struct stat opened, finished, current;
        valid = file >= 0 && fstat(file, &opened) == 0 && source_stat_same(&named, &opened);
        if (valid && copy && !ignored_directory) valid = source_snapshot_write(snapshot, &header, sizeof(header)) && source_snapshot_write(snapshot, relative, (size_t)length);
        if (valid && S_ISDIR(named.st_mode)) valid = source_walk_snapshot(file, device, depth + 1, relative, snapshot, copy, metadata, predicted, entries);
        else if (valid && copy) {
            unsigned char buffer[65536]; uint64_t read_bytes = 0;
            while (valid && read_bytes < header.byte_count) {
                size_t wanted = header.byte_count - read_bytes < sizeof(buffer) ? (size_t)(header.byte_count - read_bytes) : sizeof(buffer);
                ssize_t count = read(file, buffer, wanted);
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0 || !source_snapshot_write(snapshot, buffer, (size_t)count)) { valid = false; break; }
                read_bytes += (uint64_t)count;
            }
            unsigned char extra; ssize_t count;
            do { count = read(file, &extra, 1); } while (count < 0 && errno == EINTR);
            valid = valid && count == 0 && read_bytes == header.byte_count;
            memset(buffer, 0, sizeof(buffer));
        }
        valid = valid && fstat(file, &finished) == 0 && source_stat_same(&named, &finished) &&
            fstatat(directory, entry->d_name, &current, AT_SYMLINK_NOFOLLOW) == 0 && source_stat_same(&named, &current);
        if (!source_close_fd(&file)) valid = false;
        if (!valid) break;
    }
    if (closedir(stream) != 0) valid = false;
    return valid && fstat(directory, &after) == 0 && source_stat_same(&before, &after);
}
static bool source_capture_snapshot(int git, const struct cliq_worker_packet *request, struct cliq_source_snapshot *snapshot, uint64_t reserve) {
    struct stat root;
    source_snapshot_init(snapshot, request);
    if (reserve >= snapshot->limit) return false;
    snapshot->limit -= reserve;
    if (fstat(git, &root) != 0 || !S_ISDIR(root.st_mode)) return false;
    struct sha256_context first, second; sha256_init(&first); sha256_init(&second);
    uint64_t expected = 0, expected_entries = 0, actual = 0, actual_entries = 0;
    if (!source_walk_snapshot(git, root.st_dev, 0, "", snapshot, false, &first, &expected, &expected_entries) ||
        expected == 0 || expected_entries == 0 || request->max_file_bytes == 0) return false;
    uint64_t shards = (expected - 1) / request->max_file_bytes + 1;
    /* Shared tmpfs extraction and output must fit while the immutable input
     * remains alive. This is a refusal under the original ceiling, not an
     * extra quota or a claim all simultaneous maxima fit. */
    uint64_t rounded = 0;
    for (uint64_t i = 0, left = expected; i < shards; i++) {
        uint64_t bytes = left < request->max_file_bytes ? left : request->max_file_bytes;
        if (bytes > UINT64_MAX - 4095 || !source_add_u64(&rounded, (bytes + 4095) & ~UINT64_C(4095), request->max_generation_bytes)) return false;
        left -= bytes;
    }
    if (shards > CLIQ_SOURCE_MAX_SHARDS || shards + 2 * snapshot->max_depth + 12 >= request->max_open_files ||
        rounded > snapshot->limit / 2) return false;
    if (!source_walk_snapshot(git, root.st_dev, 0, "", snapshot, true, &second, &actual, &actual_entries)) return false;
    unsigned char first_digest[32], second_digest[32]; sha256_final(&first, first_digest); sha256_final(&second, second_digest);
    if (expected != actual || expected != snapshot->bytes || expected_entries != actual_entries ||
        memcmp(first_digest, second_digest, sizeof(first_digest)) != 0) return false;
    snapshot->entries = actual_entries; sha256_final(&snapshot->hash, snapshot->digest);
    int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    for (uint32_t i = 0; i < snapshot->count; i++) {
        struct stat file;
        if (fchmod(snapshot->shards[i], 0400) != 0 || fcntl(snapshot->shards[i], F_ADD_SEALS, required) != 0 ||
            fcntl(snapshot->shards[i], F_GET_SEALS) != required || fstat(snapshot->shards[i], &file) != 0 ||
            !S_ISREG(file.st_mode) || file.st_size < 0 || (uint64_t)file.st_size != snapshot->shard_bytes[i] ||
            file.st_size > (off_t)request->max_file_bytes) return false;
        char filename[64]; snprintf(filename, sizeof(filename), "/proc/self/fd/%d", snapshot->shards[i]);
        int readonly = open(filename, O_RDONLY | O_CLOEXEC);
        struct stat actual_identity;
        bool valid = readonly >= 0 && fstat(readonly, &actual_identity) == 0 && actual_identity.st_dev == file.st_dev &&
            actual_identity.st_ino == file.st_ino && actual_identity.st_size == file.st_size && fcntl(readonly, F_GET_SEALS) == required;
        if (!source_close_fd(&snapshot->shards[i])) valid = false;
        snapshot->shards[i] = readonly;
        if (!valid) return false;
    }
    return true;
}
#endif
