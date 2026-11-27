#ifndef CLIQ_SOURCE_GIT_MATERIALIZE_H
#define CLIQ_SOURCE_GIT_MATERIALIZE_H

#include "source-git-snapshot.h"

struct source_snapshot_reader {
    struct cliq_source_snapshot *snapshot;
    uint32_t shard;
    uint64_t offset, bytes;
    struct sha256_context hash;
};
static bool source_snapshot_read(struct source_snapshot_reader *reader, void *target, size_t length) {
    unsigned char *bytes = target; size_t used = 0;
    if (reader->bytes > reader->snapshot->bytes || length > reader->snapshot->bytes - reader->bytes) return false;
    while (used < length) {
        if (reader->shard >= reader->snapshot->count) return false;
        uint64_t available = reader->snapshot->shard_bytes[reader->shard] - reader->offset;
        if (available == 0) { reader->shard++; reader->offset = 0; continue; }
        size_t wanted = available < length - used ? (size_t)available : length - used;
        ssize_t count = pread(reader->snapshot->shards[reader->shard], bytes + used, wanted, (off_t)reader->offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        sha256_update(&reader->hash, bytes + used, (size_t)count);
        used += (size_t)count; reader->offset += (uint64_t)count; reader->bytes += (uint64_t)count;
    }
    return true;
}
/* Parent components must have been materialized by the same stream. No
 * symlink traversal, host path or overwrite branch is available. */
static int source_material_parent(int root, const char *relative, char leaf[256]) {
    char path[CLIQ_SOURCE_PATH_BYTES]; size_t length = strlen(relative);
    if (length == 0 || length >= sizeof(path)) return -1;
    memcpy(path, relative, length + 1);
    int current = fcntl(root, F_DUPFD_CLOEXEC, 5);
    if (current < 0) return -1;
    char *at = path;
    for (;;) {
        char *slash = strchr(at, '/');
        if (!slash) {
            size_t bytes = strlen(at);
            if (bytes == 0 || bytes > 255) { source_close_fd(&current); return -1; }
            memcpy(leaf, at, bytes + 1); return current;
        }
        *slash = '\0';
        int next = openat(current, at, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        struct stat directory;
        bool valid = next >= 0 && fstat(next, &directory) == 0 && S_ISDIR(directory.st_mode) &&
            directory.st_uid == geteuid() && (directory.st_mode & 07777) == 0700;
        if (!source_close_fd(&current)) valid = false;
        if (!valid) { source_close_fd(&next); return -1; }
        current = next; at = slash + 1;
    }
}
static int source_sealed_readonly(int writer) {
    int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (fchmod(writer, 0400) != 0 || fcntl(writer, F_ADD_SEALS, required) != 0 || fcntl(writer, F_GET_SEALS) != required) return -1;
    char path[64]; snprintf(path, sizeof(path), "/proc/self/fd/%d", writer);
    int reader = open(path, O_RDONLY | O_CLOEXEC);
    struct stat before, after;
    if (reader < 0 || fstat(writer, &before) != 0 || fstat(reader, &after) != 0 || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_size != after.st_size || fcntl(reader, F_GET_SEALS) != required) {
        source_close_fd(&reader); return -1;
    }
    return reader;
}
static bool source_materialize_snapshot(struct cliq_source_snapshot *snapshot, int git, int *config, int *exclude) {
    struct source_snapshot_reader reader = { .snapshot = snapshot };
    sha256_init(&reader.hash); uint64_t entries = 0; bool config_seen = false;
    int config_writer = -1, exclude_writer = -1; bool exclude_seen = false, valid = true;
    while (valid && reader.bytes < snapshot->bytes) {
        struct cliq_source_entry_header header; char relative[CLIQ_SOURCE_PATH_BYTES];
        if (!source_snapshot_read(&reader, &header, sizeof(header)) || header.magic != CLIQ_SOURCE_HEADER_MAGIC ||
            header.path_bytes == 0 || header.path_bytes >= sizeof(relative) ||
            !source_snapshot_read(&reader, relative, header.path_bytes) ||
            !cliq_source_path(relative, header.path_bytes) || !source_add_u64(&entries, 1, CLIQ_SOURCE_MAX_ENTRIES)) { valid = false; break; }
        relative[header.path_bytes] = '\0';
        bool directory = header.kind == CLIQ_SOURCE_DIRECTORY, raw_config = header.kind == CLIQ_SOURCE_CONFIG,
            raw_rule = header.kind == CLIQ_SOURCE_EXCLUDE, raw = raw_config || raw_rule;
        if ((header.kind != CLIQ_SOURCE_DIRECTORY && header.kind != CLIQ_SOURCE_FILE && !raw) ||
            header.mode != (uint32_t)(directory ? 0700 : 0600) || (directory && header.byte_count != 0) ||
            header.byte_count > snapshot->file_limit || source_forbidden_path(relative) ||
            (raw_config && (config_seen || strcmp(relative, "config") != 0 || header.byte_count > CLIQ_SOURCE_MAX_CONFIG)) ||
            (raw_rule && (!snapshot->exclude_enabled || exclude_seen || strcmp(relative, "info/exclude") != 0 || header.byte_count > snapshot->rule_limit ||
                !snapshot->rule_present || header.byte_count != snapshot->rule_bytes)) ||
            (!raw_rule && strcmp(relative, "info/exclude") == 0) ||
            (!raw_config && strcmp(relative, "config") == 0)) { valid = false; break; }
        int file = -1, parent = -1;
        if (raw) {
            int *writer = raw_config ? &config_writer : &exclude_writer;
            if (raw_config) config_seen = true; else exclude_seen = true;
            *writer = memfd_create(raw_config ? "cliq-source-raw-config" : "cliq-source-authorized-exclude", MFD_CLOEXEC | MFD_ALLOW_SEALING);
            file = *writer;
        } else {
            char leaf[256]; parent = source_material_parent(git, relative, leaf);
            valid = parent >= 0;
            if (valid && directory) valid = mkdirat(parent, leaf, 0700) == 0;
            if (valid && !directory) file = openat(parent, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        }
        if (valid && !directory) {
            valid = file >= 0; uint64_t remaining = header.byte_count; unsigned char buffer[65536];
            while (valid && remaining) {
                size_t bytes = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
                valid = source_snapshot_read(&reader, buffer, bytes) && source_write_all(file, buffer, bytes);
                remaining -= bytes;
            }
            memset(buffer, 0, sizeof(buffer));
            struct stat metadata;
            valid = valid && fstat(file, &metadata) == 0 && S_ISREG(metadata.st_mode) && metadata.st_nlink == (raw ? 0 : 1) &&
                metadata.st_uid == geteuid() && metadata.st_size >= 0 && (uint64_t)metadata.st_size == header.byte_count;
        }
        if (!raw && !source_close_fd(&file)) valid = false;
        if (!source_close_fd(&parent)) valid = false;
    }
    unsigned char digest[32]; sha256_final(&reader.hash, digest);
    valid = valid && entries == snapshot->entries && reader.bytes == snapshot->bytes &&
        memcmp(digest, snapshot->digest, sizeof(digest)) == 0 && exclude_seen == snapshot->rule_present;
    if (valid && !config_seen) {
        config_writer = memfd_create("cliq-source-raw-config", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        valid = config_writer >= 0;
    }
    int sealed = valid ? source_sealed_readonly(config_writer) : -1;
    int sealed_rule = valid && exclude_seen ? source_sealed_readonly(exclude_writer) : -1;
    if (!source_close_fd(&config_writer)) valid = false;
    if (!source_close_fd(&exclude_writer)) valid = false;
    if (!source_snapshot_close(snapshot)) valid = false;
    if (!valid || sealed < 0 || (exclude_seen && sealed_rule < 0)) { source_close_fd(&sealed); source_close_fd(&sealed_rule); return false; }
    *config = sealed; *exclude = sealed_rule; return true;
}
#endif
