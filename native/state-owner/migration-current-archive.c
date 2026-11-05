/* Fresh readonly observations of the one original archive selected by closed
 * history. This is neither the producer's old holder nor a new SQLite pager.
 * All selectors are fixed under the held Root; packets are data, never an
 * authority token. The private TS consumer must close original birth/history.
 * Included only by the distinct current-inspector receiver. */
#define CA_MAX_ENTRIES 1048576U
#define CA_MANIFEST_BYTES UINT64_C(268435456)
typedef struct ca_file {
    int guard, reader, verified;
    struct stat identity;
    uint64_t size, offset;
    char digest[65];
    struct sha256_context hash;
} ca_file;
typedef struct ca_entry {
    uint64_t inode, size;
    int64_t mtime_seconds, ctime_seconds;
    uint32_t mtime_nanos, ctime_nanos;
    unsigned char seen;
    char name[];
} ca_entry;
struct ci_archive {
    int collection_fd, directory_fd, source_cas_fd, target_cas_fd, entry_fd;
    struct stat collection, directory, source_cas, target_cas, entry_before;
    ca_file manifest, image;
    ca_entry **entries;
    size_t count, verified, expected_entries, scan_seen;
    uint64_t total_bytes, expected_bytes, combined_bytes, entry_offset;
    char entries_digest[65], entry_digest[65];
    struct sha256_context entries_hash, entry_hash;
    DIR *scan;
    int manifest_reads, payload_selected, entry_pass, namespace_complete;
};
static int ca_regular(const struct stat *value) {
    return S_ISREG(value->st_mode) && value->st_uid == geteuid() && value->st_gid == getegid() &&
        (value->st_mode & 07777) == 0400 && value->st_nlink == 1 && value->st_size >= 0;
}
static int ca_directory_same(migration_filesystem *scope, int parent, const char *name, int fd,
                              const struct stat *identity, int stable) {
    struct stat actual;
    return migrate_scope_directory(scope, parent, name, fd, identity) && fstat(fd, &actual) == 0 &&
        (!stable || source_metadata_same(&actual, identity));
}
static int ca_named_file(int parent, const char *name, int fd, const struct stat *identity) {
    struct stat actual, named;
    return fd >= 0 && fstat(fd, &actual) == 0 && ca_regular(&actual) && source_metadata_same(&actual, identity) &&
        fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&actual, &named);
}
static int ca_custody(migration_filesystem *scope) {
    ci_archive *archive = scope->inspection->archive; if (!archive) return 0;
    struct stat absent;
    if (fstatat(scope->binding->owner->root_fd, "local-models", &absent, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return -1;
    if (archive->collection_fd >= 0 && !ca_directory_same(scope, scope->migration_fd, "kernel-archives",
        archive->collection_fd, &archive->collection, 0)) return -1;
    if (archive->directory_fd >= 0 && !ca_directory_same(scope, archive->collection_fd, scope->inspection->archive_id,
        archive->directory_fd, &archive->directory, 1)) return -1;
    if (archive->manifest.guard >= 0 && !ca_named_file(archive->directory_fd, "manifest-v1.json",
        archive->manifest.guard, &archive->manifest.identity)) return -1;
    if (archive->image.guard >= 0 && !ca_named_file(archive->directory_fd, "kernel.sqlite3",
        archive->image.guard, &archive->image.identity)) return -1;
    if (archive->source_cas_fd >= 0 && !ca_directory_same(scope, scope->binding->owner->root_fd, "cas",
        archive->source_cas_fd, &archive->source_cas, 0)) return -1;
    if (archive->target_cas_fd >= 0 && !ca_directory_same(scope, archive->directory_fd, "cas",
        archive->target_cas_fd, &archive->target_cas, 1)) return -1;
    return 0;
}
static int ca_close_scan(migration_filesystem *scope) {
    ci_archive *archive = scope->inspection->archive; DIR *original = archive->scan; archive->scan = NULL;
    if (!original || closedir(original) == 0) return 0;
    migrate_scope_poison(scope); return -1;
}
static int ca_retire(migration_filesystem *scope) {
    ci_archive *archive = scope->inspection->archive; if (!archive) return 0;
    int failed = ca_close_scan(scope) != 0;
    int *const descriptors[] = {&archive->entry_fd, &archive->manifest.reader, &archive->image.reader,
        &archive->manifest.guard, &archive->image.guard, &archive->target_cas_fd, &archive->source_cas_fd,
        &archive->directory_fd, &archive->collection_fd};
    for (size_t index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]); ++index)
        if (migrate_scope_close_fd(scope, descriptors[index]) != 0) failed = 1;
    return failed ? -1 : 0;
}
static void ca_free(migration_filesystem *scope) {
    ci_archive *archive = scope->inspection->archive; if (!archive) return;
    for (size_t index = 0; index < archive->count; ++index) free(archive->entries[index]);
    free(archive->entries); free(archive); scope->inspection->archive = NULL;
}
static int ca_current(migration_filesystem *scope) {
    return ci_legacy_entry(scope) == 0 && migrate_scope_check(scope, scope->env) == 0 &&
        migrate_legacy_locks_ready(scope) ? 0 : -1;
}
static int ca_buffer(napi_env env, napi_value input, const unsigned char **bytes, size_t *size) {
    bool buffer = false; void *actual = NULL;
    if (napi_is_buffer(env, input, &buffer) != napi_ok || !buffer ||
        napi_get_buffer_info(env, input, &actual, size) != napi_ok) return -1;
    *bytes = actual; return 0;
}
static void ca_digest(const unsigned char *bytes, char hex[65]) {
    for (size_t index = 0; index < 32; ++index) snprintf(hex + index * 2, 3, "%02x", bytes[index]);
}
static int ca_witness(const struct stat *identity, const unsigned char *packet) {
    return ci_device(identity) == ci_le64(packet) && (uint64_t)identity->st_ino == ci_le64(packet + 8);
}
static int ca_open_file(migration_filesystem *scope, ca_file *file, const char *name,
                        uint64_t device, uint64_t inode, uint64_t size, const unsigned char *digest) {
    ci_archive *archive = scope->inspection->archive;
    file->guard = openat(archive->directory_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (file->guard < 0 || fstat(file->guard, &file->identity) != 0 || !ca_regular(&file->identity) ||
        file->identity.st_dev != archive->directory.st_dev ||
        ci_device(&file->identity) != device || (uint64_t)file->identity.st_ino != inode ||
        (uint64_t)file->identity.st_size != size || !ca_named_file(archive->directory_fd, name, file->guard, &file->identity)) return -1;
    file->size = size; file->offset = 0; ca_digest(digest, file->digest); sha256_init(&file->hash);
    file->reader = openat(archive->directory_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat actual;
    return file->reader >= 0 && fstat(file->reader, &actual) == 0 && source_metadata_same(&actual, &file->identity) ? 0 : -1;
}
static int ca_file_step(migration_filesystem *scope, ca_file *file, const char *name, unsigned char bytes[65536], size_t *size) {
    ci_archive *archive = scope->inspection->archive; struct stat actual;
    if (!ca_named_file(archive->directory_fd, name, file->guard, &file->identity) ||
        file->reader < 0 || fstat(file->reader, &actual) != 0 || !source_metadata_same(&actual, &file->identity)) return -1;
    size_t wanted = file->size - file->offset; if (wanted > 65536) wanted = 65536;
    ssize_t count;
    do { count = pread(file->reader, bytes, wanted ? wanted : 1, (off_t)file->offset); } while (count < 0 && errno == EINTR);
    if (wanted) {
        if (count <= 0 || (size_t)count > wanted) return -1;
        sha256_update(&file->hash, bytes, (size_t)count); file->offset += (size_t)count; *size = (size_t)count;
        return fstat(file->reader, &actual) == 0 && source_metadata_same(&actual, &file->identity) ? 0 : -1;
    }
    char digest[65]; publication_hash_hex(&file->hash, digest);
    if (count || strcmp(digest, file->digest) || fsync(file->reader) != 0 || fsync(archive->directory_fd) != 0 ||
        !ca_named_file(archive->directory_fd, name, file->guard, &file->identity) ||
        migrate_scope_close_fd(scope, &file->reader) != 0) return -1;
    file->verified = 1; *size = 0; return 1;
}
static int ca_reopen_file(migration_filesystem *scope, ca_file *file, const char *name) {
    ci_archive *archive = scope->inspection->archive;
    if (!file->verified || file->reader >= 0 || !ca_named_file(archive->directory_fd, name, file->guard, &file->identity)) return -1;
    file->reader = openat(archive->directory_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat actual;
    if (file->reader < 0 || fstat(file->reader, &actual) != 0 || !source_metadata_same(&actual, &file->identity)) return -1;
    file->offset = 0; file->verified = 0; sha256_init(&file->hash); return 0;
}
static napi_value ca_boolean(napi_env env, int complete) {
    napi_value result; return napi_get_boolean(env, complete != 0, &result) == napi_ok ? result : NULL;
}
/* CLQMA001 + original collection dev/ino, directory dev/ino, manifest dev/ino,
 * manifest byteCount, uid/reserved0 and SHA256. No selected path is accepted. */
static napi_value ca_select(napi_env env, napi_callback_info info) {
    napi_value args[2]; size_t count = 2; migration_filesystem *scope = ci_receiver(env, info, &count, args); if (!scope) return NULL;
    const unsigned char *p; size_t size;
    if (count != 1 || ca_current(scope) != 0 || scope->inspection->archive || ca_buffer(env, args[0], &p, &size) != 0 ||
        size != 104 || memcmp(p, "CLQMA001", 8) || !ci_le64(p + 56) || ci_le64(p + 56) > CA_MANIFEST_BYTES ||
        ci_le32(p + 64) != (uint32_t)geteuid() || ci_le32(p + 68))
        return migrate_scope_error(env, scope, "current archive selection requires its original bounded fixed manifest witness");
    ci_archive *archive = calloc(1, sizeof(*archive));
    if (!archive) return migrate_scope_error(env, scope, "current archive allocation failed");
    scope->inspection->archive = archive;
    archive->collection_fd = archive->directory_fd = archive->source_cas_fd = archive->target_cas_fd = archive->entry_fd = -1;
    archive->manifest.guard = archive->manifest.reader = archive->image.guard = archive->image.reader = -1;
    if (ci_open_directory(scope, scope->migration_fd, "kernel-archives", &archive->collection_fd, &archive->collection) != 0 ||
        archive->collection.st_dev != scope->binding->owner->root.st_dev ||
        !ca_witness(&archive->collection, p + 8) ||
        ci_open_directory(scope, archive->collection_fd, scope->inspection->archive_id, &archive->directory_fd, &archive->directory) != 0 ||
        archive->directory.st_dev != scope->binding->owner->root.st_dev ||
        !ca_witness(&archive->directory, p + 24) ||
        ca_open_file(scope, &archive->manifest, "manifest-v1.json", ci_le64(p + 40), ci_le64(p + 48), ci_le64(p + 56), p + 72) != 0 ||
        ca_current(scope) != 0) return migrate_scope_error(env, scope, "original archive manifest identity is unavailable or changed");
    return mp_undefined(env);
}
static napi_value ca_verify_manifest_next(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL; ci_archive *archive = scope->inspection->archive;
    if (ca_current(scope) != 0 || !archive || archive->manifest.verified || archive->manifest_reads)
        return migrate_scope_error(env, scope, "current archive has no first full manifest verification");
    unsigned char bytes[65536]; size_t size; int step = ca_file_step(scope, &archive->manifest, "manifest-v1.json", bytes, &size);
    if (step < 0) return migrate_scope_error(env, scope, "original manifest full bytes or original reader retirement failed");
    return ca_boolean(env, step);
}
static napi_value ca_read_manifest_chunk(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL; ci_archive *archive = scope->inspection->archive;
    if (ca_current(scope) != 0 || !archive || archive->manifest_reads >= 2 ||
        (archive->manifest_reads == 1 && !archive->entry_pass))
        return migrate_scope_error(env, scope, "manifest consumer is outside its fixed header/entry pass");
    if (archive->manifest.reader < 0 && ca_reopen_file(scope, &archive->manifest, "manifest-v1.json") != 0)
        return migrate_scope_error(env, scope, "manifest first complete hash and real reader close are required");
    unsigned char bytes[65536]; size_t size; int step = ca_file_step(scope, &archive->manifest, "manifest-v1.json", bytes, &size); napi_value result;
    if (step < 0) return migrate_scope_error(env, scope, "manifest stream changed, lacked EOF or did not actually close");
    if (step) { archive->manifest_reads++; return napi_get_null(env, &result) == napi_ok ? result : NULL; }
    return napi_create_buffer_copy(env, size, bytes, NULL, &result) == napi_ok ? result : NULL;
}
/* CLQMH001 + image(dev/ino/bytes/hash), sourceCAS(dev/ino), targetCAS(dev/ino),
 * entryCount,totalBytes,combinedPayloadBytes,uid/reserved0,entriesDigest. */
static napi_value ca_select_payload(napi_env env, napi_callback_info info) {
    napi_value args[2]; size_t count = 2; migration_filesystem *scope = ci_receiver(env, info, &count, args); if (!scope) return NULL;
    ci_archive *archive = scope->inspection->archive; const unsigned char *p; size_t size;
    if (count != 1 || ca_current(scope) != 0 || !archive || archive->manifest_reads != 1 || !archive->manifest.verified ||
        archive->payload_selected || ca_buffer(env, args[0], &p, &size) != 0 || size != 160 || memcmp(p, "CLQMH001", 8) ||
        !ci_le64(p + 24) || ci_le64(p + 24) > CI_SOURCE_BYTES || ci_le64(p + 96) > CA_MAX_ENTRIES ||
        ci_le64(p + 104) > CI_SOURCE_BYTES - ci_le64(p + 24) || ci_le64(p + 112) != ci_le64(p + 24) + ci_le64(p + 104) ||
        ci_le64(p + 112) > CI_SOURCE_BYTES - archive->manifest.size || ci_le32(p + 120) != (uint32_t)geteuid() || ci_le32(p + 124))
        return migrate_scope_error(env, scope, "archive payload requires its complete closed header within the original total bound");
    uint64_t index_bytes = ci_le64(p + 96) * sizeof(*archive->entries);
    if (index_bytes > MIGRATION_BACKUP_METADATA_BYTES - scope->backup_metadata_bytes ||
        ca_open_file(scope, &archive->image, "kernel.sqlite3", ci_le64(p + 8), ci_le64(p + 16), ci_le64(p + 24), p + 32) != 0 ||
        ci_open_directory(scope, scope->binding->owner->root_fd, "cas", &archive->source_cas_fd, &archive->source_cas) != 0 ||
        !ca_witness(&archive->source_cas, p + 64) ||
        ci_open_directory(scope, archive->directory_fd, "cas", &archive->target_cas_fd, &archive->target_cas) != 0 ||
        !ca_witness(&archive->target_cas, p + 80) || archive->source_cas.st_dev != scope->binding->owner->root.st_dev ||
        archive->target_cas.st_dev != scope->binding->owner->root.st_dev || same_inode(&archive->source_cas, &archive->target_cas))
        return migrate_scope_error(env, scope, "original archived image or source/target namespace identities changed");
    archive->expected_entries = (size_t)ci_le64(p + 96); archive->expected_bytes = ci_le64(p + 104); archive->combined_bytes = ci_le64(p + 112);
    if (archive->expected_entries) {
        archive->entries = calloc(archive->expected_entries, sizeof(*archive->entries));
        if (!archive->entries) return migrate_scope_error(env, scope, "current archive bounded index allocation failed");
    }
    scope->backup_metadata_bytes += index_bytes; ca_digest(p + 128, archive->entries_digest); sha256_init(&archive->entries_hash);
    archive->payload_selected = 1; return mp_undefined(env);
}
static napi_value ca_verify_image_next(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL; ci_archive *archive = scope->inspection->archive;
    if (ca_current(scope) != 0 || !archive || !archive->payload_selected || archive->image.verified || archive->entry_pass)
        return migrate_scope_error(env, scope, "archive image has no original full current verification");
    unsigned char bytes[65536]; size_t size; int step = ca_file_step(scope, &archive->image, "kernel.sqlite3", bytes, &size);
    if (step < 0) return migrate_scope_error(env, scope, "original archived SQL image identity, complete hash or real close failed");
    return ca_boolean(env, step);
}
static napi_value ca_begin_entry_pass(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL; ci_archive *archive = scope->inspection->archive;
    if (ca_current(scope) != 0 || !archive || !archive->payload_selected || !archive->image.verified ||
        archive->manifest_reads != 1 || !archive->manifest.verified || archive->entry_pass ||
        ca_reopen_file(scope, &archive->manifest, "manifest-v1.json") != 0)
        return migrate_scope_error(env, scope, "archive entries require the independently complete header and original image");
    archive->entry_pass = 1; return mp_undefined(env);
}
static int ca_hex(const char *text, size_t size) {
    for (size_t index = 0; index < size; ++index)
        if (!((text[index] >= '0' && text[index] <= '9') || (text[index] >= 'a' && text[index] <= 'f'))) return 0;
    return 1;
}
static int ca_name(const char *name) {
    size_t size = strlen(name);
    if (size == 64 && ca_hex(name, 64)) return 1;
    if (size == 44 && !memcmp(name, ".tmp-stream-", 12) && ca_hex(name + 12, 32)) return 2;
    if (size == 102 && !memcmp(name, ".tmp-", 5) && ca_hex(name + 5, 64) && name[69] == '-' && ca_hex(name + 70, 32)) return 3;
    return 0;
}
static void ca_entry_times(ca_entry *entry, const struct stat *identity) {
#ifdef __APPLE__
    entry->mtime_seconds = identity->st_mtimespec.tv_sec; entry->mtime_nanos = (uint32_t)identity->st_mtimespec.tv_nsec;
    entry->ctime_seconds = identity->st_ctimespec.tv_sec; entry->ctime_nanos = (uint32_t)identity->st_ctimespec.tv_nsec;
#else
    entry->mtime_seconds = identity->st_mtim.tv_sec; entry->mtime_nanos = (uint32_t)identity->st_mtim.tv_nsec;
    entry->ctime_seconds = identity->st_ctim.tv_sec; entry->ctime_nanos = (uint32_t)identity->st_ctim.tv_nsec;
#endif
}
static int ca_entry_same(ci_archive *archive, ca_entry *entry, const struct stat *identity) {
    ca_entry current = {0}; ca_entry_times(&current, identity);
    return ca_regular(identity) && identity->st_dev == archive->target_cas.st_dev && (uint64_t)identity->st_ino == entry->inode &&
        (uint64_t)identity->st_size == entry->size && current.mtime_seconds == entry->mtime_seconds && current.mtime_nanos == entry->mtime_nanos &&
        current.ctime_seconds == entry->ctime_seconds && current.ctime_nanos == entry->ctime_nanos;
}
/* CLQMC001 + kind/reserved0/nameBytes, archive inode, original source inode,
 * byteCount,original sourceMode,reserved0,rawsha256,nameUTF8. */
static napi_value ca_begin_entry(napi_env env, napi_callback_info info) {
    napi_value args[2]; size_t count = 2; migration_filesystem *scope = ci_receiver(env, info, &count, args); if (!scope) return NULL;
    ci_archive *archive = scope->inspection->archive; const unsigned char *p; size_t size;
    if (count != 1 || ca_current(scope) != 0 || !archive || !archive->entry_pass || archive->namespace_complete ||
        archive->manifest_reads != 1 || archive->count != archive->verified || archive->count >= archive->expected_entries ||
        archive->entry_fd >= 0 || ca_buffer(env, args[0], &p, &size) != 0 || size < 81 || size > 182 ||
        memcmp(p, "CLQMC001", 8) || p[8] < 1 || p[8] > 3 || p[9] || p[10] || p[11] ||
        !ci_le32(p + 12) || ci_le32(p + 12) > 102 || size != 80 + (size_t)ci_le32(p + 12) ||
        ci_le32(p + 44) || ci_le64(p + 32) > archive->expected_bytes - archive->total_bytes ||
        (ci_le32(p + 40) != 0400 && !(p[8] == 2 && ci_le32(p + 40) == 0600)))
        return migrate_scope_error(env, scope, "archive entry is outside its fixed complete original namespace packet");
    size_t name_size = ci_le32(p + 12), allocation = sizeof(ca_entry) + name_size + 1;
    if (allocation > MIGRATION_BACKUP_METADATA_BYTES - scope->backup_metadata_bytes)
        return migrate_scope_error(env, scope, "archive and original source indexes exceed the shared metadata ceiling");
    ca_entry *entry = calloc(1, allocation);
    if (!entry) return migrate_scope_error(env, scope, "archive entry allocation failed");
    memcpy(entry->name, p + 80, name_size); entry->inode = ci_le64(p + 16); entry->size = ci_le64(p + 32);
    ca_digest(p + 48, archive->entry_digest);
    if (strlen(entry->name) != name_size || ca_name(entry->name) != p[8] ||
        (archive->count && strcmp(archive->entries[archive->count - 1]->name, entry->name) >= 0) ||
        (p[8] == 1 && strcmp(entry->name, archive->entry_digest)) ||
        (p[8] == 3 && memcmp(entry->name + 5, archive->entry_digest, 64))) goto failed;
    archive->entry_fd = openat(archive->target_cas_fd, entry->name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (archive->entry_fd < 0 || fstat(archive->entry_fd, &archive->entry_before) != 0 || !ca_regular(&archive->entry_before) ||
        archive->entry_before.st_dev != archive->target_cas.st_dev || (uint64_t)archive->entry_before.st_ino != entry->inode ||
        (uint64_t)archive->entry_before.st_size != entry->size) goto failed;
    struct stat named;
    if (fstatat(archive->target_cas_fd, entry->name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !source_metadata_same(&named, &archive->entry_before)) goto failed;
    ca_entry_times(entry, &archive->entry_before); archive->entries[archive->count++] = entry; archive->total_bytes += entry->size;
    scope->backup_metadata_bytes += allocation; archive->entry_offset = 0; sha256_init(&archive->entry_hash);
    static const char *const kinds[] = {"published", "temporary_stream", "temporary_ref"};
    char decimal[32]; int decimal_size = snprintf(decimal, sizeof(decimal), "%llu", (unsigned long long)entry->size);
    sha256_update(&archive->entries_hash, (const unsigned char *)entry->name, name_size);
    sha256_update(&archive->entries_hash, (const unsigned char *)"\0", 1);
    sha256_update(&archive->entries_hash, (const unsigned char *)kinds[p[8] - 1], strlen(kinds[p[8] - 1]));
    sha256_update(&archive->entries_hash, (const unsigned char *)"\0", 1);
    sha256_update(&archive->entries_hash, (const unsigned char *)archive->entry_digest, 64);
    sha256_update(&archive->entries_hash, (const unsigned char *)"\0", 1);
    sha256_update(&archive->entries_hash, (const unsigned char *)decimal, (size_t)decimal_size);
    sha256_update(&archive->entries_hash, (const unsigned char *)"\n", 1);
    return mp_undefined(env);
failed:
    free(entry); return migrate_scope_error(env, scope, "original archived CAS entry identity, name or content binding changed");
}
static napi_value ca_verify_entry_next(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL; ci_archive *archive = scope->inspection->archive;
    if (ca_current(scope) != 0 || !archive || archive->count != archive->verified + 1 || archive->entry_fd < 0)
        return migrate_scope_error(env, scope, "archive has no exact in-progress original entry");
    ca_entry *entry = archive->entries[archive->verified]; struct stat actual, named;
    if (fstat(archive->entry_fd, &actual) != 0 || !source_metadata_same(&actual, &archive->entry_before) ||
        fstatat(archive->target_cas_fd, entry->name, &named, AT_SYMLINK_NOFOLLOW) != 0 || !source_metadata_same(&actual, &named)) goto failed;
    unsigned char bytes[65536]; size_t wanted = entry->size - archive->entry_offset; if (wanted > sizeof(bytes)) wanted = sizeof(bytes);
    ssize_t count;
    do { count = pread(archive->entry_fd, bytes, wanted ? wanted : 1, (off_t)archive->entry_offset); } while (count < 0 && errno == EINTR);
    if (wanted) {
        if (count <= 0 || (size_t)count > wanted) goto failed;
        sha256_update(&archive->entry_hash, bytes, (size_t)count); archive->entry_offset += (size_t)count;
        if (fstat(archive->entry_fd, &actual) != 0 || !source_metadata_same(&actual, &archive->entry_before)) goto failed;
        return ca_boolean(env, 0);
    }
    char digest[65]; publication_hash_hex(&archive->entry_hash, digest);
    if (count || strcmp(digest, archive->entry_digest) || fsync(archive->entry_fd) != 0 || fsync(archive->target_cas_fd) != 0 ||
        fstat(archive->entry_fd, &actual) != 0 || !source_metadata_same(&actual, &archive->entry_before) ||
        fstatat(archive->target_cas_fd, entry->name, &named, AT_SYMLINK_NOFOLLOW) != 0 || !source_metadata_same(&actual, &named) ||
        migrate_scope_close_fd(scope, &archive->entry_fd) != 0) goto failed;
    archive->verified++; return ca_boolean(env, 1);
failed:
    return migrate_scope_error(env, scope, "archived CAS full bytes, original identity, fsync or actual close failed");
}
static size_t ca_find(ci_archive *archive, const char *name) {
    size_t low = 0, high = archive->count;
    while (low < high) { size_t mid = low + (high - low) / 2; int order = strcmp(name, archive->entries[mid]->name);
        if (!order) return mid;
        if (order < 0) high = mid; else low = mid + 1;
    }
    return SIZE_MAX;
}
static int ca_archive_root(migration_filesystem *scope) {
    ci_archive *archive = scope->inspection->archive; int fd = openat(archive->directory_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    DIR *scan = fdopendir(fd); if (!scan) { migrate_scope_close_fd(scope, &fd); return -1; }
    unsigned int names = 0, steps = 0; int valid = 1;
    for (;;) {
        errno = 0; struct dirent *entry = readdir(scan);
        if (!entry) { if (errno) valid = 0; break; }
        if (++steps > 8) { valid = 0; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        unsigned int bit = !strcmp(entry->d_name, "manifest-v1.json") ? 1 : !strcmp(entry->d_name, "kernel.sqlite3") ? 2 :
            !strcmp(entry->d_name, "cas") ? 4 : 0;
        if (!bit || (names & bit)) { valid = 0; break; } names |= bit;
    }
    if (closedir(scan) != 0) { migrate_scope_poison(scope); return -1; }
    return valid && names == 7 && fsync(archive->directory_fd) == 0 ? 0 : -1;
}
static napi_value ca_verify_namespace_next(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL; ci_archive *archive = scope->inspection->archive;
    if (ca_current(scope) != 0 || !archive || !archive->entry_pass || archive->manifest_reads != 2 || !archive->manifest.verified ||
        archive->count != archive->expected_entries || archive->verified != archive->count || archive->entry_fd >= 0 ||
        archive->total_bytes != archive->expected_bytes || archive->namespace_complete)
        return migrate_scope_error(env, scope, "archive namespace lacks the complete joined original entry stream");
    if (!archive->scan) {
        char digest[65]; publication_hash_hex(&archive->entries_hash, digest);
        if (strcmp(digest, archive->entries_digest) || ca_archive_root(scope) != 0) goto failed;
        int fd = openat(archive->target_cas_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) goto failed;
        archive->scan = fdopendir(fd);
        if (!archive->scan) { migrate_scope_close_fd(scope, &fd); goto failed; }
    }
    for (unsigned int step = 0; step < 64; ++step) {
        errno = 0; struct dirent *entry = readdir(archive->scan);
        if (!entry) {
            if (errno || archive->scan_seen != archive->count || fsync(archive->target_cas_fd) != 0 ||
                ca_custody(scope) != 0 || ca_close_scan(scope) != 0) goto failed;
            archive->namespace_complete = 1; return ca_boolean(env, 1);
        }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        size_t found = ca_find(archive, entry->d_name); struct stat named;
        if (found == SIZE_MAX || archive->entries[found]->seen ||
            fstatat(archive->target_cas_fd, entry->d_name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            !ca_entry_same(archive, archive->entries[found], &named)) goto failed;
        archive->entries[found]->seen = 1; archive->scan_seen++;
    }
    return ca_boolean(env, 0);
failed:
    return migrate_scope_error(env, scope, "archive has a missing, replaced, changed or extra physical object");
}
static napi_value ca_inspect(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL; ci_archive *archive = scope->inspection->archive;
    if (ca_current(scope) != 0 || !archive || !archive->namespace_complete || !archive->manifest.verified || !archive->image.verified ||
        migrate_legacy_locks_assert_current(scope) != 0)
        return migrate_scope_error(env, scope, "archive is not one complete current original-object observation");
    napi_value result, kind, count, bytes, sha;
    if (napi_create_object(env, &result) != napi_ok ||
        napi_create_string_utf8(env, "current_checked_original_archive", NAPI_AUTO_LENGTH, &kind) != napi_ok ||
        napi_create_double(env, (double)archive->count, &count) != napi_ok ||
        napi_create_double(env, (double)(archive->combined_bytes + archive->manifest.size), &bytes) != napi_ok ||
        napi_create_string_utf8(env, archive->manifest.digest, 64, &sha) != napi_ok ||
        napi_set_named_property(env, result, "kind", kind) != napi_ok ||
        napi_set_named_property(env, result, "entryCount", count) != napi_ok ||
        napi_set_named_property(env, result, "totalBytes", bytes) != napi_ok ||
        napi_set_named_property(env, result, "manifestSha256", sha) != napi_ok ||
        !identity_member(env, result, "archiveDirectory", &archive->directory) ||
        !identity_member(env, result, "manifestFile", &archive->manifest.identity) ||
        !identity_member(env, result, "databaseFile", &archive->image.identity) ||
        !identity_member(env, result, "casDirectory", &archive->target_cas)) return NULL;
    return result;
}
