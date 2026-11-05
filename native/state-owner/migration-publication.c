/* Fixed physical control spine of one genuine migration holder. These writes
 * are not SQLite commit, credential readiness or Run authority evidence. The
 * original Store and complete retained readers independently require those.
 * Native never accepts an output path, caller FD, mode or "verified" Boolean.
 * Synchronous fsync below has no Stop2 latency claim; online qualification
 * still needs the original task's real cancellation and resource join. */
#define MIGRATION_DOCUMENT_BYTES 1048576U
enum migration_publication_file_id {
    MP_PREPARATION, MP_CONTROL, MP_STOP_COPY, MP_AUTH_ORIGINAL, MP_AUTH_MARKER,
    MP_AUTHORITY_LEGACY, MP_AUTHORITY_ROOT, MP_CONTROL_OLD_1, MP_CONTROL_OLD_2,
    MP_CONTROL_OLD_3, MP_PREVIOUS_RENDEZVOUS, MP_TEMP, MP_SECOND_TEMP, MP_FILES
};
enum migration_publication_parent { MP_CAS_PARENT, MP_MIGRATION_PARENT, MP_PACKAGE_PARENT, MP_LEGACY_PARENT };
typedef struct migration_publication_file {
    int fd, parent, complete, unlinked, published, identity_known;
    mode_t mode;
    struct stat identity;
    size_t byte_count;
    char leaf[NAME_MAX + 1], digest[65];
} migration_publication_file;
typedef struct migration_publication_top_entry { migration_backup_node *node; uint64_t seen; } migration_publication_top_entry;
struct migration_publication_state {
    int phase, cas_fd, cas_identity_known, auth_observed, auth_present;
    struct stat cas;
    migration_publication_file files[MP_FILES];
    migration_publication_top_entry *top;
    size_t top_count;
    uint64_t top_epoch;
    migration_backup_node **inventory;
    size_t inventory_count;
    int inventory_indexed;
};

static int mp_parent(migration_filesystem *scope, int role) {
    return role == MP_CAS_PARENT ? scope->publication->cas_fd : role == MP_MIGRATION_PARENT ? scope->migration_fd :
        role == MP_PACKAGE_PARENT ? scope->package_fd : role == MP_LEGACY_PARENT ? scope->legacy_fd : -1;
}
static int mp_fd_is_original(const migration_publication_file *file) {
    struct stat observed;
    return file->fd < 0 || !file->identity_known || (fstat(file->fd, &observed) == 0 && same_inode(&observed, &file->identity)) ? 0 : -1;
}
static int mp_file_held(migration_filesystem *scope, const migration_publication_file *file) {
    struct stat opened, named;
    if (file->fd < 0) return 0;
    if (!file->identity_known || fstat(file->fd, &opened) != 0 || !S_ISREG(opened.st_mode) || opened.st_uid != geteuid() ||
        !same_inode(&opened, &file->identity) || (opened.st_mode & 07777) != file->mode ||
        opened.st_nlink != (file->unlinked ? 0 : 1) || opened.st_size < 0) return -1;
    if (file->complete && (!source_metadata_same(&opened, &file->identity) || (uint64_t)opened.st_size != file->byte_count)) return -1;
    if (file->unlinked) return 0;
    return fstatat(mp_parent(scope, file->parent), file->leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        source_metadata_same(&opened, &named) ? 0 : -1;
}
static int migrate_publication_custody(migration_filesystem *scope) {
    migration_publication_state *state = scope->publication;
    if (!state) return 0;
    struct stat observed;
    if (state->cas_fd >= 0 && state->cas_identity_known && (fstat(state->cas_fd, &observed) != 0 || !same_inode(&observed, &state->cas))) return -1;
    for (size_t index = 0; index < MP_FILES; ++index) if (mp_fd_is_original(&state->files[index]) != 0) return -1;
    return 0;
}
static int migrate_publication_validate(migration_filesystem *scope) {
    migration_publication_state *state = scope->publication;
    if (!state) return 0;
    if (state->cas_fd >= 0 && (!state->cas_identity_known ||
        !migrate_scope_directory(scope, scope->binding->owner->root_fd, "cas", state->cas_fd, &state->cas))) return -1;
    for (size_t index = 0; index < MP_FILES; ++index) if (mp_file_held(scope, &state->files[index]) != 0) return -1;
    if (state->auth_observed && !state->auth_present && state->files[MP_AUTH_MARKER].fd < 0) {
        struct stat named;
        if (fstatat(scope->legacy_fd, "auth.json", &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return -1;
    }
    return 0;
}
static int migrate_publication_retire(migration_filesystem *scope) {
    if (!scope->publication) return 0;
    for (size_t index = 0; index < MP_FILES; ++index)
        if (migrate_scope_close_fd(scope, &scope->publication->files[index].fd) != 0) return -1;
    return migrate_scope_close_fd(scope, &scope->publication->cas_fd);
}
static void migrate_publication_free(migration_filesystem *scope) {
    if (!scope->publication) return;
    free(scope->publication->top); free(scope->publication->inventory); free(scope->publication); scope->publication = NULL;
}
static int mp_current(migration_filesystem *scope, napi_env env) {
    return !scope->failed && migrate_scope_check(scope, env) == 0 && migrate_publication_validate(scope) == 0 ? 0 : -1;
}
static int mp_create_state(migration_filesystem *scope) {
    if (scope->publication) return -1;
    migration_publication_state *state = calloc(1, sizeof(*state));
    if (!state) return -1;
    state->cas_fd = -1;
    for (size_t index = 0; index < MP_FILES; ++index) state->files[index].fd = -1;
    scope->publication = state;
    /* Fixed control history uses same-filesystem no-replace rename into this
     * private package. Refuse this profile before the initial stop write. */
    if (scope->migration.st_dev != scope->package.st_dev) return -1;
    state->cas_fd = openat(scope->binding->owner->root_fd, "cas", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (state->cas_fd < 0 || fstat(state->cas_fd, &state->cas) != 0) return -1;
    state->cas_identity_known = 1;
    return private_directory(&state->cas) &&
        migrate_scope_directory(scope, scope->binding->owner->root_fd, "cas", state->cas_fd, &state->cas) ? 0 : -1;
}
static int mp_buffer(napi_env env, napi_value value, const unsigned char **bytes, size_t *count) {
    bool buffer = false; void *data = NULL;
    if (napi_is_buffer(env, value, &buffer) != napi_ok || !buffer || napi_get_buffer_info(env, value, &data, count) != napi_ok ||
        !*count || *count > MIGRATION_DOCUMENT_BYTES) return -1;
    *bytes = data; return 0;
}
static void mp_digest(const unsigned char *bytes, size_t count, char digest[65]) {
    struct sha256_context hash; sha256_init(&hash); sha256_update(&hash, bytes, count); publication_hash_hex(&hash, digest);
}
static int mp_read_hash(migration_publication_file *file, unsigned char *copy) {
    struct stat before, after;
    if (fstat(file->fd, &before) != 0 || !S_ISREG(before.st_mode) || !same_inode(&before, &file->identity) ||
        before.st_size < 1 || before.st_size > MIGRATION_DOCUMENT_BYTES ||
        (file->complete && !source_metadata_same(&before, &file->identity))) return -1;
    size_t offset = 0; unsigned char bytes[65536]; struct sha256_context hash; sha256_init(&hash);
    while (offset < (size_t)before.st_size) {
        size_t wanted = (size_t)before.st_size - offset; if (wanted > sizeof(bytes)) wanted = sizeof(bytes);
        ssize_t count; do { count = pread(file->fd, bytes, wanted, (off_t)offset); } while (count < 0 && errno == EINTR);
        if (count <= 0 || (size_t)count > wanted) return -1;
        sha256_update(&hash, bytes, (size_t)count); if (copy) memcpy(copy + offset, bytes, (size_t)count); offset += (size_t)count;
    }
    ssize_t end; do { end = pread(file->fd, bytes, 1, (off_t)offset); } while (end < 0 && errno == EINTR);
    char digest[65]; publication_hash_hex(&hash, digest);
    if (end != 0 || fstat(file->fd, &after) != 0 || !source_metadata_same(&before, &after) ||
        (file->digest[0] && (file->byte_count != offset || strcmp(file->digest, digest)))) return -1;
    file->identity = after; file->byte_count = offset; memcpy(file->digest, digest, 65); return 0;
}
static int mp_adopt_readonly_observation(migration_filesystem *scope, migration_publication_file *file, int parent,
                                       const char *leaf, mode_t mode, const unsigned char *expected, size_t count) {
    if (file->fd >= 0 || strlen(leaf) > NAME_MAX) return -1;
    struct stat named;
    if (fstatat(mp_parent(scope, parent), leaf, &named, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(named.st_mode) ||
        named.st_uid != geteuid() || (named.st_mode & 07777) != mode || named.st_nlink != 1 ||
        named.st_size < 1 || named.st_size > MIGRATION_DOCUMENT_BYTES) return -1;
    file->fd = openat(mp_parent(scope, parent), leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    file->parent = parent; file->mode = mode; strcpy(file->leaf, leaf);
    if (file->fd < 0 || fstat(file->fd, &file->identity) != 0) return -1;
    file->identity_known = 1;
    if (!source_metadata_same(&named, &file->identity)) return -1;
    file->byte_count = (size_t)named.st_size; file->complete = 1;
    if (file->fd < 0 || mp_file_held(scope, file) != 0 || mp_read_hash(file, NULL) != 0) return -1;
    if (expected) { char digest[65]; mp_digest(expected, count, digest);
        if (count != file->byte_count || strcmp(file->digest, digest)) return -1; }
    file->complete = 1; file->published = 1; return mp_file_held(scope, file);
}
static int mp_birth(migration_filesystem *scope, migration_publication_file *file, int parent, const char *leaf,
                    const unsigned char *input, size_t count) {
    if (file->fd >= 0 || !count || count > MIGRATION_DOCUMENT_BYTES || strlen(leaf) > NAME_MAX) return -1;
    unsigned char *copy = malloc(count); if (!copy) return -1; memcpy(copy, input, count);
    file->parent = parent; file->mode = 0600; strcpy(file->leaf, leaf);
    file->fd = openat(mp_parent(scope, parent), leaf, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    int valid = file->fd >= 0 && fstat(file->fd, &file->identity) == 0;
    if (valid) file->identity_known = 1;
    valid = valid && S_ISREG(file->identity.st_mode) &&
        file->identity.st_uid == geteuid() && (file->identity.st_mode & 07777) == 0600 && file->identity.st_nlink == 1;
    size_t offset = 0;
    while (valid && offset < count) {
        size_t wanted = count - offset; if (wanted > 65536) wanted = 65536;
        ssize_t written; do { written = pwrite(file->fd, copy + offset, wanted, (off_t)offset); } while (written < 0 && errno == EINTR);
        if (written <= 0 || (size_t)written > wanted) valid = 0; else offset += (size_t)written;
    }
    char expected[65]; mp_digest(copy, count, expected); free(copy);
    if (!valid || fsync(file->fd) != 0 || mp_read_hash(file, NULL) != 0 || file->byte_count != count || strcmp(file->digest, expected)) return -1;
    file->complete = 1;
    if (mp_file_held(scope, file) != 0) return -1;
    int readonly = openat(mp_parent(scope, parent), leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat observed;
    if (readonly < 0 || fstat(readonly, &observed) != 0 || !source_metadata_same(&observed, &file->identity)) {
        if (migrate_scope_close_fd(scope, &readonly) != 0) return -1;
        return -1;
    }
    if (migrate_scope_close_fd(scope, &file->fd) != 0) { file->fd = readonly; return -1; }
    file->fd = readonly;
    return fsync(mp_parent(scope, parent)) == 0 && mp_file_held(scope, file) == 0 ? 0 : -1;
}
static int mp_refresh_owned(migration_filesystem *scope, migration_publication_file *file) {
    /* Only callers immediately after their actual owned rename/chmod/unlink
     * reach this helper. Identity/length/full hash never become mutable. */
    file->complete = 0;
    if (mp_read_hash(file, NULL) != 0) return -1;
    file->complete = 1; return mp_file_held(scope, file);
}
static int mp_rename_new(migration_filesystem *scope, migration_publication_file *file, int parent, const char *leaf) {
    if (mp_file_held(scope, file) != 0 || !file->complete || !publication_rename_exclusive(mp_parent(scope, file->parent), file->leaf,
        mp_parent(scope, parent), leaf)) return -1;
    int prior = file->parent; file->parent = parent; strcpy(file->leaf, leaf); file->published = 1;
    return mp_refresh_owned(scope, file) == 0 && fsync(mp_parent(scope, prior)) == 0 &&
        (prior == parent || fsync(mp_parent(scope, parent)) == 0) ? 0 : -1;
}
static int mp_exchange(migration_filesystem *scope, migration_publication_file *old, migration_publication_file *fresh) {
    if (old->parent != fresh->parent || mp_file_held(scope, old) != 0 || mp_file_held(scope, fresh) != 0 ||
        !old->complete || !fresh->complete || !publication_exchange(mp_parent(scope, old->parent), old->leaf,
          mp_parent(scope, fresh->parent), fresh->leaf)) return -1;
    char leaf[NAME_MAX + 1]; strcpy(leaf, old->leaf); strcpy(old->leaf, fresh->leaf); strcpy(fresh->leaf, leaf);
    fresh->published = 1;
    return mp_refresh_owned(scope, old) == 0 && mp_refresh_owned(scope, fresh) == 0 && fsync(mp_parent(scope, fresh->parent)) == 0 ? 0 : -1;
}
static int mp_unlink_owned(migration_filesystem *scope, migration_publication_file *file) {
    if (mp_file_held(scope, file) != 0 || file->unlinked || unlinkat(mp_parent(scope, file->parent), file->leaf, 0) != 0) return -1;
    file->unlinked = 1;
    return mp_refresh_owned(scope, file) == 0 && fsync(mp_parent(scope, file->parent)) == 0 ? 0 : -1;
}
static int mp_absent(migration_filesystem *scope, int parent, const char *leaf) {
    struct stat observed;
    return fstatat(mp_parent(scope, parent), leaf, &observed, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT ? 0 : -1;
}
static int mp_top_compare(const void *left, const void *right) {
    return strcmp(((const migration_publication_top_entry *)left)->node->name, ((const migration_publication_top_entry *)right)->node->name);
}
static int mp_top_index(migration_filesystem *scope) {
    migration_publication_state *state = scope->publication;
    if (state->top) return 0;
    size_t count = 0;
    for (migration_backup_node *node = scope->backup_nodes; node; node = node->next) if (node->parent == scope->backup_root) count++;
    if (scope->backup_metadata_bytes > MIGRATION_BACKUP_METADATA_BYTES ||
        count > (MIGRATION_BACKUP_METADATA_BYTES - scope->backup_metadata_bytes) / sizeof(*state->top)) return -1;
    state->top = calloc(count ? count : 1, sizeof(*state->top)); if (!state->top) return -1;
    state->top_count = count; scope->backup_metadata_bytes += count * sizeof(*state->top); size_t offset = 0;
    for (migration_backup_node *node = scope->backup_nodes; node; node = node->next) if (node->parent == scope->backup_root) state->top[offset++].node = node;
    qsort(state->top, count, sizeof(*state->top), mp_top_compare); return 0;
}
static migration_publication_top_entry *mp_top_find(migration_publication_state *state, const char *name) {
    size_t low = 0, high = state->top_count;
    while (low < high) { size_t mid = low + (high - low) / 2; int comparison = strcmp(name, state->top[mid].node->name);
        if (!comparison) return &state->top[mid];
        if (comparison < 0) high = mid; else low = mid + 1; }
    return NULL;
}
static int mp_is_named_file(migration_filesystem *scope, const migration_publication_file *file, const char *name, const struct stat *info) {
    return file->fd >= 0 && !file->unlinked && file->parent == MP_LEGACY_PARENT && !strcmp(file->leaf, name) &&
        mp_file_held(scope, file) == 0 && source_metadata_same(&file->identity, info);
}
static int mp_refresh_source_root(migration_filesystem *scope) {
    if (!scope->backup_started) return 0;
    if (!scope->backup_complete || !scope->backup_root || mp_top_index(scope) != 0) return -1;
    migration_publication_state *state = scope->publication;
    if (state->top_epoch == UINT64_MAX) return -1;
    uint64_t epoch = ++state->top_epoch; struct stat before, after;
    if (fstat(scope->legacy_fd, &before) != 0 || !same_inode(&before, &scope->backup_root->source)) return -1;
    int duplicate = fcntl(scope->legacy_fd, F_DUPFD_CLOEXEC, 3); if (duplicate < 0) return -1;
    DIR *directory = fdopendir(duplicate);
    if (!directory) { migrate_scope_close_fd(scope, &duplicate); return -1; }
    /* dup shares the original open directory offset. The earlier completed
     * copier exhausted it; this independent full enumeration must start at
     * the actual beginning, not interpret the inherited EOF as an empty root. */
    rewinddir(directory);
    size_t seen = 0; int valid = 1;
    for (;;) {
        errno = 0; struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) valid = 0; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat named;
        if (fstatat(scope->legacy_fd, entry->d_name, &named, AT_SYMLINK_NOFOLLOW) != 0) { valid = 0; break; }
        if ((S_ISDIR(named.st_mode) && (same_inode(&named, &scope->binding->owner->root) ||
              migrate_legacy_locks_owns(scope, &named))) ||
            (S_ISREG(named.st_mode) && source_metadata_same(&named, &scope->binding->gate->file))) continue;
        int owned = 0;
        for (size_t index = 0; index < MP_FILES; ++index) if (mp_is_named_file(scope, &state->files[index], entry->d_name, &named)) { owned = 1; break; }
        if (owned) continue;
        migration_publication_top_entry *expected = mp_top_find(state, entry->d_name);
        if (!expected || expected->seen == epoch || !source_metadata_same(&named, &expected->node->source)) { valid = 0; break; }
        expected->seen = epoch; seen++;
    }
    if (closedir(directory) != 0) { migrate_scope_poison(scope); return -1; }
    if (!valid || seen != state->top_count || fstat(scope->legacy_fd, &after) != 0 || !source_metadata_same(&before, &after) ||
        migrate_scope_legacy_chain_held(scope) != 0 || migrate_publication_validate(scope) != 0) return -1;
    /* Only after the all-and-only original top entries plus exact owned
     * protocol entries match do actual own leaf changes update this one stat.
     * This is not whole-tree/quiescence or old-creator evidence. */
    scope->backup_root->source = after; return 0;
}
static int migrate_publication_owns_rendezvous(migration_filesystem *scope, const struct stat *observed) {
    if (!scope->publication) return 0;
    migration_publication_file *file = &scope->publication->files[MP_STOP_COPY];
    if (file->unlinked) file = &scope->publication->files[MP_AUTHORITY_LEGACY];
    return file->fd >= 0 && file->published && !file->unlinked && mp_file_held(scope, file) == 0 && source_metadata_same(&file->identity, observed);
}
static int migrate_publication_allows_backup(migration_filesystem *scope) {
    /* Original native component campaign does not create migration authority.
     * A production publication holder, once present, has the strict spine. */
    return !scope->publication || (scope->publication->phase == 1 && scope->publication->auth_observed &&
        migrate_legacy_locks_ready(scope) &&
        migrate_publication_validate(scope) == 0);
}
static napi_value mp_undefined(napi_env env) { napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL; }
static int mp_root_value(napi_env env, napi_value target, const char *key, const char *path, const struct stat *identity) {
    napi_value result, uid, mode, nofollow;
#ifdef __APPLE__
    unsigned long long device = (uint32_t)identity->st_dev;
#else
    unsigned long long device = identity->st_dev;
#endif
    return napi_create_object(env, &result) == napi_ok && publication_set_string(env, result, "canonicalAbsolutePath", path) &&
        decimal_member(env, result, "deviceId", device) && decimal_member(env, result, "directoryFileId", identity->st_ino) &&
        napi_create_uint32(env, identity->st_uid, &uid) == napi_ok && napi_set_named_property(env, result, "ownerUid", uid) == napi_ok &&
        napi_create_uint32(env, identity->st_mode & 07777, &mode) == napi_ok && napi_set_named_property(env, result, "mode", mode) == napi_ok &&
        napi_get_boolean(env, true, &nofollow) == napi_ok && napi_set_named_property(env, result, "openedNoFollow", nofollow) == napi_ok &&
        napi_object_freeze(env, result) == napi_ok && napi_set_named_property(env, target, key, result) == napi_ok;
}
static napi_value migrate_publication_roots(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info); if (!scope) return NULL;
    if (mp_current(scope, env) != 0) return migrate_scope_error(env, scope, "migration roots are not genuinely held");
    struct stat legacy, backup; char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s/migration/owned-import/%s/backup", scope->binding->owner->path, scope->migration_id);
    napi_value result;
    if (length < 0 || (size_t)length >= sizeof(path) || fstat(scope->legacy_fd, &legacy) != 0 || fstat(scope->backup_fd, &backup) != 0 ||
        napi_create_object(env, &result) != napi_ok || !mp_root_value(env, result, "legacyRoot", scope->legacy_path, &legacy) ||
        !mp_root_value(env, result, "backupRoot", path, &backup) || mp_current(scope, env) != 0)
        return migrate_scope_error(env, scope, "migration roots observation failed");
    return result;
}
static napi_value migrate_publication_initial(napi_env env, napi_callback_info info) {
    size_t count = 4; napi_value arguments[4];
    migration_filesystem *scope = migrate_scope_receiver(env, info, &count, arguments); if (!scope) return NULL;
    const unsigned char *control, *previous = NULL; size_t control_size, previous_size = 0; char ref[65];
    if ((count != 2 && count != 3) || mp_current(scope, env) != 0 || scope->backup_started || scope->candidate_created ||
        migrate_scope_text(env, arguments[0], ref, sizeof(ref)) != 0 || strlen(ref) != 64 || strspn(ref, "0123456789abcdef") != 64 ||
        mp_buffer(env, arguments[1], &control, &control_size) != 0 ||
        (count == 3 && mp_buffer(env, arguments[2], &previous, &previous_size) != 0) || mp_create_state(scope) != 0)
        return migrate_scope_error(env, scope, "initial migration spine requires its original new package and bounded canonical inputs");
    migration_publication_state *state = scope->publication;
    migration_publication_file *prep = &state->files[MP_PREPARATION], *current = &state->files[MP_CONTROL], *stop = &state->files[MP_STOP_COPY];
    if (mp_adopt_readonly_observation(scope, prep, MP_CAS_PARENT, ref, 0400, NULL, 0) != 0 || strcmp(prep->digest, ref) ||
        fsync(prep->fd) != 0 || fsync(state->cas_fd) != 0 || mp_absent(scope, MP_MIGRATION_PARENT, "control-v1.json") != 0 ||
        mp_absent(scope, MP_MIGRATION_PARENT, "authority-v1.json") != 0)
        return migrate_scope_error(env, scope, "preparation is not the complete original CAS object or a control already exists");
    if (previous ? mp_adopt_readonly_observation(scope, &state->files[MP_PREVIOUS_RENDEZVOUS], MP_LEGACY_PARENT,
        ".cliq-generation-v1.json", 0600, previous, previous_size) != 0 : mp_absent(scope, MP_LEGACY_PARENT, ".cliq-generation-v1.json") != 0)
        return migrate_scope_error(env, scope, "Legacy rendezvous differs from its exact authorized preimage");
    char temp[NAME_MAX + 1];
    if (snprintf(temp, sizeof(temp), ".cliq-%s-control-1.tmp", scope->migration_id) < 0 ||
        mp_birth(scope, current, MP_MIGRATION_PARENT, temp, control, control_size) != 0 ||
        mp_rename_new(scope, current, MP_MIGRATION_PARENT, "control-v1.json") != 0 ||
        snprintf(temp, sizeof(temp), ".cliq-%s-rendezvous.tmp", scope->migration_id) < 0 ||
        mp_birth(scope, stop, MP_LEGACY_PARENT, temp, control, control_size) != 0)
        return migrate_scope_error(env, scope, "initial control or Legacy stop-copy did not completely publish");
    if (previous) {
        migration_publication_file *old = &state->files[MP_PREVIOUS_RENDEZVOUS];
        if (mp_exchange(scope, old, stop) != 0 || mp_unlink_owned(scope, old) != 0)
            return migrate_scope_error(env, scope, "captured previous Legacy marker did not retire during the new stop-copy publication");
    } else if (mp_rename_new(scope, stop, MP_LEGACY_PARENT, ".cliq-generation-v1.json") != 0)
        return migrate_scope_error(env, scope, "new Legacy stop-copy did not durably publish");
    state->phase = 1;
    if (mp_current(scope, env) != 0) return migrate_scope_error(env, scope, "initial migration spine drifted after publication");
    return mp_undefined(env);
}
static napi_value migrate_publication_control(napi_env env, napi_callback_info info) {
    size_t count = 2; napi_value arguments[2]; migration_filesystem *scope = migrate_scope_receiver(env, info, &count, arguments);
    if (!scope) return NULL;
    const unsigned char *bytes; size_t size; migration_publication_state *state = scope->publication;
    if (count != 1 || mp_current(scope, env) != 0 || migrate_legacy_locks_assert_current(scope) != 0 || !state || state->phase < 1 || state->phase > 3 ||
        mp_buffer(env, arguments[0], &bytes, &size) != 0 || !scope->candidate_sealed || scope->children || !scope->source_verified_for_seal)
        return migrate_scope_error(env, scope, "control successor requires its original sealed candidate and contiguous spine");
    migration_publication_file *current = &state->files[MP_CONTROL], *fresh = &state->files[MP_TEMP];
    char temp[NAME_MAX + 1], history[64]; int prior = state->phase;
    snprintf(temp, sizeof(temp), ".cliq-%s-control-%d.tmp", scope->migration_id, prior + 1);
    snprintf(history, sizeof(history), "control-%d.json", prior);
    if (mp_birth(scope, fresh, MP_MIGRATION_PARENT, temp, bytes, size) != 0 || mp_exchange(scope, current, fresh) != 0 ||
        mp_rename_new(scope, current, MP_PACKAGE_PARENT, history) != 0 || fchmod(current->fd, 0400) != 0)
        return migrate_scope_error(env, scope, "control replacement did not retain its original displaced inode");
    current->mode = 0400;
    if (fsync(current->fd) != 0 || mp_refresh_owned(scope, current) != 0 || fsync(scope->package_fd) != 0)
        return migrate_scope_error(env, scope, "original control history did not durably seal");
    state->files[MP_CONTROL_OLD_1 + prior - 1] = *current; *current = *fresh;
    memset(fresh, 0, sizeof(*fresh)); fresh->fd = -1; state->phase++;
    return mp_current(scope, env) == 0 && migrate_legacy_locks_assert_current(scope) == 0 ? mp_undefined(env) : migrate_scope_error(env, scope, "new control spine drifted");
}
static napi_value migrate_publication_auth_observation(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info); if (!scope) return NULL;
    migration_publication_state *state = scope->publication;
    if (mp_current(scope, env) != 0 || migrate_legacy_locks_assert_current(scope) != 0 || !state || state->phase < 1 || state->phase > 4 ||
        (!state->auth_observed && (state->phase != 1 || scope->backup_started)))
        return migrate_scope_error(env, scope, "private auth observation requires the durable original stop spine before backup");
    if (!state->auth_observed) {
        struct stat named;
        if (fstatat(scope->legacy_fd, "auth.json", &named, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno != ENOENT) return migrate_scope_error(env, scope, "original auth presence is unavailable");
            state->auth_present = 0;
        } else {
            if (mp_adopt_readonly_observation(scope, &state->files[MP_AUTH_ORIGINAL], MP_LEGACY_PARENT, "auth.json", 0600, NULL, 0) != 0)
                return migrate_scope_error(env, scope, "original auth is not one complete private no-follow file");
            state->auth_present = 1;
        }
        state->auth_observed = 1;
    }
    napi_value result;
    if (napi_create_object(env, &result) != napi_ok || !publication_set_string(env, result, "presence", state->auth_present ? "present" : "absent")) return NULL;
    if (state->auth_present) {
        migration_publication_file *file = &state->files[MP_AUTH_ORIGINAL]; napi_value size, mode, links;
        if (mp_read_hash(file, NULL) != 0 || !identity_member(env, result, "file", &file->identity) ||
            !publication_set_string(env, result, "contentDigest", file->digest) ||
            napi_create_double(env, file->byte_count, &size) != napi_ok || napi_set_named_property(env, result, "byteCount", size) != napi_ok ||
            napi_create_uint32(env, 0600, &mode) != napi_ok || napi_set_named_property(env, result, "mode", mode) != napi_ok ||
            napi_create_uint32(env, 1, &links) != napi_ok || napi_set_named_property(env, result, "linkCount", links) != napi_ok) return NULL;
    } else if (!publication_set_string(env, result, "noFollowLookupResult", "ENOENT")) return NULL;
    return mp_current(scope, env) == 0 && migrate_legacy_locks_assert_current(scope) == 0 ? result : migrate_scope_error(env, scope, "original auth observation changed");
}
static napi_value migrate_publication_auth_marker(napi_env env, napi_callback_info info) {
    size_t count = 2; napi_value arguments[2]; migration_filesystem *scope = migrate_scope_receiver(env, info, &count, arguments);
    if (!scope) return NULL;
    const unsigned char *bytes; size_t size; migration_publication_state *state = scope->publication;
    if (count != 1 || mp_current(scope, env) != 0 || migrate_legacy_locks_assert_current(scope) != 0 || !state || state->phase != 4 || !state->auth_observed ||
        !scope->candidate_sealed || scope->children || migrate_backup_source_root_stable(scope) != 0 ||
        mp_buffer(env, arguments[0], &bytes, &size) != 0)
        return migrate_scope_error(env, scope, "auth cutover requires its original committed-import intent and private observation");
    migration_publication_file *marker = &state->files[MP_AUTH_MARKER]; char temp[NAME_MAX + 1];
    snprintf(temp, sizeof(temp), ".cliq-%s-auth.tmp", scope->migration_id);
    if (mp_birth(scope, marker, MP_LEGACY_PARENT, temp, bytes, size) != 0)
        return migrate_scope_error(env, scope, "auth marker did not completely stage");
    if (state->auth_present) {
        migration_publication_file *original = &state->files[MP_AUTH_ORIGINAL];
        if (mp_read_hash(original, NULL) != 0 || mp_exchange(scope, original, marker) != 0 || mp_unlink_owned(scope, original) != 0)
            return migrate_scope_error(env, scope, "original private auth did not retire through its held replacement");
    } else if (mp_rename_new(scope, marker, MP_LEGACY_PARENT, "auth.json") != 0)
        return migrate_scope_error(env, scope, "absent auth marker did not publish by no-replace");
    state->phase = 5;
    return mp_refresh_source_root(scope) == 0 && mp_current(scope, env) == 0 && migrate_legacy_locks_assert_current(scope) == 0 ? mp_undefined(env) :
        migrate_scope_error(env, scope, "auth marker changed an unowned source entry");
}
static napi_value migrate_publication_authority(napi_env env, napi_callback_info info) {
    size_t count = 2; napi_value arguments[2]; migration_filesystem *scope = migrate_scope_receiver(env, info, &count, arguments);
    if (!scope) return NULL;
    const unsigned char *bytes; size_t size; migration_publication_state *state = scope->publication;
    if (count != 1 || mp_current(scope, env) != 0 || migrate_legacy_locks_assert_current(scope) != 0 || !state || state->phase != 5 || !scope->candidate_sealed || scope->children ||
        migrate_backup_source_root_stable(scope) != 0 || mp_buffer(env, arguments[0], &bytes, &size) != 0 ||
        mp_absent(scope, MP_MIGRATION_PARENT, "authority-v1.json") != 0)
        return migrate_scope_error(env, scope, "Kernel authority requires its exact original committed/auth-cutover spine");
    migration_publication_file *legacy = &state->files[MP_AUTHORITY_LEGACY], *root = &state->files[MP_AUTHORITY_ROOT];
    migration_publication_file *old = &state->files[MP_STOP_COPY]; char temp[NAME_MAX + 1];
    snprintf(temp, sizeof(temp), ".cliq-%s-kernel-authority.tmp", scope->migration_id);
    if (mp_birth(scope, root, MP_MIGRATION_PARENT, temp, bytes, size) != 0 ||
        mp_birth(scope, legacy, MP_LEGACY_PARENT, temp, bytes, size) != 0 || strcmp(root->digest, legacy->digest) ||
        root->byte_count != legacy->byte_count || mp_exchange(scope, old, legacy) != 0 || mp_unlink_owned(scope, old) != 0 ||
        mp_refresh_source_root(scope) != 0 || mp_rename_new(scope, root, MP_MIGRATION_PARENT, "authority-v1.json") != 0)
        return migrate_scope_error(env, scope, "identical Legacy-first/StateRoot-last authority publication did not complete");
    state->phase = 6;
    return mp_current(scope, env) == 0 && migrate_legacy_locks_assert_current(scope) == 0 ? mp_undefined(env) : migrate_scope_error(env, scope, "published Kernel authority drifted");
}
static napi_value mp_read_document(napi_env env, napi_callback_info info, int selected) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info); if (!scope) return NULL;
    migration_publication_state *state = scope->publication;
    if (mp_current(scope, env) != 0 || !state || state->phase < 1)
        return migrate_scope_error(env, scope, "original migration document is unavailable");
    if (selected == MP_STOP_COPY && state->phase == 6) selected = MP_AUTHORITY_LEGACY;
    migration_publication_file *file = &state->files[selected];
    if (file->fd < 0 || file->unlinked || !file->complete || file->byte_count > MIGRATION_DOCUMENT_BYTES)
        return migrate_scope_error(env, scope, "original named document is not complete");
    unsigned char *bytes = malloc(file->byte_count); napi_value result = NULL;
    if (!bytes) return migrate_scope_error(env, scope, "document read allocation failed");
    int valid = mp_read_hash(file, bytes) == 0 && mp_current(scope, env) == 0 &&
        napi_create_buffer_copy(env, file->byte_count, bytes, NULL, &result) == napi_ok;
    free(bytes); return valid ? result : migrate_scope_error(env, scope, "original document bytes changed during complete read");
}
static napi_value migrate_publication_read_control(napi_env env, napi_callback_info info) { return mp_read_document(env, info, MP_CONTROL); }
static napi_value migrate_publication_read_preparation(napi_env env, napi_callback_info info) { return mp_read_document(env, info, MP_PREPARATION); }
static napi_value migrate_publication_read_rendezvous(napi_env env, napi_callback_info info) { return mp_read_document(env, info, MP_STOP_COPY); }
static napi_value migrate_publication_assert_credential_cutover(napi_env env, napi_callback_info info) {
    size_t count = 2; napi_value arguments[2]; migration_filesystem *scope = migrate_scope_receiver(env, info, &count, arguments);
    if (!scope) return NULL;
    const unsigned char *bytes; size_t size; char digest[65]; migration_publication_state *state = scope->publication;
    if (count != 1 || mp_current(scope, env) != 0 || migrate_legacy_locks_assert_current(scope) != 0 || !state || state->phase != 3 || !state->auth_observed ||
        !scope->backup_complete || !scope->context_exhausted || !scope->candidate_sealed || !scope->source_verified_for_seal ||
        migrate_backup_source_root_stable(scope) != 0 || mp_buffer(env, arguments[0], &bytes, &size) != 0)
        return migrate_scope_error(env, scope, "final import requires its exact original credential-cutover control and held source boundary");
    mp_digest(bytes, size, digest);
    migration_publication_file *control = &state->files[MP_CONTROL];
    if (!control->complete || control->unlinked || !control->published || control->byte_count != size || strcmp(control->digest, digest) ||
        mp_file_held(scope, control) != 0)
        return migrate_scope_error(env, scope, "final import control differs from the complete original held document");
    return migrate_legacy_locks_assert_current(scope) == 0 ? mp_undefined(env) :
        migrate_scope_error(env, scope, "original Legacy lock cohort changed after final control assertion");
}
static int mp_inventory_compare(const void *left, const void *right) {
    return strcmp((*(migration_backup_node *const *)left)->path, (*(migration_backup_node *const *)right)->path);
}
static int mp_inventory_index(migration_filesystem *scope) {
    migration_publication_state *state = scope->publication;
    if (state->inventory_indexed) return 0;
    size_t count = 0;
    for (migration_backup_node *node = scope->backup_nodes; node; node = node->next) if (node->parent) {
        if (!node->complete || !node->path[0]) return -1;
        count++;
    }
    if ((uint64_t)count != scope->backup_entry_count || scope->backup_metadata_bytes > MIGRATION_BACKUP_METADATA_BYTES ||
        count > (MIGRATION_BACKUP_METADATA_BYTES - scope->backup_metadata_bytes) / sizeof(*state->inventory)) return -1;
    state->inventory = calloc(count ? count : 1, sizeof(*state->inventory)); if (!state->inventory) return -1;
    state->inventory_count = count; scope->backup_metadata_bytes += count * sizeof(*state->inventory); size_t offset = 0;
    for (migration_backup_node *node = scope->backup_nodes; node; node = node->next) if (node->parent) state->inventory[offset++] = node;
    qsort(state->inventory, count, sizeof(*state->inventory), mp_inventory_compare);
    for (size_t index = 1; index < count; ++index) if (strcmp(state->inventory[index - 1]->path, state->inventory[index]->path) >= 0) return -1;
    state->inventory_indexed = 1; return 0;
}
static napi_value migrate_publication_inventory_page(napi_env env, napi_callback_info info) {
    size_t count = 2; napi_value arguments[2]; migration_filesystem *scope = migrate_scope_receiver(env, info, &count, arguments);
    if (!scope) return NULL;
    char after[4097]; migration_publication_state *state = scope->publication;
    if (count != 1 || mp_current(scope, env) != 0 || !state || state->phase < 1 || state->phase > 4 || !scope->backup_complete ||
        migrate_backup_source_root_stable(scope) != 0 || migrate_scope_text(env, arguments[0], after, sizeof(after)) != 0 || mp_inventory_index(scope) != 0)
        return migrate_scope_error(env, scope, "complete backup inventory requires its original captured copy and fixed readonly cursor");
    size_t low = 0, high = state->inventory_count;
    while (low < high) { size_t mid = low + (high - low) / 2;
        if (strcmp(state->inventory[mid]->path, after) <= 0) low = mid + 1; else high = mid; }
    /* At most 32 exact 4096-byte paths plus descriptor metadata fit beneath
     * the unchanged 256KiB retained inventory leaf budget. */
    size_t length = state->inventory_count - low; if (length > 32) length = 32;
    napi_value result, entries, first, total, complete;
    if (napi_create_object(env, &result) != napi_ok || napi_create_array_with_length(env, length, &entries) != napi_ok) return NULL;
    for (size_t index = 0; index < length; ++index) {
        napi_value entry = migrate_backup_entry(env, state->inventory[low + index]);
        if (!entry || napi_set_element(env, entries, (uint32_t)index, entry) != napi_ok) return NULL;
    }
    if (napi_create_double(env, low, &first) != napi_ok || napi_create_double(env, state->inventory_count, &total) != napi_ok ||
        napi_get_boolean(env, low + length == state->inventory_count, &complete) != napi_ok ||
        napi_set_named_property(env, result, "entries", entries) != napi_ok || napi_set_named_property(env, result, "firstOrdinal", first) != napi_ok ||
        napi_set_named_property(env, result, "totalEntries", total) != napi_ok || napi_set_named_property(env, result, "complete", complete) != napi_ok ||
        mp_current(scope, env) != 0)
        return migrate_scope_error(env, scope, "complete backup inventory page changed during its readonly observation");
    return result;
}
