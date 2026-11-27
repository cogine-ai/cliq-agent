/* One current original-inventory stream. Every entry is fresh readonly
 * descriptor-relative observation of recorded source/backup identities, never
 * adoption of an old FD or creator progress. Included by the current holder. */
#define CI_SOURCE_BYTES (50ULL * 1024ULL * 1024ULL * 1024ULL)
static uint32_t ci_le32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t ci_le64(const unsigned char *p) { return (uint64_t)ci_le32(p) | (uint64_t)ci_le32(p + 4) << 32; }
static size_t ci_find(current_migration_inspection *state, const char *path) {
    size_t low = 0, high = state->count;
    while (low < high) {
        size_t mid = low + (high - low) / 2; int order = strcmp(path, state->entries[mid]->path);
        if (!order) return mid;
        if (order < 0) high = mid; else low = mid + 1;
    }
    return SIZE_MAX;
}
static int ci_match(const ci_entry *entry, int side, const struct stat *actual) {
    if (ci_device(actual) != entry->device[side] || (uint64_t)actual->st_ino != entry->inode[side] ||
        actual->st_uid != entry->owner[side] || actual->st_uid != geteuid()) return -1;
    if (entry->kind == 1) return S_ISDIR(actual->st_mode) && actual->st_nlink >= 1 &&
        (uint32_t)(actual->st_mode & 07777) == (side ? 0500U : entry->mode) ? 0 : -1;
    if (entry->kind == 2) return S_ISREG(actual->st_mode) && actual->st_nlink == 1 && actual->st_size >= 0 &&
        (uint64_t)actual->st_size == entry->byte_count && (uint32_t)(actual->st_mode & 07777) == (side ? 0400U : entry->mode) ? 0 : -1;
    return entry->kind == 3 && S_ISLNK(actual->st_mode) && (!side ? (uint32_t)(actual->st_mode & 07777) == entry->mode : 1) ? 0 : -1;
}
static int ci_parent(migration_filesystem *scope, const ci_entry *entry, int side) {
    current_migration_inspection *state = scope->inspection; char path[4097]; strcpy(path, entry->path);
    char *last = strrchr(path, '/'); if (last) *last = '\0'; else path[0] = '\0';
    int root = side ? scope->backup_fd : scope->legacy_fd, current = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat actual; const struct stat *identity = side ? &scope->backup : &scope->legacy;
    if (current < 0 || fstat(current, &actual) != 0 || !ml_same_directory(&actual, identity)) goto failed;
    char prefix[4097] = "", *part = path;
    while (*part) {
        char *slash = strchr(part, '/'); if (slash) *slash = '\0';
        size_t used = strlen(prefix), size = strlen(part);
        if (!size || size > NAME_MAX || used + (used ? 1 : 0) + size > 4096) goto failed;
        if (used) prefix[used++] = '/';
        memcpy(prefix + used, part, size + 1);
        size_t found = ci_find(state, prefix);
        if (found == SIZE_MAX || state->entries[found]->kind != 1 || found >= state->verified) goto failed;
        struct stat named; int next = openat(current, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 || fstat(next, &actual) != 0 || ci_match(state->entries[found], side, &actual) != 0 ||
            fstatat(current, part, &named, AT_SYMLINK_NOFOLLOW) != 0 || !source_metadata_same(&actual, &named)) {
            migrate_scope_close_fd(scope, &next); goto failed;
        }
        if (migrate_scope_close_fd(scope, &current) != 0) { migrate_scope_close_fd(scope, &next); goto failed; }
        current = next; if (!slash) break; part = slash + 1;
    }
    return current;
failed:
    migrate_scope_close_fd(scope, &current); return -1;
}
static const char *ci_leaf(const ci_entry *entry) {
    const char *slash = strrchr(entry->path, '/'); return slash ? slash + 1 : entry->path;
}
static int ci_named(migration_filesystem *scope, ci_entry *entry, int side, struct stat *identity) {
    int parent = ci_parent(scope, entry, side); if (parent < 0) return -1;
    int valid = fstatat(parent, ci_leaf(entry), identity, AT_SYMLINK_NOFOLLOW) == 0 && ci_match(entry, side, identity) == 0;
    if (migrate_scope_close_fd(scope, &parent) != 0) return -1;
    return valid ? 0 : -1;
}
static napi_value ci_begin_entry(napi_env env, napi_callback_info info) {
    size_t count = 2; napi_value arguments[2]; migration_filesystem *scope = ci_receiver(env, info, &count, arguments); if (!scope) return NULL;
    current_migration_inspection *state = scope->inspection; bool buffer = false; void *input = NULL; size_t size = 0;
    if (count != 1 || ci_legacy_entry(scope) != 0 || !migrate_legacy_locks_ready(scope) || state->entries_sealed ||
        state->count != state->verified || state->count >= state->expected_entries || state->active_fd >= 0 ||
        napi_is_buffer(env, arguments[0], &buffer) != napi_ok || !buffer || napi_get_buffer_info(env, arguments[0], &input, &size) != napi_ok ||
        size < 105 || size > 4200) return migrate_scope_error(env, scope, "current inventory requires one complete original bounded entry");
    const unsigned char *p = input; uint32_t path_size = ci_le32(p + 12); size_t allocation = sizeof(ci_entry) + (size_t)path_size + 1;
    if (memcmp(p, "CLQMI001", 8) || p[8] < 1 || p[8] > 3 || p[9] < 1 || p[9] > 3 || p[10] || p[11] ||
        !path_size || path_size > 4096 || size != 104 + (size_t)path_size || ci_le32(p + 16) > 07777 ||
        ci_le32(p + 20) != (uint32_t)geteuid() || ci_le32(p + 24) != (uint32_t)geteuid() ||
        ci_le64(p + 32) != ci_device(&scope->legacy) || ci_le64(p + 48) != ci_device(&scope->backup) ||
        (p[8] == 2 ? ci_le32(p + 28) != 1 || ci_le64(p + 64) > 9007199254740991ULL : ci_le32(p + 28) || ci_le64(p + 64)) ||
        allocation > MIGRATION_BACKUP_METADATA_BYTES - scope->backup_metadata_bytes)
        return migrate_scope_error(env, scope, "current inventory packet differs from fixed original identities");
    ci_entry *entry = calloc(1, allocation); if (!entry) return migrate_scope_error(env, scope, "current inventory allocation failed");
    entry->path = (char *)(entry + 1); memcpy(entry->path, p + 104, path_size);
    if (strlen(entry->path) != path_size || !utf8_valid((unsigned char *)entry->path) || entry->path[0] == '/' || strchr(entry->path, '\\') ||
        !strcmp(entry->path, "auth.json") || (state->count && strcmp(state->entries[state->count - 1]->path, entry->path) >= 0)) goto rejected;
    size_t components = 0; const char *part = entry->path;
    for (;;) {
        const char *end = strchr(part, '/'); size_t length = end ? (size_t)(end - part) : strlen(part);
        if (!length || length > NAME_MAX || ++components > 64 || (length == 1 && part[0] == '.') ||
            (length == 2 && part[0] == '.' && part[1] == '.')) goto rejected;
        if (!end) break;
        part = end + 1;
    }
    entry->kind = p[8]; entry->purpose = p[9]; entry->mode = ci_le32(p + 16); entry->owner[0] = ci_le32(p + 20); entry->owner[1] = ci_le32(p + 24);
    entry->device[0] = ci_le64(p + 32); entry->inode[0] = ci_le64(p + 40); entry->device[1] = ci_le64(p + 48); entry->inode[1] = ci_le64(p + 56);
    entry->byte_count = ci_le64(p + 64);
    if (entry->kind == 1) for (size_t index = 72; index < 104; ++index) if (p[index]) goto rejected;
    for (size_t index = 0; index < 32; ++index) snprintf(entry->digest + index * 2, 3, "%02x", p[72 + index]);
    if (entry->byte_count > CI_SOURCE_BYTES - state->source_bytes) goto rejected;
    state->source_bytes += entry->byte_count; state->entries[state->count++] = entry; scope->backup_metadata_bytes += allocation;
    state->active_side = 0; state->active_offset = 0; return mp_undefined(env);
rejected:
    free(entry); return migrate_scope_error(env, scope, "current inventory contains an unsafe or unordered original relative path");
}
static int ci_begin_side(migration_filesystem *scope, ci_entry *entry, int side) {
    current_migration_inspection *state = scope->inspection; int parent = ci_parent(scope, entry, side); if (parent < 0) return -1;
    struct stat named; int valid = fstatat(parent, ci_leaf(entry), &named, AT_SYMLINK_NOFOLLOW) == 0 && ci_match(entry, side, &named) == 0;
    if (valid && entry->kind == 3) {
        unsigned char bytes[4097]; ssize_t count = readlinkat(parent, ci_leaf(entry), (char *)bytes, sizeof(bytes)); struct stat after;
        struct sha256_context hash; char digest[65]; sha256_init(&hash);
        if (count < 0 || count > 4096) valid = 0;
        else {
            sha256_update(&hash, bytes, (size_t)count); publication_hash_hex(&hash, digest);
            valid = !strcmp(digest, entry->digest) && fstatat(parent, ci_leaf(entry), &after, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&named, &after);
        }
        if (valid) entry->observed[side] = named;
    } else if (valid) {
        state->active_fd = openat(parent, ci_leaf(entry), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (entry->kind == 1 ? O_DIRECTORY : 0));
        valid = state->active_fd >= 0 && fstat(state->active_fd, &entry->observed[side]) == 0 && source_metadata_same(&named, &entry->observed[side]);
        if (valid && entry->kind == 1) valid = fsync(state->active_fd) == 0 && migrate_scope_close_fd(scope, &state->active_fd) == 0;
        else if (valid) { sha256_init(&state->active_hash); state->active_offset = 0; }
    }
    if (valid && entry->kind != 2) valid = fsync(parent) == 0;
    if (migrate_scope_close_fd(scope, &parent) != 0) return -1;
    return valid ? 0 : -1;
}
static napi_value ci_verify_entry_next(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    current_migration_inspection *state = scope->inspection;
    if (ci_legacy_entry(scope) != 0 || !migrate_legacy_locks_ready(scope) || state->entries_sealed || state->count != state->verified + 1)
        return migrate_scope_error(env, scope, "current inventory has no exact in-progress original entry");
    ci_entry *entry = state->entries[state->verified];
    if (state->active_side < 2) {
        int side = state->active_side;
        if (state->active_fd < 0 && ci_begin_side(scope, entry, side) != 0) goto failed;
        if (entry->kind == 2) {
            struct stat actual, named;
            if (fstat(state->active_fd, &actual) != 0 || !source_metadata_same(&actual, &entry->observed[side]) ||
                ci_named(scope, entry, side, &named) != 0 || !source_metadata_same(&actual, &named)) goto failed;
            unsigned char bytes[65536]; size_t wanted = entry->byte_count - state->active_offset;
            if (wanted > sizeof(bytes)) wanted = sizeof(bytes);
            ssize_t count;
            do { count = pread(state->active_fd, bytes, wanted ? wanted : 1, (off_t)state->active_offset); } while (count < 0 && errno == EINTR);
            if (wanted) {
                if (count <= 0 || (size_t)count > wanted) goto failed;
                sha256_update(&state->active_hash, bytes, (size_t)count); state->active_offset += (size_t)count;
                if (fstat(state->active_fd, &actual) != 0 || !source_metadata_same(&actual, &entry->observed[side])) goto failed;
                napi_value result; return napi_get_boolean(env, false, &result) == napi_ok ? result : NULL;
            }
            char digest[65]; publication_hash_hex(&state->active_hash, digest);
            int parent = ci_parent(scope, entry, side);
            if (count != 0 || strcmp(digest, entry->digest) || parent < 0) { migrate_scope_close_fd(scope, &parent); goto failed; }
            int synced = fsync(state->active_fd) == 0 && fsync(parent) == 0;
            if (migrate_scope_close_fd(scope, &parent) != 0 || migrate_scope_close_fd(scope, &state->active_fd) != 0 || !synced) goto failed;
        }
        state->active_side++;
    }
    if (state->active_side == 2) state->verified++;
    napi_value result; return napi_get_boolean(env, state->active_side == 2, &result) == napi_ok ? result : NULL;
failed:
    return migrate_scope_error(env, scope, "current original source/backup identity, full bytes, fsync or close failed");
}
static napi_value ci_finish_entries(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL; current_migration_inspection *state = scope->inspection;
    if (ci_legacy_entry(scope) != 0 || !migrate_legacy_locks_ready(scope) || state->entries_sealed ||
        state->count != state->expected_entries || state->verified != state->count || state->active_fd >= 0)
        return migrate_scope_error(env, scope, "current original inventory did not reach exact complete EOF");
    state->entries_sealed = 1; return mp_undefined(env);
}
static int ci_protocol_object(migration_filesystem *scope, const char *name, const struct stat *identity, int top) {
    if (S_ISDIR(identity->st_mode) && (same_inode(identity, &scope->binding->owner->root) ||
        migrate_legacy_locks_owns(scope, identity))) return 1;
    if (S_ISREG(identity->st_mode) && same_inode(identity, &scope->binding->gate->file)) return 1;
    if (top) for (size_t index = 0; index < MP_FILES; ++index)
        if (mp_is_named_file(scope, &scope->publication->files[index], name, identity)) return 1;
    return 0;
}
static int ci_push_scan(migration_filesystem *scope, int fd, size_t node) {
    current_migration_inspection *state = scope->inspection;
    if (state->walk_count >= sizeof(state->walk) / sizeof(state->walk[0])) {
        migrate_scope_close_fd(scope, &fd); return -1;
    }
    struct stat before;
    if (fd < 0 || fstat(fd, &before) != 0 || !S_ISDIR(before.st_mode)) {
        migrate_scope_close_fd(scope, &fd); return -1;
    }
    DIR *directory = fdopendir(fd);
    if (!directory) { migrate_scope_close_fd(scope, &fd); return -1; }
    ci_walk *walk = &state->walk[state->walk_count++];
    *walk = (ci_walk){.fd = fd, .directory = directory, .node = node, .before = before};
    return 0;
}
static int ci_scan_root(migration_filesystem *scope, int side) {
    int parent = side ? scope->backup_fd : scope->legacy_fd;
    int fd = openat(parent, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat opened; const struct stat *expected = side ? &scope->backup : &scope->legacy;
    if (fd < 0 || fstat(fd, &opened) != 0 || !ml_same_directory(&opened, expected)) {
        migrate_scope_close_fd(scope, &fd); return -1;
    }
    return ci_push_scan(scope, fd, SIZE_MAX);
}
static napi_value ci_begin_whole_trees(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    current_migration_inspection *state = scope->inspection;
    if (ci_legacy_entry(scope) != 0 || migrate_legacy_locks_assert_current(scope) != 0 || !state->entries_sealed ||
        state->verified != state->expected_entries || state->active_fd >= 0 || state->walk_count ||
        (state->scan_started && !state->trees_complete) || state->scan_epoch == UINT64_MAX)
        return migrate_scope_error(env, scope, "current whole-tree read requires exact original inventory and joined prior reads");
    state->scan_epoch++; state->scan_side = 0; state->scan_seen = 0; state->trees_complete = 0; state->scan_started = 1;
    if (ci_scan_root(scope, 0) != 0) return migrate_scope_error(env, scope, "current source all-and-only scan did not open its actual root");
    return mp_undefined(env);
}
static napi_value ci_verify_whole_trees_next(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    current_migration_inspection *state = scope->inspection;
    if (ci_legacy_entry(scope) != 0 || !migrate_legacy_locks_ready(scope) || !state->scan_started)
        return migrate_scope_error(env, scope, "current whole-tree verification has not actually started");
    if (state->trees_complete) {
        napi_value result; return napi_get_boolean(env, true, &result) == napi_ok ? result : NULL;
    }
    for (size_t step = 0; step < 64; ++step) {
        if (!state->walk_count) {
            if (state->scan_seen != state->expected_entries) goto failed;
            if (state->scan_side == 1) { state->trees_complete = 1; break; }
            state->scan_side = 1; state->scan_seen = 0;
            if (ci_scan_root(scope, 1) != 0) goto failed;
        }
        ci_walk *walk = &state->walk[state->walk_count - 1]; errno = 0;
        struct dirent *member = readdir(walk->directory);
        if (!member) {
            struct stat after;
            if (errno || fstat(walk->fd, &after) != 0 || !source_metadata_same(&walk->before, &after) || fsync(walk->fd) != 0) goto failed;
            DIR *original = walk->directory; walk->directory = NULL; walk->fd = -1; state->walk_count--;
            if (closedir(original) != 0) { migrate_scope_poison(scope); goto failed; }
            continue;
        }
        const char *name = member->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        size_t size = strlen(name);
        if (!size || size > NAME_MAX || strchr(name, '\\') || !utf8_valid((unsigned char *)name)) goto failed;
        struct stat named;
        if (fstatat(walk->fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0) goto failed;
        if (!state->scan_side && ci_protocol_object(scope, name, &named, walk->node == SIZE_MAX)) continue;
        const char *prefix = walk->node == SIZE_MAX ? "" : state->entries[walk->node]->path;
        char path[4097]; size_t prefix_size = strlen(prefix);
        if (prefix_size + (prefix_size ? 1 : 0) + size > 4096) goto failed;
        memcpy(path, prefix, prefix_size);
        if (prefix_size) path[prefix_size++] = '/';
        memcpy(path + prefix_size, name, size + 1);
        size_t found = ci_find(state, path);
        if (found == SIZE_MAX) goto failed;
        ci_entry *entry = state->entries[found]; int side = state->scan_side;
        if (entry->seen[side] == state->scan_epoch || ci_match(entry, side, &named) != 0 ||
            !source_metadata_same(&entry->observed[side], &named)) goto failed;
        entry->seen[side] = state->scan_epoch; state->scan_seen++;
        if (state->scan_seen > state->expected_entries) goto failed;
        if (entry->kind == 1) {
            int fd = openat(walk->fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); struct stat opened;
            if (fd < 0 || fstat(fd, &opened) != 0 || !source_metadata_same(&named, &opened)) {
                migrate_scope_close_fd(scope, &fd); goto failed;
            }
            if (ci_push_scan(scope, fd, found) != 0) goto failed;
        }
    }
    napi_value result; return napi_get_boolean(env, state->trees_complete != 0, &result) == napi_ok ? result : NULL;
failed:
    return migrate_scope_error(env, scope, "current source/backup complete sets, identities or original bytes changed");
}
static napi_value ci_inspect_retained(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    current_migration_inspection *state = scope->inspection;
    if (ci_legacy_entry(scope) != 0 || migrate_legacy_locks_assert_current(scope) != 0 || !state->trees_complete ||
        state->walk_count || state->active_fd >= 0 || state->verified != state->expected_entries)
        return migrate_scope_error(env, scope, "current retained-object observation requires both complete real trees");
    napi_value result, count, size;
    if (napi_create_object(env, &result) != napi_ok ||
        !publication_set_string(env, result, "kind", "retained_original_objects_unchanged") ||
        !publication_set_string(env, result, "sourceAuth", state->auth_absent ? "absent" : "matched_original_marker") ||
        !mp_root_value(env, result, "legacyRoot", scope->legacy_path, &scope->legacy) ||
        napi_create_double(env, (double)state->verified, &count) != napi_ok || napi_set_named_property(env, result, "entryCount", count) != napi_ok ||
        napi_create_double(env, (double)state->source_bytes, &size) != napi_ok || napi_set_named_property(env, result, "byteCount", size) != napi_ok ||
        !decimal_member(env, result, "inspectionEpoch", state->scan_epoch) ||
        napi_object_freeze(env, result) != napi_ok) return NULL;
    return result;
}
