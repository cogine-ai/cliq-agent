/* Complete noncredential backup, in joined <=64KiB physical steps. Only the
 * active bounded directory ancestry and current source/copy FDs remain open.
 * Completed descriptors actually retire; later read-only observations rewalk
 * original identities from continuously held roots and fully rehash bytes.
 * auth.json bytes never enter this copier; their dedicated authority owns them. */
struct migration_backup_node {
    migration_backup_node *parent, *next;
    int source_fd, destination_fd, source_borrowed, destination_borrowed;
    DIR *directory;
    char *name, *path;
    struct stat source, destination;
    int kind, copied, rereading, complete;
    uint64_t offset;
    struct sha256_context hash;
    char digest[65];
    size_t depth;
};
static int migrate_context_source_kind(const char *path);

/* The supported first physical profile has a finite metadata budget and a
 * finite open ancestry. Neither a large host ulimit nor total file count may
 * silently turn into an unbounded descriptor/memory claim. Scale qualification
 * must exercise these exact limits rather than assuming 50GiB implies them. */
#define MIGRATION_BACKUP_METADATA_BYTES (256ULL * 1024ULL * 1024ULL)
#define MIGRATION_BACKUP_DEPTH 64

static int migrate_backup_source_root_stable(migration_filesystem *scope) {
    struct stat held;
    return scope->backup_root && scope->backup_root->complete &&
        fstat(scope->legacy_fd, &held) == 0 && source_metadata_same(&held, &scope->backup_root->source) ? 0 : -1;
}

static int migrate_backup_retire(migration_filesystem *scope) {
    for (migration_backup_node *node = scope->backup_nodes; node; node = node->next) {
        if (node->directory) {
            DIR *original = node->directory; node->directory = NULL;
            if (closedir(original) != 0) { migrate_scope_poison(scope); return -1; }
        }
        if (!node->destination_borrowed && migrate_scope_close_fd(scope, &node->destination_fd) != 0) return -1;
        if (!node->source_borrowed && migrate_scope_close_fd(scope, &node->source_fd) != 0) return -1;
    }
    return 0;
}
static void migrate_backup_free(migration_filesystem *scope) {
    free(scope->context_index);
    migration_backup_node *node = scope->backup_nodes;
    while (node) { migration_backup_node *next = node->next; free(node->name); free(node->path); free(node); node = next; }
}
static int migrate_backup_source_held(migration_filesystem *scope, migration_backup_node *node) {
    if (migrate_scope_check(scope, scope->env) != 0) return -1;
    for (migration_backup_node *current = node; current; current = current->parent) {
        struct stat named, held;
        if (current->parent && (fstatat(current->parent->source_fd, current->name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            !source_metadata_same(&named, &current->source))) return -1;
        if (current->kind != 3 && (current->source_fd < 0 || fstat(current->source_fd, &held) != 0 ||
            !source_metadata_same(&held, &current->source))) return -1;
    }
    return 0;
}
static int migrate_backup_destination_held(migration_filesystem *scope, migration_backup_node *node) {
    if (migrate_scope_check(scope, scope->env) != 0) return -1;
    for (migration_backup_node *current = node; current; current = current->parent) {
        struct stat held, named;
        if (current->kind == 3) {
            if (!current->parent || fstatat(current->parent->destination_fd, current->name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
                !source_metadata_same(&named, &current->destination)) return -1;
            continue;
        }
        if (current->destination_fd < 0 || fstat(current->destination_fd, &held) != 0 ||
            !same_inode(&held, &current->destination) || held.st_uid != geteuid() ||
            held.st_dev != scope->backup.st_dev || held.st_nlink < 1) return -1;
        mode_t expected_mode = current->kind == 1 ? (current->complete && current->parent ? 0500 : 0700) :
            current->rereading || current->complete ? 0400 : 0600;
        if ((held.st_mode & 07777) != expected_mode ||
            (current->kind == 1 ? !S_ISDIR(held.st_mode) : !S_ISREG(held.st_mode) || held.st_nlink != 1)) return -1;
        if (current->parent && (fstatat(current->parent->destination_fd, current->name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_inode(&held, &named) || held.st_mode != named.st_mode || held.st_uid != named.st_uid)) return -1;
        if (current->complete && current->kind == 2 && !source_metadata_same(&held, &current->destination)) return -1;
    }
    return 0;
}
static migration_backup_node *migrate_backup_allocate(migration_filesystem *scope, migration_backup_node *parent,
                                                       const char *name, const struct stat *source) {
    migration_backup_node *node = calloc(1, sizeof(*node));
    if (!node) return NULL;
    node->source_fd = node->destination_fd = -1; node->parent = parent; node->source = *source;
    node->name = strdup(name);
    size_t prefix = parent ? strlen(parent->path) : 0, length = strlen(name);
    uint64_t allocation = sizeof(*node) + length + 1 + prefix + (prefix ? 1 : 0) + length + 1;
    node->depth = parent ? parent->depth + 1 : 0;
    if (node->depth > MIGRATION_BACKUP_DEPTH || prefix + (prefix ? 1 : 0) + length > 4096 ||
        allocation > MIGRATION_BACKUP_METADATA_BYTES - scope->backup_metadata_bytes) goto failed;
    node->path = malloc(prefix + (prefix ? 1 : 0) + length + 1);
    if (!node->name || !node->path) goto failed;
    if (prefix) { memcpy(node->path, parent->path, prefix); node->path[prefix++] = '/'; }
    memcpy(node->path + prefix, name, length + 1);
    node->kind = S_ISDIR(source->st_mode) ? 1 : S_ISREG(source->st_mode) ? 2 : S_ISLNK(source->st_mode) ? 3 : 0;
    node->next = scope->backup_nodes; scope->backup_nodes = node;
    scope->backup_metadata_bytes += allocation;
    return node;
failed:
    free(node->name); free(node->path); free(node); return NULL;
}
static int migrate_backup_open_directory(migration_filesystem *scope, migration_backup_node *node) {
    int enumeration = fcntl(node->source_fd, F_DUPFD_CLOEXEC, 3);
    if (enumeration < 0) return -1;
    node->directory = fdopendir(enumeration);
    if (!node->directory) { migrate_scope_close_fd(scope, &enumeration); return -1; }
    return 0;
}
static napi_value migrate_backup_progress(napi_env env) {
    napi_value result; return napi_get_boolean(env, false, &result) == napi_ok ? result : NULL;
}
static napi_value migrate_backup_entry(napi_env env, migration_backup_node *node) {
    napi_value result, kind, text, mode, count, purpose;
    const char *label = node->kind == 1 ? "directory" : node->kind == 2 ? "regular_file" : "unfollowed_link_metadata";
    int source_kind = node->kind == 2 ? migrate_context_source_kind(node->path) : 0;
    const char *source_purpose = source_kind > 5 || source_kind == 4 ? "validation_only" : source_kind ? "portable_context" : "backup_only";
    if (napi_create_object(env, &result) != napi_ok ||
        napi_create_string_utf8(env, node->path, NAPI_AUTO_LENGTH, &text) != napi_ok ||
        napi_set_named_property(env, result, "canonicalRootRelativePath", text) != napi_ok ||
        napi_create_string_utf8(env, label, NAPI_AUTO_LENGTH, &kind) != napi_ok || napi_set_named_property(env, result, "kind", kind) != napi_ok ||
        napi_create_string_utf8(env, source_purpose, NAPI_AUTO_LENGTH, &purpose) != napi_ok || napi_set_named_property(env, result, "purpose", purpose) != napi_ok ||
        !identity_member(env, result, "sourceIdentity", &node->source) ||
        !identity_member(env, result, "backupIdentity", &node->destination) ||
        napi_create_uint32(env, node->source.st_mode & 07777, &mode) != napi_ok || napi_set_named_property(env, result, "mode", mode) != napi_ok) return NULL;
    if (node->kind != 1 && (napi_create_string_utf8(env, node->digest, 64, &text) != napi_ok ||
        napi_set_named_property(env, result, node->kind == 2 ? "contentDigest" : "linkTextDigest", text) != napi_ok)) return NULL;
    if (node->kind == 2 && (napi_create_double(env, (double)node->source.st_size, &count) != napi_ok ||
        napi_set_named_property(env, result, "byteCount", count) != napi_ok ||
        napi_create_uint32(env, 1, &count) != napi_ok || napi_set_named_property(env, result, "linkCount", count) != napi_ok)) return NULL;
    return napi_object_freeze(env, result) == napi_ok ? result : NULL;
}
static int migrate_backup_begin(migration_filesystem *scope) {
    struct stat source;
    if (fstat(scope->legacy_fd, &source) != 0) return -1;
    migration_backup_node *root = migrate_backup_allocate(scope, NULL, "", &source);
    if (!root) return -1;
    root->source_fd = scope->legacy_fd; root->source_borrowed = 1;
    root->destination_fd = scope->backup_fd; root->destination_borrowed = 1;
    root->destination = scope->backup;
    if (migrate_backup_open_directory(scope, root) != 0) return -1;
    scope->backup_root = scope->backup_stack = root; scope->backup_started = 1;
    return 0;
}
static napi_value migrate_backup_copy_file(napi_env env, migration_filesystem *scope, migration_backup_node *node) {
    if (migrate_backup_source_held(scope, node) != 0 || migrate_backup_destination_held(scope, node) != 0)
        return migrate_scope_error(env, scope, "backup source or destination identity changed");
    unsigned char bytes[65536]; ssize_t size;
    int descriptor = node->rereading ? node->destination_fd : node->source_fd;
    do { size = pread(descriptor, bytes, sizeof(bytes), (off_t)node->offset); } while (size < 0 && errno == EINTR);
    if (size < 0 || node->offset > (uint64_t)node->source.st_size ||
        (uint64_t)size > (uint64_t)node->source.st_size - node->offset)
        return migrate_scope_error(env, scope, "backup bounded read differs from complete original file");
    if (size) {
        sha256_update(&node->hash, bytes, (size_t)size);
        if (!node->rereading) {
            size_t written = 0;
            while (written < (size_t)size) {
                ssize_t count = pwrite(node->destination_fd, bytes + written, (size_t)size - written, (off_t)(node->offset + written));
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) return migrate_scope_error(env, scope, "backup complete copy write failed");
                written += (size_t)count;
            }
        }
        node->offset += (uint64_t)size;
        return migrate_backup_progress(env);
    }
    if (node->offset != (uint64_t)node->source.st_size || migrate_backup_source_held(scope, node) != 0)
        return migrate_scope_error(env, scope, "backup source file became incomplete");
    char digest[65]; publication_hash_hex(&node->hash, digest);
    if (node->rereading) {
        struct stat held;
        if (strcmp(digest, node->digest) != 0 || fstat(node->destination_fd, &held) != 0 ||
            held.st_size != node->source.st_size || migrate_backup_destination_held(scope, node) != 0)
            return migrate_scope_error(env, scope, "backup complete reread differs from original copied bytes");
        node->destination = held; node->complete = 1; scope->backup_active = NULL;
        if (migrate_scope_close_fd(scope, &node->source_fd) != 0 || migrate_scope_close_fd(scope, &node->destination_fd) != 0)
            return migrate_scope_error(env, scope, "backup completed file descriptors did not retire");
        return migrate_backup_entry(env, node);
    }
    if (fsync(node->destination_fd) != 0 || fchmod(node->destination_fd, 0400) != 0 ||
        fsync(node->destination_fd) != 0 || fsync(node->parent->destination_fd) != 0)
        return migrate_scope_error(env, scope, "backup copied file did not durably seal");
    struct stat original, readonly_identity;
    if (fstat(node->destination_fd, &original) != 0) return migrate_scope_error(env, scope, "backup copied identity unavailable");
    int readonly = openat(node->parent->destination_fd, node->name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (readonly < 0 || fstat(readonly, &readonly_identity) != 0 || !source_metadata_same(&original, &readonly_identity)) {
        if (migrate_scope_close_fd(scope, &readonly) != 0) return migrate_scope_error(env, scope, "backup readonly close failed");
        return migrate_scope_error(env, scope, "backup readonly file differs from original copy");
    }
    if (migrate_scope_close_fd(scope, &node->destination_fd) != 0) { node->destination_fd = readonly; return migrate_scope_error(env, scope, "backup writable copy did not retire"); }
    node->destination_fd = readonly; node->destination = readonly_identity;
    memcpy(node->digest, digest, sizeof(node->digest)); node->rereading = 1; node->offset = 0; sha256_init(&node->hash);
    return migrate_backup_progress(env);
}
static napi_value migrate_backup_next(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info);
    if (!scope) return NULL;
    if (!migrate_publication_allows_backup(scope))
        return migrate_scope_error(env, scope, "backup requires its original complete stop spine and private auth observation");
    if (scope->failed || migrate_scope_check(scope, env) != 0 || scope->backup_complete)
        return migrate_scope_error(env, scope, "backup scope is unavailable or already complete");
    if (!scope->backup_started && migrate_backup_begin(scope) != 0)
        return migrate_scope_error(env, scope, "backup initial directory could not be held");
    if (scope->backup_active) return migrate_backup_copy_file(env, scope, scope->backup_active);
    migration_backup_node *parent = scope->backup_stack;
    if (!parent || !parent->directory || migrate_backup_source_held(scope, parent) != 0 || migrate_backup_destination_held(scope, parent) != 0)
        return migrate_scope_error(env, scope, "backup complete directory identity changed");
    errno = 0; struct dirent *entry = readdir(parent->directory);
    if (!entry) {
        if (errno || migrate_backup_source_held(scope, parent) != 0 || fsync(parent->destination_fd) != 0)
            return migrate_scope_error(env, scope, "backup directory did not completely enumerate and sync");
        DIR *original = parent->directory; parent->directory = NULL;
        if (closedir(original) != 0) { migrate_scope_poison(scope); return migrate_scope_error(env, scope, "backup enumeration did not retire"); }
        if (parent->parent && (fchmod(parent->destination_fd, 0500) != 0 || fsync(parent->destination_fd) != 0 ||
            fsync(parent->parent->destination_fd) != 0)) return migrate_scope_error(env, scope, "backup directory did not durably seal");
        if (fstat(parent->destination_fd, &parent->destination) != 0) return migrate_scope_error(env, scope, "backup final directory identity unavailable");
        parent->complete = 1; scope->backup_stack = parent->parent;
        if (parent->parent && (migrate_scope_close_fd(scope, &parent->source_fd) != 0 ||
            migrate_scope_close_fd(scope, &parent->destination_fd) != 0))
            return migrate_scope_error(env, scope, "backup completed directory descriptors did not retire");
        if (parent->parent) return migrate_backup_entry(env, parent);
        scope->backup_complete = 1;
        napi_value result; return napi_get_null(env, &result) == napi_ok ? result : NULL;
    }
    const char *name = entry->d_name;
    if (!strcmp(name, ".") || !strcmp(name, "..")) return migrate_backup_progress(env);
    size_t length = strlen(name);
    if (!length || length > NAME_MAX || strchr(name, '\\') || !utf8_valid((unsigned char *)name))
        return migrate_scope_error(env, scope, "backup entry name is not a canonical bounded UTF-8 component");
    /* Only the dedicated source auth contract may read this entry's bytes. */
    if (!parent->parent && !strcmp(name, "auth.json")) return migrate_backup_progress(env);
    struct stat source;
    if (fstatat(parent->source_fd, name, &source, AT_SYMLINK_NOFOLLOW) != 0)
        return migrate_scope_error(env, scope, "backup source metadata is unavailable");
    if (S_ISDIR(source.st_mode) && (same_inode(&source, &scope->binding->owner->root) ||
        migrate_legacy_locks_owns(scope, &source))) return migrate_backup_progress(env);
    /* The actual currently held cooperation gate is protocol custody, not
     * Legacy data. Copying/restoring its pathname would replace the live flock
     * inode. Skip only that genuine same-image gate inode, never a basename. */
    if (S_ISREG(source.st_mode) && same_inode(&source, &scope->binding->gate->file)) return migrate_backup_progress(env);
    /* Only this scope's genuine named stop-copy inode is protocol metadata.
     * A matching basename or arbitrary foreign file is never an exclusion. */
    if (!parent->parent && migrate_publication_owns_rendezvous(scope, &source)) return migrate_backup_progress(env);
    if (source.st_uid != geteuid() || source.st_dev != scope->legacy.st_dev ||
        (!S_ISDIR(source.st_mode) && !S_ISREG(source.st_mode) && !S_ISLNK(source.st_mode)) ||
        (S_ISREG(source.st_mode) && (source.st_nlink != 1 || source.st_size < 0 || (uint64_t)source.st_size > 9007199254740991ULL)) ||
        scope->backup_entry_count == 9007199254740991ULL)
        return migrate_scope_error(env, scope, "backup source has unsupported ownership, device, type or hardlink");
    migration_backup_node *node = migrate_backup_allocate(scope, parent, name, &source);
    if (!node) return migrate_scope_error(env, scope, "backup entry allocation or relative path bound failed");
    if (node->kind != 2 && migrate_context_source_kind(node->path))
        return migrate_scope_error(env, scope, "recognized legacy context source is not a regular single-link file");
    if (!parent->parent && node->kind != 1 && (!strcmp(name, "sessions") || !strcmp(name, "plans") ||
        !strcmp(name, "handoffs") || !strcmp(name, "tx") || !strcmp(name, "checkpoints") || !strcmp(name, "workspaces")))
        return migrate_scope_error(env, scope, "recognized legacy state root is not a no-follow directory");
    scope->backup_entry_count++;
    if (node->kind == 3) {
        char target[4097]; ssize_t size = readlinkat(parent->source_fd, name, target, sizeof(target) - 1);
        if (size < 1 || (size_t)size >= sizeof(target) - 1) return migrate_scope_error(env, scope, "backup link metadata is not bounded");
        target[size] = '\0';
        if (strlen(target) != (size_t)size || !utf8_valid((unsigned char *)target) || migrate_backup_source_held(scope, node) != 0 ||
            symlinkat(target, parent->destination_fd, name) != 0 || fsync(parent->destination_fd) != 0 ||
            fstatat(parent->destination_fd, name, &node->destination, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISLNK(node->destination.st_mode) || node->destination.st_uid != geteuid())
            return migrate_scope_error(env, scope, "backup link metadata did not copy without following");
        struct sha256_context hash; sha256_init(&hash); sha256_update(&hash, (unsigned char *)target, (size_t)size); publication_hash_hex(&hash, node->digest);
        char observed[4097]; ssize_t copied = readlinkat(parent->destination_fd, name, observed, sizeof(observed) - 1);
        if (copied != size || memcmp(observed, target, (size_t)size) != 0 || migrate_backup_destination_held(scope, node) != 0)
            return migrate_scope_error(env, scope, "backup complete link metadata reread differs");
        node->complete = 1; return migrate_backup_entry(env, node);
    }
    node->source_fd = openat(parent->source_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (node->kind == 1 ? O_DIRECTORY : 0));
    struct stat held;
    if (node->source_fd < 0 || fstat(node->source_fd, &held) != 0 || !source_metadata_same(&held, &source))
        return migrate_scope_error(env, scope, "backup source opened a different object");
    if (node->kind == 1) {
        if (mkdirat(parent->destination_fd, name, 0700) != 0 ||
            (node->destination_fd = openat(parent->destination_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0 ||
            fstat(node->destination_fd, &node->destination) != 0 || !private_directory(&node->destination) ||
            migrate_backup_open_directory(scope, node) != 0)
            return migrate_scope_error(env, scope, "backup directory birth failed");
        scope->backup_stack = node; return migrate_backup_progress(env);
    }
    if ((uint64_t)source.st_size > 9007199254740991ULL - scope->backup_byte_count)
        return migrate_scope_error(env, scope, "backup total byte count exceeds safe integer range");
    scope->backup_byte_count += (uint64_t)source.st_size;
    node->destination_fd = openat(parent->destination_fd, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (node->destination_fd < 0 || fstat(node->destination_fd, &node->destination) != 0 || !private_lock_file(&node->destination))
        return migrate_scope_error(env, scope, "backup file birth failed");
    sha256_init(&node->hash); node->offset = 0; scope->backup_active = node;
    return migrate_backup_progress(env);
}

static int migrate_context_safe_id(const char *value) {
    size_t length = strlen(value);
    return length && length <= 128 && strspn(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") == length;
}
static int migrate_context_source_kind(const char *path) {
    if (!strcmp(path, "workspace-index.json") || !strcmp(path, "state.json")) return 6;
    char copy[4097]; size_t length = strlen(path);
    if (length > 4096) return 0;
    memcpy(copy, path, length + 1);
    char *parts[6], *cursor = copy; size_t count = 0;
    for (;;) {
        if (count == sizeof(parts) / sizeof(parts[0])) return 0;
        parts[count++] = cursor;
        char *next = strchr(cursor, '/'); if (!next) break;
        *next = '\0'; cursor = next + 1;
    }
    if (count == 5 && !strcmp(parts[0], "sessions") && strlen(parts[1]) == 4 &&
        strspn(parts[1], "0123456789") == 4 && strlen(parts[2]) == 2 && strspn(parts[2], "0123456789") == 2 &&
        strlen(parts[3]) == 2 && strspn(parts[3], "0123456789") == 2) {
        size_t file_length = strlen(parts[4]);
        if (file_length > 5 && !strcmp(parts[4] + file_length - 5, ".json")) {
            parts[4][file_length - 5] = '\0'; if (migrate_context_safe_id(parts[4])) return 1;
        }
    }
    if (count == 5 && !strcmp(parts[0], "plans") && migrate_context_safe_id(parts[1]) &&
        migrate_context_safe_id(parts[2]) && migrate_context_safe_id(parts[3])) {
        if (!strcmp(parts[4], "plan.json")) return 2;
        if (!strcmp(parts[4], "plan.md")) return 3;
        if (!strcmp(parts[4], "progress.json")) return 4;
    }
    if (count == 3 && !strcmp(parts[0], "handoffs") && migrate_context_safe_id(parts[1]) &&
        !strcmp(parts[2], "handoff.json")) return 5;
    if (count == 3 && !strcmp(parts[0], "workspaces") && migrate_context_safe_id(parts[1]) &&
        !strcmp(parts[2], "state.json")) return 7;
    if (count == 3 && !strcmp(parts[0], "tx") && migrate_context_safe_id(parts[1]) &&
        (!strcmp(parts[2], "state.json") || !strcmp(parts[2], "apply-progress.json") ||
         !strcmp(parts[2], "abort-progress.json") || !strcmp(parts[2], "recovery.json"))) return 8;
    return 0;
}

/* Fixed producer order, independent of directory encounter order. Validation
 * precedes portable content; a plan's actual Markdown is delivered immediately
 * before its JSON/progress, so the producer holds at most one bounded plan.
 * This index consumes the same whole-operation metadata budget as the capture;
 * it never keeps one source FD or full body per entry. */
static int migrate_context_compare(const void *left, const void *right) {
    const migration_backup_node *a = *(migration_backup_node *const *)left;
    const migration_backup_node *b = *(migration_backup_node *const *)right;
    int a_kind = migrate_context_source_kind(a->path), b_kind = migrate_context_source_kind(b->path);
    int a_family = a_kind > 5 ? 0 : a_kind == 1 ? 1 : a_kind == 5 ? 3 : 2;
    int b_family = b_kind > 5 ? 0 : b_kind == 1 ? 1 : b_kind == 5 ? 3 : 2;
    if (a_family != b_family) return a_family < b_family ? -1 : 1;
    if (a_family == 2 || (a_kind == 8 && b_kind == 8)) {
        const char *a_leaf = strrchr(a->path, '/'), *b_leaf = strrchr(b->path, '/');
        size_t a_size = (size_t)(a_leaf - a->path), b_size = (size_t)(b_leaf - b->path);
        size_t shared = a_size < b_size ? a_size : b_size;
        int prefix = memcmp(a->path, b->path, shared);
        if (prefix) return prefix;
        if (a_size != b_size) return a_size < b_size ? -1 : 1;
        int a_order = a_family == 2 ? (a_kind == 3 ? 0 : a_kind == 2 ? 1 : 2) :
            !strcmp(a_leaf, "/state.json") ? 0 : !strcmp(a_leaf, "/apply-progress.json") ? 1 :
            !strcmp(a_leaf, "/abort-progress.json") ? 2 : 3;
        int b_order = b_family == 2 ? (b_kind == 3 ? 0 : b_kind == 2 ? 1 : 2) :
            !strcmp(b_leaf, "/state.json") ? 0 : !strcmp(b_leaf, "/apply-progress.json") ? 1 :
            !strcmp(b_leaf, "/abort-progress.json") ? 2 : 3;
        if (a_order != b_order) return a_order < b_order ? -1 : 1;
    }
    return strcmp(a->path, b->path);
}
static int migrate_context_build_index(migration_filesystem *scope) {
    size_t count = 0;
    for (migration_backup_node *node = scope->backup_nodes; node; node = node->next) {
        if (node->kind != 2 || !migrate_context_source_kind(node->path)) continue;
        if (!node->complete || count == SIZE_MAX) return -1;
        count++;
    }
    if (count > (MIGRATION_BACKUP_METADATA_BYTES - scope->backup_metadata_bytes) / sizeof(*scope->context_index)) return -1;
    if (count) {
        scope->context_index = malloc(count * sizeof(*scope->context_index));
        if (!scope->context_index) return -1;
        size_t offset = 0;
        for (migration_backup_node *node = scope->backup_nodes; node; node = node->next)
            if (node->kind == 2 && migrate_context_source_kind(node->path)) scope->context_index[offset++] = node;
        qsort(scope->context_index, count, sizeof(*scope->context_index), migrate_context_compare);
        scope->backup_metadata_bytes += count * sizeof(*scope->context_index);
    }
    scope->context_count = count; scope->context_started = 1;
    return 0;
}
/* Exactly two data passes: complete source/controls preflight, then projection
 * over the same retained backup and all original identities. The native EOF/
 * hash/close of every source is required before either boundary. No caller can
 * restart a partial reader or reset this operation's metadata/byte accounting. */
static napi_value migrate_context_begin_projection(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info);
    if (!scope) return NULL;
    if (scope->failed || migrate_scope_check(scope, env) != 0 || !scope->backup_complete || migrate_backup_source_root_stable(scope) != 0 || !scope->context_exhausted ||
        scope->context_active || scope->children || scope->context_projection_started || !scope->candidate_created || scope->candidate_sealing)
        return migrate_scope_error(env, scope, "projection requires the complete joined original preflight and its new candidate");
    scope->context_projection_started = 1; scope->context_index_offset = 0; scope->context_exhausted = 0;
    napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}

/* Read-only re-observation, never old FD/creator or deletion authority. Every
 * component must match the original in-memory capture through the continuously
 * held original roots; a pathname or equal bytes alone cannot select an entry. */
static int migrate_backup_reopen(migration_filesystem *scope, migration_backup_node *node, int backup) {
    migration_backup_node *chain[MIGRATION_BACKUP_DEPTH + 1]; size_t depth = 0;
    for (migration_backup_node *current = node; current && current->parent; current = current->parent) {
        if (depth == sizeof(chain) / sizeof(chain[0])) return -1;
        chain[depth++] = current;
    }
    if (migrate_scope_check(scope, scope->env) != 0) return -1;
    int current = fcntl(backup ? scope->backup_fd : scope->legacy_fd, F_DUPFD_CLOEXEC, 3);
    if (current < 0) return -1;
    for (size_t index = depth; index > 0; --index) {
        migration_backup_node *entry = chain[index - 1];
        const struct stat *expected = backup ? &entry->destination : &entry->source;
        struct stat named, held;
        if (entry->kind == 3 || fstatat(current, entry->name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            !source_metadata_same(&named, expected)) goto failed;
        int next = openat(current, entry->name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (entry->kind == 1 ? O_DIRECTORY : 0));
        if (next < 0) goto failed;
        int valid = fstat(next, &held) == 0 && source_metadata_same(&held, expected) &&
            fstatat(current, entry->name, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&held, &named);
        if (migrate_scope_close_fd(scope, &current) != 0) {
            /* Keep actual next custody on failed prior close; no numeric reuse
             * is closed a second time. The poisoned process retains this FD. */
            scope->retained_observation_fd = next;
            return -1;
        }
        current = next;
        if (!valid) goto failed;
    }
    if (migrate_scope_check(scope, scope->env) == 0) return current;
failed:
    migrate_scope_close_fd(scope, &current);
    return -1;
}
/* One bounded original-identity observation per step, over the complete
 * captured namespace (including backup-only files and every directory), never
 * just the latest context body. Reopened FDs are read-only current observations,
 * not old creator/deletion proof. Supported writers are independently stopped
 * by the genuine account/legacy cooperation gates; these stats cannot promise
 * that an uncooperative future process will never write. */
static napi_value migrate_backup_verify_source_next(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info);
    if (!scope) return NULL;
    int final = scope->candidate_created != 0;
    if (scope->failed || migrate_scope_check(scope, env) != 0 || !scope->backup_complete || !scope->context_exhausted ||
        migrate_backup_source_root_stable(scope) != 0 || scope->context_active || scope->children || scope->candidate_sealing ||
        (final ? scope->source_verified_for_seal || (scope->context_count && !scope->context_projection_started) :
          scope->source_verified_before_candidate || scope->context_projection_started))
        return migrate_scope_error(env, scope, "source revalidation requires its exact original joined data boundary");
    if (!scope->backup_verify_running) { scope->backup_verify_next = scope->backup_nodes; scope->backup_verify_running = 1; }
    migration_backup_node *node = scope->backup_verify_next;
    if (node) {
        scope->backup_verify_next = node->next;
        if (!node->complete) return migrate_scope_error(env, scope, "source inventory contains an incomplete original entry");
        if (node->kind == 3) {
            int parent = migrate_backup_reopen(scope, node->parent, 0);
            if (parent < 0) return migrate_scope_error(env, scope, "source link parent no longer matches the original capture");
            struct stat before, after; char text[PATH_MAX + 1], digest[65];
            int valid = fstatat(parent, node->name, &before, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&before, &node->source);
            ssize_t length = valid ? readlinkat(parent, node->name, text, sizeof(text)) : -1;
            if (length < 0 || (size_t)length >= sizeof(text)) valid = 0;
            else { struct sha256_context hash; sha256_init(&hash); sha256_update(&hash, (const uint8_t *)text, (size_t)length); publication_hash_hex(&hash, digest);
                if (strcmp(digest, node->digest) != 0 || fstatat(parent, node->name, &after, AT_SYMLINK_NOFOLLOW) != 0 ||
                    !source_metadata_same(&after, &node->source)) valid = 0; }
            if (migrate_scope_close_fd(scope, &parent) != 0) return migrate_scope_error(env, scope, "source observation descriptor did not retire");
            if (!valid) return migrate_scope_error(env, scope, "source link changed after its complete copied metadata");
        } else {
            int observed = migrate_backup_reopen(scope, node, 0);
            if (observed < 0) return migrate_scope_error(env, scope, "complete original source metadata changed after backup");
            if (migrate_scope_close_fd(scope, &observed) != 0) return migrate_scope_error(env, scope, "source observation descriptor did not retire");
        }
        napi_value result; return napi_get_boolean(env, false, &result) == napi_ok ? result : NULL;
    }
    if (migrate_backup_source_root_stable(scope) != 0) return migrate_scope_error(env, scope, "source root changed at its complete verification boundary");
    scope->backup_verify_running = 0;
    if (final) scope->source_verified_for_seal = 1; else scope->source_verified_before_candidate = 1;
    napi_value result; return napi_get_boolean(env, true, &result) == napi_ok ? result : NULL;
}
static int migrate_context_held(migration_filesystem *scope, migration_backup_node *node) {
    struct stat observed;
    if (scope->context_fd < 0 || migrate_scope_check(scope, scope->env) != 0 ||
        fstat(scope->context_fd, &observed) != 0 || !source_metadata_same(&observed, &node->destination)) return -1;
    int source = migrate_backup_reopen(scope, node, 0);
    if (source < 0) return -1;
    return migrate_scope_close_fd(scope, &source);
}
static napi_value migrate_context_next(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info);
    if (!scope) return NULL;
    if (scope->failed || migrate_scope_check(scope, env) != 0 || !scope->backup_complete ||
        migrate_backup_source_root_stable(scope) != 0 || scope->context_active)
        return migrate_scope_error(env, scope, "context sources require the original complete backup and joined prior reader");
    if (!scope->context_started && migrate_context_build_index(scope) != 0)
        return migrate_scope_error(env, scope, "context source index exceeded the original complete metadata budget");
    migration_backup_node *selected = scope->context_index_offset < scope->context_count ?
        scope->context_index[scope->context_index_offset++] : NULL;
    if (!selected) { scope->context_exhausted = 1; napi_value result; return napi_get_null(env, &result) == napi_ok ? result : NULL; }
    if (scope->children == UINT64_MAX || (scope->context_fd = migrate_backup_reopen(scope, selected, 1)) < 0 ||
        migrate_context_held(scope, selected) != 0)
        return migrate_scope_error(env, scope, "context source is not its unchanged original verified backup object");
    scope->context_active = selected; scope->context_offset = 0; scope->context_complete = 0;
    scope->children++; sha256_init(&scope->context_hash);
    return migrate_backup_entry(env, selected);
}
static napi_value migrate_context_chunk(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info);
    if (!scope) return NULL;
    migration_backup_node *node = scope->context_active;
    if (scope->failed || !node || scope->context_complete || migrate_backup_source_root_stable(scope) != 0 || migrate_context_held(scope, node) != 0)
        return migrate_scope_error(env, scope, "context source reader changed or is unavailable");
    if (scope->context_offset == (uint64_t)node->source.st_size) {
        char digest[65]; publication_hash_hex(&scope->context_hash, digest);
        if (strcmp(digest, node->digest) != 0) return migrate_scope_error(env, scope, "complete context source hash differs");
        scope->context_complete = 1;
        napi_value result; return napi_get_null(env, &result) == napi_ok ? result : NULL;
    }
    uint64_t remaining = (uint64_t)node->source.st_size - scope->context_offset;
    size_t size = remaining > 65536 ? 65536 : (size_t)remaining, consumed = 0;
    if (scope->context_total_read_bytes > 2 * scope->backup_byte_count ||
        (uint64_t)size > 2 * scope->backup_byte_count - scope->context_total_read_bytes)
        return migrate_scope_error(env, scope, "context reads exceeded their fixed original two-pass byte accounting");
    napi_value result; void *bytes;
    if (napi_create_buffer(env, size, &bytes, &result) != napi_ok) return NULL;
    while (consumed < size) {
        ssize_t count = pread(scope->context_fd, (unsigned char *)bytes + consumed, size - consumed,
            (off_t)(scope->context_offset + consumed));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return migrate_scope_error(env, scope, "context source became incomplete during bounded read");
        consumed += (size_t)count;
    }
    sha256_update(&scope->context_hash, bytes, size); scope->context_offset += size;
    scope->context_total_read_bytes += size;
    if (migrate_context_held(scope, node) != 0)
        return migrate_scope_error(env, scope, "context source identity changed during read");
    return result;
}
static napi_value migrate_context_close(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info);
    if (!scope) return NULL;
    /* Cancellation may discard partial context. It neither authenticates those
     * bytes nor discards an actual OS descriptor: both originals remain owned
     * by the backup scope until its real complete retirement. */
    if (!scope->context_active || !scope->children || migrate_scope_check(scope, env) != 0)
        return migrate_scope_error(env, scope, "context source has no original reader to join");
    if (migrate_scope_close_fd(scope, &scope->context_fd) != 0)
        return migrate_scope_error(env, scope, "context current observation descriptor did not retire");
    if (!scope->context_complete) scope->failed = 1;
    scope->context_active = NULL; scope->children--;
    napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
