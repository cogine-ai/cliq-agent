/* One original-owner migration package. No arbitrary destination, FD, mode or
 * SQL is accepted. Included after the actual account/credential gate. */
#include "migration-candidate-borrow.h"
#include "migration-legacy-locks.h"
typedef struct migration_backup_node migration_backup_node;
typedef struct migration_publication_state migration_publication_state;
static int migrate_backup_retire(migration_filesystem *scope);
static void migrate_backup_free(migration_filesystem *scope);
static napi_value migrate_backup_next(napi_env env, napi_callback_info info);
static napi_value migrate_context_next(napi_env env, napi_callback_info info);
static napi_value migrate_context_chunk(napi_env env, napi_callback_info info);
static napi_value migrate_context_close(napi_env env, napi_callback_info info);
static napi_value migrate_context_begin_projection(napi_env env, napi_callback_info info);
static int migrate_backup_source_root_stable(migration_filesystem *scope);
static napi_value migrate_backup_verify_source_next(napi_env env, napi_callback_info info);
static int migrate_publication_custody(migration_filesystem *scope);
static int migrate_publication_validate(migration_filesystem *scope);
static int migrate_publication_retire(migration_filesystem *scope);
static void migrate_publication_free(migration_filesystem *scope);
static int migrate_publication_owns_rendezvous(migration_filesystem *scope, const struct stat *observed);
static int migrate_publication_allows_backup(migration_filesystem *scope);
static napi_value migrate_publication_roots(napi_env env, napi_callback_info info);
static napi_value migrate_publication_initial(napi_env env, napi_callback_info info);
static napi_value migrate_publication_control(napi_env env, napi_callback_info info);
static napi_value migrate_publication_auth_observation(napi_env env, napi_callback_info info);
static napi_value migrate_publication_auth_marker(napi_env env, napi_callback_info info);
static napi_value migrate_publication_authority(napi_env env, napi_callback_info info);
static napi_value migrate_publication_read_control(napi_env env, napi_callback_info info);
static napi_value migrate_publication_read_preparation(napi_env env, napi_callback_info info);
static napi_value migrate_publication_read_rendezvous(napi_env env, napi_callback_info info);
static napi_value migrate_publication_assert_credential_cutover(napi_env env, napi_callback_info info);
static napi_value migrate_publication_inventory_page(napi_env env, napi_callback_info info);

typedef struct current_migration_inspection current_migration_inspection;
static int ci_custody(migration_filesystem *scope);
static int ci_retire(migration_filesystem *scope);
static void ci_free(migration_filesystem *scope);
static int ci_legacy_entry(migration_filesystem *scope);

struct migration_filesystem {
    migration_credential_gate *binding;
    napi_ref binding_ref;
    napi_env env;
    int legacy_fd, migration_fd, collection_fd, package_fd;
    int backup_fd, candidate_dir_fd, archive_fd, candidate_fd;
    struct stat legacy, migration, collection, package;
    struct stat backup, candidate_dir, archive, candidate;
    char migration_id[44], legacy_path[PATH_MAX];
    char legacy_walk_path[PATH_MAX];
    int *legacy_chain;
    struct stat *legacy_chain_ids;
    char **legacy_chain_names;
    size_t legacy_chain_count;
    int retired, uncertain, failed, finalized, candidate_created, candidate_sealing, candidate_sealed;
    uint64_t children, seal_offset;
    struct stat seal_before;
    struct sha256_context seal_hash;
    char candidate_digest[65];
    migration_backup_node *backup_nodes, *backup_stack, *backup_active, *backup_root, *backup_verify_next;
    uint64_t backup_entry_count, backup_byte_count;
    int backup_started, backup_complete;
    int backup_verify_running, source_verified_before_candidate, source_verified_for_seal;
    migration_backup_node **context_index, *context_active;
    size_t context_count, context_index_offset;
    int context_fd, retained_observation_fd;
    uint64_t context_offset;
    struct sha256_context context_hash;
    int context_started, context_complete, context_exhausted, context_projection_started;
    uint64_t context_total_read_bytes;
    uint64_t backup_metadata_bytes;
    migration_publication_state *publication;
    migration_legacy_locks *legacy_locks;
    current_migration_inspection *inspection;
};
static const napi_type_tag migration_filesystem_tag = {0x1879e20bd5a44c86ULL, 0xac9d105e7f11b2aaULL};

static void migrate_scope_poison(migration_filesystem *scope) {
    scope->uncertain = 1;
    scope->binding->uncertain = 1;
    scope->binding->owner->migration_retirement_error = 1;
    atomic_store(&kernel_global_poisoned, 1);
}
static int migrate_scope_close_fd(migration_filesystem *scope, int *descriptor) {
    int original = *descriptor; *descriptor = -1;
    if (original < 0 || close(original) == 0) return 0;
    migrate_scope_poison(scope); return -1;
}
static int migrate_scope_directory(migration_filesystem *scope, int parent, const char *leaf,
                                   int descriptor, const struct stat *original) {
    struct stat held, named;
    (void)scope;
    return descriptor >= 0 && fstat(descriptor, &held) == 0 && private_directory(&held) &&
        same_inode(&held, original) && fstatat(parent, leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        private_directory(&named) && same_inode(&held, &named);
}
static int migrate_scope_hold_legacy_chain(migration_filesystem *scope) {
    size_t length = strlen(scope->legacy_path), capacity = 2;
    if (length < 2 || scope->legacy_path[0] != '/' || scope->legacy_path[length - 1] == '/') return -1;
    for (size_t index = 1; index < length; ++index) if (scope->legacy_path[index] == '/') capacity++;
    if (capacity > 65) return -1; /* fixed <=64-component source-root profile */
    scope->legacy_chain = malloc(capacity * sizeof(*scope->legacy_chain));
    scope->legacy_chain_ids = calloc(capacity, sizeof(*scope->legacy_chain_ids));
    scope->legacy_chain_names = calloc(capacity, sizeof(*scope->legacy_chain_names));
    if (!scope->legacy_chain || !scope->legacy_chain_ids || !scope->legacy_chain_names) return -1;
    memcpy(scope->legacy_walk_path, scope->legacy_path, length + 1);
    scope->legacy_chain[0] = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    scope->legacy_chain_count = 1;
    if (scope->legacy_chain[0] < 0 || fstat(scope->legacy_chain[0], &scope->legacy_chain_ids[0]) != 0) return -1;
    char *component = scope->legacy_walk_path + 1;
    for (;;) {
        char *end = strchr(component, '/');
        if (end) *end = '\0';
        size_t size = strlen(component);
        if (!size || size > NAME_MAX || strcmp(component, ".") == 0 || strcmp(component, "..") == 0) return -1;
        size_t current = scope->legacy_chain_count;
        scope->legacy_chain_names[current - 1] = component;
        scope->legacy_chain[current] = openat(scope->legacy_chain[current - 1], component,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        scope->legacy_chain_count++;
        if (scope->legacy_chain[current] < 0 || fstat(scope->legacy_chain[current], &scope->legacy_chain_ids[current]) != 0 ||
            !S_ISDIR(scope->legacy_chain_ids[current].st_mode)) return -1;
        /* Equality and a source inside StateRoot are unsupported. The default
         * reverse overlap is handled later by skipping only the held root inode. */
        if (same_inode(&scope->legacy_chain_ids[current], &scope->binding->owner->root)) return -1;
        if (!end) break;
        component = end + 1;
    }
    scope->legacy_fd = scope->legacy_chain[scope->legacy_chain_count - 1];
    scope->legacy = scope->legacy_chain_ids[scope->legacy_chain_count - 1];
    return scope->legacy.st_uid == geteuid() && (scope->legacy.st_mode & 07022) == 0 ? 0 : -1;
}
static int migrate_scope_legacy_chain_held(migration_filesystem *scope) {
    struct stat held, named;
    if (!scope->legacy_chain_count) return -1;
    for (size_t index = 0; index < scope->legacy_chain_count; ++index) {
        const struct stat *original = &scope->legacy_chain_ids[index];
        if (scope->legacy_chain[index] < 0 || fstat(scope->legacy_chain[index], &held) != 0 ||
            !S_ISDIR(held.st_mode) || !same_inode(&held, original) || held.st_uid != original->st_uid ||
            held.st_gid != original->st_gid || held.st_mode != original->st_mode) return -1;
        if (index && (fstatat(scope->legacy_chain[index - 1], scope->legacy_chain_names[index - 1], &named,
            AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(named.st_mode) || !same_inode(&held, &named) ||
            held.st_uid != named.st_uid || held.st_gid != named.st_gid || held.st_mode != named.st_mode)) return -1;
    }
    return 0;
}
static int migrate_scope_check(migration_filesystem *scope, napi_env env) {
    /* Binding/custody only. A changed source stops new data/commit boundaries,
     * but does not pretend an otherwise genuine read-only FD failed to close. */
    if (!scope || scope->env != env || scope->retired || scope->uncertain ||
        migration_credential_check(scope->binding, env) != 0) return -1;
    state_lock *owner = scope->binding->owner;
    if (migrate_scope_legacy_chain_held(scope) != 0 ||
        !migrate_scope_directory(scope, owner->root_fd, "migration", scope->migration_fd, &scope->migration) ||
        !migrate_scope_directory(scope, scope->migration_fd, "owned-import", scope->collection_fd, &scope->collection) ||
        !migrate_scope_directory(scope, scope->collection_fd, scope->migration_id, scope->package_fd, &scope->package) ||
        !migrate_scope_directory(scope, scope->package_fd, "backup", scope->backup_fd, &scope->backup) ||
        (!scope->inspection &&
          (!migrate_scope_directory(scope, scope->package_fd, "candidate", scope->candidate_dir_fd, &scope->candidate_dir) ||
           !migrate_scope_directory(scope, scope->package_fd, "archive", scope->archive_fd, &scope->archive))) ||
        migrate_publication_custody(scope) != 0 || migrate_legacy_locks_custody(scope) != 0 || ci_custody(scope) != 0) return -1;
    return 0;
}
static int migrate_scope_no_sidecars(migration_filesystem *scope) {
    static const char *const leaves[] = {"kernel.sqlite3-wal", "kernel.sqlite3-shm", "kernel.sqlite3-journal"};
    struct stat info;
    for (size_t index = 0; index < sizeof(leaves) / sizeof(leaves[0]); ++index) {
        if (fstatat(scope->candidate_dir_fd, leaves[index], &info, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return -1;
    }
    return 0;
}
static int migrate_scope_candidate_file(migration_filesystem *scope, int sealed) {
    struct stat held, named;
    mode_t mode = sealed ? 0400 : 0600;
    if (scope->candidate_fd < 0 || fstat(scope->candidate_fd, &held) != 0 ||
        !S_ISREG(held.st_mode) || held.st_uid != geteuid() || held.st_gid != getegid() ||
        (held.st_mode & 07777) != mode || held.st_nlink != 1 || held.st_size < 0 ||
        !same_inode(&held, &scope->candidate) ||
        fstatat(scope->candidate_dir_fd, "kernel.sqlite3", &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !source_metadata_same(&held, &named)) return -1;
    return sealed && !source_metadata_same(&held, &scope->candidate) ? -1 : 0;
}
static int migrate_scope_check_candidate(migration_filesystem *scope, napi_env env,
                                          const migration_candidate_borrow *borrow) {
    return migrate_scope_check(scope, env) == 0 && scope->candidate_sealed && scope->children &&
        borrow && borrow->image_fd == scope->candidate_fd &&
        source_metadata_same(&borrow->image, &scope->candidate) &&
        borrow->byte_count == (uint64_t)scope->candidate.st_size &&
        strcmp(borrow->full_digest, scope->candidate_digest) == 0 &&
        migrate_scope_candidate_file(scope, 1) == 0 && migrate_scope_no_sidecars(scope) == 0 ? 0 : -1;
}
static int migrate_scope_borrow_candidate(migration_filesystem *scope, napi_env env,
                                           migration_candidate_borrow *borrow) {
    if (!borrow || scope->failed || migrate_scope_check(scope, env) != 0 ||
        (scope->backup_complete && migrate_backup_source_root_stable(scope) != 0) || !scope->candidate_sealed ||
        scope->children == UINT64_MAX || migrate_scope_candidate_file(scope, 1) != 0 ||
        migrate_scope_no_sidecars(scope) != 0) return -1;
    *borrow = (migration_candidate_borrow){.image_fd = scope->candidate_fd, .image = scope->candidate,
        .byte_count = (uint64_t)scope->candidate.st_size};
    memcpy(borrow->full_digest, scope->candidate_digest, sizeof(borrow->full_digest));
    scope->children++;
    return 0;
}
static int migrate_scope_release_candidate(migration_filesystem *scope, napi_env env,
                                            migration_candidate_borrow *borrow) {
    if (migrate_scope_check_candidate(scope, env, borrow) != 0) return -1;
    scope->children--;
    borrow->image_fd = -1;
    return 0;
}
static int migrate_scope_retire(migration_filesystem *scope) {
    if (scope->uncertain || scope->children || migrate_legacy_locks_can_retire(scope) != 0) return -1;
    if (ci_retire(scope) != 0 || migrate_publication_retire(scope) != 0) return -1;
    if (migrate_scope_close_fd(scope, &scope->context_fd) != 0) return -1;
    if (migrate_backup_retire(scope) != 0) return -1;
    int *const descriptors[] = {&scope->candidate_fd, &scope->archive_fd, &scope->candidate_dir_fd,
        &scope->backup_fd, &scope->package_fd, &scope->collection_fd, &scope->migration_fd};
    for (size_t index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]); ++index)
        if (migrate_scope_close_fd(scope, descriptors[index]) != 0) return -1;
    scope->legacy_fd = -1; /* alias of the last original chain descriptor */
    for (size_t index = scope->legacy_chain_count; index > 0; --index)
        if (migrate_scope_close_fd(scope, &scope->legacy_chain[index - 1]) != 0) return -1;
    if (scope->binding_ref) {
        napi_ref original = scope->binding_ref; scope->binding_ref = NULL;
        if (napi_delete_reference(scope->env, original) != napi_ok) { migrate_scope_poison(scope); return -1; }
        scope->binding->borrowers--;
    }
    scope->retired = 1;
    return 0;
}
static void migrate_scope_free(migration_filesystem *scope) {
    ci_free(scope);
    migrate_backup_free(scope);
    migrate_publication_free(scope);
    migrate_legacy_locks_free(scope);
    free(scope->legacy_chain); free(scope->legacy_chain_ids); free(scope->legacy_chain_names); free(scope);
}
static napi_value migrate_scope_error(napi_env env, migration_filesystem *scope, const char *message) {
    if (scope) scope->failed = 1; /* Failed writes/hashes are never silently retried. Actual close remains permitted. */
    napi_throw_error(env, scope && scope->uncertain ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_MIGRATION_FILESYSTEM", message);
    return NULL;
}
static migration_filesystem *migrate_scope_receiver(napi_env env, napi_callback_info info,
                                                    size_t *count, napi_value *arguments) {
    napi_value self; bool tagged = false; migration_filesystem *scope = NULL;
    if (napi_get_cb_info(env, info, count, arguments, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &migration_filesystem_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&scope) != napi_ok || !scope || scope->env != env ||
        !kernel_global_main_thread()) {
        migrate_scope_error(env, NULL, "invalid original migration filesystem receiver"); return NULL;
    }
    return scope;
}
static migration_filesystem *migrate_scope_no_arguments(napi_env env, napi_callback_info info) {
    napi_value argument; size_t count = 1;
    migration_filesystem *scope = migrate_scope_receiver(env, info, &count, &argument);
    if (scope && count) { migrate_scope_error(env, scope, "migration filesystem method accepts no arguments"); return NULL; }
    return scope;
}
static napi_value migrate_scope_assert(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info);
    if (!scope) return NULL;
    if (migrate_scope_check(scope, env) != 0 || migrate_publication_validate(scope) != 0 ||
        migrate_legacy_locks_validate(scope) != 0 ||
        (scope->backup_complete && migrate_backup_source_root_stable(scope) != 0))
        return migrate_scope_error(env, scope, "migration filesystem identity or complete captured source changed or retired");
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value migrate_scope_close(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info);
    if (!scope) return NULL;
    if (scope->children) return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "migration filesystem children remain held");
    if (!scope->retired && (migrate_scope_check(scope, env) != 0 || migrate_scope_retire(scope) != 0))
        return migrate_scope_error(env, scope, "migration filesystem did not retire; original custody retained");
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static void migrate_scope_finalize(napi_env env, void *data, void *hint) {
    (void)hint;
    migration_filesystem *scope = data;
    if (!scope || scope->env != env || !kernel_global_main_thread() || scope->children || scope->uncertain) return;
    scope->finalized = 1;
    if (scope->retired || (migrate_scope_check(scope, env) == 0 && migrate_scope_retire(scope) == 0)) migrate_scope_free(scope);
}
static int migrate_scope_hold_directory(migration_filesystem *scope, int parent, const char *leaf,
                                         int *descriptor, struct stat *identity, int new_only) {
    int created = mkdirat(parent, leaf, 0700) == 0;
    if (!created && (new_only || errno != EEXIST)) return -1;
    *descriptor = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (*descriptor < 0 || fstat(*descriptor, identity) != 0 || !private_directory(identity) ||
        migrate_scope_directory(scope, parent, leaf, *descriptor, identity) != 1) return -1;
    return !created || (fsync(*descriptor) == 0 && fsync(parent) == 0) ? 0 : -1;
}
static napi_value migrate_scope_create_candidate(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info);
    if (!scope) return NULL;
    if (scope->failed || migrate_scope_check(scope, env) != 0 ||
        (scope->publication && migrate_legacy_locks_assert_current(scope) != 0) || scope->candidate_created || scope->candidate_fd >= 0 ||
        !scope->backup_complete || migrate_backup_source_root_stable(scope) != 0 || !scope->context_exhausted || scope->context_projection_started ||
        (scope->backup_entry_count && !scope->source_verified_before_candidate))
        return migrate_scope_error(env, scope, "candidate must be newly created by its original migration scope");
    scope->candidate_fd = openat(scope->candidate_dir_fd, "kernel.sqlite3",
        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (scope->candidate_fd < 0 || fstat(scope->candidate_fd, &scope->candidate) != 0 ||
        migrate_scope_candidate_file(scope, 0) != 0 || fsync(scope->candidate_fd) != 0 ||
        fsync(scope->candidate_dir_fd) != 0)
        return migrate_scope_error(env, scope, "candidate birth failed; no existing image is adopted");
    scope->candidate_created = 1;
    napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static napi_value migrate_scope_candidate_build_path(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info);
    if (!scope) return NULL;
    if (scope->failed || migrate_scope_check(scope, env) != 0 || !scope->candidate_created || scope->candidate_sealing || scope->candidate_sealed ||
        migrate_scope_candidate_file(scope, 0) != 0)
        return migrate_scope_error(env, scope, "candidate build locator is unavailable");
    char location[PATH_MAX];
    int count = snprintf(location, sizeof(location), "%s/migration/owned-import/%s/candidate/kernel.sqlite3",
        scope->binding->owner->path, scope->migration_id);
    if (count < 0 || (size_t)count >= sizeof(location)) return migrate_scope_error(env, scope, "candidate build locator exceeds its bound");
    napi_value result; return napi_create_string_utf8(env, location, (size_t)count, &result) == napi_ok ? result : NULL;
}
static napi_value migrate_scope_seal_candidate_next(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info);
    if (!scope) return NULL;
    if (scope->failed || migrate_scope_check(scope, env) != 0 ||
        (scope->publication && (!migrate_legacy_locks_ready(scope) ||
          (!scope->candidate_sealing && migrate_legacy_locks_assert_current(scope) != 0))) ||
        !scope->candidate_created || scope->candidate_sealed || scope->children ||
        !scope->backup_complete || migrate_backup_source_root_stable(scope) != 0 || !scope->context_exhausted ||
        (scope->backup_entry_count && !scope->source_verified_for_seal) || (scope->context_count && !scope->context_projection_started) ||
        migrate_scope_candidate_file(scope, 0) != 0 || migrate_scope_no_sidecars(scope) != 0)
        return migrate_scope_error(env, scope, "candidate writer must actually close and retire all sidecars before seal");
    if (!scope->candidate_sealing) {
        if (fstat(scope->candidate_fd, &scope->seal_before) != 0 || scope->seal_before.st_size < 1 ||
            (uint64_t)scope->seal_before.st_size > 9007199254740991ULL || fsync(scope->candidate_fd) != 0)
            return migrate_scope_error(env, scope, "candidate cannot enter complete image verification");
        sha256_init(&scope->seal_hash); scope->seal_offset = 0; scope->candidate_sealing = 1;
    }
    struct stat current;
    if (fstat(scope->candidate_fd, &current) != 0 || !source_metadata_same(&current, &scope->seal_before))
        return migrate_scope_error(env, scope, "candidate changed during complete verification");
    unsigned char bytes[65536];
    ssize_t size;
    do { size = pread(scope->candidate_fd, bytes, sizeof(bytes), (off_t)scope->seal_offset); } while (size < 0 && errno == EINTR);
    if (size < 0 || (uint64_t)size > (uint64_t)scope->seal_before.st_size - scope->seal_offset)
        return migrate_scope_error(env, scope, "candidate image read failed or exceeded its original length");
    if (size) {
        sha256_update(&scope->seal_hash, bytes, (size_t)size); scope->seal_offset += (uint64_t)size;
        napi_value result; return napi_get_boolean(env, false, &result) == napi_ok ? result : NULL;
    }
    if (scope->seal_offset != (uint64_t)scope->seal_before.st_size ||
        fstat(scope->candidate_fd, &current) != 0 || !source_metadata_same(&current, &scope->seal_before) ||
        migrate_scope_no_sidecars(scope) != 0 || fchmod(scope->candidate_fd, 0400) != 0 || fsync(scope->candidate_fd) != 0 ||
        fsync(scope->candidate_dir_fd) != 0)
        return migrate_scope_error(env, scope, "candidate image did not completely verify and durably seal");
    publication_hash_hex(&scope->seal_hash, scope->candidate_digest);
    int readonly = openat(scope->candidate_dir_fd, "kernel.sqlite3", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat sealed;
    if (readonly < 0 || fstat(readonly, &sealed) != 0 || !same_inode(&sealed, &scope->seal_before) ||
        !S_ISREG(sealed.st_mode) || sealed.st_uid != geteuid() || sealed.st_gid != getegid() ||
        (sealed.st_mode & 07777) != 0400 || sealed.st_nlink != 1 || sealed.st_size != scope->seal_before.st_size) {
        if (migrate_scope_close_fd(scope, &readonly) != 0) return migrate_scope_error(env, scope, "candidate readonly retirement failed");
        return migrate_scope_error(env, scope, "sealed candidate readonly identity differs");
    }
    if (migrate_scope_close_fd(scope, &scope->candidate_fd) != 0) {
        /* Retain the actual new readonly description if old writable close was
         * uncertain; never close a reused numeric writable descriptor again. */
        scope->candidate_fd = readonly;
        return migrate_scope_error(env, scope, "candidate writable description did not retire");
    }
    scope->candidate_fd = readonly; scope->candidate = sealed;
    scope->candidate_sealed = 1;
    if (migrate_scope_candidate_file(scope, 1) != 0 || migrate_scope_check(scope, env) != 0 ||
        (scope->publication && migrate_legacy_locks_assert_current(scope) != 0))
        return migrate_scope_error(env, scope, "sealed candidate named identity changed");
    napi_value result; return napi_get_boolean(env, true, &result) == napi_ok ? result : NULL;
}
static int migrate_scope_text(napi_env env, napi_value value, char *target, size_t capacity) {
    napi_valuetype type; size_t length, copied; napi_value encoded; bool same = false;
    return napi_typeof(env, value, &type) == napi_ok && type == napi_string &&
        napi_get_value_string_utf8(env, value, NULL, 0, &length) == napi_ok && length < capacity &&
        napi_get_value_string_utf8(env, value, target, capacity, &copied) == napi_ok && copied == length &&
        strlen(target) == length && napi_create_string_utf8(env, target, length, &encoded) == napi_ok &&
        napi_strict_equals(env, value, encoded, &same) == napi_ok && same ? 0 : -1;
}
static napi_value acquire_migration_filesystem(napi_env env, napi_callback_info info) {
    size_t count = 4; napi_value arguments[4]; bool tagged = false;
    migration_credential_gate *binding = NULL;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || count != 3 ||
        napi_check_object_type_tag(env, arguments[0], &migration_credential_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, arguments[0], (void **)&binding) != napi_ok || migration_credential_check(binding, env) != 0 ||
        binding->borrowers == UINT_MAX)
        return migrate_scope_error(env, NULL, "migration filesystem requires original root-bound exclusive gate");
    migration_filesystem *scope = calloc(1, sizeof(*scope));
    if (!scope) return migrate_scope_error(env, NULL, "migration filesystem allocation failed");
    scope->binding = binding; scope->env = env;
    scope->legacy_fd = scope->migration_fd = scope->collection_fd = scope->package_fd = -1;
    scope->backup_fd = scope->candidate_dir_fd = scope->archive_fd = scope->candidate_fd = -1;
    scope->context_fd = -1;
    scope->retained_observation_fd = -1;
    if (migrate_scope_text(env, arguments[1], scope->migration_id, sizeof(scope->migration_id)) != 0 || strlen(scope->migration_id) != 43 ||
        migrate_scope_text(env, arguments[2], scope->legacy_path, sizeof(scope->legacy_path)) != 0) goto failed;
    for (size_t index = 0; index < 43; ++index) {
        unsigned char item = (unsigned char)scope->migration_id[index];
        if (!((item >= 'A' && item <= 'Z') || (item >= 'a' && item <= 'z') ||
              (item >= '0' && item <= '9') || item == '_' || item == '-')) goto failed;
    }
    /* Retain the original gate before opening any owned directory. This is a
     * borrow, not an unlock/relock or structural StateOwner replacement. */
    if (napi_create_reference(env, arguments[0], 1, &scope->binding_ref) != napi_ok) {
        migrate_scope_poison(scope); return migrate_scope_error(env, scope, "migration parent retention failed");
    }
    binding->borrowers++;
    if (migrate_scope_hold_legacy_chain(scope) != 0) goto failed;
    if (migrate_scope_hold_directory(scope, binding->owner->root_fd, "migration", &scope->migration_fd, &scope->migration, 0) != 0 ||
        migrate_scope_hold_directory(scope, scope->migration_fd, "owned-import", &scope->collection_fd, &scope->collection, 0) != 0 ||
        migrate_scope_hold_directory(scope, scope->collection_fd, scope->migration_id, &scope->package_fd, &scope->package, 1) != 0 ||
        migrate_scope_hold_directory(scope, scope->package_fd, "backup", &scope->backup_fd, &scope->backup, 1) != 0 ||
        migrate_scope_hold_directory(scope, scope->package_fd, "candidate", &scope->candidate_dir_fd, &scope->candidate_dir, 1) != 0 ||
        migrate_scope_hold_directory(scope, scope->package_fd, "archive", &scope->archive_fd, &scope->archive, 1) != 0 ||
        migrate_scope_check(scope, env) != 0) goto failed;
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, migrate_scope_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, migrate_scope_close, NULL, NULL, NULL, napi_default, NULL},
        {"prepareLegacyLocksNext", NULL, migrate_legacy_locks_prepare_next, NULL, NULL, NULL, napi_default, NULL},
        {"assertLegacyLocks", NULL, migrate_legacy_locks_assert, NULL, NULL, NULL, napi_default, NULL},
        {"releaseLegacyLocks", NULL, migrate_legacy_locks_release, NULL, NULL, NULL, napi_default, NULL},
        {"observeRoots", NULL, migrate_publication_roots, NULL, NULL, NULL, napi_default, NULL},
        {"publishInitialSpine", NULL, migrate_publication_initial, NULL, NULL, NULL, napi_default, NULL},
        {"advanceControl", NULL, migrate_publication_control, NULL, NULL, NULL, napi_default, NULL},
        {"observeOriginalAuth", NULL, migrate_publication_auth_observation, NULL, NULL, NULL, napi_default, NULL},
        {"publishAuthCutover", NULL, migrate_publication_auth_marker, NULL, NULL, NULL, napi_default, NULL},
        {"publishKernelAuthority", NULL, migrate_publication_authority, NULL, NULL, NULL, napi_default, NULL},
        {"readControlBytes", NULL, migrate_publication_read_control, NULL, NULL, NULL, napi_default, NULL},
        {"readPreparationBytes", NULL, migrate_publication_read_preparation, NULL, NULL, NULL, napi_default, NULL},
        {"readRendezvousBytes", NULL, migrate_publication_read_rendezvous, NULL, NULL, NULL, napi_default, NULL},
        {"assertCredentialCutoverControl", NULL, migrate_publication_assert_credential_cutover, NULL, NULL, NULL, napi_default, NULL},
        {"readBackupInventoryPage", NULL, migrate_publication_inventory_page, NULL, NULL, NULL, napi_default, NULL},
        {"createCandidate", NULL, migrate_scope_create_candidate, NULL, NULL, NULL, napi_default, NULL},
        {"candidateBuildPath", NULL, migrate_scope_candidate_build_path, NULL, NULL, NULL, napi_default, NULL},
        {"sealCandidateNext", NULL, migrate_scope_seal_candidate_next, NULL, NULL, NULL, napi_default, NULL},
        {"copyBackupNext", NULL, migrate_backup_next, NULL, NULL, NULL, napi_default, NULL},
        {"verifyBackupSourceNext", NULL, migrate_backup_verify_source_next, NULL, NULL, NULL, napi_default, NULL},
        {"beginContextProjection", NULL, migrate_context_begin_projection, NULL, NULL, NULL, napi_default, NULL},
        {"nextContextSource", NULL, migrate_context_next, NULL, NULL, NULL, napi_default, NULL},
        {"readContextSourceChunk", NULL, migrate_context_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"closeContextSource", NULL, migrate_context_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &migration_filesystem_tag) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_wrap(env, result, scope, migrate_scope_finalize, NULL, NULL) != napi_ok) goto failed;
    return result;
failed:
    if (migrate_scope_retire(scope) != 0) return migrate_scope_error(env, scope, "migration creation failed with uncertain original custody");
    migrate_scope_free(scope);
    return migrate_scope_error(env, NULL, "migration creation refused; existing package/unsafe root is never adopted");
}
#include "migration-backup.c"
#include "migration-publication.c"
#include "migration-legacy-locks.c"
#include "migration-current-inspector.c"
