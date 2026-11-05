/* Current read-only observer of original source/backup identities. It reuses
 * migration_filesystem custody and the one canonical Legacy lock engine, but
 * has a distinct tag: old creator/candidate callbacks cannot accept it. No old
 * progress/birth/complete flag is fabricated. Included after the shared locks. */
static const napi_type_tag current_migration_inspector_tag = {0xcbb1d427128347b1ULL, 0xabf3e28fbc354ca8ULL};
typedef struct ci_entry {
    char *path; uint64_t device[2], inode[2], byte_count; uint32_t owner[2], mode;
    unsigned int kind, purpose; char digest[65]; struct stat observed[2]; uint64_t seen[2];
} ci_entry;
typedef struct ci_walk { int fd; DIR *directory; size_t node; struct stat before; } ci_walk;
typedef struct ci_archive ci_archive;
static int ca_custody(migration_filesystem *scope);
static int ca_retire(migration_filesystem *scope);
static void ca_free(migration_filesystem *scope);
struct current_migration_inspection {
    char archive_id[44];
    uint64_t expected_entries;
    int documents_complete, auth_absent, retired;
    ci_entry **entries; size_t count, verified;
    int entries_sealed, active_fd, active_side; uint64_t active_offset, source_bytes;
    struct sha256_context active_hash;
    ci_walk walk[65]; size_t walk_count; int scan_side, scan_started, trees_complete;
    uint64_t scan_epoch, scan_seen;
    ci_archive *archive;
};
static int ci_custody(migration_filesystem *scope) {
    return !scope->inspection ? 0 : !scope->inspection->retired && ca_custody(scope) == 0 ? 0 : -1;
}
static int ci_retire(migration_filesystem *scope) {
    if (!scope->inspection) return 0;
    current_migration_inspection *state = scope->inspection;
    if (ca_retire(scope) != 0) return -1;
    if (migrate_scope_close_fd(scope, &state->active_fd) != 0) return -1;
    while (state->walk_count) {
        ci_walk *walk = &state->walk[--state->walk_count]; DIR *directory = walk->directory; walk->directory = NULL; walk->fd = -1;
        if (directory && closedir(directory) != 0) { migrate_scope_poison(scope); return -1; }
    }
    state->retired = 1; return 0;
}
static void ci_free(migration_filesystem *scope) {
    current_migration_inspection *state = scope->inspection; if (!state) return;
    ca_free(scope);
    for (size_t index = 0; index < state->count; ++index) free(state->entries[index]);
    free(state->entries); free(state); scope->inspection = NULL;
}
static int ci_legacy_entry(migration_filesystem *scope) {
    if (!scope->inspection || !scope->inspection->documents_complete || scope->inspection->retired || scope->failed ||
        scope->backup_started || scope->candidate_created || scope->children || mp_current(scope, scope->env) != 0) return -1;
    if (scope->inspection->auth_absent) { struct stat actual;
        if (fstatat(scope->legacy_fd, "auth.json", &actual, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return -1; }
    return 0;
}
static migration_filesystem *ci_receiver(napi_env env, napi_callback_info info, size_t *count, napi_value *arguments) {
    napi_value self; bool tagged = false; migration_filesystem *scope = NULL;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, count, arguments, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &current_migration_inspector_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&scope) != napi_ok || !scope || scope->env != env || !scope->inspection)
        return migrate_scope_error(env, NULL, "invalid current migration inspector receiver"), NULL;
    return scope;
}
static migration_filesystem *ci_no_arguments(napi_env env, napi_callback_info info) {
    napi_value ignored; size_t count = 1;
    migration_filesystem *scope = ci_receiver(env, info, &count, &ignored);
    if (scope && count) return migrate_scope_error(env, scope, "current inspector accepts no arguments"), NULL;
    return scope;
}
static napi_value ci_assert(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    if (ci_legacy_entry(scope) != 0 || migrate_legacy_locks_validate(scope) != 0)
        return migrate_scope_error(env, scope, "current migration observation changed or retired");
    return mp_undefined(env);
}
static napi_value ci_close(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    if (scope->children) return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "current inspector children remain genuinely held");
    /* Data drift refuses all observations, but does not manufacture an FD
     * retirement failure. This exact receiver still owns its descriptors.
     * A failed binding/join/actual close remains a real retirement error. */
    if (!scope->retired && (scope->uncertain || migration_credential_check(scope->binding, env) != 0 || migrate_scope_retire(scope) != 0)) {
        migrate_scope_poison(scope);
        return migrate_scope_error(env, scope, "current inspector original resources did not retire");
    }
    return mp_undefined(env);
}
static napi_value ci_prepare_locks(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    return ml_prepare_for_scope(env, scope, 1);
}
static napi_value ci_assert_locks(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    if (ci_legacy_entry(scope) != 0 || migrate_legacy_locks_assert_current(scope) != 0)
        return migrate_scope_error(env, scope, "current inspector canonical Legacy locks are not complete");
    return mp_undefined(env);
}
static napi_value ci_release_locks(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    return ml_release_for_scope(env, info, scope);
}
static int ci_open_directory(migration_filesystem *scope, int parent, const char *leaf, int *fd, struct stat *identity) {
    *fd = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    return *fd >= 0 && fstat(*fd, identity) == 0 && private_directory(identity) &&
        migrate_scope_directory(scope, parent, leaf, *fd, identity) == 1 ? 0 : -1;
}
static uint64_t ci_device(const struct stat *identity) {
#ifdef __APPLE__
    return (uint32_t)identity->st_dev;
#else
    return (uint64_t)identity->st_dev;
#endif
}
static int ci_id(napi_env env, napi_value value, char result[44]) {
    return migrate_scope_text(env, value, result, 44) == 0 && strlen(result) == 43 &&
        strspn(result, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") == 43 ? 0 : -1;
}
#include "migration-current-inventory.c"
#include "migration-current-archive.c"

/* Nine fixed arguments: gate,id,attempt,LegacyRoot,eight root/mode/count witnesses,
 * exact current Root control, Kernel authority, current Legacy rendezvous and
 * exact original nonsecret auth marker. All old-history/source bindings are
 * independently closed by the private TS consumer before mutating methods. */
static napi_value open_current_migration_inspector(napi_env env, napi_callback_info info) {
    napi_value arguments[10]; size_t count = 10; bool tagged = false, array = false;
    migration_credential_gate *binding = NULL;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || count != 9 ||
        napi_check_object_type_tag(env, arguments[0], &migration_credential_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, arguments[0], (void **)&binding) != napi_ok || migration_credential_check(binding, env) != 0 || binding->borrowers == UINT_MAX)
        return migrate_scope_error(env, NULL, "current migration inspector requires original Root/Owner/EX");
    migration_filesystem *scope = calloc(1, sizeof(*scope));
    current_migration_inspection *state = calloc(1, sizeof(*state));
    if (!scope || !state) { free(scope); free(state); return migrate_scope_error(env, NULL, "current inspector allocation failed"); }
    scope->binding = binding; scope->env = env; scope->inspection = state; state->active_fd = -1;
    scope->legacy_fd = scope->migration_fd = scope->collection_fd = scope->package_fd = -1;
    scope->backup_fd = scope->candidate_dir_fd = scope->archive_fd = scope->candidate_fd = scope->context_fd = scope->retained_observation_fd = -1;
    uint32_t length = 0; uint64_t witness[8]; const unsigned char *documents[4]; size_t sizes[4];
    if (ci_id(env, arguments[1], scope->migration_id) != 0 || ci_id(env, arguments[2], state->archive_id) != 0 ||
        migrate_scope_text(env, arguments[3], scope->legacy_path, sizeof(scope->legacy_path)) != 0 ||
        napi_is_array(env, arguments[4], &array) != napi_ok || !array || napi_get_array_length(env, arguments[4], &length) != napi_ok || length != 8) goto failed;
    for (uint32_t index = 0; index < 8; ++index) {
        napi_value value; bool lossless = false;
        if (napi_get_element(env, arguments[4], index, &value) != napi_ok ||
            napi_get_value_bigint_uint64(env, value, &witness[index], &lossless) != napi_ok || !lossless) goto failed;
    }
    if (witness[6] != (uint64_t)geteuid() || witness[7] > 9007199254740991ULL || witness[2] > 07777 || witness[5] != 0700) goto failed;
    for (size_t index = 0; index < 4; ++index) if (mp_buffer(env, arguments[5 + index], &documents[index], &sizes[index]) != 0) goto failed;
    if (napi_create_reference(env, arguments[0], 1, &scope->binding_ref) != napi_ok) { migrate_scope_poison(scope); goto failed; }
    binding->borrowers++;
    if (migrate_scope_hold_legacy_chain(scope) != 0 || ci_device(&scope->legacy) != witness[0] || (uint64_t)scope->legacy.st_ino != witness[1] ||
        (uint64_t)(scope->legacy.st_mode & 07777) != witness[2] ||
        ci_open_directory(scope, binding->owner->root_fd, "migration", &scope->migration_fd, &scope->migration) != 0 ||
        ci_open_directory(scope, scope->migration_fd, "owned-import", &scope->collection_fd, &scope->collection) != 0 ||
        ci_open_directory(scope, scope->collection_fd, scope->migration_id, &scope->package_fd, &scope->package) != 0 ||
        ci_open_directory(scope, scope->package_fd, "backup", &scope->backup_fd, &scope->backup) != 0 ||
        ci_device(&scope->backup) != witness[3] || (uint64_t)scope->backup.st_ino != witness[4] ||
        (uint64_t)(scope->backup.st_mode & 07777) != witness[5] || mp_create_state(scope) != 0) goto failed;
    if (mp_adopt_readonly_observation(scope, &scope->publication->files[MP_CONTROL], MP_MIGRATION_PARENT, "control-v1.json", 0600, documents[0], sizes[0]) != 0 ||
        mp_adopt_readonly_observation(scope, &scope->publication->files[MP_AUTHORITY_ROOT], MP_MIGRATION_PARENT, "authority-v1.json", 0600, documents[1], sizes[1]) != 0 ||
        mp_adopt_readonly_observation(scope, &scope->publication->files[MP_AUTHORITY_LEGACY], MP_LEGACY_PARENT, ".cliq-generation-v1.json", 0600, documents[2], sizes[2]) != 0) goto failed;
    struct stat auth;
    if (fstatat(scope->legacy_fd, "auth.json", &auth, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno != ENOENT) goto failed;
        state->auth_absent = 1;
    } else if (mp_adopt_readonly_observation(scope, &scope->publication->files[MP_AUTH_MARKER], MP_LEGACY_PARENT,
        "auth.json", 0600, documents[3], sizes[3]) != 0) goto failed;
    state->expected_entries = witness[7];
    if (state->expected_entries > (MIGRATION_BACKUP_METADATA_BYTES - scope->backup_metadata_bytes) / sizeof(*state->entries)) goto failed;
    if (state->expected_entries) {
        state->entries = calloc((size_t)state->expected_entries, sizeof(*state->entries));
        if (!state->entries) goto failed;
    }
    scope->backup_metadata_bytes += state->expected_entries * sizeof(*state->entries); state->documents_complete = 1;
    if (ci_legacy_entry(scope) != 0) goto failed;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, ci_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, ci_close, NULL, NULL, NULL, napi_default, NULL},
        {"prepareLegacyLocksNext", NULL, ci_prepare_locks, NULL, NULL, NULL, napi_default, NULL},
        {"assertLegacyLocks", NULL, ci_assert_locks, NULL, NULL, NULL, napi_default, NULL},
        {"releaseLegacyLocks", NULL, ci_release_locks, NULL, NULL, NULL, napi_default, NULL},
        {"beginExpectedEntry", NULL, ci_begin_entry, NULL, NULL, NULL, napi_default, NULL},
        {"verifyExpectedEntryNext", NULL, ci_verify_entry_next, NULL, NULL, NULL, napi_default, NULL},
        {"finishExpectedEntries", NULL, ci_finish_entries, NULL, NULL, NULL, napi_default, NULL},
        {"beginWholeTreeVerification", NULL, ci_begin_whole_trees, NULL, NULL, NULL, napi_default, NULL},
        {"verifyWholeTreesNext", NULL, ci_verify_whole_trees_next, NULL, NULL, NULL, napi_default, NULL},
        {"inspectRetainedLegacy", NULL, ci_inspect_retained, NULL, NULL, NULL, napi_default, NULL},
        {"selectOriginalKernelArchive", NULL, ca_select, NULL, NULL, NULL, napi_default, NULL},
        {"verifyArchiveManifestNext", NULL, ca_verify_manifest_next, NULL, NULL, NULL, napi_default, NULL},
        {"readArchiveManifestChunk", NULL, ca_read_manifest_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"selectArchivePayload", NULL, ca_select_payload, NULL, NULL, NULL, napi_default, NULL},
        {"verifyArchiveImageNext", NULL, ca_verify_image_next, NULL, NULL, NULL, napi_default, NULL},
        {"beginArchiveEntryPass", NULL, ca_begin_entry_pass, NULL, NULL, NULL, napi_default, NULL},
        {"beginArchiveCasEntry", NULL, ca_begin_entry, NULL, NULL, NULL, napi_default, NULL},
        {"verifyArchiveCasEntryNext", NULL, ca_verify_entry_next, NULL, NULL, NULL, napi_default, NULL},
        {"verifyArchiveNamespaceNext", NULL, ca_verify_namespace_next, NULL, NULL, NULL, napi_default, NULL},
        {"inspectVerifiedArchive", NULL, ca_inspect, NULL, NULL, NULL, napi_default, NULL}
    };
    napi_value result;
    if (napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &current_migration_inspector_tag) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_wrap(env, result, scope, migrate_scope_finalize, NULL, NULL) != napi_ok) goto failed;
    return result;
failed:
    if (migrate_scope_retire(scope) != 0) return migrate_scope_error(env, scope, "current inspector creation failed with retained original custody");
    migrate_scope_free(scope); return migrate_scope_error(env, NULL, "current inspector refused original current documents or roots");
}
