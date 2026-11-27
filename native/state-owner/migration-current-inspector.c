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
    cliq_model_store_archive *model_source;
    struct cliq_model_store_archive_directories model_directories;
    int model_released, model_verified, rollback_publisher, rollback_draining, original_archive_borrowed;
    int rollback_resume_prepared, rollback_resume_archive_ready, rollback_legacy_already;
    unsigned char rollback_auth_witness[16];
    rw_archive *runtime_witnesses;
    ci_archive *archive;
};
static int ci_model_source(migration_filesystem *scope) {
    current_migration_inspection *state = scope->inspection; struct stat actual;
    if (state->model_source) return cliq_model_store_archive_assert(state->model_source) == 0 ? 0 : -1;
    if (state->model_released) {
        return fstatat(scope->binding->owner->root_fd, "local-models", &actual, AT_SYMLINK_NOFOLLOW) == 0 &&
            private_directory(&actual) && source_metadata_same(&actual, &state->model_directories.store) ? 0 : -1;
    }
    return fstatat(scope->binding->owner->root_fd, "local-models", &actual, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT ? 0 : -1;
}
static int ci_custody(migration_filesystem *scope) {
    if (!scope->inspection) return 0;
    migration_credential_gate *binding = scope->binding; struct stat runtime_entry;
    return !scope->inspection->retired && ci_model_source(scope) == 0 &&
        migrate_scope_directory(scope, binding->owner->root_fd, "runtime", binding->owner->runtime_fd, &binding->owner->runtime) &&
        (scope->inspection->runtime_witnesses ? rw_custody(scope->inspection->runtime_witnesses) == 0 :
            fstatat(binding->owner->runtime_fd, "local-inference", &runtime_entry, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT) &&
        ca_custody(scope) == 0 ? 0 : -1;
}
static int ci_retire(migration_filesystem *scope) {
    if (!scope->inspection) return 0;
    current_migration_inspection *state = scope->inspection;
    if (state->rollback_publisher || state->original_archive_borrowed) return -1;
    if (rw_retire(state->runtime_witnesses) != 0) { migrate_scope_poison(scope); return -1; }
    state->runtime_witnesses = NULL;
    if (ca_retire(scope) != 0) return -1;
    if (state->model_source) {
        int closed = state->model_verified && !scope->failed ? cliq_model_store_archive_end(scope->env, state->model_source) :
            cliq_model_store_archive_cancel(scope->env, state->model_source);
        if (closed != 0) return -1;
        state->model_source = NULL;
    }
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
        scope->backup_started || scope->candidate_created || scope->children || scope->inspection->original_archive_borrowed ||
        mp_current(scope, scope->env) != 0) return -1;
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
static napi_value ci_begin_process_cut(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    return mq_begin_cut(scope, env);
}
static napi_value ci_step_process_cut(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    return mq_step_cut(scope, env);
}
static napi_value ci_settle_process_package(napi_env env, napi_callback_info info) {
    napi_value args[3]; size_t count = 3; char digest[65]; bool unrelated;
    migration_filesystem *scope = ci_receiver(env, info, &count, args);
    if (!scope || count != 2 || migrate_scope_text(env, args[0], digest, sizeof(digest)) != 0 || strlen(digest) != 64 ||
        napi_get_value_bool(env, args[1], &unrelated) != napi_ok)
        return migrate_scope_error(env, NULL, "invalid current process package inspection");
    return mq_settle_package(scope, env, digest, unrelated);
}
static napi_value ci_cancel_process_cut(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    return mq_cancel_cut(scope, env);
}
static napi_value ci_assert(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    if (ci_legacy_entry(scope) != 0 || migrate_legacy_locks_validate(scope) != 0)
        return migrate_scope_error(env, scope, "current migration observation changed or retired");
    return mp_undefined(env);
}
static napi_value ci_close(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = ci_no_arguments(env, info); if (!scope) return NULL;
    if (scope->children || scope->inspection->rollback_publisher || scope->inspection->original_archive_borrowed)
        return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "current inspector children remain genuinely held");
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
#include "migration-current-rollback.c"

/* A single existing visitor owns the real model lock. Only the original
 * archive of this current rollback holder may borrow it, without ending the
 * source or opening a second model lock/visitor. No raw FD leaves native. */
static int ci_take_original_archive_loan(napi_env env, napi_value value, migration_credential_gate *binding,
                                         migration_filesystem **out, napi_ref *reference) {
    bool tagged = false; migration_filesystem *scope = NULL;
    if (napi_check_object_type_tag(env, value, &current_migration_inspector_tag, &tagged) != napi_ok) return -1;
    if (!tagged) return 1;
    if (napi_unwrap(env, value, (void **)&scope) != napi_ok || !scope || scope->binding != binding || scope->env != env ||
        ci_legacy_entry(scope) != 0 || !scope->inspection->rollback_publisher || !scope->inspection->rollback_draining ||
        scope->inspection->archive || migrate_legacy_locks_ready(scope) == 0 ||
        napi_create_reference(env, value, 1, reference) != napi_ok) return -1;
    scope->inspection->original_archive_borrowed = 1; *out = scope;
    return 0;
}
static int ci_return_original_archive_loan(napi_env env, migration_filesystem *scope, napi_ref reference, int data_failed) {
    if (!scope || scope->env != env || !scope->inspection || !scope->inspection->original_archive_borrowed || !reference ||
        migration_credential_check(scope->binding, env) != 0 || napi_delete_reference(env, reference) != napi_ok) return -1;
    scope->inspection->original_archive_borrowed = 0;
    if (data_failed) scope->failed = 1;
    return 0;
}

/* Nine fixed arguments plus an optional genuine original model-scope tag:
 * gate,id,attempt,LegacyRoot,eight root/mode/count witnesses,
 * exact current Root control, Kernel authority, current Legacy rendezvous and
 * exact original nonsecret auth marker. A successor also supplies the exact
 * prepared marker bytes and four original staged/displaced identities.
 * The signed TS reader independently closes the retained SQL/CAS history. */
static napi_value open_current_migration_inspector(napi_env env, napi_callback_info info) {
    napi_value arguments[13]; size_t count = 13; bool tagged = false, array = false;
    migration_credential_gate *binding = NULL;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok ||
        (count != 9 && count != 10 && count != 11 && count != 12) ||
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
    napi_valuetype model_type = napi_null;
    if (count >= 10 && napi_typeof(env, arguments[9], &model_type) != napi_ok) goto failed;
    if (count >= 10 && model_type != napi_null) {
        if (cliq_model_store_archive_begin(env, arguments[9], binding, &state->model_source) != 0 ||
            cliq_model_store_archive_directories(state->model_source, &state->model_directories) != 0 ||
            state->model_directories.store.st_dev != binding->owner->root.st_dev ||
            state->model_directories.objects.st_dev != binding->owner->root.st_dev) goto failed;
    } else if (ci_model_source(scope) != 0) goto failed;
    if (rw_open_source(env, binding, &state->runtime_witnesses) < 0) goto failed;
    if (migrate_scope_hold_legacy_chain(scope) != 0 || ci_device(&scope->legacy) != witness[0] || (uint64_t)scope->legacy.st_ino != witness[1] ||
        (uint64_t)(scope->legacy.st_mode & 07777) != witness[2] ||
        ci_open_directory(scope, binding->owner->root_fd, "migration", &scope->migration_fd, &scope->migration) != 0 ||
        ci_open_directory(scope, scope->migration_fd, "owned-import", &scope->collection_fd, &scope->collection) != 0 ||
        ci_open_directory(scope, scope->collection_fd, scope->migration_id, &scope->package_fd, &scope->package) != 0 ||
        ci_open_directory(scope, scope->package_fd, "backup", &scope->backup_fd, &scope->backup) != 0 ||
        ci_device(&scope->backup) != witness[3] || (uint64_t)scope->backup.st_ino != witness[4] ||
        (uint64_t)(scope->backup.st_mode & 07777) != witness[5] || mp_create_state(scope) != 0) goto failed;
    if (mp_adopt_readonly_observation(scope, &scope->publication->files[MP_CONTROL], MP_MIGRATION_PARENT, "control-v1.json", 0600, documents[0], sizes[0]) != 0 ||
        mp_adopt_readonly_observation(scope, &scope->publication->files[MP_AUTHORITY_ROOT], MP_MIGRATION_PARENT, "authority-v1.json", 0600, documents[1], sizes[1]) != 0) goto failed;
    if (count == 12) {
        const unsigned char *marker, *packet; size_t marker_size, packet_size;
        if (mp_buffer(env, arguments[10], &marker, &marker_size) != 0 || ca_buffer(env, arguments[11], &packet, &packet_size) != 0 ||
            cr_open_prepared_recovery(scope, documents[2], sizes[2], marker, marker_size, packet, packet_size) != 0) goto failed;
    } else if (mp_adopt_readonly_observation(scope, &scope->publication->files[MP_AUTHORITY_LEGACY],
        MP_LEGACY_PARENT, ".cliq-generation-v1.json", 0600, documents[2], sizes[2]) != 0) goto failed;
    if (count == 11) {
        const unsigned char *packet; size_t packet_size;
        if (ca_buffer(env, arguments[10], &packet, &packet_size) != 0 || cr_bind_auth_intent(scope, packet, packet_size) != 0)
            goto failed;
        state->rollback_resume_archive_ready = 1;
    }
    struct stat auth;
    if (fstatat(scope->legacy_fd, "auth.json", &auth, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno != ENOENT) goto failed;
        state->auth_absent = 1;
    } else if (count == 12 || mp_adopt_readonly_observation(scope, &scope->publication->files[MP_AUTH_MARKER], MP_LEGACY_PARENT,
        "auth.json", 0600, documents[3], sizes[3]) != 0) goto failed;
    if (count == 11 && !state->auth_absent &&
        !ca_witness(&scope->publication->files[MP_AUTH_MARKER].identity, state->rollback_auth_witness)) goto failed;
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
        {"beginLegacyProcessCut", NULL, ci_begin_process_cut, NULL, NULL, NULL, napi_default, NULL},
        {"stepLegacyProcessCut", NULL, ci_step_process_cut, NULL, NULL, NULL, napi_default, NULL},
        {"settleLegacyProcessPackage", NULL, ci_settle_process_package, NULL, NULL, NULL, napi_default, NULL},
        {"cancelLegacyProcessCut", NULL, ci_cancel_process_cut, NULL, NULL, NULL, napi_default, NULL},
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
        {"selectArchiveModelStore", NULL, ca_select_models, NULL, NULL, NULL, napi_default, NULL},
        {"selectArchiveRuntimeWitnesses", NULL, ca_select_runtime_witnesses, NULL, NULL, NULL, napi_default, NULL},
        {"verifyArchiveRuntimeWitnessesNext", NULL, ca_verify_runtime_witnesses_next, NULL, NULL, NULL, napi_default, NULL},
        {"beginRetiredRuntimeWitnessObservation", NULL, ca_begin_retired_runtime_observation, NULL, NULL, NULL, napi_default, NULL},
        {"observeRetiredRuntimeWitnessNext", NULL, ca_retired_runtime_observation_next, NULL, NULL, NULL, napi_default, NULL},
        {"retiredRuntimeWitnessObservation", NULL, ca_retired_runtime_observation, NULL, NULL, NULL, napi_default, NULL},
        {"verifyArchiveModelStoreNext", NULL, ca_verify_models_next, NULL, NULL, NULL, napi_default, NULL},
        {"finishArchiveModelInspection", NULL, ca_finish_models, NULL, NULL, NULL, napi_default, NULL},
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
