/* Fixed physical publication for one continuous current rollback holder.
 * The readonly inspector retains its own tag and methods. The separately
 * tagged writer borrows that inspector's exact Owner, EX, model visitor,
 * Legacy locks and observed original documents. The signed Store separately
 * verifies retained receipts and the actual last SQL transaction. */
static const napi_type_tag current_rollback_publisher_tag = {0x7c8e3d53777c4475ULL, 0xa79d81e449eaf12eULL};
enum current_rollback_phase { CR_INSPECTED, CR_DRAINING, CR_ARCHIVE_READY, CR_AUTH_ABSENT, CR_MARKERS_STAGED, CR_RESTORING, CR_PUBLISHED };
typedef struct current_rollback_publisher {
    napi_env env;
    napi_ref inspector_ref;
    migration_filesystem *scope;
    enum current_rollback_phase phase;
    uint64_t pre_auth_scan;
    int retired;
} current_rollback_publisher;

static int cr_marker_temp(migration_filesystem *scope, char leaf[NAME_MAX + 1]) {
    int size = snprintf(leaf, NAME_MAX + 1, ".cliq-%s-legacy-authority.tmp", scope->inspection->archive_id);
    return size >= 0 && size <= NAME_MAX ? 0 : -1;
}
/* CLQMR001, old Root and Legacy identity, staged Root and Legacy identity,
 * uid and optional require-unpublished guard. The old and new marker bytes come from the closed history.
 * Only the fixed staged or final Legacy name can contain the original inode. */
static int cr_open_prepared_recovery(migration_filesystem *scope, const unsigned char *old_bytes, size_t old_length,
                                      const unsigned char *new_bytes, size_t new_length, const unsigned char *packet, size_t size) {
    if (size != 80 || memcmp(packet, "CLQMR001", 8) || ci_le32(packet + 72) != (uint32_t)geteuid() || ci_le32(packet + 76) > 1)
        return -1;
    migration_publication_file *old_root = &scope->publication->files[MP_AUTHORITY_ROOT];
    migration_publication_file *old_legacy = &scope->publication->files[MP_AUTHORITY_LEGACY];
    migration_publication_file *root = &scope->publication->files[MP_ROLLBACK_ROOT_PREPARED];
    migration_publication_file *legacy = &scope->publication->files[MP_ROLLBACK_LEGACY_PREPARED];
    char leaf[NAME_MAX + 1], old_digest[65], new_digest[65];
    mp_digest(old_bytes, old_length, old_digest); mp_digest(new_bytes, new_length, new_digest);
    if (!strcmp(old_digest, new_digest) || cr_marker_temp(scope, leaf) != 0 ||
        !ca_witness(&old_root->identity, packet + 8) || strcmp(old_root->digest, old_digest) ||
        mp_adopt_readonly_observation(scope, root, MP_MIGRATION_PARENT, leaf, 0600, new_bytes, new_length) != 0 ||
        !ca_witness(&root->identity, packet + 40) ||
        mp_adopt_readonly_observation(scope, old_legacy, MP_LEGACY_PARENT, ".cliq-generation-v1.json", 0600, NULL, 0) != 0)
        return -1;
    if (ca_witness(&old_legacy->identity, packet + 24) && !strcmp(old_legacy->digest, old_digest)) {
        if (mp_adopt_readonly_observation(scope, legacy, MP_LEGACY_PARENT, leaf, 0600, new_bytes, new_length) != 0 ||
            !ca_witness(&legacy->identity, packet + 56)) return -1;
    } else {
        if (ci_le32(packet + 76) || !ca_witness(&old_legacy->identity, packet + 56) || strcmp(old_legacy->digest, new_digest)) return -1;
        *legacy = *old_legacy;
        memset(old_legacy, 0, sizeof(*old_legacy)); old_legacy->fd = -1;
        if (mp_adopt_readonly_observation(scope, old_legacy, MP_LEGACY_PARENT, leaf, 0600, old_bytes, old_length) != 0 ||
            !ca_witness(&old_legacy->identity, packet + 24)) return -1;
        scope->inspection->rollback_legacy_already = 1;
    }
    scope->inspection->rollback_resume_prepared = 1;
    return 0;
}

static current_rollback_publisher *cr_receiver(napi_env env, napi_callback_info info, size_t *count, napi_value *args) {
    napi_value self; bool tagged = false; current_rollback_publisher *publisher = NULL;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, count, args, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &current_rollback_publisher_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&publisher) != napi_ok || !publisher || publisher->env != env || publisher->retired) {
        migrate_scope_error(env, NULL, "invalid original rollback publisher receiver");
        return NULL;
    }
    return publisher;
}
static int cr_current(current_rollback_publisher *publisher) {
    migration_filesystem *scope = publisher->scope;
    return !publisher->retired && scope->inspection->rollback_publisher && ci_legacy_entry(scope) == 0 &&
        migrate_legacy_locks_assert_current(scope) == 0 ? 0 : -1;
}
static int cr_bind_auth_intent(migration_filesystem *scope, const unsigned char *packet, size_t size) {
    if (size != 32 || memcmp(packet, "CLQMA001", 8) || ci_le32(packet + 24) != (uint32_t)geteuid() ||
        ci_le32(packet + 28) || ci_le64(packet + 8) != ci_device(&scope->legacy) || !ci_le64(packet + 16)) return -1;
    memcpy(scope->inspection->rollback_auth_witness, packet + 8, 16); return 0;
}
static int cr_archive_complete(migration_filesystem *scope) {
    current_migration_inspection *state = scope->inspection; ci_archive *archive = state->archive;
    return archive && archive->namespace_complete && archive->manifest.verified && archive->image.verified &&
        (!archive->model_bytes || (state->model_verified && state->model_source));
}
static int cr_replace_control(migration_filesystem *scope, const unsigned char *bytes, size_t length, const char *phase) {
    migration_publication_file *current = &scope->publication->files[MP_CONTROL];
    migration_publication_file *staged = &scope->publication->files[MP_ROLLBACK_CONTROL_TEMP];
    char leaf[NAME_MAX + 1];
    int count = snprintf(leaf, sizeof(leaf), ".cliq-%s-rollback-%s.tmp", scope->inspection->archive_id, phase);
    if (count < 0 || (size_t)count >= sizeof(leaf) ||
        mp_read_hash(current, NULL) != 0 || mp_birth(scope, staged, MP_MIGRATION_PARENT, leaf, bytes, length) != 0 ||
        mp_exchange(scope, current, staged) != 0 || mp_unlink_owned(scope, current) != 0 ||
        migrate_scope_close_fd(scope, &current->fd) != 0) return -1;
    *current = *staged;
    memset(staged, 0, sizeof(*staged)); staged->fd = -1;
    return 0;
}
static napi_value cr_publish_draining(napi_env env, napi_callback_info info) {
    napi_value args[2]; size_t count = 2;
    current_rollback_publisher *publisher = cr_receiver(env, info, &count, args); if (!publisher) return NULL;
    migration_filesystem *scope = publisher->scope; current_migration_inspection *state = scope->inspection;
    const unsigned char *bytes; size_t length;
    if (count != 1 || cr_current(publisher) != 0 || publisher->phase != CR_INSPECTED || !state->trees_complete ||
        state->archive || state->auth_absent || mp_buffer(env, args[0], &bytes, &length) != 0 ||
        cr_replace_control(scope, bytes, length, "draining") != 0)
        return migrate_scope_error(env, scope, "rollback draining did not publish its fixed current control");
    state->rollback_draining = 1; publisher->phase = CR_DRAINING;
    return cr_current(publisher) == 0 ? mp_undefined(env) :
        migrate_scope_error(env, scope, "rollback draining lost original custody");
}
static napi_value cr_observe_auth_preimage(napi_env env, napi_callback_info info) {
    napi_value args[1], result; size_t count = 1;
    current_rollback_publisher *publisher = cr_receiver(env, info, &count, args); if (!publisher) return NULL;
    migration_filesystem *scope = publisher->scope;
    migration_publication_file *marker = &scope->publication->files[MP_AUTH_MARKER];
    if (count || cr_current(publisher) != 0 || publisher->phase != CR_DRAINING || scope->inspection->auth_absent ||
        !cr_archive_complete(scope) || marker->fd < 0 || mp_read_hash(marker, NULL) != 0 ||
        napi_create_object(env, &result) != napi_ok || !identity_member(env, result, "file", &marker->identity) ||
        !publication_set_string(env, result, "sha256", marker->digest) || napi_object_freeze(env, result) != napi_ok)
        return migrate_scope_error(env, scope, "rollback archive handoff requires its actual complete original auth marker");
    return result;
}
static napi_value cr_publish_archive_ready(napi_env env, napi_callback_info info) {
    napi_value args[3]; size_t count = 3;
    current_rollback_publisher *publisher = cr_receiver(env, info, &count, args); if (!publisher) return NULL;
    migration_filesystem *scope = publisher->scope;
    migration_publication_file *marker = &scope->publication->files[MP_AUTH_MARKER];
    const unsigned char *bytes, *packet; size_t length, packet_size;
    if (count != 2 || cr_current(publisher) != 0 || publisher->phase != CR_DRAINING || scope->inspection->auth_absent ||
        !cr_archive_complete(scope) || marker->fd < 0 || mp_read_hash(marker, NULL) != 0 ||
        mp_buffer(env, args[0], &bytes, &length) != 0 || ca_buffer(env, args[1], &packet, &packet_size) != 0 ||
        cr_bind_auth_intent(scope, packet, packet_size) != 0 || !ca_witness(&marker->identity, scope->inspection->rollback_auth_witness) ||
        cr_replace_control(scope, bytes, length, "archive-ready") != 0)
        return migrate_scope_error(env, scope, "rollback archive handoff did not durably bind its exact auth preimage");
    publisher->phase = CR_ARCHIVE_READY;
    return cr_current(publisher) == 0 ? mp_undefined(env) :
        migrate_scope_error(env, scope, "rollback archive handoff lost its original physical custody");
}
static napi_value cr_restore_absent(napi_env env, napi_callback_info info) {
    napi_value args[2]; size_t count = 2; char control_digest[65];
    current_rollback_publisher *publisher = cr_receiver(env, info, &count, args); if (!publisher) return NULL;
    migration_filesystem *scope = publisher->scope; current_migration_inspection *state = scope->inspection;
    migration_publication_file *control = &scope->publication->files[MP_CONTROL];
    if (count != 1 || cr_current(publisher) != 0 || publisher->phase != CR_ARCHIVE_READY || !cr_archive_complete(scope) ||
        migrate_scope_text(env, args[0], control_digest, sizeof(control_digest)) != 0 || strlen(control_digest) != 64 ||
        mp_read_hash(control, NULL) != 0 || strcmp(control_digest, control->digest) ||
        (state->auth_absent && !state->rollback_resume_archive_ready))
        return migrate_scope_error(env, scope, "auth removal requires the complete original archive and exact original marker");
    migration_publication_file *marker = &scope->publication->files[MP_AUTH_MARKER];
    struct stat original = marker->identity;
    const int observed_absent = state->auth_absent;
    if (observed_absent ? marker->fd >= 0 || mp_absent(scope, MP_LEGACY_PARENT, "auth.json") != 0 ||
        fsync(scope->legacy_fd) != 0 || mp_absent(scope, MP_LEGACY_PARENT, "auth.json") != 0 :
        marker->fd < 0 || !ca_witness(&original, state->rollback_auth_witness) || mp_read_hash(marker, NULL) != 0 ||
        mp_unlink_owned(scope, marker) != 0 || mp_absent(scope, MP_LEGACY_PARENT, "auth.json") != 0 ||
        migrate_scope_close_fd(scope, &marker->fd) != 0)
        return migrate_scope_error(env, scope, "original auth marker removal did not finish durably");
    state->auth_absent = 1; publisher->pre_auth_scan = state->scan_epoch; publisher->phase = CR_AUTH_ABSENT;
    napi_value result;
    if (cr_current(publisher) != 0 || napi_create_object(env, &result) != napi_ok ||
        (!observed_absent && !identity_member(env, result, "previousMarkerFile", &original)) ||
        !publication_set_string(env, result, "kind", observed_absent ?
            "original_intent_current_absence_and_directory_synced" : "exact_marker_removed_and_directory_synced") ||
        napi_object_freeze(env, result) != napi_ok)
        return migrate_scope_error(env, scope, "auth absence lacks its complete original physical observation");
    return result;
}
static napi_value cr_stage_markers(napi_env env, napi_callback_info info) {
    napi_value args[2]; size_t count = 2;
    current_rollback_publisher *publisher = cr_receiver(env, info, &count, args); if (!publisher) return NULL;
    migration_filesystem *scope = publisher->scope; current_migration_inspection *state = scope->inspection;
    const unsigned char *bytes; size_t length;
    if (count != 1 || cr_current(publisher) != 0 || publisher->phase != CR_AUTH_ABSENT || !state->auth_absent ||
        !state->trees_complete || state->scan_epoch <= publisher->pre_auth_scan ||
        mp_buffer(env, args[0], &bytes, &length) != 0)
        return migrate_scope_error(env, scope, "marker staging requires its current complete restored Legacy tree");
    migration_publication_file *root = &scope->publication->files[MP_ROLLBACK_ROOT_PREPARED];
    migration_publication_file *legacy = &scope->publication->files[MP_ROLLBACK_LEGACY_PREPARED];
    char leaf[NAME_MAX + 1];
    if (cr_marker_temp(scope, leaf) != 0 ||
        mp_birth(scope, root, MP_MIGRATION_PARENT, leaf, bytes, length) != 0 ||
        mp_birth(scope, legacy, MP_LEGACY_PARENT, leaf, bytes, length) != 0 ||
        root->byte_count != legacy->byte_count || strcmp(root->digest, legacy->digest) ||
        same_inode(&root->identity, &legacy->identity))
        return migrate_scope_error(env, scope, "both exact Legacy authority marker copies must durably stage");
    publisher->phase = CR_MARKERS_STAGED;
    napi_value result;
    if (cr_current(publisher) != 0 || napi_create_object(env, &result) != napi_ok ||
        !identity_member(env, result, "rootFile", &root->identity) ||
        !identity_member(env, result, "legacyFile", &legacy->identity) ||
        !identity_member(env, result, "originalRootFile", &scope->publication->files[MP_AUTHORITY_ROOT].identity) ||
        !identity_member(env, result, "originalLegacyFile", &scope->publication->files[MP_AUTHORITY_LEGACY].identity) ||
        !publication_set_string(env, result, "contentDigest", root->digest) ||
        napi_object_freeze(env, result) != napi_ok)
        return migrate_scope_error(env, scope, "prepared markers lack exact original source identities");
    return result;
}
static napi_value cr_publish_restoring(napi_env env, napi_callback_info info) {
    napi_value args[2]; size_t count = 2;
    current_rollback_publisher *publisher = cr_receiver(env, info, &count, args); if (!publisher) return NULL;
    migration_filesystem *scope = publisher->scope; const unsigned char *bytes; size_t length;
    if (count != 1 || cr_current(publisher) != 0 || publisher->phase != CR_MARKERS_STAGED ||
        mp_buffer(env, args[0], &bytes, &length) != 0 || cr_replace_control(scope, bytes, length, "restoring") != 0)
        return migrate_scope_error(env, scope, "restoring control did not bind the original staged markers");
    publisher->phase = CR_RESTORING;
    return cr_current(publisher) == 0 ? mp_undefined(env) :
        migrate_scope_error(env, scope, "restoring control lost original custody");
}
static napi_value cr_publish_markers(napi_env env, napi_callback_info info) {
    napi_value args[1]; size_t count = 1;
    current_rollback_publisher *publisher = cr_receiver(env, info, &count, args); if (!publisher) return NULL;
    migration_filesystem *scope = publisher->scope;
    if (count || cr_current(publisher) != 0 || publisher->phase != CR_RESTORING)
        return migrate_scope_error(env, scope, "authority publication requires its exact prepared restoring scope");
    migration_publication_file *root = &scope->publication->files[MP_ROLLBACK_ROOT_PREPARED];
    migration_publication_file *legacy = &scope->publication->files[MP_ROLLBACK_LEGACY_PREPARED];
    migration_publication_file *old_root = &scope->publication->files[MP_AUTHORITY_ROOT];
    migration_publication_file *old_legacy = &scope->publication->files[MP_AUTHORITY_LEGACY];
    if (mp_read_hash(root, NULL) != 0 || mp_read_hash(legacy, NULL) != 0 ||
        root->byte_count != legacy->byte_count || strcmp(root->digest, legacy->digest) ||
        mp_read_hash(old_root, NULL) != 0 || mp_read_hash(old_legacy, NULL) != 0 ||
        (scope->inspection->rollback_legacy_already ? fsync(scope->legacy_fd) != 0 : mp_exchange(scope, old_legacy, legacy) != 0) ||
        cr_current(publisher) != 0 ||
        mp_exchange(scope, old_root, root) != 0)
        return migrate_scope_error(env, scope, "prepared Legacy-first and StateRoot-last authority publication failed");
    /* Displaced original markers retain their identities at fixed staged
     * names. After the Root exchange and fsync only actual retirement follows. */
    publisher->phase = CR_PUBLISHED; return mp_undefined(env);
}
static napi_value cr_close(napi_env env, napi_callback_info info) {
    napi_value args[1]; size_t count = 1;
    current_rollback_publisher *publisher = cr_receiver(env, info, &count, args); if (!publisher) return NULL;
    migration_filesystem *scope = publisher->scope;
    if (count) return migrate_scope_error(env, scope, "rollback publisher close accepts no arguments");
    if (scope->inspection->original_archive_borrowed)
        return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "rollback publisher has its live original archive borrow");
    if (!scope->inspection->rollback_publisher || !publisher->inspector_ref ||
        migration_credential_check(scope->binding, env) != 0 || napi_delete_reference(env, publisher->inspector_ref) != napi_ok) {
        migrate_scope_poison(scope);
        return migrate_scope_error(env, scope, "rollback publisher did not retire its original inspector borrow");
    }
    publisher->inspector_ref = NULL; publisher->retired = 1; publisher->scope = NULL;
    scope->inspection->rollback_publisher = 0;
    return mp_undefined(env);
}
static void cr_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    current_rollback_publisher *publisher = data;
    if (publisher->retired) free(publisher);
}
static napi_value create_current_rollback_publisher(napi_env env, napi_callback_info info) {
    napi_value args[2]; size_t count = 2; bool tagged = false; migration_filesystem *scope = NULL;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, args, NULL, NULL) != napi_ok || count != 1 ||
        napi_check_object_type_tag(env, args[0], &current_migration_inspector_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, args[0], (void **)&scope) != napi_ok || !scope || !scope->inspection || scope->env != env ||
        scope->inspection->rollback_publisher || !scope->inspection->trees_complete ||
        ci_legacy_entry(scope) != 0 || migrate_legacy_locks_assert_current(scope) != 0)
        return migrate_scope_error(env, NULL, "rollback publisher requires its genuine current original source and locks");
    current_migration_inspection *state = scope->inspection; ci_archive *archive = state->archive;
    if (state->rollback_resume_prepared || state->rollback_resume_archive_ready) {
        if ((state->rollback_resume_prepared && !state->auth_absent) || !cr_archive_complete(scope))
            return migrate_scope_error(env, scope, "rollback successor requires the complete original archive and prepared absence");
    } else if (archive || state->auth_absent)
        return migrate_scope_error(env, scope, "first rollback publication requires its exact original marker before archive birth");
    current_rollback_publisher *publisher = calloc(1, sizeof(*publisher));
    if (!publisher) return migrate_scope_error(env, scope, "rollback publisher allocation failed");
    publisher->scope = scope; publisher->env = env;
    publisher->phase = state->rollback_resume_prepared ? CR_RESTORING : state->rollback_resume_archive_ready ? CR_ARCHIVE_READY : CR_INSPECTED;
    const napi_property_descriptor methods[] = {
        {"publishDraining", NULL, cr_publish_draining, NULL, NULL, NULL, napi_default, NULL},
        {"observeAuthPreimage", NULL, cr_observe_auth_preimage, NULL, NULL, NULL, napi_default, NULL},
        {"publishArchiveReady", NULL, cr_publish_archive_ready, NULL, NULL, NULL, napi_default, NULL},
        {"restoreAbsentAuth", NULL, cr_restore_absent, NULL, NULL, NULL, napi_default, NULL},
        {"stageLegacyAuthority", NULL, cr_stage_markers, NULL, NULL, NULL, napi_default, NULL},
        {"publishRestoring", NULL, cr_publish_restoring, NULL, NULL, NULL, napi_default, NULL},
        {"publishPreparedAuthority", NULL, cr_publish_markers, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, cr_close, NULL, NULL, NULL, napi_default, NULL}
    };
    napi_value result;
    if (napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &current_rollback_publisher_tag) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_create_reference(env, args[0], 1, &publisher->inspector_ref) != napi_ok) {
        free(publisher); return migrate_scope_error(env, scope, "rollback publisher cannot retain its genuine inspector");
    }
    if (napi_wrap(env, result, publisher, cr_finalize, NULL, NULL) != napi_ok) {
        if (napi_delete_reference(env, publisher->inspector_ref) != napi_ok) { migrate_scope_poison(scope); return migrate_scope_error(env, scope, "rollback publisher borrow is uncertain"); }
        free(publisher); return migrate_scope_error(env, scope, "rollback publisher receiver did not bind");
    }
    scope->inspection->rollback_publisher = 1; return result;
}
