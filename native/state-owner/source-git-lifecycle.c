/* Fixed byte decoding only. No observation, descriptor or permission is
 * minted by this export; the current physical checker remains separate. */
#include "../linux/source-git-history-data.h"

static int source_lifecycle_number(napi_env env, napi_value result, const char *key, double number) {
    napi_value value;
    return napi_create_double(env, number, &value) == napi_ok && napi_set_named_property(env, result, key, value) == napi_ok;
}
static int source_lifecycle_decimal(napi_env env, napi_value result, const char *key, uint64_t number) {
    char value[32]; snprintf(value, sizeof(value), "%llu", (unsigned long long)number);
    return string_property(env, result, key, value);
}
static int source_lifecycle_directory(napi_env env, napi_value result, const char *key,
    const struct cliq_source_directory_identity *directory) {
    napi_value value;
    return napi_create_object(env, &value) == napi_ok &&
        source_lifecycle_decimal(env, value, "deviceId", directory->device) &&
        source_lifecycle_decimal(env, value, "fileId", directory->inode) &&
        source_lifecycle_number(env, value, "ownerUid", (double)directory->uid) &&
        source_lifecycle_number(env, value, "ownerGid", (double)directory->gid) &&
        source_lifecycle_number(env, value, "mode", (double)(directory->mode & 07777)) &&
        napi_object_freeze(env, value) == napi_ok && napi_set_named_property(env, result, key, value) == napi_ok;
}
static int source_lifecycle_maybe_text(napi_env env, napi_value result, const char *key, const char *text) {
    if (text) return string_property(env, result, key, text);
    napi_value value;
    return napi_get_null(env, &value) == napi_ok && napi_set_named_property(env, result, key, value) == napi_ok;
}
static int source_lifecycle_process(napi_env env, napi_value list, uint32_t index, const char *role, int64_t pid, const char *token) {
    napi_value value;
    return napi_create_object(env, &value) == napi_ok && string_property(env, value, "role", role) &&
        source_lifecycle_number(env, value, "pid", (double)pid) && string_property(env, value, "processStartToken", token) &&
        napi_object_freeze(env, value) == napi_ok && napi_set_element(env, list, index, value) == napi_ok;
}
static napi_value decode_source_git_lifecycle(napi_env env, napi_callback_info info) {
    napi_value args[1], result, processes, backing; size_t argc = 1, length = 0, offset = 0;
    void *bytes = NULL; bool array = false; napi_typedarray_type type;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1 ||
        napi_is_typedarray(env, args[0], &array) != napi_ok || !array ||
        napi_get_typedarray_info(env, args[0], &type, &length, &bytes, &backing, &offset) != napi_ok ||
        type != napi_uint8_array || length < sizeof(struct cliq_source_birth) ||
        length > CLIQ_SOURCE_HISTORY_MAX_BYTES) return native_error(env, "invalid fixed source lifecycle bytes");
    struct cliq_source_birth header; memcpy(&header, bytes, sizeof(header));
    struct cliq_source_history history; struct cliq_source_retirement_data projection;
    if (!cliq_source_history_decode(bytes, length, &header, &history) ||
        !cliq_source_retirement_project(&history, &projection)) return native_error(env, "source lifecycle has incomplete original provenance");
    unsigned char digest[32]; struct sha256_context hash; sha256_init(&hash); sha256_update(&hash, bytes, length); sha256_final(&hash, digest);
    char hex[65]; static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) { hex[i * 2] = alphabet[digest[i] >> 4]; hex[i * 2 + 1] = alphabet[digest[i] & 15]; } hex[64] = '\0';
    struct cliq_source_directory_identity staging = { .device = header.staging_device, .inode = header.staging_inode,
        .uid = header.owner_uid, .gid = header.staging_gid, .mode = S_IFDIR | 0700 };
    if (napi_create_object(env, &result) != napi_ok ||
        !string_property(env, result, "format", "cliq-source-native-lifecycle-v2") ||
        !string_property(env, result, "lifecycleDigest", hex) || !source_lifecycle_number(env, result, "byteCount", (double)length) ||
        !string_property(env, result, "inspectionId", header.inspection_id) || !string_property(env, result, "stagingNonceDigest", header.staging_nonce) ||
        !string_property(env, result, "targetRef", header.target_ref) || !string_property(env, result, "inputIntentRef", header.input_intent_ref) ||
        !source_lifecycle_directory(env, result, "stateRoot", &header.state_root) ||
        !source_lifecycle_directory(env, result, "runtime", &header.runtime) ||
        !source_lifecycle_directory(env, result, "sourceParent", &header.source_parent) ||
        !source_lifecycle_directory(env, result, "staging", &staging) ||
        !source_lifecycle_decimal(env, result, "workspaceDeviceId", header.workspace_device) ||
        !source_lifecycle_decimal(env, result, "workspaceFileId", header.workspace_inode) ||
        !source_lifecycle_decimal(env, result, "gitDeviceId", header.git_device) ||
        !source_lifecycle_decimal(env, result, "gitFileId", header.git_inode) ||
        !source_lifecycle_number(env, result, "originalSupervisorPid", (double)header.supervisor_pid) ||
        !string_property(env, result, "originalSupervisorStartToken", header.supervisor_start_token) ||
        !source_lifecycle_directory(env, result, "controllerRoot", &history.creator.root) ||
        !source_lifecycle_directory(env, result, "controllerParent", &history.creator.parent) ||
        !source_lifecycle_directory(env, result, "controllerLeaf", &history.creator.leaf) ||
        !string_property(env, result, "controllerLeafName", history.creator.leaf_name) ||
        !source_lifecycle_number(env, result, "originalControllerPid", (double)history.creator.pid) ||
        !string_property(env, result, "originalControllerStartToken", history.creator.process_start_token) ||
        !source_lifecycle_number(env, result, "recordCount", history.count) ||
        !source_lifecycle_number(env, result, "lastBirthKind", projection.last_kind) ||
        !source_lifecycle_number(env, result, "reserved", projection.reserved ? 1 : 0) ||
        !source_lifecycle_number(env, result, "blocked", projection.blocked ? 1 : 0) ||
        !source_lifecycle_number(env, result, "released", projection.released ? 1 : 0) ||
        !source_lifecycle_number(env, result, "continued", projection.continued ? 1 : 0) ||
        !source_lifecycle_maybe_text(env, result, "launchNonceDigest", projection.launch_nonce) ||
        !source_lifecycle_maybe_text(env, result, "containmentPlanRef", projection.plan_ref) ||
        !source_lifecycle_maybe_text(env, result, "sandboxLaunchRef", projection.sandbox_launch_ref) ||
        !source_lifecycle_maybe_text(env, result, "sandboxLaunchDigest", projection.sandbox_launch_digest)) return NULL;
    if (history.ready.pid) {
        if (!source_lifecycle_decimal(env, result, "pidNamespaceId", history.ready.pid_namespace_inode)) return NULL;
    } else if (!source_lifecycle_maybe_text(env, result, "pidNamespaceId", NULL)) return NULL;
    if (projection.reserved) {
        if (!source_lifecycle_decimal(env, result, "cgroupDeviceId", projection.cgroup_device) ||
            !source_lifecycle_decimal(env, result, "cgroupId", projection.cgroup_inode)) return NULL;
    } else if (!source_lifecycle_maybe_text(env, result, "cgroupDeviceId", NULL) ||
        !source_lifecycle_maybe_text(env, result, "cgroupId", NULL)) return NULL;
    napi_value birth;
    if (napi_create_object(env, &birth) != napi_ok ||
        !source_lifecycle_decimal(env, birth, "deviceId", header.birth_device) ||
        !source_lifecycle_decimal(env, birth, "fileId", header.birth_inode) ||
        !source_lifecycle_number(env, birth, "ownerUid", (double)header.owner_uid) ||
        napi_object_freeze(env, birth) != napi_ok || napi_set_named_property(env, result, "birthIdentity", birth) != napi_ok) return NULL;
    if (napi_create_array(env, &processes) != napi_ok) return NULL;
    uint32_t at = 0;
    if (history.monitor.monitor_pid && !source_lifecycle_process(env, processes, at++, "monitor", history.monitor.monitor_pid, history.monitor.monitor_start_token)) return NULL;
    if (history.ready.pid && (!source_lifecycle_process(env, processes, at++, "worker", history.ready.pid, history.ready.start_token) ||
        !source_lifecycle_process(env, processes, at++, "namespace_init", history.ready.namespace_init_pid, history.ready.init_native_start_token))) return NULL;
    if (napi_object_freeze(env, processes) != napi_ok || napi_set_named_property(env, result, "processes", processes) != napi_ok) return NULL;
    if (projection.snapshot && (!string_property(env, result, "snapshotDigest", projection.snapshot->source_snapshot_digest) ||
        !source_lifecycle_number(env, result, "sourceByteCount", (double)projection.snapshot->source_byte_count) ||
        !source_lifecycle_number(env, result, "entryCount", (double)projection.snapshot->source_entry_count) ||
        !source_lifecycle_number(env, result, "shardCount", (double)projection.snapshot->source_shard_count))) return NULL;
    return napi_object_freeze(env, result) == napi_ok ? result : NULL;
}
