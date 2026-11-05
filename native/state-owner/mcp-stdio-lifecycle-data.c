/* Portable pure raw/hash-chain projection. These values are retained audit
 * data, not live scope, current process death or permission to clean up. */
#include "../linux/mcp-stdio-protocol.h"
static napi_value stdio_input_binding_value(napi_env env, const struct cliq_mcp_stdio_history *history) {
    napi_value value; napi_create_object(env, &value);
    int64_t pid; const char *token;
    if (history->purpose == CLIQ_MCP_STDIO_ADMIN) {
        const struct cliq_mcp_admin_birth *h = &history->header.admin;
        string_property(env, value, "kind", "admin");
        string_property(env, value, "adminOperationId", h->operation); string_property(env, value, "principalId", h->principal);
        string_property(env, value, "nonce", h->nonce); admin_mcp_data_number(env, value, "attempt", h->attempt);
        string_property(env, value, "targetRef", h->target_ref); string_property(env, value, "targetDigest", h->target_digest);
        string_property(env, value, "probePayloadCoreRef", h->core_ref); string_property(env, value, "probePayloadCoreDigest", h->core_digest);
        string_property(env, value, "plannedContainmentRef", h->plan_ref); string_property(env, value, "plannedContainmentDigest", h->plan_digest);
        string_property(env, value, "sandboxLaunchSpecRef", h->spec_ref); string_property(env, value, "sandboxLaunchSpecDigest", h->spec_digest);
        pid = h->supervisor_pid; token = h->supervisor_start_token;
    } else if (history->purpose == CLIQ_MCP_STDIO_RECOVERY) {
        const struct cliq_mcp_stdio_recovery_identity *id = &history->header.recovery.identity;
        string_property(env, value, "kind", "recovery");
#define RECOVERY_PROJECT_TEXT(field, capacity) string_property(env, value, #field, id->field);
        CLIQ_MCP_STDIO_RECOVERY_TEXT_FIELDS(RECOVERY_PROJECT_TEXT)
        CLIQ_MCP_STDIO_RECOVERY_DIGEST_FIELDS(RECOVERY_PROJECT_TEXT)
#undef RECOVERY_PROJECT_TEXT
#define RECOVERY_PROJECT_NUMBER(field, minimum) admin_mcp_data_number(env, value, #field, id->field);
        CLIQ_MCP_STDIO_RECOVERY_NUMBER_FIELDS(RECOVERY_PROJECT_NUMBER)
#undef RECOVERY_PROJECT_NUMBER
        pid = history->header.recovery.supervisor_pid; token = history->header.recovery.supervisor_start_token;
    } else {
        const struct cliq_mcp_stdio_run_identity *id = &history->header.run.identity;
        string_property(env, value, "kind", "run");
#define STDIO_BIND_TEXT(key, field) string_property(env, value, key, id->field)
        STDIO_BIND_TEXT("runId", run); STDIO_BIND_TEXT("principalId", principal); STDIO_BIND_TEXT("launchOpId", launch_op);
        STDIO_BIND_TEXT("batchItemId", batch_item); STDIO_BIND_TEXT("callId", call); STDIO_BIND_TEXT("workerLaunchId", worker_launch);
        STDIO_BIND_TEXT("supervisorInstanceId", supervisor); STDIO_BIND_TEXT("nonce", nonce); STDIO_BIND_TEXT("registryRef", registry_ref);
        STDIO_BIND_TEXT("manifestDigest", manifest_digest); STDIO_BIND_TEXT("toolRequestRef", tool_request_ref); STDIO_BIND_TEXT("toolRequestDigest", tool_request_digest);
        STDIO_BIND_TEXT("requestRef", launch_request_ref); STDIO_BIND_TEXT("requestDigest", launch_request_digest);
        STDIO_BIND_TEXT("targetRef", target_ref); STDIO_BIND_TEXT("targetDigest", target_digest); STDIO_BIND_TEXT("grantRef", grant_ref); STDIO_BIND_TEXT("grantDigest", grant_digest);
        STDIO_BIND_TEXT("plannedContainmentRef", plan_ref); STDIO_BIND_TEXT("plannedContainmentDigest", plan_digest);
        STDIO_BIND_TEXT("sandboxLaunchSpecRef", spec_ref); STDIO_BIND_TEXT("sandboxLaunchSpecDigest", spec_digest);
#undef STDIO_BIND_TEXT
#define STDIO_BIND_NUMBER(key, field) admin_mcp_data_number(env, value, key, id->field)
        STDIO_BIND_NUMBER("attempt", launch_attempt); STDIO_BIND_NUMBER("lifecycleSeq", lifecycle_seq); STDIO_BIND_NUMBER("callIndex", call_index);
        STDIO_BIND_NUMBER("leaseEpoch", lease_epoch); STDIO_BIND_NUMBER("stateOwnerEpoch", owner_epoch);
        STDIO_BIND_NUMBER("callDeadlineMs", call_deadline_ms); STDIO_BIND_NUMBER("launchDeadlineMs", launch_deadline_ms);
#undef STDIO_BIND_NUMBER
        pid = history->header.run.supervisor_pid; token = history->header.run.supervisor_start_token;
    }
    admin_mcp_data_number(env, value, "originalSupervisorPid", (uint64_t)pid);
    string_property(env, value, "originalSupervisorStartToken", token);
    napi_object_freeze(env, value); return value;
}
static napi_value stdio_process_value(napi_env env, int64_t pid, const char *token) {
    napi_value value; napi_create_object(env, &value);
    admin_mcp_data_number(env, value, "pid", (uint64_t)pid); string_property(env, value, "processStartToken", token);
    napi_object_freeze(env, value); return value;
}
static napi_value stdio_reservation_value(napi_env env, const struct cliq_worker_packet *packet) {
    napi_value value; napi_create_object(env, &value);
    string_property(env, value, "cgroupName", packet->cgroup_name);
    char text[32]; snprintf(text, sizeof(text), "%llu", (unsigned long long)packet->cgroup_device); string_property(env, value, "cgroupDevice", text);
    snprintf(text, sizeof(text), "%llu", (unsigned long long)packet->cgroup_inode); string_property(env, value, "cgroupInode", text);
    napi_object_freeze(env, value); return value;
}
static napi_value stdio_image_value(napi_env env, const char *digest, uint64_t bytes) {
    napi_value value; napi_create_object(env, &value);
    string_property(env, value, "digest", digest); admin_mcp_data_number(env, value, "byteCount", bytes);
    napi_object_freeze(env, value); return value;
}
static napi_value decode_mcp_stdio_cleanup_for(napi_env env, napi_callback_info info, bool recovery) {
    size_t argc = 2, size = 0; napi_value args[2]; bool buffer = false; void *bytes = NULL;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1 ||
        napi_is_buffer(env, args[0], &buffer) != napi_ok || !buffer || napi_get_buffer_info(env, args[0], &bytes, &size) != napi_ok)
        return native_error(env, "Invalid bounded MCP stdio cleanup data");
    struct cliq_mcp_stdio_cleanup_header cleanup; struct cliq_mcp_stdio_history original;
    if (!cliq_mcp_stdio_cleanup_bytes(bytes, size, &cleanup, &original) || (original.purpose == CLIQ_MCP_STDIO_RECOVERY) != recovery)
        return native_error(env, "Invalid complete MCP stdio current cleanup data");
    napi_value value, current, flag; napi_create_object(env, &value);
    admin_mcp_data_number(env, value, "schemaVersion", 1); string_property(env, value, "format", recovery ? "cliq-mcp-stdio-recovery-native-cleanup-v1" : "cliq-mcp-stdio-native-cleanup-v1");
    napi_set_named_property(env, value, "originalBinding", stdio_input_binding_value(env, &original));
    string_property(env, value, "originalBirthDigest", cleanup.retirement.stdio_original_birth_digest);
    napi_set_named_property(env, value, "originalController", stdio_process_value(env, original.first.controller_pid, original.first.controller_start_token));
    napi_set_named_property(env, value, "originalReservation", stdio_reservation_value(env, &original.last.packet));
    napi_create_object(env, &current); string_property(env, current, "supervisorInstanceId", cleanup.checker_supervisor);
    admin_mcp_data_number(env, current, "stateOwnerEpoch", cleanup.checker_owner_epoch);
    admin_mcp_data_number(env, current, "supervisorPid", (uint64_t)cleanup.checker_supervisor_pid);
    string_property(env, current, "supervisorStartToken", cleanup.checker_supervisor_token);
    admin_mcp_data_number(env, current, "controllerPid", (uint64_t)cleanup.checker_controller_pid);
    string_property(env, current, "controllerStartToken", cleanup.checker_controller_token);
    napi_object_freeze(env, current); napi_set_named_property(env, value, "currentChecker", current);
    napi_set_named_property(env, value, "retirement", admin_mcp_packet_value(env, &cleanup.retirement));
    admin_mcp_data_number(env, value, "observedAtMs", cleanup.retirement.observed_at_ms);
    napi_get_boolean(env, true, &flag); napi_set_named_property(env, value, "priorSupervisorDead", flag);
    napi_set_named_property(env, value, "priorControllerDead", flag); napi_set_named_property(env, value, "outputCustodyRetired", flag);
    admin_mcp_data_number(env, value, "remainingDescendants", 0); napi_object_freeze(env, value); return value;
}
static napi_value decode_mcp_stdio_lifecycle_for(napi_env env, napi_callback_info info, bool recovery) {
    size_t argc = 2, size = 0; napi_value args[2]; bool buffer = false; void *bytes = NULL;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1 || napi_is_buffer(env, args[0], &buffer) != napi_ok || !buffer ||
        napi_get_buffer_info(env, args[0], &bytes, &size) != napi_ok || size > sizeof(((struct cliq_mcp_stdio_history *)0)->header) +
        CLIQ_MCP_STDIO_MAX_PROGRESS * sizeof(struct cliq_mcp_stdio_progress)) return native_error(env, "Invalid bounded MCP stdio lifecycle data");
    struct cliq_mcp_stdio_history history;
    if (!cliq_mcp_stdio_history_bytes(bytes, size, &history) || (history.purpose == CLIQ_MCP_STDIO_RECOVERY) != recovery) return native_error(env, "Invalid complete original MCP stdio lifecycle hashchain");
    napi_value value, observation, joined; napi_create_object(env, &value);
    admin_mcp_data_number(env, value, "schemaVersion", 1); string_property(env, value, "format", recovery ? "cliq-mcp-stdio-recovery-native-lifecycle-v1" : "cliq-mcp-stdio-native-lifecycle-v1");
    napi_set_named_property(env, value, "binding", stdio_input_binding_value(env, &history));
    const struct cliq_mcp_admin_directory *root, *runtime, *parent, *birth; int64_t pid; const char *token;
    if (history.purpose == CLIQ_MCP_STDIO_ADMIN) {
        root = &history.header.admin.state_root; runtime = &history.header.admin.runtime; parent = &history.header.admin.admin_parent; birth = &history.header.admin.birth;
        pid = history.header.admin.supervisor_pid; token = history.header.admin.supervisor_start_token;
    } else if (recovery) {
        root = &history.header.recovery.state_root; runtime = &history.header.recovery.runtime;
        parent = &history.header.recovery.private_parent; birth = &history.header.recovery.birth;
        pid = history.header.recovery.supervisor_pid; token = history.header.recovery.supervisor_start_token;
    } else {
        root = &history.header.run.state_root; runtime = &history.header.run.runtime; parent = &history.header.run.private_parent; birth = &history.header.run.birth;
        pid = history.header.run.supervisor_pid; token = history.header.run.supervisor_start_token;
    }
    napi_set_named_property(env, value, "originalSupervisor", stdio_process_value(env, pid, token));
    napi_set_named_property(env, value, "stateRootIdentity", admin_mcp_identity_value(env, root));
    napi_set_named_property(env, value, "runtimeIdentity", admin_mcp_identity_value(env, runtime));
    napi_set_named_property(env, value, "privateParentIdentity", admin_mcp_identity_value(env, parent));
    napi_set_named_property(env, value, "birthIdentity", admin_mcp_identity_value(env, birth));
    napi_set_named_property(env, value, "controller", stdio_process_value(env, history.count ? history.first.controller_pid : 0, history.count ? history.first.controller_start_token : ""));
    napi_value images; napi_create_object(env, &images);
    napi_set_named_property(env, images, "server", stdio_image_value(env, history.last.packet.stdio_server_digest, history.last.packet.stdio_server_bytes));
    napi_set_named_property(env, images, "client", stdio_image_value(env, history.last.packet.stdio_init_digest, history.last.packet.stdio_init_bytes));
    napi_set_named_property(env, images, "isolation", stdio_image_value(env, history.last.packet.stdio_bwrap_digest, history.last.packet.stdio_bwrap_bytes));
    napi_set_named_property(env, images, "recipe", stdio_image_value(env, history.last.packet.stdio_recipe_digest, history.last.packet.stdio_recipe_bytes));
    napi_object_freeze(env, images); napi_set_named_property(env, value, "images", images);
    napi_set_named_property(env, value, "reservation", stdio_reservation_value(env, &history.last.packet));
    if (history.ready.kind == 5) observation = admin_mcp_packet_value(env, &history.ready.packet); else napi_get_null(env, &observation);
    napi_set_named_property(env, value, "containment", observation);
    if (history.count && history.last.kind >= 8) observation = admin_mcp_packet_value(env, &history.last.packet); else napi_get_null(env, &observation);
    napi_set_named_property(env, value, "retirement", observation);
    napi_create_object(env, &joined);
    bool dead = history.count && history.last.kind >= 8 && !history.last.packet.populated && !history.last.packet.remaining_descendants && (!history.ready.kind || history.last.packet.init_reaped == 1);
    admin_mcp_data_bool(env, joined, "deathJoined", dead);
    admin_mcp_data_bool(env, joined, "outputCustodyRetired", dead && history.last.kind == 9);
    admin_mcp_data_bool(env, joined, "protocolCompleted", history.count && history.last.packet.stdio_protocol_complete == 1);
    admin_mcp_data_bool(env, joined, "execReleased", history.exec_released);
    admin_mcp_data_bool(env, joined, recovery ? "statusReleased" : "effectReleased", history.count && history.last.packet.stdio_operation_released == 1);
    admin_mcp_data_bool(env, joined, "responseRefused", history.count && history.last.packet.stdio_response_refused == 1);
    admin_mcp_data_bool(env, joined, "ownerDrained", history.count && history.last.packet.stdio_owner_drained == 1);
    admin_mcp_data_bool(env, joined, "spawnAttempted", history.spawn_attempted);
    napi_object_freeze(env, joined); napi_set_named_property(env, value, "joined", joined);
    admin_mcp_data_number(env, value, "progressKind", history.count ? history.last.kind : 0);
    const unsigned char *digest = history.count ? history.last.digest : cliq_mcp_stdio_header_digest(&history);
    char text[65]; for (size_t i = 0; i < 32; i++) snprintf(text + i * 2, 3, "%02x", digest[i]); string_property(env, value, "progressDigest", text);
    napi_object_freeze(env, value); return value;
}

static napi_value decode_mcp_stdio_lifecycle(napi_env env, napi_callback_info info) { return decode_mcp_stdio_lifecycle_for(env, info, false); }
static napi_value decode_mcp_stdio_cleanup(napi_env env, napi_callback_info info) { return decode_mcp_stdio_cleanup_for(env, info, false); }
static napi_value decode_mcp_stdio_recovery_lifecycle(napi_env env, napi_callback_info info) { return decode_mcp_stdio_lifecycle_for(env, info, true); }
static napi_value decode_mcp_stdio_recovery_cleanup(napi_env env, napi_callback_info info) { return decode_mcp_stdio_cleanup_for(env, info, true); }

