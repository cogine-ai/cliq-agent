/* Pure two-source data projection. A copied header never becomes the opaque
 * original scope's current observation or permission to perform any action. */
#include "../linux/mcp-admin-original-retirement.h"
static napi_value decode_mcp_admin_original_retirement(napi_env env, napi_callback_info info) {
    size_t argc = 3, size = 0, original_size = 0; napi_value args[3]; bool first = false, second = false;
    void *bytes = NULL, *original = NULL;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 2 ||
        napi_is_buffer(env, args[0], &first) != napi_ok || !first || napi_is_buffer(env, args[1], &second) != napi_ok || !second ||
        napi_get_buffer_info(env, args[0], &bytes, &size) != napi_ok ||
        napi_get_buffer_info(env, args[1], &original, &original_size) != napi_ok)
        return native_error(env, "Invalid MCP Admin original current observation data");
    struct cliq_mcp_admin_original_retirement data; struct cliq_mcp_admin_original_source source;
    if (!cliq_mcp_admin_original_retirement_bytes(bytes, size, original, original_size, &data, &source))
        return native_error(env, "MCP Admin current observation differs from its full original closed source");
    napi_value result, observer, process, reservation;
    napi_create_object(env, &result); admin_mcp_data_number(env, result, "schemaVersion", 1);
    string_property(env, result, "format", "cliq-mcp-admin-original-retirement-v1");
    string_property(env, result, "transport", data.transport == CLIQ_MCP_ADMIN_ORIGINAL_HTTP ? "streamable_http" : "stdio");
    napi_set_named_property(env, result, "originalBinding", admin_mcp_binding_value(env, &source.binding));
    char text[65]; for (size_t i = 0; i < 32; i++) snprintf(text + i * 2, 3, "%02x", data.original_digest[i]);
    string_property(env, result, "originalLifecycleRef", text); admin_mcp_data_number(env, result, "originalLifecycleByteCount", data.original_bytes);
    napi_create_object(env, &observer); string_property(env, observer, "supervisorInstanceId", data.observer_supervisor);
    admin_mcp_data_number(env, observer, "stateOwnerEpoch", data.observer_epoch); admin_mcp_data_number(env, observer, "supervisorPid", (uint64_t)data.observer_pid);
    string_property(env, observer, "supervisorStartToken", data.observer_token); napi_object_freeze(env, observer);
    napi_set_named_property(env, result, "currentObserver", observer);
    napi_set_named_property(env, result, "stateRootIdentity", admin_mcp_identity_value(env, &source.binding.state_root));
    napi_set_named_property(env, result, "runtimeIdentity", admin_mcp_identity_value(env, &source.binding.runtime));
    napi_set_named_property(env, result, "privateParentIdentity", admin_mcp_identity_value(env, &source.binding.admin_parent));
    napi_set_named_property(env, result, "birthIdentity", admin_mcp_identity_value(env, &source.binding.birth));
    napi_set_named_property(env, result, "controllerRootIdentity", admin_mcp_identity_value(env, &source.root));
    napi_create_object(env, &process); admin_mcp_data_number(env, process, "pid", (uint64_t)source.controller_pid);
    string_property(env, process, "processStartToken", source.controller_token); napi_object_freeze(env, process);
    napi_set_named_property(env, result, "originalController", process);
    napi_create_object(env, &reservation); string_property(env, reservation, "cgroupName", source.last.cgroup_name);
    snprintf(text, sizeof(text), "%llu", (unsigned long long)source.last.cgroup_device); string_property(env, reservation, "deviceId", text);
    snprintf(text, sizeof(text), "%llu", (unsigned long long)source.last.cgroup_inode); string_property(env, reservation, "fileId", text);
    napi_object_freeze(env, reservation); napi_set_named_property(env, result, "originalReservation", reservation);
    admin_mcp_data_number(env, result, "observedAtMs", data.observed_at_ms);
    const char *flags[] = {"originalControllerDead", "originalProcessesDead", "originalReservationAbsent", "originalControllerLeafAbsent", "originalInputClosed"};
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) admin_mcp_data_bool(env, result, flags[i], true);
    napi_object_freeze(env, result); return result;
}
