/* Test data only. These values cannot identify any production MCP owner. */
#include "mcp-node-loop.h"

static napi_value capture(napi_env env, napi_callback_info info) {
    (void)info;
    napi_value value;
    return napi_create_external(env, env, NULL, NULL, &value) == napi_ok ? value : NULL;
}

static napi_value compare(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argument, result, exact, same_loop;
    void *peer = NULL;
    if (napi_get_cb_info(env, info, &argc, &argument, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_value_external(env, argument, &peer) != napi_ok)
        return NULL;
    if (napi_create_object(env, &result) != napi_ok ||
        napi_get_boolean(env, peer == env, &exact) != napi_ok ||
        napi_get_boolean(env, cliq_mcp_same_node_loop(env, peer), &same_loop) != napi_ok ||
        napi_set_named_property(env, result, "sameAddon", exact) != napi_ok ||
        napi_set_named_property(env, result, "sameLoop", same_loop) != napi_ok)
        return NULL;
    return result;
}

NAPI_MODULE_INIT() {
    napi_property_descriptor methods[] = {
        { "capture", NULL, capture, NULL, NULL, NULL, napi_default, NULL },
        { "compare", NULL, compare, NULL, NULL, NULL, napi_default, NULL }
    };
    return napi_define_properties(env, exports, sizeof(methods) / sizeof(*methods), methods) == napi_ok ? exports : NULL;
}
