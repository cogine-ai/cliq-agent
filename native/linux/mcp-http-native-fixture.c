/*
 * Private fixture image only. Build on real Linux with the same real GIO, OpenSSL and Node headers as the broker, then
 * invoke runMcpNativeFixture in Node. No fixture export exists in the signed production image. The tests exercise
 * actual C framing/NoEcho code; they assert no lifecycle authority.
 */
#define _GNU_SOURCE
#define CLIQ_MCP_HTTP_BROKER_MODULE 1
#define CLIQ_MCP_NATIVE_FIXTURE 1
#include <node_api.h>
static napi_value mcp_native_fixture_run(napi_env env, napi_callback_info info);
#include "credential-platform.c"
static napi_value mcp_native_fixture_run(napi_env env, napi_callback_info info) {
    (void)info;
    unsigned        checks = 0;
    const char     *valid[] = {"{}", "{\"a\":[1,true,null,\"\\ud83d\\ude00\"]}", "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"};
    const char     *invalid[] = {"{\"a\":1,\"\\u0061\":2}", "{\"x\":\"\\ud800\"}", "[1,]", "{\"n\":1e999}", "{}{}"};
    for (size_t i = 0; i < sizeof(valid) / sizeof(*valid); i++) {
        struct mcp_json json;
        if (!mcp_json_parse((const unsigned char *)valid[i], strlen(valid[i]), &json))
            goto refused;
        free(json.nodes);
        checks++;
    }
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        struct mcp_json json;
        if (mcp_json_parse((const unsigned char *)invalid[i], strlen(invalid[i]), &json)) {
            free(json.nodes);
            goto refused;
        } checks++;
    }
    for (unsigned depth = 32; depth <= 33; depth++) {
        unsigned char   nested[66];
        memset(nested, '[', depth);
        memset(nested + depth, ']', depth);
        struct mcp_json json;
        bool            parsed = mcp_json_parse(nested, depth * 2, &json);
        if (parsed)
            free(json.nodes);
        if (parsed != (depth == 32))
            goto refused;
        checks++;
    }
    struct broker   broker = {0};
    atomic_init(&broker.cancelled, false);
    atomic_init(&broker.unsafe, false);
    atomic_init(&broker.error, NULL);
    clock_gettime(CLOCK_MONOTONIC, &broker.platform.deadline);
    broker.platform.deadline.tv_sec += 30;
    unsigned char   key[] = "Key";
    broker.platform.secret = key;
    broker.platform.secret_size = 3;
    broker.sse = true;
    const unsigned char notification[] = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}";
    const unsigned char result_event[] = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
    if (!mcp_no_echo_all(&broker, notification, sizeof(notification) - 1) || !mcp_no_echo_all(&broker, result_event, sizeof(result_event) - 1))
        goto refused;
    checks++;
    const unsigned char tail[] = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\ndata: \"\xe2\x84\xaa" "ey\"\xe2";
    broker.response = (unsigned char *)tail;
    broker.response_size = sizeof(tail) - 1;
    if (mcp_screen_capture(&broker))
        goto refused;
    checks++;
    /*
     * An immutable received span remains screenable after Stop/deadline. Live header/credential screens keep their
     * original cancellation gate.
     */
    for (unsigned scenario = 0; scenario < 2; scenario++) {
        atomic_store(&broker.cancelled, scenario == 0);
        clock_gettime(CLOCK_MONOTONIC, &broker.platform.deadline);
        broker.platform.deadline.tv_sec += scenario == 0 ? 30 : -1;
        atomic_store(&broker.error, NULL);
        const unsigned char safe[] = "{\"safe\":true}";
        if (!mcp_no_echo_all(&broker, safe, sizeof(safe) - 1))
            goto refused;
        checks++;
        if (mcp_no_echo_all(&broker, key, sizeof(key) - 1) || !atomic_load(&broker.error) || strcmp(atomic_load(&broker.error), "broker_response_refused"))
            goto refused;
        checks++;
        atomic_store(&broker.error, NULL);
        if (broker_no_echo(&broker, safe, sizeof(safe) - 1) || !atomic_load(&broker.error) || strcmp(atomic_load(&broker.error), "broker_cancelled_or_expired"))
            goto refused;
        checks++;
    }
    atomic_store(&broker.cancelled, false);
    clock_gettime(CLOCK_MONOTONIC, &broker.platform.deadline);
    broker.platform.deadline.tv_sec += 30;
    atomic_store(&broker.error, NULL);
    broker.platform.secret = NULL;
    broker.platform.secret_size = 0;
    broker.sse_data = g_string_new(NULL);
    broker.sse_event = g_string_new(NULL);
    if (!broker.sse_data || !broker.sse_event)
        goto refused;
    const char     *empty_data[] = {"data:\n\n", "data\n\n"};
    for (size_t i = 0; i < sizeof(empty_data) / sizeof(*empty_data); i++) {
        broker.response = (unsigned char *)empty_data[i];
        broker.response_size = strlen(empty_data[i]);
        broker.sse_line_start = broker.parse_at = 0;
        broker.sse_data_present = false;
        g_string_truncate(broker.sse_data, 0);
        atomic_store(&broker.error, NULL);
        if (mcp_sse_next(&broker) || !atomic_load(&broker.error) || strcmp(atomic_load(&broker.error), "mcp_response_refused"))
            goto refused;
        checks++;
    }
    const unsigned char partial_data[] = "data:\ndata: \n";
    broker.response = (unsigned char *)partial_data;
    broker.response_size = sizeof(partial_data) - 1;
    broker.sse_line_start = broker.parse_at = 0;
    broker.sse_data_present = false;
    g_string_truncate(broker.sse_data, 0);
    atomic_store(&broker.error, NULL);
    if (!mcp_sse_next(&broker) || !broker.sse_data_present || broker.sse_data->len != 1 || broker.sse_data->str[0] != '\n')
        goto refused;
    checks++;
    g_string_free(broker.sse_data, TRUE);
    g_string_free(broker.sse_event, TRUE);
    broker.sse_data = broker.sse_event = NULL;
    atomic_store(&broker.error, NULL);
    broker.maximum_response_bytes = 65536;
    broker.response = calloc(1, 65536);
    if (!broker.response)
        goto refused;
    broker.response_size = 65535;
    unsigned char   byte = 'x';
    if (!mcp_append(&broker, &byte, 1) || mcp_append(&broker, &byte, 1)) {
        free(broker.response);
        goto refused;
    } free(broker.response);
    checks++;
    napi_value      result;
    napi_create_object(env, &result);
    set_number(env, result, "checks", checks);
    napi_object_freeze(env, result);
    return result;
refused:napi_throw_error(env, "ERR_CLIQ_MCP_NATIVE_FIXTURE", "Actual C MCP protocol fixture failed");
    return NULL;
}
