#ifndef CLIQ_MCP_HTTP_BROKER_H
#define CLIQ_MCP_HTTP_BROKER_H
#include "mcp-http-owner-bridge.h"
#define BROKER_BODY_CAP 1048576
#define BROKER_HEADER_CAP 65536
#define BROKER_TRUST_CAP (16 * 1048576)
#define BROKER_PIN_CAP 64
#define BROKER_ID_CAP 257
#define MCP_MAX_PINGS 8u
#define MCP_MAX_NODES 20002u
#define MCP_MAX_ENTRIES 10000u
enum mcp_work {
    MCP_PREPARE, MCP_CONNECT_STAGE, MCP_EXCHANGE_STAGE, MCP_READ_STAGE, MCP_CONNECT_PING, MCP_EXCHANGE_PING, MCP_RETIRE
};
enum mcp_message_kind {
    MCP_NOTIFICATION, MCP_PING, MCP_RESPONSE
};
enum mcp_ping_state {
    MCP_PING_RECEIVED, MCP_PING_CONNECTING, MCP_PING_CONNECTED, MCP_PING_RELEASED, MCP_PING_ACK_JOINED
};
struct mcp_json_node {
    size_t          start, end;
    unsigned        child, next;
    char            type;
};
struct mcp_json {
    const unsigned char *bytes;
    size_t          size, at;
    struct mcp_json_node *nodes;
    unsigned        count, entries;
};
struct mcp_frame {
    unsigned char  *body;
    size_t          size;
    char            digest[65];
    unsigned char  *id;
    size_t          id_size;
};
struct mcp_connection {
    GSocketConnection *connection;
    GSocket        *socket;
    SSL_CTX        *context;
    SSL            *tls;
};
struct mcp_http_state {
    bool            headers_received, length_present, chunked, chunk_end, entity_eof, awaiting_chunk_crlf, sse;
    uint64_t        content_remaining, chunk_remaining;
    unsigned        status;
};
struct broker;
struct mcp_receipt {
    struct broker  *owner;
    napi_env        env;
    pid_t           creator_pid;
    unsigned        phase, ordinal;
    enum mcp_message_kind kind;
    enum mcp_ping_state ping_state;
    unsigned char   nonce[32];
    char            digest[65];
    unsigned char  *message, *id;
    size_t          size, id_size;
    bool            finish_started, finished;
    napi_ref        object, owner_ref;
    struct mcp_receipt *next;
};
struct mcp_capture {
    struct broker  *owner;
    unsigned        phase, ordinal;
    unsigned char  *bytes;
    size_t          size, end_offset;
    char            digest[65];
    bool            sse, http_eof, joined, screened, no_echo_refused;
    napi_ref        object;
};
struct mcp_join {
    struct broker  *owner;
    napi_env        env;
    pid_t           creator_pid;
};
struct broker {
    struct task     platform;
    napi_env        env;
    pid_t           creator_pid;
    napi_async_work work;
    napi_async_cleanup_hook_handle cleanup_hook;
    napi_deferred   ready_deferred, phase_deferred, message_deferred, close_deferred, final_deferred;
    napi_ref        handle, close_promise, peer_ref;
    struct native_callbacks callbacks;
    uv_timer_t      timer;
    bool            timer_ready, timer_closing, timer_closed, working, prepared, closing, retired, close_finished, env_closing,
                    finalize_requested;
    bool            credential_present, admin, bound, connected, request_started, network_started, setup_released, effect_released,
                    protocol_complete;
    bool            phase_attempted[4], phase_released[4], phase_completed[4], headers_received, length_present, chunked,
                    chunk_end, entity_eof, awaiting_chunk_crlf;
    bool            sse, invalidated, fence_locked, token_revoked, message_ready, unsafe_pinned, sse_skip_lf, sse_data_present;
    unsigned        active_releases, fence_borrows, next_phase, phase, ordinal, ping_count, data_responses;
    uint32_t        port, maximum_response_bytes;
    size_t          pin_count, trust_size, response_size, response_capacity, parse_at, sse_line_start, sse_event_end;
    uint64_t        content_remaining, chunk_remaining, header_total;
    char            host[TEXT_CAP], server_name[TEXT_CAP], path[TEXT_CAP * 2], trust_digest[65], token_digest[65];
    unsigned char   token[32], pins[BROKER_PIN_CAP][32];
    unsigned char  *trust, *response;
    GSocketConnection *connection;
    GSocket        *socket;
    SSL_CTX        *tls_context;
    SSL            *tls;
    struct mcp_connection paused;
    struct mcp_http_state paused_http;
    GString        *sse_data, *sse_event;
    unsigned        status, aggregate_entries;
    struct mcp_frame frames[4];
    struct mcp_receipt *pending, *ping, *receipts;
    bool            ack_ready, admin_requested, admin_event_delivered;
    struct mcp_capture *admin_final_capture;
    struct mcp_capture *captures[3];
    struct mcp_join joined;
    struct cliq_mcp_run_binding run_binding;
    struct cliq_mcp_admin_binding admin_binding;
    struct cliq_mcp_admin_peer_handle *peer;
    struct cliq_mcp_admin_observation peer_observation;
    pthread_mutex_t release_mutex;
    bool            mutex_ready;
    atomic_bool     cancelled, unsafe, fence_retained;
                    _Atomic(const char *)error;
    enum mcp_work   stage;
    struct broker  *unretired_next;
};
static const    napi_type_tag mcp_run_tag = {UINT64_C(0xc18559e22b0c45e4), UINT64_C(0xb677427afd8bce57)};
static const    napi_type_tag mcp_admin_tag = {UINT64_C(0x419cb490b55c44c0), UINT64_C(0x83e26cf9bfc793b2)};
static const    napi_type_tag mcp_message_tag = {UINT64_C(0xa2737ee4ab8e4479), UINT64_C(0xac33cb12c79cd634)};
static const    napi_type_tag mcp_ping_tag = {UINT64_C(0x12c129152d4c4218), UINT64_C(0xb2dadde4a9ae583f)};
static const    napi_type_tag mcp_raw_tag = {UINT64_C(0xe1101fa816144194), UINT64_C(0x88b2678df2510396)};
static const    napi_type_tag mcp_unusable_tag = {UINT64_C(0xb5869de488dd48d7), UINT64_C(0xb0ef1b3a99826a1f)};
static const    napi_type_tag mcp_bytes_tag = {UINT64_C(0xc21d9b3026d54775), UINT64_C(0x8b48f0179dbf31bb)};
static const    napi_type_tag mcp_response_join_tag = {UINT64_C(0x63e555e38ad54a85), UINT64_C(0xad8cc214b25615f7)};
static const    napi_type_tag mcp_run_join_tag = {UINT64_C(0x50e9cb69deab40d1), UINT64_C(0x905569b911167b9d)};
static const    napi_type_tag mcp_admin_join_tag = {UINT64_C(0x9ead2cb285cc4464), UINT64_C(0x971981babd9e7f42)};
static const    napi_type_tag mcp_fence_tag = {UINT64_C(0xc8a60e6aa1af42fb), UINT64_C(0xb2b850a438520233)};
static struct broker *mcp_unretired;
static void     mcp_begin_close(struct broker *broker);
static void     mcp_finish_close(struct broker *broker);
static void     mcp_free(napi_env env, struct broker *broker);
static bool     mcp_queue(struct broker *broker, enum mcp_work stage);
static bool
broker_fail(struct broker *broker, const char *code)
{
    const char     *expected = NULL;
    atomic_compare_exchange_strong(&broker->error, &expected, code);
    return false;
}
#include "http-owner-mechanism.h"

/*
 * The live parser is deliberately protocol-only. Full initialize/tool/result schemas are independently recomputed by
 * Supervisor from actual captures.
 */
static void
mcp_json_space(struct mcp_json *json)
{
    while (json->at < json->size && strchr(" \t\r\n", json->bytes[json->at]))
        json->at++;
}
static bool
mcp_json_string(struct mcp_json *json, GString * decoded)
{
    if (json->at == json->size || json->bytes[json->at++] != '"')
        return false;
    while (json->at < json->size) {
        unsigned char   byte = json->bytes[json->at++];
        if (byte == '"')
            return true;
        if (byte < 0x20)
            return false;
        if (byte == '\\') {
            if (json->at == json->size)
                return false;
            byte = json->bytes[json->at++];
            if (byte == 'u') {
                unsigned        point = 0;
                if (json->size - json->at < 4)
                    return false;
                for (unsigned i = 0; i < 4; i++) {
                    int             digit = broker_hex_digit(json->bytes[json->at++]);
                    if (digit < 0)
                        return false;
                    point = point * 16 + (unsigned)digit;
                }
                if (point >= 0xd800 && point <= 0xdbff) {
                    if (json->size - json->at < 6 || json->bytes[json->at++] != '\\' || json->bytes[json->at++] != 'u')
                        return false;
                    unsigned        low = 0;
                    for (unsigned i = 0; i < 4; i++) {
                        int             digit = broker_hex_digit(json->bytes[json->at++]);
                        if (digit < 0)
                            return false;
                        low = low * 16 + (unsigned)digit;
                    }
                    if (low < 0xdc00 || low > 0xdfff)
                        return false;
                    point = 0x10000 + (point - 0xd800) * 1024 + low - 0xdc00;
                } else if (point >= 0xdc00 && point <= 0xdfff)
                    return false;
                char            encoded[6];
                int             size = g_unichar_to_utf8(point, encoded);
                if (decoded)
                    g_string_append_len(decoded, encoded, size);
                continue;
            }
            if (byte == 'b')
                byte = '\b';
            else if (byte == 'f')
                byte = '\f';
            else if (byte == 'n')
                byte = '\n';
            else if (byte == 'r')
                byte = '\r';
            else if (byte == 't')
                byte = '\t';
            else if (byte != '"' && byte != '\\' && byte != '/')
                return false;
        }
        if (decoded)
            g_string_append_c(decoded, (char)byte);
    }
    return false;
}
static bool
mcp_json_value(struct mcp_json *json, unsigned depth, unsigned *result)
{
    mcp_json_space(json);
    if (json->at == json->size || json->count + 1 >= MCP_MAX_NODES)
        return false;
    unsigned char   byte = json->bytes[json->at];
    if ((byte == '{' || byte == '[') && depth >= 32)
        return false;
    unsigned        index = ++json->count;
    struct mcp_json_node *node = &json->nodes[index];
    *result = index;
    node->start = json->at;
    node->type = (char)byte;
    if (byte == '"') {
        if (!mcp_json_string(json, NULL))
            return false;
    } else if (byte == '{' || byte == '[') {
        json->at++;
        mcp_json_space(json);
        unsigned        last = 0;
        GHashTable     *keys = byte == '{' ? g_hash_table_new_full(g_bytes_hash, g_bytes_equal, (GDestroyNotify) g_bytes_unref, NULL) : NULL;
        bool            valid = true;
        if (json->at < json->size && json->bytes[json->at] == (byte == '{' ? '}' : ']'))
            json->at++;
        else
            for (;;) {
                if (++json->entries > MCP_MAX_ENTRIES) {
                    valid = false;
                    break;
                }
                if (byte == '{') {
                    unsigned        key = ++json->count;
                    if (key + 1 >= MCP_MAX_NODES) {
                        valid = false;
                        break;
                    }
                    struct mcp_json_node *key_node = &json->nodes[key];
                    key_node->start = json->at;
                    key_node->type = '"';
                    GString        *decoded = g_string_new(NULL);
                    valid = decoded && mcp_json_string(json, decoded);
                    if (valid) {
                        GBytes         *name = g_bytes_new(decoded->str, decoded->len);
                        if (g_hash_table_contains(keys, name)) {
                            g_bytes_unref(name);
                            valid = false;
                        } else
                            g_hash_table_add(keys, name);
                    }
                    if (decoded)
                        g_string_free(decoded, TRUE);
                    key_node->end = json->at;
                    mcp_json_space(json);
                    if (!valid || json->at == json->size || json->bytes[json->at++] != ':') {
                        valid = false;
                        break;
                    }
                    if (last)
                        json->nodes[last].next = key;
                    else
                        node->child = key;
                    last = key;
                }
                unsigned        child;
                if (!mcp_json_value(json, depth + 1, &child)) {
                    valid = false;
                    break;
                }
                if (last)
                    json->nodes[last].next = child;
                else
                    node->child = child;
                last = child;
                mcp_json_space(json);
                if (json->at == json->size) {
                    valid = false;
                    break;
                }
                unsigned char   end = json->bytes[json->at++];
                if (end == (byte == '{' ? '}' : ']'))
                    break;
                if (end != ',') {
                    valid = false;
                    break;
                }
                mcp_json_space(json);
            }
        if (keys)
            g_hash_table_unref(keys);
        if (!valid)
            return false;
    } else if (byte == 't' || byte == 'f' || byte == 'n') {
        const char     *literal = byte == 't' ? "true" : byte == 'f' ? "false" : "null";
        size_t          size = strlen(literal);
        if (json->size - json->at < size || memcmp(json->bytes + json->at, literal, size))
            return false;
        json->at += size;
    } else {
        node->type = '#';
        if (byte == '-') {
            json->at++;
            if (json->at == json->size)
                return false;
        }
        if (json->bytes[json->at] == '0')
            json->at++;
        else {
            if (json->bytes[json->at] < '1' || json->bytes[json->at] > '9')
                return false;
            while (json->at < json->size && json->bytes[json->at] >= '0' && json->bytes[json->at] <= '9')
                json->at++;
        }
        if (json->at < json->size && json->bytes[json->at] == '.') {
            json->at++;
            size_t          start = json->at;
            while (json->at < json->size && json->bytes[json->at] >= '0' && json->bytes[json->at] <= '9')
                json->at++;
            if (start == json->at)
                return false;
        }
        if (json->at < json->size && (json->bytes[json->at] == 'e' || json->bytes[json->at] == 'E')) {
            json->at++;
            if (json->at < json->size && (json->bytes[json->at] == '+' || json->bytes[json->at] == '-'))
                json->at++;
            size_t          start = json->at;
            while (json->at < json->size && json->bytes[json->at] >= '0' && json->bytes[json->at] <= '9')
                json->at++;
            if (start == json->at)
                return false;
        }
        char           *number = g_strndup((const char *)json->bytes + node->start, json->at - node->start), *end = NULL;
        double          value = number ? g_ascii_strtod(number, &end) : INFINITY;
        bool            valid = number && end && !*end && isfinite(value);
        g_free(number);
        if (!valid)
            return false;
    }
    node->end = json->at;
    return true;
}
static bool
mcp_json_parse(const unsigned char *bytes, size_t size, struct mcp_json *json)
{
    memset(json, 0, sizeof(*json));
    if (!size || size > BROKER_BODY_CAP || !g_utf8_validate((const char *)bytes, (gssize) size, NULL))
        return false;
    json->bytes = bytes;
    json->size = size;
    json->nodes = calloc(MCP_MAX_NODES, sizeof(*json->nodes));
    unsigned        root;
    bool            valid = json->nodes && mcp_json_value(json, 0, &root);
    mcp_json_space(json);
    if (!valid || json->at != size || root != 1) {
        free(json->nodes);
        json->nodes = NULL;
        return false;
    }
    return true;
}
static bool
mcp_json_text(const struct mcp_json *json, unsigned index, const char *expected)
{
    if (!index || json->nodes[index].type != '"')
        return false;
    struct mcp_json copy = *json;
    copy.at = json->nodes[index].start;
    GString        *decoded = g_string_new(NULL);
    bool            valid = decoded && mcp_json_string(&copy, decoded) && decoded->len == strlen(expected) && !memcmp(decoded->str, expected, decoded->len);
    if (decoded)
        g_string_free(decoded, TRUE);
    return valid;
}
static unsigned
mcp_json_member(const struct mcp_json *json, unsigned object, const char *name)
{
    if (!object || json->nodes[object].type != '{')
        return 0;
    for (unsigned key = json->nodes[object].child; key;) {
        unsigned        value = json->nodes[key].next;
        if (mcp_json_text(json, key, name))
            return value;
        key = json->nodes[value].next;
    }
    return 0;
}
static bool
mcp_json_keys(const struct mcp_json *json, unsigned object, const char *const *allowed, size_t count)
{
    if (!object || json->nodes[object].type != '{')
        return false;
    for (unsigned key = json->nodes[object].child; key;) {
        bool            known = false;
        for (size_t i = 0; i < count; i++)
            known |= mcp_json_text(json, key, allowed[i]);
        if (!known)
            return false;
        unsigned        value = json->nodes[key].next;
        key = json->nodes[value].next;
    }
    return true;
}
static bool
mcp_json_id(const struct mcp_json *json, unsigned index, unsigned char **output, size_t * size)
{
    if (!index)
        return false;
    const struct mcp_json_node *node = &json->nodes[index];
    if (node->type == '"') {
        struct mcp_json copy = *json;
        copy.at = node->start;
        GString        *decoded = g_string_new(NULL);
        bool            valid = decoded && mcp_json_string(&copy, decoded);
        if (valid) {
            *size = decoded->len + 1;
            *output = malloc(*size);
            valid = *output != NULL;
            if (valid) {
                (*output)[0] = 's';
                memcpy(*output + 1, decoded->str, decoded->len);
            }
        }
        if (decoded)
            g_string_free(decoded, TRUE);
        return valid;
    }
    if (node->type != '#')
        return false;
    char           *number = g_strndup((const char *)json->bytes + node->start, node->end - node->start), *end = NULL;
    double          value = number ? g_ascii_strtod(number, &end) : INFINITY;
    bool            valid = number && end && !*end && isfinite(value) && fabs(value) <= 9007199254740991.0 && trunc(value) == value;
    if (valid) {
        char            encoded[64];
        int             count = snprintf(encoded, sizeof(encoded), "n%.0f", value == 0 ? 0 : value);
        *size = (size_t) count;
        *output = malloc(*size);
        valid = count > 0 && *output;
        if (valid)
            memcpy(*output, encoded, *size);
    }
    g_free(number);
    return valid;
}
struct mcp_module {
    napi_env        env;
    napi_ref        data_validator;
};
static bool
mcp_plain_data(napi_env env, napi_value value)
{
    napi_value      validator, answer, global;
    bool            valid = false;
    struct mcp_module *module = NULL;
    return napi_get_instance_data(env, (void **)&module) == napi_ok && module && module->env == env && module->data_validator && napi_get_reference_value(env, module->data_validator, &validator) == napi_ok &&
        napi_get_global(env, &global)== napi_ok && napi_call_function(env, global, validator, 1, &value, &answer)== napi_ok &&
        napi_get_value_bool(env, answer, &valid) == napi_ok && valid;
}
static bool
mcp_run_binding(napi_env env, napi_value value, struct cliq_mcp_run_binding *binding)
{
    const char     *keys[] = {"runId", "opId", "attempt", "dispatchId", "dispatchJournalSeq", "requestRef", "requestDigest", "targetRef", "targetDigest", "grantRef", "grantDigest", "registryRef", "manifestDigest", "toolContractDigest", "batchItemId", "callId", "callIndex", "supervisorInstanceId", "stateOwnerEpoch", "workerLaunchId", "leaseEpoch", "brokerFenceTokenDigest", "deadlineMs"};
    return mcp_plain_data(env, value) && fields(env, value, keys, 23) &&
        field_text(env, value, "runId", binding->run, sizeof(binding->run)) && field_text(env, value, "opId", binding->op, sizeof(binding->op)) &&
        field_text(env, value, "dispatchId", binding->dispatch, sizeof(binding->dispatch)) && field_text(env, value, "supervisorInstanceId", binding->supervisor, sizeof(binding->supervisor)) &&
        field_text(env, value, "batchItemId", binding->batch_item, sizeof(binding->batch_item)) && field_text(env, value, "callId", binding->call, sizeof(binding->call)) &&
        field_text(env, value, "workerLaunchId", binding->worker_launch, sizeof(binding->worker_launch)) &&
        broker_digest(env, value, "requestRef", binding->request_ref) && broker_digest(env, value, "requestDigest", binding->request_digest) &&
        broker_digest(env, value, "targetRef", binding->target_ref) && broker_digest(env, value, "targetDigest", binding->target_digest) &&
        broker_digest(env, value, "grantRef", binding->grant_ref) && broker_digest(env, value, "grantDigest", binding->grant_digest) &&
        broker_digest(env, value, "registryRef", binding->registry_ref) && broker_digest(env, value, "manifestDigest", binding->manifest_digest) &&
        broker_digest(env, value, "toolContractDigest", binding->tool_digest) && broker_digest(env, value, "brokerFenceTokenDigest", binding->token_digest) &&
        broker_integer(env, value, "attempt", 0, &binding->attempt) && broker_integer(env, value, "dispatchJournalSeq", 1, &binding->sequence) &&
        broker_integer(env, value, "callIndex", 0, &binding->call_index) && broker_integer(env, value, "stateOwnerEpoch", 1, &binding->owner_epoch) &&
        broker_integer(env, value, "leaseEpoch", 1, &binding->lease_epoch) && broker_integer(env, value, "deadlineMs", 1, &binding->deadline_ms);
}
static bool
mcp_admin_binding(napi_env env, napi_value value, struct cliq_mcp_admin_binding *binding)
{
    const char     *keys[] = {"adminOperationId", "attempt", "principalId", "method", "controlRequestDigest", "targetRef", "targetDigest", "probePayloadCoreRef", "probePayloadCoreDigest", "probeRequestDigest", "dispatchId", "supervisorInstanceId", "stateOwnerEpoch", "processContainmentRef", "plannedContainmentRef", "plannedContainmentDigest", "sandboxLaunchSpecRef", "sandboxLaunchSpecDigest", "deadlineMs"};
    return mcp_plain_data(env, value) && fields(env, value, keys, 19) &&
        field_text(env, value, "adminOperationId", binding->operation, sizeof(binding->operation)) && field_text(env, value, "principalId", binding->principal, sizeof(binding->principal)) &&
        field_text(env, value, "method", binding->method, sizeof(binding->method)) && (!strcmp(binding->method, "mcp.register") || !strcmp(binding->method, "mcp.refresh")) &&
        field_text(env, value, "dispatchId", binding->dispatch, sizeof(binding->dispatch)) && field_text(env, value, "supervisorInstanceId", binding->supervisor, sizeof(binding->supervisor)) &&
        broker_digest(env, value, "controlRequestDigest", binding->control_digest) && broker_digest(env, value, "targetRef", binding->target_ref) &&
        broker_digest(env, value, "targetDigest", binding->target_digest) && broker_digest(env, value, "probePayloadCoreRef", binding->core_ref) &&
        broker_digest(env, value, "probePayloadCoreDigest", binding->core_digest) && broker_digest(env, value, "probeRequestDigest", binding->probe_digest) &&
        broker_digest(env, value, "processContainmentRef", binding->containment_ref) && broker_digest(env, value, "plannedContainmentRef", binding->plan_ref) &&
        broker_digest(env, value, "plannedContainmentDigest", binding->plan_digest) && broker_digest(env, value, "sandboxLaunchSpecRef", binding->spec_ref) &&
        broker_digest(env, value, "sandboxLaunchSpecDigest", binding->spec_digest) && broker_integer(env, value, "attempt", 0, &binding->attempt) &&
        broker_integer(env, value, "stateOwnerEpoch", 1, &binding->owner_epoch) && broker_integer(env, value, "deadlineMs", 1, &binding->deadline_ms);
}
static const char *
mcp_phase_name(unsigned phase)
{
    static const char *names[] = {"initialize", "initialized", "tools_list", "tools_call"};
    return phase < 4 ? names[phase] : "invalid";
}
static bool
mcp_frame_valid(struct mcp_frame *frame, unsigned phase)
{
    struct mcp_json json;
    if (!mcp_json_parse(frame->body, frame->size, &json))
        return false;
    const char     *keys[] = {"jsonrpc", "id", "method", "params"};
    static const char *methods[] = {"initialize", "notifications/initialized", "tools/list", "tools/call"};
    unsigned        id = mcp_json_member(&json, 1, "id"), params = mcp_json_member(&json, 1, "params");
    bool            valid = mcp_json_keys(&json, 1, keys, 4) && mcp_json_text(&json, mcp_json_member(&json, 1, "jsonrpc"), "2.0") &&
    mcp_json_text(&json, mcp_json_member(&json, 1, "method"), methods[phase]);
    if (phase == 1)
        valid = valid && !id && !params;
    else
        valid = valid && mcp_json_id(&json, id, &frame->id, &frame->id_size);
    if (phase == 0) {
        const char     *param_keys[] = {"protocolVersion", "capabilities", "clientInfo"};
        unsigned        caps = mcp_json_member(&json, params, "capabilities"), info = mcp_json_member(&json, params, "clientInfo");
        const char     *info_keys[] = {"name", "version"};
        valid = valid && mcp_json_keys(&json, params, param_keys, 3) && mcp_json_text(&json, mcp_json_member(&json, params, "protocolVersion"), "2025-11-25") &&
            caps && json.nodes[caps].type == '{' && !json.nodes[caps].child && mcp_json_keys(&json, info, info_keys, 2) &&
            mcp_json_text(&json, mcp_json_member(&json, info, "name"), "@cogineai/cliq") && mcp_json_member(&json, info, "version") && json.nodes[mcp_json_member(&json, info, "version")].type == '"';
    } else if (phase == 2)
        valid = valid && !params;
    else if (phase == 3) {
        const char     *param_keys[] = {"name", "arguments"};
        unsigned        name = mcp_json_member(&json, params, "name"), arguments = mcp_json_member(&json, params, "arguments");
        valid = valid && mcp_json_keys(&json, params, param_keys, 2) && name && json.nodes[name].type == '"' && arguments && json.nodes[arguments].type == '{';
    }
    free(json.nodes);
    return valid;
}
static bool
mcp_input(napi_env env, napi_value input, struct broker *broker, uint64_t * deadline)
{
    const char     *keys[] = {"authentication", "target", "trustStoreBytes", "trustStoreDigest", "maximumResponseBytes", "remainingDeadlineMs", "recipe"};
    const char     *target_keys[] = {"hostAscii", "port", "path", "serverNameAscii", "spkiSha256Pins"};
    napi_value      authentication, target, pins, recipe, kind_value;
    char            kind[32];
    bool            array;
    uint32_t        count;
    uint64_t        limit;
    if (!mcp_plain_data(env, input) || !fields(env, input, keys, 7) || !member(env, input, "authentication", &authentication) ||
    !field_text(env, authentication, "kind", kind, sizeof(kind)) || !member(env, authentication, "kind", &kind_value))
        return false;
    if (!strcmp(kind, "public")) {
        const char     *auth_keys[] = {"kind"};
        if (!fields(env, authentication, auth_keys, 1))
            return false;
    } else if (!strcmp(kind, "bearer")) {
        const char     *auth_keys[] = {"kind", "selector", "expectedObservation"};
        napi_value      selector, expected;
        if (!fields(env, authentication, auth_keys, 3) || !member(env, authentication, "selector", &selector) || !parse_selector(env, selector, &broker->platform.selector) ||
            !member(env, authentication, "expectedObservation", &expected) || !parse_expected(env, expected, &broker->platform))
            return false;
        broker->credential_present = true;
    } else
        return false;
    if (!member(env, input, "target", &target) || !fields(env, target, target_keys, 5) || !field_text(env, target, "hostAscii", broker->host, sizeof(broker->host)) || !broker_host(broker->host) ||
        !field_text(env, target, "serverNameAscii", broker->server_name, sizeof(broker->server_name)) || !broker_host(broker->server_name) ||
        !field_u32(env, target, "port", &broker->port) || !broker->port || broker->port > 65535 || !field_text(env, target, "path", broker->path, sizeof(broker->path)) || !broker_path(broker->path) ||
        !member(env, target, "spkiSha256Pins", &pins) || napi_is_array(env, pins, &array) != napi_ok || !array || napi_get_array_length(env, pins, &count) != napi_ok || !count || count > BROKER_PIN_CAP ||
        !broker_integer(env, input, "maximumResponseBytes", 65536, &limit) || limit > BROKER_BODY_CAP ||
        !broker_integer(env, input, "remainingDeadlineMs", 1, deadline) || *deadline > INT_MAX || (broker->admin && *deadline > 300000))
        return false;
    broker->maximum_response_bytes = (uint32_t) limit;
    char            previous[65] = {0};
    for (uint32_t i = 0; i < count; i++) {
        napi_value      pin;
        char            text[65];
        size_t          size;
        if (napi_get_element(env, pins, i, &pin) != napi_ok || napi_get_value_string_utf8(env, pin, text, sizeof(text), &size) != napi_ok || size != 64 || strspn(text, "0123456789abcdef") != 64 || (i && strcmp(previous, text) >= 0))
            return false;
        for (size_t byte = 0; byte < 32; byte++) {
            char            pair[3] = {text[byte * 2], text[byte * 2 + 1], 0};
            broker->pins[i][byte] = (unsigned char)strtoul(pair, NULL, 16);
        } memcpy(previous, text, sizeof(previous));
    }
    broker->pin_count = count;
    if (!broker_buffer(env, input, "trustStoreBytes", BROKER_TRUST_CAP, &broker->trust, &broker->trust_size) || !broker_digest(env, input, "trustStoreDigest", broker->trust_digest))
        return false;
    char            digest[65];
    if (!digest_hex(broker->trust, broker->trust_size, digest) || strcmp(digest, broker->trust_digest) ||
        !member(env, input, "recipe", &recipe) || napi_is_array(env, recipe, &array) != napi_ok || !array || napi_get_array_length(env, recipe, &count) != napi_ok || count != (broker->admin ? 3u : 4u))
        return false;
    for (unsigned i = 0; i < count; i++) {
        napi_value      value;
        char            phase[32];
        const char     *frame_keys[] = {"phase", "bodyBytes", "bodyBytesDigest"};
        struct mcp_frame *frame = &broker->frames[i];
        if (napi_get_element(env, recipe, i, &value) != napi_ok || !fields(env, value, frame_keys, 3) || !field_text(env, value, "phase", phase, sizeof(phase)) || strcmp(phase, mcp_phase_name(i)) ||
            !broker_buffer(env, value, "bodyBytes", BROKER_BODY_CAP, &frame->body, &frame->size) || !broker_digest(env, value, "bodyBytesDigest", frame->digest) ||
         !digest_hex(frame->body, frame->size, digest) || strcmp(digest, frame->digest) || !mcp_frame_valid(frame, i))
            return false;
    }
    return true;
}
static bool
mcp_retire_connection(struct broker *broker)
{
    if (broker->tls) {
        SSL_free(broker->tls);
        broker->tls = NULL;
    }
    if (broker->tls_context) {
        SSL_CTX_free(broker->tls_context);
        broker->tls_context = NULL;
    }
    if (broker->connection) {
        GError         *error = NULL;
        bool            valid = g_io_stream_close(G_IO_STREAM(broker->connection), NULL, &error);
        g_clear_error(&error);
        if (!valid) {
            atomic_store(&broker->unsafe, true);
            atomic_store(&retirement_failed, true);
            return broker_fail(broker, "resource_retirement");
        }
        g_object_unref(broker->connection);
        broker->connection = NULL;
        broker->socket = NULL;
    }
    return true;
}
static bool
mcp_retire_platform(struct broker *broker)
{
    struct task    *task = &broker->platform;
    if (task->bus) {
        GError         *error = NULL;
        bool            valid = g_dbus_connection_is_closed(task->bus) || g_dbus_connection_close_sync(task->bus, NULL, &error);
        g_clear_error(&error);
        if (!valid) {
            task->unsafe = true;
            atomic_store(&retirement_failed, true);
        } else {
            g_object_unref(task->bus);
            task->bus = NULL;
        }
    }
    if (!retired_close(task, &task->runtime_fd))
        task->unsafe = true;
    if (task->unsafe) {
        atomic_store(&broker->unsafe, true);
        return broker_fail(broker, "resource_retirement");
    } return true;
}
static void
mcp_pause_connection(struct broker *broker)
{
    broker->paused = (struct mcp_connection){
        broker->connection, broker->socket, broker->tls_context, broker->tls
    };
    broker->paused_http = (struct mcp_http_state){
        broker->headers_received, broker->length_present, broker->chunked, broker->chunk_end, broker->entity_eof, broker->awaiting_chunk_crlf, broker->sse, broker->content_remaining, broker->chunk_remaining, broker->status
    };
    broker->connection = NULL;
    broker->socket = NULL;
    broker->tls_context = NULL;
    broker->tls = NULL;
}
static void
mcp_restore_connection(struct broker *broker)
{
    broker->connection = broker->paused.connection;
    broker->socket = broker->paused.socket;
    broker->tls_context = broker->paused.context;
    broker->tls = broker->paused.tls;
    broker->paused = (struct mcp_connection){
        0
    };
    broker->headers_received = broker->paused_http.headers_received;
    broker->length_present = broker->paused_http.length_present;
    broker->chunked = broker->paused_http.chunked;
    broker->chunk_end = broker->paused_http.chunk_end;
    broker->entity_eof = broker->paused_http.entity_eof;
    broker->awaiting_chunk_crlf = broker->paused_http.awaiting_chunk_crlf;
    broker->sse = broker->paused_http.sse;
    broker->content_remaining = broker->paused_http.content_remaining;
    broker->chunk_remaining = broker->paused_http.chunk_remaining;
    broker->status = broker->paused_http.status;
}
static bool
mcp_headers(struct broker *broker, bool acknowledgement)
{
    char            line[8193];
    size_t          total = 0;
    unsigned        informational = 0;
    for (;;) {
        if (!broker_line(broker, line, sizeof(line), &total) || strlen(line) < 12 || strncmp(line, "HTTP/1.1 ", 9) ||
            line[9] < '1' || line[9] > '5' || line[10] < '0' || line[10] > '9' || line[11] < '0' || line[11] > '9' || (line[12] && line[12] != ' '))
            return broker_fail(broker, "mcp_response_refused");
        broker->status = (unsigned)(line[9] - '0') * 100 + (unsigned)(line[10] - '0') * 10 + (unsigned)(line[11] - '0');
        broker->length_present = false;
        broker->chunked = false;
        broker->sse = false;
        bool            media = false;
        unsigned        count = 0;
        while (broker_line(broker, line, sizeof(line), &total) && line[0]) {
            if (++count > 128 || line[0] == ' ' || line[0] == '\t')
                return broker_fail(broker, "mcp_response_refused");
            char           *colon = strchr(line, ':');
            if (!colon || colon == line)
                return broker_fail(broker, "mcp_response_refused");
            *colon = '\0';
            if (strspn(line, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~") != strlen(line))
                return broker_fail(broker, "mcp_response_refused");
            char           *value = colon + 1;
            while (*value == ' ' || *value == '\t')
                value++;
            size_t          size = strlen(value);
            while (size && (value[size - 1] == ' ' || value[size - 1] == '\t'))
                value[--size] = '\0';
            if (!broker_no_echo(broker, (unsigned char *)value, size))
                return false;
            if (!strcasecmp(line, "mcp-session-id") || !strcasecmp(line, "set-cookie") || !strcasecmp(line, "location") || !strcasecmp(line, "www-authenticate"))
                return broker_fail(broker, "mcp_session_or_redirect_refused");
            if (!strcasecmp(line, "content-length")) {
                if (broker->length_present || !size || size > 20 || strspn(value, "0123456789") != size)
                    return broker_fail(broker, "mcp_response_refused");
                errno = 0;
                char           *end;
                broker->content_remaining = strtoull(value, &end, 10);
                if (errno || *end)
                    return broker_fail(broker, "mcp_response_refused");
                broker->length_present = true;
            } else if (!strcasecmp(line, "transfer-encoding")) {
                if (broker->chunked || strcasecmp(value, "chunked"))
                    return broker_fail(broker, "mcp_response_refused");
                broker->chunked = true;
            } else if (!strcasecmp(line, "content-encoding") && strcasecmp(value, "identity"))
                return broker_fail(broker, "mcp_response_refused");
            else if (!strcasecmp(line, "content-type")) {
                if (media)
                    return broker_fail(broker, "mcp_response_refused");
                media = true;
                char           *semicolon = strchr(value, ';');
                if (semicolon) {
                    *semicolon = '\0';
                    char           *parameter = semicolon + 1;
                    while (*parameter == ' ')
                        parameter++;
                    if (strcasecmp(parameter, "charset=utf-8") && strcasecmp(parameter, "charset=\"utf-8\""))
                        return broker_fail(broker, "mcp_response_refused");
                }
                if (!strcasecmp(value, "text/event-stream"))
                    broker->sse = true;
                else if (strcasecmp(value, "application/json"))
                    return broker_fail(broker, "mcp_response_refused");
            }
        }
        if (atomic_load(&broker->error) || (broker->chunked && broker->length_present))
            return broker_fail(broker, "mcp_response_refused");
        if (broker->status >= 200) {
            if (!acknowledgement && !media)
                return broker_fail(broker, "mcp_response_refused");
            break;
        }
        if (broker->status == 101 || ++informational > 8 || broker->chunked || (broker->length_present && broker->content_remaining))
            return broker_fail(broker, "mcp_response_refused");
    }
    broker->header_total += total;
    if (broker->header_total > (uint64_t) (broker->admin ? 11u : 12u) * BROKER_HEADER_CAP)
        return broker_fail(broker, "mcp_response_refused");
    broker->chunk_remaining = 0;
    broker->chunk_end = false;
    broker->awaiting_chunk_crlf = false;
    broker->entity_eof = false;
    broker->headers_received = true;
    if (acknowledgement) {
        if (broker->status != 202 || (broker->length_present && broker->content_remaining))
            return broker_fail(broker, "mcp_ack_refused");
    } else if (broker->status != 200 && (broker->status < 400 || broker->status > 599))
        return broker_fail(broker, "mcp_response_refused");
    return true;
}
static ssize_t mcp_entity_read(struct broker *broker, unsigned char *bytes, size_t capacity){
    if (broker->entity_eof)
        return 0;
    if (broker->chunked) {
        while (!broker->chunk_remaining) {
            if (broker->awaiting_chunk_crlf) {
                unsigned char   ending[2];
                if (broker_read(broker, ending, 1) != 1 || broker_read(broker, ending + 1, 1) != 1 || ending[0] != '\r' || ending[1] != '\n') {
                    broker_fail(broker, "mcp_response_refused");
                    return -1;
                } broker->awaiting_chunk_crlf = false;
            }
            char            line[8193];
            size_t          total = 0;
            if (!broker_line(broker, line, sizeof(line), &total) || !line[0] || strlen(line) > 16 || strspn(line, "0123456789abcdefABCDEF") != strlen(line)) {
                broker_fail(broker, "mcp_response_refused");
                return -1;
            }
            errno = 0;
            char           *end;
            broker->chunk_remaining = strtoull(line, &end, 16);
            if (errno || *end) {
                broker_fail(broker, "mcp_response_refused");
                return -1;
            }
            if (!broker->chunk_remaining) {
                if (!broker_line(broker, line, sizeof(line), &total) || line[0]) {
                    broker_fail(broker, "mcp_response_refused");
                    return -1;
                } broker->entity_eof = true;
                return 0;
            }
        }
        if (broker->chunk_remaining < capacity)
            capacity = (size_t) broker->chunk_remaining;
    } else if (broker->length_present) {
        if (!broker->content_remaining) {
            broker->entity_eof = true;
            return 0;
        } if (broker->content_remaining < capacity)
            capacity = (size_t) broker->content_remaining;
    }
    ssize_t         received = broker_read(broker, bytes, capacity);
    if (received < 0)
        return -1;
    if (!received) {
        if (broker->chunked || (broker->length_present && broker->content_remaining)) {
            broker_fail(broker, "mcp_transport_interrupted");
            return -1;
        } broker->entity_eof = true;
        return 0;
    }
    if (broker->chunked) {
        broker->chunk_remaining -= (uint64_t) received;
        if (!broker->chunk_remaining)
            broker->awaiting_chunk_crlf = true;
    } else if (broker->length_present)
        broker->content_remaining -= (uint64_t) received;
    return received;
}
static bool
mcp_write_request(struct broker *broker, const unsigned char *body, size_t body_size)
{
    size_t          capacity = strlen(broker->path) + strlen(broker->host) + broker->platform.secret_size + 1024;
    unsigned char  *headers = malloc(capacity);
    if (!headers)
        return broker_fail(broker, "mcp_worker_unavailable");
    int             prefix = snprintf((char *)headers, capacity, "POST %s HTTP/1.1\r\nHost: %s:%u\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: %zu\r\n%s%s", broker->path, broker->host, broker->port, body_size,
                                      broker->phase == 0 ? "" : "MCP-Protocol-Version: 2025-11-25\r\n", broker->credential_present ? "Authorization: Bearer " : "");
    bool            valid = prefix > 0 && (size_t) prefix + broker->platform.secret_size + 4 <= capacity;
    size_t          size = valid ? (size_t) prefix : 0;
    if (valid && broker->credential_present) {
        memcpy(headers + size, broker->platform.secret, broker->platform.secret_size);
        size += broker->platform.secret_size;
        memcpy(headers + size, "\r\n", 2);
        size += 2;
    }
    if (valid) {
        memcpy(headers + size, "\r\n", 2);
        size += 2;
        valid = broker_write(broker, headers, size) && broker_write(broker, body, body_size);
    }
    wipe(headers, capacity);
    free(headers);
    return valid;
}
static bool
mcp_append(struct broker *broker, const unsigned char *bytes, size_t size)
{
    if (size > broker->maximum_response_bytes - broker->response_size)
        return broker_fail(broker, "mcp_response_over_limit");
    memcpy(broker->response + broker->response_size, bytes, size);
    broker->response_size += size;
    return true;
}
static bool
mcp_no_echo_all(struct broker *broker, const unsigned char *bytes, size_t size)
{
    if (!broker_no_echo_mode(broker, bytes, size, true))
        return false;
    /*
     * A finite SSE tail may end halfway through UTF-8. Screen every valid scalar prefix independently too; an invalid
     * tail cannot suppress NFC and nested JSON-string screening of an earlier recoverable key.
     */
    size_t          at = 0;
    while (at < size) {
        const char     *end = NULL;
        bool            valid = g_utf8_validate((const char *)bytes + at, (gssize) (size - at), &end);
        size_t          count = valid ? size - at : (size_t) (end - ((const char *)bytes + at));
        if (count && !broker_no_echo_mode(broker, bytes + at, count, true))
            return false;
        at += count;
        if (!valid)
            at++;
    }
    return true;
}
static bool
mcp_sse_data_field(const unsigned char *bytes, size_t start, size_t end, size_t * content)
{
    size_t          colon = start;
    while (colon < end && bytes[colon] != ':')
        colon++;
    if (colon - start != 4 || memcmp(bytes + start, "data", 4))
        return false;
    *content = colon < end ? colon + 1 : end;
    if (*content < end && bytes[*content] == ' ')
        (*content)++;
    return true;
}
/*
 * Screen original raw bytes, then every reconstructed SSE data projection, including an unterminated tail data field
 * and partial JSON string escape. No event/chunk gets a fresh raw-byte or projection budget.
 */
static bool
mcp_screen_capture(struct broker *broker)
{
    if (!mcp_no_echo_all(broker, broker->response, broker->response_size))
        return false;
    if (!broker->sse)
        return true;
    GString        *data = g_string_new(NULL);
    if (!data)
        return broker_fail(broker, "mcp_worker_unavailable");
    size_t          start = broker->response_size >= 3 && !memcmp(broker->response, "\xef\xbb\xbf", 3) ? 3 : 0;
    bool            valid = true, data_present = false;
    while (start < broker->response_size) {
        size_t          end = start;
        while (end < broker->response_size && broker->response[end] != '\r' && broker->response[end] != '\n')
            end++;
        size_t          count = end - start;
        if (!count) {
            valid = mcp_no_echo_all(broker, (const unsigned char *)data->str, data->len);
            g_string_truncate(data, 0);
            data_present = false;
            if (!valid)
                break;
        } else {
            size_t          at;
            if (!mcp_sse_data_field(broker->response, start, end, &at))
                goto next_line;
            if (data_present)
                g_string_append_c(data, '\n');
            g_string_append_len(data, (const char *)broker->response + at, (gssize) (end - at));
            data_present = true;
            if (!mcp_no_echo_all(broker, (const unsigned char *)data->str, data->len)) {
                valid = false;
                break;
            }
        }
next_line:
        if (end == broker->response_size)
            break;
        if (broker->response[end] == '\r' && end + 1 < broker->response_size && broker->response[end + 1] == '\n')
            end++;
        start = end + 1;
    }
    wipe(data->str, data->len);
    g_string_free(data, TRUE);
    return valid;
}
static bool
mcp_empty_ack(struct broker *broker)
{
    if (!mcp_headers(broker, true))
        return false;
    unsigned char   byte;
    ssize_t         count = mcp_entity_read(broker, &byte, 1);
    return (count == 0 && broker->entity_eof && mcp_retire_connection(broker)) || broker_fail(broker, "mcp_ack_refused");
}
static struct mcp_receipt *
mcp_decode_message(struct broker *broker, const unsigned char *bytes, size_t size)
{
    struct mcp_json json;
    if (!mcp_json_parse(bytes, size, &json)) {
        broker_fail(broker, "mcp_response_refused");
        return NULL;
    }
    struct mcp_receipt *receipt = NULL;
    unsigned        id = mcp_json_member(&json, 1, "id"), result = mcp_json_member(&json, 1, "result"), error = mcp_json_member(&json, 1, "error"), method = mcp_json_member(&json, 1, "method"),
                    params = mcp_json_member(&json, 1, "params");
    const char     *response_keys[] = {"jsonrpc", "id", "result", "error"}, *request_keys[] = {"jsonrpc", "id", "method", "params"};
    bool            valid = mcp_json_text(&json, mcp_json_member(&json, 1, "jsonrpc"), "2.0") && broker->aggregate_entries <= MCP_MAX_ENTRIES - json.entries;
    if (valid)
        broker->aggregate_entries += json.entries;
    enum mcp_message_kind kind = MCP_NOTIFICATION;
    unsigned char  *semantic_id = NULL;
    size_t          semantic_id_size = 0;
    if (result || error) {
        valid = valid && mcp_json_keys(&json, 1, response_keys, 4) && !!result != !!error && mcp_json_id(&json, id, &semantic_id, &semantic_id_size) &&
            semantic_id_size == broker->frames[broker->phase].id_size && !memcmp(semantic_id, broker->frames[broker->phase].id, semantic_id_size);
        if (result)
            valid = valid && json.nodes[result].type == '{';
        if (error) {
            const char     *error_keys[] = {"code", "message", "data"};
            unsigned        code = mcp_json_member(&json, error, "code"), message = mcp_json_member(&json, error, "message");
            unsigned char  *integer = NULL;
            size_t          integer_size = 0;
            valid = valid && mcp_json_keys(&json, error, error_keys, 3) && code && json.nodes[code].type == '#' && mcp_json_id(&json, code, &integer, &integer_size) && message && json.nodes[message].type == '"';
            free(integer);
        }
        if (broker->phase == 2 && result && mcp_json_member(&json, result, "nextCursor"))
            valid = false;
        kind = MCP_RESPONSE;
    } else {
        valid = valid && mcp_json_keys(&json, 1, request_keys, 4) && method && (!params || json.nodes[params].type == '{');
        if (id) {
            valid = valid && mcp_json_text(&json, method, "ping") && (!params || !json.nodes[params].child) && mcp_json_id(&json, id, &semantic_id, &semantic_id_size) && broker->ping_count < MCP_MAX_PINGS;
            kind = MCP_PING;
        } else {
            bool            changed = mcp_json_text(&json, method, "notifications/tools/list_changed");
            valid = valid && (changed || mcp_json_text(&json, method, "notifications/progress") || mcp_json_text(&json, method, "notifications/message"));
            if (changed) {
                valid = valid && (!params || !json.nodes[params].child);
                broker->invalidated = true;
            }
        }
    }
    if (valid) {
        receipt = calloc(1, sizeof(*receipt));
        if (receipt) {
            receipt->message = malloc(size);
            receipt->owner = broker;
            receipt->env = broker->env;
            receipt->creator_pid = broker->creator_pid;
            receipt->phase = broker->phase;
            receipt->ordinal = ++broker->ordinal;
            receipt->kind = kind;
            receipt->size = size;
            receipt->id = semantic_id;
            semantic_id = NULL;
            receipt->id_size = semantic_id_size;
            valid = receipt->message && RAND_bytes(receipt->nonce, sizeof(receipt->nonce)) == 1 && digest_hex(bytes, size, receipt->digest);
            if (valid) {
                memcpy(receipt->message, bytes, size);
                receipt->next = broker->receipts;
                broker->receipts = receipt;
                if (kind == MCP_PING) {
                    broker->ping_count++;
                    receipt->ping_state = MCP_PING_RECEIVED;
                    broker->ping = receipt;
                }
            } else {
                free(receipt->id);
                free(receipt->message);
                free(receipt);
                receipt = NULL;
            }
        }
    }
    free(semantic_id);
    free(json.nodes);
    if (!receipt)
        broker_fail(broker, "mcp_response_refused");
    return receipt;
}
static void     mcp_tail_notifications(struct broker *broker, size_t start);
static bool
mcp_drain_received_tail(struct broker *broker)
{
    /*
     * OpenSSL may already hold the rest of the TLS record that supplied the terminal SSE event. Consume only
     * SSL_pending plaintext, never another socket read, and retain every parseable entity byte in that read-ahead.
     * Partial chunk framing is transport data, not a fabricated HTTP EOF.
     */
    unsigned char   bytes[16384];
    char            line[17];
    size_t          line_size = 0;
    bool            line_cr = false, zero_chunk = false, wire_refused = false;
    unsigned        ending = 0;
    while (broker->tls && SSL_pending(broker->tls) > 0) {
        int             pending = SSL_pending(broker->tls);
        size_t          wanted = (size_t) pending < sizeof(bytes) ? (size_t) pending : sizeof(bytes), received = 0;
        if (SSL_read_ex(broker->tls, bytes, wanted, &received) != 1 || !received) {
            wipe(bytes, sizeof(bytes));
            return broker_fail(broker, "mcp_transport_interrupted");
        }
        for (size_t at = 0; at < received; at++) {
            unsigned char   byte = bytes[at];
            if (wire_refused)
                continue;
            if (broker->entity_eof) {
                broker->invalidated = true;
                continue;
            }
            if (!broker->chunked) {
                if (broker->length_present && !broker->content_remaining) {
                    broker->entity_eof = true;
                    broker->invalidated = true;
                    continue;
                } if (!mcp_append(broker, &byte, 1)) {
                    wipe(bytes, sizeof(bytes));
                    return false;
                } if (broker->length_present && !--broker->content_remaining)
                    broker->entity_eof = true;
                continue;
            }
            if (broker->chunk_remaining) {
                if (!mcp_append(broker, &byte, 1)) {
                    wipe(bytes, sizeof(bytes));
                    return false;
                } if (!--broker->chunk_remaining) {
                    broker->awaiting_chunk_crlf = true;
                    ending = 0;
                } continue;
            }
            if (broker->awaiting_chunk_crlf || zero_chunk) {
                if (byte != (ending ? '\n' : '\r')) {
                    broker->invalidated = true;
                    wire_refused = true;
                    continue;
                } if (++ending == 2) {
                    ending = 0;
                    if (zero_chunk)
                        broker->entity_eof = true;
                    else
                        broker->awaiting_chunk_crlf = false;
                } continue;
            }
            if (line_cr) {
                if (byte != '\n' || !line_size) {
                    broker->invalidated = true;
                    wire_refused = true;
                    continue;
                } line[line_size] = '\0';
                errno = 0;
                char           *end;
                broker->chunk_remaining = strtoull(line, &end, 16);
                if (errno || *end) {
                    broker->invalidated = true;
                    wire_refused = true;
                    continue;
                } zero_chunk = !broker->chunk_remaining;
                line_size = 0;
                line_cr = false;
                ending = 0;
                continue;
            }
            if (byte == '\r') {
                line_cr = true;
                continue;
            } if (line_size == 16 || broker_hex_digit(byte) < 0) {
                broker->invalidated = true;
                wire_refused = true;
                continue;
            } line[line_size++] = (char)byte;
        }
    }
    wipe(bytes, sizeof(bytes));
    wipe(line, sizeof(line));
    return true;
}
static bool
mcp_freeze_capture(struct broker *broker, struct mcp_receipt *receipt, size_t event_end)
{
    if (broker->sse && !mcp_drain_received_tail(broker))
        return false;
    if (broker->sse)
        mcp_tail_notifications(broker, event_end);
    const char     *prior = atomic_load(&broker->error);
    bool            screened = mcp_screen_capture(broker), unusable = false;
    if (!screened && !prior && broker->sse && receipt->kind == MCP_RESPONSE) {
        const char     *expected = atomic_load(&broker->error);
        unusable = expected && !strcmp(expected, "broker_response_refused") && atomic_compare_exchange_strong(&broker->error, &expected, "mcp_full_capture_no_echo_refused");
    }
    if ((!screened && !unusable) || !mcp_retire_connection(broker))
        return false;
    struct mcp_capture *capture = calloc(1, sizeof(*capture));
    if (!capture)
        return broker_fail(broker, "mcp_worker_unavailable");
    capture->owner = broker;
    capture->phase = broker->phase;
    capture->ordinal = receipt->ordinal;
    capture->bytes = broker->response;
    capture->size = broker->response_size;
    capture->end_offset = event_end;
    capture->sse = broker->sse;
    capture->http_eof = broker->entity_eof;
    capture->joined = true;
    capture->screened = screened;
    capture->no_echo_refused = unusable;
    if (!digest_hex(capture->bytes, capture->size, capture->digest)) {
        free(capture);
        return broker_fail(broker, "mcp_worker_unavailable");
    }
    broker->response = NULL;
    broker->response_size = 0;
    if (broker->data_responses >= (broker->admin ? 2u : 3u)) {
        wipe(capture->bytes, capture->size);
        free(capture->bytes);
        free(capture);
        return broker_fail(broker, "mcp_extra_response_refused");
    }
    if (unusable) {
        wipe(capture->bytes, capture->size);
        free(capture->bytes);
        capture->bytes = NULL;
    }
    broker->captures[broker->data_responses++] = capture;
    return true;
}
static void
mcp_tail_notifications(struct broker *broker, size_t start)
{
    GString        *data = g_string_new(NULL);
    bool            data_present = false;
    if (!data) {
        broker->invalidated = true;
        return;
    }
    while (start < broker->response_size) {
        size_t          end = start;
        while (end < broker->response_size && broker->response[end] != '\r' && broker->response[end] != '\n')
            end++;
        if (end == broker->response_size)
            break;
        size_t          next = end + 1;
        if (broker->response[end] == '\r' && next < broker->response_size && broker->response[next] == '\n')
            next++;
        if (end == start && data_present) {
            struct mcp_json json;
            if (!mcp_json_parse((unsigned char *)data->str, data->len, &json))
                broker->invalidated = true;
            else {
                unsigned        method = mcp_json_member(&json, 1, "method");
                const char     *allowed[] = {"jsonrpc", "method", "params"};
                if (!mcp_json_keys(&json, 1, allowed, 3) || !mcp_json_text(&json, mcp_json_member(&json, 1, "jsonrpc"), "2.0") ||
                    !(mcp_json_text(&json, method, "notifications/progress") || mcp_json_text(&json, method, "notifications/message")))
                    broker->invalidated = true;
                if (broker->aggregate_entries > MCP_MAX_ENTRIES - json.entries)
                    broker->invalidated = true;
                else
                    broker->aggregate_entries += json.entries;
                free(json.nodes);
            }
            g_string_truncate(data, 0);
            data_present = false;
        } else {
            size_t          at;
            if (!mcp_sse_data_field(broker->response, start, end, &at)) {
                start = next;
                continue;
            }
            if (data_present)
                g_string_append_c(data, '\n');
            g_string_append_len(data, (char *)broker->response + at, (gssize) (end - at));
            data_present = true;
        }
        start = next;
    }
    wipe(data->str, data->len);
    g_string_free(data, TRUE);
}
static bool
mcp_sse_next(struct broker *broker)
{
    size_t          start = broker->sse_line_start;
    if (start == 0 && broker->response_size >= 3 && !memcmp(broker->response, "\xef\xbb\xbf", 3))
        start = broker->sse_line_start = 3;
    if (broker->sse_skip_lf && broker->parse_at < broker->response_size) {
        if (broker->response[broker->parse_at] == '\n') {
            broker->parse_at++;
            broker->sse_line_start = broker->parse_at;
            start = broker->parse_at;
        } broker->sse_skip_lf = false;
    }
    for (size_t at = broker->parse_at; at < broker->response_size; at++) {
        unsigned char   byte = broker->response[at];
        if (byte != '\r' && byte != '\n')
            continue;
        if (byte == '\r' && at + 1 == broker->response_size)
            broker->sse_skip_lf = true;
        size_t          end = at;
        if (byte == '\r' && at + 1 < broker->response_size && broker->response[at + 1] == '\n')
            at++;
        size_t          line_end = at + 1, count = end - start;
        broker->sse_line_start = line_end;
        broker->parse_at = line_end;
        if (!count) {
            if (broker->sse_data_present) {
                if (broker->sse_event->len && strcmp(broker->sse_event->str, "message"))
                    return broker_fail(broker, "mcp_response_refused");
                if (!mcp_no_echo_all(broker, (unsigned char *)broker->sse_data->str, broker->sse_data->len))
                    return false;
                struct mcp_receipt *receipt = mcp_decode_message(broker, (unsigned char *)broker->sse_data->str, broker->sse_data->len);
                if (!receipt)
                    return false;
                g_string_truncate(broker->sse_data, 0);
                broker->sse_data_present = false;
                g_string_truncate(broker->sse_event, 0);
                broker->pending = receipt;
                if (receipt->kind == MCP_RESPONSE)
                    return mcp_freeze_capture(broker, receipt, line_end);
                /*
                 * Only this fully screened event crosses the message boundary. The unchanged complete raw prefix
                 * remains owned until final freeze/join and its full raw/reconstructed-data screen.
                 */
                return true;
            }
            g_string_truncate(broker->sse_event, 0);
        } else if (broker->response[start] != ':') {
            size_t          colon = start;
            while (colon < end && broker->response[colon] != ':')
                colon++;
            size_t          content = colon < end ? colon + 1 : end;
            if (content < end && broker->response[content] == ' ')
                content++;
            if (colon - start == 4 && !memcmp(broker->response + start, "data", 4)) {
                if (broker->sse_data_present)
                    g_string_append_c(broker->sse_data, '\n');
                g_string_append_len(broker->sse_data, (char *)broker->response + content, (gssize) (end - content));
                broker->sse_data_present = true;
            } else if (colon - start == 5 && !memcmp(broker->response + start, "event", 5)) {
                g_string_truncate(broker->sse_event, 0);
                g_string_append_len(broker->sse_event, (char *)broker->response + content, (gssize) (end - content));
            }
        }
        start = line_end;
    }
    broker->parse_at = broker->response_size;
    return true;
}
static bool
mcp_read_message(struct broker *broker)
{
    if (!broker->headers_received && !mcp_headers(broker, false))
        return false;
    if (!broker->response) {
        broker->response = malloc(broker->maximum_response_bytes);
        if (!broker->response)
            return broker_fail(broker, "mcp_worker_unavailable");
    }
    unsigned char   bytes[8192];
    bool            valid = true;
    for (;;) {
        if (broker->sse) {
            if (!mcp_sse_next(broker)) {
                valid = false;
                break;
            } if (broker->pending)
                break;
        }
        ssize_t         count = mcp_entity_read(broker, bytes, sizeof(bytes));
        if (count < 0) {
            valid = false;
            break;
        }
        if (count) {
            if (!mcp_append(broker, bytes, (size_t) count)) {
                valid = false;
                break;
            } continue;
        }
        if (broker->sse) {
            valid = mcp_sse_next(broker) && broker->pending;
            if (!valid)
                broker_fail(broker, "mcp_incomplete_sse_response");
            break;
        }
        if (!mcp_screen_capture(broker)) {
            valid = false;
            break;
        }
        struct mcp_receipt *receipt = mcp_decode_message(broker, broker->response, broker->response_size);
        if (!receipt || receipt->kind != MCP_RESPONSE) {
            valid = broker_fail(broker, "mcp_response_refused");
            break;
        }
        broker->pending = receipt;
        valid = mcp_freeze_capture(broker, receipt, 0);
        break;
    }
    wipe(bytes, sizeof(bytes));
    return valid;
}
static bool
mcp_ping_body(struct broker *broker, unsigned char **output, size_t * size)
{
    struct mcp_receipt *receipt = broker->ping;
    if (!receipt)
        return false;
    struct mcp_json json;
    if (!mcp_json_parse(receipt->message, receipt->size, &json))
        return false;
    unsigned        id = mcp_json_member(&json, 1, "id");
    const struct mcp_json_node *node = id ? &json.nodes[id] : NULL;
    bool            valid = node != NULL;
    static const char prefix[] = "{\"jsonrpc\":\"2.0\",\"id\":";
    static const char suffix[] = ",\"result\":{}}";
    if (valid) {
        size_t          id_size = node->end - node->start;
        *size = sizeof(prefix) - 1 + id_size + sizeof(suffix) - 1;
        *output = malloc(*size);
        valid = *output != NULL;
        if (valid) {
            memcpy(*output, prefix, sizeof(prefix) - 1);
            memcpy(*output + sizeof(prefix) - 1, receipt->message + node->start, id_size);
            memcpy(*output + sizeof(prefix) - 1 + id_size, suffix, sizeof(suffix) - 1);
        }
    }
    free(json.nodes);
    return valid;
}
static napi_value mcp_error(struct broker *broker){
    napi_value      message, error;
    napi_create_string_utf8(broker->env, atomic_load(&broker->unsafe) ? "Installed MCP owner resources did not retire" : "Installed MCP owner refused the operation", NAPI_AUTO_LENGTH, &message);
    napi_create_error(broker->env, NULL, message, &error);
    set_string(broker->env, error, "code", atomic_load(&broker->unsafe) ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_MCP_BROKER");
    set_string(broker->env, error, "brokerCode", atomic_load(&broker->unsafe) ? "resource_retirement" : atomic_load(&broker->error) ? atomic_load(&broker->error) : "mcp_operation_refused");
    return error;
}
static bool
mcp_current(struct broker *broker, napi_env env)
{
    return broker && broker->env == env && broker->creator_pid == getpid() && syscall(SYS_gettid) == getpid();
}
static struct broker *
mcp_receiver(napi_env env, napi_callback_info info, size_t * argc, napi_value * args)
{
    napi_value      self;
    bool            run = false, admin = false;
    struct broker  *broker = NULL;
    if (napi_get_cb_info(env, info, argc, args, &self, NULL) != napi_ok || napi_check_object_type_tag(env, self, &mcp_run_tag, &run) != napi_ok ||
        napi_check_object_type_tag(env, self, &mcp_admin_tag, &admin) != napi_ok || (!run && !admin) || napi_unwrap(env, self, (void **)&broker) != napi_ok ||
        !mcp_current(broker, env) || broker->admin != admin) {
        napi_throw_type_error(env, NULL, "Invalid installed MCP owner");
        return NULL;
    } return broker;
}
static bool
mcp_binding_matches(struct broker *broker, napi_value value, bool allow_bind, bool live)
{
    bool            valid = false;
    if (broker->admin) {
        struct cliq_mcp_admin_binding binding = {0};
        valid = mcp_admin_binding(broker->env, value, &binding);
        if (valid && broker->bound)
            valid = !memcmp(&binding, &broker->admin_binding, sizeof(binding));
        else if (valid && allow_bind && broker->peer) {
            const struct cliq_mcp_admin_binding *original = &broker->peer->binding;
            valid = broker->peer->assert_current && broker->peer->assert_current(broker->peer) && !strcmp(binding.operation, original->operation) && binding.attempt == original->attempt && !strcmp(binding.principal, original->principal) &&
                !strcmp(binding.target_ref, original->target_ref) && !strcmp(binding.target_digest, original->target_digest) && !strcmp(binding.core_ref, original->core_ref) && !strcmp(binding.core_digest, original->core_digest) &&
                !strcmp(binding.plan_ref, original->plan_ref) && !strcmp(binding.plan_digest, original->plan_digest) && !strcmp(binding.spec_ref, original->spec_ref) && !strcmp(binding.spec_digest, original->spec_digest);
            if (valid) {
                broker->admin_binding = binding;
                broker->bound = true;
            }
        } else
            valid = false;
        if (valid && live)
            valid = broker->peer && broker->peer->assert_current && broker->peer->assert_current(broker->peer) && !memcmp(&binding, &broker->peer->binding, sizeof(binding));
    } else {
        struct cliq_mcp_run_binding binding = {0};
        valid = mcp_run_binding(broker->env, value, &binding) && !strcmp(binding.token_digest, broker->token_digest);
        if (valid && broker->bound)
            valid = !memcmp(&binding, &broker->run_binding, sizeof(binding));
        else if (valid && allow_bind) {
            broker->run_binding = binding;
            broker->bound = true;
        } else
            valid = false;
    }
    if (valid && live) {
        struct timespec now;
        uint64_t        deadline = broker->admin ? broker->admin_binding.deadline_ms : broker->run_binding.deadline_ms;
        valid = !broker->closing && !broker->retired && broker_live(broker) && !clock_gettime(CLOCK_REALTIME, &now) && now.tv_sec >= 0 &&
            (uint64_t) now.tv_sec <= UINT64_C(9007199254740) && (uint64_t) now.tv_sec * 1000 + (uint64_t) now.tv_nsec / 1000000 < deadline;
    }
    return valid;
}
static void
mcp_receipt_finalizer(napi_env env, void *data, void *hint)
{
    (void)hint;
    struct mcp_receipt *receipt = data;
    napi_ref        owner = receipt->owner_ref;
    receipt->owner_ref = NULL;
    if (owner)
        napi_delete_reference(env, owner);
}
static napi_value mcp_receipt_value(struct mcp_receipt *receipt){
    napi_value      value, owner;
    struct broker  *broker = receipt->owner;
    if (napi_create_object(broker->env, &value) != napi_ok || napi_type_tag_object(broker->env, value, receipt->kind == MCP_PING ? &mcp_ping_tag : &mcp_message_tag) != napi_ok ||
        napi_get_reference_value(broker->env, broker->handle, &owner) != napi_ok || napi_create_reference(broker->env, owner, 1, &receipt->owner_ref) != napi_ok ||
        napi_wrap(broker->env, value, receipt, mcp_receipt_finalizer, NULL, NULL) != napi_ok || napi_object_freeze(broker->env, value) != napi_ok)
        return NULL;
    return value;
}
static bool
mcp_receipt_unwrap(struct broker *broker, napi_value value, enum mcp_message_kind kind, struct mcp_receipt **receipt)
{
    bool            tagged = false;
    return napi_check_object_type_tag(broker->env, value, kind == MCP_PING ? &mcp_ping_tag : &mcp_message_tag, &tagged) == napi_ok && tagged &&
        napi_unwrap(broker->env, value, (void **)receipt) == napi_ok && *receipt && (*receipt)->owner == broker && (*receipt)->kind == kind &&
        (*receipt)->env == broker->env && (*receipt)->creator_pid == getpid();
}
struct mcp_capture_handle {
    struct mcp_capture *capture;
    napi_ref        owner;
};
static void
mcp_capture_finalizer(napi_env env, void *data, void *hint)
{
    (void)hint;
    struct mcp_capture_handle *handle = data;
    if (handle->owner)
        napi_delete_reference(env, handle->owner);
    free(handle);
}
static bool
mcp_wrap_capture(struct broker *broker, napi_value value, struct mcp_capture *capture, const napi_type_tag * tag)
{
    struct mcp_capture_handle *handle = calloc(1, sizeof(*handle));
    napi_value      owner;
    if (!handle)
        return false;
    handle->capture = capture;
    if (napi_type_tag_object(broker->env, value, tag) != napi_ok || napi_get_reference_value(broker->env, broker->handle, &owner) != napi_ok ||
        napi_create_reference(broker->env, owner, 1, &handle->owner) != napi_ok || napi_wrap(broker->env, value, handle, mcp_capture_finalizer, NULL, NULL) != napi_ok) {
        if (handle->owner)
            napi_delete_reference(broker->env, handle->owner);
        free(handle);
        return false;
    } return true;
}
static napi_value mcp_copy_bytes(napi_env env, napi_callback_info info) {
    size_t          argc = 1;
    napi_value      args[1], self, value;
    bool            tagged = false;
    struct mcp_capture_handle *handle = NULL;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc || napi_check_object_type_tag(env, self, &mcp_bytes_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&handle) != napi_ok || !handle || !mcp_current(handle->capture->owner, env) || !handle->capture->joined || !handle->capture->screened || !handle->capture->bytes) {
        napi_throw_type_error(env, NULL, "Invalid screened MCP capture");
        return NULL;
    }
    return napi_create_buffer_copy(env, handle->capture->size, handle->capture->bytes, NULL, &value) == napi_ok ? value : NULL;
}
static napi_value mcp_raw_value(struct broker *broker, struct mcp_capture *capture){
    if (!capture->screened || !capture->bytes)
        return NULL;
    napi_value      value, bytes, join;
    if (napi_create_object(broker->env, &value) != napi_ok || napi_create_object(broker->env, &bytes) != napi_ok || napi_create_object(broker->env, &join) != napi_ok)
        return NULL;
    const           napi_property_descriptor methods[] = {{"copy", NULL, mcp_copy_bytes, NULL, NULL, NULL, napi_default, NULL}};
    if (!mcp_wrap_capture(broker, value, capture, &mcp_raw_tag) || !mcp_wrap_capture(broker, bytes, capture, &mcp_bytes_tag) || !mcp_wrap_capture(broker, join, capture, &mcp_response_join_tag) ||
        napi_define_properties(broker->env, bytes, 1, methods) != napi_ok || napi_object_freeze(broker->env, bytes) != napi_ok || napi_object_freeze(broker->env, join) != napi_ok ||
        napi_set_named_property(broker->env, value, "screenedRawCapture", bytes) != napi_ok || napi_set_named_property(broker->env, value, "actualResponseJoin", join) != napi_ok)
        return NULL;
    set_string(broker->env, value, "mediaType", capture->sse ? "text/event-stream" : "application/json");
    set_string(broker->env, value, "termination", capture->sse ? "sse_response_event" : "http_eof");
    set_number(broker->env, value, "rawFinitePrefixBytes", capture->size);
    set_string(broker->env, value, "rawFinitePrefixDigest", capture->digest);
    set_number(broker->env, value, "receivedTailBytes", capture->sse ? capture->size - capture->end_offset : 0);
    if (capture->sse)
        set_number(broker->env, value, "responseEventEndOffset", capture->end_offset);
    return napi_object_freeze(broker->env, value) == napi_ok ? value : NULL;
}
static napi_value mcp_message_value(struct broker *broker){
    napi_value      value;
    if (napi_create_object(broker->env, &value) != napi_ok)
        return NULL;
    if (broker->ack_ready) {
        broker->ack_ready = false;
        set_string(broker->env, value, "kind", "stage_completed");
        set_string(broker->env, value, "phase", "initialized");
    } else if (broker->admin_requested && !broker->pending) {
        broker->admin_event_delivered = true;
        set_string(broker->env, value, "kind", "stage_requested");
        set_string(broker->env, value, "phase", mcp_phase_name(broker->next_phase));
    } else {
        struct mcp_receipt *receipt = broker->pending;
        if (!receipt)
            return NULL;
        broker->pending = NULL;
        set_string(broker->env, value, "kind", receipt->kind == MCP_PING ? "ping" : receipt->kind == MCP_RESPONSE ? "response" : "notification");
        set_string(broker->env, value, "phase", mcp_phase_name(receipt->phase));
        set_number(broker->env, value, "ordinal", receipt->ordinal);
        set_string(broker->env, value, "messageDigest", receipt->digest);
        napi_value      bytes, proof = mcp_receipt_value(receipt);
        if (!proof || napi_create_buffer_copy(broker->env, receipt->size, receipt->message, NULL, &bytes) != napi_ok || napi_set_named_property(broker->env, value, "messageBytes", bytes) != napi_ok || napi_set_named_property(broker->env, value, "receipt", proof) != napi_ok)
            return NULL;
    }
    return napi_object_freeze(broker->env, value) == napi_ok ? value : NULL;
}
static bool
mcp_deliver_pending(struct broker *broker)
{
    if (!broker->message_deferred || (!broker->pending && !broker->ack_ready && !(broker->admin_requested && !broker->admin_event_delivered)))
        return true;
    napi_value      value = mcp_message_value(broker);
    if (!value)
        return broker_fail(broker, "mcp_worker_unavailable");
    napi_resolve_deferred(broker->env, broker->message_deferred, value);
    broker->message_deferred = NULL;
    return true;
}
static bool
mcp_poll_admin_requested(struct broker *broker)
{
    if (!broker->admin || !broker->peer || broker->closing || broker->admin_requested || broker->working || broker->connected || broker->pending || broker->ping || broker->protocol_complete)
        return true;
    struct cliq_mcp_fixed_frame_view view = {0};
    int             state = broker->peer->peer.poll_fixed_frame(broker->peer->peer.context, &view);
    if (state < 0)
        return broker_fail(broker, "mcp_admin_protocol_refused");
    if (!state)
        return true;
    if (view.phase != broker->next_phase || view.phase > 2 || view.size != broker->frames[view.phase].size ||
        memcmp(view.bytes, broker->frames[view.phase].body, view.size) || strcmp(view.digest, broker->frames[view.phase].digest))
        return broker_fail(broker, "mcp_admin_frame_mismatch");
    broker->admin_requested = true;
    broker->admin_event_delivered = false;
    return mcp_deliver_pending(broker);
}
static napi_value mcp_connect_stage_call(napi_env env, napi_callback_info info) {
    size_t          argc = 3;
    napi_value      args[3];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    char            phase[32];
    size_t          size;
    bool            valid = argc == 2 && napi_get_value_string_utf8(env, args[1], phase, sizeof(phase), &size) == napi_ok && !strcmp(phase, mcp_phase_name(broker->next_phase)) &&
    !broker->working && !broker->connected && !broker->pending && !broker->ping && !broker->ack_ready && broker->prepared && atomic_load(&broker->fence_retained) &&
    broker->next_phase < (broker->admin ? 3u : 4u) && !broker->phase_attempted[broker->next_phase] && !broker->invalidated && (!broker->admin || broker->admin_requested) &&
    broker->bound && !atomic_load(&broker->error) && mcp_binding_matches(broker, args[0], false, true);
    napi_value      promise;
    if (!valid || napi_create_promise(env, &broker->phase_deferred, &promise) != napi_ok) {
        napi_throw_type_error(env, NULL, "MCP fixed-stage CONNECT is unavailable or mismatched");
        return NULL;
    }
    broker->phase = broker->next_phase;
    broker->phase_attempted[broker->phase] = true;
    broker->network_started = true;
    broker->active_releases++;
    if (!mcp_queue(broker, MCP_CONNECT_STAGE))
        mcp_begin_close(broker);
    return promise;
}
static napi_value mcp_release_stage_call(napi_env env, napi_callback_info info) {
    size_t          argc = 3;
    napi_value      args[3];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    char            phase[32];
    size_t          size;
    bool            valid = argc == 2 && napi_get_value_string_utf8(env, args[1], phase, sizeof(phase), &size) == napi_ok && !strcmp(phase, mcp_phase_name(broker->phase)) &&
    !broker->working && broker->connected && !broker->phase_released[broker->phase] && !broker->pending && !broker->ping && !broker->invalidated &&
    atomic_load(&broker->fence_retained) && !atomic_load(&broker->error) && mcp_binding_matches(broker, args[0], false, true);
    if (!valid || pthread_mutex_lock(&broker->release_mutex)) {
        napi_throw_type_error(env, NULL, "MCP fixed-stage release is unavailable or mismatched");
        return NULL;
    }
    valid = !broker->token_revoked && !atomic_load(&broker->cancelled);
    if (valid) {
        broker->phase_released[broker->phase] = true;
        broker->request_started = true;
        if (broker->phase == 3)
            broker->effect_released = true;
        else
            broker->setup_released = true;
        broker->admin_requested = false;
    }
    if (pthread_mutex_unlock(&broker->release_mutex)) {
        atomic_store(&broker->unsafe, true);
        atomic_store(&retirement_failed, true);
        valid = false;
    }
    if (!valid) {
        napi_throw(env, mcp_error(broker));
        return NULL;
    }
    if (!mcp_queue(broker, MCP_EXCHANGE_STAGE)) {
        mcp_begin_close(broker);
        napi_throw(env, mcp_error(broker));
        return NULL;
    }
    napi_value      value;
    napi_get_undefined(env, &value);
    return value;
}
static napi_value mcp_next_message_call(napi_env env, napi_callback_info info) {
    size_t          argc = 1;
    napi_value      args[1];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    napi_value      promise;
    if (argc || broker->message_deferred || broker->closing || broker->retired || !broker->prepared || napi_create_promise(env, &broker->message_deferred, &promise) != napi_ok) {
        napi_throw_type_error(env, NULL, "MCP message queue is unavailable or occupied");
        return NULL;
    }
    if (!mcp_deliver_pending(broker) || !mcp_poll_admin_requested(broker))
        mcp_begin_close(broker);
    else if (broker->message_deferred && !broker->working && broker->connected && !broker->ping && broker->phase_released[broker->phase]) {
        if (!mcp_queue(broker, MCP_READ_STAGE))
            mcp_begin_close(broker);
    }
    return promise;
}
static napi_value mcp_connect_ping_call(napi_env env, napi_callback_info info) {
    size_t          argc = 3;
    napi_value      args[3];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    struct mcp_receipt *receipt = NULL;
    napi_value      promise;
    bool            valid = argc == 2 && !broker->working && broker->connected && broker->ping && mcp_receipt_unwrap(broker, args[1], MCP_PING, &receipt) && receipt == broker->ping &&
    receipt->phase == broker->phase && receipt->ping_state == MCP_PING_RECEIVED && !broker->pending && !atomic_load(&broker->error) && mcp_binding_matches(broker, args[0], false, true);
    if (!valid || napi_create_promise(env, &broker->phase_deferred, &promise) != napi_ok) {
        napi_throw_type_error(env, NULL, "MCP ping CONNECT receipt is unavailable or mismatched");
        return NULL;
    }
    receipt->ping_state = MCP_PING_CONNECTING;
    mcp_pause_connection(broker);
    broker->active_releases++;
    if (!mcp_queue(broker, MCP_CONNECT_PING))
        mcp_begin_close(broker);
    return promise;
}
static napi_value mcp_release_ping_call(napi_env env, napi_callback_info info) {
    size_t          argc = 3;
    napi_value      args[3];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    struct mcp_receipt *receipt = NULL;
    bool            valid = argc == 2 && !broker->working && broker->ping && broker->connection && mcp_receipt_unwrap(broker, args[1], MCP_PING, &receipt) && receipt == broker->ping &&
    receipt->ping_state == MCP_PING_CONNECTED && !atomic_load(&broker->error) && mcp_binding_matches(broker, args[0], false, true);
    if (!valid || pthread_mutex_lock(&broker->release_mutex)) {
        napi_throw_type_error(env, NULL, "MCP ping release receipt is unavailable or mismatched");
        return NULL;
    }
    valid = !broker->token_revoked && !atomic_load(&broker->cancelled);
    if (valid) {
        receipt->ping_state = MCP_PING_RELEASED;
        broker->request_started = true;
        broker->setup_released = true;
    }
    if (pthread_mutex_unlock(&broker->release_mutex)) {
        atomic_store(&broker->unsafe, true);
        atomic_store(&retirement_failed, true);
        valid = false;
    }
    if (!valid || !mcp_queue(broker, MCP_EXCHANGE_PING)) {
        mcp_begin_close(broker);
        napi_throw(env, mcp_error(broker));
        return NULL;
    }
    napi_value      value;
    napi_get_undefined(env, &value);
    return value;
}
static napi_value mcp_finish_response_call(napi_env env, napi_callback_info info) {
    size_t          argc = 2;
    napi_value      args[2];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    struct mcp_receipt *receipt = NULL;
    struct mcp_capture *capture = NULL;
    bool            valid = argc == 1 && (!broker->working || broker->stage == MCP_RETIRE) && mcp_receipt_unwrap(broker, args[0], MCP_RESPONSE, &receipt) && !receipt->finish_started;
    if (valid)
        for (unsigned i = 0; i < broker->data_responses; i++)
            if (broker->captures[i]->phase == receipt->phase && broker->captures[i]->ordinal == receipt->ordinal)
                capture = broker->captures[i];
    if (!valid || !capture || !capture->joined) {
        napi_throw_type_error(env, NULL, "MCP final response receipt is unavailable or mismatched");
        return NULL;
    }
    receipt->finish_started = true;
    napi_value      promise;
    napi_deferred   deferred;
    if (napi_create_promise(env, &deferred, &promise) != napi_ok) {
        napi_throw(env, mcp_error(broker));
        return NULL;
    }
    if (capture->no_echo_refused) {
        napi_reject_deferred(env, deferred, mcp_error(broker));
        return promise;
    }
    napi_value      value = mcp_raw_value(broker, capture);
    if (!value) {
        napi_reject_deferred(env, deferred, mcp_error(broker));
        return promise;
    }
    receipt->finished = true;
    broker->phase_completed[receipt->phase] = true;
    broker->connected = false;
    broker->next_phase = receipt->phase + 1;
    broker->active_releases = 0;
    if (broker->admin && broker->peer) {
        struct cliq_mcp_screened_message_view view = {receipt->phase, receipt->message, receipt->size, false};
        if (broker->peer->peer.deliver_screened_message(broker->peer->peer.context, &view) < 0)
            broker_fail(broker, "mcp_admin_protocol_refused");
    }
    if (broker->next_phase == (broker->admin ? 3u : 4u))
        broker->protocol_complete = true;
    if (broker->admin && broker->protocol_complete) {
        broker->final_deferred = deferred;
        broker->admin_final_capture = capture;
    } else
        napi_resolve_deferred(env, deferred, value);
    return promise;
}
static napi_value mcp_assert_binding_call(napi_env env, napi_callback_info info) {
    size_t          argc = 2;
    napi_value      args[2];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    if (argc != 1 || !mcp_binding_matches(broker, args[0], false, false)) {
        napi_throw_type_error(env, NULL, "MCP original binding is mismatched");
        return NULL;
    } napi_value    value;
    napi_get_undefined(env, &value);
    return value;
}
static napi_value mcp_bind_call(napi_env env, napi_callback_info info) {
    size_t          argc = 2;
    napi_value      args[2];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    if (argc != 1 || !broker->prepared || broker->closing || broker->retired || broker->network_started || broker->request_started || !atomic_load(&broker->fence_retained) ||
        !mcp_binding_matches(broker, args[0], true, false)) {
        napi_throw_type_error(env, NULL, "MCP original immutable binding is unavailable or mismatched");
        return NULL;
    }
    napi_value      value;
    napi_get_undefined(env, &value);
    return value;
}
static napi_value mcp_unusable_value(struct broker *broker, struct mcp_capture *capture){
    napi_value      value, join;
    if (napi_create_object(broker->env, &value) != napi_ok || napi_create_object(broker->env, &join) != napi_ok || !mcp_wrap_capture(broker, value, capture, &mcp_unusable_tag) || !mcp_wrap_capture(broker, join, capture, &mcp_response_join_tag))
        return NULL;
    set_string(broker->env, value, "kind", "mcp_known_response_unusable");
    set_string(broker->env, value, "mediaType", "text/event-stream");
    set_string(broker->env, value, "termination", "sse_response_event");
    set_string(broker->env, value, "reason", "full_capture_no_echo_refused");
    set_number(broker->env, value, "rawFinitePrefixBytes", capture->size);
    set_string(broker->env, value, "rawFinitePrefixDigest", capture->digest);
    set_number(broker->env, value, "responseEventEndOffset", capture->end_offset);
    set_number(broker->env, value, "receivedTailBytes", capture->size - capture->end_offset);
    napi_object_freeze(broker->env, join);
    napi_set_named_property(broker->env, value, "actualResponseJoin", join);
    return napi_object_freeze(broker->env, value) == napi_ok ? value : NULL;
}
static struct mcp_capture *
mcp_unusable_capture(struct broker *broker, struct mcp_receipt *receipt)
{
    if (!receipt->finish_started || receipt->finished || !broker->close_finished || !broker->retired || !atomic_load(&broker->fence_retained) || atomic_load(&broker->unsafe))
        return NULL;
    for (unsigned i = 0; i < broker->data_responses; i++) {
        struct mcp_capture *capture = broker->captures[i];
        if (capture->phase == receipt->phase && capture->ordinal == receipt->ordinal && capture->sse && capture->joined && capture->no_echo_refused && !capture->screened && !capture->bytes)
            return capture;
    } return NULL;
}
static napi_value mcp_read_unusable_call(napi_env env, napi_callback_info info) {
    size_t          argc = 2;
    napi_value      args[2];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    struct mcp_receipt *receipt = NULL;
    if (atomic_load(&broker->unsafe)) {
        napi_throw(env, mcp_error(broker));
        return NULL;
    }
    struct mcp_capture *capture = argc == 1 && mcp_receipt_unwrap(broker, args[0], MCP_RESPONSE, &receipt) ? mcp_unusable_capture(broker, receipt) : NULL;
    if (!capture) {
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "MCP original joined unusable-response custody is unavailable");
        return NULL;
    } return mcp_unusable_value(broker, capture);
}
static napi_value mcp_assert_unusable_call(napi_env env, napi_callback_info info) {
    size_t          argc = 3;
    napi_value      args[3];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    struct mcp_receipt *receipt = NULL;
    struct mcp_capture_handle *handle = NULL;
    bool            tagged = false;
    struct mcp_capture *capture = argc == 2 && mcp_receipt_unwrap(broker, args[0], MCP_RESPONSE, &receipt) ? mcp_unusable_capture(broker, receipt) : NULL;
    if (!capture || napi_check_object_type_tag(env, args[1], &mcp_unusable_tag, &tagged) != napi_ok || !tagged || napi_unwrap(env, args[1], (void **)&handle) != napi_ok || !handle || handle->capture != capture) {
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "MCP original unusable-response proof is unavailable or mismatched");
        return NULL;
    } napi_value    value;
    napi_get_undefined(env, &value);
    return value;
}
static napi_value mcp_assert_joined_call(napi_env env, napi_callback_info info) {
    size_t          argc = 3;
    napi_value      args[3];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    bool            tagged = false;
    struct mcp_join *join = NULL;
    if (atomic_load(&broker->unsafe)) {
        napi_throw(env, mcp_error(broker));
        return NULL;
    }
    if (argc != 2 || !mcp_binding_matches(broker, args[1], false, false) || !atomic_load(&broker->fence_retained) || !broker->close_finished || !broker->retired || atomic_load(&broker->unsafe) ||
        !broker->token_revoked || !atomic_load(&broker->cancelled) || broker->active_releases || broker->working || broker->work ||
        broker->connection || broker->socket || broker->tls || broker->tls_context || broker->paused.connection || broker->paused.socket || broker->paused.tls || broker->paused.context ||
        (broker->timer_ready && !broker->timer_closed) || broker->platform.bus || broker->platform.runtime_fd >= 0 || broker->platform.cancel || broker->peer ||
        napi_check_object_type_tag(env, args[0], broker->admin ? &mcp_admin_join_tag : &mcp_run_join_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, args[0], (void **)&join) != napi_ok || !join || join != &broker->joined || join->owner != broker || join->env != env || join->creator_pid != getpid()) {
        napi_throw_type_error(env, NULL, "MCP original joined owner proof is unavailable or mismatched");
        return NULL;
    } napi_value    value;
    napi_get_undefined(env, &value);
    return value;
}
static napi_value mcp_assert_raw_call(napi_env env, napi_callback_info info) {
    size_t          argc = 3;
    napi_value      args[3];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    bool            tagged = false;
    struct mcp_receipt *receipt = NULL;
    struct mcp_capture_handle *handle = NULL;
    if (argc != 2 || !mcp_receipt_unwrap(broker, args[0], MCP_RESPONSE, &receipt) || !receipt->finished || napi_check_object_type_tag(env, args[1], &mcp_raw_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, args[1], (void **)&handle) != napi_ok || !handle || handle->capture->owner != broker || !handle->capture->joined || handle->capture->phase != receipt->phase || handle->capture->ordinal != receipt->ordinal) {
        napi_throw_type_error(env, NULL, "MCP original response custody is unavailable or mismatched");
        return NULL;
    } napi_value    value;
    napi_get_undefined(env, &value);
    return value;
}
static napi_value mcp_retain_call(napi_env env, napi_callback_info info) {
    size_t          argc = 1;
    napi_value      args[1];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    bool            expected = false;
    if (argc || !broker->prepared || broker->closing || broker->bound || !atomic_compare_exchange_strong(&broker->fence_retained, &expected, true)) {
        napi_throw_type_error(env, NULL, "MCP original domain cannot be retained");
        return NULL;
    } napi_value    value;
    napi_get_undefined(env, &value);
    return value;
}
static napi_value mcp_attach_peer_call(napi_env env, napi_callback_info info) {
    size_t          argc = 2;
    napi_value      args[2];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    bool            tagged = false;
    struct cliq_mcp_admin_peer_handle *peer = NULL;
    if (argc != 1 || !broker->admin || broker->peer || broker->bound || broker->closing || napi_check_object_type_tag(env, args[0], &CLIQ_MCP_ADMIN_PEER_TAG, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, args[0], (void **)&peer) != napi_ok || !peer || peer->abi_version != CLIQ_MCP_OWNER_ABI || peer->creator_pid != getpid() || peer->environment != env ||
        peer->borrowed || !peer->assert_current || !peer->assert_current(peer) || !peer->peer.context || !peer->peer.cancel || !peer->peer.poll_joined || !peer->peer.release_recipe ||
        !peer->peer.poll_fixed_frame || !peer->peer.deliver_screened_message || !peer->peer.begin_output_ack || !peer->peer.poll_output_ack || !peer->peer.release ||
        napi_create_reference(env, args[0], 1, &broker->peer_ref) != napi_ok) {
        napi_throw_type_error(env, NULL, "MCP Admin requires its genuine original contained protocol peer");
        return NULL;
    }
    peer->borrowed = true;
    broker->peer = peer;
    napi_value      value;
    napi_get_undefined(env, &value);
    return value;
}
static napi_value mcp_release_domain_call(napi_env env, napi_callback_info info) {
    size_t          argc = 1;
    napi_value      args[1];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    if (argc || !broker->retired || !broker->close_finished || broker->fence_locked || atomic_load(&broker->unsafe)) {
        napi_throw_type_error(env, NULL, "MCP original domain still owns resources or a guard");
        return NULL;
    }
    atomic_store(&broker->fence_retained, false);
    mcp_finish_close(broker);
    napi_value      value;
    napi_get_undefined(env, &value);
    return value;
}
struct mcp_fence {
    struct broker  *owner;
    napi_env        env;
    pid_t           creator_pid;
    napi_ref        original;
    bool            active;
};
static bool
mcp_fence_drop(struct mcp_fence *fence)
{
    if (!fence->active)
        return true;
    struct broker  *broker = fence->owner;
    if (!mcp_current(broker, fence->env) || fence->creator_pid != getpid() || (!(broker->env_closing && !broker->fence_locked) && (!broker->fence_locked || pthread_mutex_unlock(&broker->release_mutex)))) {
        atomic_store(&broker->unsafe, true);
        atomic_store(&retirement_failed, true);
        return false;
    }
    broker->fence_locked = false;
    napi_ref        original = fence->original;
    fence->original = NULL;
    fence->active = false;
    fence->owner = NULL;
    if (original && !broker->env_closing && napi_delete_reference(fence->env, original) != napi_ok) {
        atomic_store(&broker->unsafe, true);
        atomic_store(&retirement_failed, true);
        return false;
    }
    if (!broker->fence_borrows) {
        atomic_store(&broker->unsafe, true);
        atomic_store(&retirement_failed, true);
        return false;
    } broker->fence_borrows--;
    if (broker->finalize_requested)
        mcp_free(fence->env, broker);
    return true;
}
static void
mcp_fence_finalizer(napi_env env, void *data, void *hint)
{
    (void)env;
    (void)hint;
    struct mcp_fence *fence = data;
    if (mcp_fence_drop(fence))
        free(fence);
}
static struct mcp_fence *
mcp_fence_receiver(napi_env env, napi_callback_info info)
{
    size_t          argc = 1;
    napi_value      args[1], self;
    bool            tagged = false;
    struct mcp_fence *fence = NULL;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc || napi_check_object_type_tag(env, self, &mcp_fence_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&fence) != napi_ok || !fence || fence->env != env || fence->creator_pid != getpid() || syscall(SYS_gettid) != getpid() || (fence->active && !mcp_current(fence->owner, env))) {
        napi_throw_type_error(env, NULL, "Invalid original MCP no-release guard");
        return NULL;
    } return fence;
}
static napi_value mcp_fence_assert_call(napi_env env, napi_callback_info info) {
    struct mcp_fence *fence = mcp_fence_receiver(env, info);
    if (!fence)
        return NULL;
    struct broker  *broker = fence->owner;
    if (!fence->active || !broker->fence_locked || !broker->retired || broker->network_started || broker->request_started || broker->peer || !broker->token_revoked || broker->active_releases || atomic_load(&broker->unsafe)) {
        napi_throw_type_error(env, NULL, "Original MCP zero-I/O guard is no longer held");
        return NULL;
    } napi_value    value;
    napi_get_undefined(env, &value);
    return value;
}
static napi_value mcp_fence_close_call(napi_env env, napi_callback_info info) {
    struct mcp_fence *fence = mcp_fence_receiver(env, info);
    if (!fence)
        return NULL;
    struct broker  *original = fence->owner;
    if (!mcp_fence_drop(fence)) {
        if (original)
            napi_throw(env, mcp_error(original));
        else
            napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "MCP original guard did not retire");
        return NULL;
    } napi_value    value;
    napi_get_undefined(env, &value);
    return value;
}
static napi_value mcp_acquire_fence_call(napi_env env, napi_callback_info info) {
    size_t          argc = 2;
    napi_value      args[2];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    if (argc != 1 || broker->admin || !broker->retired || !broker->close_finished || broker->network_started || broker->request_started || broker->fence_locked ||
        !broker->bound || !atomic_load(&broker->fence_retained) || atomic_load(&broker->unsafe) || !mcp_binding_matches(broker, args[0], false, false) || pthread_mutex_lock(&broker->release_mutex)) {
        napi_throw_type_error(env, NULL, "MCP no-release requires the same original joined zero-I/O owner");
        return NULL;
    }
    bool            valid = broker->token_revoked && !broker->active_releases && !broker->network_started && !broker->request_started;
    struct mcp_fence *fence = valid ? calloc(1, sizeof(*fence)) : NULL;
    napi_value      value = NULL, owner;
    if (fence) {
        fence->owner = broker;
        fence->env = env;
        fence->creator_pid = getpid();
        fence->active = true;
        broker->fence_locked = true;
        broker->fence_borrows++;
        const           napi_property_descriptor methods[] = {{"assertHeld", NULL, mcp_fence_assert_call, NULL, NULL, NULL, napi_default, NULL}, {"close", NULL, mcp_fence_close_call, NULL, NULL, NULL, napi_default, NULL}};
        if (napi_create_object(env, &value) != napi_ok || napi_get_reference_value(env, broker->handle, &owner) != napi_ok || napi_create_reference(env, owner, 1, &fence->original) != napi_ok ||
            napi_type_tag_object(env, value, &mcp_fence_tag) != napi_ok || napi_wrap(env, value, fence, mcp_fence_finalizer, NULL, NULL) != napi_ok || napi_define_properties(env, value, 2, methods) != napi_ok || napi_object_freeze(env, value) != napi_ok) {
            mcp_fence_drop(fence);
            value = NULL;
        }
    } else if (pthread_mutex_unlock(&broker->release_mutex)) {
        atomic_store(&broker->unsafe, true);
        atomic_store(&retirement_failed, true);
    }
    if (!value) {
        napi_throw(env, mcp_error(broker));
        return NULL;
    } return value;
}
static napi_value mcp_join_value(struct broker *broker){
    napi_value      value, stages;
    if (napi_create_object(broker->env, &value) != napi_ok || napi_create_array(broker->env, &stages) != napi_ok)
        return NULL;
    broker->joined = (struct mcp_join){
        broker, broker->env, broker->creator_pid
    };
    if (napi_type_tag_object(broker->env, value, broker->admin ? &mcp_admin_join_tag : &mcp_run_join_tag) != napi_ok || napi_wrap(broker->env, value, &broker->joined, NULL, NULL, NULL) != napi_ok)
        return NULL;
    set_string(broker->env, value, "kind", "mcp_http_owner_joined");
    set_string(broker->env, value, "purpose", broker->admin ? "admin" : "run");
    if (broker->admin)
        set_boolean(broker->env, value, "adminPeerJoined", true);
    else
        set_string(broker->env, value, "brokerFenceTokenDigest", broker->token_digest);
    set_boolean(broker->env, value, "networkStarted", broker->network_started);
    set_boolean(broker->env, value, "requestStarted", broker->request_started);
    set_boolean(broker->env, value, "setupReleased", broker->setup_released);
    set_boolean(broker->env, value, "effectReleased", broker->effect_released);
    unsigned        count = 0;
    for (unsigned i = 0; i < (broker->admin ? 3u : 4u); i++)
        if (broker->phase_completed[i]) {
            napi_value      phase;
            napi_create_string_utf8(broker->env, mcp_phase_name(i), NAPI_AUTO_LENGTH, &phase);
            napi_set_element(broker->env, stages, count++, phase);
        }
    napi_object_freeze(broker->env, stages);
    napi_set_named_property(broker->env, value, "completedStages", stages);
    set_boolean(broker->env, value, "tokenRevoked", true);
    set_number(broker->env, value, "matchingActiveReleaseCount", 0);
    set_boolean(broker->env, value, "networkJoined", true);
    set_boolean(broker->env, value, "tasksJoined", true);
    return napi_object_freeze(broker->env, value) == napi_ok ? value : NULL;
}
static bool
mcp_peer_joined(struct broker *broker)
{
    if (!broker->admin || !broker->peer)
        return true;
    struct cliq_mcp_admin_peer *peer = &broker->peer->peer;
    int             joined = peer->poll_joined(peer->context, &broker->peer_observation);
    if (joined < 0) {
        atomic_store(&broker->unsafe, true);
        atomic_store(&retirement_failed, true);
        return false;
    }
    if (!joined || !broker->peer_observation.death_joined)
        return false;
    if (!broker->peer_observation.output_custody_retired) {
        int             begun = peer->begin_output_ack(peer->context);
        if (begun < 0) {
            atomic_store(&broker->unsafe, true);
            atomic_store(&retirement_failed, true);
            return false;
        }
        int             done = peer->poll_output_ack(peer->context);
        if (done < 0) {
            atomic_store(&broker->unsafe, true);
            atomic_store(&retirement_failed, true);
            return false;
        } if (!done)
            return false;
    }
    peer->release(peer->context);
    broker->peer->borrowed = false;
    broker->peer = NULL;
    if (broker->peer_ref && !broker->env_closing) {
        napi_delete_reference(broker->env, broker->peer_ref);
        broker->peer_ref = NULL;
    } return true;
}
static void
mcp_free(napi_env env, struct broker *broker)
{
    if (!broker->finalize_requested || !broker->close_finished || !broker->retired || broker->working || broker->fence_borrows || broker->fence_locked ||
        atomic_load(&broker->fence_retained) || atomic_load(&broker->unsafe) || callbacks_held(&broker->callbacks) || broker->cleanup_hook)
        return;
    if (broker->close_promise && !broker->env_closing)
        napi_delete_reference(env, broker->close_promise);
    for (unsigned i = 0; i < 4; i++) {
        if (broker->frames[i].body) {
            wipe(broker->frames[i].body, broker->frames[i].size);
            free(broker->frames[i].body);
        } free(broker->frames[i].id);
    }
    for (unsigned i = 0; i < broker->data_responses; i++) {
        struct mcp_capture *capture = broker->captures[i];
        if (capture->bytes) {
            wipe(capture->bytes, capture->size);
            free(capture->bytes);
        } free(capture);
    }
    struct mcp_receipt *receipt = broker->receipts;
    while (receipt) {
        struct mcp_receipt *next = receipt->next;
        wipe(receipt->message, receipt->size);
        free(receipt->message);
        free(receipt->id);
        wipe(receipt, sizeof(*receipt));
        free(receipt);
        receipt = next;
    }
    if (broker->response) {
        wipe(broker->response, broker->maximum_response_bytes);
        free(broker->response);
    } if (broker->sse_data)
        g_string_free(broker->sse_data, TRUE);
    if (broker->sse_event)
        g_string_free(broker->sse_event, TRUE);
    if (broker->mutex_ready && pthread_mutex_destroy(&broker->release_mutex)) {
        atomic_store(&broker->unsafe, true);
        atomic_store(&retirement_failed, true);
        return;
    }
    wipe(broker, sizeof(*broker));
    free(broker);
}
static void
mcp_finalize(napi_env env, void *data, void *hint)
{
    (void)hint;
    struct broker  *broker = data;
    broker->finalize_requested = true;
    mcp_free(env, broker);
}
static void
mcp_retire_callbacks(struct broker *broker)
{
    if (!broker->close_finished || !broker->retired || (broker->timer_ready && !broker->timer_closed) || broker->callbacks.depth || broker->callbacks.retiring)
        return;
    callbacks_retire(&broker->callbacks);
    if (!atomic_load(&broker->fence_retained) && !broker->fence_locked && broker->cleanup_hook) {
        if (napi_remove_async_cleanup_hook(broker->cleanup_hook) != napi_ok)
            callback_fatal("MCP cleanup hook did not retire");
        broker->cleanup_hook = NULL;
    }
}
static void
mcp_release_callback(struct broker *broker)
{
    mcp_retire_callbacks(broker);
    if (!broker->callbacks.borrows)
        callback_fatal("MCP callback borrow underflow");
    broker->callbacks.borrows--;
    mcp_free(broker->env, broker);
}
static void
mcp_finish_close(struct broker *broker)
{
    broker->callbacks.borrows++;
    if (!broker->retired || (broker->timer_ready && !broker->timer_closed))
        goto done;
    if (broker->env_closing && !broker->fence_locked)
        atomic_store(&broker->fence_retained, false);
    if (!broker->close_finished) {
        broker->close_finished = true;
        if (broker->platform.cancel && !atomic_load(&broker->unsafe)) {
            g_object_unref(broker->platform.cancel);
            broker->platform.cancel = NULL;
        }
        if (!broker->env_closing) {
            if (broker->ready_deferred) {
                napi_reject_deferred(broker->env, broker->ready_deferred, mcp_error(broker));
                broker->ready_deferred = NULL;
            }
            if (broker->phase_deferred) {
                napi_reject_deferred(broker->env, broker->phase_deferred, mcp_error(broker));
                broker->phase_deferred = NULL;
            }
            if (broker->message_deferred) {
                napi_reject_deferred(broker->env, broker->message_deferred, mcp_error(broker));
                broker->message_deferred = NULL;
            }
            if (broker->final_deferred) {
                napi_reject_deferred(broker->env, broker->final_deferred, mcp_error(broker));
                broker->final_deferred = NULL;
            }
            if (broker->close_deferred) {
                napi_value      value = atomic_load(&broker->unsafe) ? NULL : mcp_join_value(broker);
                if (value)
                    napi_resolve_deferred(broker->env, broker->close_deferred, value);
                else
                    napi_reject_deferred(broker->env, broker->close_deferred, mcp_error(broker));
                broker->close_deferred = NULL;
            }
        }
        if (atomic_load(&broker->unsafe) && !broker->unsafe_pinned) {
            broker->unsafe_pinned = true;
            broker->unretired_next = mcp_unretired;
            mcp_unretired = broker;
        }
    }
    if (!atomic_load(&broker->fence_retained) && !broker->fence_locked && !atomic_load(&broker->unsafe) && broker->handle) {
        napi_ref        handle = broker->handle;
        broker->handle = NULL;
        if (!broker->env_closing)
            napi_delete_reference(broker->env, handle);
        wipe(broker->token, sizeof(broker->token));
    }
done:mcp_release_callback(broker);
}
static void
mcp_timer_closed(uv_handle_t * timer)
{
    struct broker  *broker = timer->data;
    struct native_callback_scope scope;
    callbacks_enter(&broker->callbacks, broker->env_closing, &scope);
    broker->timer_closed = true;
    mcp_finish_close(broker);
    callbacks_close(&broker->callbacks, &scope);
    mcp_release_callback(broker);
}
static void
mcp_close_timer_when_joined(struct broker *broker)
{
    if (!broker->retired)
        return;
    if (!mcp_peer_joined(broker)) {
        if (atomic_load(&broker->unsafe) && !broker->timer_closing) {
            broker->timer_closing = true;
            uv_close((uv_handle_t *) & broker->timer, mcp_timer_closed);
        } return;
    }
    if (broker->timer_ready && !broker->timer_closing) {
        broker->timer_closing = true;
        uv_close((uv_handle_t *) & broker->timer, mcp_timer_closed);
    } else
        mcp_finish_close(broker);
}
static void
mcp_worker(napi_env env, void *data)
{
    (void)env;
    struct broker  *broker = data;
    if (broker->stage == MCP_RETIRE) {
        (void)mcp_retire_connection(broker);
        if (broker->paused.connection) {
            mcp_restore_connection(broker);
            (void)mcp_retire_connection(broker);
        } (void)mcp_retire_platform(broker);
        if (broker->platform.secret) {
            wipe(broker->platform.secret, broker->platform.secret_size);
            free(broker->platform.secret);
            broker->platform.secret = NULL;
            broker->platform.secret_size = 0;
        }
        if (broker->trust) {
            wipe(broker->trust, broker->trust_size);
            free(broker->trust);
            broker->trust = NULL;
        }
    } else if (!broker_live(broker))
        return;
    else if (broker->stage == MCP_PREPARE) {
        if (broker->credential_present)
            (void)broker_read_key(broker);
    } else if (broker->stage == MCP_CONNECT_STAGE || broker->stage == MCP_CONNECT_PING)
        (void)broker_connect(broker);
    else if (broker->stage == MCP_EXCHANGE_PING) {
        unsigned char  *body = NULL;
        size_t          size = 0;
        bool            valid = mcp_ping_body(broker, &body, &size) && mcp_write_request(broker, body, size) && mcp_empty_ack(broker);
        if (body) {
            wipe(body, size);
            free(body);
        } if (!valid)
            broker_fail(broker, "mcp_ping_ack_refused");
    } else {
        bool            valid = true;
        if (broker->stage == MCP_EXCHANGE_STAGE)
            valid = mcp_write_request(broker, broker->frames[broker->phase].body, broker->frames[broker->phase].size);
        if (valid) {
            if (broker->phase == 1)
                (void)mcp_empty_ack(broker);
            else
                (void)mcp_read_message(broker);
        }
    }
    if (broker->platform.error)
        broker_fail(broker, "credential_redemption_refused");
    if (broker->platform.unsafe || atomic_load(&retirement_failed)) {
        atomic_store(&broker->unsafe, true);
        broker_fail(broker, "resource_retirement");
    } ERR_clear_error();
}
static void
mcp_complete(napi_env env, napi_status status, void *data)
{
    struct broker  *broker = data;
    broker->callbacks.borrows++;
    broker->working = false;
    if (broker->work && napi_delete_async_work(env, broker->work) != napi_ok) {
        atomic_store(&broker->unsafe, true);
        atomic_store(&retirement_failed, true);
    } broker->work = NULL;
    if (status != napi_ok)
        broker_fail(broker, "mcp_worker_unavailable");
    if (broker->stage == MCP_RETIRE) {
        broker->active_releases = 0;
        broker->retired = true;
        mcp_close_timer_when_joined(broker);
        mcp_release_callback(broker);
        return;
    }
    if (!atomic_load(&broker->error)) {
        if (broker->stage == MCP_PREPARE && !broker->closing) {
            broker->prepared = true;
            if (broker->ready_deferred && !broker->env_closing) {
                napi_value      value;
                napi_get_undefined(env, &value);
                napi_resolve_deferred(env, broker->ready_deferred, value);
                broker->ready_deferred = NULL;
            }
        } else if (broker->stage == MCP_CONNECT_STAGE || broker->stage == MCP_CONNECT_PING) {
            if (broker->stage == MCP_CONNECT_STAGE) {
                broker->connected = true;
                broker->headers_received = false;
                broker->response_size = 0;
                broker->parse_at = 0;
                broker->sse_line_start = 0;
                broker->sse_skip_lf = false;
                broker->aggregate_entries = 0;
                g_string_truncate(broker->sse_data, 0);
                broker->sse_data_present = false;
                g_string_truncate(broker->sse_event, 0);
            } else
                broker->ping->ping_state = MCP_PING_CONNECTED;
            if (broker->phase_deferred && !broker->env_closing) {
                napi_value      value;
                napi_get_undefined(env, &value);
                napi_resolve_deferred(env, broker->phase_deferred, value);
                broker->phase_deferred = NULL;
            }
        } else if (broker->stage == MCP_EXCHANGE_PING) {
            broker->ping->ping_state = MCP_PING_ACK_JOINED;
            broker->ping = NULL;
            broker->active_releases--;
            mcp_restore_connection(broker);
            if (broker->message_deferred && !broker->closing && !mcp_queue(broker, MCP_READ_STAGE))
                mcp_begin_close(broker);
        } else if (broker->phase == 1) {
            broker->phase_completed[1] = true;
            broker->connected = false;
            broker->active_releases = 0;
            broker->next_phase = 2;
            broker->ack_ready = true;
            if (broker->admin && broker->peer) {
                struct cliq_mcp_screened_message_view view = {1, NULL, 0, true};
                if (broker->peer->peer.deliver_screened_message(broker->peer->peer.context, &view) < 0)
                    broker_fail(broker, "mcp_admin_protocol_refused");
            }
        }
    }
    if (!broker->env_closing && !mcp_deliver_pending(broker))
        broker_fail(broker, "mcp_worker_unavailable");
    if (atomic_load(&broker->error) || broker->closing)
        mcp_begin_close(broker);
    mcp_release_callback(broker);
}
static bool
mcp_queue(struct broker *broker, enum mcp_work stage)
{
    if (broker->working)
        return broker_fail(broker, "mcp_capacity_one_violation");
    napi_value      resource;
    broker->stage = stage;
    if (napi_create_string_utf8(broker->env, "cliq-installed-mcp-http-owner", NAPI_AUTO_LENGTH, &resource) != napi_ok ||
      napi_create_async_work(broker->env, NULL, resource, mcp_worker, mcp_complete, broker, &broker->work) != napi_ok)
        return broker_fail(broker, "mcp_worker_unavailable");
    if (napi_queue_async_work(broker->env, broker->work) != napi_ok) {
        if (napi_delete_async_work(broker->env, broker->work) != napi_ok) {
            atomic_store(&broker->unsafe, true);
            atomic_store(&retirement_failed, true);
        } broker->work = NULL;
        return broker_fail(broker, "mcp_worker_unavailable");
    }
    broker->working = true;
    return true;
}
static void
mcp_begin_close(struct broker *broker)
{
    if (broker->retired) {
        mcp_close_timer_when_joined(broker);
        return;
    } broker->closing = true;
    atomic_store(&broker->cancelled, true);
    if (broker->platform.cancel)
        g_cancellable_cancel(broker->platform.cancel);
    if (pthread_mutex_lock(&broker->release_mutex)) {
        atomic_store(&broker->unsafe, true);
        atomic_store(&retirement_failed, true);
    } else {
        broker->token_revoked = true;
        if (pthread_mutex_unlock(&broker->release_mutex)) {
            atomic_store(&broker->unsafe, true);
            atomic_store(&retirement_failed, true);
        }
    }
    if (broker->peer && !broker->protocol_complete && broker->peer->peer.cancel(broker->peer->peer.context) < 0) {
        atomic_store(&broker->unsafe, true);
        atomic_store(&retirement_failed, true);
    }
    if (!broker->working && !mcp_queue(broker, MCP_RETIRE)) {
        atomic_store(&broker->unsafe, true);
        atomic_store(&retirement_failed, true);
        broker->retired = true;
        mcp_close_timer_when_joined(broker);
    }
}
static void
mcp_timer(uv_timer_t * timer)
{
    struct broker  *broker = timer->data;
    struct native_callback_scope scope;
    callbacks_enter(&broker->callbacks, broker->env_closing, &scope);
    if (!remaining(&broker->platform) || atomic_load(&retirement_failed)) {
        if (broker->peer && broker->peer->peer.cancel(broker->peer->peer.context) < 0) {
            atomic_store(&broker->unsafe, true);
            atomic_store(&retirement_failed, true);
        } mcp_begin_close(broker);
    } else if (broker->closing)
        mcp_begin_close(broker);
    else if (broker->final_deferred && broker->peer) {
        struct cliq_mcp_admin_observation observation = {0};
        int             state = broker->peer->peer.poll_joined(broker->peer->peer.context, &observation);
        if (state < 0) {
            atomic_store(&broker->unsafe, true);
            atomic_store(&retirement_failed, true);
            mcp_begin_close(broker);
        } else if (state == 1) {
            if (!observation.packet.admin_protocol_complete || broker->invalidated) {
                broker_fail(broker, "mcp_admin_protocol_refused");
                mcp_begin_close(broker);
            } else {
                napi_value      value = mcp_raw_value(broker, broker->admin_final_capture);
                if (value)
                    napi_resolve_deferred(broker->env, broker->final_deferred, value);
                else
                    napi_reject_deferred(broker->env, broker->final_deferred, mcp_error(broker));
                broker->final_deferred = NULL;
            }
        }
    } else if (!mcp_poll_admin_requested(broker))
        mcp_begin_close(broker);
    callbacks_close(&broker->callbacks, &scope);
    mcp_release_callback(broker);
}
static void
mcp_cleanup(napi_async_cleanup_hook_handle hook, void *data)
{
    (void)hook;
    struct broker  *broker = data;
    broker->env_closing = true;
    struct native_callback_scope scope;
    callbacks_enter(&broker->callbacks, true, &scope);
    if (broker->fence_locked) {
        if (pthread_mutex_unlock(&broker->release_mutex)) {
            atomic_store(&broker->unsafe, true);
            atomic_store(&retirement_failed, true);
        } else
            broker->fence_locked = false;
    }
    atomic_store(&broker->fence_retained, false);
    mcp_begin_close(broker);
    callbacks_close(&broker->callbacks, &scope);
    mcp_release_callback(broker);
}
static napi_value mcp_close_call(napi_env env, napi_callback_info info) {
    size_t          argc = 1;
    napi_value      args[1];
    struct broker  *broker = mcp_receiver(env, info, &argc, args);
    if (!broker)
        return NULL;
    napi_value      promise;
    if (argc) {
        napi_throw_type_error(env, NULL, "MCP close accepts no arguments");
        return NULL;
    }
    if (broker->close_promise) {
        napi_get_reference_value(env, broker->close_promise, &promise);
        return promise;
    }
    if (napi_create_promise(env, &broker->close_deferred, &promise) != napi_ok || napi_create_reference(env, promise, 1, &broker->close_promise) != napi_ok)
        return NULL;
    if (broker->close_finished) {
        if (atomic_load(&broker->unsafe))
            napi_reject_deferred(env, broker->close_deferred, mcp_error(broker));
        else
            napi_resolve_deferred(env, broker->close_deferred, mcp_join_value(broker));
        broker->close_deferred = NULL;
        return promise;
    }
    mcp_begin_close(broker);
    mcp_finish_close(broker);
    return promise;
}
static napi_value mcp_owner_value(struct broker *broker, napi_value ready){
    napi_value      value;
    if (napi_create_object(broker->env, &value) != napi_ok || napi_type_tag_object(broker->env, value, broker->admin ? &mcp_admin_tag : &mcp_run_tag) != napi_ok ||
        napi_wrap(broker->env, value, broker, mcp_finalize, NULL, NULL) != napi_ok)
        return NULL;
    const           napi_property_descriptor methods[] = {
        {"connectStage", NULL, mcp_connect_stage_call, NULL, NULL, NULL, napi_default, NULL}, {"releaseStage", NULL, mcp_release_stage_call, NULL, NULL, NULL, napi_default, NULL},
        {"nextMessage", NULL, mcp_next_message_call, NULL, NULL, NULL, napi_default, NULL}, {"connectPing", NULL, mcp_connect_ping_call, NULL, NULL, NULL, napi_default, NULL},
        {"releasePing", NULL, mcp_release_ping_call, NULL, NULL, NULL, napi_default, NULL}, {"finishResponse", NULL, mcp_finish_response_call, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, mcp_close_call, NULL, NULL, NULL, napi_default, NULL}, {"assertBinding", NULL, mcp_assert_binding_call, NULL, NULL, NULL, napi_default, NULL},
        {"bind", NULL, mcp_bind_call, NULL, NULL, NULL, napi_default, NULL}, {"readUnusableResponse", NULL, mcp_read_unusable_call, NULL, NULL, NULL, napi_default, NULL},
        {"assertUnusableResponse", NULL, mcp_assert_unusable_call, NULL, NULL, NULL, napi_default, NULL},
        {"assertJoined", NULL, mcp_assert_joined_call, NULL, NULL, NULL, napi_default, NULL}, {"assertRawResponse", NULL, mcp_assert_raw_call, NULL, NULL, NULL, napi_default, NULL},
        {broker->admin ? "retainDomain" : "retainDispatchFence", NULL, mcp_retain_call, NULL, NULL, NULL, napi_default, NULL},
        {broker->admin ? "releaseDomain" : "releaseDispatchFence", NULL, mcp_release_domain_call, NULL, NULL, NULL, napi_default, NULL},
    };
    if (napi_define_properties(broker->env, value, sizeof(methods) / sizeof(*methods), methods) != napi_ok)
        return NULL;
    napi_property_descriptor extra = {broker->admin ? "attachProtocolPeer" : "acquireNoReleaseFence", NULL, broker->admin ? mcp_attach_peer_call : mcp_acquire_fence_call, NULL, NULL, NULL, napi_default, NULL};
    if (napi_define_properties(broker->env, value, 1, &extra) != napi_ok || napi_set_named_property(broker->env, value, "ready", ready) != napi_ok || napi_create_reference(broker->env, value, 1, &broker->handle) != napi_ok)
        return NULL;
    if (!broker->admin)
        set_string(broker->env, value, "brokerFenceTokenDigest", broker->token_digest);
    return napi_object_freeze(broker->env, value) == napi_ok ? value : NULL;
}
static napi_value mcp_prepare(napi_env env, napi_callback_info info, bool admin){
    size_t          argc = 2;
    napi_value      args[2];
    if (atomic_load(&retirement_failed) || syscall(SYS_gettid) != getpid() || napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1) {
        napi_throw_type_error(env, NULL, "MCP owner preparation is unavailable");
        return NULL;
    }
    struct broker  *broker = calloc(1, sizeof(*broker));
    if (!broker) {
        napi_throw_error(env, NULL, "MCP owner allocation is unavailable");
        return NULL;
    }
    broker->env = env;
    broker->creator_pid = getpid();
    broker->admin = admin;
    broker->platform.runtime_fd = -1;
    atomic_init(&broker->cancelled, false);
    atomic_init(&broker->unsafe, false);
    atomic_init(&broker->fence_retained, false);
    atomic_init(&broker->error, NULL);
    uint64_t        milliseconds = 0;
    bool            valid = current_user(&broker->platform.uid, &broker->platform.gid, broker->platform.home) && mcp_input(env, args[0], broker, &milliseconds) &&
    RAND_bytes(broker->token, sizeof(broker->token)) == 1 && digest_hex(broker->token, sizeof(broker->token), broker->token_digest) && !clock_gettime(CLOCK_MONOTONIC, &broker->platform.deadline);
    if (valid) {
        broker->platform.deadline.tv_sec += (time_t) (milliseconds / 1000);
        broker->platform.deadline.tv_nsec += (long)(milliseconds % 1000) * 1000000;
        if (broker->platform.deadline.tv_nsec >= 1000000000) {
            broker->platform.deadline.tv_sec++;
            broker->platform.deadline.tv_nsec -= 1000000000;
        } valid = !pthread_mutex_init(&broker->release_mutex, NULL);
        broker->mutex_ready = valid;
    }
    if (!valid) {
        for (unsigned i = 0; i < 4; i++) {
            if (broker->frames[i].body) {
                wipe(broker->frames[i].body, broker->frames[i].size);
                free(broker->frames[i].body);
            } free(broker->frames[i].id);
        } if (broker->trust) {
            wipe(broker->trust, broker->trust_size);
            free(broker->trust);
        } free(broker);
        napi_throw_type_error(env, NULL, "Invalid MCP owner preparation");
        return NULL;
    }
    broker->platform.cancel = g_cancellable_new();
    broker->sse_data = g_string_new(NULL);
    broker->sse_event = g_string_new(NULL);
    napi_value      ready, handle = NULL;
    uv_loop_t      *loop;
    if (napi_create_promise(env, &broker->ready_deferred, &ready) == napi_ok)
        handle = mcp_owner_value(broker, ready);
    if (!handle || !broker->platform.cancel || !broker->sse_data || !broker->sse_event || napi_add_async_cleanup_hook(env, mcp_cleanup, broker, &broker->cleanup_hook) != napi_ok ||
        !callbacks_init(&broker->callbacks, env, "cliq MCP owner callbacks") || napi_get_uv_event_loop(env, &loop) != napi_ok || uv_timer_init(loop, &broker->timer)) {
        atomic_store(&broker->unsafe, true);
        atomic_store(&retirement_failed, true);
        broker->unsafe_pinned = true;
        broker->unretired_next = mcp_unretired;
        mcp_unretired = broker;
        napi_throw(env, mcp_error(broker));
        return NULL;
    }
    broker->timer_ready = true;
    broker->timer.data = broker;
    uv_update_time(loop);
    if (uv_timer_start(&broker->timer, mcp_timer, 1, 10) || !mcp_queue(broker, MCP_PREPARE)) {
        broker_fail(broker, "mcp_worker_unavailable");
        mcp_begin_close(broker);
    } return handle;
}
static napi_value mcp_prepare_admin(napi_env env, napi_callback_info info) {
    return mcp_prepare(env, info, true);
}
static napi_value mcp_prepare_run(napi_env env, napi_callback_info info) {
    return mcp_prepare(env, info, false);
}
static void
mcp_module_finalize(napi_env env, void *data, void *hint)
{
    (void)hint;
    struct mcp_module *module = data;
    if (module->data_validator)
        napi_delete_reference(env, module->data_validator);
    free(module);
}
static napi_value initialize_mcp_broker(napi_env env, napi_value exports) {
    /*
     * Capture fixed bootstrap intrinsics before any caller input is traversed. Proxies are refused before descriptor
     * access; no getter is invoked. The selected SEA bootstrap is responsible for pristine builtin identity.
     */
    const char     *source = "(()=>{const p=process.getBuiltinModule('node:util').types.isProxy;const own=Reflect.ownKeys;const desc=Object.getOwnPropertyDescriptor;const view=ArrayBuffer.isView;const S=Set;const apply=Reflect.apply;const has=S.prototype.has,add=S.prototype.add,del=S.prototype.delete;return x=>{let n=0;const seen=new S();const walk=(v,d)=>{if(v===null||typeof v!=='object')return typeof v!=='function'&&typeof v!=='symbol'&&typeof v!=='bigint';if(p(v)||d>32||++n>10000||apply(has,seen,[v]))return false;apply(add,seen,[v]);if(view(v))return true;for(const k of own(v)){if(typeof k!=='string')return false;const q=desc(v,k);if(!q||!('value'in q)||!walk(q.value,d+1))return false;}apply(del,seen,[v]);return true;};return walk(x,0);};})()";
    struct mcp_module *module = calloc(1, sizeof(*module));
    if (!module)
        return NULL;
    module->env = env;
    napi_value      code, validator;
    if (!OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) || napi_create_string_utf8(env, source, NAPI_AUTO_LENGTH, &code) != napi_ok ||
        napi_run_script(env, code, &validator) != napi_ok || napi_create_reference(env, validator, 1, &module->data_validator) != napi_ok || napi_set_instance_data(env, module, mcp_module_finalize, NULL) != napi_ok) {
        napi_throw_error(env, NULL, "MCP native bootstrap is unavailable");
        return NULL;
    }
    const           napi_property_descriptor methods[] = {{"prepareAdminHttp", NULL, mcp_prepare_admin, NULL, NULL, NULL, napi_default, NULL}, {"prepareRunHttp", NULL, mcp_prepare_run, NULL, NULL, NULL, napi_default, NULL}};
    if (napi_define_properties(env, exports, 2, methods) != napi_ok)
        return NULL;
#if defined(CLIQ_MCP_NATIVE_FIXTURE)
    const           napi_property_descriptor fixture = {"runMcpNativeFixture", NULL, mcp_native_fixture_run, NULL, NULL, NULL, napi_default, NULL};
    if (napi_define_properties(env, exports, 1, &fixture) != napi_ok)
        return NULL;
#endif
    set_number(env, exports, "interfaceVersion", 1);
    return exports;
}
NAPI_MODULE(cliq_linux_mcp_http_broker, initialize_mcp_broker)
#endif
