#ifndef CLIQ_MCP_STDIO_BROKER_H
#define CLIQ_MCP_STDIO_BROKER_H
/* Distinct signed stdio image. Fixed frames and all received bytes stay in
 * this original process. JS never owns a server pipe or raw IPC frame. */
#include "mcp-stdio-owner-bridge.h"
#include <sys/mman.h>
#include "mcp-protocol-data.h"
_Static_assert(CLIQ_MCP_STDIO_MAX_MESSAGE == MCP_PROTOCOL_BODY_CAP, "same original MCP protocol body bound");
static napi_value undefined(napi_env env) { napi_value value; napi_get_undefined(env, &value); return value; }
// Private objects holding this broker or its original proof use the current layout tags.
static const napi_type_tag STDIO_RUN_OWNER_TAG = {UINT64_C(0x802f897f2e974fc4), UINT64_C(0xeda20d8ffdeb3e18)};
static const napi_type_tag STDIO_ADMIN_OWNER_TAG = {UINT64_C(0x52cee503ede7445a), UINT64_C(0xf92fcd068ed76776)};
static const napi_type_tag STDIO_RECOVERY_OWNER_TAG = {UINT64_C(0xdcc9abd1e4bd4f2a), UINT64_C(0xdc53f9cac384afae)};
static const napi_type_tag STDIO_RECOVERY_JOIN_TAG = {UINT64_C(0x8a993ce3a3734023), UINT64_C(0xf86a011b5e8f32c5)};
static const napi_type_tag STDIO_RECOVERY_FENCE_TAG = {UINT64_C(0x686008605ef04f2b), UINT64_C(0xe70952e556c7ae6c)};
static const napi_type_tag STDIO_RECEIPT_TAG = {UINT64_C(0x3749a4ab2b284fd0), UINT64_C(0xd5fe84be16a88e2d)};
static const napi_type_tag STDIO_JOIN_TAG = {UINT64_C(0x7dc9693e834649c7), UINT64_C(0xef166b7bab705b16)};
static const napi_type_tag STDIO_RAW_TAG = {UINT64_C(0x9a5b5d733801465d), UINT64_C(0xfa41fa84d8f2352d)};
static const napi_type_tag STDIO_UNUSABLE_TAG = {UINT64_C(0xa856946b96624d5e), UINT64_C(0xcff763951c155cfe)};
static const napi_type_tag STDIO_BYTES_TAG = {UINT64_C(0xd1048d5bede84e53), UINT64_C(0xdce28268e0a1af5c)};
static const napi_type_tag STDIO_RESPONSE_JOIN_TAG = {UINT64_C(0x1cb6adf2c33c49a8), UINT64_C(0xebe310405c1e4ded)};
static const napi_type_tag STDIO_FENCE_TAG = {UINT64_C(0xd5094eea54d74f8c), UINT64_C(0xe2312923e90531cc)};
static const napi_type_tag STDIO_RECOVERY_UNAVAILABLE_JOIN_TAG = {UINT64_C(0x7c7846d89b3248b1), UINT64_C(0xa29aedd25cb69584)};
static const napi_type_tag STDIO_RECOVERY_UNAVAILABLE_FENCE_TAG = {UINT64_C(0x684323a2cc714639), UINT64_C(0x85f31301e4c9ac06)};
struct broker;
enum stdio_message_kind { STDIO_NOTIFICATION, STDIO_PING, STDIO_RESPONSE };
struct stdio_receipt {
    struct broker *owner;
    struct stdio_receipt *next;
    unsigned phase, ordinal;
    enum stdio_message_kind kind;
    unsigned char *message, *ping_id;
    size_t size, ping_id_size, start, end, response_end;
    bool advanced, ping_released, capture_refused;
    char digest[65], capture_digest[65];
};
struct stdio_proof { struct broker *owner; struct stdio_receipt *receipt; napi_ref original; bool fence_active; };
struct broker {
    struct task platform;
    napi_env env; pid_t creator_pid;
    struct cliq_mcp_stdio_recipe recipe;
    struct cliq_mcp_stdio_peer *peer;
    struct cliq_mcp_stdio_launch_binding launch;
    struct cliq_mcp_stdio_call_binding call;
    struct mcp_frame frames[4];
    struct stdio_receipt *receipts, *pending, *advancing, *ping;
    napi_ref handle, peer_ref, close_promise, work_owner;
    napi_deferred message_deferred, close_deferred;
    napi_async_cleanup_hook_handle cleanup_hook;
    struct native_callbacks callbacks;
    uv_timer_t timer;
    bool timer_ready, timer_closing, timer_closed, env_closing, finalized;
    bool admin, recovery, status_released, bound, call_bound, exec_released, setup_released, effect_released, retained, fence_locked;
    bool closing, close_finished, retired, unsafe, raw_screened, raw_refused, response_refused, io_aborted;
    bool payload_refused, refused_output_discarded;
    bool stage_requested, stage_released, stage_written, protocol_complete, protocol_sent, cancel_queued, client_joined, output_eof[2];
    bool await_write, write_ping;
    unsigned command_kind, write_phase;
    unsigned phase, completed, ordinal, ping_count, aggregate_entries, ack_stream;
    unsigned references;
    uint64_t deadline_ms, stop_deadline_ms, retired_at_ms;
    unsigned char *output[2], *tx, rx_header[16], *rx;
    size_t output_size[2], parse_at, capture_start, tx_size, tx_at, rx_header_at, rx_size, rx_at;
    unsigned rx_kind;
    char token_digest[65];
    pthread_mutex_t release_mutex;
    bool mutex_ready;
    _Atomic(const char *) error;
};
static uint64_t stdio_clock_ms(clockid_t kind) {
    struct timespec now;
    return clock_gettime(kind, &now) || now.tv_sec < 0 ? 0 : (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static bool broker_live(struct broker *broker) {
    uint64_t now = stdio_clock_ms(CLOCK_MONOTONIC);
    return now && now < broker->deadline_ms && !broker->closing;
}
static bool broker_fail(struct broker *broker, const char *code) {
    const char *expected = NULL; atomic_compare_exchange_strong(&broker->error, &expected, code); return false;
}
#include "no-echo-bytes-mechanism.h"
enum stdio_received_screen { STDIO_SCREEN_CLEAR, STDIO_SCREEN_REFUSED, STDIO_SCREEN_UNSAFE };
static enum stdio_received_screen stdio_screen_received(struct broker *broker, const unsigned char *bytes, size_t size) {
    const char *prior = atomic_exchange(&broker->error, NULL);
    bool valid = mcp_no_echo_all(broker, bytes, size);
    const char *screen_error = atomic_exchange(&broker->error, prior);
    if (valid) return STDIO_SCREEN_CLEAR;
    if (screen_error && !strcmp(screen_error, "broker_response_refused")) return STDIO_SCREEN_REFUSED;
    return STDIO_SCREEN_UNSAFE;
}
static void stdio_mark_refused(struct broker *broker, bool payload) {
    broker->response_refused = true;
    broker->payload_refused = broker->recovery && payload;
    broker_fail(broker, "mcp_response_refused");
}
static bool stdio_current(struct broker *broker, napi_env env) {
    return broker && broker->env == env && broker->creator_pid == getpid() && syscall(SYS_gettid) == getpid();
}
static napi_value stdio_error(struct broker *broker, bool physical) {
    napi_value message, error;
    napi_create_string_utf8(broker->env, physical ? "MCP stdio resources require retirement" : "MCP stdio original operation refused", NAPI_AUTO_LENGTH, &message);
    napi_create_error(broker->env, NULL, message, &error);
    set_string(broker->env, error, "code", physical ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_MCP_BROKER");
    set_string(broker->env, error, "brokerCode", broker->response_refused ? "mcp_response_refused" : "mcp_transport_interrupted");
    return error;
}
static napi_value stdio_throw(struct broker *broker, bool physical) { napi_throw(broker->env, stdio_error(broker, physical)); return NULL; }
static struct broker *stdio_receiver(napi_env env, napi_callback_info info, size_t *argc, napi_value *args) {
    napi_value self; bool run = false, admin = false, recovery = false; struct broker *broker = NULL;
    if (napi_get_cb_info(env, info, argc, args, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &STDIO_RUN_OWNER_TAG, &run) != napi_ok ||
        napi_check_object_type_tag(env, self, &STDIO_ADMIN_OWNER_TAG, &admin) != napi_ok ||
        napi_check_object_type_tag(env, self, &STDIO_RECOVERY_OWNER_TAG, &recovery) != napi_ok || (!run && !admin && !recovery) ||
        napi_unwrap(env, self, (void **)&broker) != napi_ok || !stdio_current(broker, env) || broker->admin != admin || broker->recovery != recovery) {
        napi_throw_type_error(env, NULL, "Invalid original installed MCP stdio owner"); return NULL;
    }
    return broker;
}
static uint32_t stdio_le32(const unsigned char *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}
static void stdio_put32(unsigned char *bytes, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) bytes[i] = (unsigned char)(value >> (i * 8));
}
static bool stdio_hash(const unsigned char *bytes, size_t size, char digest[65]) {
    unsigned char hash[32]; if (!SHA256(bytes, size, hash)) return false;
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) { digest[i * 2] = alphabet[hash[i] >> 4]; digest[i * 2 + 1] = alphabet[hash[i] & 15]; }
    digest[64] = 0; return true;
}
static bool stdio_enqueue(struct broker *broker, unsigned kind, const void *bytes, size_t size) {
    if (broker->tx || size > broker->recipe.header.maximum_response_bytes) return false;
    broker->tx = malloc(size + 16); if (!broker->tx) return false;
    broker->tx_size = size + 16; broker->tx_at = 0;
    stdio_put32(broker->tx, CLIQ_MCP_STDIO_CHANNEL_MAGIC); stdio_put32(broker->tx + 4, 1);
    stdio_put32(broker->tx + 8, kind); stdio_put32(broker->tx + 12, (uint32_t)size);
    if (size) memcpy(broker->tx + 16, bytes, size);
    return true;
}
static bool stdio_flush(struct broker *broker, int fd) {
    while (broker->tx && broker->tx_at < broker->tx_size) {
        ssize_t n = send(fd, broker->tx + broker->tx_at, broker->tx_size - broker->tx_at, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return true;
        if (n <= 0) return false;
        broker->tx_at += (size_t)n;
    }
    if (broker->tx) { wipe(broker->tx, broker->tx_size); free(broker->tx); broker->tx = NULL; broker->tx_size = broker->tx_at = 0; }
    if (broker->ack_stream) {
        unsigned char scalar[4]; stdio_put32(scalar, broker->ack_stream);
        if (!stdio_enqueue(broker, CLIQ_MCP_STDIO_CHUNK_ACK, scalar, sizeof(scalar))) return false;
        broker->ack_stream = 0;
    }
    return true;
}
static bool stdio_member_text(struct mcp_json *json, const char *name, char *output, size_t capacity) {
    unsigned index = mcp_json_member(json, 1, name);
    if (!index || json->nodes[index].type != '"') return false;
    struct mcp_json copy = *json; copy.at = json->nodes[index].start; GString *decoded = g_string_new(NULL);
    bool valid = decoded && mcp_json_string(&copy, decoded) && decoded->len && decoded->len < capacity && !memchr(decoded->str, 0, decoded->len);
    if (valid) memcpy(output, decoded->str, decoded->len + 1);
    if (decoded) g_string_free(decoded, TRUE);
    return valid;
}
static bool stdio_member_digest(struct mcp_json *json, const char *name, char output[65]) {
    return stdio_member_text(json, name, output, 65) && cliq_mcp_admin_digest(output);
}
static bool stdio_member_number(struct mcp_json *json, const char *name, uint64_t minimum, uint64_t *output) {
    unsigned index = mcp_json_member(json, 1, name);
    unsigned char *id = NULL; size_t size = 0;
    if (!index || json->nodes[index].type != '#' || !mcp_json_id(json, index, &id, &size)) return false;
    bool valid = size > 1 && id[0] == 'n' && id[1] != '-';
    char *number = valid ? g_strndup((char *)id + 1, size - 1) : NULL; free(id);
    if (!number) return false;
    errno = 0; char *end; unsigned long long value = strtoull(number, &end, 10);
    valid = !errno && !*end && value >= minimum && value <= UINT64_C(9007199254740991);
    if (valid) *output = value;
    g_free(number); return valid;
}
static bool stdio_parse_launch_bytes(const unsigned char *bytes, size_t size, unsigned purpose, struct cliq_mcp_stdio_launch_binding *binding) {
    struct mcp_json json; if (size > 32768 || !mcp_json_parse(bytes, size, &json)) return false;
    binding->purpose = purpose; bool valid;
    if (purpose == CLIQ_MCP_STDIO_ADMIN) {
        const char *keys[] = {"adminOperationId","attempt","principalId","method","controlRequestDigest","targetRef","targetDigest",
            "probePayloadCoreRef","probePayloadCoreDigest","probeRequestDigest","dispatchId","supervisorInstanceId","stateOwnerEpoch",
            "processContainmentRef","plannedContainmentRef","plannedContainmentDigest","sandboxLaunchSpecRef","sandboxLaunchSpecDigest","nonce","deadlineMs"};
        struct cliq_mcp_admin_binding *b = &binding->admin;
        valid = mcp_json_keys(&json, 1, keys, 20);
#define STDIO_ADMIN_TEXT(key, field) valid = valid && stdio_member_text(&json, key, b->field, sizeof(b->field))
#define STDIO_ADMIN_DIGEST(key, field) valid = valid && stdio_member_digest(&json, key, b->field)
        STDIO_ADMIN_TEXT("adminOperationId", operation); STDIO_ADMIN_TEXT("principalId", principal); STDIO_ADMIN_TEXT("method", method);
        STDIO_ADMIN_TEXT("dispatchId", dispatch); STDIO_ADMIN_TEXT("supervisorInstanceId", supervisor);
        STDIO_ADMIN_DIGEST("controlRequestDigest", control_digest); STDIO_ADMIN_DIGEST("targetRef", target_ref); STDIO_ADMIN_DIGEST("targetDigest", target_digest);
        STDIO_ADMIN_DIGEST("probePayloadCoreRef", core_ref); STDIO_ADMIN_DIGEST("probePayloadCoreDigest", core_digest); STDIO_ADMIN_DIGEST("probeRequestDigest", probe_digest);
        STDIO_ADMIN_DIGEST("processContainmentRef", containment_ref); STDIO_ADMIN_DIGEST("plannedContainmentRef", plan_ref); STDIO_ADMIN_DIGEST("plannedContainmentDigest", plan_digest);
        STDIO_ADMIN_DIGEST("sandboxLaunchSpecRef", spec_ref); STDIO_ADMIN_DIGEST("sandboxLaunchSpecDigest", spec_digest);
#undef STDIO_ADMIN_TEXT
#undef STDIO_ADMIN_DIGEST
        valid = valid && (!strcmp(b->method, "mcp.register") || !strcmp(b->method, "mcp.refresh")) &&
            stdio_member_number(&json, "attempt", 0, &b->attempt) && stdio_member_number(&json, "stateOwnerEpoch", 1, &b->owner_epoch) &&
            stdio_member_number(&json, "deadlineMs", 1, &b->deadline_ms) && stdio_member_digest(&json, "nonce", binding->nonce);
    } else if (purpose == CLIQ_MCP_STDIO_RECOVERY) {
        const char *keys[] = {"runId","principalId","probeKind","brokerDispatchId","inspectorSupervisorInstanceId","originalOpId","originalDispatchId","effectServerToolName","adapterExecutableId","profileId","statusOperationName","previousWaitingSubjectRef","waitingSubjectRef","reconciliationSubjectDigest","probeNonceDigest","probeDispatchDigest","brokerRequestDigest","brokerTargetDigest","brokerFenceTokenDigest","originalInstanceIdentityRef","originalInstanceIdentityDigest","registryRevisionRef","registryManifestDigest","adapterRef","adapterDigest","adapterExecutableDigest","profileDigest","statusRequestTemplateRef","statusRequestTemplateDigest","statusRequestDigest","plannedContainmentRef","plannedContainmentDigest","sandboxLaunchSpecRef","sandboxLaunchSpecDigest","nonce","probeOrdinal","probeStartedAtMs","probeDeadlineAtMs","inspectorStateOwnerEpoch","originalAttempt","originalDispatchJournalSeq"};
        struct cliq_mcp_stdio_recovery_identity *b = &binding->recovery;
        valid = mcp_json_keys(&json, 1, keys, 41);
#define RECOVERY_PARSE_TEXT(field, capacity) valid = valid && stdio_member_text(&json, #field, b->field, capacity);
        CLIQ_MCP_STDIO_RECOVERY_TEXT_FIELDS(RECOVERY_PARSE_TEXT)
#undef RECOVERY_PARSE_TEXT
#define RECOVERY_PARSE_DIGEST(field, capacity) valid = valid && stdio_member_digest(&json, #field, b->field);
        CLIQ_MCP_STDIO_RECOVERY_DIGEST_FIELDS(RECOVERY_PARSE_DIGEST)
#undef RECOVERY_PARSE_DIGEST
#define RECOVERY_PARSE_NUMBER(field, minimum) valid = valid && stdio_member_number(&json, #field, minimum, &b->field);
        CLIQ_MCP_STDIO_RECOVERY_NUMBER_FIELDS(RECOVERY_PARSE_NUMBER)
#undef RECOVERY_PARSE_NUMBER
        valid = valid && cliq_mcp_stdio_recovery_identity_valid(b);
        memcpy(binding->nonce, b->nonce, 65); memcpy(binding->token_digest, b->brokerFenceTokenDigest, 65);
    } else if (purpose == CLIQ_MCP_STDIO_RUN) {
        const char *keys[] = {"runId","launchOpId","attempt","lifecycleSeq","batchItemId","callId","callIndex","workerLaunchId","leaseEpoch","principalId",
            "supervisorInstanceId","stateOwnerEpoch","dispatchId","dispatchJournalSeq","registryRef","manifestDigest","toolRequestRef","toolRequestDigest",
            "requestRef","requestDigest","targetRef","targetDigest","grantRef","grantDigest","plannedContainmentRef","plannedContainmentDigest",
            "sandboxLaunchSpecRef","sandboxLaunchSpecDigest","nonce","releaseFenceTokenDigest","launchDeadlineMs","callDeadlineMs"};
        struct cliq_mcp_stdio_run_identity *b = &binding->run;
        valid = mcp_json_keys(&json, 1, keys, 32);
#define STDIO_RUN_TEXT(key, field) valid = valid && stdio_member_text(&json, key, b->field, sizeof(b->field))
#define STDIO_RUN_DIGEST(key, field) valid = valid && stdio_member_digest(&json, key, b->field)
#define STDIO_RUN_NUMBER(key, field, minimum) valid = valid && stdio_member_number(&json, key, minimum, &b->field)
        STDIO_RUN_TEXT("runId", run); STDIO_RUN_TEXT("launchOpId", launch_op); STDIO_RUN_TEXT("batchItemId", batch_item); STDIO_RUN_TEXT("callId", call);
        STDIO_RUN_TEXT("workerLaunchId", worker_launch); STDIO_RUN_TEXT("principalId", principal); STDIO_RUN_TEXT("supervisorInstanceId", supervisor);
        STDIO_RUN_DIGEST("registryRef", registry_ref); STDIO_RUN_DIGEST("manifestDigest", manifest_digest); STDIO_RUN_DIGEST("toolRequestRef", tool_request_ref);
        STDIO_RUN_DIGEST("toolRequestDigest", tool_request_digest); STDIO_RUN_DIGEST("requestRef", launch_request_ref); STDIO_RUN_DIGEST("requestDigest", launch_request_digest);
        STDIO_RUN_DIGEST("targetRef", target_ref); STDIO_RUN_DIGEST("targetDigest", target_digest); STDIO_RUN_DIGEST("grantRef", grant_ref); STDIO_RUN_DIGEST("grantDigest", grant_digest);
        STDIO_RUN_DIGEST("plannedContainmentRef", plan_ref); STDIO_RUN_DIGEST("plannedContainmentDigest", plan_digest); STDIO_RUN_DIGEST("sandboxLaunchSpecRef", spec_ref);
        STDIO_RUN_DIGEST("sandboxLaunchSpecDigest", spec_digest); STDIO_RUN_DIGEST("nonce", nonce);
        STDIO_RUN_NUMBER("attempt", launch_attempt, 0); STDIO_RUN_NUMBER("lifecycleSeq", lifecycle_seq, 0); STDIO_RUN_NUMBER("callIndex", call_index, 0);
        STDIO_RUN_NUMBER("leaseEpoch", lease_epoch, 1); STDIO_RUN_NUMBER("stateOwnerEpoch", owner_epoch, 1);
        STDIO_RUN_NUMBER("launchDeadlineMs", launch_deadline_ms, 1); STDIO_RUN_NUMBER("callDeadlineMs", call_deadline_ms, 1);
#undef STDIO_RUN_TEXT
#undef STDIO_RUN_DIGEST
#undef STDIO_RUN_NUMBER
        valid = valid && stdio_member_text(&json, "dispatchId", binding->dispatch, sizeof(binding->dispatch)) &&
            stdio_member_number(&json, "dispatchJournalSeq", 1, &binding->sequence) &&
            stdio_member_digest(&json, "releaseFenceTokenDigest", binding->token_digest) && b->launch_deadline_ms <= b->call_deadline_ms;
        memcpy(binding->nonce, b->nonce, 65);
    } else valid = false;
    free(json.nodes); return valid;
}
static bool stdio_buffer(napi_env env, napi_value value, const unsigned char **bytes, size_t *size) {
    bool buffer = false; void *data = NULL;
    if (napi_is_buffer(env, value, &buffer) != napi_ok || !buffer || napi_get_buffer_info(env, value, &data, size) != napi_ok) return false;
    *bytes = data; return true;
}
static bool stdio_launch_argument(struct broker *broker, napi_value value, struct cliq_mcp_stdio_launch_binding *binding) {
    const unsigned char *bytes; size_t size;
    return stdio_buffer(broker->env, value, &bytes, &size) &&
        stdio_parse_launch_bytes(bytes, size, broker->recipe.purpose, binding) &&
        (broker->admin || !strcmp(binding->token_digest, broker->token_digest));
}
static bool stdio_call_argument(struct broker *broker, napi_value value, struct cliq_mcp_stdio_call_binding *binding) {
    const unsigned char *bytes; size_t size; struct mcp_json json;
    if (broker->admin || broker->recovery || !stdio_buffer(broker->env, value, &bytes, &size) || size > 65536 || !mcp_json_parse(bytes, size, &json)) return false;
    const char *keys[] = {"launch","opId","attempt","dispatchId","dispatchJournalSeq","requestRef","requestDigest","targetRef","targetDigest",
        "grantRef","grantDigest","toolContractDigest","instanceIdentityRef","instanceIdentityDigest","releaseFenceTokenDigest"};
    unsigned launch = mcp_json_member(&json, 1, "launch");
    bool valid = mcp_json_keys(&json, 1, keys, 15) && launch &&
        stdio_parse_launch_bytes(bytes + json.nodes[launch].start, json.nodes[launch].end - json.nodes[launch].start, CLIQ_MCP_STDIO_RUN, &binding->launch) &&
        !memcmp(&binding->launch, &broker->launch, sizeof(binding->launch));
#define STDIO_CALL_DIGEST(key, field) valid = valid && stdio_member_digest(&json, key, binding->field)
    STDIO_CALL_DIGEST("requestRef", request_ref); STDIO_CALL_DIGEST("requestDigest", request_digest);
    STDIO_CALL_DIGEST("targetRef", target_ref); STDIO_CALL_DIGEST("targetDigest", target_digest);
    STDIO_CALL_DIGEST("grantRef", grant_ref); STDIO_CALL_DIGEST("grantDigest", grant_digest); STDIO_CALL_DIGEST("toolContractDigest", tool_digest);
    STDIO_CALL_DIGEST("instanceIdentityRef", instance_ref); STDIO_CALL_DIGEST("instanceIdentityDigest", instance_digest);
    STDIO_CALL_DIGEST("releaseFenceTokenDigest", token_digest);
#undef STDIO_CALL_DIGEST
    valid = valid && !strcmp(binding->token_digest, broker->token_digest) &&
        stdio_member_text(&json, "opId", binding->op, sizeof(binding->op)) && stdio_member_text(&json, "dispatchId", binding->dispatch, sizeof(binding->dispatch)) &&
        stdio_member_number(&json, "attempt", 0, &binding->attempt) && stdio_member_number(&json, "dispatchJournalSeq", 1, &binding->sequence);
    free(json.nodes); return valid;
}
static bool stdio_binding_matches(struct broker *broker, napi_value value, bool call, bool live) {
    bool valid;
    if (call) { struct cliq_mcp_stdio_call_binding binding = {0}; valid = broker->call_bound && stdio_call_argument(broker, value, &binding) && !memcmp(&binding, &broker->call, sizeof(binding)); }
    else { struct cliq_mcp_stdio_launch_binding binding = {0}; valid = broker->bound && stdio_launch_argument(broker, value, &binding) && !memcmp(&binding, &broker->launch, sizeof(binding)); }
    if (valid && live) {
        uint64_t deadline = broker->admin ? broker->launch.admin.deadline_ms : broker->recovery ? broker->launch.recovery.probeDeadlineAtMs : call ? broker->launch.run.call_deadline_ms : broker->launch.run.launch_deadline_ms;
        uint64_t now = stdio_clock_ms(CLOCK_REALTIME);
        valid = broker_live(broker) && now && now < deadline && broker->retained && broker->peer && broker->peer->assert_current &&
            broker->peer->assert_current(broker->peer) && !atomic_load(&broker->peer->revoked);
    }
    return valid;
}
static struct stdio_receipt *stdio_decode(struct broker *broker, const unsigned char *bytes, size_t size, size_t end) {
    struct mcp_json json;
    // The response ceiling includes its mandatory LF framing byte.
    if (size >= broker->recipe.header.maximum_response_bytes) {
        stdio_mark_refused(broker, false);
        return NULL;
    }
    if (!mcp_json_parse(bytes, size, &json)) {
        // This is a complete LF-delimited payload inside an already validated
        // native packet. Invalid JSON can be discarded after a finite NoEcho
        // disposition; allocation failure cannot supply that observation.
        bool payload = broker->recovery && !json.allocation_failed &&
            stdio_screen_received(broker, bytes, size) != STDIO_SCREEN_UNSAFE;
        stdio_mark_refused(broker, payload);
        return NULL;
    }
    unsigned id = mcp_json_member(&json, 1, "id"), result = mcp_json_member(&json, 1, "result"), error = mcp_json_member(&json, 1, "error");
    unsigned method = mcp_json_member(&json, 1, "method"), params = mcp_json_member(&json, 1, "params");
    const char *response_keys[] = {"jsonrpc","id","result","error"}, *request_keys[] = {"jsonrpc","id","method","params"};
    bool valid = mcp_json_text(&json, mcp_json_member(&json, 1, "jsonrpc"), "2.0") &&
        broker->aggregate_entries <= MCP_MAX_ENTRIES - json.entries;
    if (valid) broker->aggregate_entries += json.entries;
    enum stdio_message_kind kind = STDIO_NOTIFICATION;
    unsigned char *semantic = NULL; size_t semantic_size = 0;
    if (result || error) {
        valid = valid && broker->phase != 1 && broker->phase < broker->recipe.header.phase_count &&
            mcp_json_keys(&json, 1, response_keys, 4) && !!result != !!error &&
            mcp_json_id(&json, id, &semantic, &semantic_size) &&
            semantic_size == broker->frames[broker->phase].id_size &&
            !memcmp(semantic, broker->frames[broker->phase].id, semantic_size);
        if (result) valid = valid && json.nodes[result].type == '{';
        if (error) {
            const char *keys[] = {"code","message","data"}; unsigned char *integer = NULL; size_t integer_size = 0;
            unsigned code = mcp_json_member(&json, error, "code"), message = mcp_json_member(&json, error, "message");
            valid = valid && mcp_json_keys(&json, error, keys, 3) && code && json.nodes[code].type == '#' &&
                mcp_json_id(&json, code, &integer, &integer_size) && message && json.nodes[message].type == '"';
            free(integer);
        }
        if (broker->phase == 2 && result && mcp_json_member(&json, result, "nextCursor")) valid = false;
        kind = STDIO_RESPONSE;
    } else {
        valid = valid && mcp_json_keys(&json, 1, request_keys, 4) && method && (!params || json.nodes[params].type == '{');
        if (id) {
            valid = valid && !broker->ping && broker->ping_count < 8 && mcp_json_text(&json, method, "ping") &&
                (!params || !json.nodes[params].child) && mcp_json_id(&json, id, &semantic, &semantic_size);
            kind = STDIO_PING;
        } else {
            bool changed = mcp_json_text(&json, method, "notifications/tools/list_changed");
            valid = valid && (changed || mcp_json_text(&json, method, "notifications/progress") || mcp_json_text(&json, method, "notifications/message")) &&
                (!changed || !params || !json.nodes[params].child);
        }
    }
    // The complete actual event is screened before it can become a JS receipt.
    // Matching detection inside a refused event cannot substitute for this.
    bool payload_refused = false;
    if (broker->recovery) {
        enum stdio_received_screen screen = json.allocation_failed ? STDIO_SCREEN_UNSAFE : stdio_screen_received(broker, bytes, size);
        payload_refused = screen != STDIO_SCREEN_UNSAFE && (!valid || screen == STDIO_SCREEN_REFUSED);
        valid = valid && screen == STDIO_SCREEN_CLEAR;
    } else {
        valid = valid && mcp_no_echo_all(broker, bytes, size);
    }
    struct stdio_receipt *receipt = valid ? calloc(1, sizeof(*receipt)) : NULL;
    if (receipt) {
        receipt->message = malloc(size); receipt->owner = broker; receipt->phase = broker->phase;
        receipt->ordinal = ++broker->ordinal; receipt->kind = kind; receipt->size = size;
        receipt->start = broker->capture_start; receipt->response_end = end;
        if (receipt->message) memcpy(receipt->message, bytes, size); else valid = false;
        valid = valid && stdio_hash(bytes, size, receipt->digest);
        if (kind == STDIO_PING && valid) {
            receipt->ping_id_size = json.nodes[id].end - json.nodes[id].start;
            receipt->ping_id = malloc(receipt->ping_id_size);
            valid = receipt->ping_id != NULL;
            if (valid) memcpy(receipt->ping_id, bytes + json.nodes[id].start, receipt->ping_id_size);
        }
        if (valid) { receipt->next = broker->receipts; broker->receipts = receipt; }
        else { free(receipt->message); free(receipt->ping_id); free(receipt); receipt = NULL; }
    }
    free(semantic); free(json.nodes);
    if (!receipt) stdio_mark_refused(broker, payload_refused);
    return receipt;
}
static bool stdio_parse_lines(struct broker *broker) {
    if (broker->response_refused || broker->pending || broker->advancing || broker->ping || !broker->stage_released || broker->phase >= broker->recipe.header.phase_count) return true;
    while (broker->parse_at < broker->output_size[0]) {
        unsigned char *lf = memchr(broker->output[0] + broker->parse_at, '\n', broker->output_size[0] - broker->parse_at);
        if (!lf) {
            if (broker->output_size[0] - broker->parse_at >= broker->recipe.header.maximum_response_bytes) {
                broker->response_refused = true; return broker_fail(broker, "mcp_response_refused");
            }
            return true;
        }
        size_t end = (size_t)(lf - broker->output[0]) + 1, size = end - broker->parse_at - 1;
        struct stdio_receipt *receipt = stdio_decode(broker, broker->output[0] + broker->parse_at, size, end);
        broker->parse_at = end;
        if (!receipt) return broker->payload_refused;
        if (receipt->kind == STDIO_PING) {
            broker->ping_count++;
            if (broker->closing) { receipt->ping_released = true; continue; }
            broker->ping = receipt;
        }
        if (receipt->kind == STDIO_RESPONSE) {
            broker->advancing = receipt;
            if (broker->phase + 1 == broker->recipe.header.phase_count) {
                broker->protocol_complete = true; broker->completed = broker->recipe.header.phase_count;
            }
        }
        if (broker->closing && receipt->kind != STDIO_RESPONSE) continue;
        broker->pending = receipt; return true;
    }
    return true;
}
static void stdio_proof_finalize(napi_env env, void *data, void *hint) {
    (void)hint; struct stdio_proof *proof = data;
    if (proof->fence_active) {
        proof->owner->unsafe = true; atomic_store(&retirement_failed, true);
        // Keep the actual locked mutex and original owner pinned. GC cannot
        // turn a lost continuously held release guard into a fresh guard.
        return;
    }
    if (proof->original) napi_delete_reference(env, proof->original);
    free(proof);
}
static bool stdio_wrap_proof(struct broker *broker, napi_value object, struct stdio_receipt *receipt, const napi_type_tag *tag) {
    struct stdio_proof *proof = calloc(1, sizeof(*proof)); napi_value owner;
    if (!proof) return false;
    proof->owner = broker; proof->receipt = receipt;
    bool valid = napi_get_reference_value(broker->env, broker->handle, &owner) == napi_ok && owner &&
        napi_create_reference(broker->env, owner, 1, &proof->original) == napi_ok &&
        napi_type_tag_object(broker->env, object, tag) == napi_ok &&
        napi_wrap(broker->env, object, proof, stdio_proof_finalize, NULL, NULL) == napi_ok;
    if (!valid) { if (proof->original) napi_delete_reference(broker->env, proof->original); free(proof); }
    return valid;
}
static struct stdio_proof *stdio_unwrap_proof(struct broker *broker, napi_value value, const napi_type_tag *tag) {
    bool valid = false; struct stdio_proof *proof = NULL;
    return napi_check_object_type_tag(broker->env, value, tag, &valid) == napi_ok && valid &&
        napi_unwrap(broker->env, value, (void **)&proof) == napi_ok && proof && proof->owner == broker ? proof : NULL;
}
static napi_value stdio_message_value(struct broker *broker, struct stdio_receipt *receipt) {
    napi_value value, bytes, proof;
    if (napi_create_object(broker->env, &value) != napi_ok || napi_create_object(broker->env, &proof) != napi_ok ||
        !stdio_wrap_proof(broker, proof, receipt, &STDIO_RECEIPT_TAG) || napi_object_freeze(broker->env, proof) != napi_ok ||
        napi_create_buffer_copy(broker->env, receipt->size, receipt->message, NULL, &bytes) != napi_ok) return NULL;
    const char *kind = receipt->kind == STDIO_RESPONSE ? "response" : receipt->kind == STDIO_PING ? "ping" : "notification";
    set_string(broker->env, value, "kind", kind); set_string(broker->env, value, "phase", mcp_phase_name(receipt->phase));
    set_number(broker->env, value, "ordinal", receipt->ordinal); set_string(broker->env, value, "messageDigest", receipt->digest);
    napi_set_named_property(broker->env, value, "messageBytes", bytes); napi_set_named_property(broker->env, value, "receipt", proof);
    napi_object_freeze(broker->env, value); return value;
}
static napi_value stdio_stage_value(struct broker *broker, bool written) {
    napi_value value; napi_create_object(broker->env, &value);
    set_string(broker->env, value, "kind", written ? "stage_written" : "stage_requested");
    set_string(broker->env, value, "phase", written ? "initialized" : mcp_phase_name(broker->phase));
    napi_object_freeze(broker->env, value); return value;
}
static napi_value stdio_join_value(struct broker *broker, bool unavailable) {
    napi_value value, flag, stages, phase;
    if (napi_create_object(broker->env, &value) != napi_ok) return NULL;
    const napi_type_tag *tag = unavailable ? &STDIO_RECOVERY_UNAVAILABLE_JOIN_TAG : broker->recovery ? &STDIO_RECOVERY_JOIN_TAG : &STDIO_JOIN_TAG;
    if (!stdio_wrap_proof(broker, value, NULL, tag)) return NULL;
    const char *kind = unavailable ? "mcp_stdio_recovery_response_unavailable_joined" :
        broker->recovery ? "mcp_stdio_recovery_owner_joined" : "mcp_stdio_owner_joined";
    set_string(broker->env, value, "kind", kind);
    set_string(broker->env, value, "purpose", broker->admin ? "admin" : broker->recovery ? "recovery" : "run");
    if (unavailable) set_string(broker->env, value, "reason", "native_response_refused");
    napi_get_boolean(broker->env, broker->exec_released, &flag); napi_set_named_property(broker->env, value, "execReleased", flag);
    napi_get_boolean(broker->env, broker->setup_released, &flag); napi_set_named_property(broker->env, value, "setupReleased", flag);
    napi_get_boolean(broker->env, broker->recovery ? broker->status_released : broker->effect_released, &flag); napi_set_named_property(broker->env, value, broker->recovery ? "statusReleased" : "effectReleased", flag);
    napi_get_boolean(broker->env, true, &flag);
    const char *fields[] = {"tokenRevoked","processJoined","pipesJoined","tasksJoined","outputCustodyRetired"};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) napi_set_named_property(broker->env, value, fields[i], flag);
    set_number(broker->env, value, "matchingActiveReleaseCount", 0); napi_create_array(broker->env, &stages);
    for (unsigned i = 0; i < broker->completed; i++) {
        napi_create_string_utf8(broker->env, mcp_phase_name(i), NAPI_AUTO_LENGTH, &phase); napi_set_element(broker->env, stages, i, phase);
    }
    napi_object_freeze(broker->env, stages); napi_set_named_property(broker->env, value, "completedStages", stages);
    if (!broker->admin) set_string(broker->env, value, "releaseFenceTokenDigest", broker->token_digest);
    napi_object_freeze(broker->env, value); return value;
}
static void stdio_deliver(struct broker *broker) {
    if (!broker->message_deferred || broker->env_closing) return;
    napi_value value = NULL;
    if (broker->pending) {
        if (broker->await_write && !broker->closing) return;
        struct stdio_receipt *receipt = broker->pending; broker->pending = NULL; value = stdio_message_value(broker, receipt);
    } else if (broker->stage_written) { broker->stage_written = false; value = stdio_stage_value(broker, true); }
    else if (!broker->closing && broker->exec_released && !broker->stage_requested && !broker->stage_released && broker->phase < broker->recipe.header.phase_count) {
        broker->stage_requested = true; value = stdio_stage_value(broker, false);
    } else if ((broker->closing && broker->retired) || broker->response_refused || broker->unsafe) {
        napi_reject_deferred(broker->env, broker->message_deferred,
            stdio_error(broker, broker->unsafe || (broker->response_refused && !broker->payload_refused)));
        broker->message_deferred = NULL; return;
    }
    if (value) { napi_resolve_deferred(broker->env, broker->message_deferred, value); broker->message_deferred = NULL; }
}
static void stdio_begin_close(struct broker *broker);
static bool stdio_receive_packet(struct broker *broker, unsigned kind, const unsigned char *bytes, size_t size) {
    if (kind == CLIQ_MCP_STDIO_STDOUT || kind == CLIQ_MCP_STDIO_STDERR) {
        unsigned stream = kind == CLIQ_MCP_STDIO_STDERR ? 1 : 0;
        if (!size || size > CLIQ_MCP_STDIO_CHUNK_BYTES || broker->output_eof[stream] || broker->ack_stream ||
            size > broker->recipe.header.maximum_output_bytes - broker->output_size[0] - broker->output_size[1]) return false;
        if (!broker->refused_output_discarded)
            memcpy(broker->output[stream] + broker->output_size[stream], bytes, size);
        broker->output_size[stream] += size;
        broker->ack_stream = stream + 1;
        return stream || stdio_parse_lines(broker);
    }
    if (kind == CLIQ_MCP_STDIO_OUTPUT_EOF && size == 4) {
        unsigned stream = stdio_le32(bytes);
        if (stream < 1 || stream > 2 || broker->output_eof[stream - 1] || broker->ack_stream) return false;
        broker->output_eof[stream - 1] = true; broker->ack_stream = stream; return true;
    }
    if (kind == CLIQ_MCP_STDIO_FRAME_WRITTEN && size == 8 && broker->await_write && !stdio_le32(bytes + 4)) {
        unsigned phase = stdio_le32(bytes);
        if (broker->write_ping) {
            if (phase != UINT32_MAX || !broker->ping || !broker->ping->ping_released) return false;
            broker->ping = NULL;
        } else {
            if (phase != broker->write_phase || phase != broker->phase) return false;
            if (phase == 1) {
                broker->stage_written = true; broker->phase = broker->completed = 2;
                broker->stage_requested = broker->stage_released = false;
            }
        }
        broker->await_write = false; return true;
    }
    if (kind == CLIQ_MCP_STDIO_CLIENT_JOINED && size == 4 && stdio_le32(bytes) <= 1 &&
        broker->output_eof[0] && broker->output_eof[1] && !broker->ack_stream && !broker->client_joined) {
        // The actual server may exit before the host requests cancellation or
        // its already-screened final response's protocol-done frame is read.
        // This reports only the client's genuine pipe/reap join; scope death
        // and output ACK still require their independent original checks.
        if ((stdio_le32(bytes) == 1 && !broker->protocol_complete) || (broker->tx &&
            stdio_le32(broker->tx + 8) == CLIQ_MCP_STDIO_CHUNK_ACK && broker->tx_at != broker->tx_size)) return false;
        // No further frame can be delivered to the reaped client. Discard an
        // original unfinished command without claiming its write completed.
        if (broker->tx) { wipe(broker->tx, broker->tx_size); free(broker->tx); broker->tx = NULL; broker->tx_at = broker->tx_size = 0; }
        broker->command_kind = 0; broker->client_joined = true; stdio_begin_close(broker); return true;
    }
    return false;
}
static bool stdio_read(struct broker *broker, int fd) {
    // At most one bounded IPC payload is allocated. A complete message is not
    // followed by another server read until this task has consumed its bytes.
    for (unsigned turn = 0; turn < 4; turn++) {
        unsigned char *target = broker->rx ? broker->rx + broker->rx_at : broker->rx_header + broker->rx_header_at;
        size_t left = broker->rx ? broker->rx_size - broker->rx_at : sizeof(broker->rx_header) - broker->rx_header_at;
        ssize_t n = recv(fd, target, left, MSG_DONTWAIT);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return true;
        if (n <= 0) return broker->client_joined;
        if (!broker->rx) {
            broker->rx_header_at += (size_t)n;
            if (broker->rx_header_at < sizeof(broker->rx_header)) continue;
            if (stdio_le32(broker->rx_header) != CLIQ_MCP_STDIO_CHANNEL_MAGIC || stdio_le32(broker->rx_header + 4) != 1) return false;
            broker->rx_kind = stdio_le32(broker->rx_header + 8); broker->rx_size = stdio_le32(broker->rx_header + 12);
            if (!broker->rx_size || broker->rx_size > CLIQ_MCP_STDIO_CHUNK_BYTES) return false;
            broker->rx = malloc(broker->rx_size); broker->rx_at = 0;
            if (!broker->rx) return false;
        } else {
            broker->rx_at += (size_t)n;
            if (broker->rx_at < broker->rx_size) continue;
            bool valid = stdio_receive_packet(broker, broker->rx_kind, broker->rx, broker->rx_size);
            wipe(broker->rx, broker->rx_size); free(broker->rx); broker->rx = NULL; broker->rx_at = broker->rx_size = broker->rx_header_at = 0;
            if (!valid) return false;
            return true;
        }
    }
    return true;
}
static bool stdio_flush_or_join(struct broker *broker, int fd) {
    if (stdio_flush(broker, fd)) return true;
    // A naturally exiting fixed client sends its joined packet before closing
    // this socket. Consume that actual packet before treating an undeliverable
    // final protocol/cancel command as an interrupted lifecycle. The packet
    // decoder still refuses an unfinished output ACK or missing EOF.
    return stdio_read(broker, fd) && broker->client_joined;
}
static void stdio_free(struct broker *broker);
static bool stdio_peer_progress(struct broker *broker, bool drained) {
    if (!broker->peer) return true;
    struct cliq_mcp_stdio_owner_progress progress = {.phase = broker->protocol_complete ? broker->recipe.header.phase_count : broker->completed,
        .protocol_complete = broker->protocol_complete, .effect_released = broker->effect_released, .status_released = broker->status_released,
        .response_refused = broker->response_refused, .owner_drained = drained};
    return broker->peer->progress && broker->peer->progress(broker->peer, &progress) > 0;
}
static bool stdio_queue_command(struct broker *broker) {
    if (broker->client_joined) return true;
    if (broker->tx || broker->ack_stream) return true;
    if (broker->command_kind && !broker->closing) {
        unsigned kind = broker->command_kind; broker->command_kind = 0;
        if (kind == CLIQ_MCP_STDIO_FRAME) {
            unsigned char scalar[4]; stdio_put32(scalar, broker->write_phase);
            return stdio_enqueue(broker, kind, scalar, sizeof(scalar));
        }
        if (kind != CLIQ_MCP_STDIO_PING_REPLY || !broker->ping || !broker->ping->ping_released) return false;
        const char prefix[] = "{\"id\":", suffix[] = ",\"jsonrpc\":\"2.0\",\"result\":{}}";
        size_t size = sizeof(prefix) - 1 + broker->ping->ping_id_size + sizeof(suffix) - 1;
        if (size > broker->recipe.header.maximum_response_bytes) return false;
        unsigned char *body = malloc(size); if (!body) return false;
        memcpy(body, prefix, sizeof(prefix) - 1); memcpy(body + sizeof(prefix) - 1, broker->ping->ping_id, broker->ping->ping_id_size);
        memcpy(body + sizeof(prefix) - 1 + broker->ping->ping_id_size, suffix, sizeof(suffix) - 1);
        bool valid = stdio_enqueue(broker, kind, body, size); wipe(body, size); free(body); return valid;
    }
    if (broker->protocol_complete && !broker->protocol_sent) {
        if (!stdio_enqueue(broker, CLIQ_MCP_STDIO_PROTOCOL_DONE, NULL, 0)) return false;
        broker->protocol_sent = true;
    } else if (broker->closing && !broker->cancel_queued && !broker->client_joined) {
        if (!stdio_enqueue(broker, CLIQ_MCP_STDIO_CANCEL, NULL, 0)) return false;
        broker->cancel_queued = true;
    }
    return true;
}
static void stdio_discard_refused_output(struct broker *broker) {
    if (broker->refused_output_discarded) return;
    broker->refused_output_discarded = true;
    for (unsigned stream = 0; stream < 2; stream++)
        wipe(broker->output[stream], broker->output_size[stream]);
    broker->pending = NULL;
    stdio_begin_close(broker);
}
static bool stdio_screen_recovery_drain(struct broker *broker) {
    if (!broker->recovery || broker->response_refused || broker->raw_screened) return true;
    // Commit the disposition before the original controller's last drained
    // progress and ACK. Later history can verify it from that original record.
    enum stdio_received_screen out = stdio_screen_received(broker, broker->output[0], broker->output_size[0]);
    enum stdio_received_screen err = stdio_screen_received(broker, broker->output[1], broker->output_size[1]);
    if (out == STDIO_SCREEN_UNSAFE || err == STDIO_SCREEN_UNSAFE) return false;
    broker->raw_screened = true;
    broker->raw_refused = out == STDIO_SCREEN_REFUSED || err == STDIO_SCREEN_REFUSED;
    if (broker->raw_refused) {
        stdio_mark_refused(broker, true);
        stdio_discard_refused_output(broker);
    }
    return true;
}
static bool stdio_io_drained(const struct broker *broker) {
    return broker->closing && broker->client_joined && broker->output_eof[0] && broker->output_eof[1] &&
        !broker->rx && !broker->rx_header_at && !broker->tx && !broker->ack_stream;
}
static void stdio_observe_peer_retirement(struct broker *broker) {
    struct cliq_mcp_stdio_peer *peer = broker->peer;
    if (!atomic_load(&peer->physical_joined) || !atomic_load(&peer->output_retired) ||
        (broker->payload_refused && !atomic_load(&peer->operation_closed))) return;
    broker->retired = true;
    if (!broker->retired_at_ms) broker->retired_at_ms = stdio_clock_ms(CLOCK_MONOTONIC);
}
static bool stdio_pump_io(struct broker *broker) {
    if (!broker->peer) { if (broker->closing) broker->retired = true; return true; }
    int fd = broker->peer->operation_fd ? broker->peer->operation_fd(broker->peer) : -1;
    if (fd < 0) {
        if (broker->closing && !broker->exec_released) {
            if (!stdio_peer_progress(broker, true)) return false;
            stdio_observe_peer_retirement(broker);
        } else if (stdio_io_drained(broker) && atomic_load(&broker->peer->io_joined) &&
            broker->peer->assert_current && broker->peer->assert_current(broker->peer)) {
            // The actual ACK may retire this operation FD before the next
            // broker tick. Only already-observed drain and the same original
            // peer's joined/output facts can close the descriptor-less path.
            stdio_observe_peer_retirement(broker);
        }
        return true;
    }
    if (!stdio_flush_or_join(broker, fd) || !stdio_queue_command(broker) || !stdio_flush_or_join(broker, fd)) return false;
    if (!stdio_read(broker, fd)) return false;
    if (!stdio_flush_or_join(broker, fd)) return false;
    if (!stdio_parse_lines(broker)) return false;
    bool drained = stdio_io_drained(broker);
    if (drained && !stdio_screen_recovery_drain(broker)) return false;
    if (!stdio_peer_progress(broker, drained)) return false;
    if (drained) stdio_observe_peer_retirement(broker);
    return true;
}
static bool stdio_unavailable_joined(const struct broker *broker) {
    const struct cliq_mcp_stdio_peer *peer = broker->peer;
    return broker->recovery && broker->bound && broker->exec_released && !broker->effect_released &&
        broker->response_refused && broker->payload_refused && broker->refused_output_discarded &&
        broker->close_finished && broker->retired && !broker->unsafe && !broker->io_aborted &&
        broker->retired_at_ms && broker->retired_at_ms < broker->stop_deadline_ms &&
        broker->client_joined && broker->output_eof[0] && broker->output_eof[1] &&
        !broker->rx && !broker->rx_header_at && !broker->tx && !broker->ack_stream &&
        peer && peer->purpose == CLIQ_MCP_STDIO_RECOVERY && broker->peer->assert_current &&
        broker->peer->assert_current(broker->peer) && atomic_load(&peer->revoked) && atomic_load(&peer->io_joined) &&
        atomic_load(&peer->physical_joined) && atomic_load(&peer->output_retired) && atomic_load(&peer->operation_closed);
}
static void stdio_close_timer(uv_handle_t *handle) {
    struct broker *broker = handle->data; struct native_callback_scope callback;
    callbacks_enter(&broker->callbacks, broker->env_closing, &callback);
    broker->timer_closed = true; broker->close_finished = true;
    if (broker->recipe.fd >= 0) { int fd = broker->recipe.fd; broker->recipe.fd = -1; if (close(fd)) broker->unsafe = true; }
    stdio_deliver(broker);
    if (broker->close_promise) { napi_delete_reference(broker->env, broker->close_promise); broker->close_promise = NULL; }
    if (broker->close_deferred && !broker->env_closing) {
        napi_deferred deferred = broker->close_deferred; broker->close_deferred = NULL;
        napi_value joined = broker->unsafe || broker->response_refused ? NULL : stdio_join_value(broker, false);
        if (joined) napi_resolve_deferred(broker->env, deferred, joined);
        else napi_reject_deferred(broker->env, deferred, stdio_error(broker, true));
    }
    if (broker->cleanup_hook && (!broker->retained || broker->env_closing)) {
        napi_remove_async_cleanup_hook(broker->cleanup_hook); broker->cleanup_hook = NULL;
    }
    callbacks_close(&broker->callbacks, &callback); callbacks_retire(&broker->callbacks);
    if (broker->callbacks.borrows) broker->callbacks.borrows--;
    if (broker->work_owner && (!broker->retained || broker->env_closing)) {
        napi_delete_reference(broker->env, broker->work_owner); broker->work_owner = NULL;
    }
    if (broker->finalized) stdio_free(broker);
}
static void stdio_abort_io(struct broker *broker) {
    if (broker->io_aborted) return;
    broker->io_aborted = broker->unsafe = true;
    // Retain only progress already observed, never a fabricated drained flag.
    (void)stdio_peer_progress(broker, false);
    stdio_begin_close(broker);
    if (broker->peer && (!broker->peer->cancel || broker->peer->cancel(broker->peer, true) < 0))
        atomic_store(&retirement_failed, true);
}
static bool stdio_close_ready(const struct broker *broker) {
    return broker->closing && (broker->retired || (broker->io_aborted &&
        (!broker->peer || atomic_load(&broker->peer->operation_closed))));
}
static void stdio_tick(uv_timer_t *timer) {
    struct broker *broker = timer->data; struct native_callback_scope callback;
    callbacks_enter(&broker->callbacks, broker->env_closing, &callback);
    if (broker->recovery && broker->bound && !broker->closing) {
        uint64_t now = stdio_clock_ms(CLOCK_REALTIME);
        if (!now) stdio_abort_io(broker);
        else if (now >= broker->launch.recovery.probeDeadlineAtMs) stdio_begin_close(broker);
    }
    if (!broker->closing && !broker_live(broker)) stdio_begin_close(broker);
    if (broker->closing && broker->pending && broker->pending->kind != STDIO_RESPONSE && !broker->message_deferred) broker->pending = NULL;
    if (!broker->io_aborted && !stdio_pump_io(broker)) { broker_fail(broker, "mcp_transport_interrupted"); stdio_abort_io(broker); }
    if (broker->unsafe || (broker->response_refused && !broker->payload_refused)) stdio_abort_io(broker);
    else if (broker->payload_refused) stdio_discard_refused_output(broker);
    stdio_deliver(broker);
    if (broker->closing && !broker->retired && stdio_clock_ms(CLOCK_MONOTONIC) >= broker->stop_deadline_ms && !broker->unsafe) {
        broker->unsafe = true; atomic_store(&retirement_failed, true);
        if (broker->close_deferred && !broker->env_closing) {
            napi_reject_deferred(broker->env, broker->close_deferred, stdio_error(broker, true)); broker->close_deferred = NULL;
        }
    }
    if (stdio_close_ready(broker) && !broker->timer_closing) {
        broker->timer_closing = true; uv_timer_stop(&broker->timer); uv_close((uv_handle_t *)&broker->timer, stdio_close_timer);
    }
    callbacks_close(&broker->callbacks, &callback);
    if (broker->callbacks.borrows) broker->callbacks.borrows--;
}
static void stdio_begin_close(struct broker *broker) {
    if (broker->closing) return;
    broker->closing = true; broker->stop_deadline_ms = stdio_clock_ms(CLOCK_MONOTONIC) + 2000; broker->command_kind = 0;
    if (broker->peer && (!broker->peer->cancel || broker->peer->cancel(broker->peer, false) < 0)) broker->unsafe = true;
}
static void stdio_cleanup(napi_async_cleanup_hook_handle hook, void *data) {
    (void)hook; struct broker *broker = data; broker->env_closing = true;
    if (!broker->close_finished) stdio_abort_io(broker);
    if (broker->close_finished && broker->cleanup_hook) {
        napi_remove_async_cleanup_hook(broker->cleanup_hook); broker->cleanup_hook = NULL;
        if (broker->work_owner) { napi_delete_reference(broker->env, broker->work_owner); broker->work_owner = NULL; }
    }
}
static void stdio_free(struct broker *broker) {
    // Recipe JS wrappers may outlive the owner JS wrapper. Their independent C
    // borrow keeps only original preparation data, never a recreatable owner.
    if (broker->references || !broker->timer_closed || broker->fence_locked || broker->cleanup_hook || broker->callbacks.borrows) return;
    for (unsigned i = 0; i < 4; i++) free(broker->frames[i].id);
    struct stdio_receipt *receipt = broker->receipts;
    while (receipt) { struct stdio_receipt *next = receipt->next; wipe(receipt->message, receipt->size); free(receipt->message); free(receipt->ping_id); free(receipt); receipt = next; }
    if (broker->peer_ref) napi_delete_reference(broker->env, broker->peer_ref);
    if (broker->handle) napi_delete_reference(broker->env, broker->handle);
    if (broker->tx) { wipe(broker->tx, broker->tx_size); free(broker->tx); }
    if (broker->rx) { wipe(broker->rx, broker->rx_size); free(broker->rx); }
    for (unsigned i = 0; i < 2; i++) { wipe(broker->output[i], broker->output_size[i]); free(broker->output[i]); }
    wipe(broker->recipe.bytes, broker->recipe.size); free(broker->recipe.bytes);
    if (broker->mutex_ready) pthread_mutex_destroy(&broker->release_mutex);
    free(broker);
}
static void stdio_owner_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint; struct broker *broker = data; broker->finalized = true;
    if (broker->references) broker->references--;
    stdio_begin_close(broker); stdio_free(broker);
}
static void stdio_recipe_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint; struct cliq_mcp_stdio_recipe *recipe = data; struct broker *broker = recipe->owner;
    if (broker->references) broker->references--;
    stdio_free(broker);
}
static bool stdio_recipe_owner(struct cliq_mcp_stdio_recipe *recipe, void **value) {
    struct broker *broker = recipe->owner; napi_value owner = NULL;
    if (!stdio_current(broker, recipe->environment) || broker->finalized || broker->closing ||
        napi_get_reference_value(broker->env, broker->handle, &owner) != napi_ok || !owner) return false;
    *value = owner; return true;
}
static bool stdio_register_peer(struct cliq_mcp_stdio_recipe *recipe, struct cliq_mcp_stdio_peer *peer, void *value) {
    struct broker *broker = recipe->owner;
    if (!stdio_current(broker, recipe->environment) || broker->closing || broker->peer || recipe->consumed ||
        peer->abi_version != CLIQ_MCP_STDIO_OWNER_ABI || peer->recipe != recipe || peer->purpose != recipe->purpose ||
        peer->creator_pid != getpid() || peer->environment != broker->env || !peer->assert_current || !peer->assert_current(peer) ||
        napi_create_reference(broker->env, (napi_value)value, 1, &broker->peer_ref) != napi_ok) return false;
    broker->peer = peer; return true;
}
static napi_value stdio_recipe_copy(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; bool admin = false, run = false, recovery = false; struct cliq_mcp_stdio_recipe *recipe = NULL;
    if (napi_get_cb_info(env, info, &argc, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &CLIQ_MCP_STDIO_ADMIN_RECIPE_TAG, &admin) != napi_ok ||
        napi_check_object_type_tag(env, self, &CLIQ_MCP_STDIO_RUN_RECIPE_TAG, &run) != napi_ok ||
        napi_check_object_type_tag(env, self, &CLIQ_MCP_STDIO_RECOVERY_RECIPE_TAG, &recovery) != napi_ok || (!admin && !run && !recovery) ||
        napi_unwrap(env, self, (void **)&recipe) != napi_ok || !recipe || !stdio_current(recipe->owner, env) ||
        recipe->purpose != (admin ? CLIQ_MCP_STDIO_ADMIN : recovery ? CLIQ_MCP_STDIO_RECOVERY : CLIQ_MCP_STDIO_RUN)) {
        napi_throw_type_error(env, NULL, "Invalid original MCP stdio fixed recipe"); return NULL;
    }
    napi_value value; if (napi_create_buffer_copy(env, recipe->size, recipe->bytes, NULL, &value) != napi_ok) return NULL;
    return value;
}
static napi_value stdio_attach(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    bool tagged = false; struct cliq_mcp_stdio_peer *peer = NULL;
    const napi_type_tag *tag = broker->admin ? &CLIQ_MCP_STDIO_ADMIN_PEER_TAG : broker->recovery ? &CLIQ_MCP_STDIO_RECOVERY_PEER_TAG : &CLIQ_MCP_STDIO_RUN_PEER_TAG;
    if (argc != 1 || broker->closing || napi_check_object_type_tag(env, args[0], tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, args[0], (void **)&peer) != napi_ok || peer != broker->peer || !peer ||
        peer->recipe != &broker->recipe || !peer->assert_current || !peer->assert_current(peer)) return stdio_throw(broker, false);
    return undefined(env);
}
static bool stdio_recovery_frame_matches(struct broker *broker, const struct cliq_mcp_stdio_recovery_identity *binding) {
    if (strcmp(binding->statusRequestDigest, broker->recipe.header.frames[3].digest)) return false;
    struct mcp_json json;
    if (!mcp_json_parse(broker->frames[3].body, broker->frames[3].size, &json)) return false;
    unsigned params = mcp_json_member(&json, 1, "params");
    bool valid = params && mcp_json_text(&json, mcp_json_member(&json, params, "name"), binding->statusOperationName);
    free(json.nodes); return valid;
}
static napi_value stdio_bind_launch(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    struct cliq_mcp_stdio_launch_binding binding = {0};
    if (argc != 1 || broker->closing || !stdio_launch_argument(broker, args[0], &binding) ||
        (broker->recovery && !stdio_recovery_frame_matches(broker, &binding.recovery)) ||
        (broker->bound ? memcmp(&binding, &broker->launch, sizeof(binding)) :
        !broker->peer || !broker->peer->bind_launch || !broker->peer->bind_launch(broker->peer, &binding))) return stdio_throw(broker, false);
    if (!broker->bound) {
        if (broker->recovery) {
            uint64_t real = stdio_clock_ms(CLOCK_REALTIME), monotonic = stdio_clock_ms(CLOCK_MONOTONIC);
            if (!real || !monotonic || real < binding.recovery.probeStartedAtMs || real >= binding.recovery.probeDeadlineAtMs) return stdio_throw(broker, false);
            uint64_t original_deadline = monotonic + binding.recovery.probeDeadlineAtMs - real;
            if (original_deadline < broker->deadline_ms) broker->deadline_ms = original_deadline;
        }
        broker->launch = binding; broker->bound = true;
    }
    return undefined(env);
}
static napi_value stdio_assert_launch(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    if (argc != 1 || !stdio_binding_matches(broker, args[0], false, false)) return stdio_throw(broker, false);
    return undefined(env);
}
static napi_value stdio_bind_call(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    struct cliq_mcp_stdio_call_binding binding = {0};
    if (argc != 1 || broker->admin || broker->recovery || broker->closing || !broker->bound || broker->completed != 3 || broker->effect_released ||
        !stdio_call_argument(broker, args[0], &binding) || (broker->call_bound && memcmp(&binding, &broker->call, sizeof(binding)))) return stdio_throw(broker, false);
    if (!broker->call_bound) { broker->call = binding; broker->call_bound = true; }
    return undefined(env);
}
static napi_value stdio_assert_call(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    if (argc != 1 || !stdio_binding_matches(broker, args[0], true, false)) return stdio_throw(broker, false);
    return undefined(env);
}
static napi_value stdio_release_exec(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    if (argc != 1 || broker->exec_released || broker->fence_locked || !stdio_binding_matches(broker, args[0], false, true) ||
        !broker->peer->release_exec || pthread_mutex_lock(&broker->release_mutex)) return stdio_throw(broker, false);
    bool valid = !broker->closing && broker->peer->release_exec(broker->peer) > 0;
    // A lost result after this entry cannot create another executable claim.
    broker->exec_released = true;
    if (pthread_mutex_unlock(&broker->release_mutex)) { broker->unsafe = true; valid = false; }
    if (!valid) { stdio_begin_close(broker); return stdio_throw(broker, true); }
    return undefined(env);
}
static napi_value stdio_release_stage(napi_env env, napi_callback_info info) {
    size_t argc = 3; napi_value args[3]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    char phase[32]; size_t length = 0;
    bool valid = argc == 2 && napi_get_value_string_utf8(env, args[1], phase, sizeof(phase), &length) == napi_ok &&
        length && length < sizeof(phase) && strlen(phase) == length && broker->exec_released && broker->stage_requested &&
        !broker->stage_released && !broker->await_write && !broker->command_kind && !broker->fence_locked &&
        broker->phase < broker->recipe.header.phase_count && !strcmp(phase, mcp_phase_name(broker->phase)) &&
        stdio_binding_matches(broker, args[0], broker->phase == 3 && !broker->recovery, true);
    if (!valid || pthread_mutex_lock(&broker->release_mutex)) return stdio_throw(broker, false);
    valid = !broker->closing;
    if (valid) {
        broker->stage_released = true; broker->await_write = true; broker->write_ping = false; broker->write_phase = broker->phase;
        broker->command_kind = CLIQ_MCP_STDIO_FRAME;
        if (broker->phase == 3) { if (broker->recovery) broker->status_released = true; else broker->effect_released = true; } else broker->setup_released = true;
        valid = stdio_peer_progress(broker, false) && stdio_pump_io(broker);
    }
    if (pthread_mutex_unlock(&broker->release_mutex)) { broker->unsafe = true; valid = false; }
    if (!valid) { stdio_begin_close(broker); return stdio_throw(broker, broker->unsafe || broker->response_refused); }
    return undefined(env);
}
static napi_value stdio_release_ping(napi_env env, napi_callback_info info) {
    size_t argc = 3; napi_value args[3]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    struct stdio_proof *proof = argc == 2 ? stdio_unwrap_proof(broker, args[1], &STDIO_RECEIPT_TAG) : NULL;
    struct stdio_receipt *receipt = proof ? proof->receipt : NULL;
    if (!receipt || receipt != broker->ping || receipt->kind != STDIO_PING || receipt->ping_released || broker->await_write || broker->command_kind ||
        broker->fence_locked || !stdio_binding_matches(broker, args[0], broker->phase == 3 && !broker->recovery, true) ||
        pthread_mutex_lock(&broker->release_mutex)) return stdio_throw(broker, false);
    receipt->ping_released = true; broker->await_write = true; broker->write_ping = true; broker->command_kind = CLIQ_MCP_STDIO_PING_REPLY;
    bool valid = stdio_pump_io(broker);
    if (pthread_mutex_unlock(&broker->release_mutex)) { broker->unsafe = true; valid = false; }
    if (!valid) { stdio_begin_close(broker); return stdio_throw(broker, broker->unsafe || broker->response_refused); }
    return undefined(env);
}
static napi_value stdio_advance(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    struct stdio_proof *proof = argc == 1 ? stdio_unwrap_proof(broker, args[0], &STDIO_RECEIPT_TAG) : NULL;
    struct stdio_receipt *receipt = proof ? proof->receipt : NULL;
    if (!receipt || receipt != broker->advancing || receipt->kind != STDIO_RESPONSE || receipt->advanced || broker->closing ||
        broker->phase != receipt->phase || broker->phase + 1 >= broker->recipe.header.phase_count || broker->await_write)
        return stdio_throw(broker, false);
    receipt->end = broker->output_size[0]; receipt->advanced = true; broker->capture_start = receipt->response_end;
    broker->advancing = NULL; broker->phase++; broker->completed = broker->phase; broker->stage_requested = broker->stage_released = false;
    return undefined(env);
}
static napi_value stdio_next_message(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct broker *broker = stdio_receiver(env, info, &argc, NULL);
    if (!broker) return NULL;
    if (broker->message_deferred || !broker->bound || !broker->exec_released) return stdio_throw(broker, false);
    napi_value promise;
    if (napi_create_promise(env, &broker->message_deferred, &promise) != napi_ok) return NULL;
    if (!stdio_parse_lines(broker)) stdio_begin_close(broker);
    stdio_deliver(broker); return promise;
}
static napi_value stdio_close(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct broker *broker = stdio_receiver(env, info, &argc, NULL);
    if (!broker) return NULL;
    napi_value promise;
    if (broker->close_promise) { napi_get_reference_value(env, broker->close_promise, &promise); return promise; }
    if (napi_create_promise(env, &broker->close_deferred, &promise) != napi_ok) return NULL;
    if (broker->close_finished) {
        napi_deferred deferred = broker->close_deferred; broker->close_deferred = NULL;
        napi_value joined = broker->unsafe || broker->response_refused ? NULL : stdio_join_value(broker, false);
        if (joined) napi_resolve_deferred(env, deferred, joined);
        else napi_reject_deferred(env, deferred, stdio_error(broker, true));
    } else {
        if (napi_create_reference(env, promise, 1, &broker->close_promise) != napi_ok) return NULL;
        stdio_begin_close(broker);
    }
    return promise;
}
static napi_value stdio_read_unavailable_join(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value args[1];
    struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    if (argc || !stdio_unavailable_joined(broker)) return stdio_throw(broker, true);
    napi_value result = stdio_join_value(broker, true);
    return result ? result : stdio_throw(broker, true);
}
static napi_value stdio_assert_unavailable_join(napi_env env, napi_callback_info info) {
    size_t argc = 3; napi_value args[3];
    struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    if (argc != 2 || !stdio_unavailable_joined(broker) ||
        !stdio_unwrap_proof(broker, args[0], &STDIO_RECOVERY_UNAVAILABLE_JOIN_TAG) ||
        !stdio_binding_matches(broker, args[1], false, false))
        return stdio_throw(broker, true);
    return undefined(env);
}
static napi_value stdio_assert_join(napi_env env, napi_callback_info info) {
    size_t argc = 3; napi_value args[3]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    if (broker->unsafe || broker->response_refused) return stdio_throw(broker, true);
    if (argc != 2 || !broker->close_finished || !broker->retired || !stdio_unwrap_proof(broker, args[0], broker->recovery ? &STDIO_RECOVERY_JOIN_TAG : &STDIO_JOIN_TAG) ||
        !stdio_binding_matches(broker, args[1], false, false)) return stdio_throw(broker, false);
    return undefined(env);
}
static bool stdio_screen_all(struct broker *broker) {
    if (broker->raw_screened) return !broker->raw_refused;
    if (!broker->close_finished || !broker->retired || broker->unsafe || broker->response_refused) return false;
    // Explicit received-data mode is confined to these already captured spans.
    // The main-thread call cannot change live release/header/TLS screening.
    const char *prior = atomic_load(&broker->error); atomic_store(&broker->error, NULL);
    bool valid = mcp_no_echo_all(broker, broker->output[0], broker->output_size[0]) &&
        mcp_no_echo_all(broker, broker->output[1], broker->output_size[1]);
    const char *screen_error = atomic_load(&broker->error); atomic_store(&broker->error, prior);
    if (!valid && (!screen_error || strcmp(screen_error, "broker_response_refused"))) return false;
    broker->raw_screened = true; broker->raw_refused = !valid; return valid;
}
static napi_value stdio_copy_capture(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; bool tagged = false; struct stdio_proof *proof = NULL;
    if (napi_get_cb_info(env, info, &argc, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &STDIO_BYTES_TAG, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&proof) != napi_ok || !proof || !stdio_current(proof->owner, env) ||
        !proof->receipt || !proof->owner->raw_screened || proof->owner->raw_refused || !proof->owner->close_finished) {
        napi_throw_type_error(env, NULL, "Invalid original screened MCP stdio capture"); return NULL;
    }
    struct stdio_receipt *receipt = proof->receipt; napi_value bytes;
    if (napi_create_buffer_copy(env, receipt->end - receipt->start, proof->owner->output[0] + receipt->start, NULL, &bytes) != napi_ok) return NULL;
    return bytes;
}
static napi_value stdio_capture_value(struct broker *broker, struct stdio_receipt *receipt, bool unusable) {
    napi_env env = broker->env; napi_value value, join, bytes;
    if (!receipt->end) receipt->end = broker->output_size[0];
    if (receipt->start > receipt->response_end || receipt->response_end > receipt->end || receipt->end > broker->output_size[0] ||
        receipt->end - receipt->start > broker->recipe.header.maximum_response_bytes ||
        !stdio_hash(broker->output[0] + receipt->start, receipt->end - receipt->start, receipt->capture_digest)) return NULL;
    if (napi_create_object(env, &value) != napi_ok || napi_create_object(env, &join) != napi_ok ||
        !stdio_wrap_proof(broker, value, receipt, unusable ? &STDIO_UNUSABLE_TAG : &STDIO_RAW_TAG) ||
        !stdio_wrap_proof(broker, join, receipt, &STDIO_RESPONSE_JOIN_TAG) || napi_object_freeze(env, join) != napi_ok) return NULL;
    set_string(env, value, "framing", "newline_json_rpc"); set_string(env, value, "termination", "stdio_response_line");
    set_number(env, value, "rawFinitePrefixBytes", (double)(receipt->end - receipt->start));
    set_string(env, value, "rawFinitePrefixDigest", receipt->capture_digest);
    set_number(env, value, "responseLineEndOffset", (double)(receipt->response_end - receipt->start));
    set_number(env, value, "receivedTailBytes", (double)(receipt->end - receipt->response_end)); napi_set_named_property(env, value, "actualResponseJoin", join);
    if (unusable) { set_string(env, value, "kind", "mcp_known_response_unusable"); set_string(env, value, "reason", "full_capture_no_echo_refused"); }
    else {
        const napi_property_descriptor method = {"copy", NULL, stdio_copy_capture, NULL, NULL, NULL, napi_default, NULL};
        if (napi_create_object(env, &bytes) != napi_ok || !stdio_wrap_proof(broker, bytes, receipt, &STDIO_BYTES_TAG) ||
            napi_define_properties(env, bytes, 1, &method) != napi_ok || napi_object_freeze(env, bytes) != napi_ok ||
            napi_set_named_property(env, value, "screenedRawCapture", bytes) != napi_ok) return NULL;
    }
    napi_object_freeze(env, value); return value;
}
static napi_value stdio_finish_response(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    struct stdio_proof *proof = argc == 1 ? stdio_unwrap_proof(broker, args[0], &STDIO_RECEIPT_TAG) : NULL;
    struct stdio_receipt *receipt = proof ? proof->receipt : NULL;
    if (!receipt || receipt->kind != STDIO_RESPONSE || !broker->close_finished || !broker->retired || broker->unsafe || broker->response_refused)
        return stdio_throw(broker, true);
    napi_value promise; napi_deferred deferred;
    if (napi_create_promise(env, &deferred, &promise) != napi_ok) return NULL;
    if (!stdio_screen_all(broker)) {
        receipt->capture_refused = broker->raw_screened && broker->raw_refused;
        napi_reject_deferred(env, deferred, stdio_error(broker, !receipt->capture_refused)); return promise;
    }
    napi_value value = stdio_capture_value(broker, receipt, false);
    if (value) napi_resolve_deferred(env, deferred, value); else napi_reject_deferred(env, deferred, stdio_error(broker, true));
    return promise;
}
static napi_value stdio_read_unusable(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    struct stdio_proof *proof = argc == 1 ? stdio_unwrap_proof(broker, args[0], &STDIO_RECEIPT_TAG) : NULL;
    if (!proof || !proof->receipt || proof->receipt->kind != STDIO_RESPONSE || !proof->receipt->capture_refused ||
        !broker->close_finished || !broker->retired || broker->unsafe || broker->response_refused || !broker->raw_screened || !broker->raw_refused)
        return stdio_throw(broker, true);
    return stdio_capture_value(broker, proof->receipt, true);
}
static napi_value stdio_assert_capture(napi_env env, napi_callback_info info, bool unusable) {
    size_t argc = 3; napi_value args[3]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    struct stdio_proof *receipt = argc == 2 ? stdio_unwrap_proof(broker, args[0], &STDIO_RECEIPT_TAG) : NULL;
    struct stdio_proof *capture = argc == 2 ? stdio_unwrap_proof(broker, args[1], unusable ? &STDIO_UNUSABLE_TAG : &STDIO_RAW_TAG) : NULL;
    if (!receipt || !capture || !receipt->receipt || capture->receipt != receipt->receipt || !broker->close_finished || !broker->retired ||
        broker->unsafe || broker->response_refused || !broker->raw_screened || broker->raw_refused != unusable)
        return stdio_throw(broker, true);
    return undefined(env);
}
static napi_value stdio_assert_raw(napi_env e, napi_callback_info i) { return stdio_assert_capture(e, i, false); }
static napi_value stdio_assert_unusable(napi_env e, napi_callback_info i) { return stdio_assert_capture(e, i, true); }
static napi_value stdio_retain(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct broker *broker = stdio_receiver(env, info, &argc, NULL);
    if (!broker) return NULL;
    if (broker->retained || broker->closing) return stdio_throw(broker, false);
    broker->retained = true; return undefined(env);
}
static napi_value stdio_release_domain_for(napi_env env, napi_callback_info info, bool unavailable) {
    size_t argc = 1; napi_value args[1]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    if (!broker->retained || !broker->close_finished || !broker->retired || broker->unsafe || broker->fence_locked ||
        (unavailable ? argc || !stdio_unavailable_joined(broker) : broker->response_refused))
        return stdio_throw(broker, true);
    broker->retained = false;
    if (broker->cleanup_hook) { napi_remove_async_cleanup_hook(broker->cleanup_hook); broker->cleanup_hook = NULL; }
    if (broker->work_owner) { napi_delete_reference(env, broker->work_owner); broker->work_owner = NULL; }
    return undefined(env);
}
static napi_value stdio_release_domain(napi_env e, napi_callback_info i) { return stdio_release_domain_for(e, i, false); }
static napi_value stdio_release_unavailable_domain(napi_env e, napi_callback_info i) { return stdio_release_domain_for(e, i, true); }
static struct stdio_proof *stdio_fence_receiver(napi_env env, napi_callback_info info, bool *unavailable) {
    size_t argc = 0; napi_value self; bool tagged = false, recovery = false, refused = false; struct stdio_proof *proof = NULL;
    if (napi_get_cb_info(env, info, &argc, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &STDIO_FENCE_TAG, &tagged) != napi_ok ||
        napi_check_object_type_tag(env, self, &STDIO_RECOVERY_FENCE_TAG, &recovery) != napi_ok ||
        napi_check_object_type_tag(env, self, &STDIO_RECOVERY_UNAVAILABLE_FENCE_TAG, &refused) != napi_ok ||
        (!tagged && !recovery && !refused) || napi_unwrap(env, self, (void **)&proof) != napi_ok || !proof ||
        !stdio_current(proof->owner, env) || proof->owner->recovery != (recovery || refused)) {
        napi_throw_type_error(env, NULL, "Invalid original MCP stdio release-domain guard"); return NULL;
    }
    if (unavailable) *unavailable = refused;
    return proof;
}
static napi_value stdio_fence_assert(napi_env env, napi_callback_info info) {
    bool unavailable = false;
    struct stdio_proof *proof = stdio_fence_receiver(env, info, &unavailable); if (!proof) return NULL;
    struct broker *broker = proof->owner;
    if (!proof->fence_active || !broker->fence_locked || !broker->retained || !broker->close_finished || !broker->retired ||
        !(broker->recovery ? broker->bound && broker->peer && atomic_load(&broker->peer->revoked) : broker->call_bound) || broker->unsafe ||
        (unavailable ? !stdio_unavailable_joined(broker) : broker->response_refused)) return stdio_throw(broker, true);
    return undefined(env);
}
static napi_value stdio_fence_close(napi_env env, napi_callback_info info) {
    struct stdio_proof *proof = stdio_fence_receiver(env, info, NULL); if (!proof) return NULL;
    if (!proof->fence_active) return undefined(env);
    struct broker *broker = proof->owner;
    if (!broker->fence_locked || pthread_mutex_unlock(&broker->release_mutex)) { broker->unsafe = true; return stdio_throw(broker, true); }
    proof->fence_active = false; broker->fence_locked = false; return undefined(env);
}
static napi_value stdio_acquire_fence_for(napi_env env, napi_callback_info info, bool unavailable) {
    size_t argc = 2; napi_value args[2]; struct broker *broker = stdio_receiver(env, info, &argc, args);
    if (!broker) return NULL;
    if (argc != 1 || broker->admin || !broker->retained || !broker->close_finished || !broker->retired ||
        broker->unsafe || broker->fence_locked || (unavailable ? !stdio_unavailable_joined(broker) : broker->response_refused) ||
        !stdio_binding_matches(broker, args[0], !broker->recovery, false) ||
        (broker->recovery && (!broker->peer || !atomic_load(&broker->peer->revoked))) ||
        pthread_mutex_lock(&broker->release_mutex)) return stdio_throw(broker, true);
    napi_value value; struct stdio_proof *proof = NULL;
    const napi_property_descriptor methods[] = {{"assertHeld", NULL, stdio_fence_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, stdio_fence_close, NULL, NULL, NULL, napi_default, NULL}};
    const napi_type_tag *tag = unavailable ? &STDIO_RECOVERY_UNAVAILABLE_FENCE_TAG : broker->recovery ? &STDIO_RECOVERY_FENCE_TAG : &STDIO_FENCE_TAG;
    if (napi_create_object(env, &value) != napi_ok || !stdio_wrap_proof(broker, value, NULL, tag) ||
        napi_unwrap(env, value, (void **)&proof) != napi_ok || !proof || napi_define_properties(env, value, 2, methods) != napi_ok) {
        pthread_mutex_unlock(&broker->release_mutex); return stdio_throw(broker, true);
    }
    proof->fence_active = true; broker->fence_locked = true; napi_object_freeze(env, value); return value;
}
static napi_value stdio_acquire_fence(napi_env e, napi_callback_info i) { return stdio_acquire_fence_for(e, i, false); }
static napi_value stdio_acquire_unavailable_fence(napi_env e, napi_callback_info i) { return stdio_acquire_fence_for(e, i, true); }
static void stdio_abandon_preparation(struct broker *broker) {
    broker->closing = broker->retired = broker->close_finished = broker->timer_closed = true;
    if (broker->recipe.fd >= 0) { int fd = broker->recipe.fd; broker->recipe.fd = -1; if (close(fd)) atomic_store(&retirement_failed, true); }
    if (broker->cleanup_hook) { napi_remove_async_cleanup_hook(broker->cleanup_hook); broker->cleanup_hook = NULL; }
    callbacks_retire(&broker->callbacks);
    if (broker->work_owner) { napi_delete_reference(broker->env, broker->work_owner); broker->work_owner = NULL; }
    if (!broker->references) stdio_free(broker);
}
static napi_value stdio_prepare(napi_env env, napi_callback_info info, unsigned purpose) {
    bool admin = purpose == CLIQ_MCP_STDIO_ADMIN, recovery = purpose == CLIQ_MCP_STDIO_RECOVERY;
    size_t argc = 3; napi_value args[3]; const unsigned char *bytes = NULL; size_t size = 0; double remaining;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 2 || syscall(SYS_gettid) != getpid() ||
        atomic_load(&retirement_failed) || !stdio_buffer(env, args[0], &bytes, &size) || size < sizeof(struct cliq_mcp_stdio_recipe_header) ||
        size > CLIQ_MCP_STDIO_MAX_RECIPE || napi_get_value_double(env, args[1], &remaining) != napi_ok ||
        !isfinite(remaining) || remaining < 1 || remaining > INT_MAX || trunc(remaining) != remaining) {
        napi_throw_type_error(env, NULL, "Invalid fixed MCP stdio preparation bytes"); return NULL;
    }
    struct broker *broker = calloc(1, sizeof(*broker));
    if (!broker) { napi_throw_error(env, NULL, "MCP stdio owner allocation unavailable"); return NULL; }
    broker->env = env; broker->creator_pid = getpid(); broker->admin = admin; broker->recovery = recovery; broker->recipe.fd = -1;
    broker->recipe.abi_version = CLIQ_MCP_STDIO_OWNER_ABI; broker->recipe.purpose = purpose;
    broker->recipe.creator_pid = getpid(); broker->recipe.environment = env; broker->recipe.owner = broker;
    broker->recipe.register_peer = stdio_register_peer; broker->recipe.owner_value = stdio_recipe_owner;
    broker->recipe.size = size; broker->recipe.bytes = malloc(size);
    if (broker->recipe.bytes) memcpy(broker->recipe.bytes, bytes, size);
    atomic_init(&broker->error, NULL); broker->deadline_ms = stdio_clock_ms(CLOCK_MONOTONIC) + (uint64_t)remaining;
    bool valid = broker->recipe.bytes && cliq_mcp_stdio_recipe_valid(broker->recipe.bytes, size, &broker->recipe.header) &&
        broker->recipe.header.purpose == broker->recipe.purpose && stdio_hash(broker->recipe.bytes, size, broker->recipe.digest);
    for (unsigned phase = 0; valid && phase < broker->recipe.header.phase_count; phase++) {
        broker->frames[phase].body = broker->recipe.bytes + broker->recipe.header.frames[phase].offset;
        broker->frames[phase].size = (size_t)broker->recipe.header.frames[phase].bytes;
        memcpy(broker->frames[phase].digest, broker->recipe.header.frames[phase].digest, 65);
        valid = mcp_frame_valid(&broker->frames[phase], phase) &&
            broker_no_echo(broker, broker->frames[phase].body, broker->frames[phase].size);
    }
    unsigned char token[32];
    valid = valid && RAND_bytes(token, sizeof(token)) == 1 && stdio_hash(token, sizeof(token), broker->token_digest);
    wipe(token, sizeof(token));
    if (valid) { valid = !pthread_mutex_init(&broker->release_mutex, NULL); broker->mutex_ready = valid; }
    if (valid) {
        broker->output[0] = malloc((size_t)broker->recipe.header.maximum_output_bytes);
        broker->output[1] = malloc((size_t)broker->recipe.header.maximum_output_bytes);
        broker->recipe.fd = memfd_create("cliq-mcp-stdio-recipe", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        valid = broker->output[0] && broker->output[1] && broker->recipe.fd >= 0;
    }
    for (size_t at = 0; valid && at < size;) {
        ssize_t n = write(broker->recipe.fd, broker->recipe.bytes + at, size - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) valid = false; else at += (size_t)n;
    }
    valid = valid && !fchmod(broker->recipe.fd, 0400) &&
        !fcntl(broker->recipe.fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    if (!valid) {
        stdio_abandon_preparation(broker); napi_throw_type_error(env, NULL, "MCP stdio fixed preparation recipe refused"); return NULL;
    }
    napi_value owner, recipe, ready; napi_deferred deferred;
    const napi_property_descriptor methods[] = {
        {"attachProtocolPeer", NULL, stdio_attach, NULL, NULL, NULL, napi_default, NULL},
        {recovery ? "bindProbe" : "bindLaunch", NULL, stdio_bind_launch, NULL, NULL, NULL, napi_default, NULL},
        {recovery ? "assertProbeBinding" : "assertLaunchBinding", NULL, stdio_assert_launch, NULL, NULL, NULL, napi_default, NULL},
        {"releaseExec", NULL, stdio_release_exec, NULL, NULL, NULL, napi_default, NULL},
        {"nextMessage", NULL, stdio_next_message, NULL, NULL, NULL, napi_default, NULL},
        {"releaseStage", NULL, stdio_release_stage, NULL, NULL, NULL, napi_default, NULL},
        {"releasePing", NULL, stdio_release_ping, NULL, NULL, NULL, napi_default, NULL},
        {"advanceResponse", NULL, stdio_advance, NULL, NULL, NULL, napi_default, NULL},
        {"finishResponse", NULL, stdio_finish_response, NULL, NULL, NULL, napi_default, NULL},
        {"readUnusableResponse", NULL, stdio_read_unusable, NULL, NULL, NULL, napi_default, NULL},
        {"assertRawResponse", NULL, stdio_assert_raw, NULL, NULL, NULL, napi_default, NULL},
        {"assertUnusableResponse", NULL, stdio_assert_unusable, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, stdio_close, NULL, NULL, NULL, napi_default, NULL},
        {"assertJoined", NULL, stdio_assert_join, NULL, NULL, NULL, napi_default, NULL},
        {"retainDomain", NULL, stdio_retain, NULL, NULL, NULL, napi_default, NULL},
        {"releaseDomain", NULL, stdio_release_domain, NULL, NULL, NULL, napi_default, NULL}
    };
    const napi_property_descriptor run_methods[] = {
        {"bindCall", NULL, stdio_bind_call, NULL, NULL, NULL, napi_default, NULL},
        {"assertCallBinding", NULL, stdio_assert_call, NULL, NULL, NULL, napi_default, NULL},
        {"acquireEffectFence", NULL, stdio_acquire_fence, NULL, NULL, NULL, napi_default, NULL}
    };
    const napi_property_descriptor copy = {"copyData", NULL, stdio_recipe_copy, NULL, NULL, NULL, napi_default, NULL};
    valid = napi_create_object(env, &owner) == napi_ok && napi_create_object(env, &recipe) == napi_ok &&
        napi_type_tag_object(env, owner, admin ? &STDIO_ADMIN_OWNER_TAG : recovery ? &STDIO_RECOVERY_OWNER_TAG : &STDIO_RUN_OWNER_TAG) == napi_ok &&
        napi_type_tag_object(env, recipe, admin ? &CLIQ_MCP_STDIO_ADMIN_RECIPE_TAG : recovery ? &CLIQ_MCP_STDIO_RECOVERY_RECIPE_TAG : &CLIQ_MCP_STDIO_RUN_RECIPE_TAG) == napi_ok &&
        napi_define_properties(env, owner, sizeof(methods) / sizeof(methods[0]), methods) == napi_ok &&
        napi_define_properties(env, recipe, 1, &copy) == napi_ok;
    if (valid && !admin) {
        const napi_property_descriptor probe_methods[] = {
            {"acquireProbeFence", NULL, stdio_acquire_fence, NULL, NULL, NULL, napi_default, NULL},
            {"readUnavailableJoined", NULL, stdio_read_unavailable_join, NULL, NULL, NULL, napi_default, NULL},
            {"assertUnavailableJoined", NULL, stdio_assert_unavailable_join, NULL, NULL, NULL, napi_default, NULL},
            {"acquireUnavailableProbeFence", NULL, stdio_acquire_unavailable_fence, NULL, NULL, NULL, napi_default, NULL},
            {"releaseUnavailableDomain", NULL, stdio_release_unavailable_domain, NULL, NULL, NULL, napi_default, NULL}
        };
        valid = recovery ? napi_define_properties(env, owner, sizeof(probe_methods) / sizeof(probe_methods[0]), probe_methods) == napi_ok :
            napi_define_properties(env, owner, sizeof(run_methods) / sizeof(run_methods[0]), run_methods) == napi_ok;
        set_string(env, owner, "releaseFenceTokenDigest", broker->token_digest);
    }
    if (valid) {
        valid = napi_wrap(env, owner, broker, stdio_owner_finalize, NULL, NULL) == napi_ok;
        if (valid) broker->references++;
    }
    if (valid) {
        valid = napi_wrap(env, recipe, &broker->recipe, stdio_recipe_finalize, NULL, NULL) == napi_ok;
        if (valid) broker->references++;
    }
    valid = valid && napi_create_reference(env, owner, 0, &broker->handle) == napi_ok &&
        napi_create_reference(env, owner, 1, &broker->work_owner) == napi_ok &&
        napi_object_freeze(env, recipe) == napi_ok && napi_set_named_property(env, owner, "recipe", recipe) == napi_ok &&
        napi_create_promise(env, &deferred, &ready) == napi_ok && napi_set_named_property(env, owner, "ready", ready) == napi_ok &&
        callbacks_init(&broker->callbacks, env, "cliq MCP stdio owner callbacks") &&
        napi_add_async_cleanup_hook(env, stdio_cleanup, broker, &broker->cleanup_hook) == napi_ok;
    if (!valid) {
        stdio_abandon_preparation(broker); napi_throw_error(env, NULL, "MCP stdio original owning receiver unavailable"); return NULL;
    }
    napi_resolve_deferred(env, deferred, undefined(env));
    uv_loop_t *loop = NULL;
    if (napi_get_uv_event_loop(env, &loop) != napi_ok || uv_timer_init(loop, &broker->timer)) {
        stdio_abandon_preparation(broker); napi_throw_error(env, NULL, "MCP stdio callback owner unavailable"); return NULL;
    }
    broker->timer_ready = true; broker->timer.data = broker; uv_update_time(loop);
    if (uv_timer_start(&broker->timer, stdio_tick, 1, 2)) {
        broker->unsafe = true; broker->closing = broker->retired = broker->timer_closing = true;
        uv_close((uv_handle_t *)&broker->timer, stdio_close_timer);
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "MCP stdio callback start did not complete"); return NULL;
    }
    napi_object_freeze(env, owner); return owner;
}
static napi_value prepare_admin_stdio(napi_env env, napi_callback_info info) { return stdio_prepare(env, info, CLIQ_MCP_STDIO_ADMIN); }
static napi_value prepare_run_stdio(napi_env env, napi_callback_info info) { return stdio_prepare(env, info, CLIQ_MCP_STDIO_RUN); }
static napi_value prepare_recovery_stdio(napi_env env, napi_callback_info info) { return stdio_prepare(env, info, CLIQ_MCP_STDIO_RECOVERY); }
#if defined(CLIQ_MCP_STDIO_DATA_FIXTURE)
#include "mcp-admin-original-retirement.h"
static bool stdio_fixture_admin_closed(unsigned char **bytes, size_t *size) {
    struct cliq_mcp_admin_birth birth = {0};
    birth.magic = CLIQ_MCP_ADMIN_BIRTH_MAGIC; birth.version = 1; birth.supervisor_pid = 123; birth.attempt = 1;
    memcpy(birth.supervisor_start_token, "linux-proc-start-ticks:1", 24);
    memcpy(birth.operation, "fixture-admin", 14); memcpy(birth.principal, "fixture-principal", 18);
    char *digests[] = {birth.nonce, birth.target_ref, birth.target_digest, birth.core_ref, birth.core_digest,
        birth.plan_ref, birth.plan_digest, birth.spec_ref, birth.spec_digest};
    for (size_t i = 0; i < sizeof(digests) / sizeof(digests[0]); i++) memset(digests[i], 'a', 64);
    cliq_mcp_admin_hash(&birth, offsetof(struct cliq_mcp_admin_birth, digest), birth.digest);
    *size = sizeof(birth) + 9 * sizeof(struct cliq_mcp_admin_progress); *bytes = calloc(1, *size);
    if (!*bytes) return false;
    memcpy(*bytes, &birth, sizeof(birth)); unsigned char previous[32]; memcpy(previous, birth.digest, 32);
    for (unsigned i = 0; i < 9; i++) {
        struct cliq_mcp_admin_progress frame = {0}; frame.magic = CLIQ_MCP_ADMIN_PROGRESS_MAGIC; frame.version = 1; frame.kind = frame.ordinal = i + 1;
        frame.controller_pid = 456; memcpy(frame.controller_start_token, "linux-proc-start-ticks:2", 24); memcpy(frame.controller_leaf_name, "fixture-controller", 19);
        frame.controller_root.device = frame.controller_parent.device = frame.controller_leaf.device = 1;
        frame.controller_root.inode = 100; frame.controller_parent.inode = 101; frame.controller_leaf.inode = 102;
        frame.controller_root.mode = frame.controller_parent.mode = frame.controller_leaf.mode = S_IFDIR | 0700;
        struct cliq_worker_packet *packet = &frame.packet;
        packet->magic = CLIQ_WORKER_MAGIC; packet->version = CLIQ_WORKER_VERSION; packet->command = CLIQ_MCP_ADMIN_RESERVE;
        packet->admin_attempt = 1; packet->cgroup_device = 1; packet->cgroup_inode = 103; packet->observed_at_ms = 1000 + i;
        memcpy(packet->admin_operation_id, birth.operation, sizeof(birth.operation)); memcpy(packet->admin_principal_id, birth.principal, sizeof(birth.principal));
        memcpy(packet->cgroup_name, "cliq-mcp-admin-fixture", 23);
#define STDIO_FIXTURE_DIGEST(field, value) memcpy(packet->field, birth.value, 65)
        STDIO_FIXTURE_DIGEST(nonce, nonce); STDIO_FIXTURE_DIGEST(admin_target_ref, target_ref); STDIO_FIXTURE_DIGEST(admin_target_digest, target_digest);
        STDIO_FIXTURE_DIGEST(admin_core_ref, core_ref); STDIO_FIXTURE_DIGEST(admin_core_digest, core_digest); STDIO_FIXTURE_DIGEST(plan_ref, plan_ref);
        STDIO_FIXTURE_DIGEST(admin_plan_digest, plan_digest); STDIO_FIXTURE_DIGEST(sandbox_launch_ref, spec_ref); STDIO_FIXTURE_DIGEST(sandbox_launch_digest, spec_digest);
#undef STDIO_FIXTURE_DIGEST
        if (i >= 4) {
            packet->pid = 789; packet->namespace_init_pid = 790; packet->pid_namespace_inode = 104;
            memcpy(packet->start_token, "linux-proc-start-ticks:3", 24); memcpy(packet->init_native_start_token, "linux-proc-start-ticks:4", 24);
        }
        packet->admin_protocol_complete = i >= 6 ? 1 : 0; packet->init_reaped = i >= 7 ? 1 : 0;
        memcpy(frame.previous, previous, 32); cliq_mcp_admin_hash(&frame, offsetof(struct cliq_mcp_admin_progress, digest), frame.digest);
        memcpy(previous, frame.digest, 32); memcpy(*bytes + sizeof(birth) + i * sizeof(frame), &frame, sizeof(frame));
    }
    return true;
}
static bool stdio_fixture_recipe(unsigned purpose, unsigned char **bytes, size_t *size) {
    const char *frames[] = {
        "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{\"capabilities\":{},\"clientInfo\":{\"name\":\"@cogineai/cliq\",\"version\":\"fixture\"},\"protocolVersion\":\"2025-11-25\"}}",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}",
        "{\"id\":2,\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}",
        "{\"id\":3,\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"arguments\":{},\"name\":\"fixture\"}}"
    };
    struct cliq_mcp_stdio_recipe_header header = {0};
    header.magic = CLIQ_MCP_STDIO_RECIPE_MAGIC; header.version = 1; header.purpose = purpose;
    header.phase_count = purpose == CLIQ_MCP_STDIO_ADMIN ? 3 : 4; header.maximum_response_bytes = 65536;
    header.maximum_output_bytes = 65536; header.server_bytes = 256;
    memset(header.server_digest, 'a', 64);
    size_t at = sizeof(header);
    for (unsigned i = 0; i < header.phase_count; i++) {
        header.frames[i].offset = at; header.frames[i].bytes = strlen(frames[i]);
        if (!stdio_hash((const unsigned char *)frames[i], strlen(frames[i]), header.frames[i].digest)) return false;
        at += strlen(frames[i]);
    }
    *bytes = calloc(1, at); if (!*bytes) return false; *size = at; memcpy(*bytes, &header, sizeof(header));
    for (unsigned i = 0; i < header.phase_count; i++) memcpy(*bytes + header.frames[i].offset, frames[i], strlen(frames[i]));
    return true;
}
static napi_value run_mcp_stdio_data_fixture(napi_env env, napi_callback_info info) {
    (void)info; unsigned checks = 0; unsigned char *recipe = NULL, *capture_out = NULL, *capture_err = NULL, *chunk = NULL, *original = NULL; size_t recipe_size = 0, original_size = 0;
#define STDIO_FIXTURE_ASSERT(condition) do { if (!(condition)) { free(recipe); free(capture_out); free(capture_err); free(chunk); free(original); napi_throw_error(env, NULL, "MCP stdio pure data fixture failed"); return NULL; } checks++; } while (0)
    struct cliq_mcp_stdio_recipe_header header;
    STDIO_FIXTURE_ASSERT(stdio_fixture_recipe(CLIQ_MCP_STDIO_ADMIN, &recipe, &recipe_size));
    STDIO_FIXTURE_ASSERT(cliq_mcp_stdio_recipe_valid(recipe, recipe_size, &header) && header.phase_count == 3);
    STDIO_FIXTURE_ASSERT(!cliq_mcp_stdio_recipe_valid(recipe, recipe_size - 1, &header));
    recipe[113] = 1; STDIO_FIXTURE_ASSERT(!cliq_mcp_stdio_recipe_valid(recipe, recipe_size, &header)); recipe[113] = 0;
    STDIO_FIXTURE_ASSERT(cliq_mcp_stdio_recipe_valid(recipe, recipe_size, &header));
    for (unsigned i = 0; i < header.phase_count; i++) {
        struct mcp_frame frame = {.body = recipe + header.frames[i].offset, .size = (size_t)header.frames[i].bytes};
        bool valid = mcp_frame_valid(&frame, i); free(frame.id); STDIO_FIXTURE_ASSERT(valid);
    }
    free(recipe); recipe = NULL;
    STDIO_FIXTURE_ASSERT(stdio_fixture_recipe(CLIQ_MCP_STDIO_RUN, &recipe, &recipe_size));
    STDIO_FIXTURE_ASSERT(cliq_mcp_stdio_recipe_valid(recipe, recipe_size, &header) && header.phase_count == 4);
    struct mcp_json json;
    const unsigned char duplicate[] = "{\"jsonrpc\":\"2.0\",\"id\":3,\"id\":3,\"result\":{}}";
    STDIO_FIXTURE_ASSERT(!mcp_json_parse(duplicate, sizeof(duplicate) - 1, &json));
    struct broker data = {0}; atomic_init(&data.error, NULL); data.deadline_ms = UINT64_MAX;
    data.recipe.header = header; data.phase = 3; data.stage_released = true;
    data.frames[3].body = recipe + header.frames[3].offset; data.frames[3].size = (size_t)header.frames[3].bytes;
    STDIO_FIXTURE_ASSERT(mcp_frame_valid(&data.frames[3], 3));
    const unsigned char safe[] = "{\"id\":3,\"jsonrpc\":\"2.0\",\"result\":{}}";
    struct stdio_receipt *received = stdio_decode(&data, safe, sizeof(safe) - 1, sizeof(safe));
    STDIO_FIXTURE_ASSERT(received && received->kind == STDIO_RESPONSE && received->phase == 3);
    const unsigned char wrong[] = "{\"id\":2,\"jsonrpc\":\"2.0\",\"result\":{}}";
    STDIO_FIXTURE_ASSERT(!stdio_decode(&data, wrong, sizeof(wrong) - 1, sizeof(wrong)));
    data.response_refused = false; atomic_store(&data.error, NULL);
    const unsigned char secret[] = "fixture-private-key";
    data.platform.secret = (unsigned char *)secret; data.platform.secret_size = sizeof(secret) - 1;
    data.closing = true; data.deadline_ms = 0;
    STDIO_FIXTURE_ASSERT(mcp_no_echo_all(&data, safe, sizeof(safe) - 1));
    STDIO_FIXTURE_ASSERT(!broker_no_echo(&data, safe, sizeof(safe) - 1));
    atomic_store(&data.error, NULL);
    const unsigned char tail[] = "{\"id\":3,\"jsonrpc\":\"2.0\",\"result\":{}}\nfixture-private-key";
    STDIO_FIXTURE_ASSERT(!mcp_no_echo_all(&data, tail, sizeof(tail) - 1));
    const unsigned char escaped[] = "\"fixture-\\u0070rivate-key\"";
    atomic_store(&data.error, NULL); STDIO_FIXTURE_ASSERT(!mcp_no_echo_all(&data, escaped, sizeof(escaped) - 1));
    atomic_store(&data.error, NULL);
    data.output[0] = (unsigned char *)safe; data.output_size[0] = sizeof(safe) - 1; data.advancing = NULL; data.pending = NULL; data.parse_at = 0;
    STDIO_FIXTURE_ASSERT(stdio_parse_lines(&data) && !data.pending && !data.parse_at);
    // The original complete-output ceiling is independent of one framed
    // JSON response. These are inert packet bytes, never a scope/join proof.
    struct broker capture = {0}; atomic_init(&capture.error, NULL);
    capture.recipe.header = header; capture.recipe.header.maximum_output_bytes = 131072;
    capture.output[0] = capture_out = malloc(131072); capture.output[1] = capture_err = malloc(131072); chunk = malloc(65537);
    STDIO_FIXTURE_ASSERT(capture_out && capture_err && chunk);
    memset(chunk, 'x', 65537);
    STDIO_FIXTURE_ASSERT(stdio_receive_packet(&capture, CLIQ_MCP_STDIO_STDERR, chunk, 65536));
    capture.ack_stream = 0;
    STDIO_FIXTURE_ASSERT(stdio_receive_packet(&capture, CLIQ_MCP_STDIO_STDERR, chunk, 65536) && capture.output_size[1] == 131072);
    capture.ack_stream = 0;
    STDIO_FIXTURE_ASSERT(!stdio_receive_packet(&capture, CLIQ_MCP_STDIO_STDOUT, chunk, 1) && !capture.output_size[0]);
    capture.output_size[1] = 0; capture.phase = 3; capture.stage_released = true; capture.frames[3] = data.frames[3];
    memset(chunk, ' ', 65537); memcpy(chunk, safe, sizeof(safe) - 1);
    STDIO_FIXTURE_ASSERT(mcp_json_parse(chunk, 65537, &json)); free(json.nodes);
    STDIO_FIXTURE_ASSERT(!stdio_decode(&capture, chunk, 65537, 65538) && capture.response_refused);
    capture.response_refused = false; memset(capture_out, ' ', 65537); capture.output_size[0] = 65537;
    STDIO_FIXTURE_ASSERT(!stdio_parse_lines(&capture) && capture.response_refused);
    capture.response_refused = false; capture.output_eof[0] = capture.output_eof[1] = true;
    unsigned char client_joined[4] = {0};
    STDIO_FIXTURE_ASSERT(stdio_receive_packet(&capture, CLIQ_MCP_STDIO_CLIENT_JOINED, client_joined, sizeof(client_joined)) &&
        capture.client_joined && capture.closing && !capture.retired);
    capture.client_joined = capture.closing = false; capture.protocol_complete = true;
    STDIO_FIXTURE_ASSERT(stdio_receive_packet(&capture, CLIQ_MCP_STDIO_CLIENT_JOINED, client_joined, sizeof(client_joined)) && capture.protocol_complete);
    capture.client_joined = capture.closing = capture.protocol_complete = false; stdio_put32(client_joined, 1);
    STDIO_FIXTURE_ASSERT(!stdio_receive_packet(&capture, CLIQ_MCP_STDIO_CLIENT_JOINED, client_joined, sizeof(client_joined)) && !capture.client_joined);
    stdio_put32(client_joined, 0); capture.protocol_complete = true;
    STDIO_FIXTURE_ASSERT(stdio_enqueue(&capture, CLIQ_MCP_STDIO_CHUNK_ACK, client_joined, sizeof(client_joined)) &&
        !stdio_receive_packet(&capture, CLIQ_MCP_STDIO_CLIENT_JOINED, client_joined, sizeof(client_joined)) && !capture.client_joined);
    wipe(capture.tx, capture.tx_size); free(capture.tx); capture.tx = NULL; capture.tx_at = capture.tx_size = 0;
    STDIO_FIXTURE_ASSERT(stdio_enqueue(&capture, CLIQ_MCP_STDIO_PROTOCOL_DONE, NULL, 0) &&
        stdio_receive_packet(&capture, CLIQ_MCP_STDIO_CLIENT_JOINED, client_joined, sizeof(client_joined)) &&
        capture.client_joined && !capture.tx && !capture.retired && !capture.completed);
    // Inert decision data only: a local cleanup bit can close the failed timer,
    // but never changes the independent complete-capture retirement fact.
    struct cliq_mcp_stdio_peer cleanup_data = {0}; atomic_init(&cleanup_data.operation_closed, false); atomic_init(&cleanup_data.io_joined, false);
    capture.peer = &cleanup_data; capture.io_aborted = true;
    STDIO_FIXTURE_ASSERT(!stdio_close_ready(&capture) && !capture.retired);
    atomic_store(&cleanup_data.operation_closed, true);
    STDIO_FIXTURE_ASSERT(stdio_close_ready(&capture) && !capture.retired && !atomic_load(&cleanup_data.io_joined));
    // Synthetic immutable bytes exercise only the cross-source decoder. They
    // never enter a native factory, StateOwner, filesystem or proof registry.
    struct cliq_mcp_admin_original_retirement current = {0}, checked;
    struct cliq_mcp_admin_original_source source;
    STDIO_FIXTURE_ASSERT(stdio_fixture_admin_closed(&original, &original_size) &&
        cliq_mcp_admin_original_source(original, original_size, CLIQ_MCP_ADMIN_ORIGINAL_HTTP, &source));
    current.magic = CLIQ_MCP_ADMIN_ORIGINAL_RETIREMENT_MAGIC; current.version = 1; current.transport = CLIQ_MCP_ADMIN_ORIGINAL_HTTP;
    current.original_bytes = original_size; current.observer_epoch = 1; current.observed_at_ms = 2000; current.observer_pid = source.binding.supervisor_pid;
    memcpy(current.observer_supervisor, "fixture-supervisor", 19); memcpy(current.observer_token, source.binding.supervisor_start_token, sizeof(current.observer_token));
    current.controller_root = source.root; cliq_mcp_admin_hash(original, original_size, current.original_digest);
#define STDIO_FIXTURE_CURRENT_HASH() cliq_mcp_admin_hash(&current, offsetof(struct cliq_mcp_admin_original_retirement, digest), current.digest)
    STDIO_FIXTURE_CURRENT_HASH();
    STDIO_FIXTURE_ASSERT(cliq_mcp_admin_original_retirement_bytes((unsigned char *)&current, sizeof(current), original, original_size, &checked, &source));
    STDIO_FIXTURE_ASSERT(!cliq_mcp_admin_original_retirement_bytes((unsigned char *)&current, sizeof(current) - 1, original, original_size, &checked, &source));
    current.observed_at_ms = 999; STDIO_FIXTURE_CURRENT_HASH();
    STDIO_FIXTURE_ASSERT(!cliq_mcp_admin_original_retirement_bytes((unsigned char *)&current, sizeof(current), original, original_size, &checked, &source));
    current.observed_at_ms = 2000; current.observer_pid++; STDIO_FIXTURE_CURRENT_HASH();
    STDIO_FIXTURE_ASSERT(!cliq_mcp_admin_original_retirement_bytes((unsigned char *)&current, sizeof(current), original, original_size, &checked, &source));
    current.observer_pid--; current.controller_root.inode++; STDIO_FIXTURE_CURRENT_HASH();
    STDIO_FIXTURE_ASSERT(!cliq_mcp_admin_original_retirement_bytes((unsigned char *)&current, sizeof(current), original, original_size, &checked, &source));
    current.controller_root.inode--; current.observer_supervisor[100] = 'x'; STDIO_FIXTURE_CURRENT_HASH();
    STDIO_FIXTURE_ASSERT(!cliq_mcp_admin_original_retirement_bytes((unsigned char *)&current, sizeof(current), original, original_size, &checked, &source));
    current.observer_supervisor[100] = 0; STDIO_FIXTURE_CURRENT_HASH(); original[original_size - 1] ^= 1;
    cliq_mcp_admin_hash(original, original_size, current.original_digest); STDIO_FIXTURE_CURRENT_HASH();
    STDIO_FIXTURE_ASSERT(!cliq_mcp_admin_original_retirement_bytes((unsigned char *)&current, sizeof(current), original, original_size, &checked, &source));
#undef STDIO_FIXTURE_CURRENT_HASH
    free(original); original = NULL;
    free(capture_out); capture_out = NULL; free(capture_err); capture_err = NULL; free(chunk); chunk = NULL;
    data.platform.secret = NULL; data.platform.secret_size = 0;
    free(data.frames[3].id);
    while (data.receipts) {
        struct stdio_receipt *next = data.receipts->next; free(data.receipts->message); free(data.receipts->ping_id); free(data.receipts); data.receipts = next;
    }
    free(recipe); recipe = NULL;
#undef STDIO_FIXTURE_ASSERT
    napi_value value; napi_create_object(env, &value); set_number(env, value, "checks", checks);
    set_boolean(env, value, "factoryExecuted", false); set_boolean(env, value, "authorityExecuted", false);
    napi_object_freeze(env, value); return value;
}
static napi_value run_mcp_stdio_recovery_data_fixture(napi_env env, napi_callback_info info) {
    (void)info; unsigned checks = 0; unsigned char *recipe = NULL; size_t size = 0;
#define RECOVERY_DATA_ASSERT(condition) do { if (!(condition)) { free(recipe); napi_throw_error(env, NULL, "MCP recovery pure data fixture failed"); return NULL; } checks++; } while (0)
    struct cliq_mcp_stdio_recipe_header header;
    RECOVERY_DATA_ASSERT(stdio_fixture_recipe(CLIQ_MCP_STDIO_RECOVERY, &recipe, &size));
    RECOVERY_DATA_ASSERT(cliq_mcp_stdio_recipe_valid(recipe, size, &header) && header.purpose == CLIQ_MCP_STDIO_RECOVERY && header.phase_count == 4);
    ((struct cliq_mcp_stdio_recipe_header *)recipe)->purpose = 4;
    RECOVERY_DATA_ASSERT(!cliq_mcp_stdio_recipe_valid(recipe, size, &header));
    ((struct cliq_mcp_stdio_recipe_header *)recipe)->purpose = CLIQ_MCP_STDIO_RECOVERY;
    RECOVERY_DATA_ASSERT(cliq_mcp_stdio_recipe_valid(recipe, size, &header));
    struct cliq_mcp_stdio_recovery_birth birth = {0};
    birth.magic = CLIQ_MCP_STDIO_RECOVERY_BIRTH_MAGIC; birth.version = 1; birth.supervisor_pid = 123;
    strcpy(birth.supervisor_start_token, "linux-proc-start-ticks:123");
#define RECOVERY_FIX_TEXT(field, capacity) strcpy(birth.identity.field, "x");
    CLIQ_MCP_STDIO_RECOVERY_TEXT_FIELDS(RECOVERY_FIX_TEXT)
#undef RECOVERY_FIX_TEXT
#define RECOVERY_FIX_DIGEST(field, capacity) memset(birth.identity.field, 'a', 64);
    CLIQ_MCP_STDIO_RECOVERY_DIGEST_FIELDS(RECOVERY_FIX_DIGEST)
#undef RECOVERY_FIX_DIGEST
#define RECOVERY_FIX_NUMBER(field, minimum) birth.identity.field = minimum;
    CLIQ_MCP_STDIO_RECOVERY_NUMBER_FIELDS(RECOVERY_FIX_NUMBER)
#undef RECOVERY_FIX_NUMBER
    strcpy(birth.identity.probeKind, "automatic"); strcpy(birth.identity.effectServerToolName, "effect");
    strcpy(birth.identity.statusOperationName, "fixture"); memset(birth.identity.waitingSubjectRef, 'b', 64);
    birth.identity.probeStartedAtMs = 1000; birth.identity.probeDeadlineAtMs = 31000;
    RECOVERY_DATA_ASSERT(cliq_mcp_stdio_recovery_identity_valid(&birth.identity));
    birth.identity.probeDeadlineAtMs++;
    RECOVERY_DATA_ASSERT(!cliq_mcp_stdio_recovery_identity_valid(&birth.identity)); birth.identity.probeDeadlineAtMs--;
    strcpy(birth.identity.statusOperationName, "effect");
    RECOVERY_DATA_ASSERT(!cliq_mcp_stdio_recovery_identity_valid(&birth.identity)); strcpy(birth.identity.statusOperationName, "fixture");
    birth.identity.originalDispatchJournalSeq = 0;
    RECOVERY_DATA_ASSERT(!cliq_mcp_stdio_recovery_identity_valid(&birth.identity)); birth.identity.originalDispatchJournalSeq = 1;
    cliq_mcp_admin_hash(&birth, offsetof(struct cliq_mcp_stdio_recovery_birth, digest), birth.digest);
    struct cliq_mcp_stdio_history history;
    RECOVERY_DATA_ASSERT(cliq_mcp_stdio_history_bytes((const unsigned char *)&birth, sizeof(birth), &history) &&
        history.purpose == CLIQ_MCP_STDIO_RECOVERY && !history.count);
    RECOVERY_DATA_ASSERT(!cliq_mcp_stdio_history_bytes((const unsigned char *)&birth, sizeof(birth) - 1, &history));
    birth.magic = CLIQ_MCP_STDIO_RUN_BIRTH_MAGIC;
    RECOVERY_DATA_ASSERT(!cliq_mcp_stdio_history_bytes((const unsigned char *)&birth, sizeof(birth), &history));
    birth.magic = CLIQ_MCP_STDIO_RECOVERY_BIRTH_MAGIC;
    struct broker broker = {0}; broker.recipe.header = header;
    broker.frames[3].body = recipe + header.frames[3].offset; broker.frames[3].size = (size_t)header.frames[3].bytes;
    memcpy(birth.identity.statusRequestDigest, header.frames[3].digest, 65);
    RECOVERY_DATA_ASSERT(stdio_recovery_frame_matches(&broker, &birth.identity));
    strcpy(birth.identity.statusOperationName, "effect");
    RECOVERY_DATA_ASSERT(!stdio_recovery_frame_matches(&broker, &birth.identity)); strcpy(birth.identity.statusOperationName, "fixture");
    memset(birth.identity.statusRequestDigest, 'a', 64);
    RECOVERY_DATA_ASSERT(!stdio_recovery_frame_matches(&broker, &birth.identity));
    RECOVERY_DATA_ASSERT(cliq_mcp_stdio_release_flags_valid(CLIQ_MCP_STDIO_RUN, true, false));
    RECOVERY_DATA_ASSERT(!cliq_mcp_stdio_release_flags_valid(CLIQ_MCP_STDIO_RUN, false, true));
    RECOVERY_DATA_ASSERT(cliq_mcp_stdio_release_flags_valid(CLIQ_MCP_STDIO_RECOVERY, false, true));
    RECOVERY_DATA_ASSERT(!cliq_mcp_stdio_release_flags_valid(CLIQ_MCP_STDIO_RECOVERY, true, false));
    RECOVERY_DATA_ASSERT(!cliq_mcp_stdio_release_flags_valid(CLIQ_MCP_STDIO_ADMIN, true, false));
    RECOVERY_DATA_ASSERT(!cliq_mcp_stdio_release_flags_valid(CLIQ_MCP_STDIO_ADMIN, false, true));
    struct cliq_worker_packet packet = {0}; packet.magic = CLIQ_WORKER_MAGIC; packet.version = 9;
    packet.command = CLIQ_MCP_STDIO_RESERVE; packet.stdio_purpose = CLIQ_MCP_STDIO_RECOVERY; packet.stdio_status_released = 1;
    RECOVERY_DATA_ASSERT(cliq_mcp_stdio_packet_closed(&packet));
    packet.stdio_purpose = 4;
    RECOVERY_DATA_ASSERT(!cliq_mcp_stdio_packet_closed(&packet));
    packet.stdio_purpose = CLIQ_MCP_STDIO_RECOVERY;
    memcpy(packet.stdio_server_digest, birth.identity.adapterExecutableDigest, 65);
    memset(packet.stdio_init_digest, 'b', 64);
    RECOVERY_DATA_ASSERT(cliq_mcp_stdio_recovery_program_matches(&packet, &birth.identity));
    memcpy(packet.stdio_init_digest, birth.identity.adapterExecutableDigest, 65);
    RECOVERY_DATA_ASSERT(!cliq_mcp_stdio_recovery_program_matches(&packet, &birth.identity));
    memset(packet.stdio_server_digest, 'b', 64);
    RECOVERY_DATA_ASSERT(!cliq_mcp_stdio_recovery_program_matches(&packet, &birth.identity));
    // Complete bounded payload refusal permits only checked discard/drain.
    // These inert bytes never provide a peer, token, socket or physical join.
    unsigned char output[128] = {0}, errors[128] = {0}, empty[128] = {0};
    const unsigned char malformed[] = "{\"id\":3,\"result\":{\"sentinel\":\"untrusted\"\n";
    struct broker refused = {0};
    atomic_init(&refused.error, NULL);
    refused.recovery = true; refused.recipe.header = header;
    refused.recipe.header.maximum_output_bytes = sizeof(output);
    refused.phase = 3; refused.stage_released = true;
    refused.output[0] = output; refused.output[1] = errors;
    RECOVERY_DATA_ASSERT(stdio_receive_packet(&refused, CLIQ_MCP_STDIO_STDOUT, malformed, sizeof(malformed) - 1) &&
        refused.response_refused && refused.payload_refused && !refused.protocol_complete && !refused.retired && refused.ack_stream == 1);
    stdio_discard_refused_output(&refused);
    RECOVERY_DATA_ASSERT(refused.refused_output_discarded && refused.closing && !memcmp(output, empty, sizeof(output)) &&
        refused.output_size[0] == sizeof(malformed) - 1 && refused.ack_stream == 1);
    refused.ack_stream = 0;
    RECOVERY_DATA_ASSERT(stdio_receive_packet(&refused, CLIQ_MCP_STDIO_STDERR, malformed, sizeof(malformed) - 1) &&
        refused.ack_stream == 2 && !memcmp(errors, empty, sizeof(errors)) && refused.output_size[1] == sizeof(malformed) - 1);
    refused.ack_stream = 0;
    RECOVERY_DATA_ASSERT(!stdio_receive_packet(&refused, CLIQ_MCP_STDIO_STDOUT, output, sizeof(output)) &&
        refused.output_size[0] == sizeof(malformed) - 1);
    RECOVERY_DATA_ASSERT(!stdio_receive_packet(&refused, CLIQ_MCP_STDIO_OUTPUT_EOF, output, 3) && !stdio_unavailable_joined(&refused));
    struct broker ordinary = {0};
    atomic_init(&ordinary.error, NULL); ordinary.recipe.header = header;
    RECOVERY_DATA_ASSERT(!stdio_decode(&ordinary, malformed, sizeof(malformed) - 2, sizeof(malformed) - 1) &&
        ordinary.response_refused && !ordinary.payload_refused);
    struct broker oversized = {0};
    atomic_init(&oversized.error, NULL); oversized.recovery = true; oversized.recipe.header = header;
    oversized.recipe.header.maximum_response_bytes = 4;
    RECOVERY_DATA_ASSERT(!stdio_decode(&oversized, malformed, sizeof(malformed) - 2, sizeof(malformed) - 1) &&
        oversized.response_refused && !oversized.payload_refused);
    struct broker tail = {0};
    unsigned char secret[] = "fixture-inert-tail-key";
    atomic_init(&tail.error, NULL);
    tail.recovery = true; tail.output[0] = output; tail.output[1] = errors;
    tail.platform.secret = secret; tail.platform.secret_size = sizeof(secret) - 1;
    memcpy(errors, secret, sizeof(secret) - 1); tail.output_size[1] = sizeof(secret) - 1;
    RECOVERY_DATA_ASSERT(stdio_screen_recovery_drain(&tail) && tail.raw_screened && tail.raw_refused &&
        tail.payload_refused && !memcmp(errors, empty, sizeof(errors)) && !stdio_unavailable_joined(&tail));
    free(recipe);
#undef RECOVERY_DATA_ASSERT
    napi_value value; napi_create_object(env, &value); set_number(env, value, "checks", checks);
    set_boolean(env, value, "factoryExecuted", false); set_boolean(env, value, "authorityExecuted", false);
    napi_object_freeze(env, value); return value;
}
#endif
static napi_value initialize_stdio_broker(napi_env env, napi_value exports) {
    if (!OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)) { napi_throw_error(env, NULL, "MCP stdio native bootstrap unavailable"); return NULL; }
    const napi_property_descriptor methods[] = {{"prepareAdminStdio", NULL, prepare_admin_stdio, NULL, NULL, NULL, napi_default, NULL},
        {"prepareRunStdio", NULL, prepare_run_stdio, NULL, NULL, NULL, napi_default, NULL},
        {"prepareRecoveryStdio", NULL, prepare_recovery_stdio, NULL, NULL, NULL, napi_default, NULL}};
    if (napi_define_properties(env, exports, 3, methods) != napi_ok) return NULL;
#if defined(CLIQ_MCP_STDIO_DATA_FIXTURE)
    const napi_property_descriptor fixtures[] = {
        {"runMcpStdioDataFixture", NULL, run_mcp_stdio_data_fixture, NULL, NULL, NULL, napi_default, NULL},
        {"runMcpStdioRecoveryDataFixture", NULL, run_mcp_stdio_recovery_data_fixture, NULL, NULL, NULL, napi_default, NULL}};
    if (napi_define_properties(env, exports, 2, fixtures) != napi_ok) return NULL;
#endif
    set_number(env, exports, "interfaceVersion", 1); return exports;
}
NAPI_MODULE(cliq_linux_mcp_stdio_broker, initialize_stdio_broker)
#endif
