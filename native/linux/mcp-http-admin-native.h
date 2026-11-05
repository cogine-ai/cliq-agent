#ifndef CLIQ_MCP_HTTP_ADMIN_NATIVE_H
#define CLIQ_MCP_HTTP_ADMIN_NATIVE_H
#include "mcp-http-admin-protocol.h"
static const    napi_type_tag MCP_ADMIN_CLEANUP_TAG = {UINT64_C(0xdc9baed351794135), UINT64_C(0xbc53d9542d980374)};
static const    napi_type_tag MCP_ADMIN_CLEANUP_OBSERVATION_TAG = {UINT64_C(0xaae5fc94975d4326), UINT64_C(0x8311ae6b64cb5fca)};
static const    napi_type_tag MCP_ADMIN_JOINED_TAG = {UINT64_C(0x486a01f6bc0a48ae), UINT64_C(0xa3151456604274b1)};
struct mcp_admin_native_scope {
    struct cliq_mcp_admin_peer_handle bridge;
    struct controller *controller;
    struct cliq_mcp_admin_input *input;
    napi_ref        input_ref;
    struct cliq_worker_packet identity, observation;
    unsigned        pending;
    bool            reserved, starting, ready, released, stopping, joined, ack_started, acked, closed, peer_released;
    bool            retained;
    uint64_t        checker_epoch;
    char            checker_supervisor[257], checker_token[192], original_digest[65];
    struct cliq_mcp_admin_history original_history;
    int             outgoing_fd;
    unsigned char  *frame, *snapshot;
    size_t          frame_size, snapshot_size;
    unsigned        frame_phase;
    char            frame_digest[65];
};
static bool
mcp_admin_native_current(struct mcp_admin_native_scope *scope)
{
    return scope && scope->bridge.creator_pid == getpid() && scope->bridge.environment == scope->controller->env && syscall(SYS_gettid) == getpid() &&
        !scope->controller->retirement_failed && !atomic_load(&native_retirement_failed) && (scope->joined || (!scope->closed && !scope->controller->closed && anchor_current(scope->controller) &&
                                                                                                               controller_placement(scope->controller, scope->controller->token) && scope->input && scope->input->assert_current && scope->input->assert_current(scope->input)));
}
static bool
mcp_admin_native_hash_fd(int fd, uint64_t size, char digest[65])
{
    struct sha256_context hash;
    sha256_init(&hash);
    unsigned char   bytes[65536];
    uint64_t        at = 0;
    while (at < size) {
        size_t          wanted = size - at < sizeof(bytes) ? (size_t) (size - at) : sizeof(bytes);
        ssize_t         n = pread(fd, bytes, wanted, (off_t) at);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        sha256_update(&hash, bytes, (size_t) n);
        at += (uint64_t) n;
    } unsigned char result[32];
    sha256_final(&hash, result);
    for (size_t i = 0; i < 32; i++)
        snprintf(digest + i * 2, 3, "%02x", result[i]);
    return true;
}
static void
mcp_admin_native_joined(struct controller *controller)
{
    struct mcp_admin_native_scope *scope = controller->mcp_admin;
    if (!scope || scope->acked)
        return;
    /* Historical kind9 can close only this original execution scope. A
     * current checker requires its own authenticated CLEANUP_RETAINED reply;
     * reaping that checker cannot promote the old journal into its actions. */
    if (scope->retained) {
        controller->retirement_failed = true;
        return;
    }
    struct cliq_mcp_admin_history history;
    bool            valid = scope->input && scope->input->birth_fd >= 0 && cliq_mcp_admin_read_history(scope->input->birth_fd, &history, &scope->snapshot, &scope->snapshot_size) &&
    history.count && history.last.kind == 9 && !history.last.packet.populated && !history.last.packet.remaining_descendants && (!scope->ready || history.last.packet.init_reaped == 1);
    struct stat     named;
    valid = valid && fstatat(controller->anchor_root, scope->identity.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    if (valid) {
        scope->observation = history.last.packet;
        scope->joined = true;
        scope->acked = true;
        scope->closed = true;
    } else
        controller->retirement_failed = true;
}
static void
mcp_admin_native_complete(napi_env env, struct controller *controller)
{
    struct mcp_admin_native_scope *scope = controller->mcp_admin;
    if (!scope || !scope->acked || !scope->input)
        return;
    if (controller->env != env || controller->creator_pid != getpid() || syscall(SYS_gettid) != getpid() ||
        !controller->closed || !controller->cleanup_done || !controller->reaped || controller->retirement_failed || !scope->joined || !scope->closed) {
        controller->retirement_failed = true;
        return;
    }
    if (!scope->retained) {
        struct cliq_mcp_admin_history history;
        if (!scope->snapshot || !cliq_mcp_admin_history_bytes(scope->snapshot, scope->snapshot_size, &history) ||
            !history.count || history.last.kind != 9 || memcmp(&history.header, &scope->input->binding, sizeof(history.header)) ||
            history.first.controller_pid != controller->pid || strcmp(history.first.controller_start_token, controller->token) ||
            !cliq_mcp_admin_packet_same(&scope->identity, &history.last.packet) ||
            (scope->pending && (scope->pending < CLIQ_MCP_ADMIN_RESERVE || scope->pending > CLIQ_MCP_ADMIN_ACK ||
                                controller->pending != scope->pending || controller->pending_scope))) {
            controller->retirement_failed = true;
            return;
        }
    }
    if (!retire_descriptor(&scope->outgoing_fd)) {
        controller->retirement_failed = true;
        return;
    }
    atomic_store(&scope->input->execution_joined, true);
    if (scope->input->retire(scope->input) || !atomic_load(&scope->input->closed)) {
        controller->retirement_failed = true;
        return;
    }
    if (!scope->retained && scope->pending) {
        /* The revoked channel and its complete original domain have joined.
         * Consume only the cancelled local request, never a semantic reply,
         * no-effect fact or a current-checker cleanup observation. */
        controller->pending = 0;
        scope->pending = 0;
    }
}
static bool
mcp_admin_peer_current(struct cliq_mcp_admin_peer_handle *bridge)
{
    return bridge && bridge->abi_version == CLIQ_MCP_OWNER_ABI && mcp_admin_native_current((struct mcp_admin_native_scope *)bridge);
}
static int
mcp_admin_reply(struct mcp_admin_native_scope *scope, struct cliq_worker_packet *response, int files[CLIQ_WORKER_MAX_FDS], size_t * count)
{
    struct controller *controller = scope->controller;
    if (!mcp_admin_native_current(scope) || !scope->pending || controller->pending != scope->pending || controller->pending_scope)
        return -1;
    if (!cliq_receive_flags(controller->socket, response, files, CLIQ_WORKER_MAX_FDS, count, MSG_DONTWAIT)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        controller->retirement_failed = true;
        return -1;
    }
    unsigned        expected = scope->pending;
    controller->pending = 0;
    scope->pending = 0;
    bool            valid = response->status == 0 && response->command == expected && cliq_mcp_admin_packet_same(response, &scope->identity);
    if (!valid) {
        for (size_t i = 0; i < *count; i++)
            if (!retire_descriptor(&files[i]))
                controller->retirement_failed = true;
        *count = 0;
        return -1;
    } scope->observation = *response;
    return 1;
}
static bool
mcp_admin_request(struct mcp_admin_native_scope *scope, unsigned command, int *files, size_t count)
{
    if (!mcp_admin_native_current(scope) || scope->closed || scope->acked || scope->pending || scope->controller->pending)
        return false;
    struct cliq_worker_packet request = scope->identity;
    request.command = command;
    request.admin_phase = scope->frame_phase;
    if (!begin_request(scope->controller, NULL, &request, files, count))
        return false;
    scope->pending = command;
    return true;
}
static bool
mcp_admin_stage_decode(struct mcp_admin_native_scope *scope, const unsigned char *bytes, size_t size, unsigned phase)
{
    /*
     * Signed helper emits canonical {bodyJson,phase}. This decoder accepts precisely that envelope; the broker
     * independently parses and matches the resulting actual bytes against its fixed precommitted frame.
     */
    const char      prefix[] = "{\"bodyJson\":\"";
    if (size < sizeof(prefix) || memcmp(bytes, prefix, sizeof(prefix) - 1))
        return false;
    unsigned char  *body = malloc(size);
    if (!body)
        return false;
    size_t          at = sizeof(prefix) - 1, out = 0;
    bool            ended = false;
    while (at < size) {
        unsigned char   byte = bytes[at++];
        if (byte == '"') {
            ended = true;
            break;
        } if (byte < 0x20) {
            free(body);
            return false;
        }
        if (byte == '\\') {
            if (at == size) {
                free(body);
                return false;
            } byte = bytes[at++];
            if (byte == 'u') {
                if (size - at < 4 || bytes[at] != '0' || bytes[at + 1] != '0') {
                    free(body);
                    return false;
                } unsigned      value = 0;
                for (unsigned i = 2; i < 4; i++) {
                    unsigned char   c = bytes[at + i];
                    unsigned        digit = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : 16;
                    if (digit == 16) {
                        free(body);
                        return false;
                    } value = value * 16 + digit;
                } at += 4;
                byte = (unsigned char)value;
            } else if (byte == 'b')
                byte = '\b';
            else if (byte == 'f')
                byte = '\f';
            else if (byte == 'n')
                byte = '\n';
            else if (byte == 'r')
                byte = '\r';
            else if (byte == 't')
                byte = '\t';
            else if (byte != '"' && byte != '\\' && byte != '/') {
                free(body);
                return false;
            }
        }
        body[out++] = byte;
    }
    const char     *names[] = {"initialize", "initialized", "tools_list"};
    char            suffix[64];
    int             suffix_size = phase < 3 ? snprintf(suffix, sizeof(suffix), ",\"phase\":\"%s\"}", names[phase]) : -1;
    if (!ended || suffix_size < 0 || size - at != (size_t) suffix_size || memcmp(bytes + at, suffix, (size_t) suffix_size) || !out || out > CLIQ_MCP_ADMIN_MAX_MESSAGE) {
        free(body);
        return false;
    }
    free(scope->frame);
    scope->frame = body;
    scope->frame_size = out;
    scope->frame_phase = phase;
    struct sha256_context hash;
    unsigned char   digest[32];
    sha256_init(&hash);
    sha256_update(&hash, body, out);
    sha256_final(&hash, digest);
    for (size_t i = 0; i < 32; i++)
        snprintf(scope->frame_digest + i * 2, 3, "%02x", digest[i]);
    return true;
}
static int
mcp_admin_poll_pending(struct mcp_admin_native_scope *scope)
{
    if (!scope->pending)
        return 1;
    struct cliq_worker_packet response;
    int             files[CLIQ_WORKER_MAX_FDS];
    size_t          count = 0;
    unsigned        command = scope->pending;
    int             state = mcp_admin_reply(scope, &response, files, &count);
    if (state <= 0)
        return state;
    bool            valid = true;
    if (command == CLIQ_MCP_ADMIN_RESERVE) {
        valid = !count && response.cgroup_inode && response.cgroup_device;
        scope->reserved = valid;
        scope->identity = response;
    } else if (command == CLIQ_MCP_ADMIN_CLEANUP_RETAINED) {
        valid = !count && scope->retained && !response.populated && !response.remaining_descendants && (!scope->original_history.ready.kind || response.init_reaped == 1) &&
            !strcmp(response.admin_original_birth_digest, scope->original_digest) && response.admin_checker_supervisor_pid == getpid() && response.admin_checker_owner_epoch == scope->checker_epoch &&
            !strcmp(response.admin_checker_supervisor_id, scope->checker_supervisor) && !strcmp(response.admin_checker_supervisor_token, scope->checker_token);
        if (valid) {
            scope->joined = true;
            scope->acked = true;
            scope->closed = true;
            atomic_store(&scope->input->execution_joined, true);
            valid = scope->input->retire(scope->input) == 0;
        }
    } else if (command == CLIQ_MCP_ADMIN_CREATE_BLOCKED) {
        valid = !count && response.pid > 0 && response.namespace_init_pid > 0 && response.pid_namespace_inode && response.populated == 1;
        scope->ready = valid;
        scope->identity = response;
    } else if (command == CLIQ_MCP_ADMIN_POLL) {
        if (count == 1) {
            struct stat     file;
            valid = response.admin_phase < 3 && !scope->frame && !fstat(files[0], &file) && S_ISREG(file.st_mode) && file.st_size > 0 && file.st_size <= CLIQ_MCP_ADMIN_MAX_MESSAGE &&
                fcntl(files[0], F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
            unsigned char  *bytes = valid ? malloc((size_t) file.st_size) : NULL;
            valid = valid && bytes && cliq_mcp_admin_read_exact(files[0], bytes, (size_t) file.st_size, 0) && mcp_admin_stage_decode(scope, bytes, (size_t) file.st_size, response.admin_phase);
            free(bytes);
        } else if (count)
            valid = false;
        if (!response.populated && !response.remaining_descendants && response.init_reaped == 1)
            scope->joined = true;
    } else if (command == CLIQ_MCP_ADMIN_STOP) {
        valid = !count && !response.populated && !response.remaining_descendants && (!scope->ready || response.init_reaped == 1);
        scope->joined = valid;
    } else if (command == CLIQ_MCP_ADMIN_ACK) {
        valid = !count && scope->joined;
        struct cliq_mcp_admin_history history;
        valid = valid && cliq_mcp_admin_read_history(scope->input->birth_fd, &history, &scope->snapshot, &scope->snapshot_size) && history.count && history.last.kind == 9 &&
            !history.last.packet.populated && !history.last.packet.remaining_descendants;
        struct stat     named;
        valid = valid && fstatat(scope->controller->anchor_root, scope->identity.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
        if (valid) {
            atomic_store(&scope->input->execution_joined, true);
            valid = scope->input->retire(scope->input) == 0;
        } scope->acked = valid;
        scope->closed = valid;
    } else
        valid = !count;
    for (size_t i = 0; i < count; i++)
        if (!retire_descriptor(&files[i]))
            valid = false;
    if (!valid) {
        scope->controller->retirement_failed = true;
        atomic_store(&native_retirement_failed, true);
        return -1;
    } return 1;
}
static int
mcp_admin_peer_release_recipe(void *context, const struct cliq_mcp_admin_binding *binding)
{
    struct mcp_admin_native_scope *scope = context;
    if (!mcp_admin_native_current(scope) || scope->closed || scope->joined || scope->acked || !scope->ready || scope->released || scope->pending || scope->controller->pending ||
        strcmp(binding->operation, scope->input->binding.operation) || binding->attempt != scope->input->binding.attempt || strcmp(binding->principal, scope->input->binding.principal) ||
        strcmp(binding->target_ref, scope->input->binding.target_ref) || strcmp(binding->target_digest, scope->input->binding.target_digest) ||
        strcmp(binding->core_ref, scope->input->binding.core_ref) || strcmp(binding->core_digest, scope->input->binding.core_digest) || strcmp(binding->plan_ref, scope->input->binding.plan_ref) ||
        strcmp(binding->plan_digest, scope->input->binding.plan_digest) || strcmp(binding->spec_ref, scope->input->binding.spec_ref) || strcmp(binding->spec_digest, scope->input->binding.spec_digest))
        return -1;
    scope->bridge.binding = *binding;
    scope->released = true;
    return mcp_admin_request(scope, CLIQ_MCP_ADMIN_RELEASE_RECIPE, NULL, 0) ? 1 : -1;
}
static int      mcp_admin_flush_outgoing(struct mcp_admin_native_scope *scope);
static int
mcp_admin_peer_poll_frame(void *context, struct cliq_mcp_fixed_frame_view *view)
{
    struct mcp_admin_native_scope *scope = context;
    if (!mcp_admin_native_current(scope) || !scope->released || scope->closed)
        return -1;
    int             state = mcp_admin_poll_pending(scope);
    if (state <= 0)
        return state;
    if (scope->outgoing_fd >= 0) {
        int             flushed = mcp_admin_flush_outgoing(scope);
        if (flushed <= 0)
            return flushed;
    }
    if (scope->frame) {
        view->phase = scope->frame_phase;
        view->bytes = scope->frame;
        view->size = scope->frame_size;
        memcpy(view->digest, scope->frame_digest, 65);
        return 1;
    }
    if (scope->controller->pending)
        return 0;
    return mcp_admin_request(scope, CLIQ_MCP_ADMIN_POLL, NULL, 0) ? 0 : -1;
}
static int
mcp_admin_flush_outgoing(struct mcp_admin_native_scope *scope)
{
    if (scope->outgoing_fd < 0)
        return 1;
    if (scope->pending || scope->controller->pending)
        return 0;
    struct cliq_worker_packet request = scope->identity;
    request.command = CLIQ_MCP_ADMIN_DELIVER;
    request.admin_phase = scope->frame_phase;
    request.admin_protocol_complete = 1;
    if (!begin_request(scope->controller, NULL, &request, &scope->outgoing_fd, 1))
        return -1;
    scope->pending = CLIQ_MCP_ADMIN_DELIVER;
    return retire_descriptor(&scope->outgoing_fd) ? 0 : -1;
}
static int
mcp_admin_peer_deliver(void *context, const struct cliq_mcp_screened_message_view *view)
{
    struct mcp_admin_native_scope *scope = context;
    if (!mcp_admin_native_current(scope) || !scope->frame || view->phase != scope->frame_phase || scope->pending || scope->outgoing_fd >= 0)
        return -1;
    static const unsigned char ack[] = "{\"phase\":\"initialized\",\"ack\":true}";
    const unsigned char *bytes = view->acknowledgement ? ack : view->bytes;
    size_t          size = view->acknowledgement ? sizeof(ack) - 1 : view->size;
    if (!size || size > CLIQ_MCP_ADMIN_MAX_MESSAGE)
        return -1;
    int             fd = memfd_create("cliq-mcp-admin-screened-message", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0)
        return -1;
    bool            valid = write(fd, bytes, size) == (ssize_t) size && !fchmod(fd, 0400) && !fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    if (valid) {
        scope->outgoing_fd = fd;
        fd = -1;
        free(scope->frame);
        scope->frame = NULL;
        scope->frame_size = 0;
    } if (!retire_descriptor(&fd))
        valid = false;
    if (!valid)
        return -1;
    return mcp_admin_flush_outgoing(scope) < 0 ? -1 : 1;
}
static int
mcp_admin_peer_cancel(void *context)
{
    struct mcp_admin_native_scope *scope = context;
    if (scope->controller->closed && !scope->controller->cleanup_done)
        return 0;
    if (!mcp_admin_native_current(scope))
        return -1;
    if (scope->joined)
        return 1;
    scope->stopping = true;
    if (!retire_descriptor(&scope->outgoing_fd))
        return -1;
    int             state = mcp_admin_poll_pending(scope);
    if (state <= 0)
        return state;
    if (scope->joined)
        return 1;
    if (scope->retained)
        return 0;
    if (scope->pending || scope->controller->pending)
        return 0;
    return mcp_admin_request(scope, CLIQ_MCP_ADMIN_STOP, NULL, 0) ? 1 : -1;
}
static int
mcp_admin_peer_poll_joined(void *context, struct cliq_mcp_admin_observation *view)
{
    struct mcp_admin_native_scope *scope = context;
    if (scope->controller->closed && !scope->controller->cleanup_done)
        return 0;
    if (!mcp_admin_native_current(scope))
        return -1;
    int             state = scope->acked ? 1 : mcp_admin_poll_pending(scope);
    if (state < 0)
        return -1;
    view->death_joined = scope->joined;
    view->output_acknowledged = scope->acked;
    view->output_custody_retired = scope->acked;
    view->packet = scope->observation;
    if (scope->joined)
        return 1;
    if (!state)
        return 0;
    if (scope->controller->pending)
        return 0;
    if (scope->outgoing_fd >= 0) {
        int             flushed = mcp_admin_flush_outgoing(scope);
        if (flushed <= 0)
            return flushed;
    }
    if (scope->stopping)
        return mcp_admin_request(scope, CLIQ_MCP_ADMIN_STOP, NULL, 0) ? 0 : -1;
    return mcp_admin_request(scope, CLIQ_MCP_ADMIN_POLL, NULL, 0) ? 0 : -1;
}
static int
mcp_admin_peer_begin_ack(void *context)
{
    struct mcp_admin_native_scope *scope = context;
    if (!mcp_admin_native_current(scope) || !scope->joined)
        return -1;
    if (scope->acked || scope->ack_started)
        return 1;
    int             state = mcp_admin_poll_pending(scope);
    if (state <= 0)
        return state;
    if (scope->controller->pending)
        return 0;
    scope->ack_started = true;
    return mcp_admin_request(scope, CLIQ_MCP_ADMIN_ACK, NULL, 0) ? 1 : -1;
}
static int
mcp_admin_peer_poll_ack(void *context)
{
    struct mcp_admin_native_scope *scope = context;
    if (!mcp_admin_native_current(scope))
        return -1;
    int             state = mcp_admin_poll_pending(scope);
    if (state < 0)
        return -1;
    return scope->acked ? 1 : 0;
}
static void
mcp_admin_peer_release(void *context)
{
    struct mcp_admin_native_scope *scope = context;
    if (!mcp_admin_native_current(scope) || !scope->joined || !scope->acked) {
        scope->controller->retirement_failed = true;
        atomic_store(&native_retirement_failed, true);
        return;
    } scope->peer_released = true;
    if (scope->controller->mcp_admin == scope)
        scope->controller->mcp_admin = NULL;
}
static struct mcp_admin_native_scope *
mcp_admin_scope_receiver(napi_env env, napi_callback_info info, size_t * argc, napi_value * args)
{
    napi_value      self;
    struct mcp_admin_native_scope *scope = NULL;
    if (napi_get_cb_info(env, info, argc, args, &self, NULL) != napi_ok || (!tagged(env, self, &CLIQ_MCP_ADMIN_PEER_TAG, (void **)&scope) && !tagged(env, self, &MCP_ADMIN_CLEANUP_TAG, (void **)&scope)) || !scope || scope->bridge.environment != env || !mcp_admin_native_current(scope)) {
        failure(env, "Invalid genuine Admin MCP scope");
        return NULL;
    } return scope;
}
static napi_value mcp_admin_poll_reserved(napi_env env, napi_callback_info info) {
    size_t          argc = 0;
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, NULL);
    if (!scope)
        return NULL;
    if (!scope->reserved) {
        int             state = mcp_admin_poll_pending(scope);
        if (state < 0)
            return failure(env, "Admin MCP reservation refused");
        if (!state)
            return undefined(env);
    } return scope_observation(env, &scope->identity);
}
static napi_value mcp_admin_create_call(napi_env env, napi_callback_info info) {
    size_t          argc = 0;
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, NULL);
    if (!scope)
        return NULL;
    if (!scope->reserved || scope->starting || !mcp_admin_request(scope, CLIQ_MCP_ADMIN_CREATE_BLOCKED, NULL, 0))
        return failure(env, "Admin MCP blocked birth is unavailable");
    scope->starting = true;
    return undefined(env);
}
static napi_value mcp_admin_poll_ready(napi_env env, napi_callback_info info) {
    size_t          argc = 0;
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, NULL);
    if (!scope)
        return NULL;
    if (!scope->ready) {
        int             state = mcp_admin_poll_pending(scope);
        if (state < 0)
            return failure(env, "Admin MCP actual READY refused");
        if (!state)
            return undefined(env);
    } return scope_observation(env, &scope->identity);
}
static bool
mcp_admin_native_binding(napi_env env, napi_value value, struct cliq_mcp_admin_binding *binding)
{
    napi_value      keys;
    uint32_t        key_count;
    if (napi_get_all_property_names(env, value, napi_key_own_only, napi_key_all_properties, napi_key_numbers_to_strings, &keys) != napi_ok || napi_get_array_length(env, keys, &key_count) != napi_ok || key_count != 19)
        return false;
#define MCP_ADMIN_TEXT(js,c) if(!field_string(env,value,js,binding->c,sizeof(binding->c)))return false
#define MCP_ADMIN_DIGEST(js,c) MCP_ADMIN_TEXT(js,c);if(!cliq_mcp_admin_digest(binding->c))return false
    MCP_ADMIN_TEXT("adminOperationId", operation);
    MCP_ADMIN_TEXT("principalId", principal);
    MCP_ADMIN_TEXT("method", method);
    if (strcmp(binding->method, "mcp.register") && strcmp(binding->method, "mcp.refresh"))
        return false;
    MCP_ADMIN_TEXT("dispatchId", dispatch);
    MCP_ADMIN_TEXT("supervisorInstanceId", supervisor);
    MCP_ADMIN_DIGEST("controlRequestDigest", control_digest);
    MCP_ADMIN_DIGEST("targetRef", target_ref);
    MCP_ADMIN_DIGEST("targetDigest", target_digest);
    MCP_ADMIN_DIGEST("probePayloadCoreRef", core_ref);
    MCP_ADMIN_DIGEST("probePayloadCoreDigest", core_digest);
    MCP_ADMIN_DIGEST("probeRequestDigest", probe_digest);
    MCP_ADMIN_DIGEST("processContainmentRef", containment_ref);
    MCP_ADMIN_DIGEST("plannedContainmentRef", plan_ref);
    MCP_ADMIN_DIGEST("plannedContainmentDigest", plan_digest);
    MCP_ADMIN_DIGEST("sandboxLaunchSpecRef", spec_ref);
    MCP_ADMIN_DIGEST("sandboxLaunchSpecDigest", spec_digest);
#undef MCP_ADMIN_TEXT
#undef MCP_ADMIN_DIGEST
    return field_number(env, value, "attempt", &binding->attempt) && field_number(env, value, "stateOwnerEpoch", &binding->owner_epoch) && binding->owner_epoch && field_number(env, value, "deadlineMs", &binding->deadline_ms) && binding->deadline_ms;
}
static napi_value mcp_admin_release_call(napi_env env, napi_callback_info info) {
    size_t          argc = 2;
    napi_value      args[2];
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, args);
    if (!scope)
        return NULL;
    struct cliq_mcp_admin_binding binding = {0};
    if (argc != 1 || !mcp_admin_native_binding(env, args[0], &binding) || mcp_admin_peer_release_recipe(scope, &binding) < 0)
        return failure(env, "Admin MCP original recipe release refused");
    return undefined(env);
}
static napi_value mcp_admin_poll_stage(napi_env env, napi_callback_info info) {
    size_t          argc = 0;
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, NULL);
    if (!scope)
        return NULL;
    struct cliq_mcp_fixed_frame_view view;
    int             state = mcp_admin_peer_poll_frame(scope, &view);
    if (state < 0)
        return failure(env, "Admin MCP helper protocol refused");
    if (!state)
        return undefined(env);
    napi_value      result;
    napi_create_object(env, &result);
    static const char *names[] = {"initialize", "initialized", "tools_list"};
    set_string(env, result, "kind", "stage_requested");
    set_string(env, result, "phase", names[view.phase]);
    napi_object_freeze(env, result);
    return result;
}
static napi_value mcp_admin_stop_call(napi_env env, napi_callback_info info) {
    size_t          argc = 0;
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, NULL);
    if (!scope)
        return NULL;
    if (mcp_admin_peer_cancel(scope) < 0)
        return failure(env, "Admin MCP original stop could not be issued");
    return undefined(env);
}
struct mcp_admin_join_proof {
    struct mcp_admin_native_scope *scope;
    napi_ref        original;
    bool            custody_retired;
};
static void
mcp_admin_join_finalize(napi_env env, void *data, void *hint)
{
    (void)hint;
    struct mcp_admin_join_proof *proof = data;
    napi_ref        original = proof->original;
    proof->original = NULL;
    if (original)
        napi_delete_reference(env, original);
    free(proof);
}
static napi_value mcp_admin_assert_join_call(napi_env env, napi_callback_info info) {
    size_t          argc = 2;
    napi_value      args[2];
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, args);
    if (!scope)
        return NULL;
    struct mcp_admin_join_proof *proof = NULL;
    if (argc != 1 || !tagged(env, args[0], &MCP_ADMIN_JOINED_TAG, (void **)&proof) || !proof || proof->scope != scope || !proof->custody_retired ||
        !scope->joined || !scope->acked || !scope->closed || scope->pending || scope->outgoing_fd >= 0 || !atomic_load(&scope->input->execution_joined) || !atomic_load(&scope->input->closed)) {
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "Original Admin MCP scope has no exact irreversible joined custody proof");
        return NULL;
    }
    return undefined(env);
}
static napi_value mcp_admin_poll_join(napi_env env, napi_callback_info info) {
    size_t          argc = 0;
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, NULL);
    if (!scope)
        return NULL;
    struct cliq_mcp_admin_observation view;
    int             state = mcp_admin_peer_poll_joined(scope, &view);
    if (state < 0)
        return failure(env, "Admin MCP original containment did not join");
    if (!state)
        return undefined(env);
    napi_value      result, observation = scope_observation(env, &view.packet), value;
    napi_create_object(env, &result);
    napi_set_named_property(env, result, "observation", observation);
    napi_get_boolean(env, true, &value);
    napi_set_named_property(env, result, "deathJoined", value);
    napi_get_boolean(env, view.output_acknowledged, &value);
    napi_set_named_property(env, result, "outputAcknowledged", value);
    napi_get_boolean(env, view.output_custody_retired, &value);
    napi_set_named_property(env, result, "outputCustodyRetired", value);
    struct mcp_admin_join_proof *proof = calloc(1, sizeof(*proof));
    napi_value      self;
    if (!proof)
        return failure(env, "Admin MCP joined proof allocation failed");
    proof->scope = scope;
    proof->custody_retired = view.output_custody_retired && view.output_acknowledged;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok || napi_create_reference(env, self, 1, &proof->original) != napi_ok || napi_type_tag_object(env, result, &MCP_ADMIN_JOINED_TAG) != napi_ok ||
        napi_wrap(env, result, proof, mcp_admin_join_finalize, NULL, NULL) != napi_ok) {
        if (proof->original)
            napi_delete_reference(env, proof->original);
        free(proof);
        return failure(env, "Admin MCP joined proof lifetime failed");
    }
    napi_object_freeze(env, result);
    return result;
}
static napi_value mcp_admin_begin_ack_call(napi_env env, napi_callback_info info) {
    size_t          argc = 0;
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, NULL);
    if (!scope)
        return NULL;
    if (mcp_admin_peer_begin_ack(scope) < 0)
        return failure(env, "Admin MCP output acknowledgement refused");
    return undefined(env);
}
static napi_value mcp_admin_poll_ack_call(napi_env env, napi_callback_info info) {
    size_t          argc = 0;
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, NULL);
    if (!scope)
        return NULL;
    int             state = mcp_admin_peer_poll_ack(scope);
    if (state < 0)
        return failure(env, "Admin MCP output custody did not retire");
    napi_value      result;
    napi_get_boolean(env, state == 1, &result);
    return result;
}
static napi_value mcp_admin_snapshot_call(napi_env env, napi_callback_info info) {
    size_t          argc = 0;
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, NULL);
    if (!scope)
        return NULL;
    if (!scope->acked || !scope->snapshot)
        return undefined(env);
    napi_value      result;
    return napi_create_buffer_copy(env, scope->snapshot_size, scope->snapshot, NULL, &result) == napi_ok ? result : NULL;
}
static napi_value mcp_admin_reobserve_retirement(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value args[1], self;
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, args);
    if (!scope) return NULL;
    if (argc || scope->retained || !scope->joined || !scope->acked || !scope->closed || scope->pending ||
        scope->outgoing_fd >= 0 || scope->bridge.borrowed || !scope->released || !scope->snapshot ||
        napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok)
        return failure(env, "MCP Admin has no complete original retirement to reobserve");
    return mcp_admin_original_value(env, self, scope, scope->controller, scope->input, scope->snapshot, scope->snapshot_size,
        &scope->bridge.binding, CLIQ_MCP_ADMIN_ORIGINAL_HTTP);
}
static napi_value mcp_admin_assert_retirement(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2];
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, args);
    if (!scope) return NULL;
    if (argc != 1 || scope->retained || !scope->joined || !scope->acked || !scope->closed || scope->pending || scope->outgoing_fd >= 0)
        return failure(env, "MCP Admin original current observation is unavailable");
    return mcp_admin_original_assert(env, scope, scope->controller, args[0], CLIQ_MCP_ADMIN_ORIGINAL_HTTP);
}
static void
mcp_admin_native_finalize(napi_env env, void *data, void *hint)
{
    (void)hint;
    struct mcp_admin_native_scope *scope = data;
    if (!scope->acked || scope->bridge.borrowed)
        return;
    if (scope->controller->mcp_admin == scope)
        scope->controller->mcp_admin = NULL;
    if (scope->input_ref)
        napi_delete_reference(env, scope->input_ref);
    free(scope->frame);
    free(scope->snapshot);
    controller_release(scope->controller);
    free(scope);
}
static napi_value seal_mcp_admin_script(napi_env env, napi_callback_info info) {
    return seal_fixed_script(env, info, &MCP_ADMIN_SCRIPT_TAG);
}
static napi_value reserve_mcp_admin(napi_env env, napi_callback_info info) {
    size_t          argc = 7;
    napi_value      args[7], self, result;
    struct controller *controller;
    struct cliq_mcp_admin_input *input;
    struct image   *helper, *bwrap, *script;
    struct cliq_guest_toolchain *guest;
    bool            buffer;
    void           *recipe;
    size_t          recipe_size;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 6 || !tagged(env, self, &CONTROLLER_TAG, (void **)&controller) || controller->env != env || controller->creator_pid != getpid() || syscall(SYS_gettid) != getpid() ||
        controller->closed || !controller->ready || controller->pending || controller->mcp_admin || (controller->source_requested && !controller->preparation_finished) || controller->retained_requested ||
        !tagged(env, args[0], &CLIQ_MCP_ADMIN_INPUT_TAG, (void **)&input) || input->abi_version != CLIQ_MCP_ADMIN_INPUT_ABI || input->creator_pid != getpid() || input->environment != env || !input->assert_current || !input->assert_current(input) || !input->retire ||
        atomic_load(&input->closed) || atomic_load(&input->execution_claimed) || !tagged(env, args[1], &IMAGE_TAG, (void **)&helper) || helper->fd < 0 || !tagged(env, args[2], &IMAGE_TAG, (void **)&bwrap) || bwrap->fd < 0 ||
        !tagged(env, args[3], &CLIQ_GUEST_TOOLCHAIN_TAG, (void **)&guest) || guest->abi_version != CLIQ_GUEST_ABI_VERSION || !atomic_load(&guest->ready) || atomic_load(&guest->revoked) || !guest->file_count || guest->file_count > CLIQ_VERIFIER_MAX_FILES || strcmp(guest->node_path, "/usr/bin/node") ||
        !tagged(env, args[4], &MCP_ADMIN_SCRIPT_TAG, (void **)&script) || script->fd < 0 || !script->byte_count || script->byte_count > CLIQ_MCP_ADMIN_MAX_MESSAGE || !cliq_mcp_admin_digest(script->digest) ||
        napi_is_buffer(env, args[5], &buffer) != napi_ok || !buffer || napi_get_buffer_info(env, args[5], &recipe, &recipe_size) != napi_ok || !recipe_size || recipe_size > CLIQ_MCP_ADMIN_MAX_CONFIG || !controller_placement(controller, controller->token))
        return failure(env, "Admin MCP requires original physical input and exact signed fixed images");
    struct mcp_admin_native_scope *scope = calloc(1, sizeof(*scope));
    struct cliq_mcp_admin_config *config = calloc(1, sizeof(*config));
    if (!scope || !config) {
        free(scope);
        free(config);
        return failure(env, "Admin MCP owner allocation unavailable");
    }
    scope->controller = controller;
    scope->input = input;
    scope->outgoing_fd = -1;
    scope->bridge.abi_version = CLIQ_MCP_OWNER_ABI;
    scope->bridge.creator_pid = getpid();
    scope->bridge.environment = env;
    scope->bridge.assert_current = mcp_admin_peer_current;
    struct cliq_mcp_admin_binding *static_binding = &scope->bridge.binding;
    const struct cliq_mcp_admin_birth *original = &input->binding;
    memcpy(static_binding->operation, original->operation, sizeof(static_binding->operation));
    memcpy(static_binding->principal, original->principal, sizeof(static_binding->principal));
    static_binding->attempt = original->attempt;
    memcpy(static_binding->target_ref, original->target_ref, 65);
    memcpy(static_binding->target_digest, original->target_digest, 65);
    memcpy(static_binding->core_ref, original->core_ref, 65);
    memcpy(static_binding->core_digest, original->core_digest, 65);
    memcpy(static_binding->plan_ref, original->plan_ref, 65);
    memcpy(static_binding->plan_digest, original->plan_digest, 65);
    memcpy(static_binding->spec_ref, original->spec_ref, 65);
    memcpy(static_binding->spec_digest, original->spec_digest, 65);
    scope->bridge.peer = (struct cliq_mcp_admin_peer){
        scope, mcp_admin_peer_release_recipe, mcp_admin_peer_poll_frame, mcp_admin_peer_deliver, mcp_admin_peer_cancel, mcp_admin_peer_poll_joined, mcp_admin_peer_begin_ack, mcp_admin_peer_poll_ack, mcp_admin_peer_release
    };
    struct cliq_worker_packet *request = &scope->identity;
    *request = cliq_packet(CLIQ_MCP_ADMIN_RESERVE);
    memcpy(request->admin_operation_id, input->binding.operation, sizeof(request->admin_operation_id));
    memcpy(request->admin_principal_id, input->binding.principal, sizeof(request->admin_principal_id));
    request->admin_attempt = input->binding.attempt;
    memcpy(request->nonce, input->binding.nonce, 65);
    memcpy(request->admin_target_ref, input->binding.target_ref, 65);
    memcpy(request->admin_target_digest, input->binding.target_digest, 65);
    memcpy(request->admin_core_ref, input->binding.core_ref, 65);
    memcpy(request->admin_core_digest, input->binding.core_digest, 65);
    memcpy(request->plan_ref, input->binding.plan_ref, 65);
    memcpy(request->admin_plan_digest, input->binding.plan_digest, 65);
    memcpy(request->sandbox_launch_ref, input->binding.spec_ref, 65);
    memcpy(request->sandbox_launch_digest, input->binding.spec_digest, 65);
    snprintf(request->cgroup_name, sizeof(request->cgroup_name), "cliq-mcp-admin-%s", request->nonce);
    snprintf(request->pid_namespace_reservation, sizeof(request->pid_namespace_reservation), "cliq-mcp-admin-pidns:%s", request->nonce);
    request->subreaper_pid = controller->pid;
    memcpy(request->subreaper_start_token, controller->token, sizeof(request->subreaper_start_token));
    request->max_processes = 16;
    request->memory_bytes = 268435456;
    request->cpu_quota = 100000;
    request->max_open_files = 128;
    request->max_file_bytes = 268435456;
    request->max_generation_bytes = 536870912;
    request->max_output_bytes = 65536;
    config->magic = CLIQ_MCP_ADMIN_CONFIG_MAGIC;
    config->version = 1;
    config->file_count = guest->file_count;
    config->maximum_response_bytes = CLIQ_MCP_ADMIN_MAX_MESSAGE;
    config->script_bytes = script->byte_count;
    memcpy(config->script_digest, script->digest, 65);
    config->recipe_bytes = recipe_size;
    struct stat     init;
    bool            valid = !fstat(helper->fd, &init) && S_ISREG(init.st_mode) && init.st_size > 0 && init.st_size <= 268435456;
    config->init_bytes = valid ? (uint64_t) init.st_size : 0;
    valid = valid && mcp_admin_native_hash_fd(helper->fd, config->init_bytes, config->init_digest);
    unsigned char   digest[32];
    cliq_mcp_admin_hash(recipe, recipe_size, digest);
    for (size_t i = 0; i < 32; i++)
        snprintf(config->recipe_digest + i * 2, 3, "%02x", digest[i]);
    int             files[CLIQ_WORKER_MAX_FDS] = {controller->anchor_root, input->birth_fd, -1, helper->fd, bwrap->fd, script->fd, -1};
    for (uint32_t i = 0; valid && i < guest->file_count; i++) {
        config->files[i].byte_count = guest->files[i].byte_count;
        memcpy(config->files[i].path, guest->files[i].path, sizeof(config->files[i].path));
        memcpy(config->files[i].digest, guest->files[i].digest, 65);
        files[7 + i] = guest->files[i].fd;
    }
    valid = valid && cliq_mcp_admin_config_valid(config);
    int             config_fd = valid ? memfd_create("cliq-mcp-admin-config", MFD_CLOEXEC | MFD_ALLOW_SEALING) : -1,
                    recipe_fd = valid ? memfd_create("cliq-mcp-admin-recipe", MFD_CLOEXEC | MFD_ALLOW_SEALING) : -1;
    valid = valid && config_fd >= 0 && recipe_fd >= 0 && write(config_fd, config, sizeof(*config)) == (ssize_t) sizeof(*config) && write(recipe_fd, recipe, recipe_size) == (ssize_t) recipe_size && !fchmod(config_fd, 0400) && !fchmod(recipe_fd, 0400) && !fcntl(config_fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) && !fcntl(recipe_fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    free(config);
    const           napi_property_descriptor methods[] = {{"pollReserved", NULL, mcp_admin_poll_reserved, NULL, NULL, NULL, napi_default, NULL}, {"createBlocked", NULL, mcp_admin_create_call, NULL, NULL, NULL, napi_default, NULL}, {"pollReady", NULL, mcp_admin_poll_ready, NULL, NULL, NULL, napi_default, NULL}, {"releaseRecipe", NULL, mcp_admin_release_call, NULL, NULL, NULL, napi_default, NULL}, {"pollStageRequested", NULL, mcp_admin_poll_stage, NULL, NULL, NULL, napi_default, NULL}, {"stop", NULL, mcp_admin_stop_call, NULL, NULL, NULL, napi_default, NULL}, {"pollJoined", NULL, mcp_admin_poll_join, NULL, NULL, NULL, napi_default, NULL}, {"assertJoined", NULL, mcp_admin_assert_join_call, NULL, NULL, NULL, napi_default, NULL}, {"beginOutputAck", NULL, mcp_admin_begin_ack_call, NULL, NULL, NULL, napi_default, NULL}, {"pollOutputAck", NULL, mcp_admin_poll_ack_call, NULL, NULL, NULL, napi_default, NULL}, {"pollLifecycleSnapshot", NULL, mcp_admin_snapshot_call, NULL, NULL, NULL, napi_default, NULL}, {"reobserveRetirement", NULL, mcp_admin_reobserve_retirement, NULL, NULL, NULL, napi_default, NULL}, {"assertRetirementObservation", NULL, mcp_admin_assert_retirement, NULL, NULL, NULL, napi_default, NULL}};
    if (!valid || napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &CLIQ_MCP_ADMIN_PEER_TAG) != napi_ok || napi_define_properties(env, result, sizeof(methods) / sizeof(*methods), methods) != napi_ok || napi_create_reference(env, args[0], 1, &scope->input_ref) != napi_ok) {
        retire_descriptor(&config_fd);
        retire_descriptor(&recipe_fd);
        free(scope);
        return failure(env, "Admin MCP fixed recipe receiver unavailable");
    }
    bool            expected = false;
    if (!atomic_compare_exchange_strong(&input->execution_claimed, &expected, true)) {
        retire_descriptor(&config_fd);
        retire_descriptor(&recipe_fd);
        napi_delete_reference(env, scope->input_ref);
        free(scope);
        return failure(env, "Admin MCP original input already consumed");
    }
    controller->references++;
    controller->mcp_admin = scope;
    if (napi_wrap(env, result, scope, mcp_admin_native_finalize, NULL, NULL) != napi_ok) {
        controller->retirement_failed = true;
        return failure(env, "Admin MCP owning receiver could not be retained");
    }
    struct cliq_mcp_admin_progress origin = {0};
    origin.packet = *request;
    origin.controller_pid = controller->pid;
    memcpy(origin.controller_start_token, controller->token, sizeof(origin.controller_start_token));
    memcpy(origin.controller_leaf_name, controller->leaf_name, strlen(controller->leaf_name) + 1);
#define MCP_ADMIN_DIRECTORY(field,actual) do{origin.field.device=(actual).st_dev;origin.field.inode=(actual).st_ino;origin.field.uid=(actual).st_uid;origin.field.gid=(actual).st_gid;origin.field.mode=(actual).st_mode;}while(0)
    MCP_ADMIN_DIRECTORY(controller_root, controller->root_identity);
    MCP_ADMIN_DIRECTORY(controller_parent, controller->parent_identity);
    MCP_ADMIN_DIRECTORY(controller_leaf, controller->leaf_identity);
#undef MCP_ADMIN_DIRECTORY
    files[2] = config_fd;
    files[6] = recipe_fd;
    valid = cliq_mcp_admin_append(input->birth_fd, 1, &origin) && begin_request(controller, NULL, request, files, 7 + guest->file_count);
    if (valid)
        scope->pending = CLIQ_MCP_ADMIN_RESERVE;
    if (!retire_descriptor(&config_fd) || !retire_descriptor(&recipe_fd))
        valid = false;
    if (!valid) {
        controller->retirement_failed = true;
        return failure(env, "Admin MCP original reservation dispatch is uncertain");
    } napi_object_freeze(env, result);
    return result;
}
struct mcp_admin_cleanup_observation {
    struct mcp_admin_native_scope *scope;
    napi_ref        original;
};
static void
mcp_admin_cleanup_observation_finalize(napi_env env, void *data, void *hint)
{
    (void)hint;
    struct mcp_admin_cleanup_observation *observation = data;
    if (observation->original)
        napi_delete_reference(env, observation->original);
    free(observation);
}
static void
mcp_admin_native_bool(napi_env env, napi_value value, const char *key, bool boolean)
{
    napi_value      field;
    napi_get_boolean(env, boolean, &field);
    napi_set_named_property(env, value, key, field);
}
static napi_value mcp_admin_cleanup_observation_call(napi_env env, napi_callback_info info) {
    size_t          argc = 0;
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, NULL);
    if (!scope)
        return NULL;
    if (!scope->retained)
        return failure(env, "MCP cleanup observation requires its disjoint cleanup owner");
    if (!scope->joined) {
        int             state = mcp_admin_poll_pending(scope);
        if (state < 0)
            return failure(env, "MCP original retained cleanup refused");
        if (!state)
            return undefined(env);
    } if (!scope->joined || !scope->acked)
        return undefined(env);
    if (scope->controller->mcp_admin == scope)
        scope->controller->mcp_admin = NULL;
    napi_value      result, binding, original_controller, reservation, checker, self;
    napi_create_object(env, &result);
    napi_create_object(env, &binding);
    napi_create_object(env, &original_controller);
    napi_create_object(env, &reservation);
    napi_create_object(env, &checker);
    const struct cliq_mcp_admin_birth *header = &scope->input->binding;
    set_string(env, binding, "adminOperationId", header->operation);
    set_number(env, binding, "attempt", header->attempt);
    set_string(env, binding, "principalId", header->principal);
    set_string(env, binding, "nonce", header->nonce);
    set_string(env, binding, "targetRef", header->target_ref);
    set_string(env, binding, "targetDigest", header->target_digest);
    set_string(env, binding, "probePayloadCoreRef", header->core_ref);
    set_string(env, binding, "probePayloadCoreDigest", header->core_digest);
    set_string(env, binding, "plannedContainmentRef", header->plan_ref);
    set_string(env, binding, "plannedContainmentDigest", header->plan_digest);
    set_string(env, binding, "sandboxLaunchSpecRef", header->spec_ref);
    set_string(env, binding, "sandboxLaunchSpecDigest", header->spec_digest);
    napi_object_freeze(env, binding);
    napi_set_named_property(env, result, "originalBinding", binding);
    set_string(env, result, "kind", "mcp_admin_retained_cleanup_joined");
    set_string(env, result, "originalBirthDigest", scope->original_digest);
    set_number(env, original_controller, "pid", scope->original_history.first.controller_pid);
    set_string(env, original_controller, "processStartToken", scope->original_history.first.controller_start_token);
    napi_object_freeze(env, original_controller);
    napi_set_named_property(env, result, "originalController", original_controller);
    const struct cliq_worker_packet *packet = &scope->original_history.last.packet;
    set_string(env, reservation, "cgroupName", packet->cgroup_name);
    char            decimal[32];
    snprintf(decimal, sizeof(decimal), "%llu", (unsigned long long)packet->cgroup_device);
    set_string(env, reservation, "deviceId", decimal);
    snprintf(decimal, sizeof(decimal), "%llu", (unsigned long long)packet->cgroup_inode);
    set_string(env, reservation, "fileId", decimal);
    napi_object_freeze(env, reservation);
    napi_set_named_property(env, result, "originalReservation", reservation);
    set_string(env, checker, "supervisorInstanceId", scope->checker_supervisor);
    set_number(env, checker, "stateOwnerEpoch", scope->checker_epoch);
    set_number(env, checker, "supervisorPid", getpid());
    set_string(env, checker, "supervisorStartToken", scope->checker_token);
    set_number(env, checker, "controllerPid", scope->controller->pid);
    set_string(env, checker, "controllerStartToken", scope->controller->token);
    napi_object_freeze(env, checker);
    napi_set_named_property(env, result, "currentChecker", checker);
    set_number(env, result, "observedAtMs", scope->observation.observed_at_ms);
    mcp_admin_native_bool(env, result, "priorSupervisorDead", true);
    mcp_admin_native_bool(env, result, "priorControllerDead", true);
    mcp_admin_native_bool(env, result, "networkJoined", true);
    mcp_admin_native_bool(env, result, "outputCustodyRetired", true);
    set_number(env, result, "remainingDescendants", 0);
    struct mcp_admin_cleanup_observation *observation = calloc(1, sizeof(*observation));
    if (!observation)
        return failure(env, "Admin MCP cleanup observation allocation failed");
    observation->scope = scope;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok || napi_create_reference(env, self, 1, &observation->original) != napi_ok || napi_type_tag_object(env, result, &MCP_ADMIN_CLEANUP_OBSERVATION_TAG) != napi_ok || napi_wrap(env, result, observation, mcp_admin_cleanup_observation_finalize, NULL, NULL) != napi_ok) {
        if (observation->original)
            napi_delete_reference(env, observation->original);
        free(observation);
        return failure(env, "Admin MCP cleanup observation lifetime failed");
    }
    napi_object_freeze(env, result);
    return result;
}
static napi_value mcp_admin_assert_cleanup_call(napi_env env, napi_callback_info info) {
    size_t          argc = 2;
    napi_value      args[2];
    struct mcp_admin_native_scope *scope = mcp_admin_scope_receiver(env, info, &argc, args);
    if (!scope)
        return NULL;
    struct mcp_admin_cleanup_observation *observation = NULL;
    if (argc != 1 || !scope->retained || !scope->joined || !scope->acked || !tagged(env, args[0], &MCP_ADMIN_CLEANUP_OBSERVATION_TAG, (void **)&observation) || observation->scope != scope)
        return failure(env, "Admin MCP exact current cleanup observation mismatched");
    return undefined(env);
}
static napi_value cleanup_retained_mcp_admin(napi_env env, napi_callback_info info) {
    size_t          argc = 3;
    napi_value      args[3], self, result;
    struct controller *controller;
    struct cliq_mcp_admin_input *input;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 2 || !tagged(env, self, &CONTROLLER_TAG, (void **)&controller) || controller->creator_pid != getpid() || controller->env != env || syscall(SYS_gettid) != getpid() ||
        controller->closed || !controller->ready || controller->pending || controller->mcp_admin || !tagged(env, args[0], &CLIQ_MCP_ADMIN_RETAINED_INPUT_TAG, (void **)&input) || input->abi_version != CLIQ_MCP_ADMIN_INPUT_ABI || input->creator_pid != getpid() || input->environment != env ||
        !input->assert_current || !input->assert_current(input) || !input->retire || atomic_load(&input->closed) || atomic_load(&input->execution_claimed))
        return failure(env, "Admin MCP cleanup requires exact retained original input and current checker");
    struct mcp_admin_native_scope *scope = calloc(1, sizeof(*scope));
    if (!scope)
        return failure(env, "Admin MCP cleanup allocation failed");
    scope->controller = controller;
    scope->input = input;
    scope->outgoing_fd = -1;
    scope->retained = true;
    scope->bridge.abi_version = CLIQ_MCP_OWNER_ABI;
    scope->bridge.creator_pid = getpid();
    scope->bridge.environment = env;
    bool            valid = field_number(env, args[1], "stateOwnerEpoch", &scope->checker_epoch) && scope->checker_epoch && field_string(env, args[1], "supervisorInstanceId", scope->checker_supervisor, sizeof(scope->checker_supervisor)) &&
    cliq_process_token(getpid(), scope->checker_token) && cliq_mcp_admin_read_history(input->birth_fd, &scope->original_history, &scope->snapshot, &scope->snapshot_size) && scope->original_history.count && scope->original_history.last.kind >= 3;
    unsigned char   digest[32];
    if (valid) {
        cliq_mcp_admin_hash(scope->snapshot, scope->snapshot_size, digest);
        for (size_t i = 0; i < 32; i++)
            snprintf(scope->original_digest + i * 2, 3, "%02x", digest[i]);
        scope->identity = scope->original_history.last.packet;
        /* Current checker sends only current live wire. Original raw wire8/9
         * birth/hashchain bytes remain unchanged in the retained snapshot. */
        scope->identity.version = CLIQ_WORKER_VERSION;
        scope->identity.command = CLIQ_MCP_ADMIN_CLEANUP_RETAINED;
        scope->identity.admin_checker_owner_epoch = scope->checker_epoch;
        scope->identity.admin_checker_supervisor_pid = getpid();
        memcpy(scope->identity.admin_checker_supervisor_id, scope->checker_supervisor, sizeof(scope->checker_supervisor));
        memcpy(scope->identity.admin_checker_supervisor_token, scope->checker_token, sizeof(scope->checker_token));
        memcpy(scope->identity.admin_original_birth_digest, scope->original_digest, 65);
    }
    const           napi_property_descriptor methods[] = {{"stop", NULL, mcp_admin_stop_call, NULL, NULL, NULL, napi_default, NULL}, {"pollJoined", NULL, mcp_admin_poll_join, NULL, NULL, NULL, napi_default, NULL}, {"assertJoined", NULL, mcp_admin_assert_join_call, NULL, NULL, NULL, napi_default, NULL}, {"beginOutputAck", NULL, mcp_admin_begin_ack_call, NULL, NULL, NULL, napi_default, NULL}, {"pollOutputAck", NULL, mcp_admin_poll_ack_call, NULL, NULL, NULL, napi_default, NULL}, {"pollLifecycleSnapshot", NULL, mcp_admin_snapshot_call, NULL, NULL, NULL, napi_default, NULL}, {"pollCleanupObservation", NULL, mcp_admin_cleanup_observation_call, NULL, NULL, NULL, napi_default, NULL}, {"assertCleanupObservation", NULL, mcp_admin_assert_cleanup_call, NULL, NULL, NULL, napi_default, NULL}};
    if (!valid || napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &MCP_ADMIN_CLEANUP_TAG) != napi_ok || napi_define_properties(env, result, sizeof(methods) / sizeof(*methods), methods) != napi_ok || napi_create_reference(env, args[0], 1, &scope->input_ref) != napi_ok) {
        free(scope->snapshot);
        free(scope);
        return failure(env, "Admin MCP original cleanup provenance is incomplete");
    }
    bool            expected = false;
    if (!atomic_compare_exchange_strong(&input->execution_claimed, &expected, true)) {
        napi_delete_reference(env, scope->input_ref);
        free(scope->snapshot);
        free(scope);
        return failure(env, "Admin MCP original cleanup input already consumed");
    }
    controller->references++;
    controller->mcp_admin = scope;
    if (napi_wrap(env, result, scope, mcp_admin_native_finalize, NULL, NULL) != napi_ok) {
        controller->retirement_failed = true;
        return failure(env, "Admin MCP cleanup receiver could not be retained");
    }
    int             files[] = {controller->anchor_root, input->birth_fd};
    if (!begin_request(controller, NULL, &scope->identity, files, 2)) {
        controller->retirement_failed = true;
        return failure(env, "Admin MCP retained cleanup dispatch is uncertain");
    } scope->pending = CLIQ_MCP_ADMIN_CLEANUP_RETAINED;
    napi_object_freeze(env, result);
    return result;
}
#endif
